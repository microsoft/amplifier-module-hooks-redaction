"""
Redaction hook: masks secrets/PII in event data for logging.
Register with higher priority than logging.

Uses HookResult(action="modify") to return redacted copies rather than
mutating the shared event data dict in-place. Events that feed back into
LLM context (tool:pre, tool:post) are skipped to avoid corrupting tool
results the model needs verbatim (e.g. session IDs, timestamps).

This module is a thin Amplifier hook wrapper over the standalone ``redaction``
library, which owns the actual redaction primitives (mask_text, scrub) and
the pattern/allowlist constants. This package re-exports those names so
existing consumers that import them from ``amplifier_module_hooks_redaction``
keep working unchanged.
"""

from __future__ import annotations

# Amplifier module metadata
__amplifier_module_type__ = "hook"

import logging
from typing import Any

from amplifier_core import HookResult
from amplifier_core import ModuleCoordinator
from redaction import DEFAULT_ALLOWLIST
from redaction import DEFAULT_RULES
from redaction import PII_PATTERNS
from redaction import SECRET_PATTERNS
from redaction import mask_text
from redaction import scrub

logger = logging.getLogger(__name__)

# Public API. The redaction primitives (mask_text, scrub) and the pattern/
# allowlist constants are re-exported from redaction for backward
# compatibility, so consumer apps can depend on the vetted masker directly
# instead of vendoring a private copy.
__all__ = [
    "SECRET_PATTERNS",
    "PII_PATTERNS",
    "DEFAULT_ALLOWLIST",
    "DEFAULT_RULES",
    "mask_text",
    "scrub",
    "mount",
]


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    config = config or {}
    rules = list(config.get("rules", ["secrets", "pii-basic"]))
    # Effective allowlist = built-in structural fields ∪ user-provided entries.
    # Users extend but never reduce the defaults.
    allowlist = DEFAULT_ALLOWLIST | set(config.get("allowlist", []))
    priority = int(config.get("priority", 10))

    # Events whose data feeds back into LLM context. Redacting these
    # corrupts tool results the model needs verbatim (session IDs, etc.).
    context_events = set(
        config.get(
            "skip_events",
            [
                "tool:pre",
                "tool:post",
            ],
        )
    )

    async def handler(event: str, data: dict[str, Any]) -> HookResult:
        if event in context_events:
            return HookResult(action="continue")
        try:
            redacted = scrub(data, rules, allowlist)
            if isinstance(redacted, dict):
                redacted["redaction"] = {"applied": True, "rules": rules}
                return HookResult(action="modify", data=redacted)
        except Exception as e:
            logger.debug(f"Redaction error: {e}")
        return HookResult(action="continue")

    # Subscribe to the canonical event set
    events = [
        "session:start",
        "session:end",
        "prompt:submit",
        "prompt:complete",
        "plan:start",
        "plan:end",
        "provider:request",
        "provider:response",
        "provider:error",
        # LLM text events — carry the actual content of LLM turns.
        #
        # These were previously missing from the subscription list, which meant
        # 100% of LLM text events reached events.jsonl without redaction applied:
        #
        #   llm:request      — full message history in data.raw.messages; each
        #                       message may include prior LLM turns that echoed
        #                       secrets back to the model.
        #   llm:response     — full API response in data.raw; content blocks in
        #                       data.raw.content[*].text carry the LLM's reply.
        #   content_block:end — the streamed LLM response text in data.block.text.
        #
        # The kernel's Modify-chain (hooks.rs:231) propagates redaction mutations
        # to all subsequent handlers including hooks-logging, so events.jsonl will
        # now contain redacted text after this fix. This also affects streaming-ui
        # rendering — secrets in LLM output will be masked at the terminal, which
        # is the correct default for privacy.
        #
        # scrub() already traverses arbitrary nested dicts/lists, so adding
        # these subscriptions is sufficient — no structural changes needed.
        "llm:request",
        "llm:response",
        "content_block:end",
        "tool:pre",
        "tool:post",
        "tool:error",
        "context:pre_compact",
        "context:post_compact",
        "artifact:write",
        "artifact:read",
        "policy:violation",
        "approval:required",
        "approval:granted",
        "approval:denied",
    ]
    for ev in events:
        coordinator.hooks.on(ev, handler, name="hooks-redaction", priority=priority)

    logger.info("Mounted hooks-redaction")
    return
