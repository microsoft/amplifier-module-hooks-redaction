"""
Redaction hook: masks secrets/PII in event data for logging.
Register with higher priority than logging.

Uses HookResult(action="modify") to return redacted copies rather than
mutating the shared event data dict in-place. Events that feed back into
LLM context (tool:pre, tool:post) are skipped to avoid corrupting tool
results the model needs verbatim (e.g. session IDs, timestamps).
"""

from __future__ import annotations

# Amplifier module metadata
__amplifier_module_type__ = "hook"

import logging
import re
from collections.abc import Set as AbstractSet
from typing import Any

from amplifier_core import HookResult
from amplifier_core import ModuleCoordinator

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
    re.compile(
        r"(?:xox[abpr]-[A-Za-z0-9-]+|AIza[0-9A-Za-z-_]{35})"
    ),  # Slack/Google keys
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
PII_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\+?\d[\d\s().-]{7,}\d"),
]

# ---------------------------------------------------------------------------
# Default allowlist — structural event fields that must never be redacted.
#
# WHAT: These are infrastructure/envelope fields used for session correlation,
#       lineage tracking, event ordering, and trace identification.
#
# WHY:  Two PII regex patterns produce systematic false positives on these
#       structural fields:
#
#       1. Phone regex  \+?\d[\d\s().-]{7,}\d  matches ISO timestamps
#          (e.g. "2026-02-20T14:30:00Z" → "2026-02-20" triggers the pattern)
#          and numeric runs inside UUIDs (e.g. "446655440000" inside
#          "550e8400-e29b-41d4-a716-446655440000"). Every event carries a
#          timestamp from the kernel's emit(), so without the allowlist every
#          event's timestamp is replaced with [REDACTED:PII].
#
#       2. Email regex  [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
#          can match username fragments when project slugs derived from
#          filesystem paths (e.g. /home/user/my.project) carry dot-separated
#          segments into event fields that happen to resemble local-part@domain.
#
#       Together these cause critical identifiers to display as [REDACTED:PII],
#       breaking event correlation, session lineage trees, and trace
#       verification.
#
# HOW:  These defaults are merged (union) with user-provided
#       config["allowlist"] entries at mount() time. Users extend but never
#       replace the defaults.
# ---------------------------------------------------------------------------
DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Infrastructure envelope — present on every event via emit().
        # session_id and parent_id are the primary keys for event correlation
        # and session lineage.
        "session_id",
        "parent_id",
        "timestamp",
        # Session lineage — parent ID in session:fork events
        "parent",
        # Event classification
        "lvl",
        "level",
        # Correlation identifiers — join related events across the lifecycle
        "tool_name",
        "provider",
        "orchestrator",
        "status",
        # Streaming envelope
        "type",
        "ts",
        "seq",
        "turn_id",
        "span_id",
        "parent_span_id",
    }
)


def _mask_text(s: str, rules: list[str]) -> str:
    out = s
    if "secrets" in rules:
        for pat in SECRET_PATTERNS:
            out = pat.sub("[REDACTED:SECRET]", out)
    if "pii-basic" in rules:
        for pat in PII_PATTERNS:
            out = pat.sub("[REDACTED:PII]", out)
    return out


def _scrub(
    obj: Any, rules: list[str], allowlist: AbstractSet[str], path: str = ""
) -> Any:
    if path in allowlist:
        return obj
    if isinstance(obj, str):
        return _mask_text(obj, rules)
    if isinstance(obj, list):
        return [_scrub(v, rules, allowlist, f"{path}[{i}]") for i, v in enumerate(obj)]
    if isinstance(obj, dict):
        return {
            k: _scrub(v, rules, allowlist, f"{path}.{k}" if path else k)
            for k, v in obj.items()
        }
    return obj


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
            redacted = _scrub(data, rules, allowlist)
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
        # _scrub() already traverses arbitrary nested dicts/lists, so adding
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
