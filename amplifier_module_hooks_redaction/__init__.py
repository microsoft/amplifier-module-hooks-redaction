"""
Redaction hook: masks secrets/PII in event data for logging.
Register with higher priority than logging.

Uses HookResult(action="modify") to return redacted copies rather than
mutating the shared event data dict in-place.

PR8 overhaul — invert scanning model
======================================

OLD approach (blanket scan + allowlist):
    _scrub() walked the entire event dict and redacted every string it found,
    with a DEFAULT_ALLOWLIST of structural field names (session_id, timestamp,
    tool_name, …) that were skipped to prevent false-positive PII redaction.
    tool:pre and tool:post events were skipped entirely to avoid corrupting
    tool I/O the model needs verbatim — creating a gap where PII in tool
    inputs and outputs was never redacted.

    Problems:
    • Every new structural field had to be manually added to the allowlist or
      it would be redacted by the phone/email regexes (ISO timestamps look like
      phone numbers; UUID hex segments trigger the phone pattern; filesystem
      paths with dots trigger the email pattern).
    • The skip_events gap meant real PII in tool:pre / tool:post "input" and
      "output" payloads was never redacted — the very events most likely to
      carry user-provided data.

NEW approach (targeted content-field scan):
    _scrub_targeted() only applies redaction to values whose dict KEY is in
    DEFAULT_SCAN_FIELDS ("content", "input", "output", "messages", …).
    Everything else is traversed but scalars are left untouched.

    Benefits:
    • Structural fields (session_id, timestamp, tool_name, …) are safe by
      construction — they are never inside a scan_field key — no allowlist
      needed, no false positives.
    • tool:pre and tool:post are now fully scanned because _scrub_targeted
      only touches the "input"/"output"/"content" keys inside them, leaving
      the envelope fields intact.
    • The scan_fields set is additive-only at mount() time: users extend
      DEFAULT_SCAN_FIELDS but cannot reduce it.
"""

from __future__ import annotations

# Amplifier module metadata
__amplifier_module_type__ = "hook"

import logging
import re
from collections.abc import Set as AbstractSet
from typing import Any

from amplifier_core import HookResult  # type: ignore[import-untyped]
from amplifier_core import ModuleCoordinator  # type: ignore[import-untyped]

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
# PR8: DEFAULT_SCAN_FIELDS — replaces DEFAULT_ALLOWLIST entirely.
#
# WHAT: The set of dict-key names that carry free-form, user- or LLM-authored
#       text.  Only values under these keys are passed through _scrub_value();
#       all other keys traverse into nested dicts/lists but their scalar
#       values are returned unchanged.
#
# WHY:  Scanning content-bearing fields is the correct abstraction.  The old
#       allowlist was an inverted safety net that required enumerating every
#       structural field to protect it.  This set is the positive contract:
#       "these fields may carry PII — check them".
#
# HOW:  config["scan_fields"] at mount() time is unioned with the defaults so
#       integrators can register custom field names (e.g. "user_query") without
#       reducing core coverage.
# ---------------------------------------------------------------------------
DEFAULT_SCAN_FIELDS: frozenset[str] = frozenset(
    {
        "content",
        "message",
        "messages",
        "output",
        "input",
        "instruction",
        "text",
        "user_message",
        "system_prompt",
        "description",
    }
)


def _mask_text(s: str, rules: list[str]) -> str:
    """Apply active redaction rules to a single string value."""
    out = s
    if "secrets" in rules:
        for pat in SECRET_PATTERNS:
            out = pat.sub("[REDACTED:SECRET]", out)
    if "pii-basic" in rules:
        for pat in PII_PATTERNS:
            out = pat.sub("[REDACTED:PII]", out)
    return out


def _scrub_value(obj: Any, rules: list[str]) -> Any:
    """Recursively redact every string within a content-bearing value.

    Called once a scan_field key has been identified.  The value may be a
    plain string, a list of message dicts, or any arbitrarily nested
    structure — every string leaf is passed through _mask_text().

    This function does NOT check scan_fields; it assumes the caller has
    already determined that the entire subtree should be scrubbed.
    """
    if isinstance(obj, str):
        return _mask_text(obj, rules)
    if isinstance(obj, list):
        return [_scrub_value(v, rules) for v in obj]
    if isinstance(obj, dict):
        return {k: _scrub_value(v, rules) for k, v in obj.items()}
    return obj


def _scrub_targeted(
    obj: Any,
    rules: list[str],
    scan_fields: AbstractSet[str],
    key: str = "",
) -> Any:
    """Targeted scrub: only redact values under known content-carrying fields.

    Traversal contract:
    ┌─────────────────────────────────────────────────────────────────────┐
    │ dict  → for each (k, v):                                            │
    │           k in scan_fields → fully scrub v via _scrub_value()       │
    │           otherwise        → recurse into v (structural traversal)  │
    │ list  → recurse into each element (key context preserved)           │
    │ other → return unchanged   ← structural scalars never redacted      │
    └─────────────────────────────────────────────────────────────────────┘

    This means structural scalars (IDs, timestamps, counts, booleans)
    sitting directly in a dict are NEVER touched unless their parent key
    is a scan_field.  The phone and email regexes cannot produce false
    positives on session_id, timestamp, tool_name, etc.
    """
    if isinstance(obj, dict):
        return {
            k: _scrub_value(v, rules)
            if k in scan_fields
            else _scrub_targeted(v, rules, scan_fields, k)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_scrub_targeted(v, rules, scan_fields, key) for v in obj]
    # Scalar not under a scan_field key — return as-is.
    return obj


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    config = config or {}
    rules = list(config.get("rules", ["secrets", "pii-basic"]))

    # PR8: scan_fields is additive — integrators extend DEFAULT_SCAN_FIELDS,
    # they cannot reduce it.  This is the symmetric counterpart to the old
    # allowlist that was also additive.
    scan_fields: AbstractSet[str] = DEFAULT_SCAN_FIELDS | frozenset(
        config.get("scan_fields", [])
    )
    priority = int(config.get("priority", 10))

    async def handler(event: str, data: dict[str, Any]) -> HookResult:
        # PR8: NO skip_events / context_events guard.
        #
        # tool:pre and tool:post no longer need to be skipped because
        # _scrub_targeted only touches content-bearing keys ("input",
        # "output", "content", …).  Structural envelope fields
        # (session_id, timestamp, tool_name, status, …) are left intact
        # by construction — they are not scan_field keys.
        #
        # Removing the skip closes the security gap where PII in tool
        # inputs and outputs was never redacted.
        try:
            redacted = _scrub_targeted(data, rules, scan_fields)
            if isinstance(redacted, dict):
                redacted["redaction"] = {"applied": True, "rules": rules}
                return HookResult(action="modify", data=redacted)
        except Exception as e:
            logger.debug(f"Redaction error: {e}")
        return HookResult(action="continue")

    # Subscribe to the canonical event set.
    # tool:pre and tool:post are included and no longer bypassed.
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
