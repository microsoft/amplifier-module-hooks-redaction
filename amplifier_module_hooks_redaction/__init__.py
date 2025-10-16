"""
Redaction hook: masks secrets/PII before logging.
Register with higher priority than logging.
"""

import logging
import re
from typing import Any

from amplifier_core import HookResult
from amplifier_core import ModuleCoordinator

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
    re.compile(r"(?:xox[abpr]-[A-Za-z0-9-]+|AIza[0-9A-Za-z-_]{35})"),  # Slack/Google keys
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
PII_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\+?\d[\d\s().-]{7,}\d"),
]


def _mask_text(s: str, rules: list[str]) -> str:
    out = s
    if "secrets" in rules:
        for pat in SECRET_PATTERNS:
            out = pat.sub("[REDACTED:SECRET]", out)
    if "pii-basic" in rules:
        for pat in PII_PATTERNS:
            out = pat.sub("[REDACTED:PII]", out)
    return out


def _scrub(obj: Any, rules: list[str], allowlist: list[str], path: str = "") -> Any:
    if path in allowlist:
        return obj
    if isinstance(obj, str):
        return _mask_text(obj, rules)
    if isinstance(obj, list):
        return [_scrub(v, rules, allowlist, f"{path}[{i}]") for i, v in enumerate(obj)]
    if isinstance(obj, dict):
        return {k: _scrub(v, rules, allowlist, f"{path}.{k}" if path else k) for k, v in obj.items()}
    return obj


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    config = config or {}
    rules = list(config.get("rules", ["secrets", "pii-basic"]))
    allowlist = list(config.get("allowlist", []))
    priority = int(config.get("priority", 10))

    async def handler(event: str, data: dict[str, Any]) -> HookResult:
        try:
            redacted = _scrub(data.get("data", data), rules, allowlist)
            if "data" in data:
                data["data"] = redacted
            else:
                if isinstance(redacted, dict):
                    data.clear()
                    data.update(redacted)
            data["redaction"] = {"applied": True, "rules": rules}
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
