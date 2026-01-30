"""
Redaction hook: masks secrets/PII before logging.
Register with higher priority than logging.
"""

# Amplifier module metadata
__amplifier_module_type__ = "hook"

import logging
import re
from typing import Any

from amplifier_core import HookResult
from amplifier_core import ModuleCoordinator

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    # AWS
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
    re.compile(
        r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
    ),  # AWS Secret Key (40 char base64)
    # OpenAI
    re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),  # OpenAI project API key
    re.compile(r"sk-[A-Za-z0-9]{48,}"),  # OpenAI legacy API key
    # Anthropic
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),  # Anthropic API key
    # GitHub
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),  # GitHub personal access token
    re.compile(r"gho_[A-Za-z0-9]{36,}"),  # GitHub OAuth token
    re.compile(r"ghu_[A-Za-z0-9]{36,}"),  # GitHub user-to-server token
    re.compile(r"ghs_[A-Za-z0-9]{36,}"),  # GitHub server-to-server token
    re.compile(r"ghr_[A-Za-z0-9]{36,}"),  # GitHub refresh token
    re.compile(
        r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"
    ),  # GitHub fine-grained PAT
    # Slack/Google
    re.compile(r"xox[abpr]-[A-Za-z0-9-]+"),  # Slack tokens
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),  # Google API key
    # Azure
    re.compile(
        r"[A-Za-z0-9+/]{86}=="
    ),  # Azure storage/connection string key (64 bytes base64)
    re.compile(
        r"(?i)DefaultEndpointsProtocol=https?;[^\s\"']+"
    ),  # Azure connection string
    # Generic high-entropy secrets
    re.compile(
        r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)[\"'`]?\s*[:=]\s*[\"'`]?([A-Za-z0-9_-]{20,})[\"'`]?"
    ),  # key=value patterns
    # JWT
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    # Private keys (PEM format markers)
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),  # Private key header
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
        return {
            k: _scrub(v, rules, allowlist, f"{path}.{k}" if path else k)
            for k, v in obj.items()
        }
    return obj


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    config = config or {}
    rules = list(config.get("rules", ["secrets", "pii-basic"]))
    allowlist = list(config.get("allowlist", []))
    priority = int(config.get("priority", 10))

    async def handler(event: str, data: dict[str, Any]) -> HookResult:
        try:
            redacted = _scrub(data, rules, allowlist)
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
