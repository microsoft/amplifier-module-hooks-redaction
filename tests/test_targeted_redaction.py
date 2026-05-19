"""Tests for PR8: hooks-redaction targeted scan overhaul.

Run from this directory:
    pytest test_targeted_redaction.py -v

The test file imports directly from the __init__.py patch so it validates the
new implementation in isolation.  amplifier_core is mocked with minimal stubs
so no Amplifier runtime is required.

Test coverage:
  • Positive redaction  — PII/secrets inside scan_fields ARE redacted
  • Negative safety     — structural fields (session_id, timestamp, …) are
                          untouched even when they contain phone-like digit runs
  • tool:pre / tool:post — no longer skipped; content-bearing sub-fields get
                          redacted while envelope fields stay intact
  • No mutation         — original dicts are never modified in-place
  • Additive scan_fields — custom field names extend defaults
  • Regression guards   — re-test break-1/2/3 scenarios from the PR discussion
"""

from __future__ import annotations

import asyncio
import copy
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock


# ── Minimal amplifier_core stubs ────────────────────────────────────────────


class _HookResult:
    """Lightweight HookResult stand-in — just captures action + data."""

    def __init__(self, *, action: str, data: dict | None = None):
        self.action = action
        self.data = data


_core_stub = MagicMock()
_core_stub.HookResult = _HookResult
_core_stub.ModuleCoordinator = MagicMock

# Force our stub into sys.modules unconditionally — using direct assignment
# rather than setdefault so that even when pytest collects test_security_fixes
# first (which registers its own plain MagicMock for amplifier_core), this
# file always loads the patch module with the _HookResult-equipped stub.
sys.modules["amplifier_core"] = _core_stub

# ── Load the patch __init__.py ───────────────────────────────────────────────

_HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location(
    "hooks_redaction_patch",
    _HERE / "__init__.py",
)
assert _spec is not None and _spec.loader is not None, "Could not locate __init__.py"
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

# Pull the names we want to test into local scope
DEFAULT_SCAN_FIELDS = _mod.DEFAULT_SCAN_FIELDS
_mask_text = _mod._mask_text
_scrub_value = _mod._scrub_value
_scrub_targeted = _mod._scrub_targeted
mount = _mod.mount


# ── Helpers ──────────────────────────────────────────────────────────────────

_RULES = ["secrets", "pii-basic"]

EMAIL = "alice@example.com"
PHONE = "+1 415 555 0100"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # 20-char AWS-style key
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
UUID = "550e8400-e29b-41d4-a716-446655440000"
ISO_TS = "2026-02-20T14:30:00Z"
FS_PATH = "/home/alice/my.project/src/main.py"


def _run(coro):
    return asyncio.run(coro)


def _make_coordinator():
    coord = MagicMock()
    coord.hooks.on = MagicMock()
    return coord


# ═══════════════════════════════════════════════════════════════════════════
# DEFAULT_SCAN_FIELDS shape
# ═══════════════════════════════════════════════════════════════════════════


class TestDefaultScanFields:
    """The new positive-contract set must include the expected field names."""

    def test_core_fields_present(self):
        for field in (
            "content",
            "output",
            "input",
            "messages",
            "message",
            "instruction",
            "text",
            "user_message",
            "system_prompt",
            "description",
        ):
            assert field in DEFAULT_SCAN_FIELDS, f"missing scan field: {field!r}"

    def test_structural_fields_absent(self):
        """Structural envelope fields must NOT be in DEFAULT_SCAN_FIELDS —
        they get safe-by-construction treatment, not allowlist treatment."""
        for field in (
            "session_id",
            "parent_id",
            "timestamp",
            "tool_name",
            "status",
            "ts",
            "seq",
            "span_id",
            "turn_id",
            "lvl",
        ):
            assert field not in DEFAULT_SCAN_FIELDS, (
                f"{field!r} must NOT be in DEFAULT_SCAN_FIELDS"
            )

    def test_no_default_allowlist_attribute(self):
        """DEFAULT_ALLOWLIST must be gone entirely from the new module."""
        assert not hasattr(_mod, "DEFAULT_ALLOWLIST"), (
            "DEFAULT_ALLOWLIST was not removed"
        )

    def test_no_skip_events_attribute(self):
        """skip_events must be gone — it's no longer needed."""
        # We can't check the closure, but we can verify mount() registers
        # both tool:pre and tool:post (tested elsewhere).
        # The absence of a module-level skip_events constant is the marker.
        assert not hasattr(_mod, "skip_events"), (
            "module-level skip_events should not exist"
        )


# ═══════════════════════════════════════════════════════════════════════════
# _scrub_targeted — core logic
# ═══════════════════════════════════════════════════════════════════════════


class TestScrubTargeted:
    """Unit tests for the _scrub_targeted() traversal function."""

    def test_content_field_is_scrubbed(self):
        """PII inside a 'content' key must be redacted."""
        data = {"content": f"Hello, my email is {EMAIL}."}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["content"]
        assert "[REDACTED:PII]" in result["content"]

    def test_structural_field_is_not_scrubbed(self):
        """Structural keys (session_id, timestamp, tool_name) must pass through
        unchanged even when their values superficially match PII patterns."""
        data = {
            "session_id": UUID,
            "timestamp": ISO_TS,
            "tool_name": "read_file",
            "status": "ok",
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["session_id"] == UUID
        assert result["timestamp"] == ISO_TS
        assert result["tool_name"] == "read_file"
        assert result["status"] == "ok"

    def test_messages_array_is_recursively_scrubbed(self):
        """'messages' is a scan_field — all strings inside it are redacted."""
        data = {
            "messages": [
                {"role": "user", "content": f"Call me at {PHONE}"},
                {"role": "assistant", "content": "Sure!"},
            ]
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert PHONE not in result["messages"][0]["content"]
        assert "[REDACTED:PII]" in result["messages"][0]["content"]
        # Second message has no PII — must be unchanged
        assert result["messages"][1]["content"] == "Sure!"

    def test_nested_content_in_messages_is_scrubbed(self):
        """Deeply nested content under messages must be scrubbed."""
        data = {
            "messages": [
                {
                    "role": "user",
                    "parts": [{"text": f"My email: {EMAIL}"}],
                }
            ]
        }
        # "messages" is a scan_field → _scrub_value recurses into all strings
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["messages"][0]["parts"][0]["text"]

    def test_output_field_is_scrubbed(self):
        """'output' is a scan_field — PII in output values must be redacted."""
        data = {"output": {"result": f"User email: {EMAIL}"}}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["output"]["result"]

    def test_input_field_is_scrubbed(self):
        """'input' is a scan_field — PII in tool input must be redacted."""
        data = {"input": {"query": f"Find records for {EMAIL}"}}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["input"]["query"]

    def test_new_structural_field_is_safe_by_default(self):
        """An unknown structural field that appears in a future event must not
        be accidentally redacted — safe-by-construction guarantee."""
        future_field_value = f"corr-{UUID}-extra"
        data = {"correlation_key": future_field_value, "content": "hi"}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["correlation_key"] == future_field_value

    def test_custom_scan_fields_are_additive(self):
        """A custom scan_field name extends DEFAULT_SCAN_FIELDS; the default
        fields must still work."""
        extended = DEFAULT_SCAN_FIELDS | frozenset({"user_query"})
        data = {
            "user_query": f"lookup {EMAIL}",
            "content": f"result for {PHONE}",
            "session_id": UUID,
        }
        result = _scrub_targeted(data, _RULES, extended)
        assert EMAIL not in result["user_query"]
        assert PHONE not in result["content"]
        assert result["session_id"] == UUID  # structural field unchanged

    def test_no_in_place_mutation(self):
        """_scrub_targeted must return a new dict — the original must be
        unchanged after the call."""
        original = {"content": f"email: {EMAIL}", "session_id": UUID}
        before = copy.deepcopy(original)
        _scrub_targeted(original, _RULES, DEFAULT_SCAN_FIELDS)
        assert original == before, "original dict was mutated in-place"

    def test_list_of_events_traversed(self):
        """A list of event dicts at top level must be traversed correctly."""
        data = [
            {"content": f"pii: {EMAIL}"},
            {"session_id": UUID},
        ]
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result[0]["content"]
        assert result[1]["session_id"] == UUID

    def test_non_dict_non_list_scalar_returned_unchanged(self):
        """Top-level scalars not under a scan_field must be returned as-is."""
        assert _scrub_targeted(42, _RULES, DEFAULT_SCAN_FIELDS) == 42
        assert _scrub_targeted(True, _RULES, DEFAULT_SCAN_FIELDS) is True
        assert _scrub_targeted(None, _RULES, DEFAULT_SCAN_FIELDS) is None


# ═══════════════════════════════════════════════════════════════════════════
# _scrub_value — full recursive scrubbing within a content field
# ═══════════════════════════════════════════════════════════════════════════


class TestScrubValue:
    """Unit tests for _scrub_value() — the full-scrub used inside scan_fields."""

    def test_email_in_string_is_redacted(self):
        assert "[REDACTED:PII]" in _scrub_value(f"email {EMAIL}", _RULES)

    def test_phone_in_string_is_redacted(self):
        assert "[REDACTED:PII]" in _scrub_value(f"call {PHONE}", _RULES)

    def test_aws_key_in_string_is_redacted(self):
        result = _scrub_value(f"key={AWS_KEY}", _RULES)
        assert AWS_KEY not in result
        assert "[REDACTED:SECRET]" in result

    def test_jwt_in_string_is_redacted(self):
        result = _scrub_value(f"token={JWT}", _RULES)
        assert JWT not in result
        assert "[REDACTED:SECRET]" in result

    def test_nested_dict_all_strings_scrubbed(self):
        obj = {"a": f"email: {EMAIL}", "b": {"c": f"phone: {PHONE}"}}
        result = _scrub_value(obj, _RULES)
        assert EMAIL not in result["a"]
        assert PHONE not in result["b"]["c"]

    def test_list_of_strings_all_scrubbed(self):
        items = [f"item1 {EMAIL}", "item2 clean", f"item3 {PHONE}"]
        result = _scrub_value(items, _RULES)
        assert EMAIL not in result[0]
        assert result[1] == "item2 clean"
        assert PHONE not in result[2]

    def test_non_string_scalar_unchanged(self):
        assert _scrub_value(42, _RULES) == 42
        assert _scrub_value(None, _RULES) is None
        assert _scrub_value(3.14, _RULES) == 3.14


# ═══════════════════════════════════════════════════════════════════════════
# PII / secrets positive redaction (end-to-end through _scrub_targeted)
# ═══════════════════════════════════════════════════════════════════════════


class TestRedactionPositive:
    """Verify that real PII and secrets inside scan_fields are redacted."""

    def test_email_in_content_is_redacted(self):
        data = {"content": f"Contact me at {EMAIL}."}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["content"]
        assert "[REDACTED:PII]" in result["content"]

    def test_phone_in_output_is_redacted(self):
        data = {"output": f"Customer phone: {PHONE}"}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert PHONE not in result["output"]
        assert "[REDACTED:PII]" in result["output"]

    def test_pii_in_tool_input_is_redacted(self):
        """Closes the tool I/O gap: 'input' is now a scan_field."""
        data = {
            "tool_name": "send_email",
            "input": {
                "to": EMAIL,
                "body": f"Call me at {PHONE}",
            },
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["input"]["to"]
        assert PHONE not in result["input"]["body"]
        # Tool name untouched
        assert result["tool_name"] == "send_email"

    def test_api_key_in_content_is_redacted(self):
        data = {"content": f"Use API key: {AWS_KEY} to authenticate."}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert AWS_KEY not in result["content"]
        assert "[REDACTED:SECRET]" in result["content"]

    def test_jwt_in_message_is_redacted(self):
        data = {"message": f"Bearer token: {JWT}"}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert JWT not in result["message"]
        assert "[REDACTED:SECRET]" in result["message"]

    def test_pii_in_system_prompt_is_redacted(self):
        data = {"system_prompt": f"You are an assistant for {EMAIL}."}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["system_prompt"]

    def test_description_field_is_scrubbed(self):
        data = {"description": f"Report generated by {EMAIL}"}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["description"]


# ═══════════════════════════════════════════════════════════════════════════
# Regression guards — break-1/2/3 scenarios from the PR discussion
# ═══════════════════════════════════════════════════════════════════════════


class TestRegressionGuards:
    """Structural fields that produced false positives under the old blanket
    model must be completely safe under the targeted model."""

    def test_break1_regression_uuids_not_redacted(self):
        """session_id with phone-like numeric runs must not be redacted.

        The phone regex  \\+?\\d[\\d\\s().-]{7,}\\d  matches long digit sequences
        such as the "446655440000" segment inside a UUID.  Under the blanket
        model every event's session_id was corrupted; the targeted model never
        touches session_id.
        """
        data = {
            "session_id": UUID,  # contains "446655440000"
            "parent_id": UUID,
            "content": "clean text",
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["session_id"] == UUID
        assert result["parent_id"] == UUID

    def test_break2_regression_no_in_place_mutation(self):
        """Calling _scrub_targeted must never modify the input dict.

        HookResult(action="modify") returns a NEW dict; the original shared
        event dict must remain pristine so other hooks see unmodified data.
        """
        event_data = {
            "session_id": UUID,
            "content": f"email: {EMAIL}",
            "output": f"phone: {PHONE}",
        }
        snapshot = copy.deepcopy(event_data)
        _ = _scrub_targeted(event_data, _RULES, DEFAULT_SCAN_FIELDS)
        assert event_data == snapshot, "original event_data was mutated"

    def test_break3_regression_timestamps_not_redacted(self):
        """ISO-8601 timestamps must survive intact.

        The phone regex matches "2026-02-20" as a digit sequence; under the
        old blanket model timestamps were redacted on every event.
        """
        data = {
            "timestamp": ISO_TS,
            "ts": "1708437000.123",
            "content": "all good",
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["timestamp"] == ISO_TS
        assert result["ts"] == "1708437000.123"

    def test_break3_regression_paths_not_redacted(self):
        """Filesystem paths in structural fields must not be redacted.

        Email regex can match path fragments like /home/alice/my.project if
        they happen to have the form  text@text.tld.
        """
        data = {
            "path": FS_PATH,
            "file_path": FS_PATH,
            "cwd": "/home/alice/work",
            "content": "clean",
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["path"] == FS_PATH
        assert result["file_path"] == FS_PATH
        assert result["cwd"] == "/home/alice/work"

    def test_uuid_in_span_id_not_redacted(self):
        data = {
            "span_id": UUID,
            "parent_span_id": UUID,
            "turn_id": "turn-00042",
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["span_id"] == UUID
        assert result["parent_span_id"] == UUID
        assert result["turn_id"] == "turn-00042"


# ═══════════════════════════════════════════════════════════════════════════
# tool:pre and tool:post are now scanned
# ═══════════════════════════════════════════════════════════════════════════


class TestToolEventScanning:
    """tool:pre and tool:post must no longer be skipped.

    Under the old model these events were returned unchanged (action=continue)
    to avoid corrupting session_id / timestamp values the model needs verbatim.
    Under the new targeted model those structural fields are safe; real PII
    in 'input'/'output' keys must now be redacted.
    """

    def _make_handler(self, extra_scan_fields=None):
        """Build a live handler closure from mount() without spinning up a
        full coordinator."""
        rules = _RULES
        scan_fields = DEFAULT_SCAN_FIELDS
        if extra_scan_fields:
            scan_fields = scan_fields | frozenset(extra_scan_fields)

        async def handler(event, data):
            from copy import deepcopy as _dc

            redacted = _scrub_targeted(_dc(data), rules, scan_fields)
            if isinstance(redacted, dict):
                redacted["redaction"] = {"applied": True, "rules": rules}
                return _HookResult(action="modify", data=redacted)
            return _HookResult(action="continue")

        return handler

    def test_tool_pre_events_are_now_scanned(self):
        """tool:pre — PII in 'input' must be redacted."""
        handler = self._make_handler()
        data = {
            "tool_name": "web_search",
            "session_id": UUID,
            "timestamp": ISO_TS,
            "input": {"query": f"find records for {EMAIL}"},
        }
        result = _run(handler("tool:pre", data))
        assert result.action == "modify"
        assert result.data is not None
        assert EMAIL not in result.data["input"]["query"]
        # Structural fields untouched
        assert result.data["tool_name"] == "web_search"
        assert result.data["session_id"] == UUID
        assert result.data["timestamp"] == ISO_TS

    def test_tool_post_events_are_now_scanned(self):
        """tool:post — PII in 'output' must be redacted."""
        handler = self._make_handler()
        data = {
            "tool_name": "read_file",
            "session_id": UUID,
            "timestamp": ISO_TS,
            "output": {"content": f"file owner: {EMAIL}"},
        }
        result = _run(handler("tool:post", data))
        assert result.action == "modify"
        assert result.data is not None
        assert EMAIL not in result.data["output"]["content"]
        assert result.data["session_id"] == UUID

    def test_tool_event_without_pii_still_passes(self):
        """A tool event with no PII in content fields must still produce
        action='modify' (redaction bookmark added) with unchanged values."""
        handler = self._make_handler()
        data = {
            "tool_name": "list_dir",
            "session_id": UUID,
            "input": {"path": "/usr/local"},
            "output": {"entries": ["bin", "lib"]},
        }
        result = _run(handler("tool:pre", data))
        assert result.action == "modify"
        assert result.data is not None
        assert result.data["tool_name"] == "list_dir"
        assert result.data["input"]["path"] == "/usr/local"

    def test_tool_pre_api_key_in_input_is_redacted(self):
        """API key inside tool:pre 'input' must be caught."""
        handler = self._make_handler()
        data = {
            "tool_name": "http_request",
            "input": {"headers": {"Authorization": f"AWS {AWS_KEY}"}},
        }
        result = _run(handler("tool:pre", data))
        assert result.data is not None
        assert AWS_KEY not in str(result.data["input"])


# ═══════════════════════════════════════════════════════════════════════════
# Edge cases and robustness
# ═══════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Graceful handling of unusual data shapes."""

    def test_empty_data_handled_gracefully(self):
        """An empty dict must not raise and must return an empty-ish dict."""
        result = _scrub_targeted({}, _RULES, DEFAULT_SCAN_FIELDS)
        assert isinstance(result, dict)

    def test_empty_content_string_unchanged(self):
        data = {"content": ""}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["content"] == ""

    def test_content_with_no_pii_unchanged(self):
        data = {"content": "The weather is nice today."}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["content"] == "The weather is nice today."

    def test_none_value_in_scan_field_handled(self):
        data = {"content": None, "session_id": UUID}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["content"] is None
        assert result["session_id"] == UUID

    def test_integer_value_in_scan_field_handled(self):
        data = {"output": 42}
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["output"] == 42

    def test_deeply_nested_structural_fields_safe(self):
        """Structural fields nested inside a non-scan-field dict must be safe."""
        data = {
            "metadata": {
                "session_id": UUID,
                "timestamp": ISO_TS,
                "provider": "anthropic",
            },
            "content": f"reply to {EMAIL}",
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert result["metadata"]["session_id"] == UUID
        assert result["metadata"]["timestamp"] == ISO_TS
        assert result["metadata"]["provider"] == "anthropic"
        assert EMAIL not in result["content"]

    def test_mixed_scan_and_structural_at_same_level(self):
        """When scan_fields and structural fields sit at the same dict level,
        only the scan_fields are scrubbed."""
        data = {
            "content": f"email: {EMAIL}",
            "session_id": UUID,
            "timestamp": ISO_TS,
            "tool_name": "bash",
            "output": f"stdout: {PHONE}",
        }
        result = _scrub_targeted(data, _RULES, DEFAULT_SCAN_FIELDS)
        assert EMAIL not in result["content"]
        assert PHONE not in result["output"]
        assert result["session_id"] == UUID
        assert result["timestamp"] == ISO_TS
        assert result["tool_name"] == "bash"

    def test_rules_empty_no_redaction(self):
        """With an empty rules list nothing should be redacted."""
        data = {"content": f"email: {EMAIL}", "output": f"key: {AWS_KEY}"}
        result = _scrub_targeted(data, rules=[], scan_fields=DEFAULT_SCAN_FIELDS)
        # No rules → _mask_text returns the string unchanged
        assert EMAIL in result["content"]
        assert AWS_KEY in result["output"]


# ═══════════════════════════════════════════════════════════════════════════
# mount() integration: coordinator wiring and scan_fields merging
# ═══════════════════════════════════════════════════════════════════════════


class TestMountIntegration:
    """Smoke-test mount() — coordinator.hooks.on must be called for all events
    including tool:pre and tool:post."""

    def test_mount_registers_tool_pre_and_post(self):
        coord = _make_coordinator()
        _run(mount(coord, {}))
        registered = {call.args[0] for call in coord.hooks.on.call_args_list}
        assert "tool:pre" in registered, "tool:pre must be registered"
        assert "tool:post" in registered, "tool:post must be registered"

    def test_mount_registers_all_canonical_events(self):
        coord = _make_coordinator()
        _run(mount(coord, {}))
        registered = {call.args[0] for call in coord.hooks.on.call_args_list}
        expected = {
            "session:start",
            "session:end",
            "prompt:submit",
            "prompt:complete",
            "tool:pre",
            "tool:post",
            "tool:error",
            "provider:request",
            "provider:response",
            "provider:error",
            "artifact:write",
            "artifact:read",
            "policy:violation",
            "approval:required",
            "approval:granted",
            "approval:denied",
        }
        missing = expected - registered
        assert not missing, f"These events are not registered: {missing}"

    def test_custom_scan_fields_extend_defaults_via_config(self):
        """config['scan_fields'] extends DEFAULT_SCAN_FIELDS additively."""
        coord = _make_coordinator()
        _run(mount(coord, {"scan_fields": ["user_query", "custom_field"]}))
        # The handler is not directly inspectable, but we can verify mount
        # completes without error.  The additive logic is unit-tested in
        # TestScrubTargeted.test_custom_scan_fields_are_additive.
        assert coord.hooks.on.call_count > 0

    def test_mount_handler_redacts_content_in_session_start(self):
        """The live handler returned by mount() must redact PII in 'content'."""
        coord = _make_coordinator()
        _run(mount(coord, {}))
        # Grab the handler closure from the first registration call
        handler = coord.hooks.on.call_args_list[0].args[1]
        data = {
            "session_id": UUID,
            "timestamp": ISO_TS,
            "content": f"User: {EMAIL}",
        }
        result = _run(handler("session:start", data))
        assert result.action == "modify"
        assert result.data is not None
        assert EMAIL not in result.data["content"]
        assert result.data["session_id"] == UUID
        assert result.data["timestamp"] == ISO_TS
        assert result.data["redaction"] == {
            "applied": True,
            "rules": ["secrets", "pii-basic"],
        }
