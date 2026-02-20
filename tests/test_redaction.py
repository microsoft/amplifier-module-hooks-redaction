"""Module-specific tests for the redaction hook.

Tests the DEFAULT_ALLOWLIST behavior: structural event fields that contain
username-like strings (common in session IDs derived from filesystem paths)
must survive scrubbing untouched, while secrets/PII in other fields are
still redacted.
"""

from amplifier_module_hooks_redaction import DEFAULT_ALLOWLIST, _scrub


RULES = ["secrets", "pii-basic"]


class TestDefaultAllowlist:
    """Verify structural fields are protected by the default allowlist."""

    def test_session_id_with_username_survives(self):
        """A session_id containing a username fragment must not be redacted.

        Real-world case: session IDs are derived from project slugs which
        include filesystem paths like /home/colombod/..., producing IDs
        like 'colombod_abc123'. The email PII pattern matches 'colombod'
        as a local-part prefix, causing unwanted redaction.
        """
        event = {
            "session_id": "colombod_abc123_20260220",
            "parent_id": "colombod_parent_session",
            "timestamp": "2026-02-20T02:30:00Z",
            "turn_id": "turn_colombod_001",
            "span_id": "span_colombod_trace",
            "type": "session:start",
            "status": "active",
        }
        result = _scrub(event, RULES, DEFAULT_ALLOWLIST)

        # Every field here is in DEFAULT_ALLOWLIST — all must survive intact
        assert result["session_id"] == "colombod_abc123_20260220"
        assert result["parent_id"] == "colombod_parent_session"
        assert result["timestamp"] == "2026-02-20T02:30:00Z"
        assert result["turn_id"] == "turn_colombod_001"
        assert result["span_id"] == "span_colombod_trace"
        assert result["type"] == "session:start"
        assert result["status"] == "active"

    def test_pii_in_non_allowlisted_field_still_redacted(self):
        """Secrets and PII in regular fields must still be caught.

        This is the regression guard: the default allowlist must NOT
        weaken redaction for fields that aren't structural identifiers.
        """
        event = {
            "session_id": "colombod_abc123",  # allowlisted — survives
            "user_email": "alice@example.com",  # NOT allowlisted — redacted
            "message": "Contact bob@corp.net for access",  # NOT allowlisted — redacted
            "api_key": "AKIAIOSFODNN7EXAMPLE",  # NOT allowlisted — redacted
        }
        result = _scrub(event, RULES, DEFAULT_ALLOWLIST)

        # Allowlisted field survives
        assert result["session_id"] == "colombod_abc123"
        # Non-allowlisted fields are redacted
        assert result["user_email"] == "[REDACTED:PII]"
        assert "bob@corp.net" not in result["message"]
        assert "[REDACTED:PII]" in result["message"]
        assert "AKIAIOSFODNN7EXAMPLE" not in result["api_key"]
        assert "[REDACTED:SECRET]" in result["api_key"]


class TestUserConfigMerge:
    """Verify user-provided allowlist entries are unioned with defaults."""

    def test_user_entries_merged_with_defaults(self):
        """User config extends but never replaces the default allowlist.

        mount() computes: effective = DEFAULT_ALLOWLIST | set(config["allowlist"])
        Both sets of entries must be present in the result.
        """
        user_entries = {"my_custom_field", "another_field"}
        effective = DEFAULT_ALLOWLIST | user_entries

        # All default entries are still present
        assert "session_id" in effective
        assert "parent_id" in effective
        assert "turn_id" in effective
        assert "span_id" in effective

        # User entries are also present
        assert "my_custom_field" in effective
        assert "another_field" in effective

    def test_empty_user_config_yields_only_defaults(self):
        """When user provides no allowlist, effective == defaults."""
        effective = DEFAULT_ALLOWLIST | set([])
        assert effective == DEFAULT_ALLOWLIST

    def test_user_allowlist_protects_custom_field(self):
        """A user-added allowlist entry actually prevents redaction."""
        effective = DEFAULT_ALLOWLIST | {"custom_id"}
        event = {
            "session_id": "colombod_abc123",  # default allowlist
            "custom_id": "alice@example.com",  # user allowlist — survives despite PII match
            "notes": "alice@example.com",  # NOT allowlisted — redacted
        }
        result = _scrub(event, RULES, effective)

        assert result["session_id"] == "colombod_abc123"
        assert result["custom_id"] == "alice@example.com"  # protected by user entry
        assert result["notes"] == "[REDACTED:PII]"  # not protected
