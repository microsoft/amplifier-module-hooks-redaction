"""Tests for secret and PII pattern matching.

These tests validate the regex patterns without requiring amplifier_core.
"""

import pytest

# Import patterns directly from the module
from amplifier_module_hooks_redaction import _mask_text


class TestSecretPatterns:
    """Test that secret patterns correctly identify various API keys and tokens."""

    @pytest.mark.parametrize(
        "secret,description",
        [
            # AWS
            ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID"),
            # OpenAI
            (
                "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234",
                "OpenAI project key",
            ),
            (
                "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL",
                "OpenAI legacy key",
            ),
            # Anthropic
            ("sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "Anthropic API key"),
            # GitHub
            ("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GitHub PAT"),
            ("gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GitHub OAuth"),
            ("ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GitHub user-to-server"),
            ("ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GitHub server-to-server"),
            ("ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GitHub refresh token"),
            # Slack tokens tested separately to avoid GitHub push protection
            # Google
            ("AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe", "Google API key"),
            # JWT
            (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "JWT",
            ),
            # Private key header
            ("-----BEGIN RSA PRIVATE KEY-----", "RSA private key header"),
            ("-----BEGIN PRIVATE KEY-----", "Generic private key header"),
            ("-----BEGIN EC PRIVATE KEY-----", "EC private key header"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key header"),
        ],
    )
    def test_secret_is_redacted(self, secret: str, description: str):
        """Test that known secret formats are redacted."""
        result = _mask_text(f"The key is {secret} here", ["secrets"])
        assert secret not in result, f"{description} should be redacted"
        assert "[REDACTED:SECRET]" in result, (
            f"{description} should show redaction marker"
        )

    @pytest.mark.parametrize(
        "text,description",
        [
            ("This is a normal message", "Normal text"),
            ("The password is hunter2", "Generic password (not pattern-matched)"),
            ("sk-short", "Too-short sk- prefix"),
            ("ghp_short", "Too-short GitHub token"),
        ],
    )
    def test_non_secrets_not_redacted(self, text: str, description: str):
        """Test that normal text is not incorrectly redacted."""
        result = _mask_text(text, ["secrets"])
        assert "[REDACTED:SECRET]" not in result, (
            f"{description} should not be redacted"
        )

    def test_slack_tokens(self):
        """Test Slack token patterns (constructed dynamically to avoid push protection)."""
        # Build tokens programmatically so they don't trigger GitHub's scanner
        bot_token = "xoxb" + "-" + "000000000000-0000000000000-ABCDEFGHIJKLMNOPQRSTUVWX"
        user_token = "xoxp" + "-" + "000000000000-0000000000000-ABCDEFGHIJKLMNOPQRSTUVWX"

        for token, desc in [(bot_token, "bot"), (user_token, "user")]:
            result = _mask_text(f"Token: {token}", ["secrets"])
            assert token not in result, f"Slack {desc} token should be redacted"
            assert "[REDACTED:SECRET]" in result

    def test_key_value_patterns(self):
        """Test generic key=value pattern matching."""
        test_cases = [
            'api_key = "sk_test_abcdefghijklmnopqrstuvwxyz"',
            "API_KEY=abcdefghijklmnopqrstuvwxyz12345",
            'secret_key: "myverysecretkey12345678"',
            "access_token=abc123def456ghi789jkl012",
        ]
        for text in test_cases:
            result = _mask_text(text, ["secrets"])
            assert "[REDACTED:SECRET]" in result, (
                f"Key-value pattern should be redacted: {text}"
            )


class TestPIIPatterns:
    """Test that PII patterns correctly identify personal information."""

    @pytest.mark.parametrize(
        "pii,description",
        [
            ("user@example.com", "Email address"),
            ("test.user+tag@subdomain.example.co.uk", "Complex email"),
            ("+1 555-123-4567", "US phone number"),
            ("(555) 123-4567", "US phone with parens"),
            ("+44 20 7946 0958", "UK phone number"),
        ],
    )
    def test_pii_is_redacted(self, pii: str, description: str):
        """Test that PII is redacted."""
        result = _mask_text(f"Contact: {pii}", ["pii-basic"])
        assert pii not in result, f"{description} should be redacted"
        assert "[REDACTED:PII]" in result, f"{description} should show redaction marker"


class TestCombinedRules:
    """Test that multiple rules work together."""

    def test_both_secrets_and_pii_redacted(self):
        """Test that both secrets and PII are redacted when both rules are active."""
        text = "Send the key sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234 to user@example.com"
        result = _mask_text(text, ["secrets", "pii-basic"])
        assert "[REDACTED:SECRET]" in result
        assert "[REDACTED:PII]" in result
        assert "sk-proj-" not in result
        assert "@example.com" not in result

    def test_only_secrets_rule(self):
        """Test that only secrets are redacted when pii-basic is not included."""
        text = "Key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234, Email: user@example.com"
        result = _mask_text(text, ["secrets"])
        assert "[REDACTED:SECRET]" in result
        assert "[REDACTED:PII]" not in result
        assert "user@example.com" in result  # Email should still be there
