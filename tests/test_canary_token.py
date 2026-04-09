"""
Test suite for honeypots.canary_token
======================================
Covers token generation, registry operations, trigger reporting, stats,
export, edge cases, and data integrity checks.

Run with::

    pytest tests/test_canary_token.py -v
"""

from __future__ import annotations

import sys
import os
import time

import pytest

# Allow imports from the project root regardless of working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from honeypots.canary_token import (
    CanaryAlert,
    CanaryRegistry,
    CanaryToken,
    TokenType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def registry() -> CanaryRegistry:
    """Fresh registry with a predictable base URL for every test."""
    return CanaryRegistry(callback_base_url="https://canary.example.com/alert")


@pytest.fixture
def all_tokens(registry: CanaryRegistry):
    """One token of every type in a single registry."""
    tokens = {}
    for token_type in TokenType:
        tokens[token_type] = registry.create_token(
            token_type=token_type,
            label=f"test-{token_type.value.lower()}",
            owner="test-suite",
        )
    return registry, tokens


# ===========================================================================
# 1. TokenType enum
# ===========================================================================

class TestTokenTypeEnum:
    def test_all_five_variants_exist(self):
        variants = {t.value for t in TokenType}
        assert variants == {"HTTP_URL", "API_KEY", "CRED_PAIR", "ENV_VAR", "DOC_EMBED"}

    def test_enum_members_accessible_by_name(self):
        assert TokenType["HTTP_URL"] == TokenType.HTTP_URL
        assert TokenType["API_KEY"] == TokenType.API_KEY
        assert TokenType["CRED_PAIR"] == TokenType.CRED_PAIR
        assert TokenType["ENV_VAR"] == TokenType.ENV_VAR
        assert TokenType["DOC_EMBED"] == TokenType.DOC_EMBED


# ===========================================================================
# 2. CanaryToken dataclass — structure & defaults
# ===========================================================================

class TestCanaryTokenStructure:
    def test_token_id_is_32_hex_chars(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "test-label")
        assert len(token.token_id) == 32
        assert all(c in "0123456789abcdef" for c in token.token_id)

    def test_default_owner_is_empty_string(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "no-owner")
        assert token.owner == ""

    def test_default_tags_is_empty_list(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "no-tags")
        assert token.tags == []

    def test_tags_stored_correctly(self, registry: CanaryRegistry):
        token = registry.create_token(
            TokenType.API_KEY, "tagged", tags=["prod", "aws"]
        )
        assert "prod" in token.tags
        assert "aws" in token.tags
        assert len(token.tags) == 2

    def test_created_at_is_float(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.DOC_EMBED, "created-at-test")
        assert isinstance(token.created_at, float)

    def test_created_at_is_recent(self, registry: CanaryRegistry):
        before = time.time()
        token = registry.create_token(TokenType.DOC_EMBED, "timing-test")
        after = time.time()
        assert before <= token.created_at <= after

    def test_triggered_defaults_to_false(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "untriggered")
        assert token.triggered is False

    def test_triggered_at_defaults_to_none(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "untriggered-at")
        assert token.triggered_at is None

    def test_trigger_count_defaults_to_zero(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "zero-count")
        assert token.trigger_count == 0

    def test_owner_is_stored(self, registry: CanaryRegistry):
        token = registry.create_token(
            TokenType.CRED_PAIR, "owner-test", owner="security-team"
        )
        assert token.owner == "security-team"


# ===========================================================================
# 3. Token value formats — one class per type
# ===========================================================================

class TestHTTPURLToken:
    def test_value_starts_with_base_url(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.HTTP_URL, "url-test")
        assert token.value.startswith("https://canary.example.com/alert/")

    def test_value_ends_with_token_id(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.HTTP_URL, "url-id-test")
        assert token.value.endswith(token.token_id)

    def test_value_is_valid_url_structure(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.HTTP_URL, "url-structure")
        # Should have scheme and path
        assert "://" in token.value
        assert "/" in token.value.split("://", 1)[1]


class TestAPIKeyToken:
    def test_value_starts_with_ctkn(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "apikey-test")
        assert token.value.startswith("CTKN")

    def test_value_total_length(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "apikey-len")
        # CTKN (4) + 40 hex chars = 44
        assert len(token.value) == 44

    def test_value_suffix_is_uppercase_hex(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "apikey-hex")
        suffix = token.value[4:]  # strip CTKN prefix
        assert suffix == suffix.upper()
        assert all(c in "0123456789ABCDEF" for c in suffix)


class TestCredPairToken:
    def test_value_contains_colon_separator(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.CRED_PAIR, "cred-test")
        assert ":" in token.value

    def test_username_starts_with_canary_(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.CRED_PAIR, "cred-user")
        username = token.value.split(":")[0]
        assert username.startswith("canary_")

    def test_password_is_nonempty(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.CRED_PAIR, "cred-pass")
        password = token.value.split(":", 1)[1]
        assert len(password) > 0

    def test_exactly_one_colon_separates_user_and_pass(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.CRED_PAIR, "cred-split")
        parts = token.value.split(":", 1)
        assert len(parts) == 2


class TestEnvVarToken:
    def test_value_starts_with_ctk_(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "env-test")
        assert token.value.startswith("ctk_")

    def test_value_suffix_length(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "env-len")
        suffix = token.value[4:]  # strip ctk_
        # secrets.token_hex(24) → 48 hex chars
        assert len(suffix) == 48

    def test_value_suffix_is_lowercase_hex(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "env-hex")
        suffix = token.value[4:]
        assert all(c in "0123456789abcdef" for c in suffix)


class TestDocEmbedToken:
    def test_value_contains_canary_prefix(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.DOC_EMBED, "doc-test")
        assert "CANARY:" in token.value

    def test_value_is_html_comment(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.DOC_EMBED, "doc-html")
        assert token.value.startswith("<!--")
        assert token.value.endswith("-->")

    def test_value_embeds_token_id(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.DOC_EMBED, "doc-id")
        assert token.token_id in token.value


# ===========================================================================
# 4. Token uniqueness and determinism
# ===========================================================================

class TestTokenUniqueness:
    def test_ten_token_ids_are_all_unique(self, registry: CanaryRegistry):
        ids = [
            registry.create_token(TokenType.API_KEY, f"bulk-{i}").token_id
            for i in range(10)
        ]
        assert len(set(ids)) == 10

    def test_ten_api_key_values_are_all_unique(self, registry: CanaryRegistry):
        values = [
            registry.create_token(TokenType.API_KEY, f"vals-{i}").value
            for i in range(10)
        ]
        assert len(set(values)) == 10

    def test_fingerprint_is_deterministic(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "fp-test")
        fp1 = token.fingerprint()
        fp2 = token.fingerprint()
        assert fp1 == fp2

    def test_fingerprint_is_16_hex_chars(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.DOC_EMBED, "fp-len")
        fp = token.fingerprint()
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_different_tokens_have_different_fingerprints(
        self, registry: CanaryRegistry
    ):
        t1 = registry.create_token(TokenType.API_KEY, "fp-a")
        t2 = registry.create_token(TokenType.API_KEY, "fp-b")
        assert t1.fingerprint() != t2.fingerprint()


# ===========================================================================
# 5. CanaryToken.summary() and to_dict()
# ===========================================================================

class TestCanaryTokenMethods:
    def test_summary_contains_short_token_id(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "summary-test")
        assert token.token_id[:8] in token.summary()

    def test_summary_contains_token_type_value(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.CRED_PAIR, "summary-type")
        assert "CRED_PAIR" in token.summary()

    def test_summary_contains_label(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.HTTP_URL, "my-special-label")
        assert "my-special-label" in token.summary()

    def test_to_dict_has_all_required_keys(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "dict-keys")
        d = token.to_dict()
        required = {
            "token_id", "token_type", "value", "label", "owner",
            "tags", "created_at", "triggered", "triggered_at", "trigger_count",
        }
        assert required.issubset(d.keys())

    def test_to_dict_token_type_is_string(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "dict-type-str")
        d = token.to_dict()
        assert isinstance(d["token_type"], str)
        assert d["token_type"] == "ENV_VAR"

    def test_to_dict_created_at_is_float(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.DOC_EMBED, "dict-float")
        d = token.to_dict()
        assert isinstance(d["created_at"], float)

    def test_to_dict_tags_is_list(self, registry: CanaryRegistry):
        token = registry.create_token(
            TokenType.API_KEY, "dict-tags", tags=["a", "b"]
        )
        d = token.to_dict()
        assert isinstance(d["tags"], list)
        assert d["tags"] == ["a", "b"]


# ===========================================================================
# 6. Registry operations
# ===========================================================================

class TestRegistryOperations:
    def test_get_token_returns_correct_token(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "get-test")
        fetched = registry.get_token(token.token_id)
        assert fetched is not None
        assert fetched.token_id == token.token_id

    def test_get_token_unknown_id_returns_none(self, registry: CanaryRegistry):
        result = registry.get_token("0" * 32)
        assert result is None

    def test_list_tokens_count_matches_created(self, registry: CanaryRegistry):
        for i in range(5):
            registry.create_token(TokenType.ENV_VAR, f"list-{i}")
        assert len(registry.list_tokens()) == 5

    def test_list_tokens_returns_all_types(self, all_tokens):
        registry, tokens = all_tokens
        listed_ids = {t.token_id for t in registry.list_tokens()}
        for tok in tokens.values():
            assert tok.token_id in listed_ids

    def test_list_triggered_empty_when_none_triggered(
        self, registry: CanaryRegistry
    ):
        registry.create_token(TokenType.API_KEY, "no-trigger")
        assert registry.list_triggered() == []

    def test_list_triggered_filters_correctly(self, registry: CanaryRegistry):
        t1 = registry.create_token(TokenType.API_KEY, "will-trigger")
        t2 = registry.create_token(TokenType.API_KEY, "wont-trigger")
        registry.report_trigger(t1.token_id)
        triggered = registry.list_triggered()
        assert len(triggered) == 1
        assert triggered[0].token_id == t1.token_id

    def test_export_registry_returns_all_as_dicts(
        self, registry: CanaryRegistry
    ):
        for i in range(3):
            registry.create_token(TokenType.ENV_VAR, f"export-{i}")
        exported = registry.export_registry()
        assert len(exported) == 3
        for entry in exported:
            assert isinstance(entry, dict)
            assert "token_id" in entry


# ===========================================================================
# 7. report_trigger — state mutations
# ===========================================================================

class TestReportTrigger:
    def test_trigger_marks_triggered_true(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "mark-triggered")
        registry.report_trigger(token.token_id)
        assert token.triggered is True

    def test_trigger_increments_count_to_one(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "count-one")
        registry.report_trigger(token.token_id)
        assert token.trigger_count == 1

    def test_consecutive_triggers_increment_count(
        self, registry: CanaryRegistry
    ):
        token = registry.create_token(TokenType.API_KEY, "count-multi")
        for _ in range(5):
            registry.report_trigger(token.token_id)
        assert token.trigger_count == 5

    def test_triggered_at_set_on_first_trigger(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "triggered-at")
        before = time.time()
        registry.report_trigger(token.token_id)
        after = time.time()
        assert token.triggered_at is not None
        assert before <= token.triggered_at <= after

    def test_triggered_at_not_overwritten_on_second_trigger(
        self, registry: CanaryRegistry
    ):
        token = registry.create_token(TokenType.API_KEY, "triggered-at-stable")
        registry.report_trigger(token.token_id)
        first_ts = token.triggered_at
        registry.report_trigger(token.token_id)
        # triggered_at should remain the first timestamp
        assert token.triggered_at == first_ts

    def test_unknown_token_id_returns_none(self, registry: CanaryRegistry):
        result = registry.report_trigger("deadbeef" * 4)
        assert result is None

    def test_returns_canary_alert_instance(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "alert-type")
        alert = registry.report_trigger(token.token_id)
        assert isinstance(alert, CanaryAlert)


# ===========================================================================
# 8. CanaryAlert — content validation
# ===========================================================================

class TestCanaryAlert:
    def test_alert_token_id_matches(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "alert-id")
        alert = registry.report_trigger(token.token_id, context="unit-test")
        assert alert.token_id == token.token_id

    def test_alert_context_stored(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "alert-ctx")
        alert = registry.report_trigger(
            token.token_id, context="GitHub code search"
        )
        assert alert.context == "GitHub code search"

    def test_alert_trigger_count_reflects_state(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "alert-cnt")
        registry.report_trigger(token.token_id)
        alert = registry.report_trigger(token.token_id)
        assert alert.trigger_count == 2

    def test_http_url_token_callback_url_equals_token_value(
        self, registry: CanaryRegistry
    ):
        token = registry.create_token(TokenType.HTTP_URL, "http-cb")
        alert = registry.report_trigger(token.token_id)
        assert alert.callback_url == token.value

    def test_non_http_url_token_callback_url_contains_base(
        self, registry: CanaryRegistry
    ):
        token = registry.create_token(TokenType.API_KEY, "api-cb")
        alert = registry.report_trigger(token.token_id)
        assert "canary.example.com" in alert.callback_url

    def test_non_http_url_token_callback_url_contains_token_id(
        self, registry: CanaryRegistry
    ):
        token = registry.create_token(TokenType.ENV_VAR, "env-cb")
        alert = registry.report_trigger(token.token_id)
        assert token.token_id in alert.callback_url

    def test_alert_id_is_32_hex_chars(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.CRED_PAIR, "alert-aid")
        alert = registry.report_trigger(token.token_id)
        assert len(alert.alert_id) == 32
        assert all(c in "0123456789abcdef" for c in alert.alert_id)

    def test_alert_to_dict_has_required_keys(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.DOC_EMBED, "alert-dict")
        alert = registry.report_trigger(token.token_id)
        required = {
            "alert_id", "token_id", "token_label", "token_type",
            "context", "triggered_at", "trigger_count", "callback_url",
        }
        assert required.issubset(alert.to_dict().keys())

    def test_alert_token_label_matches_token(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.API_KEY, "label-check")
        alert = registry.report_trigger(token.token_id)
        assert alert.token_label == "label-check"

    def test_alert_token_type_is_string(self, registry: CanaryRegistry):
        token = registry.create_token(TokenType.ENV_VAR, "type-str")
        alert = registry.report_trigger(token.token_id)
        assert isinstance(alert.token_type, str)


# ===========================================================================
# 9. stats()
# ===========================================================================

class TestStats:
    def test_stats_total_correct(self, registry: CanaryRegistry):
        for i in range(4):
            registry.create_token(TokenType.API_KEY, f"s-{i}")
        s = registry.stats()
        assert s["total"] == 4

    def test_stats_triggered_correct(self, registry: CanaryRegistry):
        t1 = registry.create_token(TokenType.API_KEY, "st-1")
        t2 = registry.create_token(TokenType.API_KEY, "st-2")
        registry.create_token(TokenType.API_KEY, "st-3")
        registry.report_trigger(t1.token_id)
        registry.report_trigger(t2.token_id)
        s = registry.stats()
        assert s["triggered"] == 2

    def test_stats_by_type_has_all_types(self, registry: CanaryRegistry):
        registry.create_token(TokenType.HTTP_URL, "by-type")
        s = registry.stats()
        for token_type in TokenType:
            assert token_type.value in s["by_type"]

    def test_stats_by_type_counts_correctly(self, registry: CanaryRegistry):
        registry.create_token(TokenType.API_KEY, "bt-1")
        registry.create_token(TokenType.API_KEY, "bt-2")
        registry.create_token(TokenType.ENV_VAR, "bt-3")
        s = registry.stats()
        assert s["by_type"]["API_KEY"] == 2
        assert s["by_type"]["ENV_VAR"] == 1

    def test_stats_empty_registry(self, registry: CanaryRegistry):
        s = registry.stats()
        assert s["total"] == 0
        assert s["triggered"] == 0
        for count in s["by_type"].values():
            assert count == 0

    def test_stats_triggered_never_exceeds_total(self, registry: CanaryRegistry):
        for i in range(3):
            tok = registry.create_token(TokenType.API_KEY, f"ne-{i}")
            if i < 2:
                registry.report_trigger(tok.token_id)
        s = registry.stats()
        assert s["triggered"] <= s["total"]


# ===========================================================================
# 10. CanaryRegistry — callback base URL handling
# ===========================================================================

class TestRegistryBaseURL:
    def test_trailing_slash_stripped_from_base_url(self):
        reg = CanaryRegistry(callback_base_url="https://example.com/hook/")
        token = reg.create_token(TokenType.HTTP_URL, "slash-test")
        # Should not have double slash before token_id
        assert "//" not in token.value.replace("https://", "")

    def test_default_base_url_used_when_none_given(self):
        reg = CanaryRegistry()
        token = reg.create_token(TokenType.HTTP_URL, "default-url")
        assert "canary.internal" in token.value
