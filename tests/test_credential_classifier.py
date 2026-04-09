"""
Tests for honeypots.ssh.credential_classifier
=============================================
Comprehensive pytest suite covering all six classification labels,
priority ordering, confidence values, signal population, batch
classification, stuffing-count promotion, case-insensitive matching,
service/targeted pattern matching, and serialisation helpers.
"""

from __future__ import annotations

import sys
import os

# Allow importing from the project root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from honeypots.ssh.credential_classifier import (
    ClassificationResult,
    CredentialAttempt,
    CredentialClass,
    CredentialClassifier,
    _DEFAULT_PAIRS,
    _DICTIONARY_WORDS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def classifier() -> CredentialClassifier:
    """Fresh classifier with no stuffing history."""
    return CredentialClassifier()


@pytest.fixture()
def stuffed_classifier() -> CredentialClassifier:
    """Classifier with one IP already above the stuffing threshold."""
    return CredentialClassifier(stuffing_history={"10.0.0.1": 51})


def make_attempt(
    username: str = "user",
    password: str = "pass",
    source_ip: str = "192.0.2.1",
) -> CredentialAttempt:
    """Convenience factory for CredentialAttempt."""
    return CredentialAttempt(username=username, password=password, source_ip=source_ip)


# ---------------------------------------------------------------------------
# 1. Classification: RANDOM_JUNK (baseline / fallback)
# ---------------------------------------------------------------------------

class TestRandomJunk:
    def test_random_junk_returned_for_unknown_pair(self, classifier):
        attempt = make_attempt(username="xzqy8837fj", password="$$gibberish$$")
        result = classifier.classify(attempt)
        assert result.classification == CredentialClass.RANDOM_JUNK

    def test_random_junk_confidence(self, classifier):
        result = classifier.classify(make_attempt(username="zzz111bbb", password="qqq222aaa"))
        assert result.confidence == 0.50

    def test_random_junk_signals_not_empty(self, classifier):
        result = classifier.classify(make_attempt(username="zzzzzzz", password="xxxxxxx"))
        assert len(result.signals) > 0

    def test_random_junk_no_ip(self, classifier):
        attempt = CredentialAttempt(username="xyz9283lmn", password="!@#garbage")
        result = classifier.classify(attempt)
        assert result.classification == CredentialClass.RANDOM_JUNK


# ---------------------------------------------------------------------------
# 2. Classification: DEFAULT_CREDENTIAL
# ---------------------------------------------------------------------------

class TestDefaultCredential:
    def test_admin_admin(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_root_password(self, classifier):
        result = classifier.classify(make_attempt(username="root", password="password"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_pi_raspberry(self, classifier):
        result = classifier.classify(make_attempt(username="pi", password="raspberry"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_default_credential_confidence(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        assert result.confidence == 0.98

    def test_default_credential_signals_not_empty(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        assert len(result.signals) > 0

    def test_case_insensitive_default_upper_username(self, classifier):
        # "ADMIN" / "admin" should still match the default pair ("admin", "admin")
        result = classifier.classify(make_attempt(username="ADMIN", password="admin"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_case_insensitive_default_upper_password(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="ADMIN"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_case_insensitive_default_both_upper(self, classifier):
        result = classifier.classify(make_attempt(username="ROOT", password="ROOT"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_empty_password_admin(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password=""))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_empty_password_root(self, classifier):
        result = classifier.classify(make_attempt(username="root", password=""))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_all_default_pairs_trigger_default_credential(self, classifier):
        """Every entry in _DEFAULT_PAIRS must classify as DEFAULT_CREDENTIAL."""
        for username, password in _DEFAULT_PAIRS:
            result = classifier.classify(make_attempt(username=username, password=password))
            assert result.classification == CredentialClass.DEFAULT_CREDENTIAL, (
                f"Pair ({username!r}, {password!r}) was not classified as DEFAULT_CREDENTIAL"
            )

    def test_wrong_password_does_not_match(self, classifier):
        # "admin" / "wrongpassword" is not in the default pairs
        result = classifier.classify(make_attempt(username="admin", password="wrongpassword99"))
        assert result.classification != CredentialClass.DEFAULT_CREDENTIAL

    def test_postgres_postgres(self, classifier):
        result = classifier.classify(make_attempt(username="postgres", password="postgres"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_cisco_cisco(self, classifier):
        result = classifier.classify(make_attempt(username="cisco", password="cisco"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_ubuntu_ubuntu(self, classifier):
        result = classifier.classify(make_attempt(username="ubuntu", password="ubuntu"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL


# ---------------------------------------------------------------------------
# 3. Classification: SERVICE_ACCOUNT
# ---------------------------------------------------------------------------

class TestServiceAccount:
    def test_svc_prefix(self, classifier):
        result = classifier.classify(make_attempt(username="svc_deploy", password="randompass99"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_jenkins_username(self, classifier):
        result = classifier.classify(make_attempt(username="jenkins", password="randompass99"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_gitlab_username(self, classifier):
        result = classifier.classify(make_attempt(username="gitlab", password="somepassword"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_ansible_username(self, classifier):
        result = classifier.classify(make_attempt(username="ansible", password="somepassword"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_terraform_username(self, classifier):
        result = classifier.classify(make_attempt(username="terraform", password="somepassword"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_suffix_api_pattern(self, classifier):
        # Matches second pattern: ^[a-z]+[_-](svc|service|bot|api|...)$
        result = classifier.classify(make_attempt(username="myapp_api", password="somepassword"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_suffix_svc_pattern(self, classifier):
        result = classifier.classify(make_attempt(username="billing_svc", password="somepassword"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_service_account_confidence(self, classifier):
        result = classifier.classify(make_attempt(username="jenkins", password="somepassword"))
        assert result.confidence == 0.80

    def test_service_account_signals_not_empty(self, classifier):
        result = classifier.classify(make_attempt(username="jenkins", password="somepassword"))
        assert len(result.signals) > 0

    def test_bot_prefix(self, classifier):
        result = classifier.classify(make_attempt(username="bot_alerts", password="somepass"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_deploy_runner(self, classifier):
        result = classifier.classify(make_attempt(username="deploy_runner", password="xxx"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT


# ---------------------------------------------------------------------------
# 4. Classification: TARGETED_USER
# ---------------------------------------------------------------------------

class TestTargetedUser:
    def test_firstname_dot_lastname(self, classifier):
        result = classifier.classify(make_attempt(username="john.smith", password="xyz9283lmn"))
        assert result.classification == CredentialClass.TARGETED_USER

    def test_firstname_dot_lastname_short(self, classifier):
        result = classifier.classify(make_attempt(username="jo.li", password="xyz9283lmn"))
        assert result.classification == CredentialClass.TARGETED_USER

    def test_name_plus_year(self, classifier):
        # Matches ^[a-z]{3,6}\d{2,4}$ pattern (e.g. john2024)
        result = classifier.classify(make_attempt(username="john2024", password="xyz9283lmn"))
        assert result.classification == CredentialClass.TARGETED_USER

    def test_name_plus_short_id(self, classifier):
        result = classifier.classify(make_attempt(username="alice99", password="xyz9283lmn"))
        assert result.classification == CredentialClass.TARGETED_USER

    def test_targeted_user_confidence(self, classifier):
        result = classifier.classify(make_attempt(username="jane.doe", password="xyz9283lmn"))
        assert result.confidence == 0.75

    def test_targeted_user_signals_not_empty(self, classifier):
        result = classifier.classify(make_attempt(username="jane.doe", password="xyz9283lmn"))
        assert len(result.signals) > 0

    def test_very_long_name_not_targeted(self, classifier):
        # firstname.lastname requires 2-8 chars each; "toolongfirstname.toolongLastname" exceeds that
        result = classifier.classify(
            make_attempt(username="toolongfirstname.toolonglastname", password="xyz")
        )
        assert result.classification != CredentialClass.TARGETED_USER


# ---------------------------------------------------------------------------
# 5. Classification: DICTIONARY_WORD
# ---------------------------------------------------------------------------

class TestDictionaryWord:
    def test_password_in_dict_via_username(self, classifier):
        # username="monkey" is a dictionary word; use unknown password
        result = classifier.classify(make_attempt(username="monkey", password="xyz9283lmn"))
        assert result.classification == CredentialClass.DICTIONARY_WORD

    def test_password_in_dict_via_password(self, classifier):
        result = classifier.classify(make_attempt(username="xyz9283lmn", password="dragon"))
        assert result.classification == CredentialClass.DICTIONARY_WORD

    def test_case_insensitive_dict_username(self, classifier):
        result = classifier.classify(make_attempt(username="MONKEY", password="xyz9283lmn"))
        assert result.classification == CredentialClass.DICTIONARY_WORD

    def test_case_insensitive_dict_password(self, classifier):
        result = classifier.classify(make_attempt(username="xyz9283lmn", password="DRAGON"))
        assert result.classification == CredentialClass.DICTIONARY_WORD

    def test_dict_word_confidence(self, classifier):
        result = classifier.classify(make_attempt(username="xyz9283lmn", password="monkey"))
        assert result.confidence == 0.70

    def test_dict_word_signals_contain_matched_token(self, classifier):
        result = classifier.classify(make_attempt(username="xyz9283lmn", password="letmein"))
        assert any("letmein" in s for s in result.signals)

    def test_both_username_and_password_dict(self, classifier):
        # Both tokens are dict words; two signals should be present
        result = classifier.classify(make_attempt(username="monkey", password="dragon"))
        assert result.classification == CredentialClass.DICTIONARY_WORD
        assert len(result.signals) == 2

    def test_qwerty_classified_dict(self, classifier):
        result = classifier.classify(make_attempt(username="xyz9283lmn", password="qwerty"))
        assert result.classification == CredentialClass.DICTIONARY_WORD

    def test_iloveyou_classified_dict(self, classifier):
        result = classifier.classify(make_attempt(username="xyz9283lmn", password="iloveyou"))
        assert result.classification == CredentialClass.DICTIONARY_WORD


# ---------------------------------------------------------------------------
# 6. Classification: CREDENTIAL_STUFFING
# ---------------------------------------------------------------------------

class TestCredentialStuffing:
    def test_stuffing_detected_above_threshold(self, stuffed_classifier):
        attempt = make_attempt(source_ip="10.0.0.1")
        result = stuffed_classifier.classify(attempt)
        assert result.classification == CredentialClass.CREDENTIAL_STUFFING

    def test_stuffing_confidence(self, stuffed_classifier):
        attempt = make_attempt(source_ip="10.0.0.1")
        result = stuffed_classifier.classify(attempt)
        assert result.confidence == 0.95

    def test_stuffing_signals_mention_ip(self, stuffed_classifier):
        attempt = make_attempt(source_ip="10.0.0.1")
        result = stuffed_classifier.classify(attempt)
        assert any("10.0.0.1" in s for s in result.signals)

    def test_ip_at_threshold_not_stuffing(self, classifier):
        # Exactly 50 is NOT above threshold; should not be stuffing
        classifier.update_stuffing_count("10.0.0.2", 50)
        attempt = make_attempt(source_ip="10.0.0.2")
        result = classifier.classify(attempt)
        assert result.classification != CredentialClass.CREDENTIAL_STUFFING

    def test_ip_at_51_is_stuffing(self, classifier):
        classifier.update_stuffing_count("10.0.0.3", 51)
        result = classifier.classify(make_attempt(source_ip="10.0.0.3"))
        assert result.classification == CredentialClass.CREDENTIAL_STUFFING

    def test_unknown_ip_not_stuffing(self, classifier):
        result = classifier.classify(make_attempt(source_ip="1.2.3.4"))
        assert result.classification != CredentialClass.CREDENTIAL_STUFFING


# ---------------------------------------------------------------------------
# 7. Priority ordering
# ---------------------------------------------------------------------------

class TestPriorityOrdering:
    def test_stuffing_beats_default_credential(self, stuffed_classifier):
        """CREDENTIAL_STUFFING must win over DEFAULT_CREDENTIAL (priority 1 > 2)."""
        attempt = CredentialAttempt(
            username="admin",
            password="admin",
            source_ip="10.0.0.1",  # already in stuffed_classifier at count 51
        )
        result = stuffed_classifier.classify(attempt)
        assert result.classification == CredentialClass.CREDENTIAL_STUFFING

    def test_stuffing_beats_service_account(self, stuffed_classifier):
        """CREDENTIAL_STUFFING must win over SERVICE_ACCOUNT (priority 1 > 3)."""
        attempt = CredentialAttempt(
            username="jenkins",
            password="anypassword",
            source_ip="10.0.0.1",
        )
        result = stuffed_classifier.classify(attempt)
        assert result.classification == CredentialClass.CREDENTIAL_STUFFING

    def test_default_beats_service_account(self, classifier):
        """DEFAULT_CREDENTIAL must win over SERVICE_ACCOUNT (priority 2 > 3).

        'service' / 'service' is a default pair AND matches the service keyword;
        DEFAULT_CREDENTIAL should be returned.
        """
        attempt = make_attempt(username="service", password="service")
        result = classifier.classify(attempt)
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_default_beats_dictionary_word(self, classifier):
        """DEFAULT_CREDENTIAL must win over DICTIONARY_WORD (priority 2 > 5).

        'admin' is a dictionary word but ('admin', 'admin') is a default pair first.
        """
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        assert result.classification == CredentialClass.DEFAULT_CREDENTIAL

    def test_service_beats_dictionary_word(self, classifier):
        """SERVICE_ACCOUNT must win over DICTIONARY_WORD (priority 3 > 5).

        'jenkins' is also a word but should classify as SERVICE_ACCOUNT.
        """
        result = classifier.classify(make_attempt(username="jenkins", password="monkey"))
        assert result.classification == CredentialClass.SERVICE_ACCOUNT

    def test_stuffing_beats_targeted_user(self, stuffed_classifier):
        """CREDENTIAL_STUFFING must win over TARGETED_USER (priority 1 > 4)."""
        attempt = CredentialAttempt(
            username="john.smith",
            password="anypassword",
            source_ip="10.0.0.1",
        )
        result = stuffed_classifier.classify(attempt)
        assert result.classification == CredentialClass.CREDENTIAL_STUFFING


# ---------------------------------------------------------------------------
# 8. update_stuffing_count behaviour
# ---------------------------------------------------------------------------

class TestUpdateStuffingCount:
    def test_new_ip_initialised(self, classifier):
        classifier.update_stuffing_count("5.5.5.5")
        assert classifier.stuffing_history["5.5.5.5"] == 1

    def test_existing_ip_incremented(self, classifier):
        classifier.update_stuffing_count("5.5.5.5", 30)
        classifier.update_stuffing_count("5.5.5.5", 25)
        assert classifier.stuffing_history["5.5.5.5"] == 55

    def test_promotion_from_not_stuffing_to_stuffing(self, classifier):
        """After enough increments an IP should transition to CREDENTIAL_STUFFING."""
        ip = "6.6.6.6"
        # Below threshold — should not be stuffing yet
        classifier.update_stuffing_count(ip, 50)
        result_before = classifier.classify(make_attempt(source_ip=ip))
        assert result_before.classification != CredentialClass.CREDENTIAL_STUFFING

        # One more push over the threshold
        classifier.update_stuffing_count(ip, 1)
        result_after = classifier.classify(make_attempt(source_ip=ip))
        assert result_after.classification == CredentialClass.CREDENTIAL_STUFFING

    def test_custom_increment_large(self, classifier):
        classifier.update_stuffing_count("7.7.7.7", 100)
        assert classifier.stuffing_history["7.7.7.7"] == 100

    def test_default_increment_is_one(self, classifier):
        classifier.update_stuffing_count("8.8.8.8")
        classifier.update_stuffing_count("8.8.8.8")
        assert classifier.stuffing_history["8.8.8.8"] == 2


# ---------------------------------------------------------------------------
# 9. classify_many
# ---------------------------------------------------------------------------

class TestClassifyMany:
    def test_returns_list(self, classifier):
        attempts = [
            make_attempt(username="admin", password="admin"),
            make_attempt(username="xyz9283lmn", password="$$garbage$$"),
        ]
        results = classifier.classify_many(attempts)
        assert isinstance(results, list)

    def test_length_matches_input(self, classifier):
        attempts = [make_attempt() for _ in range(5)]
        results = classifier.classify_many(attempts)
        assert len(results) == 5

    def test_empty_input_returns_empty_list(self, classifier):
        assert classifier.classify_many([]) == []

    def test_order_preserved(self, classifier):
        attempts = [
            make_attempt(username="admin", password="admin"),     # DEFAULT_CREDENTIAL
            make_attempt(username="xyz9283lmn", password="$$garbage$$"),  # RANDOM_JUNK
        ]
        results = classifier.classify_many(attempts)
        assert results[0].classification == CredentialClass.DEFAULT_CREDENTIAL
        assert results[1].classification == CredentialClass.RANDOM_JUNK

    def test_classify_many_all_classifications_present(self, stuffed_classifier):
        """Batch call should be able to return all six classification types."""
        attempts = [
            CredentialAttempt("admin", "admin", source_ip="1.1.1.1"),        # DEFAULT
            CredentialAttempt("jenkins", "anypass", source_ip="1.1.1.1"),    # SERVICE
            CredentialAttempt("john.smith", "anypass", source_ip="1.1.1.1"), # TARGETED
            CredentialAttempt("xyz", "monkey", source_ip="1.1.1.1"),         # DICTIONARY
            CredentialAttempt("xyz9283lmn", "$$garbage$$", source_ip="1.1.1.1"),  # RANDOM
            CredentialAttempt("admin", "admin", source_ip="10.0.0.1"),       # STUFFING
        ]
        results = stuffed_classifier.classify_many(attempts)
        classes = {r.classification for r in results}
        expected = {
            CredentialClass.DEFAULT_CREDENTIAL,
            CredentialClass.SERVICE_ACCOUNT,
            CredentialClass.TARGETED_USER,
            CredentialClass.DICTIONARY_WORD,
            CredentialClass.RANDOM_JUNK,
            CredentialClass.CREDENTIAL_STUFFING,
        }
        assert classes == expected


# ---------------------------------------------------------------------------
# 10. ClassificationResult helpers: to_dict and summary
# ---------------------------------------------------------------------------

class TestClassificationResultHelpers:
    def test_to_dict_returns_dict(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        d = result.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_classification_is_string(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        d = result.to_dict()
        assert isinstance(d["classification"], str)
        assert d["classification"] == "DEFAULT_CREDENTIAL"

    def test_to_dict_confidence_rounded_to_two_decimals(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        d = result.to_dict()
        # Verify it's a float rounded to at most 2 decimal places
        assert d["confidence"] == round(d["confidence"], 2)

    def test_to_dict_contains_required_keys(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        d = result.to_dict()
        for key in ("username", "password", "source_ip", "classification",
                    "confidence", "signals", "detail"):
            assert key in d, f"Missing key: {key!r}"

    def test_to_dict_signals_is_list(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        d = result.to_dict()
        assert isinstance(d["signals"], list)

    def test_summary_returns_string(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        assert isinstance(result.summary(), str)

    def test_summary_contains_classification(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        assert "DEFAULT_CREDENTIAL" in result.summary()

    def test_summary_contains_username(self, classifier):
        result = classifier.classify(make_attempt(username="admin", password="admin"))
        assert "admin" in result.summary()

    def test_to_dict_random_junk_classification_value(self, classifier):
        result = classifier.classify(make_attempt(username="xzqy8837fj", password="$$gibberish$$"))
        d = result.to_dict()
        assert d["classification"] == "RANDOM_JUNK"

    def test_to_dict_credential_stuffing_value(self, stuffed_classifier):
        result = stuffed_classifier.classify(make_attempt(source_ip="10.0.0.1"))
        d = result.to_dict()
        assert d["classification"] == "CREDENTIAL_STUFFING"


# ---------------------------------------------------------------------------
# 11. CredentialAttempt default field values
# ---------------------------------------------------------------------------

class TestCredentialAttemptDefaults:
    def test_default_source_ip_is_empty_string(self):
        attempt = CredentialAttempt(username="x", password="y")
        assert attempt.source_ip == ""

    def test_default_timestamp_is_zero(self):
        attempt = CredentialAttempt(username="x", password="y")
        assert attempt.timestamp == 0.0

    def test_default_protocol_is_ssh(self):
        attempt = CredentialAttempt(username="x", password="y")
        assert attempt.protocol == "ssh"


# ---------------------------------------------------------------------------
# 12. CredentialClassifier initialisation
# ---------------------------------------------------------------------------

class TestClassifierInit:
    def test_no_history_starts_empty(self):
        c = CredentialClassifier()
        assert c.stuffing_history == {}

    def test_provided_history_is_copied(self):
        original = {"1.1.1.1": 10}
        c = CredentialClassifier(stuffing_history=original)
        # Mutating the classifier's internal dict should not affect the original
        c.stuffing_history["1.1.1.1"] = 99
        assert original["1.1.1.1"] == 10

    def test_none_history_yields_empty_dict(self):
        c = CredentialClassifier(stuffing_history=None)
        assert isinstance(c.stuffing_history, dict)
        assert len(c.stuffing_history) == 0
