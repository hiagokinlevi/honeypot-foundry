"""
SSH Credential Attempt Classifier
====================================
Classifies SSH login attempts by credential pattern: service account
defaults, manufacturer/vendor defaults, dictionary words, targeted
usernames, and credential stuffing indicators.

Produces structured classification reports for threat intelligence
and honeypot deception tuning.

Classifications
---------------
DEFAULT_CREDENTIAL    Known vendor/service default username:password pair
DICTIONARY_WORD       Username or password is a common dictionary word
TARGETED_USER         Username matches a real-looking targeted account
SERVICE_ACCOUNT       Username follows service account naming pattern
CREDENTIAL_STUFFING   High-volume attempts matching breach dump patterns
RANDOM_JUNK           Appears to be random/fuzzing credential

Usage::

    from honeypots.ssh.credential_classifier import CredentialClassifier, CredentialAttempt

    attempt = CredentialAttempt(
        username="admin",
        password="admin123",
        source_ip="198.51.100.5",
    )
    classifier = CredentialClassifier()
    result = classifier.classify(attempt)
    print(result.classification, result.confidence)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Classification enum
# ---------------------------------------------------------------------------

class CredentialClass(str, Enum):
    """Enumeration of SSH credential attempt classifications."""

    DEFAULT_CREDENTIAL = "DEFAULT_CREDENTIAL"
    DICTIONARY_WORD = "DICTIONARY_WORD"
    TARGETED_USER = "TARGETED_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    RANDOM_JUNK = "RANDOM_JUNK"


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class CredentialAttempt:
    """A single SSH login attempt captured by the honeypot listener."""

    username: str                   # Username submitted by the attacker
    password: str                   # Password submitted by the attacker
    source_ip: str = ""             # Originating IP address (empty if unknown)
    timestamp: float = 0.0          # Unix epoch of the attempt (0 = not recorded)
    protocol: str = "ssh"           # Protocol variant (ssh, sftp, etc.)


@dataclass
class ClassificationResult:
    """Structured result produced by CredentialClassifier.classify()."""

    username: str                           # Original username from the attempt
    password: str                           # Original password from the attempt
    source_ip: str                          # Originating IP address
    classification: CredentialClass         # Winning classification label
    confidence: float                       # Confidence score in [0.0, 1.0]
    signals: List[str] = field(default_factory=list)  # Human-readable evidence strings
    detail: str = ""                        # Optional free-text detail

    def to_dict(self) -> Dict:
        """Serialize result to a plain dictionary suitable for JSON output.

        Returns classification as its string value and confidence rounded
        to two decimal places.
        """
        return {
            "username": self.username,
            "password": self.password,
            "source_ip": self.source_ip,
            "classification": self.classification.value,  # enum → plain string
            "confidence": round(self.confidence, 2),
            "signals": list(self.signals),
            "detail": self.detail,
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of the classification."""
        signal_str = "; ".join(self.signals) if self.signals else "no signals"
        return (
            f"[{self.classification.value}] "
            f"user={self.username!r} pass={self.password!r} "
            f"ip={self.source_ip or 'unknown'} "
            f"confidence={round(self.confidence, 2)} "
            f"signals=({signal_str})"
        )


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Known vendor/service default credential pairs (username, password).
# All entries are stored lowercase; matching is performed case-insensitively.
_DEFAULT_PAIRS = {
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("user", "user"),
    ("guest", "guest"),
    ("pi", "raspberry"),
    ("ubuntu", "ubuntu"),
    ("cisco", "cisco"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("nagios", "nagios"),
    ("ftp", "ftp"),
    ("test", "test"),
    ("admin", ""),
    ("root", ""),
    ("support", "support"),
    ("service", "service"),
}

# Commonly appearing words from password breach dumps and dictionary attacks.
_DICTIONARY_WORDS: frozenset = frozenset({
    "password",
    "123456",
    "qwerty",
    "letmein",
    "monkey",
    "dragon",
    "master",
    "hello",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "soccer",
    "welcome",
    "login",
    "admin",
    "test",
    "pass",
    "abc123",
    "iloveyou",
    "trustno1",
    "1234567890",
    "superman",
    "batman",
    "michael",
    "jordan",
    "ranger",
    "solo",
    "cheese",
    # Additional high-frequency entries
    "secret",
    "changeme",
    "default",
    "guest",
    "root",
    "user",
    "demo",
    "temp",
})

# Patterns that suggest the username is a service / machine account.
_SERVICE_PATTERNS: List[re.Pattern] = [
    re.compile(
        r"^(svc|service|bot|api|app|daemon|worker|cron|runner|deploy|"
        r"jenkins|gitlab|github|ansible|puppet|chef|terraform)[-_]?\w*$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^[a-z]+[_-](svc|service|bot|api|app|worker|bot)$",
        re.IGNORECASE,
    ),
]

# Patterns that suggest the attacker is targeting a real named user account.
_TARGETED_PATTERNS: List[re.Pattern] = [
    re.compile(r"^[a-z]{2,8}\.[a-z]{2,8}$"),          # firstname.lastname
    re.compile(r"^[a-z]{3,6}\d{2,4}$"),               # name + year/id (e.g. john2024)
]

# Confidence scores assigned to each classification (fixed, not learned).
_CONFIDENCE: Dict[CredentialClass, float] = {
    CredentialClass.CREDENTIAL_STUFFING: 0.95,
    CredentialClass.DEFAULT_CREDENTIAL:  0.98,
    CredentialClass.SERVICE_ACCOUNT:     0.80,
    CredentialClass.TARGETED_USER:       0.75,
    CredentialClass.DICTIONARY_WORD:     0.70,
    CredentialClass.RANDOM_JUNK:         0.50,
}


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class CredentialClassifier:
    """Classifies SSH credential attempts using rule-based heuristics.

    Parameters
    ----------
    stuffing_history:
        Optional mapping of source_ip → attempt_count.  Any IP whose count
        exceeds 50 is treated as a credential-stuffing source.  If *None* an
        empty dict is initialised internally.
    """

    # Threshold above which an IP is flagged as credential stuffing
    _STUFFING_THRESHOLD: int = 50

    def __init__(
        self,
        stuffing_history: Optional[Dict[str, int]] = None,
    ) -> None:
        # Use provided history or start fresh; always own the dict reference
        self.stuffing_history: Dict[str, int] = (
            dict(stuffing_history) if stuffing_history is not None else {}
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(self, attempt: CredentialAttempt) -> ClassificationResult:
        """Classify a single credential attempt.

        Classification priority (highest priority wins):
        1. CREDENTIAL_STUFFING  — source IP has attempt count > 50
        2. DEFAULT_CREDENTIAL   — exact (username, password) in default pairs
        3. SERVICE_ACCOUNT      — username matches a service account pattern
        4. TARGETED_USER        — username matches a targeted-user pattern
        5. DICTIONARY_WORD      — username or password is a dictionary word
        6. RANDOM_JUNK          — none of the above

        Parameters
        ----------
        attempt:
            The :class:`CredentialAttempt` to evaluate.

        Returns
        -------
        ClassificationResult
            Populated result including classification label, confidence score,
            and a list of human-readable signal strings.
        """
        signals: List[str] = []
        user_lc = attempt.username.lower()
        pass_lc = attempt.password.lower()

        # 1. CREDENTIAL_STUFFING — high-volume IP detected in history
        if attempt.source_ip:
            count = self.stuffing_history.get(attempt.source_ip, 0)
            if count > self._STUFFING_THRESHOLD:
                signals.append(
                    f"source IP {attempt.source_ip!r} has {count} recorded "
                    f"attempts (threshold={self._STUFFING_THRESHOLD})"
                )
                return self._make_result(
                    attempt,
                    CredentialClass.CREDENTIAL_STUFFING,
                    signals,
                )

        # 2. DEFAULT_CREDENTIAL — known vendor/device default pair
        if (user_lc, pass_lc) in _DEFAULT_PAIRS:
            signals.append(
                f"pair ({attempt.username!r}, {attempt.password!r}) matches "
                "a known default credential entry"
            )
            return self._make_result(
                attempt,
                CredentialClass.DEFAULT_CREDENTIAL,
                signals,
            )

        # 3. SERVICE_ACCOUNT — username looks like a machine/service account
        for pattern in _SERVICE_PATTERNS:
            if pattern.match(attempt.username):
                signals.append(
                    f"username {attempt.username!r} matches service account "
                    f"pattern {pattern.pattern!r}"
                )
                return self._make_result(
                    attempt,
                    CredentialClass.SERVICE_ACCOUNT,
                    signals,
                )

        # 4. TARGETED_USER — username looks like a real person's account
        for pattern in _TARGETED_PATTERNS:
            if pattern.match(attempt.username):
                signals.append(
                    f"username {attempt.username!r} matches targeted-user "
                    f"pattern {pattern.pattern!r}"
                )
                return self._make_result(
                    attempt,
                    CredentialClass.TARGETED_USER,
                    signals,
                )

        # 5. DICTIONARY_WORD — username or password found in common word list
        if user_lc in _DICTIONARY_WORDS:
            signals.append(
                f"username {attempt.username!r} (normalised: {user_lc!r}) "
                "is a known dictionary word"
            )
        if pass_lc in _DICTIONARY_WORDS:
            signals.append(
                f"password {attempt.password!r} (normalised: {pass_lc!r}) "
                "is a known dictionary word"
            )
        if signals:
            return self._make_result(
                attempt,
                CredentialClass.DICTIONARY_WORD,
                signals,
            )

        # 6. RANDOM_JUNK — fallback; no recognisable pattern
        signals.append(
            f"credential pair ({attempt.username!r}, {attempt.password!r}) "
            "did not match any known pattern; likely fuzzing or random input"
        )
        return self._make_result(
            attempt,
            CredentialClass.RANDOM_JUNK,
            signals,
        )

    def classify_many(
        self,
        attempts: List[CredentialAttempt],
    ) -> List[ClassificationResult]:
        """Classify a batch of credential attempts in order.

        Parameters
        ----------
        attempts:
            Iterable of :class:`CredentialAttempt` objects.

        Returns
        -------
        list of ClassificationResult
            One result per input attempt, in the same order.
        """
        return [self.classify(attempt) for attempt in attempts]

    def update_stuffing_count(
        self,
        source_ip: str,
        increment: int = 1,
    ) -> None:
        """Increment the recorded attempt count for *source_ip*.

        If the IP is not yet tracked it is initialised to *increment*.

        Parameters
        ----------
        source_ip:
            The IP address string to update.
        increment:
            Amount to add to the current count (default 1).
        """
        current = self.stuffing_history.get(source_ip, 0)
        self.stuffing_history[source_ip] = current + increment

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_result(
        attempt: CredentialAttempt,
        cls: CredentialClass,
        signals: List[str],
    ) -> ClassificationResult:
        """Build a :class:`ClassificationResult` from classification data."""
        return ClassificationResult(
            username=attempt.username,
            password=attempt.password,
            source_ip=attempt.source_ip,
            classification=cls,
            confidence=_CONFIDENCE[cls],
            signals=signals,
        )
