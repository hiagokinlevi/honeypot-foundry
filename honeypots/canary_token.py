"""
Canary Token Generator
========================
Generates traceable canary tokens for detecting unauthorized access.
Supports HTTP callback tokens (URLs), API key-style tokens, credential
pairs, document tokens, and environment variable tokens.

Tokens are registered in a CanaryRegistry with metadata; alert callbacks
fire when a token is reported as triggered.

Token Types
-----------
HTTP_URL    Unique callback URL token for embedding in config files/docs
API_KEY     Fake API key-style token (service-specific format)
CRED_PAIR   Username/password pair for honeycredential use
ENV_VAR     Environment variable value token
DOC_EMBED   Token for embedding in document metadata/content

Usage::

    from honeypots.canary_token import CanaryRegistry, CanaryToken, TokenType

    registry = CanaryRegistry(callback_base_url="https://canary.example.com/alert")
    token = registry.create_token(
        token_type=TokenType.API_KEY,
        label="aws-key-in-config",
        owner="security-team",
        tags=["s3", "prod"],
    )
    print(token.value)        # CTKN<random>
    print(token.to_dict())    # full metadata

    # When token is seen in the wild, report it:
    alert = registry.report_trigger(token.token_id, context="Found in GitHub search")
    print(alert.to_dict())
"""

from __future__ import annotations

import hashlib
import secrets
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Token type enum
# ---------------------------------------------------------------------------

class TokenType(Enum):
    """Supported canary token varieties."""

    HTTP_URL = "HTTP_URL"    # Embeddable callback URL
    API_KEY = "API_KEY"      # Fake API key (service-format)
    CRED_PAIR = "CRED_PAIR"  # Honeycredential user:password pair
    ENV_VAR = "ENV_VAR"      # Environment variable value
    DOC_EMBED = "DOC_EMBED"  # HTML/document comment token


# ---------------------------------------------------------------------------
# CanaryToken dataclass
# ---------------------------------------------------------------------------

@dataclass
class CanaryToken:
    """A single canary token with full provenance metadata.

    Attributes
    ----------
    token_id:      32-char hex identifier derived from secrets.token_hex(16).
    token_type:    Enum variant describing how the token should be used.
    value:         The actual string to embed in the target artifact.
    label:         Human-readable description of where this token lives.
    owner:         Team or individual responsible for the token.
    tags:          Free-form classification tags (e.g. ["prod", "s3"]).
    created_at:    Unix timestamp of creation.
    triggered:     True once the token has been reported as seen.
    triggered_at:  Unix timestamp of the *first* trigger event.
    trigger_count: Total number of times this token has been reported.
    """

    token_id: str
    token_type: TokenType
    value: str
    label: str
    owner: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    triggered: bool = False
    triggered_at: Optional[float] = None
    trigger_count: int = 0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize all fields to a plain dictionary."""
        return {
            "token_id": self.token_id,
            "token_type": self.token_type.value,  # enum → string
            "value": self.value,
            "label": self.label,
            "owner": self.owner,
            "tags": list(self.tags),
            "created_at": self.created_at,
            "triggered": self.triggered,
            "triggered_at": self.triggered_at,
            "trigger_count": self.trigger_count,
        }

    def summary(self) -> str:
        """Short single-line description for logging/display."""
        return f"[{self.token_id[:8]}] {self.token_type.value}: {self.label}"

    def fingerprint(self) -> str:
        """Return first 16 hex chars of SHA-256(token_id + value).

        Deterministic for any given token; useful for deduplication.
        """
        raw = (self.token_id + self.value).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# CanaryAlert dataclass
# ---------------------------------------------------------------------------

@dataclass
class CanaryAlert:
    """Alert record produced when a canary token is reported as triggered.

    Attributes
    ----------
    alert_id:      32-char hex identifier for this alert event.
    token_id:      ID of the token that fired.
    token_label:   Human-readable label copied from the token.
    token_type:    String representation of the token's type.
    context:       Free-text description of where/how the token was seen.
    triggered_at:  Unix timestamp of this trigger event.
    trigger_count: Total trigger count on the token after this event.
    callback_url:  The URL that an HTTP-based canary system would call.
    """

    alert_id: str
    token_id: str
    token_label: str
    token_type: str
    context: str
    triggered_at: float
    trigger_count: int
    callback_url: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize all fields to a plain dictionary."""
        return {
            "alert_id": self.alert_id,
            "token_id": self.token_id,
            "token_label": self.token_label,
            "token_type": self.token_type,
            "context": self.context,
            "triggered_at": self.triggered_at,
            "trigger_count": self.trigger_count,
            "callback_url": self.callback_url,
        }


# ---------------------------------------------------------------------------
# CanaryRegistry
# ---------------------------------------------------------------------------

class CanaryRegistry:
    """Central store for all canary tokens with creation and alert logic.

    Parameters
    ----------
    callback_base_url:
        Root URL used when building HTTP_URL tokens and fallback alert URLs.
        Defaults to ``"https://canary.internal/alert"``.
    """

    def __init__(
        self,
        callback_base_url: str = "https://canary.internal/alert",
    ) -> None:
        self.callback_base_url = callback_base_url.rstrip("/")
        self._tokens: Dict[str, CanaryToken] = {}

    # ------------------------------------------------------------------
    # Token creation
    # ------------------------------------------------------------------

    def _generate_value(self, token_type: TokenType, token_id: str) -> str:
        """Build the embeddable token string for the given type."""
        if token_type == TokenType.HTTP_URL:
            # Unique callback URL — embed this in config files or docs
            return f"{self.callback_base_url}/{token_id}"

        if token_type == TokenType.API_KEY:
            # 40 uppercase hex chars prefixed with CTKN (mimics cloud key formats)
            return f"CTKN{secrets.token_hex(20).upper()}"

        if token_type == TokenType.CRED_PAIR:
            # user:password honeycredential pair
            username = f"canary_{secrets.token_hex(8)}"
            password = secrets.token_hex(16)
            return f"{username}:{password}"

        if token_type == TokenType.ENV_VAR:
            # 96 hex chars (48 bytes) prefixed with ctk_
            return f"ctk_{secrets.token_hex(24)}"

        if token_type == TokenType.DOC_EMBED:
            # HTML comment embedding the token ID — survives copy-paste of doc text
            return f"<!-- CANARY:{token_id} -->"

        raise ValueError(f"Unknown token type: {token_type!r}")  # pragma: no cover

    def create_token(
        self,
        token_type: TokenType,
        label: str,
        owner: str = "",
        tags: Optional[List[str]] = None,
    ) -> CanaryToken:
        """Create, register, and return a new canary token.

        Parameters
        ----------
        token_type: Desired variety of token.
        label:      Human-readable description (e.g. "aws-key-in-config").
        owner:      Responsible team or individual.
        tags:       Classification tags for grouping/filtering.

        Returns
        -------
        CanaryToken
            Newly created token, already stored in the registry.
        """
        token_id = secrets.token_hex(16)  # 32-char hex string
        value = self._generate_value(token_type, token_id)

        token = CanaryToken(
            token_id=token_id,
            token_type=token_type,
            value=value,
            label=label,
            owner=owner,
            tags=list(tags) if tags is not None else [],
        )

        self._tokens[token_id] = token
        return token

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def get_token(self, token_id: str) -> Optional[CanaryToken]:
        """Return the token for *token_id*, or None if not found."""
        return self._tokens.get(token_id)

    def list_tokens(self) -> List[CanaryToken]:
        """Return all registered tokens as a list."""
        return list(self._tokens.values())

    def list_triggered(self) -> List[CanaryToken]:
        """Return only tokens that have been triggered at least once."""
        return [t for t in self._tokens.values() if t.triggered]

    # ------------------------------------------------------------------
    # Trigger reporting
    # ------------------------------------------------------------------

    def report_trigger(
        self,
        token_id: str,
        context: str = "",
    ) -> Optional[CanaryAlert]:
        """Mark a token as triggered and produce an alert record.

        Parameters
        ----------
        token_id: ID of the token that was observed in the wild.
        context:  Free-text description (e.g. "Found in GitHub search").

        Returns
        -------
        CanaryAlert on success, None if *token_id* is not registered.
        """
        token = self._tokens.get(token_id)
        if token is None:
            return None

        now = time.time()

        # Update token state
        token.triggered = True
        token.trigger_count += 1
        if token.triggered_at is None:
            # Record the timestamp of the very first trigger
            token.triggered_at = now

        # Determine callback URL:
        #   HTTP_URL tokens carry their own callback URL as value;
        #   all other types use a derived path off the base URL.
        if token.token_type == TokenType.HTTP_URL:
            callback_url = token.value
        else:
            callback_url = f"{self.callback_base_url}/alert/{token_id}"

        alert = CanaryAlert(
            alert_id=secrets.token_hex(16),
            token_id=token_id,
            token_label=token.label,
            token_type=token.token_type.value,
            context=context,
            triggered_at=now,
            trigger_count=token.trigger_count,
            callback_url=callback_url,
        )

        return alert

    # ------------------------------------------------------------------
    # Export / statistics
    # ------------------------------------------------------------------

    def export_registry(self) -> List[Dict[str, Any]]:
        """Return all tokens serialized as a list of dicts."""
        return [t.to_dict() for t in self._tokens.values()]

    def stats(self) -> Dict[str, Any]:
        """Aggregate statistics over the current registry.

        Returns
        -------
        dict with keys:
            ``total``     – total token count
            ``triggered`` – number of triggered tokens
            ``by_type``   – mapping of TokenType.value → count
        """
        tokens = list(self._tokens.values())

        by_type: Dict[str, int] = {t.value: 0 for t in TokenType}
        for tok in tokens:
            by_type[tok.token_type.value] += 1

        return {
            "total": len(tokens),
            "triggered": sum(1 for t in tokens if t.triggered),
            "by_type": by_type,
        }
