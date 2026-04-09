"""
Decoy server event model.

Captures metadata about connection attempts for threat intelligence.
Credentials are ALWAYS masked before storage — the original value is never
written to disk or logs, only a SHA-256 prefix and length indicator.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class ServiceType(str, Enum):
    SSH = "ssh"
    HTTP = "http"
    API = "api"
    FTP = "ftp"
    RDP = "rdp"


class HoneypotEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    service: ServiceType
    source_ip: str
    source_port: int
    username: Optional[str] = None
    # Credential is stored only as a masked representation
    credential_observed: Optional[str] = None
    path: Optional[str] = None          # HTTP request path
    method: Optional[str] = None        # HTTP method
    user_agent: Optional[str] = None
    metadata: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _mask_credentials(self) -> "HoneypotEvent":
        """Replace raw credential with a masked placeholder before any storage."""
        if self.credential_observed and not self.credential_observed.startswith("[masked:"):
            self.credential_observed = _mask_credential(self.credential_observed)
        return self


def _mask_credential(value: str) -> str:
    """
    Replace a credential value with a non-reversible masked representation.

    Stores the first 8 hex chars of SHA-256 and the credential length.
    This allows correlation of repeated identical credentials without
    storing recoverable sensitive data.

    Args:
        value: The raw credential string to mask.

    Returns:
        Masked string in format: [masked:len=N,hash_prefix=XXXXXXXX]
    """
    h = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"[masked:len={len(value)},hash_prefix={h[:8]}]"
