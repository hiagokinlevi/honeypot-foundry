# Architecture — Honeypot Foundry

## Overview

Honeypot Foundry is a decoy server observation toolkit for defensive security teams. It runs fake SSH, HTTP, API, FTP, and RDP-banner services that log connection attempts for threat intelligence. No legitimate users ever interact with these servers; all traffic is attacker-originated.

---

## Event Flow

```
Network connection
       │
       ▼
┌─────────────────────────────────────────┐
│          Server Handler                  │
│                                         │
│  SSH: _ObservationSSHServer             │
│       validate_password() → False       │
│       validate_public_key() → False     │
│                                         │
│  HTTP: FastAPI catch_all route          │
│        returns {"status": "ok"}         │
│                                         │
│  API: FastAPI auth decoy                │
│       returns 401/404 with logging      │
│                                         │
│  FTP: FTPObservationSession             │
│       USER/PASS always denied           │
│       PWD/FEAT/SYST return safe decoys  │
│                                         │
│  RDP: Banner observer                   │
│       captures negotiation probes       │
│       returns static safe failure frame │
└──────────────┬──────────────────────────┘
               │  raw event data
               ▼
┌─────────────────────────────────────────┐
│           HoneypotEvent                 │
│  (honeypots/common/event.py)            │
│                                         │
│  • Captures: timestamp, source_ip,      │
│    source_port, service, username,      │
│    path, method, user_agent, metadata   │
│                                         │
│  • Credential masking (model_validator) │
│    Raw password → [masked:len=N,        │
│                    hash_prefix=XXXXXXXX]│
│    SHA-256 hash prefix — non-reversible │
└──────────────┬──────────────────────────┘
               │  HoneypotEvent instance
               ▼
┌─────────────────────────────────────────┐
│            EventWriter                  │
│  (collectors/writer.py)                 │
│                                         │
│  • Serializes to JSON (model_dump)      │
│  • Writes to stdout (always)            │
│  • Appends to JSONL file (if configured)│
│    line-buffered for low-latency flush  │
└──────────────┬──────────────────────────┘
               │  JSONL lines
               ▼
┌─────────────────────────────────────────┐
│         events.jsonl / stdout           │
│                                         │
│  One JSON object per line               │
│  Schema: schemas/event_schema.json      │
│  Ingestible by Splunk, Elastic,         │
│  Filebeat, Logstash, etc.               │
└─────────────────────────────────────────┘
```

---

## Module Responsibilities

### `honeypots/common/event.py`

Central data model. Defines `HoneypotEvent` (Pydantic v2) and the `_mask_credential()` utility. The `model_validator` ensures credentials are masked before the object is ever passed to any consumer — this is the security boundary that prevents raw credentials from reaching disk or logs.

### `honeypots/ssh/server.py`

asyncssh-based SSH server. The `_ObservationSSHServer` class overrides only `validate_password` and `validate_public_key`, both of which always return `False`. No `session_requested` handler is defined, providing defense-in-depth: even if authentication logic were bypassed, no shell would be available.

### `honeypots/http/server.py`

FastAPI application with a single catch-all route matching every path and HTTP method. Returns a generic `{"status": "ok"}` to all requests so scanners continue probing rather than moving on. The `OBSERVED_CREDENTIAL_PATHS` set flags events from common login endpoints for easier downstream filtering.

### `honeypots/ftp/server.py`

asyncio-based FTP decoy. Sends a realistic banner, captures `USER` and `PASS`
attempts, responds to reconnaissance commands such as `SYST`, `FEAT`, and
`PWD`, and always denies authentication. No directory listing, file transfer,
or real filesystem access is exposed.

### `honeypots/rdp/server.py`

asyncio-based RDP negotiation observer. Captures source telemetry and the first
packet payload, extracts requested protocol flags when present, and always
returns a static negotiation failure frame. No session upgrade or desktop
interaction is possible.

### `collectors/writer.py`

Stateless output layer. Accepts `HoneypotEvent` objects and serializes them to JSONL. Opened in append mode with line buffering so events are immediately available to `tail -f` and streaming SIEM connectors.

### `cli/main.py`

Click CLI entry point. Six server commands: `run-ssh`, `run-http`, `run-api`,
`run-ftp`, `run-rdp`, plus `healthcheck`. Wires together the server and writer
with dependency injection (the writer's `write` method is passed as the event callback).

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| Credentials masked at model construction | Prevents accidental logging before the masking step |
| SHA-256 prefix (8 hex chars) + length | Enables correlation of repeated credentials without reversibility |
| `validate_password` always returns `False` | Core security invariant — no authentication path can succeed |
| No `session_requested` handler | Defense-in-depth: no shell even if auth were bypassed |
| `docs_url=None, redoc_url=None` in FastAPI | Prevents automated API discovery by scanners |
| FTP replies are static/safe | Prevents exposure of a real filesystem or data channel |

---

## Data Flow for Credential Masking

```
Raw input: "password123"
    │
    ▼
SHA-256("password123") = ef92b778bafe771207fbe...
    │
    ├── hash_prefix = "ef92b778"  (first 8 hex chars)
    └── len = 11
    │
    ▼
Stored value: "[masked:len=11,hash_prefix=ef92b778]"
```

The original string cannot be recovered from this representation. Two events with identical `hash_prefix` and `len` indicate the same credential was attempted, enabling correlation across IPs.

---

## Deployment Topology

```
Internet
    │
    ▼
[Firewall / Security Group]
    │  Allow inbound TCP 2222, 2121, 3389, 8080
    │  Block outbound from honeypot host (optional but recommended)
    ▼
[Honeypot Host]
    ├── run-ssh  (port 2222)
    ├── run-ftp  (port 2121)
    ├── run-rdp  (port 3389)
    └── run-http (port 8080)
         │
         └── events.jsonl ──► Filebeat ──► Elastic / Splunk
```

The honeypot host should have no access to internal networks. Treat it as untrusted infrastructure — it receives arbitrary attacker input.
