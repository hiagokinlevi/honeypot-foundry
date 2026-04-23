# Roadmap

## v0.1 — Core Observation Servers (current)
- [x] SSH observation server (asyncssh, always denies access)
- [x] HTTP observation server (FastAPI catch-all)
- [x] Credential masking (SHA-256 prefix + length only)
- [x] JSONL event output (stdout + file)
- [x] CLI (run-ssh, run-http, healthcheck)

## v0.2 — Additional Decoy Services (current)
- [x] API credential decoy (JWT/OAuth endpoints — always denies access)
- [x] SIEM adapters: Splunk HEC, Elastic bulk, CEF/syslog
- [x] FTP observation server
- [x] RDP banner observer

## v0.3 — Kubernetes Deployment
- [x] Helm chart for multi-service deployment
- [x] Horizontal Pod Autoscaling for high-volume environments
- [x] PodDisruptionBudget for HA
- [x] NetworkPolicy isolation with default-deny egress

## v0.4 — SIEM Transport
- [x] Splunk HEC HTTP transport (configurable endpoint + token)
- [x] Elastic HTTP bulk transport
- [x] Microsoft Sentinel CEF via syslog-ng

## Automated Completions
- [x] Centralized Log Forwarder (cycle 4)
- [x] Attack Session Recording (cycle 20)
- [x] Kubernetes Honeypot Deployment (cycle 21)
- [x] Alerting Rules for SIEM (cycle 22)
- [x] Automated IP Blocking Integration (cycle 23)
- [x] Attack Data Export API (cycle 24)
- [x] Honeypot Healthcheck Endpoint (cycle 25)
- [x] Attack Event Replay CLI for SIEM Testing (cycle 26)
- [x] CLI JSONL Event Schema Validator (cycle 27)
- [x] Add configurable JSONL file rotation by size (cycle 28)
- [x] Emit per-source IP rate-limit telemetry events (cycle 29)
- [x] Add deterministic event_id to all emitted events (cycle 30)
- [x] Introduce stdout heartbeat metric line for liveness monitoring (cycle 31)
