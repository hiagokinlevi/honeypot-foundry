# honeypot-foundry

Defensive honeypot toolkit for observing attack telemetry, training blue teams, and studying adversarial behavior patterns in authorized environments.

## Objective

Provide modular, production-ready honeypot components that help security teams collect structured telemetry on attack patterns without granting real access to attackers or exposing real infrastructure.

## Problem Solved

Security teams lack affordable, modular honeypot infrastructure for collecting firsthand attack telemetry. This toolkit fills that gap with a clean Python library, structured JSON events, low-interaction protocol decoys, Docker-ready patterns, and training materials.

## Use Cases

- Collecting SSH brute-force attempt data for threat intelligence
- Monitoring web scanner behavior with HTTP honeypots
- Studying API enumeration and token-guessing patterns
- Capturing FTP credential probes and legacy service reconnaissance
- Observing RDP negotiation probes and legacy remote access reconnaissance
- Training SOC analysts on recognizing attack telemetry
- Generating realistic attack event datasets for SIEM rule development

## Structure

```
honeypots/      — SSH, HTTP, API, FTP, and RDP honeypot modules
collectors/     — Event collection and forwarding
schemas/        — JSON event schemas
cli/            — Command-line interface
helm/           — Kubernetes deployment chart with HPA/PDB/network policy
training/       — Labs and tutorials for security teams
docs/           — Architecture and operational guides
```

## How to Run

```bash
pip install -e ".[dev]"

# Start SSH honeypot on port 2222
honeypot run-ssh --port 2222 --output-file events.jsonl

# Start HTTP honeypot on port 8080
honeypot run-http --port 8080 --output-file events.jsonl

# Start API honeypot on port 8000
honeypot run-api --port 8000 --output-file events.jsonl

# Start FTP honeypot on port 2121
honeypot run-ftp --port 2121 --banner "Microsoft FTP Service" --output-file events.jsonl

# Start RDP banner observer on port 3389
honeypot run-rdp --port 3389 --output-file events.jsonl

# Bind listeners to localhost only (secure segmented deployment example)
honeypot --bind-host 127.0.0.1 run-http --port 8080 --output-file events.jsonl

# Tag all emitted events with a stable instance_id
honeypot --instance-id hp-node-a run-http --port 8080 --output-file events.jsonl
# or via environment variable fallback
HONEYPOT_INSTANCE_ID=hp-node-a honeypot run-http --port 8080 --output-file events.jsonl

# Validate config only (CI/CD or Helm startup preflight)
honeypot --dry-run-config run-http --port 8080 --output-file /var/log/honeypot/events.jsonl
```
