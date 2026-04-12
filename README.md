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

# Print Helm chart path and deployment guidance
honeypot show-helm

# Forward live events to Splunk and Microsoft Sentinel-compatible syslog
honeypot run-http \
  --port 8080 \
  --output-file events.jsonl \
  --splunk-hec-url https://splunk.example.com:8088/services/collector/event \
  --splunk-hec-token YOUR_HEC_TOKEN \
  --cef-syslog-host syslog-ng.internal \
  --cef-syslog-port 6514 \
  --cef-syslog-protocol tcp
```

Each `run-*` command can now forward live events to one or more SIEM endpoints
while still writing local JSONL telemetry:

- `--splunk-hec-url` + `--splunk-hec-token` posts Splunk HEC events with configurable index/source fields
- `--elastic-url` posts NDJSON batches to the Elastic/OpenSearch bulk API, optionally with basic auth
- `--cef-syslog-host` sends CEF-over-syslog payloads to a syslog-ng or Sentinel relay over UDP or TCP

The installed `honeypot` console script now resolves through a repository-unique
wrapper so editable installs do not collide with other k1N repositories that
also expose Click CLIs.

## Kubernetes Deployment

The repository ships a Helm chart for deploying isolated decoy services into a
cluster. By default it exposes SSH, HTTP, and API decoys, keeps FTP/RDP
disabled until explicitly enabled, creates optional HPA/PDB resources, and
applies a default-deny egress `NetworkPolicy` so a compromised pod cannot phone
home.

```bash
helm upgrade --install honeypot-foundry \
  ./helm/honeypot-foundry \
  --namespace honeypot-foundry --create-namespace

# Optional protocol toggles
helm upgrade --install honeypot-foundry \
  ./helm/honeypot-foundry \
  --namespace honeypot-foundry --create-namespace \
  --set services.ftp.enabled=true \
  --set services.rdp.enabled=true
```

## Ethical Disclaimer

Deploy only in environments you own or are explicitly authorized to monitor. This toolkit is for observation and telemetry collection only. It does not execute attacker commands, expose real services, or enable any form of offensive activity. Review applicable laws and organizational policies before deployment.

## SIEM Forwarding Notes

Live transport failures do not discard the local event stream. The honeypot
continues writing to stdout and `--output-file`, and emits a stderr warning so
operators can fix the remote connector without losing local evidence.
CEF/syslog forwarding also escapes attacker-controlled values before delivery,
including usernames, request paths, methods, and user agents, so crafted input
cannot add fake CEF fields or line breaks in downstream SIEM parsers.
HTTP SIEM endpoints also reject embedded URL credentials, query parameters, and
fragments. Pass the Splunk HEC token with `--splunk-hec-token` and Elastic
credentials with `--elastic-username` plus `--elastic-password` so secrets stay
out of URLs. Routing fields and header-backed credentials are also rejected
when they contain blank, padded, or control-character values. CEF/syslog
configuration also rejects non-string hosts and app names plus non-integer
port/facility values before any socket is opened.

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

CC BY 4.0 — see [LICENSE](LICENSE).
