# honeypot-foundry

Defensive honeypot toolkit for observing attack telemetry, training blue teams, and studying adversarial behavior patterns in authorized environments.

## Objective

Provide modular, production-ready honeypot components that help security teams collect structured telemetry on attack patterns — without granting real access to attackers or exposing real infrastructure.

## Problem Solved

Security teams lack affordable, modular honeypot infrastructure for collecting firsthand attack telemetry. This toolkit fills that gap with a clean Python library, structured JSON events, low-interaction protocol decoys, Docker-ready patterns, and training materials.

## Use Cases

- Collecting SSH brute-force attempt data for threat intelligence
- Monitoring web scanner behavior with HTTP honeypots
- Studying API enumeration and token-guessing patterns
- Capturing FTP credential probes and legacy service reconnaissance
- Training SOC analysts on recognizing attack telemetry
- Generating realistic attack event datasets for SIEM rule development

## Structure

```
honeypots/      — SSH, HTTP, API, and FTP honeypot modules
collectors/     — Event collection and forwarding
parsers/        — Log normalization
schemas/        — JSON event schemas
cli/            — Command-line interface
examples/       — Docker and Kubernetes deployment examples
training/       — Labs and tutorials for security teams
docs/           — Architecture and operational guides
```

## How to Run

```bash
pip install -e ".[dev]"

# Start SSH honeypot on port 2222
k1n-honeypot run-ssh --port 2222 --output-file events.jsonl

# Start HTTP honeypot on port 8080
k1n-honeypot run-http --port 8080 --output-file events.jsonl

# Start API honeypot on port 8000
k1n-honeypot run-api --port 8000 --output-file events.jsonl

# Start FTP honeypot on port 2121
k1n-honeypot run-ftp --port 2121 --banner "Microsoft FTP Service" --output-file events.jsonl
```

## Ethical Disclaimer

Deploy only in environments you own or are explicitly authorized to monitor. This toolkit is for observation and telemetry collection only. It does not execute attacker commands, expose real services, or enable any form of offensive activity. Review applicable laws and organizational policies before deployment.

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

CC BY 4.0 — see [LICENSE](LICENSE).
