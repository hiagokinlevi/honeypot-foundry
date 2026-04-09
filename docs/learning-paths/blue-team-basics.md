# Learning Path — Blue Team Basics with Observation Infrastructure

## Who This Is For

This learning path is designed for:

- Security analysts new to threat intelligence collection
- SOC teams adding decoy infrastructure to their detection stack
- Students learning defensive security techniques hands-on

No prior experience with honeypots is required. Familiarity with basic Linux administration and Python is helpful.

---

## Learning Objectives

By completing this path you will be able to:

1. Explain what decoy servers are and why they are a low-risk intelligence source
2. Deploy and operate SSH and HTTP observation servers
3. Read and interpret JSONL event logs
4. Identify common scanning and credential stuffing patterns
5. Forward events to a SIEM for centralized analysis
6. Apply credential masking principles to other security tools

---

## Module 1 — Defensive Mindset

### What is threat intelligence?

Threat intelligence is structured knowledge about attacker behavior that helps defenders make better decisions. Honeypots provide a unique form of intelligence: direct observation of real attacker tooling against an instrumented target.

Unlike alerts from production systems (which carry risk of false positives and data sensitivity), honeypot data is:

- **Low noise**: any traffic to a honeypot is suspicious by definition — no legitimate users connect
- **Low risk**: no real data or services are exposed
- **High fidelity**: captures attacker behavior exactly as it occurs

### The blue team role

Blue teams focus on detection, response, and hardening. Honeypot data feeds into:

- **Detection**: identifying IPs, usernames, and tooling patterns to block
- **Intelligence sharing**: contributing to community threat feeds (e.g., AbuseIPDB)
- **Hardening**: understanding which credentials attackers attempt most frequently

---

## Module 2 — Setting Up Observation Infrastructure

**Prerequisite reading**: [Tutorial 01 — Observation Server Setup](../../training/01-observation-server-setup.md)

### Key concepts

- **Host key**: The SSH server's identity. Generate once with `ssh-keygen -t ed25519`; keep consistent across restarts
- **Bind address**: Use `0.0.0.0` to accept connections on all interfaces, or a specific IP for targeted deployment
- **JSONL format**: One JSON object per line — easy to process with `jq`, Python, or stream into a SIEM

### Exercise 2.1

Deploy both servers locally and generate test events:

```bash
# Terminal 1 — SSH observation
python -m cli.main run-ssh --host 127.0.0.1 --port 2222 --host-key ./hostkey --output-file events.jsonl

# Terminal 2 — HTTP observation
python -m cli.main run-http --host 127.0.0.1 --port 8080 --output-file events.jsonl

# Terminal 3 — Generate test SSH event (will fail authentication — that is expected)
ssh -p 2222 -o StrictHostKeyChecking=no testuser@127.0.0.1

# Terminal 3 — Generate test HTTP events
curl http://127.0.0.1:8080/admin
curl -X POST http://127.0.0.1:8080/wp-login.php -d "user=admin&pass=password"
```

Verify events appear in `events.jsonl`.

---

## Module 3 — Analyzing Events

**Prerequisite reading**: [Tutorial 02 — Analyzing Events](../../training/02-analyzing-events.md)

### Pattern recognition

Three primary attack patterns you will observe:

| Pattern | Indicators | Response |
|---------|-----------|----------|
| Dictionary attack (SSH) | High volume from one IP, sequential usernames | Block IP, add credentials to watch list |
| Credential stuffing (SSH) | Many IPs, same hash_prefix values | Hash prefix appears in leaked credential database |
| Web scanning (HTTP) | Sequential paths, automated User-Agent | Identify scanning tool, check for CVE-specific probes |

### Exercise 3.1 — Identify the top attacked paths

After accumulating 50+ HTTP events, run:

```bash
jq -r '.path' events.jsonl | sort | uniq -c | sort -rn | head -10
```

Which paths received the most probes? Research what vulnerabilities those paths are associated with.

### Exercise 3.2 — Temporal analysis

```python
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

events = [json.loads(l) for l in Path("events.jsonl").read_text().splitlines() if l]
hours = Counter(
    datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).hour
    for e in events
)
for hour in sorted(hours):
    print(f"  {hour:02d}:00  {'|' * hours[hour]}  ({hours[hour]})")
```

Do attacks cluster at certain hours? What does that suggest about attacker geography?

---

## Module 4 — Credential Masking and Privacy

The k1n Honeypot Foundry never stores raw credentials. Understanding why this matters:

### Why mask credentials?

Even in a security research context, storing plaintext passwords creates legal and ethical obligations:

- Many real users reuse passwords — a stolen credential file could expose them elsewhere
- Regulations (GDPR, CCPA) may classify captured credentials as personal data
- If the honeypot host itself is compromised, raw credentials become a liability

### How masking works in this toolkit

See [Architecture — Credential Masking](../architecture.md#data-flow-for-credential-masking) for the full flow.

The SHA-256 hash prefix approach gives you:

- **Correlation**: same `hash_prefix` + `len` = same credential attempted again
- **Intelligence value**: you can check whether a hash_prefix matches known leaked passwords (via Have I Been Pwned API using k-anonymity)
- **No reversibility**: the original password cannot be recovered

### Exercise 4.1 — Check a hash prefix against HIBP

The Have I Been Pwned API supports k-anonymity: you send the first 5 characters of the SHA-256 hash and receive matching suffixes.

```python
import hashlib
import httpx

def check_credential_exposure(raw_password: str) -> int:
    """Returns the number of times this password has been seen in breaches."""
    h = hashlib.sha1(raw_password.encode()).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    resp = httpx.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    for line in resp.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            return int(count)
    return 0

# Note: this function uses raw passwords only for the purpose of
# checking exposure — never log the raw value.
print(check_credential_exposure("password"))  # Will return a very large number
```

---

## Module 5 — SIEM Integration

SIEM (Security Information and Event Management) systems aggregate logs from many sources for correlation and alerting. Honeypot events are a high-value, low-volume feed.

### Recommended integration approach

1. **Filebeat**: Lightest weight. Tails `events.jsonl` and ships to Elasticsearch or Logstash. See [Tutorial 02](../../training/02-analyzing-events.md#filebeat--logstash) for config.

2. **Direct HTTP ingest**: Use the Splunk HEC or Elastic Bulk API for environments without Filebeat.

3. **Custom parser**: For other SIEMs, parse the JSONL schema (`schemas/event_schema.json`) to map fields to your SIEM's data model.

### Alerting rules to build

| Rule | Condition | Severity |
|------|-----------|----------|
| SSH brute force | >50 SSH events from single IP in 5 min | High |
| Credential reuse | Same hash_prefix from >5 distinct IPs | Medium |
| Targeted path scan | `/etc/passwd`, `/.env`, `/.git/config` probed | High |
| New scanning tool | Unknown User-Agent pattern | Low |

---

## Module 6 — Responsible Deployment

### Legal considerations

- Deploy honeypots only on infrastructure you own or have written authorization to use
- Review local laws on intercepting network communications before exposing to the internet
- Do not use honeypot data to take offensive action against source IPs

### Operational security

- Run the honeypot host in a dedicated network segment with no access to internal resources
- Rotate SSH host keys periodically to avoid being fingerprinted by attackers
- Monitor the honeypot host itself for signs of compromise (the attacker may try to exploit the observation server)

### Data retention

- Define a retention policy for `events.jsonl` (e.g., 90 days rolling)
- Anonymize or delete source IPs after the retention period if required by local regulations

---

## Recommended Next Steps

1. Complete both tutorials in the `training/` directory
2. Set up a real internet-facing deployment in a cloud DMZ
3. Contribute observed IOCs (Indicators of Compromise) to community feeds
4. Review the [ROADMAP](../../ROADMAP.md) for upcoming features including API decoy endpoints and Kubernetes manifests
5. Explore the [Architecture document](../architecture.md) to understand how to extend the toolkit
