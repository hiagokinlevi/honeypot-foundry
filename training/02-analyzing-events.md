# Tutorial 02 — Analyzing Observation Events

## Overview

After running the observation servers for a period of time, `events.jsonl` accumulates a record of every connection attempt. This tutorial covers:

1. Reading and validating JSONL events
2. Identifying scanning patterns from the data
3. Counting unique source IPs
4. Forwarding events to a SIEM

---

## Reading Events

Each line in `events.jsonl` is a valid JSON object conforming to `schemas/event_schema.json`. Use Python's built-in `json` module or `jq` for quick analysis.

### With jq

```bash
# Pretty-print the last 10 events
tail -n 10 events.jsonl | jq .

# Show only SSH events
jq 'select(.service == "ssh")' events.jsonl

# Show only HTTP events targeting credential paths
jq 'select(.service == "http" and .metadata.is_credential_path == true)' events.jsonl
```

### With Python

```python
import json
from pathlib import Path

events = [json.loads(line) for line in Path("events.jsonl").read_text().splitlines() if line]
print(f"Total events: {len(events)}")
```

---

## Identifying Scanning Patterns

### Pattern 1 — Credential Stuffing (SSH)

Automated credential stuffing tools submit thousands of username/password combinations. Look for:

- High event volume from a single IP in a short time window
- Common usernames: `root`, `admin`, `ubuntu`, `pi`, `test`

```bash
# Top 10 usernames attempted over SSH
jq -r 'select(.service == "ssh") | .username' events.jsonl \
  | sort | uniq -c | sort -rn | head -10
```

### Pattern 2 — Web Scanning

Scanners probe for known-vulnerable paths. The `is_credential_path` flag in metadata marks attempts at login endpoints.

```bash
# Most-probed HTTP paths
jq -r 'select(.service == "http") | .path' events.jsonl \
  | sort | uniq -c | sort -rn | head -20
```

### Pattern 3 — Botnet Sweeps

Distributed botnets use many source IPs but identical tooling. Look for the same User-Agent or the same credential hash prefix across many IPs.

```bash
# Top User-Agents
jq -r 'select(.service == "http") | .user_agent // "none"' events.jsonl \
  | sort | uniq -c | sort -rn | head -10
```

---

## Counting Unique Source IPs

```bash
# Total unique source IPs across all services
jq -r '.source_ip' events.jsonl | sort -u | wc -l

# Unique IPs per service
jq -r '[.service, .source_ip] | @tsv' events.jsonl \
  | sort -u | cut -f1 | sort | uniq -c
```

### Python example — compute event rate per IP

```python
import json
from collections import Counter
from pathlib import Path

events = [json.loads(l) for l in Path("events.jsonl").read_text().splitlines() if l]
ip_counts = Counter(e["source_ip"] for e in events)

print("Top 10 source IPs:")
for ip, count in ip_counts.most_common(10):
    print(f"  {ip:20s}  {count:>6} events")
```

---

## Correlating Repeated Credentials

Even though raw passwords are never stored, the `hash_prefix` allows you to detect when the same credential is tried from multiple IPs — a strong indicator of a credential list in circulation.

```bash
# Find credential hash prefixes attempted more than 5 times
jq -r 'select(.credential_observed != null) | .credential_observed' events.jsonl \
  | sort | uniq -c | sort -rn | awk '$1 > 5'
```

---

## Forwarding Events to a SIEM

### Splunk HEC (HTTP Event Collector)

```bash
honeypot run-http \
  --port 8080 \
  --output-file events.jsonl \
  --splunk-hec-url https://splunk.example.com:8088/services/collector/event \
  --splunk-hec-token YOUR_HEC_TOKEN \
  --splunk-index honeypot \
  --splunk-source edge-decoy-1
```

### Elastic / OpenSearch (Bulk API)

```bash
honeypot run-api \
  --port 8000 \
  --elastic-url https://elastic.example.com/_bulk \
  --elastic-index honeypot-events \
  --elastic-username elastic \
  --elastic-password changeme
```

### Microsoft Sentinel via syslog-ng

```bash
honeypot run-ssh \
  --port 2222 \
  --cef-syslog-host syslog-ng.internal \
  --cef-syslog-port 6514 \
  --cef-syslog-protocol tcp
```

CEF/syslog forwarding escapes attacker-controlled values such as usernames,
paths, methods, and user agents before delivery. Downstream parser fields stay
stable even when an observed client sends CEF delimiters or embedded line
breaks.

### Filebeat / Logstash

Point Filebeat at `events.jsonl` with `json.message_key` decoding:

```yaml
filebeat.inputs:
  - type: log
    paths:
      - /opt/honeypot/events.jsonl
    json.message_key: timestamp
    json.keys_under_root: true
    json.add_error_key: true

output.logstash:
  hosts: ["logstash.example.com:5044"]
```

---

## Next Steps

- Enrich source IPs with geolocation and ASN data using a MaxMind GeoLite2 database.
- Build a dashboard in Grafana or Kibana showing event rates over time by service.
- Set up alerting when a single IP exceeds a threshold of attempts per minute.
- Review [Blue Team Basics](../docs/learning-paths/blue-team-basics.md) for the broader defensive context.
