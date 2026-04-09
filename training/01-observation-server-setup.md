# Tutorial 01 — Setting Up Observation Servers

## What Are Decoy Servers?

A decoy (honeypot) server is a network-accessible service that looks real to an attacker but has no legitimate users. Its sole purpose is observation: every connection attempt reveals information about attacker tooling, credential lists, and targeting behavior — all without risk to production infrastructure.

Honeypot Foundry provides two observation servers:

| Server | Protocol | Default Port | What it captures |
|--------|----------|--------------|-----------------|
| SSH observation | TCP/SSH | 2222 | Usernames, credential hash prefixes, SSH key types |
| HTTP observation | TCP/HTTP | 8080 | URLs probed, HTTP methods, User-Agent strings |

**Security invariant**: neither server ever grants access. Authentication is hardcoded to fail. No shell, no file access, no data exfiltration path exists.

---

## Prerequisites

- Python 3.11+
- `pip install -e ".[dev]"` from the repository root
- An SSH host key (generated below)

---

## Step 1 — Generate the SSH Host Key

The SSH observation server needs a host key to present to connecting clients. Generate one with `ssh-keygen`:

```bash
ssh-keygen -t ed25519 -f ./hostkey -N ""
```

This creates two files: `hostkey` (private key) and `hostkey.pub` (public key). The server only uses the private key file. Keep this key consistent across restarts so that repeat scanners do not generate new "host key changed" warnings.

---

## Step 2 — Configure Environment Variables

Copy the example file and adjust values for your deployment:

```bash
cp .env.example .env
```

Key settings:

```
SSH_LISTEN_PORT=2222      # Port < 1024 requires root or CAP_NET_BIND_SERVICE
SSH_HOST_KEY_PATH=./hostkey
HTTP_LISTEN_PORT=8080
EVENT_OUTPUT_FILE=events.jsonl
```

---

## Step 3 — Start the SSH Observation Server

```bash
python -m cli.main run-ssh \
  --host 0.0.0.0 \
  --port 2222 \
  --host-key ./hostkey \
  --output-file events.jsonl
```

You should see:

```
SSH observation server listening on 0.0.0.0:2222
```

Test it from another terminal (expected: authentication failure):

```bash
ssh -p 2222 root@127.0.0.1
# Permission denied (password)
```

---

## Step 4 — Start the HTTP Observation Server

```bash
python -m cli.main run-http \
  --host 0.0.0.0 \
  --port 8080 \
  --output-file events.jsonl
```

Test with curl:

```bash
curl -s http://127.0.0.1:8080/admin
# {"status":"ok"}
```

---

## Step 5 — Reading JSONL Output

Each event is one JSON object per line in `events.jsonl`. Preview live output:

```bash
tail -f events.jsonl | python -m json.tool
```

Example SSH event:

```json
{
  "timestamp": "2026-04-06T14:23:11.042Z",
  "service": "ssh",
  "source_ip": "203.0.113.45",
  "source_port": 54321,
  "username": "admin",
  "credential_observed": "[masked:len=8,hash_prefix=5e884898]",
  "path": null,
  "method": null,
  "user_agent": null,
  "metadata": {}
}
```

The `credential_observed` field contains only a masked representation — the raw password is never written anywhere.

---

## Step 6 — Verify Dependencies

```bash
python -m cli.main healthcheck
# All dependencies available.
```

---

## Next Steps

- Proceed to [Tutorial 02 — Analyzing Events](02-analyzing-events.md) to learn how to identify scanning patterns.
- Deploy behind a firewall or in a DMZ to capture real internet traffic.
- Set `SSH_LISTEN_PORT=22` (requires elevated privileges) to attract the widest range of automated scanners.
