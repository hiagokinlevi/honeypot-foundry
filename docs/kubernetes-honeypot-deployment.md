# Kubernetes Honeypot Deployment

This guide describes how to deploy the honeypot services to Kubernetes using the Helm chart in `helm/honeypot-foundry`, including:

- Multi-service honeypot pods
- Service exposure options
- Horizontal Pod Autoscaling (HPA)
- PodDisruptionBudget (PDB)
- Network policy isolation
- Centralized log forwarding

## Prerequisites

- Kubernetes cluster (1.24+ recommended)
- Helm 3.10+
- `kubectl` access to target namespace

## Chart Location

```bash
helm/honeypot-foundry
```

## Quick Start

```bash
kubectl create namespace honeypots

helm upgrade --install honeypot-foundry ./helm/honeypot-foundry \
  --namespace honeypots
```

Verify resources:

```bash
kubectl get deploy,svc,hpa,pdb -n honeypots
kubectl get pods -n honeypots -o wide
```

## Service Exposure

Use chart values to control service type and ports for each protocol decoy.

Typical options:

- `ClusterIP` for internal-only capture
- `NodePort` for lab environments
- `LoadBalancer` for internet-facing research deployments

Example override file (`values-exposure.yaml`):

```yaml
service:
  type: LoadBalancer
  annotations: {}

ports:
  ssh: 2222
  http: 8080
  api: 8000
  ftp: 2121
  rdp: 3389
```

Apply:

```bash
helm upgrade --install honeypot-foundry ./helm/honeypot-foundry \
  --namespace honeypots \
  -f values-exposure.yaml
```

## Horizontal Scaling

Enable/adjust HPA to scale pods based on utilization in high-volume attack windows.

Example (`values-hpa.yaml`):

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

Apply:

```bash
helm upgrade --install honeypot-foundry ./helm/honeypot-foundry \
  --namespace honeypots \
  -f values-hpa.yaml
```

## High Availability

PDB is chart-managed to reduce voluntary disruption during node maintenance.

Example:

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

## Network Isolation

Use the chart NetworkPolicy controls to enforce isolation and default-deny egress where appropriate.

Recommended baseline:

- Allow ingress only to exposed honeypot ports
- Allow egress only to DNS + logging backends (Splunk/Elastic/syslog)
- Deny all other egress

## Centralized Logging

Honeypot telemetry is emitted as structured JSON and can be forwarded centrally.

Configure environment variables/arguments through chart values for supported transports:

- Splunk HEC
- Elastic bulk API
- CEF/syslog (Sentinel-compatible)

Example (`values-logging.yaml`):

```yaml
env:
  - name: SPLUNK_HEC_URL
    value: "https://splunk.example.com:8088/services/collector/event"
  - name: SPLUNK_HEC_TOKEN
    valueFrom:
      secretKeyRef:
        name: honeypot-secrets
        key: splunk-hec-token
  - name: CEF_SYSLOG_HOST
    value: "syslog-ng.logging.svc.cluster.local"
  - name: CEF_SYSLOG_PORT
    value: "6514"
  - name: CEF_SYSLOG_PROTOCOL
    value: "tcp"
```

Apply:

```bash
kubectl -n honeypots create secret generic honeypot-secrets \
  --from-literal=splunk-hec-token='<token>'

helm upgrade --install honeypot-foundry ./helm/honeypot-foundry \
  --namespace honeypots \
  -f values-logging.yaml
```

## Validation

Check logs and events:

```bash
kubectl logs -n honeypots deploy/honeypot-foundry --tail=200
```

Generate traffic and confirm receipt in your SIEM/log sink.

## Security Notes

- Deploy only in authorized environments.
- Keep decoys isolated from production workloads.
- Store all tokens/credentials in Kubernetes Secrets.
- Restrict dashboard/API access with RBAC and namespace scoping.
