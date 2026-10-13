# DeceptionOps Canary: Enterprise Deception Architecture & High-Fidelity Tripwire Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI%200.110+-green.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-pytest%2019%20passed-success.svg)](https://pytest.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Covered-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade deception operations platform designed to seed realistic, zero-business-use tripwires across corporate environments, endpoints, and code repositories. When an adversary or malicious insider interacts with any canary decoy, out-of-band telemetry is correlated in real time, enriched with GeoIP/ASN/Tor threat intelligence, and immediately triggers high-signal SOC alerts and automated containment playbooks.

---

## 1. System Architecture & Tripwire Data Flow

```
  +-----------------------------------------------------------------------------+
  | DECOY GENERATION & SEEDING ENGINE (`generator/deploy_canaries.py`)          |
  |                                                                             |
  |  Canary Token Types Deployed:                                               |
  |   1. AWS Honey-Keys         --> Placed in fake developer `~/.aws/credentials`|
  |   2. Decoy Kubeconfigs      --> Placed in staging pod filesystem            |
  |   3. Sensitive Canary Files --> "Executive_Comp_2026.pdf" on shared drives  |
  |   4. Fake DB Connection URI --> Seeded in `.env.example` in source code      |
  |   5. Cloned Webhook Token   --> Embedded in internal wiki/intranet page     |
  +--------------------------------------+--------------------------------------+
                                         |
                                         | (Adversary triggers token)
                                         v
  +-----------------------------------------------------------------------------+
  | ADVERSARY ACTIONS (MITRE ATT&CK T1552, T1078, T1005, T1609)                 |
  |  - Threat actor or insider copies AWS keys and runs `aws s3 ls`             |
  |  - Attacker executes `kubectl cluster-info` or opens sensitive decoy PDF    |
  |  - Attacker tests fake database URI or triggers wiki webhook snippet        |
  +--------------------------------------+--------------------------------------+
                                         |
                                         | (Out-of-band HTTP/DNS callback)
                                         v
  +-----------------------------------------------------------------------------+
  | CENTRALIZED TRIAGE & ENRICHMENT LISTENER (`webhook_receiver/app.py`)         |
  |                                                                             |
  |  [FastAPI Microservice / Local Docker Container]                            |
  |   - Step 1: Receives real-time webhook callback with source IP & User-Agent |
  |   - Step 2: GeoIP & ASN Enrichment (identifies Tor, VPN, foreign DC)        |
  |   - Step 3: Correlation against internal IP allowlists & corporate VPN CIDR |
  |   - Step 4: Confidence Scoring: 100% True Positive (Decoy asset has NO valid|
  |             business use)                                                   |
  |                                      |                                      |
  |                                      v                                      |
  |  [HIGH-SIGNAL ALERT DISPATCHER: alert_dispatcher.py]                        |
  |   - Emits structured JSON alert to SIEM / Discord / Slack                   |
  |   - Triggers simulated containment: Revoke active session / isolate host   |
  +-----------------------------------------------------------------------------+
```

---

## 2. Seeded Canary Decoy Types & MITRE ATT&CK Mapping

| Canary Type | Deployment Location | Attacker Action Simulated | MITRE ATT&CK Technique |
| :--- | :--- | :--- | :--- |
| **AWS Honey-Keys** | Developer workstation `~/.aws/credentials` | Adversary runs `aws s3 ls --profile default` | **T1552.001** (Credentials in Files)<br>**T1078** (Valid Accounts) |
| **Decoy Kubeconfig** | Staging pod `~/.kube/config` or `k8s/kubeconfig` | Adversary attempts `kubectl cluster-info` | **T1552.001** (Credentials in Files)<br>**T1609** (Container Administration) |
| **Sensitive Canary PDF** | Corporate shared drive `Executive_Comp_2026.pdf` | Attacker opens document in PDF reader / browser | **T1005** (Data from Local System)<br>**T1083** (File & Directory Discovery) |
| **Fake Database URI** | Git source repositories `app/.env` / `.env.example` | Attacker connects to database cluster | **T1552.001** (Credentials in Files)<br>**T1190** (Credential Exploitation) |
| **Cloned Webhook Token** | Internal Engineering Wiki `docs/internal_wiki_secrets.md` | Attacker runs curl command from runbook | **T1552.005** (Cloud API Secrets)<br>**T1078** (Valid Service Accounts) |

---

## 3. Repository Structure

```
deception-ops-canary/
├── README.md                      # Enterprise deception architecture & tripwire deployment guide
├── requirements.txt               # FastAPI, uvicorn, requests, httpx, pydantic, geoip2, pytest
├── Dockerfile                     # Hardened, non-root container for the webhook receiver
├── docker-compose.yml             # One-click deployment manifest with health checks
├── .gitignore                     # Clean environment artifact filtering
├── generator/
│   ├── __init__.py
│   ├── deploy_canaries.py         # Automated credential & document decoy generator
│   └── templates/                 # Decoy templates (PDF, AWS, DB .env, Kubeconfig, Wiki)
│       ├── aws_credentials_template.ini
│       ├── database_env_template.env
│       ├── kubeconfig_template.yaml
│       └── wiki_secrets_template.md
├── webhook_receiver/
│   ├── __init__.py
│   ├── app.py                     # Async FastAPI triage listener & query API
│   ├── enricher.py                # GeoIP, ASN, Tor exit, and corporate VPN CIDR matcher
│   ├── models.py                  # Pydantic v2 schemas for triggers, enrichment, and alerts
│   └── alert_dispatcher.py        # High-signal alert dispatcher & automated containment engine
├── attacks/
│   ├── __init__.py
│   └── simulate_canary_trip.py    # Script simulating adversary accessing tripwires
└── tests/
    ├── __init__.py
    └── test_canary_pipeline.py    # Unit & end-to-end integration test suite
```

---

## 4. Step-by-Step Build & Execution Guide

### Step 1: Install Dependencies & Start Listener

```bash
# 1. Clone repository & install dependencies
git clone https://github.com/jxnv/deception-ops-canary.git
cd deception-ops-canary
pip install -r requirements.txt

# 2. Start the FastAPI Webhook Triage Receiver:
uvicorn webhook_receiver.app:app --host 0.0.0.0 --port 8000
```

Verify service health:
```bash
curl -s http://localhost:8000/healthz | jq .
```

### Step 2: Generate and Seed Canary Decoys

```bash
# Seed all 5 decoy types into simulated corporate directory
python3 generator/deploy_canaries.py --target-dir ./simulated_corporate_share
```

Outputs generated:
- `simulated_corporate_share/.aws/credentials`
- `simulated_corporate_share/k8s/kubeconfig`
- `simulated_corporate_share/Executive_Comp_2026.pdf`
- `simulated_corporate_share/app/.env` & `.env.example`
- `simulated_corporate_share/docs/internal_wiki_secrets.md`
- `simulated_corporate_share/canaries_manifest.json`

### Step 3: Simulate Adversary Interaction (Triggering Tripwires)

Simulate a threat actor finding the AWS credentials and executing reconnaissance through a Tor exit node:
```bash
python3 attacks/simulate_canary_trip.py --token-type aws_honey_key --profile tor_adversary
```

Simulate insider threat / lateral movement opening the executive compensation PDF:
```bash
python3 attacks/simulate_canary_trip.py --token-type canary_pdf --profile internal_insider
```

Simulate tripping all deployed tripwires:
```bash
python3 attacks/simulate_canary_trip.py --token-type all
```

### Step 4: Observe Real-Time Triage & High-Signal Alerting

Query the triage API for recorded alerts:
```bash
curl -s http://localhost:8000/api/v1/alerts | jq .
```

Filter by token type or network context:
```bash
curl -s "http://localhost:8000/api/v1/alerts?token_type=aws_honey_key" | jq .
curl -s "http://localhost:8000/api/v1/alerts?network_context=INTERNAL_LATERAL_MOVEMENT" | jq .
```

Inspect automated containment history:
```bash
curl -s http://localhost:8000/api/v1/containment/status | jq .
```

### Step 5: Run Automated Unit & Integration Tests

```bash
pytest tests/test_canary_pipeline.py -v
```

---

## 5. Sample SOC Alert Output

When a tripwire fires, the triage receiver formats and displays a high-visibility SOC banner:

```
================================================================================
 [!!! CRITICAL SECURITY ALERT: CANARY TRIPWIRE COMPROMISE DETECTED !!!]
================================================================================
 Alert ID:         bb25cea4-02bf-4bac-b118-ba2a83fdd6cc
 Event:            CRITICAL_CANARY_TRIPWIRE_TRIGGERED
 Fidelity:         100% (Zero False-Positive Decoy Asset)
 Token Type:       AWS_HONEY_KEY
 Token ID:         D642AE17
 MITRE ATT&CK:     T1552.001 (Credentials in Files) / T1078 (Unsanctioned Cloud Account Access)
 Adversary IP:     185.220.101.5
 User-Agent:       curl/8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0 OpenSSL/3.0.11
 Network Context:  TOR_EXIT_NODE
 Geolocation:      Amsterdam (Tor Exit), Netherlands [NL]
 ASN / Org:        AS60729 - Tor Anonymizing Overlay Network
--------------------------------------------------------------------------------
 AUTOMATED CONTAINMENT ACTIONS EXECUTED:
  [+] PERIMETER_FIREWALL_BLOCK               -> Target: 185.220.101.5 (SUCCESS_SIMULATED)
  [+] AWS_IAM_CREDENTIAL_REVOCATION          -> Target: AKIAD642AE17* (SUCCESS_SIMULATED)
  [+] SOAR_INCIDENT_TICKET_CREATED           -> Target: SEC-INC-2026-BE1EF7 (SUCCESS_SIMULATED)
================================================================================
```

---

## 6. Docker & Docker Compose Deployment

Run the complete solution inside a secure, non-root Docker container:

```bash
# Build and start receiver service
docker compose up -d

# Check health
curl http://localhost:8000/healthz

# View live container logs
docker compose logs -f webhook-receiver
```

---

## 7. Security Best Practices & Defensive Safeguards

1. **Deterministic 100% Signal-to-Noise Ratio**: Canary assets are never referenced in legitimate business workflows. Any interaction is treated as an active breach indicator with zero false positives.
2. **Defensive Path Traversal Protection**: The generator strictly validates target paths using `Path.resolve().is_relative_to(base_dir)` to prevent path traversal attempts.
3. **Least Privilege Containerization**: The Docker image executes under an unprivileged user (`appuser`, UID `10001`) with read-only principles and no shell access.
4. **Resilient Offline Threat Intelligence**: GeoIP and network classification smoothly fall back to RFC subnets, Tor exit sets, and datacenter IP heuristics when commercial MaxMind `.mmdb` files are offline.
5. **Immediate Automated Containment**: Integrates with automated SOAR response workflows to isolate compromised hosts and revoke active sessions before adversary lateral movement succeeds.
# deception-ops
