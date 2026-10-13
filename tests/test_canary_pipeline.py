"""
Automated Unit and Integration Test Suite for Deception Ops Canary System.
Verifies:
1. Decoy generation, format conformance, and security guardrails
2. Threat intelligence, GeoIP, and network context enrichment
3. FastAPI webhook receiver endpoints and background triage execution
4. Automated containment execution and alert verification
5. Full end-to-end tripwire-to-containment pipeline
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from generator.deploy_canaries import (
    deploy_all_canaries,
    generate_aws_honey_credentials,
    generate_kubeconfig_decoy,
    generate_canary_pdf,
    generate_database_env_decoy,
    generate_cloned_webhook_decoy,
    _sanitize_path,
)
from webhook_receiver.app import app, ALERTS_STORE, TRANSPARENT_GIF_BYTES
from webhook_receiver.enricher import ThreatIntelligenceEnricher, map_mitre_ttp
from webhook_receiver.models import NetworkContext


@pytest.fixture(autouse=True)
def clean_alerts_store():
    """Ensure clean alert store before and after each test."""
    ALERTS_STORE.clear()
    yield
    ALERTS_STORE.clear()


@pytest.fixture
def client():
    """FastAPI test client instance with lifespan context."""
    with TestClient(app) as test_client:
        yield test_client


# ==============================================================================
# 1. DECOY GENERATOR & SECURITY TESTS
# ==============================================================================

def test_generate_aws_honey_credentials(tmp_path: Path):
    """Verifies AWS honey credentials file creation and canary ID embedding."""
    output_path = tmp_path / ".aws" / "credentials"
    result = generate_aws_honey_credentials(output_path, "http://localhost:8000")

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "[default]" in content
    assert "[prod-data-lake]" in content
    assert "aws_access_key_id = AKIA" in content
    assert result["token_type"] == "aws_honey_key"
    assert result["mitre_ttp"] == "T1552.001 (Credentials in Files)"


def test_generate_kubeconfig_decoy(tmp_path: Path):
    """Verifies decoy kubeconfig structure and tracking server URL."""
    output_path = tmp_path / "k8s" / "kubeconfig"
    result = generate_kubeconfig_decoy(output_path, "http://localhost:8000")

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "apiVersion: v1" in content
    assert "canary-staging-cluster-admin" in content
    assert result["tracking_endpoint"] in content
    assert result["token_type"] == "kubeconfig"


def test_generate_canary_pdf(tmp_path: Path):
    """Verifies valid PDF syntax, magic bytes, and embedded URI callback action."""
    output_path = tmp_path / "Executive_Comp_2026.pdf"
    result = generate_canary_pdf(output_path, "http://localhost:8000")

    assert output_path.exists()
    bytes_data = output_path.read_bytes()
    assert bytes_data.startswith(b"%PDF-1.4")
    assert b"%%EOF" in bytes_data
    assert b"/OpenAction" in bytes_data
    assert b"/URI" in bytes_data
    assert result["tracking_endpoint"].encode("utf-8") in bytes_data
    assert result["token_type"] == "canary_pdf"


def test_generate_database_env_decoy(tmp_path: Path):
    """Verifies database .env configuration and telemetry beacon."""
    output_path = tmp_path / "app" / ".env"
    result = generate_database_env_decoy(output_path, "http://localhost:8000")

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "DB_HOST=internal-prod-db-cluster.corp.quora.internal" in content
    assert "TELEMETRY_BEACON=" in content
    assert result["token_id"] in content
    assert result["token_type"] == "database_env"


def test_generate_cloned_webhook_decoy(tmp_path: Path):
    """Verifies markdown wiki decoy containing curl tripwire."""
    output_path = tmp_path / "docs" / "wiki.md"
    result = generate_cloned_webhook_decoy(output_path, "http://localhost:8000")

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "Engineering Wiki" in content
    assert "curl -X POST" in content
    assert result["token_id"] in content


def test_deploy_all_canaries_and_manifest(tmp_path: Path):
    """Verifies orchestration of all 5 canary types and manifest generation."""
    manifest_path = tmp_path / "manifest.json"
    results = deploy_all_canaries(
        target_dir=tmp_path,
        webhook_url="http://localhost:8000",
        manifest_path=manifest_path,
    )

    assert len(results) == 5
    assert manifest_path.exists()
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_data["total_canaries"] == 5
    assert len(manifest_data["canaries"]) == 5


def test_path_traversal_protection(tmp_path: Path):
    """Verifies path traversal attempts are detected and rejected."""
    malicious_relative = Path("../../etc/passwd")
    with pytest.raises(ValueError, match="Path traversal detected"):
        _sanitize_path(tmp_path, malicious_relative)


# ==============================================================================
# 2. THREAT INTELLIGENCE & ENRICHMENT TESTS
# ==============================================================================

def test_enricher_loopback():
    enricher = ThreatIntelligenceEnricher()
    enriched = enricher.enrich("127.0.0.1")
    assert enriched.network_context == NetworkContext.LOOPBACK_LOCAL_SIMULATION
    assert enriched.is_private_ip is True


def test_enricher_internal_lateral_movement():
    enricher = ThreatIntelligenceEnricher()
    # RFC 1918 10.x.x.x
    enriched_10 = enricher.enrich("10.10.4.15")
    assert enriched_10.network_context == NetworkContext.INTERNAL_LATERAL_MOVEMENT
    assert enriched_10.is_private_ip is True

    # RFC 1918 192.168.x.x
    enriched_192 = enricher.enrich("192.168.1.50")
    assert enriched_192.network_context == NetworkContext.INTERNAL_LATERAL_MOVEMENT


def test_enricher_corporate_vpn():
    enricher = ThreatIntelligenceEnricher(corporate_vpn_cidrs=["100.64.0.0/10", "10.200.0.0/16"])
    enriched_vpn = enricher.enrich("100.64.12.99")
    assert enriched_vpn.network_context == NetworkContext.CORPORATE_VPN
    assert enriched_vpn.is_corporate_vpn is True


def test_enricher_tor_exit_node():
    enricher = ThreatIntelligenceEnricher()
    enriched_tor = enricher.enrich("185.220.101.5")
    assert enriched_tor.network_context == NetworkContext.TOR_EXIT_NODE
    assert enriched_tor.is_tor_exit_node is True


def test_enricher_external_datacenter():
    enricher = ThreatIntelligenceEnricher()
    enriched_dc = enricher.enrich("198.51.100.24")
    assert enriched_dc.is_private_ip is False
    assert enriched_dc.network_context in [
        NetworkContext.SUSPICIOUS_DATACENTER_PROXY,
        NetworkContext.EXTERNAL_INTERNET_ACCESS,
    ]


# ==============================================================================
# 3. FASTAPI RECEIVER ENDPOINTS & TRIAGE PIPELINE TESTS
# ==============================================================================

def test_health_check_endpoint(client: TestClient):
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "alerts_recorded" in data


def test_post_canary_webhook_callback(client: TestClient):
    """Tests POST /webhook/canary-callback with AWS Honey-Key trigger."""
    payload = {
        "token_id": "TEST_KEY_01",
        "token_type": "aws_honey_key",
        "source_ip": "185.220.101.5",  # Tor exit IP
        "action": "aws_s3_ls",
    }
    headers = {"User-Agent": "aws-cli/2.13.0"}
    response = client.post("/webhook/canary-callback", json=payload, headers=headers)

    assert response.status_code == 200
    res_json = response.json()
    assert res_json["status"] == "received"
    assert res_json["action"] == "triaging"

    # Verify alert was generated and stored in background
    alerts_resp = client.get("/api/v1/alerts")
    assert alerts_resp.status_code == 200
    alerts_data = alerts_resp.json()
    assert alerts_data["total"] == 1

    alert = alerts_data["alerts"][0]
    assert alert["token_id"] == "TEST_KEY_01"
    assert alert["token_type"] == "aws_honey_key"
    assert alert["source_ip"] == "185.220.101.5"
    assert alert["fidelity"] == "100%"
    assert alert["severity"] == "CRITICAL"
    assert alert["network_context"] == "TOR_EXIT_NODE"
    assert len(alert["containment_actions"]) >= 2


def test_get_track_beacon_endpoint(client: TestClient):
    """Tests GET /track for canary PDF opening."""
    params = {
        "id": "PDF_TOKEN_77",
        "token_type": "canary_pdf",
        "doc": "Executive_Comp_2026.pdf",
    }
    headers = {
        "User-Agent": "Adobe Acrobat Reader/23.0",
        "X-Forwarded-For": "10.10.4.52",  # Internal lateral IP
    }
    response = client.get("/track", params=params, headers=headers)

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/gif"
    assert response.content == TRANSPARENT_GIF_BYTES

    # Verify alert record
    alerts_resp = client.get("/api/v1/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()["alerts"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["token_id"] == "PDF_TOKEN_77"
    assert alert["token_type"] == "canary_pdf"
    assert alert["network_context"] == "INTERNAL_LATERAL_MOVEMENT"
    assert alert["source_ip"] == "10.10.4.52"


def test_generic_honeypot_webhook(client: TestClient):
    """Tests POST /webhook/generic accepting external honeypot payload."""
    payload = {
        "canarytoken": "GENERIC_HONEY_99",
        "channel": "generic",
        "source_ip": "100.64.12.99",
    }
    response = client.post("/webhook/generic", json=payload)
    assert response.status_code == 200

    alerts = client.get("/api/v1/alerts").json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["token_id"] == "GENERIC_HONEY_99"


def test_alerts_filtering_and_retrieval(client: TestClient):
    """Tests alert filtering by token_type and retrieval by ID."""
    # Trigger two different alerts
    client.post("/webhook/canary-callback", json={"token_id": "AWS_1", "token_type": "aws_honey_key"})
    client.post("/webhook/canary-callback", json={"token_id": "DB_1", "token_type": "database_env"})

    # Check total
    assert client.get("/api/v1/alerts").json()["total"] == 2

    # Filter by token_type
    resp_filtered = client.get("/api/v1/alerts?token_type=database_env")
    assert resp_filtered.json()["total"] == 1
    alert_db = resp_filtered.json()["alerts"][0]
    assert alert_db["token_type"] == "database_env"

    # Query specific alert by ID
    alert_id = alert_db["alert_id"]
    single_alert_resp = client.get(f"/api/v1/alerts/{alert_id}")
    assert single_alert_resp.status_code == 200
    assert single_alert_resp.json()["alert_id"] == alert_id


def test_containment_status_endpoint(client: TestClient):
    """Tests querying containment actions history."""
    client.post("/webhook/canary-callback", json={"token_id": "K8S_1", "token_type": "kubeconfig"})
    resp = client.get("/api/v1/containment/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_actions"] > 0
    assert len(data["recent_actions"]) > 0


# ==============================================================================
# 4. END-TO-END INTEGRATION PIPELINE TEST
# ==============================================================================

def test_end_to_end_canary_pipeline(tmp_path: Path, client: TestClient):
    """
    Full End-to-End Test:
    1. Deploy canary decoys to staging filesystem
    2. Read deployment manifest
    3. Adversary trips the AWS honey key
    4. Webhook receiver enriches metadata, verifies 100% fidelity, and executes containment
    """
    # 1. Deploy canaries
    manifest_file = tmp_path / "test_manifest.json"
    deployed = deploy_all_canaries(
        target_dir=tmp_path,
        webhook_url="http://testserver",
        manifest_path=manifest_file,
    )
    assert len(deployed) == 5

    # 2. Extract AWS canary token ID from manifest
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    aws_canary = next(c for c in manifest_data["canaries"] if c["token_type"] == "aws_honey_key")
    token_id = aws_canary["token_id"]

    # 3. Simulate adversary trip
    trip_payload = {
        "token_id": token_id,
        "token_type": "aws_honey_key",
        "source_ip": "185.220.101.6",  # Tor exit node
        "command": "aws s3 ls",
    }
    trip_headers = {"User-Agent": "aws-cli/2.13.0 Python/3.11 Linux/5.15"}
    trip_resp = client.post("/webhook/canary-callback", json=trip_payload, headers=trip_headers)
    assert trip_resp.status_code == 200

    # 4. Verify central triage alert
    alerts_resp = client.get("/api/v1/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()["alerts"]
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert["token_id"] == token_id
    assert alert["fidelity"] == "100%"
    assert alert["network_context"] == "TOR_EXIT_NODE"
    assert "T1552.001" in alert["ttp"]

    # Verify containment actions
    actions = alert["containment_actions"]
    assert any(a["action_type"] == "AWS_IAM_CREDENTIAL_REVOCATION" for a in actions)
    assert any(a["action_type"] == "SOAR_INCIDENT_TICKET_CREATED" for a in actions)
