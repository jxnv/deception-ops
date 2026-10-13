#!/usr/bin/env python3
"""
Automated Canary Token & Decoy Credential Generator.
Creates high-fidelity tripwires across endpoints, repositories, cloud configs, and filesystems.

Supported Canary Types:
1. AWS Honey-Keys: Seeded in ~/.aws/credentials (MITRE ATT&CK T1552.001)
2. Decoy Kubeconfigs: Seeded in staging pod filesystem / ~/.kube/config (MITRE ATT&CK T1552.001, T1609)
3. Sensitive Canary Files: "Executive_Comp_2026.pdf" with embedded HTTP callback (MITRE ATT&CK T1005)
4. Fake DB Connection URI: Seeded in .env / .env.example (MITRE ATT&CK T1552.001)
5. Cloned Webhook Token: Seeded in internal wiki/intranet documentation (MITRE ATT&CK T1552.005)
"""

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("canary_generator")


def _sanitize_path(base_dir: Path, relative_path: Path) -> Path:
    """
    Prevents path traversal vulnerabilities by verifying that the resolved
    target path stays strictly within the intended base directory.
    """
    resolved_base = base_dir.resolve()
    resolved_target = (base_dir / relative_path).resolve()
    if not resolved_target.is_relative_to(resolved_base):
        raise ValueError(
            f"Security Error: Path traversal detected! Target '{resolved_target}' "
            f"is outside base directory '{resolved_base}'"
        )
    return resolved_target


def generate_aws_honey_credentials(
    output_path: Path,
    webhook_url: str,
    token_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a realistic ~/.aws/credentials file embedded with canary tracking.
    In an enterprise deployment, this can be synced with Thinkst Canarytokens or
    AWS CloudTrail alerting on canary IAM access keys.

    Args:
        output_path: File destination for the credentials file.
        webhook_url: Triage listener endpoint for alerts.
        token_id: Optional unique token identifier; generated if omitted.

    Returns:
        Metadata dictionary detailing the generated decoy.
    """
    canary_id = (token_id or uuid.uuid4().hex[:8]).upper()
    sec_id = uuid.uuid4().hex[:12]

    content = f"""# Decoy AWS Credentials Profile - Deception Ops Canary
# Generated: {datetime.now(timezone.utc).isoformat()}
[default]
aws_access_key_id = AKIA{canary_id}CANARY99
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY{sec_id}KEY
region = us-east-1

[prod-data-lake]
aws_access_key_id = AKIA{canary_id[::-1]}DATA01
aws_secret_access_key = aBcdEfGhIjKlMnOpQrStUvWxYz{sec_id}SECRET
region = us-west-2

[secops-breakglass]
aws_access_key_id = AKIA{canary_id}ROOT07
aws_secret_access_key = zYxWvUtSrQpOnMlKjIhGfEdCbA{sec_id}ADMIN
region = eu-central-1
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Seeded AWS Honey Credentials at %s", output_path)

    return {
        "token_id": canary_id,
        "token_type": "aws_honey_key",
        "file_path": str(output_path),
        "tracking_endpoint": f"{webhook_url.rstrip('/')}/webhook/canary-callback",
        "mitre_ttp": "T1552.001 (Credentials in Files)",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "default_key_id": f"AKIA{canary_id}CANARY99",
            "prod_key_id": f"AKIA{canary_id[::-1]}DATA01",
        },
    }


def generate_kubeconfig_decoy(
    output_path: Path,
    webhook_url: str,
    token_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a realistic Kubernetes client config pointing to the canary triage server.
    Any attempt to execute 'kubectl cluster-info' or query the API server triggers an alert.

    Args:
        output_path: Destination path for the kubeconfig file.
        webhook_url: Triage listener endpoint.
        token_id: Optional unique token identifier.

    Returns:
        Metadata dictionary detailing the generated decoy.
    """
    canary_id = token_id or uuid.uuid4().hex[:12]
    beacon_endpoint = f"{webhook_url.rstrip('/')}/track?id={canary_id}&token_type=kubeconfig"

    content = f"""apiVersion: v1
kind: Config
preferences: {{}}
current-context: canary-staging-cluster-admin

clusters:
- cluster:
    # Canary HTTP beacon endpoint acting as decoy Kubernetes API server
    server: {beacon_endpoint}
    insecure-skip-tls-verify: true
  name: staging-k8s-us-east-1

contexts:
- context:
    cluster: staging-k8s-us-east-1
    namespace: kube-system
    user: staging-cluster-admin-canary
  name: canary-staging-cluster-admin

users:
- name: staging-cluster-admin-canary
  user:
    token: canary-k8s-jwt-{canary_id}-secret-cluster-access-token
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Seeded Decoy Kubeconfig at %s", output_path)

    return {
        "token_id": canary_id,
        "token_type": "kubeconfig",
        "file_path": str(output_path),
        "tracking_endpoint": beacon_endpoint,
        "mitre_ttp": "T1552.001 / T1609 (Container & Orchestration Access)",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "cluster_server": beacon_endpoint,
            "context": "canary-staging-cluster-admin",
        },
    }


def generate_canary_pdf(
    output_path: Path,
    webhook_url: str,
    token_id: Optional[str] = None,
    document_title: str = "Executive_Comp_2026.pdf"
) -> Dict[str, Any]:
    """
    Generates a valid, syntactically conforming PDF with embedded URI callback actions.
    When an adversary opens or renders the PDF in a compliant reader (Adobe Acrobat, Preview, Chrome),
    the /OpenAction / /URI triggers an automatic out-of-band HTTP beacon request.

    Args:
        output_path: Destination path for the canary PDF.
        webhook_url: Triage listener endpoint.
        token_id: Optional unique token identifier.
        document_title: Name/title of the decoy document.

    Returns:
        Metadata dictionary detailing the generated decoy.
    """
    canary_id = token_id or uuid.uuid4().hex[:12]
    beacon_url = f"{webhook_url.rstrip('/')}/track?id={canary_id}&token_type=canary_pdf&doc={document_title}"

    # Construct minimal valid PDF specification conforming to PDF 1.4
    # Includes /OpenAction pointing to URI action + clickable page link
    stream_content = (
        "BT\n"
        "/F1 18 Tf\n"
        "50 720 Td\n"
        "(RESTRICTED: EXECUTIVE COMPENSATION PLAN 2026-2028) Tj\n"
        "/F1 11 Tf\n"
        "0 -30 Td\n"
        "(BOARD OF DIRECTORS - STRICTLY CONFIDENTIAL - DO NOT DISTRIBUTE) Tj\n"
        "0 -25 Td\n"
        "(Document ID: DOC-EXEC-2026-" + canary_id[:6].upper() + ") Tj\n"
        "0 -20 Td\n"
        "(Authorized Recipients: Compensation Committee Only) Tj\n"
        "0 -40 Td\n"
        "(Tier 1 Executive Equity Tranche Allocations: Verified by Grant Thornton) Tj\n"
        "ET\n"
    ).encode("ascii")

    stream_len = len(stream_content)

    # Build PDF body objects
    objects: List[bytes] = []

    # 1: Catalog
    objects.append(
        b"<<\n"
        b"  /Type /Catalog\n"
        b"  /Pages 2 0 R\n"
        b"  /OpenAction 5 0 R\n"
        b">>"
    )

    # 2: Pages root
    objects.append(
        b"<<\n"
        b"  /Type /Pages\n"
        b"  /Kids [3 0 R]\n"
        b"  /Count 1\n"
        b">>"
    )

    # 3: Page object
    objects.append(
        b"<<\n"
        b"  /Type /Page\n"
        b"  /Parent 2 0 R\n"
        b"  /MediaBox [0 0 612 792]\n"
        b"  /Contents 4 0 R\n"
        b"  /Resources <<\n"
        b"    /Font << /F1 7 0 R >>\n"
        b"  >>\n"
        b"  /Annots [6 0 R]\n"
        b">>"
    )

    # 4: Page Content Stream
    objects.append(
        f"<<\n  /Length {stream_len}\n>>\nstream\n".encode("ascii")
        + stream_content
        + b"\nendstream"
    )

    # 5: OpenAction URI
    objects.append(
        f"<<\n  /Type /Action\n  /S /URI\n  /URI ({beacon_url})\n>>".encode("utf-8")
    )

    # 6: Link Annotation across whole page
    objects.append(
        f"<<\n  /Type /Annot\n  /Subtype /Link\n  /Rect [0 0 612 792]\n  /Border [0 0 0]\n  /A 5 0 R\n>>".encode("ascii")
    )

    # 7: Standard Helvetica Font
    objects.append(
        b"<<\n"
        b"  /Type /Font\n"
        b"  /Subtype /Type1\n"
        b"  /BaseFont /Helvetica-Bold\n"
        b">>"
    )

    # Assemble PDF with cross-reference table and byte offsets
    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    output_bytes = bytearray(header)
    offsets = [0]  # Object 0 is always free at offset 0

    for i, obj in enumerate(objects, start=1):
        offsets.append(len(output_bytes))
        output_bytes.extend(f"{i} 0 obj\n".encode("ascii"))
        output_bytes.extend(obj)
        output_bytes.extend(b"\nendobj\n")

    xref_offset = len(output_bytes)
    total_objects = len(objects) + 1
    output_bytes.extend(f"xref\n0 {total_objects}\n".encode("ascii"))
    output_bytes.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output_bytes.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

    trailer = (
        f"trailer\n"
        f"<<\n"
        f"  /Size {total_objects}\n"
        f"  /Root 1 0 R\n"
        f">>\n"
        f"startxref\n"
        f"{xref_offset}\n"
        f"%%EOF\n"
    )
    output_bytes.extend(trailer.encode("ascii"))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output_bytes)
    logger.info("Seeded Sensitive Canary PDF at %s", output_path)

    return {
        "token_id": canary_id,
        "token_type": "canary_pdf",
        "file_path": str(output_path),
        "tracking_endpoint": beacon_url,
        "mitre_ttp": "T1005 (Data from Local System) / T1083 (File Discovery)",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "document_title": document_title,
            "beacon_url": beacon_url,
        },
    }


def generate_database_env_decoy(
    output_path: Path,
    webhook_url: str,
    token_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a fake production database .env / .env.example configuration file.
    Includes an embedded telemetry beacon callback parameter.

    Args:
        output_path: File destination.
        webhook_url: Triage listener endpoint.
        token_id: Optional unique token identifier.

    Returns:
        Metadata dictionary detailing the generated decoy.
    """
    canary_id = token_id or uuid.uuid4().hex[:12]
    beacon_url = f"{webhook_url.rstrip('/')}/track?id={canary_id}&token_type=database_env"

    content = f"""# PRODUCTION DATABASE CONFIGURATION - HIGH PRIORITY
# Decoy Credential Trap for Source Code / Git Repositories / Build Artifacts
DB_ENGINE=postgresql
DB_HOST=internal-prod-db-cluster.corp.quora.internal
DB_PORT=5432
DB_USER=master_data_sync
DB_PASSWORD=P@ssw0rd2026_SecureSync_{canary_id[:8]}
DB_NAME=analytics_warehouse
DATABASE_URL=postgresql://master_data_sync:P%40ssw0rd2026_SecureSync_{canary_id[:8]}@internal-prod-db-cluster.corp.quora.internal:5432/analytics_warehouse

# Internal Diagnostics & Health Telemetry Beacon
TELEMETRY_BEACON={beacon_url}&component=db_connector
HEALTHCHECK_URL={beacon_url}&component=healthcheck
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Seeded Decoy Database .env at %s", output_path)

    return {
        "token_id": canary_id,
        "token_type": "database_env",
        "file_path": str(output_path),
        "tracking_endpoint": beacon_url,
        "mitre_ttp": "T1552.001 (Credentials in Files)",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "db_host": "internal-prod-db-cluster.corp.quora.internal",
            "db_user": "master_data_sync",
        },
    }


def generate_cloned_webhook_decoy(
    output_path: Path,
    webhook_url: str,
    token_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates an internal wiki runbook markdown file with an embedded webhook token.
    Adversaries performing reconnaissance on documentation or wiki repositories
    who trigger the curl command immediately fire a tripwire.

    Args:
        output_path: File destination.
        webhook_url: Triage listener endpoint.
        token_id: Optional unique token identifier.

    Returns:
        Metadata dictionary detailing the generated decoy.
    """
    canary_id = token_id or uuid.uuid4().hex[:12]
    callback_endpoint = f"{webhook_url.rstrip('/')}/webhook/canary-callback"
    beacon_endpoint = f"{webhook_url.rstrip('/')}/track?id={canary_id}&token_type=webhook_token"

    content = f"""# Engineering Wiki: Core Infrastructure & Deployment Secrets
> **Classification:** CONFIDENTIAL // INTERNAL USE ONLY  
> **Last Updated:** 2026-03-15 by SRE Team

---

### 1. Central Telemetry & Alert Ingestion Webhook
Use this internal webhook token for routing operational metrics and automated CI/CD notifications:

```bash
# Production Alertmanager Ingestion Endpoint
curl -X POST "{callback_endpoint}" \\
  -H "Content-Type: application/json" \\
  -H "X-Canary-Secret: whsec_{canary_id}_ci_prod_sync" \\
  -d '{{"token_id": "{canary_id}", "token_type": "webhook_token", "action": "ci_pipeline_sync"}}'
```

### 2. Emergency Break-Glass Token
- **Token ID:** `sec_token_{canary_id}`
- **Scope:** `corp:internal:infrastructure:admin`
- **Status:** Active
- **Health Check Beacon:** `{beacon_endpoint}`
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Seeded Cloned Webhook Wiki Decoy at %s", output_path)

    return {
        "token_id": canary_id,
        "token_type": "webhook_token",
        "file_path": str(output_path),
        "tracking_endpoint": callback_endpoint,
        "mitre_ttp": "T1552.005 / T1078 (Cloud API Credentials & Webhook Traps)",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "token_secret": f"whsec_{canary_id}_ci_prod_sync",
        },
    }


def deploy_all_canaries(
    target_dir: Path,
    webhook_url: str = "http://localhost:8000",
    manifest_path: Optional[Path] = None,
    token_types: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Orchestrates the deployment of all configured canary tripwires into the target directory.

    Args:
        target_dir: Root directory for canary deployment.
        webhook_url: Base URL of the triage receiver service.
        manifest_path: Path to write the deployment JSON manifest.
        token_types: Optional subset of token types to generate.

    Returns:
        List of generated decoy metadata records.
    """
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    types_to_deploy = set(token_types or ["all"])
    deploy_all = "all" in types_to_deploy

    results: List[Dict[str, Any]] = []

    # 1. AWS Honey Credentials
    if deploy_all or "aws_honey_key" in types_to_deploy:
        p = _sanitize_path(target_dir, Path(".aws/credentials"))
        results.append(generate_aws_honey_credentials(p, webhook_url))

    # 2. Decoy Kubeconfig
    if deploy_all or "kubeconfig" in types_to_deploy:
        p = _sanitize_path(target_dir, Path("k8s/kubeconfig"))
        results.append(generate_kubeconfig_decoy(p, webhook_url))

    # 3. Sensitive Canary PDF
    if deploy_all or "canary_pdf" in types_to_deploy:
        p = _sanitize_path(target_dir, Path("Executive_Comp_2026.pdf"))
        results.append(generate_canary_pdf(p, webhook_url))

    # 4. Fake Database .env and .env.example
    if deploy_all or "database_env" in types_to_deploy:
        p_env = _sanitize_path(target_dir, Path("app/.env"))
        p_example = _sanitize_path(target_dir, Path("app/.env.example"))
        res_env = generate_database_env_decoy(p_env, webhook_url)
        generate_database_env_decoy(p_example, webhook_url, token_id=res_env["token_id"])
        results.append(res_env)

    # 5. Cloned Webhook Token Wiki Decoy
    if deploy_all or "webhook_token" in types_to_deploy:
        p = _sanitize_path(target_dir, Path("docs/internal_wiki_secrets.md"))
        results.append(generate_cloned_webhook_decoy(p, webhook_url))

    # Save manifest
    manifest_file = manifest_path or (target_dir / "canaries_manifest.json")
    manifest_data = {
        "deployment_timestamp": datetime.now(timezone.utc).isoformat(),
        "target_directory": str(target_dir),
        "webhook_url": webhook_url,
        "total_canaries": len(results),
        "canaries": results,
    }
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    logger.info("Wrote canary deployment manifest to %s (%d tokens)", manifest_file, len(results))

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Automated Canary Token & Decoy Credential Generator"
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path("./simulated_corporate_share"),
        help="Destination directory to seed canary decoys (default: ./simulated_corporate_share)",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        default="http://localhost:8000",
        help="Base triage receiver webhook URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Custom path to output canary deployment manifest JSON",
    )
    parser.add_argument(
        "--token-types",
        nargs="+",
        default=["all"],
        help="Subset of tokens to deploy: aws_honey_key, kubeconfig, canary_pdf, database_env, webhook_token, all",
    )

    args = parser.parse_args()

    print("================================================================================")
    print("      DECEPTION-OPS: CANARY DECOY GENERATION & SEEDING ENGINE                   ")
    print("================================================================================")
    print(f"[*] Target Directory: {args.target_dir}")
    print(f"[*] Webhook URL:      {args.webhook_url}")
    print(f"[*] Token Types:      {args.token_types}\n")

    deployed = deploy_all_canaries(
        target_dir=args.target_dir,
        webhook_url=args.webhook_url,
        manifest_path=args.manifest,
        token_types=args.token_types,
    )

    print("\n[+] SUMMARY OF DEPLOYED CANARY TRIPWIRES:")
    print("--------------------------------------------------------------------------------")
    for item in deployed:
        print(f" - [{item['token_type'].upper()}] Token ID: {item['token_id']}")
        print(f"   Path:     {item['file_path']}")
        print(f"   Endpoint: {item['tracking_endpoint']}")
        print(f"   MITRE:    {item['mitre_ttp']}")
        print("--------------------------------------------------------------------------------")
    print(f"\n[+] Successfully deployed {len(deployed)} tripwires.")


if __name__ == "__main__":
    main()
