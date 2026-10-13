#!/usr/bin/env python3
"""
Adversary Tripwire Simulation Script.
Simulates threat actor or malicious insider interactions with seeded canary tripwires:
- AWS Honey-Key enumeration: `aws s3 ls` (MITRE ATT&CK T1552.001, T1078)
- Decoy Kubeconfig query: `kubectl cluster-info` (MITRE ATT&CK T1609)
- Sensitive Canary Document access: opening `Executive_Comp_2026.pdf` (MITRE ATT&CK T1005)
- Decoy Database connection probe: database connection test from .env (MITRE ATT&CK T1552.001)
- Cloned Webhook Token exploitation: running curl snippet from internal wiki (MITRE ATT&CK T1552.005)
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("adversary_sim")

PROFILES = {
    "tor_adversary": {
        "ip": "185.220.101.5",
        "user_agent": "curl/8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0 OpenSSL/3.0.11",
        "description": "External threat actor routing through Tor exit node",
    },
    "internal_insider": {
        "ip": "10.10.4.52",
        "user_agent": "aws-cli/2.13.0 Python/3.11.4 Darwin/23.1.0 botocore/2.4.0",
        "description": "Rogue developer on corporate internal LAN (Lateral Movement)",
    },
    "cloud_attacker": {
        "ip": "198.51.100.24",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "description": "Adversary operating from external bulletproof hosting / VPS",
    },
    "corporate_vpn": {
        "ip": "100.64.12.99",
        "user_agent": "kubectl/v1.28.2 (darwin/arm64) kubernetes/89b140f",
        "description": "Compromised remote contractor laptop on Corporate WireGuard/Tailscale VPN",
    },
    "local": {
        "ip": "127.0.0.1",
        "user_agent": "Python-urllib/3.11",
        "description": "Direct local simulation execution",
    },
}


def load_manifest(manifest_path: Path) -> Dict[str, Any]:
    """Loads canary manifest if available to resolve actual deployed token IDs."""
    if manifest_path.exists():
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Could not read manifest file '%s': %s", manifest_path, e)
    return {}


def simulate_tripwire(
    token_type: str,
    receiver_url: str,
    profile_name: str = "tor_adversary",
    manifest_data: Optional[Dict[str, Any]] = None,
    custom_ip: Optional[str] = None,
    custom_user_agent: Optional[str] = None,
) -> bool:
    """
    Simulates adversary behavior triggering a specific canary token.
    """
    profile = PROFILES.get(profile_name, PROFILES["tor_adversary"])
    sim_ip = custom_ip or profile["ip"]
    sim_ua = custom_user_agent or profile["user_agent"]
    receiver_url = receiver_url.rstrip("/")

    # Resolve token_id from manifest if present
    token_id = f"sim_{token_type[:6]}_99"
    if manifest_data and "canaries" in manifest_data:
        for c in manifest_data["canaries"]:
            if c.get("token_type") == token_type:
                token_id = c.get("token_id", token_id)
                break

    print("\n" + "=" * 76)
    print(f" [*] SIMULATING ADVERSARY ACTION: {token_type.upper()}")
    print("=" * 76)
    print(f" Threat Profile:     {profile_name} ({profile['description']})")
    print(f" Simulated IP:       {sim_ip}")
    print(f" User-Agent:         {sim_ua}")
    print(f" Target Token ID:    {token_id}")

    headers = {
        "User-Agent": sim_ua,
        "X-Forwarded-For": sim_ip,
        "X-Real-IP": sim_ip,
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            if token_type == "aws_honey_key":
                print(" [>] Action: Threat actor executed `aws s3 ls --profile default`")
                print(f" [>] Key used: AKIA{token_id.upper()}CANARY99")
                url = f"{receiver_url}/webhook/canary-callback"
                payload = {
                    "token_id": token_id,
                    "token_type": "aws_honey_key",
                    "source_ip": sim_ip,
                    "action": "aws_cli_s3_ls",
                    "command": "aws s3 ls",
                    "access_key": f"AKIA{token_id.upper()}CANARY99",
                }
                resp = client.post(url, json=payload, headers=headers)

            elif token_type == "kubeconfig":
                print(" [>] Action: Threat actor ran `kubectl cluster-info --kubeconfig k8s/kubeconfig`")
                url = f"{receiver_url}/track"
                params = {
                    "id": token_id,
                    "token_type": "kubeconfig",
                    "cmd": "cluster-info",
                }
                resp = client.get(url, params=params, headers=headers)

            elif token_type == "canary_pdf":
                print(" [>] Action: Threat actor downloaded and opened `Executive_Comp_2026.pdf`")
                url = f"{receiver_url}/track"
                params = {
                    "id": token_id,
                    "token_type": "canary_pdf",
                    "doc": "Executive_Comp_2026.pdf",
                }
                resp = client.get(url, params=params, headers=headers)

            elif token_type == "database_env":
                print(" [>] Action: Threat actor attempted to connect to database using .env credentials")
                url = f"{receiver_url}/track"
                params = {
                    "id": token_id,
                    "token_type": "database_env",
                    "component": "db_connector",
                }
                resp = client.get(url, params=params, headers=headers)

            elif token_type == "webhook_token":
                print(" [>] Action: Threat actor copied curl snippet from wiki and executed webhook call")
                url = f"{receiver_url}/webhook/canary-callback"
                payload = {
                    "token_id": token_id,
                    "token_type": "webhook_token",
                    "source_ip": sim_ip,
                    "action": "wiki_webhook_exploit",
                    "secret": f"whsec_{token_id}_ci_prod_sync",
                }
                resp = client.post(url, json=payload, headers=headers)

            else:
                logger.error("Unknown token type: %s", token_type)
                return False

            print(f" [<] Triage Response HTTP Status: {resp.status_code}")
            try:
                print(f" [<] Response Body: {resp.json()}")
            except Exception:
                print(f" [<] Response Content Type: {resp.headers.get('content-type', 'unknown')}")
            print("=" * 76)
            return resp.status_code in [200, 202]

    except Exception as e:
        logger.error("Tripwire simulation failed: %s", e)
        print(f"\n[!] Error connecting to receiver at {receiver_url}: {e}")
        print("    Ensure the receiver is running: uvicorn webhook_receiver.app:app --host 0.0.0.0 --port 8000")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Simulate adversary or insider triggering canary tripwires"
    )
    parser.add_argument(
        "--token-type",
        type=str,
        default="aws_honey_key",
        choices=["aws_honey_key", "kubeconfig", "canary_pdf", "database_env", "webhook_token", "all"],
        help="Canary token type to trip (default: aws_honey_key)",
    )
    parser.add_argument(
        "--receiver-url",
        type=str,
        default="http://localhost:8000",
        help="Base URL of Canary Triage Service (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default="tor_adversary",
        choices=list(PROFILES.keys()),
        help="Adversary profile to emulate (default: tor_adversary)",
    )
    parser.add_argument(
        "--source-ip",
        type=str,
        default=None,
        help="Custom IP address to simulate (overrides profile IP)",
    )
    parser.add_argument(
        "--user-agent",
        type=str,
        default=None,
        help="Custom User-Agent header string",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("./simulated_corporate_share/canaries_manifest.json"),
        help="Path to canary deployment manifest JSON",
    )

    args = parser.parse_args()

    manifest_data = load_manifest(args.manifest)

    if args.token_type == "all":
        types = ["aws_honey_key", "kubeconfig", "canary_pdf", "database_env", "webhook_token"]
        print(f"[*] Tripping all {len(types)} canary tripwires sequentially...")
        success_count = 0
        for t in types:
            ok = simulate_tripwire(
                token_type=t,
                receiver_url=args.receiver_url,
                profile_name=args.profile,
                manifest_data=manifest_data,
                custom_ip=args.source_ip,
                custom_user_agent=args.user_agent,
            )
            if ok:
                success_count += 1
            time.sleep(0.5)
        print(f"\n[+] Completed {success_count}/{len(types)} trips successfully.")
    else:
        simulate_tripwire(
            token_type=args.token_type,
            receiver_url=args.receiver_url,
            profile_name=args.profile,
            manifest_data=manifest_data,
            custom_ip=args.source_ip,
            custom_user_agent=args.user_agent,
        )


if __name__ == "__main__":
    main()
