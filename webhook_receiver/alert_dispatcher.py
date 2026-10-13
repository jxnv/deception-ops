"""
High-Signal Alert Dispatcher & Automated Containment Engine.
Emits structured JSON alerts to SIEM, Discord, Slack, and local audit storage.
Triggers immediate simulated containment actions (session revocation, host isolation).
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

from webhook_receiver.models import CanaryAlert, ContainmentAction, EnrichmentData, NetworkContext

logger = logging.getLogger("alert_dispatcher")


class AlertDispatcher:
    """
    Dispatches critical alerts to external channels (SIEM, Slack, Discord)
    and executes simulated host isolation and session revocation workflows.
    """

    def __init__(
        self,
        audit_log_path: Optional[Path] = None,
        slack_webhook_url: Optional[str] = None,
        discord_webhook_url: Optional[str] = None,
        siem_endpoint_url: Optional[str] = None,
    ):
        self.audit_log_path = audit_log_path or Path("./canary_alerts_audit.jsonl")
        self.slack_webhook_url = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.discord_webhook_url = discord_webhook_url or os.getenv("DISCORD_WEBHOOK_URL")
        self.siem_endpoint_url = siem_endpoint_url or os.getenv("SIEM_ENDPOINT_URL")
        self.containment_history: List[ContainmentAction] = []

    def execute_automated_containment(
        self,
        token_type: str,
        token_id: str,
        source_ip: str,
        network_context: str
    ) -> List[ContainmentAction]:
        """
        Simulates enterprise automated containment against adversary indicators:
        1. Host Isolation (EDR / iptables / Kubernetes NetworkPolicy)
        2. Credential & Session Revocation (AWS IAM / DB / K8s / Tokens)
        3. Automated Incident Ticket Generation (SOAR P1)
        """
        actions: List[ContainmentAction] = []
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Host Network Isolation Action
        is_internal = network_context in [
            NetworkContext.INTERNAL_LATERAL_MOVEMENT.value,
            NetworkContext.LOOPBACK_LOCAL_SIMULATION.value,
            NetworkContext.CORPORATE_VPN.value,
        ]

        if is_internal:
            host_action = ContainmentAction(
                action_type="EDR_HOST_NETWORK_ISOLATION",
                target=source_ip,
                status="SUCCESS_SIMULATED",
                executed_at=now_str,
                details={
                    "mechanism": "CrowdStrike/Defender Simulated Agent Command",
                    "command": f"isolate-endpoint --ip {source_ip} --allow-traffic secops-c2",
                    "policy": "Block all inbound and outbound network sockets except security telemetry",
                },
            )
        else:
            host_action = ContainmentAction(
                action_type="PERIMETER_FIREWALL_BLOCK",
                target=source_ip,
                status="SUCCESS_SIMULATED",
                executed_at=now_str,
                details={
                    "mechanism": "Palo Alto / AWS WAF Perimeter Rule Ingestion",
                    "rule": f"deny ip {source_ip}/32 any priority 1",
                    "duration": "Indefinite quarantine until SecOps review",
                },
            )
        actions.append(host_action)

        # 2. Targeted Credential & Session Revocation
        if token_type == "aws_honey_key":
            cred_action = ContainmentAction(
                action_type="AWS_IAM_CREDENTIAL_REVOCATION",
                target=f"AKIA{token_id.upper()}*",
                status="SUCCESS_SIMULATED",
                executed_at=now_str,
                details={
                    "action": "aws iam update-access-key --status Inactive",
                    "sts_action": "aws iam put-user-policy --policy-name RevokeOlderSessions",
                    "effect": "Immediate invalidation of all STS temporary tokens and API keys",
                },
            )
            actions.append(cred_action)

        elif token_type == "kubeconfig":
            k8s_action = ContainmentAction(
                action_type="KUBERNETES_RBAC_SERVICE_ACCOUNT_REVOCATION",
                target=f"canary-k8s-jwt-{token_id}",
                status="SUCCESS_SIMULATED",
                executed_at=now_str,
                details={
                    "cluster": "staging-k8s-us-east-1",
                    "namespace": "kube-system",
                    "action": f"kubectl delete secret -l token-id={token_id}",
                    "effect": "Kube-API server rejected subsequent Bearer tokens",
                },
            )
            actions.append(k8s_action)

        elif token_type == "database_env":
            db_action = ContainmentAction(
                action_type="DATABASE_ACCESS_REVOCATION",
                target="master_data_sync@analytics_warehouse",
                status="SUCCESS_SIMULATED",
                executed_at=now_str,
                details={
                    "db_host": "internal-prod-db-cluster.corp.quora.internal",
                    "sql_executed": "ALTER USER master_data_sync NOLOGIN; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'master_data_sync';",
                    "effect": "Terminated all active backend connections and blocked login",
                },
            )
            actions.append(db_action)

        elif token_type == "webhook_token":
            wh_action = ContainmentAction(
                action_type="API_GATEWAY_WEBHOOK_REVOCATION",
                target=f"whsec_{token_id}",
                status="SUCCESS_SIMULATED",
                executed_at=now_str,
                details={
                    "action": f"Invalidated token whsec_{token_id} on Kong/Envoy API Gateway",
                    "effect": "401 Unauthorized enforced globally",
                },
            )
            actions.append(wh_action)

        # 3. Automated Incident Ticket Creation
        ticket_id = f"SEC-INC-2026-{uuid.uuid4().hex[:6].upper()}"
        ticket_action = ContainmentAction(
            action_type="SOAR_INCIDENT_TICKET_CREATED",
            target=ticket_id,
            status="SUCCESS_SIMULATED",
            executed_at=now_str,
            details={
                "ticket_id": ticket_id,
                "priority": "P1_CRITICAL",
                "assigned_team": "Tier-3 SecOps Incident Response",
                "playbook": "SOAR-PB-DECEPTION-BREACH-RESPONSE",
            },
        )
        actions.append(ticket_action)

        # Record in history
        self.containment_history.extend(actions)
        return actions

    def record_audit_log(self, alert: CanaryAlert):
        """Appends alert to local persistent JSONL audit file."""
        try:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert.model_dump(), default=str) + "\n")
        except Exception as e:
            logger.error("Failed to write to alert audit log: %s", e)

    def print_soc_banner(self, alert: CanaryAlert):
        """Prints a high-visibility, structured alert to SOC console."""
        print("\n" + "=" * 80)
        print(" [!!! CRITICAL SECURITY ALERT: CANARY TRIPWIRE COMPROMISE DETECTED !!!]")
        print("=" * 80)
        print(f" Alert ID:         {alert.alert_id}")
        print(f" Event:            {alert.event}")
        print(f" Fidelity:         {alert.fidelity} (Zero False-Positive Decoy Asset)")
        print(f" Token Type:       {alert.token_type.upper()}")
        print(f" Token ID:         {alert.token_id}")
        print(f" MITRE ATT&CK:     {alert.ttp}")
        print(f" Adversary IP:     {alert.source_ip}")
        print(f" User-Agent:       {alert.user_agent}")
        print(f" Network Context:  {alert.network_context}")
        print(f" Geolocation:      {alert.enrichment.city}, {alert.enrichment.country_name} [{alert.enrichment.country_code}]")
        print(f" ASN / Org:        AS{alert.enrichment.asn} - {alert.enrichment.asn_org}")
        print("-" * 80)
        print(" AUTOMATED CONTAINMENT ACTIONS EXECUTED:")
        for action in alert.containment_actions:
            print(f"  [+] {action.action_type:<38} -> Target: {action.target} ({action.status})")
        print("=" * 80 + "\n")

    async def dispatch_external(self, alert: CanaryAlert):
        """Asynchronously forwards alerts to external webhooks if configured."""
        payload = alert.model_dump()

        # Slack Notification
        if self.slack_webhook_url:
            try:
                slack_msg = {
                    "text": f":rotating_light: *CRITICAL CANARY ALERT*: {alert.token_type.upper()} tripped by `{alert.source_ip}`",
                    "attachments": [
                        {
                            "color": "#FF0000",
                            "fields": [
                                {"title": "MITRE TTP", "value": alert.ttp, "short": False},
                                {"title": "Adversary IP", "value": alert.source_ip, "short": True},
                                {"title": "Context", "value": alert.network_context, "short": True},
                                {"title": "Action", "value": alert.action_required, "short": True},
                            ],
                        }
                    ],
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(self.slack_webhook_url, json=slack_msg)
            except Exception as e:
                logger.error("Slack alert dispatch failed: %s", e)

        # Discord Notification
        if self.discord_webhook_url:
            try:
                discord_msg = {
                    "content": f"🚨 **CRITICAL CANARY ALERT**: Decoy `{alert.token_type}` triggered by `{alert.source_ip}`!\n"
                               f"**Network Context:** {alert.network_context}\n"
                               f"**MITRE TTP:** {alert.ttp}"
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(self.discord_webhook_url, json=discord_msg)
            except Exception as e:
                logger.error("Discord alert dispatch failed: %s", e)

        # Generic SIEM HTTP endpoint
        if self.siem_endpoint_url:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(self.siem_endpoint_url, json=payload)
            except Exception as e:
                logger.error("SIEM alert dispatch failed: %s", e)
