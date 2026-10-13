"""
High-Signal Deception Webhook Triage Receiver.
Receives canary trigger callbacks, enriches source metadata,
emits high-fidelity SOC alerts, and executes automated simulated containment.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, Response

from webhook_receiver.alert_dispatcher import AlertDispatcher
from webhook_receiver.enricher import ThreatIntelligenceEnricher, map_mitre_ttp
from webhook_receiver.models import (
    AlertsListResponse,
    CanaryAlert,
    CanaryTrigger,
    ContainmentAction,
    EnrichmentData,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("triage_receiver")

# Global in-memory storage buffer
ALERTS_STORE: List[CanaryAlert] = []

# Global service singletons
enricher: Optional[ThreatIntelligenceEnricher] = None
dispatcher: Optional[AlertDispatcher] = None

# 1x1 Transparent GIF beacon payload for stealth tracking
TRANSPARENT_GIF_BYTES = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
    b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes threat intelligence enricher and alert dispatcher on startup."""
    global enricher, dispatcher
    logger.info("Initializing DeceptionOps Canary Triage Service...")
    enricher = ThreatIntelligenceEnricher()
    dispatcher = AlertDispatcher()
    yield
    logger.info("Shutting down DeceptionOps Canary Triage Service...")
    if enricher:
        enricher.close()


app = FastAPI(
    title="DeceptionOps Canary Triage Service",
    description="Centralized high-fidelity deception listener and automated incident containment engine",
    version="1.0.0",
    lifespan=lifespan,
)


def _extract_client_ip(request: Request, body_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Safely resolves the true client IP from proxy headers or connection socket.
    Supports simulated source IP injection from adversary testing payloads.
    """
    # 1. Explicit simulated IP in request payload for attack simulation
    if body_data and "source_ip" in body_data and body_data["source_ip"]:
        return str(body_data["source_ip"]).strip()

    # 2. X-Forwarded-For header (first hop)
    xff = request.headers.get("x-forwarded-for")
    if xff:
        client_ip = xff.split(",")[0].strip()
        if client_ip:
            return client_ip

    # 3. X-Real-IP header
    x_real = request.headers.get("x-real-ip")
    if x_real:
        return x_real.strip()

    # 4. Underlying client TCP socket
    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


async def process_and_dispatch_alert(trigger: CanaryTrigger):
    """
    Enriches trigger metadata, executes containment actions,
    and dispatches high-priority alerts to SOC channels.
    """
    global enricher, dispatcher

    # Ensure singletons exist
    if not enricher:
        enricher = ThreatIntelligenceEnricher()
    if not dispatcher:
        dispatcher = AlertDispatcher()

    # Step 2 & 3: Threat intelligence and network context enrichment
    enriched_data: EnrichmentData = enricher.enrich(trigger.source_ip)

    # Step 4: Map MITRE ATT&CK technique and confidence
    ttp_code = map_mitre_ttp(trigger.token_type)

    alert_id = str(uuid.uuid4())
    alert = CanaryAlert(
        alert_id=alert_id,
        event="CRITICAL_CANARY_TRIPWIRE_TRIGGERED",
        severity="CRITICAL",
        fidelity="100%",  # Decoy asset has NO valid business use
        ttp=ttp_code,
        timestamp=trigger.timestamp,
        token_id=trigger.token_id,
        token_type=trigger.token_type,
        source_ip=trigger.source_ip,
        user_agent=trigger.user_agent,
        network_context=enriched_data.network_context.value,
        enrichment=enriched_data,
        action_required="IMMEDIATE_HOST_CONTAINMENT",
        containment_actions=[],
        raw_metadata={
            "query_params": trigger.query_params,
            "headers": {k: v for k, v in trigger.headers.items() if k.lower() not in ["authorization"]},
            "payload": trigger.payload,
        },
    )

    # Execute simulated automated containment workflows
    containment_actions: List[ContainmentAction] = dispatcher.execute_automated_containment(
        token_type=trigger.token_type,
        token_id=trigger.token_id,
        source_ip=trigger.source_ip,
        network_context=enriched_data.network_context.value,
    )
    alert.containment_actions = containment_actions

    # Store alert in-memory
    ALERTS_STORE.append(alert)

    # Record persistent audit trail and log to console
    dispatcher.record_audit_log(alert)
    dispatcher.print_soc_banner(alert)

    # Asynchronously forward to external SIEM / Discord / Slack
    await dispatcher.dispatch_external(alert)


@app.post("/webhook/canary-callback")
async def canary_webhook(
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Central JSON callback endpoint for canary token trips.
    Triggered by Honey-Keys, Cloned Webhook tokens, and programmatic traps.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    client_ip = _extract_client_ip(request, body)
    user_agent = request.headers.get("user-agent", "unknown")

    trigger = CanaryTrigger(
        token_id=str(body.get("token_id", "unknown_id")),
        token_type=str(body.get("token_type", "aws_honey_key")),
        source_ip=client_ip,
        user_agent=user_agent,
        headers=dict(request.headers),
        payload=body,
    )

    background_tasks.add_task(process_and_dispatch_alert, trigger)
    return {"status": "received", "action": "triaging", "token_id": trigger.token_id}


@app.get("/track")
async def canary_track_beacon(
    request: Request,
    background_tasks: BackgroundTasks,
    id: Optional[str] = Query(None, description="Canary Token ID"),
    token_type: Optional[str] = Query("generic", description="Canary Token Type"),
    doc: Optional[str] = Query(None, description="Document title"),
    component: Optional[str] = Query(None, description="Triggering component"),
):
    """
    HTTP GET beacon callback endpoint.
    Triggered by Canary PDF opens, Kubeconfig probes, Database telemetry beacons,
    or stealth 1x1 image requests.
    """
    client_ip = _extract_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    query_params = dict(request.query_params)

    trigger = CanaryTrigger(
        token_id=id or query_params.get("id", "beacon_unknown"),
        token_type=token_type or query_params.get("token_type", "canary_pdf"),
        source_ip=client_ip,
        user_agent=user_agent,
        query_params=query_params,
        headers=dict(request.headers),
    )

    background_tasks.add_task(process_and_dispatch_alert, trigger)

    # Return invisible 1x1 transparent GIF to ensure stealth tracking
    return Response(content=TRANSPARENT_GIF_BYTES, media_type="image/gif")


@app.post("/webhook/generic")
async def generic_webhook(
    request: Request,
    background_tasks: BackgroundTasks
):
    """Generic endpoint accepting external honeypot formats or Thinkst webhooks."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    client_ip = _extract_client_ip(request, body)
    user_agent = request.headers.get("user-agent", "unknown")

    token_id = str(body.get("canarytoken", body.get("token", body.get("token_id", "gen_" + uuid.uuid4().hex[:6]))))
    token_type = str(body.get("channel", body.get("type", body.get("token_type", "generic"))))

    trigger = CanaryTrigger(
        token_id=token_id,
        token_type=token_type,
        source_ip=client_ip,
        user_agent=user_agent,
        headers=dict(request.headers),
        payload=body,
    )

    background_tasks.add_task(process_and_dispatch_alert, trigger)
    return {"status": "received", "action": "triaging", "token_id": trigger.token_id}


@app.get("/api/v1/alerts", response_model=AlertsListResponse)
def get_alerts(
    token_type: Optional[str] = None,
    severity: Optional[str] = None,
    network_context: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """
    Retrieves recorded high-fidelity alerts with optional filtering.
    """
    filtered = ALERTS_STORE

    if token_type:
        filtered = [a for a in filtered if a.token_type.lower() == token_type.lower()]
    if severity:
        filtered = [a for a in filtered if a.severity.lower() == severity.lower()]
    if network_context:
        filtered = [a for a in filtered if a.network_context.lower() == network_context.lower()]

    paginated = filtered[offset : offset + limit]

    filter_info = {}
    if token_type:
        filter_info["token_type"] = token_type
    if severity:
        filter_info["severity"] = severity
    if network_context:
        filter_info["network_context"] = network_context

    return AlertsListResponse(
        alerts=paginated,
        total=len(filtered),
        filter_applied=filter_info if filter_info else None,
    )


@app.get("/api/v1/alerts/{alert_id}")
def get_alert_by_id(alert_id: str):
    """Fetches full alert details for a specific alert UUID."""
    for alert in ALERTS_STORE:
        if alert.alert_id == alert_id:
            return alert
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")


@app.get("/api/v1/containment/status")
def get_containment_status():
    """Returns recent containment actions executed by the automated response engine."""
    global dispatcher
    actions = dispatcher.containment_history if dispatcher else []
    return {
        "total_actions": len(actions),
        "recent_actions": actions[-50:],
    }


@app.delete("/api/v1/alerts")
def clear_alerts():
    """Administrative reset endpoint to clear stored alerts and containment history."""
    global ALERTS_STORE, dispatcher
    ALERTS_STORE.clear()
    if dispatcher:
        dispatcher.containment_history.clear()
    return {"status": "cleared", "total_alerts": 0}


@app.get("/healthz")
@app.get("/")
def health_check():
    """Health check endpoint confirming active microservice status."""
    return {
        "status": "healthy",
        "service": "DeceptionOps Canary Triage Receiver",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alerts_recorded": len(ALERTS_STORE),
    }
