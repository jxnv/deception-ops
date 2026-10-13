# Engineering Wiki: Core Infrastructure & Deployment Secrets
> **Classification:** CONFIDENTIAL // INTERNAL USE ONLY  
> **Last Updated:** 2026-03-15 by SRE Team

---

### 1. Central Telemetry & Alert Ingestion Webhook
Use this internal webhook token for routing operational metrics and automated CI/CD notifications:

```bash
# Production Alertmanager Ingestion Endpoint
curl -X POST "{{WEBHOOK_URL}}/webhook/canary-callback" \
  -H "Content-Type: application/json" \
  -H "X-Canary-Secret: whsec_{{TOKEN_ID}}_ci_prod_sync" \
  -d '{"token_id": "{{TOKEN_ID}}", "token_type": "webhook_token", "action": "ci_pipeline_sync"}'
```

### 2. Emergency Break-Glass Token
- **Token ID:** `sec_token_{{TOKEN_ID}}`
- **Scope:** `corp:internal:infrastructure:admin`
- **Status:** Active
- **Beacon Check:** `{{WEBHOOK_URL}}/track?id={{TOKEN_ID}}&token_type=webhook_token`
