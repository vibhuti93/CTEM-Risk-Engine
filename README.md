# CTEM Continuous Threat Exposure Management - Risk Intelligence Engine

Central intelligence processor built for high-throughput vulnerability prioritization.

## Tech Stack
- **FastAPI**: Async orchestration and REST triage endpoints.
- **NATS JetStream**: Zero-latency distributed message broker event architecture.
- **Redis**: Fast lookup cache layer for external threat feeds (EPSS/CISA KEV).
- **Pydantic**: JSON data validation contracts.

## Architecture Pipeline
1. Ingests verified assets from upstream discovery modules.
2. Cross-references vulnerabilities with live threat feeds.
3. Computes a multi-factor risk score to determine SLA triage tiers.
