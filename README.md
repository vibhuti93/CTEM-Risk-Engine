# CTEM Risk Intelligence Engine 

A high-throughput, event-driven vulnerability prioritization engine built for Continuous Threat Exposure Management (CTEM). 

## Architecture Overview
This microservice acts as the central intelligence processor in a distributed cybersecurity architecture. It ingests verified IT/OT assets, cross-references vulnerabilities against threat intelligence metrics, and computes a multi-factor risk score to determine SLA triage tiers.

### Tech Stack
* **FastAPI**: Asynchronous API and pipeline orchestration.
* **NATS JetStream**: Zero-latency distributed message broker for pub/sub event routing.
* **Redis**: High-speed lookup cache for external threat feeds (EPSS, CISA KEV).
* **Pydantic**: Strict JSON data validation and contract enforcement.

## The Risk Scoring Formula
The engine shifts away from static CVSS scores by incorporating real-world exploitability.
`Composite Score = (CVSS * 10) * (EPSS * 100) * KEV_Multiplier * Asset_Weight * Exposure`

*Findings are automatically categorized into SLA Tiers (P1-Critical to P4-Low) based on active exploitation flags and environmental context.*
