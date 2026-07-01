markdown_content = """# CTEM Risk Intelligence Engine

High-throughput, event-driven vulnerability prioritization engine built for Continuous Threat Exposure Management (CTEM). The CTEM Risk Intelligence Engine acts as the central intelligence processor in a distributed cybersecurity architecture. It ingests verified IT/OT assets, cross-references vulnerabilities against live threat intelligence (EPSS, CISA KEV), and computes a multi-factor risk score to determine automated SLA triage tiers. It is a defensive (blue-team) tool designed to reduce alert fatigue by prioritizing vulnerabilities based on genuine business impact.

## Architecture Overview

```text
Team 2 (Scanners) ──►  [API / NATS Ingestion] ──► [Risk Engine] ──► [SQLite Vault] ──► Team 4 & 5 (SOC)
                                                      │
                                                      ▼
                           [Redis Cache] ◄── [Threat Intel (EPSS/KEV/CIRCL)]
