# CTEM Risk Intelligence Engine

High-throughput, event-driven vulnerability prioritization engine built for Continuous Threat Exposure Management (CTEM).

The CTEM Risk Intelligence Engine acts as the central intelligence processor in a distributed cybersecurity architecture. It ingests verified IT/OT assets, cross-references vulnerabilities against live threat intelligence (EPSS, CISA KEV), and computes a multi-factor risk score to determine automated SLA triage tiers. It is a defensive (blue-team) tool designed to reduce alert fatigue by prioritizing vulnerabilities based on genuine business impact.

## Architecture Overview

```
Team 2 (Scanners) ──► [API / NATS Ingestion] ──► [Risk Engine] ──► [SQLite Vault] ──► Team 4 & 5 (SOC)
                                                        │
                                                        ▼
                                              [Redis Cache] ◄── [Threat Intel (EPSS/KEV/CIRCL)]
```

## Quick Start (Local Setup)

The core engine and API can be run locally using Python and standard dependencies.

```bash
# 1. Navigate to the project directory
cd ~/threatgraph-team3

# 2. Create and activate a fresh Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install all required dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install sqlalchemy
```

## Production Stack (Docker Infrastructure)

The engine utilizes Redis for caching threat intelligence (to prevent API rate-limiting) and NATS JetStream for high-throughput message routing.

Run these required background services via Docker:

```bash
# Start the Redis Cache
sudo docker run -d --name redis-cache -p 6379:6379 redis

# Start NATS JetStream (Message Broker)
sudo docker run -d --name nats-server -p 4222:4222 -p 8222:8222 nats -js
```

> **Note:** If the containers already exist but are stopped, initialize them using `sudo docker start redis-cache` and `sudo docker start nats-server`.

## Running the Engine

With the infrastructure running, start the FastAPI orchestrator and the background threat intelligence fetcher:

```bash
uvicorn app.main:app --reload
```

Upon execution, the server will:

1. Initialize the SQLite database vault (`cve_data.db`).
2. Begin polling the CIRCL API for the latest CVEs in the background.
3. Establish connections to the Redis cache and NATS message broker.
4. Expose the interactive REST API documentation at: `http://127.0.0.1:8000/docs`

## Repository Layout — Mapped to the Pipeline

| Component | Location | Description |
|---|---|---|
| API Orchestrator | `app/main.py` | FastAPI entry point, background tasks, and REST routing. |
| Risk Engine | `app/risk_engine.py` | The core mathematical engine computing multi-factor risk scenarios. |
| Data Models | `app/models.py` | Pydantic schemas enforcing strict JSON payload validation. |
| Data Collection | `app/cve_fetcher.py` | Asynchronous ingestion pipeline from the external CIRCL API. |
| Storage Vault | `app/database.py` | SQLite/SQLAlchemy schema for persisting calculated risk scores. |
| Messaging | `app/messaging.py` | NATS JetStream pub/sub pipeline configurations for distributed routing. |
| Execution Proofs | `app/test_formula.py`, `app/final_integration_proof.py` | Standalone scripts validating end-to-end functionality. |

## The Risk Scoring Model

This engine shifts away from static CVSS base scores by incorporating real-world exploitability (EPSS), active exploitation catalogs (CISA KEV), and business context.

The core mathematical pipeline is:

```
Composite Score = (CVSS * 10) * (EPSS * 100) * KEV_Multiplier * Asset_Weight * Exposure
```

Findings are automatically categorized into SLA Tiers based on active exploitation flags and environmental context:

- **P1 - Critical:** Active KEV exploitation or High EPSS + Critical Asset Context.
- **P2 - High:** High EPSS + High CVSS, or Critical Asset Context.
- **P3 - Medium:** Moderate EPSS/CVSS or elevated Asset Weight.
- **P4 - Low:** Baseline vulnerabilities with low exploit likelihood.

## Executing the Validation Proofs

To verify the core processing logic without requiring full pipeline integration or browser interaction, execute the following standalone validation scripts.

Open a second terminal window, ensure your virtual environment is active, and run:

1. **Prove the Risk Formula & Priority Assignment:**

   ```bash
   python3 app/test_formula.py
   ```

   Validates the ingestion of a base CVSS score, threat intelligence processing via Redis, and the final 0-100 score with its corresponding SLA Tier.

2. **Prove End-to-End Ingestion, Storage, and Exposure:**

   ```bash
   python3 app/final_integration_proof.py
   ```

   Constructs a mock scanner payload, processes it through the engine, securely commits the result to the local SQLite vault, and executes a retrieval query to prove data persistence.

## What is Real vs. What is a Seam

This is a working reference implementation designed for a microservice architecture, honest about its boundaries:

- **Fully Implemented and Tested:** The REST API orchestrator, the risk scoring mathematical engine, Pydantic data validation, SQLite persistence layer, and background asynchronous data fetching. The validation scripts (`test_formula.py` and `final_integration_proof.py`) exercise this core logic end-to-end.
- **Integration Seams:** The EPSS and CISA KEV lookups currently utilize Redis caching with conditional mock data for specific CVEs (e.g., Log4Shell) to ensure predictable testing environments. The NATS JetStream publisher is fully configured but acts as a seam for Team 4/5 consumption.
- **Data Sources:** External CVE data is actively pulled from the real CIRCL API. Internal scanner data is simulated via structured JSON payloads POSTed to the API endpoints.
