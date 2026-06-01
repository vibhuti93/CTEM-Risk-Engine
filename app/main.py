from fastapi import FastAPI, BackgroundTasks
from app.models import AssetPayload, RawFinding, EnrichedFinding
from app.risk_engine import RiskCalculator
from app.messaging import NatsBroker
import asyncio

app = FastAPI(title="Team 3: Risk Scoring Engine", version="1.0.0")

# Initialize our custom modules
broker = NatsBroker()
risk_engine = RiskCalculator()

@app.on_event("startup")
async def startup_event():
    """Fires when the FastAPI server starts up."""
    await broker.connect()
    
    # In Phase 2, we will uncomment the line below to listen to live traffic from Team 2.
    # For now, we are triggering scans manually via the REST API to validate the math.
    # await broker.subscribe_to_assets(handle_incoming_asset)

def simulate_scans(asset: AssetPayload) -> list[RawFinding]:
    """Mocks OWASP ZAP and Trivy output for standalone validation."""
    print(f"Executing mock scans against {asset.value}...")
    return [
        RawFinding(
            cve_id="CVE-2023-44487", 
            cvss_base=7.5, 
            vulnerability_name="HTTP/2 Rapid Reset", 
            tool="ZAP"
        ),
        RawFinding(
            cve_id="CVE-2021-44228", 
            cvss_base=10.0, 
            vulnerability_name="Log4Shell", 
            tool="Trivy"
        )
    ]

async def process_asset_pipeline(asset: AssetPayload):
    """The core intelligence loop: Ingest -> Scan -> Score -> Publish."""
    print(f"\n--- Starting Pipeline for Asset: {asset.asset_id} ({asset.value}) ---")
    
    # 1. Execute the mock scanners
    raw_findings = simulate_scans(asset)
    
    # 2. Process and score each finding asynchronously
    for raw in raw_findings:
        print(f"Evaluating {raw.cve_id}...")
        
        score, sla, metrics = await risk_engine.calculate_score(
            raw, 
            asset_context={"weight": 1.5, "exposure": 1.5}
        )
        
        enriched = EnrichedFinding(
            asset_id=asset.asset_id,
            vulnerability=raw.vulnerability_name,
            cve_id=raw.cve_id,
            tool_used=raw.tool,
            composite_risk_score=score,
            sla_tier=sla,
            metrics=metrics
        )
        
        # 3. Publish the finalized intelligence to NATS for Teams 4 & 5
        await broker.publish_finding(enriched)
    
    print(f"--- Pipeline Complete for {asset.asset_id} ---\n")

@app.post("/scan/trigger")
async def trigger_scan(asset: AssetPayload, background_tasks: BackgroundTasks):
    """
    Manual REST endpoint. Acts as a handshake to validate the pipeline 
    without needing a live upstream NATS feed from Team 2.
    """
    # We pass the heavy processing to a background task so the API responds instantly
    background_tasks.add_task(process_asset_pipeline, asset)
    return {
        "status": "accepted", 
        "message": f"Asset {asset.asset_id} queued for risk processing."
    }
