import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import SessionLocal, engine, Base, CVETable
from app.models import AssetTrigger
from app.cve_fetcher import fetch_and_store_cves

async def automated_threat_ingestion():
    """Runs continuously in the background to keep the vault hydrated."""
    while True:
        print("\n[INFO] AUTO-FETCHER: Waking up to sync with CIRCL API...")
        # INCREASED: Pulls 50 records automatically instead of 5
        await fetch_and_store_cves(limit=50)
        print("[INFO] AUTO-FETCHER: Sync complete. Going back to sleep.")
        await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[+] Initializing threat intelligence vault...")
    Base.metadata.create_all(bind=engine)
    
    fetcher_task = asyncio.create_task(automated_threat_ingestion())
    
    print("[+] Connecting to NATS JetStream...")
    yield
    print("[-] Cancelling background tasks and closing connections...")
    fetcher_task.cancel()

app = FastAPI(
    title="CyArt Team 3 Risk Engine",
    description="Lead Orchestrator API for Vulnerability Ingestion & Routing",
    version="1.0.0",
    lifespan=lifespan
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/scan/trigger", tags=["Orchestration"])
async def trigger_scan(payload: AssetTrigger):
    print(f"\n[*] Starting Pipeline for Asset: {payload.asset_id} ({payload.value})")
    return {
        "status": "accepted",
        "message": f"Asset {payload.asset_id} queued for risk processing."
    }

@app.post("/intel/ingest-cves", tags=["Threat Intelligence"])
async def trigger_cve_ingestion():
    print("[*] Initiating external API call to pull 100 recent vulnerabilities...")
    # INCREASED: Manual trigger now pulls 100 records
    success = await fetch_and_store_cves(limit=100)
    if success:
        return {
            "status": "success",
            "message": "Successfully pulled and stored latest CVEs in the database."
        }
    else:
        raise HTTPException(
            status_code=500,
            detail="CVE ingestion failed. Check server logs."
        )

@app.get("/intel/cves", tags=["Threat Intelligence"])
# INCREASED: API returns up to 50 records by default
def get_cached_cves(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(CVETable).limit(limit).all()
