import httpx
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.database import SessionLocal, CVETable

async def fetch_and_store_cves(limit: int = 5) -> bool:
    """
    Executes the two primary deliverables of the CVE Ingestion Service:
    1. Pulls external threat intelligence (JSON).
    2. Parses and commits critical metrics to the local database.
    """
    # Target external Threat Intel source (CIRCL API)
    url = "https://cve.circl.lu/api/last"
    
    #  Pull CVE Data
    try:
        # Using httpx for non-blocking asynchronous network requests
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=15.0)
            response.raise_for_status() # Validate HTTP 200 OK
            raw_cve_data = response.json()
            
    except httpx.RequestError as exc:
        print(f"[ERROR] Network failure during CVE fetch: {exc}")
        return False
    except Exception as exc:
        print(f"[ERROR] Unexpected error parsing CVE payload: {exc}")
        return False
    # Store Data in Database

    db: Session = SessionLocal()
    try:
        records_added = 0
        
        # Isolate only the number of records defined by the limit
        for item in raw_cve_data[:limit]:
            cve_id = item.get("id")
            cvss_score = item.get("cvss", 0.0) # Default to 0.0 if unrated
            
            # Check if this CVE already exists in our vault to avoid duplicates
            existing_record = db.query(CVETable).filter(CVETable.cve_id == cve_id).first()
            
            if not existing_record:
                # Map the raw JSON to your strict Database Schema
                new_cve = CVETable(
                    cve_id=cve_id,
                    cvss_score=float(cvss_score) if cvss_score else 0.0
                )
                db.add(new_cve)
                records_added += 1

        # Commit the transaction to physical disk
        db.commit()
        
        if records_added > 0:
            print(f"[*] CVE Ingestion cycle complete. {records_added} new records committed to database.")
        else:
            print("[*] CVE Ingestion cycle complete. Vault is already up to date.")
            
        return True

    except IntegrityError:
        # Rollback the transaction if the database locks or hits a constraint violation
        db.rollback()
        print("[-] Database integrity error. Transaction rolled back.")
        return False
    finally:
        # Always close the connection to prevent memory leaks
        db.close()