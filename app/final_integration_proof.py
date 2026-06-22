import asyncio
import sqlite3
from app.risk_engine import RiskCalculator

class MockVulnerability:
    def __init__(self, cve_id, cvss_base):
        self.cve_id = cve_id
        self.cvss_base = cvss_base

def setup_database():
    conn = sqlite3.connect("risk_database.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT,
            vulnerability TEXT,
            composite_score REAL,
            sla_tier TEXT
        )
    ''')
    conn.commit()
    return conn

async def prove_deliverables():
    print("\n>>> [DELIVERABLE 2] CALCULATING RISK FROM INCOMING ASSET <<<")
    incoming_asset = "DB-PROD-01"
    incoming_cve = "CVE-2026-5555"
    
    print(f"[*] Simulating incoming payload -> Asset: {incoming_asset} | Vuln: {incoming_cve}")
    
    # Matching the exact inputs from your new D1 test
    raw_vuln = MockVulnerability(cve_id=incoming_cve, cvss_base=7.5)
    asset_context = {"weight": 3.0, "exposure": 1.5}
    
    calculator = RiskCalculator()
    composite_score, sla_tier, metrics = await calculator.calculate_score(raw_vuln, asset_context)
    print(f"[*] Calculation Complete! Score: {composite_score} | SLA: {sla_tier}")

    print("\n>>> [DELIVERABLE 3] STORING AND EXPOSING IN DATABASE <<<")
    conn = setup_database()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO risk_scores (asset_id, vulnerability, composite_score, sla_tier)
        VALUES (?, ?, ?, ?)
    ''', (incoming_asset, incoming_cve, composite_score, sla_tier))
    conn.commit()
    print("[*] SUCCESS: Risk score securely stored in local SQLite vault (risk_database.db).")

    print("[*] Querying database to expose stored risk scores...")
    cursor.execute("SELECT * FROM risk_scores ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    
    print("\n=======================================")
    print("    DELIVERABLE 2 & 3: FINAL PROOF     ")
    print("=======================================")
    print(f"DATABASE RECORD RETRIEVED:")
    print(f" - Record ID    : {row}")
    print(f" - Asset ID     : {row}")
    print(f" - Vulnerability: {row}")
    print(f" - Risk Score   : {row}")
    print(f" - SLA Tier     : {row}")
    print("=======================================")
    
    conn.close()

if __name__ == "__main__":
    asyncio.run(prove_deliverables())
