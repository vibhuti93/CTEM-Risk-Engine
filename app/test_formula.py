import asyncio
import json
from risk_engine import RiskCalculator

class MockVulnerability:
    def __init__(self, cve_id, cvss_base):
        self.cve_id = cve_id
        self.cvss_base = cvss_base

async def prove_formula_works():
    print(">>> Initializing Risk Calculator Engine <<<")
    calculator = RiskCalculator()

    # TEST SCENARIO: A generic threat to avoid the P1 active-exploit override
    test_cve = MockVulnerability(cve_id="CVE-2026-5555", cvss_base=7.5)
    
    # Asset weight of 3.0 ensures it stays important enough for P2 - High
    test_asset_context = {
        "weight": 3.0,
        "exposure": 1.5
    }

    print(f"[*] Simulating Threat: {test_cve.cve_id} (Base CVSS: {test_cve.cvss_base})")
    print(f"[*] Asset Context: Weight={test_asset_context['weight']}, Exposure={test_asset_context['exposure']}")
    print("[*] Crunching CTEM math...\n")

    composite_score, sla_tier, metrics = await calculator.calculate_score(test_cve, test_asset_context)

    print("=======================================")
    print("      DELIVERABLE 1: OUTPUT PROOF      ")
    print("=======================================")
    print(f"Calculated Composite Score : {composite_score} / 100")
    print(f"Assigned SLA Tier          : {sla_tier}")
    print("Underlying Metrics Used    :")
    print(json.dumps(metrics, indent=4))
    print("=======================================")

if __name__ == "__main__":
    asyncio.run(prove_formula_works())
