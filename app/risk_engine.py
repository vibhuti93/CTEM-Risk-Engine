import httpx
import redis.asyncio as redis
import json

class RiskCalculator:
    def __init__(self):
        # Connect to your local Redis Docker container
        self.cache = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        # Using a default normalization factor to scale the product to a 0-100 range
        self.normalization_factor = 100.0 

    async def fetch_epss(self, cve_id: str) -> float:
        """Mock fetch to FIRST.org EPSS API with Redis caching."""
        cached_epss = await self.cache.get(f"epss:{cve_id}")
        if cached_epss:
            return float(cached_epss)
        
        # Simulating external lookup: Log4Shell has a high likelihood, others lower
        mock_epss_score = 0.96 if "44228" in cve_id else 0.15 
        
        # Cache for 1 hour (3600 seconds)
        await self.cache.setex(f"epss:{cve_id}", 3600, mock_epss_score)
        return mock_epss_score

    async def check_kev(self, cve_id: str) -> bool:
        """Mock check against CISA KEV catalog with Redis caching."""
        cached_kev = await self.cache.get(f"kev:{cve_id}")
        if cached_kev is not None:
            # Redis stores strings, convert back to a boolean comparison
            return cached_kev.lower() == "true"

        # Simulating active exploitation flags
        is_kev_listed = "44228" in cve_id or "44487" in cve_id
        
        # Cache the result as a string representation
        await self.cache.setex(f"kev:{cve_id}", 3600, str(is_kev_listed))
        return is_kev_listed

    async def calculate_score(self, raw, asset_context: dict) -> tuple[float, str, dict]:
        """Calculates dynamic composite score based on the CTEM mandate formula."""
        epss = await self.fetch_epss(raw.cve_id)
        is_kev = await self.check_kev(raw.cve_id)
        
        # Formula Parameter Coefficients
        base_score = raw.cvss_base * 10
        exploit_likelihood = epss * 100
        kev_multiplier = 1.5 if is_kev else 1.0
        asset_weight = asset_context.get("weight", 1.5)
        exposure_multiplier = asset_context.get("exposure", 1.5)

        # Composite Score Formula implementation
        composite_score = (base_score * exploit_likelihood * kev_multiplier * asset_weight * exposure_multiplier) / self.normalization_factor
        
        # Clean mathematical ceiling capped at 100
        composite_score = round(min(composite_score, 100.0), 2)

        # Determine SLA Tier based on vulnerability context
        sla_tier = "P4 - Low"
        if is_kev or (epss > 0.5 and exposure_multiplier == 2.5 and asset_weight == 3.0):
            sla_tier = "P1 - Critical"
        elif (epss > 0.5 and raw.cvss_base > 7.0) or (asset_weight == 3.0):
            sla_tier = "P2 - High"
        elif (epss > 0.2 and raw.cvss_base > 4.0) or (asset_weight >= 2.0):
            sla_tier = "P3 - Medium"

        metrics = {
            "cvss": raw.cvss_base,
            "epss": epss,
            "kev_listed": 1.0 if is_kev else 0.0
        }
        
        return composite_score, sla_tier, metrics
