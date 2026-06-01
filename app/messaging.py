import nats
from nats.errors import ConnectionClosedError, TimeoutError, NoServersError
import json
import asyncio

class NatsBroker:
    def __init__(self):
        self.nc = None
        self.js = None

    async def connect(self):
        """Initializes connection to the NATS server and ensures streams exist."""
        try:
            # Connecting to the local NATS Docker container
            self.nc = await nats.connect("nats://localhost:4222")
            self.js = self.nc.jetstream()
            
            # Ensure the streams for our queues exist.
            # Team 2 pushes to monitoring, we push to risk.
            await self.js.add_stream(name="monitoring_stream", subjects=["events.monitoring.*"])
            await self.js.add_stream(name="risk_stream", subjects=["events.risk.*"])
            print("Successfully connected to NATS JetStream.")
        except Exception as e:
            print(f"Failed to connect to NATS: {e}")

    async def subscribe_to_assets(self, callback):
        """Listens for incoming verified assets from Team 2."""
        if self.js:
            try:
                await self.js.subscribe("events.monitoring.verified_assets", cb=callback)
                print("Subscribed to events.monitoring.verified_assets")
            except Exception as e:
                print(f"Subscription error: {e}")

    async def publish_finding(self, finding):
        """Publishes the finalized EnrichedFinding JSON to Teams 4 & 5."""
        if self.js:
            try:
                # Convert the Pydantic model to a JSON string, then encode to bytes
                payload = finding.model_dump_json().encode()
                await self.js.publish("events.risk.scored_findings", payload)
                print(f"Published scored finding for {finding.cve_id} to events.risk.scored_findings")
            except Exception as e:
                print(f"Publish error for {finding.cve_id}: {e}")
