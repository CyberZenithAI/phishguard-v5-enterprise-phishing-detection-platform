# app/core/intel.py

from __future__ import annotations

import logging
import os

from app.core.vt_client import VirusTotalClient
from app.core.otx_client import OTXClient
from app.core.abuseipdb import AbuseIPDBClient
from app.core.urlhaus import URLHausClient

LOGGER = logging.getLogger(__name__)


class ThreatIntelEngine:

    def __init__(
        self,
        vt_api_key: str | None = None,
    ) -> None:

        self.vt = VirusTotalClient(vt_api_key)

        self.enabled_sources = {
            "virustotal": self.vt.enabled
        }

        LOGGER.info(
            f"ThreatIntelEngine initialized | sources={self.enabled_sources}"
        )

    async def enrich_domain(self, domain: str) -> dict:

        result = {
            "domain": domain,
            "intel": {}
        }

        try:

            if self.vt.enabled:

                vt_result = await self.vt.lookup_domain(domain)

                result["intel"]["virustotal"] = {
                    "malicious": vt_result.malicious,
                    "suspicious": vt_result.suspicious,
                    "harmless": vt_result.harmless,
                    "reputation": vt_result.reputation,
                    "tags": vt_result.tags,
                }

            else:

                result["intel"]["virustotal"] = {
                    "status": "disabled"
                }

        except Exception as e:

            LOGGER.error(f"VirusTotal enrich failed: {e}")

            result["intel"]["virustotal"] = {
                "status": "error",
                "error": str(e),
            }

        return result

    async def close(self):

        try:
            await self.vt.close()

        except Exception as e:
            LOGGER.error(f"ThreatIntelEngine close failed: {e}")


vt_api_key = os.getenv("VT_API_KEY", "")

intel_engine = ThreatIntelEngine(
    vt_api_key=vt_api_key
)


async def enrich(domain: str):

    return await intel_engine.enrich_domain(domain)
