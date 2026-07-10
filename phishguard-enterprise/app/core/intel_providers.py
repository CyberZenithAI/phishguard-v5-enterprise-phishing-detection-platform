import httpx
from app.core.config import settings

async def check_virustotal(domain: str) -> dict | None:
    """Consulta gratuita limitada a la API de VirusTotal (si hay key)."""
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return {"malicious": malicious, "suspicious": suspicious}
        except Exception:
            pass
    return None
