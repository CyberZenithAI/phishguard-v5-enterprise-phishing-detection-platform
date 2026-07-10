import dns.resolver
import re
from urllib.parse import urlparse
from app.core.intel_providers import check_virustotal

def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]

def check_dns_mx(domain: str) -> bool:
    """Retorna True si el dominio tiene registros MX (posible dominio de correo)."""
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except Exception:
        return False

def heuristic_score(domain: str) -> int:
    score = 0
    # Dominio muy largo o con muchos guiones
    if len(domain) > 25:
        score += 10
    if domain.count('-') > 2:
        score += 15
    # Presencia de palabras clave engañosas
    suspicious_words = ['secure', 'login', 'verify', 'account', 'update', 'bank']
    for word in suspicious_words:
        if word in domain.lower():
            score += 10
    # TLDs baratos o inusuales
    cheap_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.gq']
    if any(domain.endswith(tld) for tld in cheap_tlds):
        score += 20
    return min(score, 100)

async def analyze_domain(url: str) -> dict:
    domain = extract_domain(url)
    dns_has_mx = check_dns_mx(domain)
    score = heuristic_score(domain)

    # Integración con VT si está configurada
    vt_result = await check_virustotal(domain)
    if vt_result:
        score += vt_result["malicious"] * 10
        score = min(score, 100)

    risk = "low" if score < 30 else "medium" if score < 60 else "high"

    return {
        "domain": domain,
        "score": score,
        "risk_level": risk,
        "has_mx": dns_has_mx,
        "virus_total": vt_result,
        "details": f"Heurística + VT (score={score})"
    }
