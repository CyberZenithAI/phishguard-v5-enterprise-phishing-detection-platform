import email
from email import policy
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse
import dns.resolver
from app.analysis.domain_analyzer import extract_domain, heuristic_score, check_dns_mx

def _extract_urls(text: str) -> List[str]:
    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    return url_pattern.findall(text)

def _check_dns_record(domain: str, record_type: str) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return str(answers[0]) if answers else "present"
    except Exception:
        return None

def parse_raw_email(raw_email: str):
    msg = email.message_from_string(raw_email, policy=policy.default)
    return msg

async def analyze_email(raw_email: str) -> dict:
    msg = parse_raw_email(raw_email)
    
    # Extraer cabeceras de autenticación
    spf = msg.get('Received-SPF', msg.get('Authentication-Results', None))
    dkim = msg.get('DKIM-Signature', None)
    dmarc = msg.get('DMARC-Filter', None)
    
    from_header = msg.get('From', '')
    from_domain = extract_domain(from_header) if '@' in from_header else None
    
    # Extraer todo el texto del cuerpo
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                try:
                    body += part.get_content()
                except:
                    pass
    else:
        try:
            body = msg.get_content()
        except:
            body = ""
    
    # URLs encontradas
    all_text = str(msg) + body
    urls = _extract_urls(all_text)
    
    # Análisis rápido de cada URL (dominio)
    domain_analysis = []
    total_score = 0
    for url in urls[:5]:  # limitamos a 5 para no saturar
        domain = extract_domain(url)
        score = heuristic_score(domain)
        total_score += score
        domain_analysis.append({
            "url": url,
            "domain": domain,
            "score": score,
            "has_mx": check_dns_mx(domain)
        })
    
    # Score combinado
    if urls:
        avg_url_score = total_score / len(urls)
    else:
        avg_url_score = 0
    
    # Penalizaciones por falta de autenticación
    auth_penalty = 0
    if not spf or "fail" in str(spf).lower():
        auth_penalty += 20
    if not dkim:
        auth_penalty += 20
    if not dmarc:
        auth_penalty += 10
    
    final_score = min(100, avg_url_score + auth_penalty)
    risk = "low" if final_score < 30 else "medium" if final_score < 60 else "high"
    
    return {
        "risk_score": final_score,
        "risk_level": risk,
        "headers": {
            "spf": spf or "no encontrado",
            "dkim": "presente" if dkim else "no encontrado",
            "dmarc": dmarc or "no encontrado",
            "from_domain": from_domain
        },
        "urls_found": urls,
        "domain_analysis": domain_analysis,
        "summary": f"Se encontraron {len(urls)} URLs. Fallos de autenticación: SPF={'OK' if spf and 'pass' in str(spf).lower() else 'FALLO'}, DKIM={'OK' if dkim else 'FALLO'}, DMARC={'OK' if dmarc else 'FALLO'}. Score combinado: {final_score}"
    }
