from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
from email.utils import parseaddr

import dns.asyncresolver
import dns.exception

LOGGER = logging.getLogger(__name__)


# =========================
# CONFIGURATION CONSTANTS
# =========================

MAX_DNS_LOOKUPS = 10
MAX_RECURSION_DEPTH = 5
DNS_TIMEOUT = 2.5


# =========================
# DATA MODEL
# =========================

@dataclass(slots=True)
class SPFEvaluation:
    result: str
    domain: str
    spf_record: str
    mechanisms: List[str]
    dns_lookups: int
    warnings: List[str]
    errors: List[str]
    explanation: str
    timestamp: float


# =========================
# DNS RESOLVER (SAFE)
# =========================

class DNSResolver:
    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver()
        self.cache: Dict[str, Tuple[float, List[str]]] = {}

    async def txt(self, domain: str) -> List[str]:
        now = time.time()

        if domain in self.cache:
            expiry, data = self.cache[domain]
            if expiry > now:
                return data

        try:
            self.resolver.lifetime = DNS_TIMEOUT
            answer = await self.resolver.resolve(domain, "TXT")

            records = []
            for r in answer:
                txt = "".join([b.decode() if isinstance(b, bytes) else str(b) for b in r.strings])
                records.append(txt)

            self.cache[domain] = (now + 300, records)
            return records

        except dns.exception.DNSException as e:
            LOGGER.warning(f"dns_txt_failed domain={domain} error={str(e)}")
            return []


# =========================
# SPF PARSER (RFC 7208 BASIC)
# =========================

class SPFParser:
    @staticmethod
    def extract_spf_record(txt_records: List[str]) -> Optional[str]:
        for rec in txt_records:
            if rec.lower().startswith("v=spf1"):
                return rec
        return None

    @staticmethod
    def tokenize(spf_record: str) -> List[str]:
        return spf_record.split()


# =========================
# ORGANIZATIONAL DOMAIN (SIMPLIFIED SAFE VERSION)
# =========================

class DomainUtils:
    @staticmethod
    def organizational_domain(domain: str) -> str:
        parts = domain.split(".")
        if len(parts) <= 2:
            return domain
        return ".".join(parts[-2:])


# =========================
# ALIGNMENT ENGINE (DMARC SAFE)
# =========================

class AlignmentEngine:
    @staticmethod
    def is_aligned(from_domain: str, mail_from: str, mode: str = "relaxed") -> bool:
        from_dom = DomainUtils.organizational_domain(from_domain)
        mail_dom = DomainUtils.organizational_domain(mail_from)

        if mode == "strict":
            return from_domain.lower() == mail_from.lower()

        # relaxed (DMARC default)
        return from_dom == mail_dom


# =========================
# SPF CORE ENGINE
# =========================

class SPFValidator:

    def __init__(self):
        self.dns = DNSResolver()
        self.lookup_counter = 0

    async def validate(
        self,
        ip: str,
        sender: str,
        helo: str,
        alignment_mode: str = "relaxed",
    ) -> Dict:

        warnings: List[str] = []
        errors: List[str] = []
        mechanisms: List[str] = []
        dns_lookups = 0

        timestamp = time.time()

        try:
            mail_from_name, mail_from_addr = parseaddr(sender)
            from_domain = mail_from_addr.split("@")[-1] if "@" in mail_from_addr else mail_from_addr
            helo_domain = helo.strip().lower()

            # -------------------------
            # DNS SPF FETCH
            # -------------------------
            txt_records = await self.dns.txt(from_domain)
            dns_lookups += 1

            spf_record = SPFParser.extract_spf_record(txt_records)

            if not spf_record:
                return self._build_result(
                    result="none",
                    domain=from_domain,
                    spf_record="",
                    mechanisms=[],
                    dns_lookups=dns_lookups,
                    warnings=["no_spf_record_found"],
                    errors=[],
                    explanation="No SPF record found",
                    timestamp=timestamp,
                    aligned=False,
                )

            tokens = SPFParser.tokenize(spf_record)
            mechanisms = tokens[1:]

            # -------------------------
            # SPF EVALUATION ENGINE
            # -------------------------
            result = await self._evaluate_spf(
                ip=ip,
                domain=from_domain,
                tokens=mechanisms,
                depth=0,
                dns_lookups=dns_lookups,
                warnings=warnings,
                errors=errors,
            )

            dns_lookups = self.lookup_counter

            # -------------------------
            # DMARC ALIGNMENT
            # -------------------------
            aligned = AlignmentEngine.is_aligned(
                from_domain,
                mail_from_addr.split("@")[-1] if "@" in mail_from_addr else mail_from_addr,
                mode=alignment_mode,
            )

            return self._build_result(
                result=result,
                domain=from_domain,
                spf_record=spf_record,
                mechanisms=mechanisms,
                dns_lookups=dns_lookups,
                warnings=warnings,
                errors=errors,
                explanation=f"SPF evaluation completed: {result}",
                timestamp=timestamp,
                aligned=aligned,
                helo_domain=helo_domain,
                mail_from=mail_from_addr,
                alignment_mode=alignment_mode,
            )

        except Exception as exc:
            LOGGER.exception("spf_validation_failed")
            return self._build_result(
                result="permerror",
                domain="",
                spf_record="",
                mechanisms=[],
                dns_lookups=dns_lookups,
                warnings=[],
                errors=[str(exc)],
                explanation="Fatal SPF validation error",
                timestamp=timestamp,
                aligned=False,
            )

    # =========================
    # SPF EVALUATION CORE
    # =========================

    async def _evaluate_spf(
        self,
        ip: str,
        domain: str,
        tokens: List[str],
        depth: int,
        dns_lookups: int,
        warnings: List[str],
        errors: List[str],
    ) -> str:

        if depth > MAX_RECURSION_DEPTH:
            warnings.append("spf_recursion_limit_exceeded")
            return "permerror"

        for token in tokens:

            if self.lookup_counter >= MAX_DNS_LOOKUPS:
                warnings.append("spf_dns_lookup_limit_exceeded")
                return "permerror"

            # ---------------- include ----------------
            if token.startswith("include:"):
                include_domain = token.split(":", 1)[1]
                self.lookup_counter += 1

                records = await self.dns.txt(include_domain)
                spf = SPFParser.extract_spf_record(records)

                if spf:
                    result = await self._evaluate_spf(
                        ip, include_domain, SPFParser.tokenize(spf)[1:],
                        depth + 1, dns_lookups, warnings, errors
                    )
                    if result == "pass":
                        return "pass"

            # ---------------- ip4 ----------------
            if token.startswith("ip4:"):
                cidr = token.split(":")[1]
                if self._ip_in_cidr(ip, cidr):
                    return "pass"

            # ---------------- all ----------------
            if token == "-all":
                return "fail"
            if token == "~all":
                return "softfail"
            if token == "?all":
                return "neutral"

        return "neutral"

    # =========================
    # IP MATCHING (SIMPLIFIED SAFE)
    # =========================

    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

    # =========================
    # RESPONSE BUILDER
    # =========================

    def _build_result(
        self,
        result: str,
        domain: str,
        spf_record: str,
        mechanisms: List[str],
        dns_lookups: int,
        warnings: List[str],
        errors: List[str],
        explanation: str,
        timestamp: float,
        aligned: bool,
        helo_domain: str = "",
        mail_from: str = "",
        alignment_mode: str = "",
    ) -> Dict:

        risk = "low"
        if result in ("fail", "permerror"):
            risk = "high"
        elif result in ("softfail", "neutral"):
            risk = "medium"

        return {
            "valid": result in ("pass", "neutral"),
            "result": result,
            "domain": domain,
            "organizational_domain": DomainUtils.organizational_domain(domain) if domain else "",
            "aligned": aligned,
            "alignment_mode": alignment_mode,
            "helo_domain": helo_domain,
            "mail_from": mail_from,
            "spf_record": spf_record,
            "mechanisms": mechanisms,
            "dns_lookups": dns_lookups,
            "warnings": warnings,
            "errors": errors,
            "risk_level": risk,
            "timestamp": timestamp,
        }
