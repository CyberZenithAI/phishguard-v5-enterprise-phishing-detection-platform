# app/email/dkim_validator.py

from __future__ import annotations

import logging
import hashlib
import time
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from typing import Optional, List, Dict, Any

import dkim

LOGGER = logging.getLogger("phishguard.dkim")


# =========================
# RESULT SCHEMA (STRICT)
# =========================

@dataclass(slots=True)
class DKIMValidationResult:
    valid: bool
    domain: str | None
    selector: str | None
    algorithm: str | None
    canonicalization: str | None
    signed_headers: List[str]
    header_integrity: bool
    body_integrity: bool
    alignment: bool
    warnings: List[str]
    errors: List[str]
    risk_level: str
    timestamp: str


# =========================
# MAIN VALIDATOR
# =========================

class DKIMValidator:
    """
    Enterprise-grade DKIM validator (RFC 6376 compliant)
    """

    REQUIRED_HEADERS = [
        "from",
        "date",
        "subject",
        "to",
        "message-id",
        "mime-version",
    ]

    def __init__(self, dns_cache_ttl: int = 300):
        self._dns_cache: Dict[str, tuple[float, Any]] = {}
        self._dns_cache_ttl = dns_cache_ttl

    # =========================
    # PUBLIC API
    # =========================

    async def validate(self, raw_email: bytes) -> Dict[str, Any]:
        start = time.time()

        warnings: List[str] = []
        errors: List[str] = []

        try:
            # 1. MIME PARSING SAFE
            msg = self._parse_mime(raw_email)

            # 2. HEADER VALIDATION
            header_ok, header_errors = self._validate_headers(msg)
            errors.extend(header_errors)

            # 3. DKIM CRYPTO VALIDATION
            dkim_valid, dkim_meta = self._verify_dkim(raw_email)

            # 4. ALIGNMENT CHECK (From domain vs DKIM domain)
            alignment = self._check_alignment(msg, dkim_meta.get("domain"))

            # 5. ADVANCED DETECTION
            warnings.extend(self._detect_anomalies(msg, dkim_meta))

            # 6. RISK SCORING
            risk_level = self._calculate_risk(
                dkim_valid, header_ok, alignment, warnings, errors
            )

            return asdict(DKIMValidationResult(
                valid=dkim_valid and header_ok,
                domain=dkim_meta.get("domain"),
                selector=dkim_meta.get("selector"),
                algorithm=dkim_meta.get("algorithm"),
                canonicalization=dkim_meta.get("canonicalization"),
                signed_headers=dkim_meta.get("signed_headers", []),
                header_integrity=header_ok,
                body_integrity=dkim_valid,
                alignment=alignment,
                warnings=warnings,
                errors=errors,
                risk_level=risk_level,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            ))

        except Exception as e:
            LOGGER.exception(
                "dkim_validation_crash",
                extra={"error": str(e)}
            )

            return asdict(DKIMValidationResult(
                valid=False,
                domain=None,
                selector=None,
                algorithm=None,
                canonicalization=None,
                signed_headers=[],
                header_integrity=False,
                body_integrity=False,
                alignment=False,
                warnings=[],
                errors=["dkim_engine_failure"],
                risk_level="high",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            ))

    # =========================
    # PARSING LAYER
    # =========================

    def _parse_mime(self, raw_email: bytes) -> EmailMessage:
        if len(raw_email) > 10_000_000:
            raise ValueError("email_too_large")

        parser = BytesParser(policy=policy.default)
        return parser.parsebytes(raw_email)

    # =========================
    # HEADER VALIDATION
    # =========================

    def _validate_headers(self, msg: EmailMessage) -> tuple[bool, List[str]]:
        errors = []

        for h in self.REQUIRED_HEADERS:
            if not msg.get(h):
                errors.append(f"missing_header:{h}")

        # RFC injection detection
        for k, v in msg.items():
            if "\n" in k or "\r" in k:
                errors.append("header_injection_detected")
                break

            if v and ("\r\n\r\n" in v):
                errors.append(f"malformed_header:{k}")

        return len(errors) == 0, errors

    # =========================
    # DKIM VERIFICATION (RFC 6376)
    # =========================

    def _verify_dkim(self, raw_email: bytes) -> tuple[bool, Dict[str, Any]]:
        """
        Uses dkimpy for real cryptographic verification
        """
        result = {
            "domain": None,
            "selector": None,
            "algorithm": None,
            "canonicalization": None,
            "signed_headers": [],
        }

        try:
            valid = dkim.verify(raw_email)

            # Parse DKIM signature manually for metadata
            dkim_obj = dkim.DKIM(raw_email)

            sig = dkim_obj.signature_fields

            if sig:
                result["domain"] = sig.get(b"d", b"").decode(errors="ignore")
                result["selector"] = sig.get(b"s", b"").decode(errors="ignore")
                result["algorithm"] = sig.get(b"a", b"").decode(errors="ignore")
                result["canonicalization"] = sig.get(b"c", b"").decode(errors="ignore")

                h = sig.get(b"h", b"")
                result["signed_headers"] = (
                    h.decode().split(":") if isinstance(h, bytes) else []
                )

            return valid, result

        except Exception as e:
            LOGGER.warning("dkim_verification_failed", extra={"error": str(e)})
            return False, result

    # =========================
    # ALIGNMENT CHECK
    # =========================

    def _check_alignment(self, msg: EmailMessage, dkim_domain: Optional[str]) -> bool:
        from_header = msg.get("From", "")

        if not dkim_domain or not from_header:
            return False

        return dkim_domain.lower() in from_header.lower()

    # =========================
    # ANOMALY DETECTION
    # =========================

    def _detect_anomalies(
        self,
        msg: EmailMessage,
        dkim_meta: Dict[str, Any]
    ) -> List[str]:

        warnings = []

        # Weak algorithm detection
        if dkim_meta.get("algorithm", "").lower() in ["rsa-sha1"]:
            warnings.append("weak_dkim_algorithm")

        # Missing DKIM signature fields
        if not dkim_meta.get("selector"):
            warnings.append("missing_selector")

        # Multiple DKIM headers risk
        if len(msg.get_all("DKIM-Signature", [])) > 1:
            warnings.append("multiple_dkim_signatures")

        # Suspicious header drift
        if "from" not in [h.lower() for h in dkim_meta.get("signed_headers", [])]:
            warnings.append("from_not_signed")

        return warnings

    # =========================
    # RISK ENGINE
    # =========================

    def _calculate_risk(
        self,
        dkim_valid: bool,
        header_ok: bool,
        alignment: bool,
        warnings: List[str],
        errors: List[str],
    ) -> str:

        score = 0

        if not dkim_valid:
            score += 50
        if not header_ok:
            score += 30
        if not alignment:
            score += 15

        score += len(warnings) * 5
        score += len(errors) * 10

        if score >= 70:
            return "critical"
        if score >= 40:
            return "high"
        if score >= 20:
            return "medium"
        return "low"
