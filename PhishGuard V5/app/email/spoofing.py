# app/email/spoofing.py

from __future__ import annotations

import logging
import unicodedata
from dataclasses import dataclass
from email.utils import parseaddr

LOGGER = logging.getLogger(__name__)

BRANDS = {
    "paypal.com",
    "microsoft.com",
    "google.com",
    "amazon.com",
    "apple.com",
}


@dataclass(slots=True)
class SpoofingResult:
    display_name_spoofing: bool
    reply_to_mismatch: bool
    return_path_mismatch: bool
    homoglyph_detected: bool
    impersonation_detected: bool
    risk_score: int


class SpoofingDetector:

    @staticmethod
    def normalize_unicode(value: str) -> str:
        return unicodedata.normalize("NFKD", value)

    @staticmethod
    def detect_homoglyphs(value: str) -> bool:
        normalized = unicodedata.normalize("NFKD", value)
        return normalized != value

    @staticmethod
    def domain(email_address: str) -> str:
        return email_address.split("@")[-1].lower()

    async def analyze(
        self,
        from_header: str,
        reply_to: str | None,
        return_path: str | None,
    ) -> SpoofingResult:

        display_name, sender = parseaddr(from_header)

        sender_domain = self.domain(sender)

        reply_domain = (
            self.domain(parseaddr(reply_to)[1])
            if reply_to
            else sender_domain
        )

        return_domain = (
            self.domain(parseaddr(return_path)[1])
            if return_path
            else sender_domain
        )

        display_name_spoofing = any(
            brand.split(".")[0] in display_name.lower()
            for brand in BRANDS
        )

        reply_to_mismatch = reply_domain != sender_domain
        return_path_mismatch = return_domain != sender_domain

        homoglyph_detected = self.detect_homoglyphs(display_name)

        impersonation_detected = sender_domain in BRANDS

        score = sum(
            [
                display_name_spoofing,
                reply_to_mismatch,
                return_path_mismatch,
                homoglyph_detected,
                impersonation_detected,
            ]
        )

        return SpoofingResult(
            display_name_spoofing=display_name_spoofing,
            reply_to_mismatch=reply_to_mismatch,
            return_path_mismatch=return_path_mismatch,
            homoglyph_detected=homoglyph_detected,
            impersonation_detected=impersonation_detected,
            risk_score=score * 20,
        )
