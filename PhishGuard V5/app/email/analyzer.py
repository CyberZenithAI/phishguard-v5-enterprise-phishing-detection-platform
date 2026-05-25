# app/email/analyzer.py

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from email.utils import parseaddr
from typing import Any

from app.email.attachments import AttachmentAnalyzer
from app.email.dkim_validator import DKIMValidator
from app.email.dmarc import DMARCValidator
from app.email.extractor import IOCExtractor
from app.email.parser import EmailParser
from app.email.spf import SPFValidator
from app.email.spoofing import SpoofingDetector

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalysisResult:
    parsed: dict[str, Any]
    spf: dict[str, Any]
    dkim: dict[str, Any]
    dmarc: dict[str, Any]
    spoofing: dict[str, Any]
    attachments: list[dict[str, Any]]
    iocs: dict[str, Any]
    threat_score: int


class EmailAnalyzer:

    def __init__(self) -> None:
        self.parser = EmailParser()
        self.spf = SPFValidator()
        self.dkim = DKIMValidator()
        self.dmarc = DMARCValidator()
        self.spoofing = SpoofingDetector()
        self.attachments = AttachmentAnalyzer()
        self.extractor = IOCExtractor()

    async def analyze(
        self,
        raw_email: bytes,
        source_ip: str,
        helo: str,
    ) -> AnalysisResult:

        parsed = await self.parser.parse(raw_email)

        sender_email = parseaddr(parsed.sender)[1]
        sender_domain = sender_email.split("@")[-1]

        (
            spf_result,
            dkim_result,
            spoofing_result,
            ioc_result,
            attachment_result,
        ) = await asyncio.gather(
            self.spf.validate(
                ip=source_ip,
                sender=sender_email,
                helo=helo,
            ),
            self.dkim.validate(raw_email),
            self.spoofing.analyze(
                from_header=parsed.sender,
                reply_to=parsed.headers.get("Reply-To"),
                return_path=parsed.headers.get("Return-Path"),
            ),
            self.extractor.extract_all(parsed.body),
            self.attachments.extract_attachments(parsed.message),
        )

        dmarc_result = await self.dmarc.validate(
            domain=sender_domain,
            spf_aligned=spf_result.aligned,
            dkim_aligned=dkim_result.valid,
        )

        threat_score = 0

        if spf_result.result != "pass":
            threat_score += 20

        if not dkim_result.valid:
            threat_score += 20

        if not dmarc_result.alignment_passed:
            threat_score += 20

        threat_score += spoofing_result.risk_score

        threat_score += sum(
            15 for item in attachment_result if item.suspicious
        )

        return AnalysisResult(
            parsed=asdict(parsed),
            spf=asdict(spf_result),
            dkim=asdict(dkim_result),
            dmarc=asdict(dmarc_result),
            spoofing=asdict(spoofing_result),
            attachments=[asdict(item) for item in attachment_result],
            iocs=asdict(ioc_result),
            threat_score=min(threat_score, 100),
        )
