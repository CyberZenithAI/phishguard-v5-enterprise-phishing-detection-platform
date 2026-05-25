# app/core/reputation.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ReputationScore:
    malicious_score: int
    confidence_score: int
    severity: str
    classification: str


class ReputationEngine:

    WEIGHTS = {
        "virustotal": 0.4,
        "otx": 0.2,
        "abuseipdb": 0.2,
        "urlhaus": 0.2,
    }

    def calculate(
        self,
        vt_score: int,
        otx_score: int,
        abuse_score: int,
        urlhaus_score: int,
    ) -> ReputationScore:

        weighted = (
            vt_score * self.WEIGHTS["virustotal"]
            + otx_score * self.WEIGHTS["otx"]
            + abuse_score * self.WEIGHTS["abuseipdb"]
            + urlhaus_score * self.WEIGHTS["urlhaus"]
        )

        malicious_score = int(min(weighted, 100))

        confidence_score = int(
            (
                abs(vt_score)
                + abs(otx_score)
                + abs(abuse_score)
                + abs(urlhaus_score)
            )
            / 4
        )

        severity = self._severity(malicious_score)
        classification = self._classification(malicious_score)

        return ReputationScore(
            malicious_score=malicious_score,
            confidence_score=confidence_score,
            severity=severity,
            classification=classification,
        )

    @staticmethod
    def _severity(score: int) -> str:

        if score >= 90:
            return "critical"

        if score >= 70:
            return "high"

        if score >= 40:
            return "medium"

        if score >= 20:
            return "low"

        return "informational"

    @staticmethod
    def _classification(score: int) -> str:

        if score >= 70:
            return "malicious"

        if score >= 40:
            return "suspicious"

        return "benign"
