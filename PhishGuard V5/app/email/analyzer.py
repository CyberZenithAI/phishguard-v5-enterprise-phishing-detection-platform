from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from email.utils import parseaddr

from app.email.attachments import AttachmentAnalyzer
from app.email.dkim_validator import DKIMValidator
from app.email.dmarc import DMARCValidator
from app.email.extractor import IOCExtractor
from app.email.parser import EmailParser
from app.email.spf import SPFValidator
from app.email.spoofing import SpoofingDetector

LOGGER = logging.getLogger(__name__)


# =========================================================
# 📊 SIGNAL MODEL
# =========================================================

@dataclass(slots=True)
class Signal:
    name: str
    score: float                 # 0–100 raw contribution
    confidence: float           # 0–1
    severity: str              # low/medium/high/critical
    category: str              # technical / heuristic
    evidence: Optional[Dict[str, Any]] = None


# =========================================================
# ⚖️ WEIGHT MANAGER (CONFIGURABLE)
# =========================================================

class WeightManager:
    """
    Centralized, normalized weight system.
    Prevents arbitrary scoring accumulation.
    """

    def __init__(self) -> None:
        self.weights = {
            # Technical
            "spf_fail": 0.18,
            "dkim_invalid": 0.20,
            "dmarc_fail": 0.25,
            "dns_anomaly": 0.10,
            "ioc_match": 0.22,

            # Heuristic
            "spoofing": 0.30,
            "urgency_language": 0.08,
            "brand_impersonation": 0.25,
            "suspicious_links": 0.18,
            "attachment_risk": 0.22,
        }

    def get(self, key: str) -> float:
        return self.weights.get(key, 0.0)


# =========================================================
# 📉 RISK NORMALIZER (STATISTICAL SCALING)
# =========================================================

class RiskNormalizer:

    @staticmethod
    def normalize(weighted_sum: float) -> float:
        """
        Sigmoid-based normalization → stable 0–100 range
        Prevents score explosion and keeps comparability.
        """
        import math

        x = max(min(weighted_sum, 10.0), -10.0)
        normalized = 1 / (1 + math.exp(-x))
        return round(normalized * 100, 2)


# =========================================================
# 🧠 CLASSIFICATION ENGINE
# =========================================================

class ClassificationEngine:

    @staticmethod
    def classify(score: float) -> str:
        if score <= 20:
            return "benign"
        if score <= 40:
            return "low"
        if score <= 60:
            return "suspicious"
        if score <= 80:
            return "malicious"
        return "critical"


# =========================================================
# 🧮 SCORING ENGINE CORE
# =========================================================

class ScoringEngine:

    def __init__(self, weight_manager: WeightManager) -> None:
        self.weights = weight_manager

    def apply(self, signals: List[Signal]) -> Tuple[float, float, Dict[str, float]]:
        """
        Returns:
            - final weighted score (0–100)
            - confidence score
            - weight traceability map
        """

        if not signals:
            return 0.0, 0.0, {}

        weighted_sum = 0.0
        confidence_acc = 0.0
        weight_trace: Dict[str, float] = {}

        total_weight = sum(
            self.weights.get(s.name) for s in signals
        ) or 1.0

        for s in signals:
            w = self.weights.get(s.name) / total_weight

            contribution = s.score * w * s.confidence
            weighted_sum += contribution
            confidence_acc += s.confidence * w

            weight_trace[s.name] = round(w, 4)

        final_score = RiskNormalizer.normalize(weighted_sum / 10)
        confidence = round(confidence_acc, 3)

        return final_score, confidence, weight_trace


# =========================================================
# 📦 ANALYSIS RESULT
# =========================================================

@dataclass(slots=True)
class AnalysisResult:
    parsed: Dict[str, Any]

    spf: Dict[str, Any]
    dkim: Dict[str, Any]
    dmarc: Dict[str, Any]

    spoofing: Dict[str, Any]
    attachments: List[Dict[str, Any]]
    iocs: Dict[str, Any]

    final_score: float
    classification: str
    confidence: float

    technical_score: float
    heuristic_score: float

    signals: List[Dict[str, Any]] = field(default_factory=list)
    weights_applied: Dict[str, float] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    timestamp: str = field(default_factory=lambda: str(time.time()))


# =========================================================
# 🚨 EMAIL ANALYZER (MAIN ORCHESTRATOR)
# =========================================================

class EmailAnalyzer:

    def __init__(self) -> None:
        self.parser = EmailParser()
        self.spf = SPFValidator()
        self.dkim = DKIMValidator()
        self.dmarc = DMARCValidator()
        self.spoofing = SpoofingDetector()
        self.attachments = AttachmentAnalyzer()
        self.extractor = IOCExtractor()

        self.weights = WeightManager()
        self.engine = ScoringEngine(self.weights)

    # -----------------------------------------------------
    # 🧠 SIGNAL BUILDING
    # -----------------------------------------------------

    def _build_signals(self, results: Dict[str, Any]) -> List[Signal]:

        signals: List[Signal] = []

        # SPF
        if results["spf"].result != "pass":
            signals.append(Signal(
                name="spf_fail",
                score=80,
                confidence=0.9,
                severity="high",
                category="technical",
                evidence={"spf": results["spf"].result},
            ))

        # DKIM
        if not results["dkim"].valid:
            signals.append(Signal(
                name="dkim_invalid",
                score=85,
                confidence=0.95,
                severity="high",
                category="technical",
            ))

        # DMARC
        if not results["dmarc"].alignment_passed:
            signals.append(Signal(
                name="dmarc_fail",
                score=95,
                confidence=0.98,
                severity="critical",
                category="technical",
            ))

        # Spoofing
        if results["spoofing"].risk_score > 0:
            signals.append(Signal(
                name="spoofing",
                score=min(results["spoofing"].risk_score, 100),
                confidence=0.85,
                severity="high",
                category="heuristic",
            ))

        # Attachments
        attachment_risk = sum(
            70 for a in results["attachments"] if a.suspicious
        )

        if attachment_risk > 0:
            signals.append(Signal(
                name="attachment_risk",
                score=min(attachment_risk, 100),
                confidence=0.8,
                severity="medium",
                category="heuristic",
            ))

        # IOC signals
        if results["iocs"].get("matches"):
            signals.append(Signal(
                name="ioc_match",
                score=90,
                confidence=0.95,
                severity="critical",
                category="technical",
                evidence={"iocs": results["iocs"]["matches"]},
            ))

        return signals

    # -----------------------------------------------------
    # 🧾 MAIN ANALYSIS PIPELINE
    # -----------------------------------------------------

    async def analyze(
        self,
        raw_email: bytes,
        source_ip: str,
        helo: str,
    ) -> Dict[str, Any]:

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
            self.spf.validate(ip=source_ip, sender=sender_email, helo=helo),
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

        results = {
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "spoofing": spoofing_result,
            "iocs": ioc_result,
            "attachments": attachment_result,
        }

        signals = self._build_signals(results)

        # Split technical vs heuristic
        technical = [s for s in signals if s.category == "technical"]
        heuristic = [s for s in signals if s.category == "heuristic"]

        tech_score, tech_conf, tech_weights = self.engine.apply(technical)
        heur_score, heur_conf, heur_weights = self.engine.apply(heuristic)

        final_score = min(100, round((tech_score * 0.65) + (heur_score * 0.35), 2))
        confidence = round((tech_conf + heur_conf) / 2, 3)

        classification = ClassificationEngine.classify(final_score)

        risk_factors = [s.name for s in signals if s.severity in ("high", "critical")]

        recommendations = self._generate_recommendations(classification, risk_factors)

        return {
            "parsed": parsed.__dict__,

            "spf": spf_result.__dict__,
            "dkim": dkim_result.__dict__,
            "dmarc": dmarc_result.__dict__,
            "spoofing": spoofing_result.__dict__,
            "attachments": [a.__dict__ for a in attachment_result],
            "iocs": ioc_result.__dict__,

            "final_score": final_score,
            "classification": classification,
            "confidence": confidence,

            "technical_score": tech_score,
            "heuristic_score": heur_score,

            "signals": [s.__dict__ for s in signals],
            "weights_applied": {**tech_weights, **heur_weights},

            "risk_factors": risk_factors,
            "recommendations": recommendations,

            "evidence": [
                s.evidence for s in signals if s.evidence
            ],

            "timestamp": str(time.time()),
        }

    # -----------------------------------------------------
    # 📌 RECOMMENDATION ENGINE
    # -----------------------------------------------------

    def _generate_recommendations(
        self,
        classification: str,
        risk_factors: List[str],
    ) -> List[str]:

        recs = []

        if classification in ("malicious", "critical"):
            recs.append("Block email immediately and quarantine message")

        if "spoofing" in risk_factors:
            recs.append("Verify sender identity using out-of-band channel")

        if "dkim_invalid" in risk_factors or "spf_fail" in risk_factors:
            recs.append("Reject or flag due to authentication failure")

        if "attachment_risk" in risk_factors:
            recs.append("Sandbox attachments before delivery")

        if not recs:
            recs.append("Email appears low risk - monitor passively")

        return recs
