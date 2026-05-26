# app/core/reputation.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime
import math


# =========================
# Data Structures
# =========================

@dataclass(slots=True)
class Signal:
    source: str
    score: float          # normalized 0.0 - 1.0 (malicious probability)
    confidence: float     # 0.0 - 1.0
    weight: float         # 0.0 - 1.0
    evidence: List[str] = field(default_factory=list)


@dataclass(slots=True)
class ReputationResult:
    malicious_score: float
    confidence_score: float
    risk_classification: str
    probability_malicious: float
    source_consensus: float
    evidence_strength: float
    signals: List[Dict[str, Any]]
    weighted_sources: List[Dict[str, Any]]
    risk_factors: List[str]
    explanations: List[str]
    timestamp: str


# =========================
# Core Engine
# =========================

class ReputationEngine:

    # Prior belief: slightly biased toward benign traffic
    PRIOR_MALICIOUS_PROB = 0.15

    # Source reliability (static baseline, can be dynamic later)
    SOURCE_RELIABILITY = {
        "virustotal": 0.95,
        "otx": 0.85,
        "abuseipdb": 0.90,
        "urlhaus": 0.95,
        "spf": 0.80,
        "dkim": 0.85,
        "dmarc": 0.90,
        "dns": 0.75,
    }

    # -------------------------
    # Public API
    # -------------------------

    def calculate(self, signals: List[Signal]) -> ReputationResult:
        normalized = self._normalize_signals(signals)

        prob, weighted_sources, explanations = self._probabilistic_aggregation(normalized)

        confidence = self._compute_confidence(normalized)

        consensus = self._compute_consensus(normalized)

        evidence_strength = self._compute_evidence_strength(normalized)

        classification = self._classify(prob)

        risk_factors = self._extract_risk_factors(normalized)

        return ReputationResult(
            malicious_score=round(prob * 100, 2),
            confidence_score=round(confidence * 100, 2),
            risk_classification=classification,
            probability_malicious=round(prob, 4),
            source_consensus=round(consensus, 4),
            evidence_strength=round(evidence_strength, 4),
            signals=[self._signal_to_dict(s) for s in normalized],
            weighted_sources=weighted_sources,
            risk_factors=risk_factors,
            explanations=explanations,
            timestamp=datetime.utcnow().isoformat()
        )

    # =========================
    # Normalization Layer
    # =========================

    def _normalize_signals(self, signals: List[Signal]) -> List[Signal]:
        normalized: List[Signal] = []

        for s in signals:
            score = self._clamp(s.score)
            confidence = self._clamp(s.confidence)
            weight = self._clamp(s.weight)

            # adjust by source reliability
            reliability = self.SOURCE_RELIABILITY.get(s.source, 0.7)
            adjusted_weight = self._clamp(weight * reliability)

            normalized.append(
                Signal(
                    source=s.source,
                    score=score,
                    confidence=confidence,
                    weight=adjusted_weight,
                    evidence=s.evidence[:10]
                )
            )

        return normalized

    # =========================
    # Probabilistic Model
    # =========================

    def _probabilistic_aggregation(
        self,
        signals: List[Signal]
    ) -> (float, List[Dict[str, Any]], List[str]):

        prior = self._logit(self.PRIOR_MALICIOUS_PROB)

        weighted_sum = 0.0
        total_weight = 0.0

        explanations = []
        weighted_sources = []

        for s in signals:
            # convert probability -> log-odds
            log_odds = self._logit(s.score)

            w = s.weight * s.confidence

            weighted_sum += log_odds * w
            total_weight += w

            weighted_sources.append({
                "source": s.source,
                "weight": round(w, 4),
                "score": s.score,
                "confidence": s.confidence
            })

            explanations.append(
                f"{s.source}: logit({s.score:.2f}) weighted by {w:.2f}"
            )

        if total_weight == 0:
            return self.PRIOR_MALICIOUS_PROB, weighted_sources, explanations

        posterior_logit = prior + (weighted_sum / total_weight)

        probability = self._sigmoid(posterior_logit)

        return self._clamp(probability), weighted_sources, explanations

    # =========================
    # Confidence Model (separate)
    # =========================

    def _compute_confidence(self, signals: List[Signal]) -> float:

        if not signals:
            return 0.0

        weights = [s.weight for s in signals]
        confidences = [s.confidence for s in signals]

        weighted_conf = sum(w * c for w, c in zip(weights, confidences))
        total_weight = sum(weights) or 1.0

        base = weighted_conf / total_weight

        # penalize disagreement
        variance = self._variance([s.score for s in signals])
        penalty = 1.0 - min(variance, 0.5)

        return self._clamp(base * penalty)

    # =========================
    # Consensus Model
    # =========================

    def _compute_consensus(self, signals: List[Signal]) -> float:

        if len(signals) < 2:
            return 1.0

        scores = [s.score for s in signals]
        variance = self._variance(scores)

        return self._clamp(1.0 - variance)

    # =========================
    # Evidence Strength
    # =========================

    def _compute_evidence_strength(self, signals: List[Signal]) -> float:

        total_evidence = sum(len(s.evidence) for s in signals)
        return self._clamp(total_evidence / 50)

    # =========================
    # Classification Layer
    # =========================

    def _classify(self, p: float) -> str:
        if p >= 0.85:
            return "critical"
        if p >= 0.70:
            return "malicious"
        if p >= 0.45:
            return "suspicious"
        if p >= 0.20:
            return "low_risk"
        return "benign"

    # =========================
    # Risk Factors
    # =========================

    def _extract_risk_factors(self, signals: List[Signal]) -> List[str]:
        factors = []

        for s in signals:
            if s.score > 0.7:
                factors.append(f"high_risk_signal:{s.source}")
            if s.confidence < 0.4:
                factors.append(f"low_confidence_source:{s.source}")

        return factors

    # =========================
    # Math Utilities
    # =========================

    @staticmethod
    def _logit(p: float) -> float:
        p = min(max(p, 1e-6), 1 - 1e-6)
        return math.log(p / (1 - p))

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1 / (1 + math.exp(-x))

    @staticmethod
    def _clamp(x: float) -> float:
        return max(0.0, min(1.0, x))

    @staticmethod
    def _variance(values: List[float]) -> float:
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    @staticmethod
    def _signal_to_dict(s: Signal) -> Dict[str, Any]:
        return {
            "source": s.source,
            "score": s.score,
            "confidence": s.confidence,
            "weight": s.weight,
            "evidence": s.evidence
        }
