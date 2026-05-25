# app/email/spf.py

from __future__ import annotations

import logging
from dataclasses import dataclass

import dns.asyncresolver
import spf

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SPFResult:
    result: str
    explanation: str
    aligned: bool


class SPFValidator:

    def __init__(self) -> None:
        self.resolver = dns.asyncresolver.Resolver()

    async def validate(
        self,
        ip: str,
        sender: str,
        helo: str,
    ) -> SPFResult:

        try:
            result, explanation = spf.check2(
                i=ip,
                s=sender,
                h=helo,
            )

            sender_domain = sender.split("@")[-1]
            aligned = sender_domain == helo

            return SPFResult(
                result=result,
                explanation=explanation,
                aligned=aligned,
            )

        except Exception as exc:
            LOGGER.exception("spf_validation_failed")

            return SPFResult(
                result="permerror",
                explanation=str(exc),
                aligned=False,
            )
