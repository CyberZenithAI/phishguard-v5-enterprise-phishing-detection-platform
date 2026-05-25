# app/email/dmarc.py

from __future__ import annotations

import logging
from dataclasses import dataclass

import dns.asyncresolver

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DMARCResult:
    domain: str
    policy: str
    alignment_passed: bool
    record: str | None


class DMARCValidator:

    def __init__(self) -> None:
        self.resolver = dns.asyncresolver.Resolver()

    async def fetch_record(self, domain: str) -> str | None:

        try:
            answers = await self.resolver.resolve(
                f"_dmarc.{domain}",
                "TXT",
            )

            return "".join(
                r.decode()
                for answer in answers
                for r in answer.strings
            )

        except Exception:
            return None

    @staticmethod
    def parse_policy(record: str | None) -> str:

        if not record:
            return "none"

        for item in record.split(";"):
            item = item.strip()

            if item.startswith("p="):
                return item.split("=")[1]

        return "none"

    async def validate(
        self,
        domain: str,
        spf_aligned: bool,
        dkim_aligned: bool,
    ) -> DMARCResult:

        record = await self.fetch_record(domain)

        policy = self.parse_policy(record)

        alignment_passed = spf_aligned or dkim_aligned

        return DMARCResult(
            domain=domain,
            policy=policy,
            alignment_passed=alignment_passed,
            record=record,
        )
