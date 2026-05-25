# app/email/dkim_validator.py

from __future__ import annotations

import logging
from dataclasses import dataclass

import dkim

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DKIMResult:
    valid: bool
    selector: str | None
    domain: str | None


class DKIMValidator:

    @staticmethod
    def extract_selector(signature: bytes) -> str | None:
        try:
            parts = signature.decode().split(";")

            for item in parts:
                item = item.strip()

                if item.startswith("s="):
                    return item.split("=")[1]

        except Exception:
            return None

        return None

    async def validate(self, raw_email: bytes) -> DKIMResult:

        try:
            headers = dkim.DKIM(raw_email)

            signature = headers.signature_fields.get(b"b")

            valid = headers.verify()

            selector = None
            domain = None

            if headers.signature_fields:
                selector = headers.signature_fields.get(b"s", b"").decode()
                domain = headers.signature_fields.get(b"d", b"").decode()

            return DKIMResult(
                valid=valid,
                selector=selector,
                domain=domain,
            )

        except Exception:
            LOGGER.exception("dkim_validation_failed")

            return DKIMResult(
                valid=False,
                selector=None,
                domain=None,
            )
