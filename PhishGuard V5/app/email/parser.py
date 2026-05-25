# app/email/parser.py

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ParsedEmail:
    subject: str
    sender: str
    recipients: list[str]
    body: str
    headers: dict[str, str]
    message: EmailMessage


class EmailParser:

    async def parse(self, raw_email: bytes) -> ParsedEmail:

        loop = asyncio.get_running_loop()

        message = await loop.run_in_executor(
            None,
            lambda: BytesParser(policy=policy.default).parsebytes(raw_email),
        )

        body = self.extract_body(message)

        recipients = message.get_all("to", [])

        return ParsedEmail(
            subject=message.get("subject", ""),
            sender=message.get("from", ""),
            recipients=recipients,
            body=body,
            headers=dict(message.items()),
            message=message,
        )

    @staticmethod
    def extract_body(message: EmailMessage) -> str:

        if message.is_multipart():

            body_parts: list[str] = []

            for part in message.walk():

                content_type = part.get_content_type()

                if content_type == "text/plain":

                    payload = part.get_payload(decode=True)

                    if payload:
                        body_parts.append(
                            payload.decode(
                                errors="replace",
                            )
                        )

            return "\n".join(body_parts)

        payload = message.get_payload(decode=True)

        if payload:
            return payload.decode(errors="replace")

        return ""
