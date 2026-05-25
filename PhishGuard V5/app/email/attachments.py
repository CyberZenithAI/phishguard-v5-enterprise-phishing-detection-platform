# app/email/attachments.py

from __future__ import annotations

import hashlib
import logging
import math
import mimetypes
import pathlib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

LOGGER = logging.getLogger(__name__)

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
    ".hta",
}


@dataclass(slots=True)
class AttachmentMetadata:
    filename: str
    mime_type: str
    sha256: str
    size: int
    entropy: float
    suspicious: bool
    double_extension: bool


class AttachmentAnalyzer:

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0

        frequency = {}

        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        entropy = 0.0
        length = len(data)

        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    @staticmethod
    def sha256_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def has_double_extension(filename: str) -> bool:
        suffixes = pathlib.Path(filename).suffixes
        return len(suffixes) >= 2

    @staticmethod
    def detect_real_mime(filename: str) -> str:
        mime_type, _ = mimetypes.guess_type(filename)
        return mime_type or "application/octet-stream"

    async def extract_attachments(
        self,
        message: EmailMessage,
    ) -> list[AttachmentMetadata]:

        results: list[AttachmentMetadata] = []

        for part in message.walk():

            disposition = part.get_content_disposition()

            if disposition != "attachment":
                continue

            filename = part.get_filename() or "unknown.bin"

            payload = part.get_payload(decode=True)

            if not payload:
                continue

            sha256 = self.sha256_hash(payload)
            entropy = self.calculate_entropy(payload)
            mime_type = self.detect_real_mime(filename)

            double_extension = self.has_double_extension(filename)

            suspicious = (
                pathlib.Path(filename).suffix.lower() in DANGEROUS_EXTENSIONS
                or entropy >= 7.5
                or double_extension
            )

            results.append(
                AttachmentMetadata(
                    filename=filename,
                    mime_type=mime_type,
                    sha256=sha256,
                    size=len(payload),
                    entropy=entropy,
                    suspicious=suspicious,
                    double_extension=double_extension,
                )
            )

        return results
