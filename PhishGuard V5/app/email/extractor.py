# app/email/extractor.py

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger(__name__)

URL_REGEX = re.compile(
    r"(https?://[^\s<>'\"()]+)",
    re.IGNORECASE,
)

EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

IP_REGEX = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

OBFUSCATED_PATTERNS = {
    r"\[\.\]": ".",
    r"\(dot\)": ".",
    r"\[at\]": "@",
    r"\(at\)": "@",
}


@dataclass(slots=True)
class IOCExtractionResult:
    urls: list[str]
    emails: list[str]
    domains: list[str]
    ips: list[str]


class IOCExtractor:

    @staticmethod
    def normalize_obfuscation(content: str) -> str:
        for pattern, replacement in OBFUSCATED_PATTERNS.items():
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        return content

    @staticmethod
    def extract_urls(content: str) -> list[str]:
        return sorted(set(URL_REGEX.findall(content)))

    @staticmethod
    def extract_emails(content: str) -> list[str]:
        return sorted(set(EMAIL_REGEX.findall(content)))

    @staticmethod
    def extract_domains(content: str) -> list[str]:
        domains = DOMAIN_REGEX.findall(content)
        return sorted(set(domain.lower() for domain in domains))

    @staticmethod
    def extract_ips(content: str) -> list[str]:
        ips: list[str] = []

        for candidate in IP_REGEX.findall(content):
            try:
                ipaddress.ip_address(candidate)
                ips.append(candidate)
            except ValueError:
                continue

        return sorted(set(ips))

    async def extract_all(self, content: str) -> IOCExtractionResult:
        normalized = self.normalize_obfuscation(content)

        return IOCExtractionResult(
            urls=self.extract_urls(normalized),
            emails=self.extract_emails(normalized),
            domains=self.extract_domains(normalized),
            ips=self.extract_ips(normalized),
        )
