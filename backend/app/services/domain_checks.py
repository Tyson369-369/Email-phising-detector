from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

try:
    import dns.exception
    import dns.resolver
except ImportError:  # Keeps the app importable before requirements are installed.
    dns = None

from app.utils.scoring import add_reason


# Domain helpers handle sender-domain extraction and basic SPF/DMARC DNS checks.
SENDER_AUTH_CACHE: dict[str, tuple[int, tuple[str, ...], Optional[bool], Optional[bool]]] = {}


def extract_sender_domain(sender_email: Optional[str]) -> Optional[str]:
    if not sender_email:
        return None

    match = re.search(r"[\w.!#$%&'*+/=?^`{|}~-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender_email)
    if not match:
        return None

    return match.group(1).lower().strip(".")


def hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().strip(".")


def registrable_hint(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def is_ip_hostname(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def txt_record_contains(name: str, marker: str) -> tuple[Optional[bool], Optional[str]]:
    if dns is None:
        return None, "dnspython is not installed"

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 2.5

    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False, None
    except dns.exception.DNSException as error:
        return None, str(error)

    marker_lower = marker.lower()
    for answer in answers:
        chunks = []
        for chunk in answer.strings:
            if isinstance(chunk, bytes):
                chunks.append(chunk.decode("utf-8", errors="ignore"))
            else:
                chunks.append(str(chunk))

        if marker_lower in "".join(chunks).lower():
            return True, None

    return False, None


def check_sender_authentication(
    sender_domain: Optional[str],
) -> tuple[int, list[str], Optional[bool], Optional[bool]]:
    if not sender_domain:
        return 0, [], None, None

    sender_domain = sender_domain.lower()
    cached_result = SENDER_AUTH_CACHE.get(sender_domain)
    if cached_result:
        cached_score, cached_reasons, cached_spf, cached_dmarc = cached_result
        return cached_score, list(cached_reasons), cached_spf, cached_dmarc

    score = 0
    reasons: list[str] = []

    # These checks only confirm whether SPF and DMARC TXT records exist.
    # They are useful basic indicators, but they do not prove that one
    # individual email is legitimate or malicious.
    spf_found, spf_error = txt_record_contains(sender_domain, "v=spf1")
    dmarc_found, dmarc_error = txt_record_contains(f"_dmarc.{sender_domain}", "v=DMARC1")

    if spf_error or dmarc_error:
        score += 1
        add_reason(
            reasons,
            "Could not verify SPF/DMARC records; sender authentication result is inconclusive.",
        )
        SENDER_AUTH_CACHE[sender_domain] = (score, tuple(reasons), spf_found, dmarc_found)
        return score, reasons, spf_found, dmarc_found

    if spf_found is False:
        score += 1
        add_reason(reasons, f"SPF record was not found for sender domain: {sender_domain}")

    if dmarc_found is False:
        score += 2
        add_reason(reasons, f"DMARC record was not found for sender domain: {sender_domain}")

    SENDER_AUTH_CACHE[sender_domain] = (score, tuple(reasons), spf_found, dmarc_found)
    return score, reasons, spf_found, dmarc_found
