from __future__ import annotations

import re
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from app.models.schemas import AnalysisResult, EmailLink
from app.services.banking_detector import analyze_banking_impersonation
from app.services.domain_checks import (
    check_sender_authentication,
    extract_sender_domain,
    hostname,
    is_ip_hostname,
    registrable_hint,
)
from app.utils.scoring import add_reason, build_user_summary, risk_level


# Main phishing detector service. It combines language, link, sender-domain,
# and banking checks into one rule-based risk result.
BRAND_WORDS = {
    "amazon",
    "apple",
    "bank",
    "chase",
    "dhl",
    "dropbox",
    "fedex",
    "google",
    "microsoft",
    "netflix",
    "office",
    "paypal",
    "ups",
}

SUSPICIOUS_TLDS = {
    "cam",
    "click",
    "country",
    "download",
    "gq",
    "icu",
    "link",
    "loan",
    "ml",
    "mom",
    "rest",
    "ru",
    "support",
    "tk",
    "top",
    "work",
    "xyz",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "tinyurl.com",
    "t.co",
}

URGENCY_PATTERNS = [
    r"\bact now\b",
    r"\baction required\b",
    r"\bexpires? (today|soon|in \d+ hours?)\b",
    r"\bfinal notice\b",
    r"\bimmediate(ly)?\b",
    r"\blast warning\b",
    r"\blimited time\b",
    r"\brespond within\b",
    r"\bsuspended?\b",
    r"\bverify (now|today|immediately)\b",
    r"\bwithin 24 hours\b",
]

CREDENTIAL_PATTERNS = [
    r"\bconfirm your (account|identity|password)\b",
    r"\blog[ -]?in\b",
    r"\bpassword\b",
    r"\bre-enter\b",
    r"\bsecurity alert\b",
    r"\bsign[ -]?in\b",
    r"\bupdate your payment\b",
    r"\bverify your account\b",
]

FINANCIAL_PATTERNS = [
    r"\bbank account\b",
    r"\bbilling\b",
    r"\bcredit card\b",
    r"\binvoice\b",
    r"\bpayment failed\b",
    r"\brefund\b",
    r"\bwire transfer\b",
]


def visible_url_from_link_text(text: str) -> Optional[str]:
    match = re.search(r"https?://[^\s<>()]+|www\.[^\s<>()]+", text, re.IGNORECASE)
    if not match:
        return None

    value = match.group(0)
    if value.startswith("www."):
        value = f"https://{value}"
    return value


def unwrap_redirect_url(url: str) -> Optional[str]:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for key in ("url", "u", "q", "target", "redirect", "redirect_url"):
        values = query.get(key)
        if values and values[0].startswith(("http://", "https://")):
            return unquote(values[0])
    return None


def count_matches(patterns: list[str], text: str) -> int:
    return sum(1 for pattern in patterns if re.search(pattern, text, re.IGNORECASE))


def analyze_links(links: list[EmailLink]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    for link in links:
        href = link.href.strip()
        host = hostname(href)
        parsed = urlparse(href)

        if not host:
            continue

        if parsed.scheme == "http":
            score += 10
            add_reason(reasons, f"Link uses insecure HTTP: {registrable_hint(host)}")

        if is_ip_hostname(host):
            score += 20
            add_reason(reasons, "Link points directly to an IP address.")

        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            score += 10
            add_reason(reasons, f"Link uses a commonly abused domain ending: .{tld}")

        if registrable_hint(host) in SHORTENER_DOMAINS:
            score += 12
            add_reason(reasons, f"Link uses a URL shortener: {registrable_hint(host)}")

        if "@" in parsed.netloc:
            score += 18
            add_reason(reasons, "Link contains an @ symbol in the address.")

        if host.count(".") >= 4:
            score += 8
            add_reason(reasons, f"Link has many subdomains: {host}")

        decoded = unquote(href).lower()
        if any(word in decoded for word in ("login", "verify", "secure", "account", "password")):
            score += 6
            add_reason(reasons, "Link URL contains account or login wording.")

        redirect_url = unwrap_redirect_url(href)
        if redirect_url:
            score += 8
            add_reason(reasons, "Link appears to redirect through another URL.")

        visible_url = visible_url_from_link_text(link.text)
        if visible_url:
            visible_host = hostname(visible_url)
            if visible_host and registrable_hint(visible_host) != registrable_hint(host):
                score += 25
                add_reason(
                    reasons,
                    f"Visible link text domain differs from destination: {visible_host} -> {host}",
                )

        for brand in BRAND_WORDS:
            if brand in host and not host.endswith(f"{brand}.com"):
                score += 7
                add_reason(reasons, f"Link domain references a known brand in an unusual host: {host}")
                break

    return score, reasons


def run_rule_based_analysis(
    email_text: str,
    links: list[EmailLink],
    sender_email: Optional[str] = None,
) -> AnalysisResult:
    normalized_text = email_text.lower()
    reasons: list[str] = []
    score = 0
    sender_domain = extract_sender_domain(sender_email)
    spf_found: Optional[bool] = None
    dmarc_found: Optional[bool] = None
    banking_impersonation_detected = False
    banking_brands: list[str] = []

    urgency_hits = count_matches(URGENCY_PATTERNS, normalized_text)
    credential_hits = count_matches(CREDENTIAL_PATTERNS, normalized_text)
    financial_hits = count_matches(FINANCIAL_PATTERNS, normalized_text)

    if urgency_hits:
        score += min(urgency_hits * 8, 24)
        add_reason(reasons, "Message uses urgent or threatening language.")

    if credential_hits:
        score += min(credential_hits * 10, 30)
        add_reason(reasons, "Message asks for sign-in, password, or account verification.")

    if financial_hits:
        score += min(financial_hits * 8, 24)
        add_reason(reasons, "Message references payment or financial action.")

    banking_score, banking_reasons, banking_impersonation_detected, banking_brands = (
        analyze_banking_impersonation(
            email_text,
            urgency_hits,
            credential_hits,
            financial_hits,
        )
    )
    score += banking_score
    reasons.extend(reason for reason in banking_reasons if reason not in reasons)

    if re.search(r"\b(dear customer|dear user|valued customer)\b", normalized_text):
        score += 6
        add_reason(reasons, "Message uses a generic greeting.")

    if re.search(r"\bkindly\b", normalized_text):
        score += 4
        add_reason(reasons, "Message uses phrasing often found in phishing templates.")

    link_score, link_reasons = analyze_links(links)
    score += link_score
    reasons.extend(reason for reason in link_reasons if reason not in reasons)

    auth_score, auth_reasons, spf_found, dmarc_found = check_sender_authentication(sender_domain)
    score += auth_score
    reasons.extend(reason for reason in auth_reasons if reason not in reasons)

    if links and not email_text.strip():
        score += 12
        add_reason(reasons, "Message contains links but little visible text.")

    final_score = max(0, min(100, score))

    if not reasons:
        reasons.append("No obvious phishing indicators found by the local rule-based scan.")

    level = risk_level(final_score)
    summary = build_user_summary(
        level,
        banking_impersonation_detected,
        sender_domain,
        spf_found,
        dmarc_found,
    )

    return AnalysisResult(
        risk_score=final_score,
        risk_level=level,
        summary=summary,
        reasons=reasons[:8],
        link_count=len(links),
        sender_domain=sender_domain,
        spf_found=spf_found,
        dmarc_found=dmarc_found,
        banking_impersonation_detected=banking_impersonation_detected,
        banking_brands=banking_brands,
    )
