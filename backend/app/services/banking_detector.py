from __future__ import annotations

import re

from app.utils.scoring import add_reason


# Banking checks look for Malaysian financial brands plus suspicious account language.
BANKING_IMPERSONATION_PHRASES = [
    "bank account suspended",
    "verify your banking account",
    "unauthorised transaction",
    "unauthorized transaction",
    "online banking",
    "security alert",
    "account locked",
    "confirm your account",
    "update your banking details",
    "OTP",
    "TAC",
]

MALAYSIAN_BANK_BRANDS = [
    "Maybank",
    "CIMB",
    "Public Bank",
    "RHB",
    "Hong Leong Bank",
    "AmBank",
    "Bank Islam",
    "BSN",
    "Touch 'n Go",
    "TNG",
    "DuitNow",
    "FPX",
]


def find_keywords(text: str, keywords: list[str]) -> list[str]:
    found: list[str] = []
    for keyword in keywords:
        pattern = r"\b" + re.escape(keyword).replace(r"\ ", r"\s+") + r"\b"
        if re.search(pattern, text, re.IGNORECASE):
            found.append(keyword)
    return found


def analyze_banking_impersonation(
    email_text: str,
    urgency_hits: int,
    credential_hits: int,
    financial_hits: int,
) -> tuple[int, list[str], bool, list[str]]:
    score = 0
    reasons: list[str] = []

    mentioned_brands = find_keywords(email_text, MALAYSIAN_BANK_BRANDS)
    banking_phrases = find_keywords(email_text, BANKING_IMPERSONATION_PHRASES)
    has_sensitive_request = urgency_hits > 0 or credential_hits > 0 or financial_hits > 0

    # Mentioning a bank is not suspicious by itself. The risk increases when a
    # bank brand appears together with urgent account, credential, or payment
    # language because that is common in banking phishing attempts.
    impersonation_detected = bool(mentioned_brands and has_sensitive_request)

    if banking_phrases:
        score += min(10 + len(banking_phrases) * 3, 18)
        add_reason(
            reasons,
            f"Banking-related risk language detected: {banking_phrases[0]}",
        )

    if impersonation_detected:
        score += 20
        add_reason(
            reasons,
            "Possible banking impersonation detected: "
            f"mentions {mentioned_brands[0]} with urgent account verification language.",
        )

    return score, reasons, impersonation_detected, mentioned_brands
