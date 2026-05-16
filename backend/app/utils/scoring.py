from __future__ import annotations

from typing import Optional


# Shared scoring helpers used by the different detector services.
def add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def risk_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def build_user_summary(
    level: str,
    banking_impersonation_detected: bool,
    sender_domain: Optional[str],
    spf_found: Optional[bool],
    dmarc_found: Optional[bool],
) -> str:
    if level == "high":
        summary = "This email has strong warning signs. Be careful before clicking links or entering account details."
    elif level == "medium":
        summary = "This email has some warning signs. Review the details before trusting it."
    else:
        summary = "No major warning signs were found, but still check links and sender details before acting."

    if banking_impersonation_detected:
        summary += " It may be trying to impersonate a banking or payment service."
    elif sender_domain and (spf_found is False or dmarc_found is False):
        summary += " The sender domain is missing some email authentication records."

    return summary
