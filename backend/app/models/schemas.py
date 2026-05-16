from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


# Pydantic models define the JSON shapes accepted and returned by the API.
class EmailLink(BaseModel):
    text: str = ""
    href: str


class EmailPayload(BaseModel):
    text: str = ""
    links: List[EmailLink] = Field(default_factory=list)
    page_url: Optional[str] = None
    sender_email: Optional[str] = None


class AnalysePayload(BaseModel):
    email_text: str = ""
    links: List[str] = Field(default_factory=list)
    sender_email: Optional[str] = None


class AnalysisResult(BaseModel):
    risk_score: int
    risk_level: str
    summary: str
    reasons: List[str]
    link_count: int
    sender_domain: Optional[str] = None
    spf_found: Optional[bool] = None
    dmarc_found: Optional[bool] = None
    banking_impersonation_detected: bool = False
    banking_brands: List[str] = Field(default_factory=list)
