from __future__ import annotations

from fastapi import APIRouter

from app.models.schemas import AnalysePayload, AnalysisResult, EmailLink, EmailPayload
from app.services.phishing_detector import run_rule_based_analysis


# API routes stay thin: receive JSON, call the detector service, return results.
router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/analyse", response_model=AnalysisResult)
def analyse_email(payload: AnalysePayload) -> AnalysisResult:
    links = [EmailLink(text=href, href=href) for href in payload.links]
    return run_rule_based_analysis(payload.email_text, links, payload.sender_email)


@router.post("/analyze", response_model=AnalysisResult)
def analyze_email(payload: EmailPayload) -> AnalysisResult:
    return run_rule_based_analysis(payload.text, payload.links, payload.sender_email)
