"""
SCM audit engine — BPA + NCSC compliance assessment.

Flow:
    1. Extractor pulls live config from SCM SDK into a flat AuditSnapshot
    2. BPA check engine evaluates the snapshot against PAN best practices
    3. NCSC mapper cross-references each finding to CAF v4.0 / Cyber Essentials / 10 Steps controls
    4. ReportBuilder renders a structured JSON + Markdown report
"""

from .models import AuditSnapshot, Finding, Severity, Status
from .report import ReportBuilder
from .tiers import TIER_ORDER, TIERS, TierDefinition, get_tier, score_findings_against_tier

__all__ = [
    "AuditSnapshot",
    "Finding",
    "ReportBuilder",
    "Severity",
    "Status",
    "TIER_ORDER",
    "TIERS",
    "TierDefinition",
    "get_tier",
    "score_findings_against_tier",
]
