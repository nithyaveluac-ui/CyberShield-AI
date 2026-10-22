from __future__ import annotations

from typing import Any

from strands import tool


@tool
def inspect_security_alert(
    alert_id: str,
    severity: str,
    event_type: str,
    description: str,
    source_ip: str = "not_provided",
    evidence: str = "",
) -> dict[str, Any]:
    """Structure supplied alert facts without inventing threat intelligence."""
    allowed = {"critical", "high", "medium", "low", "unknown"}
    normalized = severity.strip().lower()
    if normalized not in allowed:
        normalized = "unknown"

    return {
        "alert_id": alert_id.strip() or "not_provided",
        "severity": normalized,
        "event_type": event_type.strip() or "unknown",
        "description": description.strip() or "not_provided",
        "source_ip": source_ip.strip() or "not_provided",
        "evidence": evidence.strip() or "not_provided",
        "analysis_limits": [
            "Only supplied facts are available.",
            "IP reputation and external threat intelligence were not checked.",
            "No security response action was executed.",
        ],
    }


@tool
def format_triage_recommendation(
    decision: str,
    reasoning: str,
    evidence: str,
    requires_human_review: bool = True,
) -> dict[str, Any]:
    """Format a non-disruptive triage recommendation for analyst review."""
    if decision not in {"Monitor", "Investigate", "Escalate"}:
        decision = "Investigate"

    if not reasoning.strip():
        reasoning = "Insufficient explanation; analyst review is required."

    if not evidence.strip():
        evidence = "No supporting evidence was supplied."
        requires_human_review = True

    return {
        "decision": decision,
        "reasoning": reasoning.strip(),
        "evidence": evidence.strip(),
        "requires_human_review": bool(requires_human_review),
        "automated_response_performed": False,
    }


TOOLS = [inspect_security_alert, format_triage_recommendation]
