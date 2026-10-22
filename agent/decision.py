"""REUSABLE DECISION PATTERN: Evidence-grounded security alert triage.

Pattern: #guardrails

What it does
Uses Strands Decider 2B to check whether a proposed security-alert triage
recommendation is supported by supplied evidence, proportionate to the stated
severity, and suitable for human review. It does not execute disruptive actions.

Typed questions
QUESTIONS contains three yes/no decisions:
- evidence_grounded: Is the recommendation supported by supplied alert facts?
  true means supported; false means it assumes facts or threat intelligence
  that were not supplied.
- risk_justified: Does the decision match the supplied severity and evidence?
  true means proportionate; false means it overstates or ignores the evidence.
- human_review: Should a human analyst review the recommendation?
  true means uncertainty, incomplete evidence, or high impact warrants review;
  false means the evidence is sufficiently clear for this non-disruptive
  recommendation.

Wiring
SecurityAlertGuard implements Strands InterventionHandler and guards calls to
format_triage_recommendation. It passes the proposed tool call and conversation
state to Decider.ask(QUESTIONS), then uses the returned probabilities to
Proceed, Guide, or Confirm. An unchanged retry after guidance is denied.
The guard records its verdicts for audit. The analyst remains responsible
for security decisions.

Reuse
Import SecurityAlertGuard and attach an instance through the Strands Agent
interventions list. Define typed questions for your own policy, limit the
guarded tool names, and tune the confidence thresholds using labelled test
cases. Evaluate held-out examples before relying on the pattern in production.
"""



from __future__ import annotations

import json
from typing import Any

from strands.interventions import (
    Confirm,
    Deny,
    Guide,
    InterventionHandler,
    Proceed,
)

from decider_kit import Decider
from decider_kit.patterns.guardrails import render_messages


PATTERN_TAG = "#guardrails"

GUARDED_TOOLS = {"format_triage_recommendation"}

QUESTIONS = {
    "evidence_grounded": Decider.noul(
        "Is the proposed security alert recommendation supported by the supplied alert facts?",
        {
            "true": "The recommendation is supported by explicit alert fields or evidence.",
            "false": "The recommendation assumes facts, threat intelligence, or activity not supplied.",
        },
    ),
    "risk_justified": Decider.noul(
        "Does the proposed triage decision match the severity and evidence actually provided?",
        {
            "true": "The decision is proportionate to the provided severity and evidence.",
            "false": "The decision overstates or ignores the supplied evidence.",
        },
    ),
    "human_review": Decider.noul(
        "Should a human security analyst review this recommendation before relying on it?",
        {
            "true": "Evidence is missing, conflicting, uncertain, or the alert is high impact.",
            "false": "Evidence is clear and sufficient for this non-disruptive recommendation.",
        },
    ),
}


class SecurityAlertGuard(InterventionHandler):
    """Check triage recommendations against alert evidence before returning them."""

    name = "security-alert-guard"

    def __init__(
        self,
        decider: Decider,
        yes: float = 0.5,
        unsure_band: tuple[float, float] = (0.4, 0.6),
    ):
        self.decider = decider
        self.yes = yes
        self.unsure_band = unsure_band
        self.log: list[dict[str, Any]] = []
        self._guided: set[str] = set()

    def before_invocation(self, event, **kwargs):
        self._guided.clear()
        return Proceed()

    def before_tool_call(self, event, **kwargs):
        name = event.tool_use["name"]
        if name not in GUARDED_TOOLS:
            return Proceed()

        args = event.tool_use.get("input") or {}
        sig = f"{name}:{json.dumps(args, sort_keys=True)}"

        if sig in self._guided:
            self.log.append({
                "pattern": PATTERN_TAG,
                "tool": name,
                "verdict": "deny",
                "reason": "retried an unchanged guided recommendation",
            })
            return Deny(
                reason="The recommendation was already returned for review. "
                       "Request missing evidence or revise the recommendation."
            )

        state = (
            "A security analyst conversation and a proposed non-disruptive alert triage recommendation.\n\n"
            f"--- CONVERSATION ---\n{render_messages(event.agent.messages)}\n\n"
            f"--- PROPOSED RECOMMENDATION ---\ntool: {name}\n"
            f"arguments: {json.dumps(args, sort_keys=True)}\n\n"
            "Assess only the supplied facts. Do not infer external threat intelligence."
        )

        answers = self.decider.ask(state, QUESTIONS)
        grounded = answers["evidence_grounded"].p_yes or 0.0
        justified = answers["risk_justified"].p_yes or 0.0
        review = answers["human_review"].p_yes or 0.0

        lo, hi = self.unsure_band
        rec = {
            "pattern": PATTERN_TAG,
            "tool": name,
            "evidence_grounded": round(grounded, 3),
            "risk_justified": round(justified, 3),
            "human_review": round(review, 3),
            "decider_ms": round(self.decider.last_latency_ms or 0),
        }

        if grounded < self.yes:
            rec["verdict"] = "guide"
            action = Guide(
                feedback="Do not invent security evidence. Ask for missing alert fields "
                         "and ground the recommendation in supplied facts."
            )
        elif justified < self.yes:
            rec["verdict"] = "guide"
            action = Guide(
                feedback="Choose a proportionate Monitor, Investigate, or Escalate "
                         "recommendation supported by the supplied alert evidence."
            )
        elif lo <= review <= hi or grounded <= hi or justified <= hi:
            rec["verdict"] = "confirm"
            action = Confirm(
                prompt="A human security analyst must review this recommendation before relying on it.",
                response="yes",
            )
        elif review > hi:
            rec["verdict"] = "confirm"
            action = Confirm(
                prompt="The Decider recommends human review of this security alert.",
                response="yes",
            )
        else:
            rec["verdict"] = "proceed"
            action = Proceed()

        if rec["verdict"] == "guide":
            self._guided.add(sig)

        self.log.append(rec)
        return action
