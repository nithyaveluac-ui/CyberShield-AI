"""CyberShield AI: evidence-grounded security alert triage using Strands and Decider."""

from __future__ import annotations

import time
from typing import Any

from strands import Agent

from decider_kit import Decider
from decider_kit.llm import (
    agent_model,
    default_model_id,
    image_blocks,
    strip_thinking,
)

from .decision import SecurityAlertGuard
from .tools import TOOLS

NAME = "CyberShield AI Security Alert Triage Agent"

SYSTEM_PROMPT = """You are CyberShield AI, a security alert triage assistant.

Your job is to help security analysts assess supplied security alerts.

Rules:
- Use inspect_security_alert to structure alert facts provided by the user.
- Never invent alert IDs, IP reputation, threat intelligence, evidence, or scan results.
- If essential information is missing, ask the user to provide it.
- Recommend only Monitor, Investigate, or Escalate when appropriate.
- Explain recommendations using the supplied evidence.
- Use format_triage_recommendation to format a proposed recommendation.
- Treat high severity, incomplete evidence, and uncertainty cautiously.
- A human analyst remains responsible for reviewing the recommendation.
- Never claim that a host was blocked, isolated, or remediated.
- Never perform disruptive security actions.
- Be concise, clear, and useful to a security analyst.
"""


class HackathonAgent:
    """One Strands agent per session, with the Decider guardrail attached."""

    def __init__(
        self,
        decider: Decider | None = None,
        model_id: str | None = None,
        eager: bool | None = None,
    ):
        # Keep the kit's public constructor compatible with its demo and benchmark.
        self.decider = decider or Decider()
        self.eager = False
        self.model_id = model_id or default_model_id()
        self.sessions: dict[str, tuple[Agent, SecurityAlertGuard]] = {}

    def _session(self, session_id: str) -> tuple[Agent, SecurityAlertGuard]:
        if session_id not in self.sessions:
            guard = SecurityAlertGuard(self.decider)
            agent = Agent(
                model=agent_model(self.model_id),
                system_prompt=SYSTEM_PROMPT,
                tools=TOOLS,
                interventions=[guard],
                callback_handler=None,
            )
            self.sessions[session_id] = (agent, guard)

        return self.sessions[session_id]

    def chat(
        self,
        message: str,
        session_id: str = "default",
        images: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Return the assistant reply, guardrail decisions, model and latency."""
        agent, guard = self._session(session_id)
        before = len(guard.log)
        t0 = time.perf_counter()

        result = agent(
            [*image_blocks(images), {"text": message}] if images else message,
            invocation_state={"images": list(images or [])},
        )

        reply = strip_thinking(str(result))
        return {
            "reply": reply,
            "decisions": guard.log[before:],
            "model_id": self.model_id,
            "latency_ms": round((time.perf_counter() - t0) * 1000),
            "agent": NAME,
            "eager": self.eager,
        }


if __name__ == "__main__":
    import json
    import sys

    agent = HackathonAgent()
    messages = sys.argv[1:] or [
        "Triage this alert: ID AL-1001, severity high, event type repeated failed logins. "
        "Description: 25 failed login attempts from source IP 192.0.2.10. "
        "Evidence: authentication log shows repeated failures."
    ]
    for message in messages:
        print(json.dumps(agent.chat(message), indent=2))
