# TODO title (also set it in fields.md)

By TODO your name

TODO Hook: the problem, the project in one sentence, why it is cool, the headline result.

## The project

TODO Who it is for, what it does, its features (from agent/AGENT.md), and a short real conversation from facts.json demo_turns.



## How I built it

TODO Strands Agents, the tools, Amazon Bedrock, AgentCore Runtime, where Strands Decider 2B sits; Kiro and the spec-driven build in a sentence or two.

## The decision I handed to Strands Decider 2B

TODO Why this decision needs a fast, calibrated decision model; the typed questions and options; what the agent does with each answer and when it is unsure.

```python
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
```

< FIGURE 1 of 5: upload submission/article/img/architecture.png here >
Alt text: Architecture: the user, the agent with its tools and decision, Amazon Bedrock and Strands Decider 2B

## Measured

TODO Paste and explain the table from facts.json bench_table; say where the decider ran and which model; be honest about weak spots.

< FIGURE 2 of 5: upload submission/article/img/bench-accuracy.png here >
Alt text: Accuracy of Strands Decider 2B and the Bedrock LLM on the labelled cases

< FIGURE 3 of 5: upload submission/article/img/bench-latency.png here >
Alt text: Median latency per decision for both

< FIGURE 4 of 5: upload submission/article/img/bench-cost.png here >
Alt text: Cost per 1,000 decisions for both

< FIGURE 5 of 5: upload submission/article/img/bench-confidence.png here >
Alt text: Accuracy against the share of decisions answered without a human, as the confidence threshold moves

## The reusable decision pattern

TODO Where it lives (agent/decision.py), how another builder drops it into their agent.

## What I learned and what is next

TODO

---

Code: https://github.com/nithyaveluac-ui/CyberShield-AI . Video: TODO video link . Tags: #strands-decider-2b #guardrails

Built with the AWS User Group Madurai Strands Decider hackathon kit
