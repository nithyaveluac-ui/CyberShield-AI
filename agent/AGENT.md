# Use case

Original project: CyberShield AI Security Alert Triage Agent.

- **Pitch:** an AI-assisted security alert triage agent that grounds its recommendations in supplied evidence and routes uncertain cases for human review.
- **Who it is for:** security analysts and teams that need consistent, evidence-based initial alert triage.
- **Features:**
  - structure supplied alert details without inventing threat intelligence;
  - recommend Monitor, Investigate, or Escalate based on the provided facts;
  - use Strands Decider 2B to check evidence grounding, risk proportionality, and human-review needs;
  - record decisions for review without automatically performing disruptive security actions.
- **The decision handed to Strands Decider 2B:** is the recommendation evidence-grounded, proportionate to the supplied risk, and appropriate for human review? (#guardrails)
- **Why a decision model:** the guard needs explicit decision scores that application logic can use to allow, guide, or request confirmation for a proposed recommendation.
- **Amazon Bedrock:** the conversational agent uses the configured Strands model provider. Deployment status must be verified separately.
