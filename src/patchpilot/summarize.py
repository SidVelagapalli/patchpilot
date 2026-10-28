"""Optional LLM step: turn a finding into a plain-English risk summary. Falls back to a template."""

import json
import os

MODEL = "<anthropic-model-id>"
SYSTEM = ("You write 3-sentence vulnerability summaries for a solo developer. Sentence 1: what is vulnerable "
          "and the realistic impact for a web app. Sentence 2: how urgent (say if it's known exploited). "
          "Sentence 3: the exact fix (upgrade command). Use only the facts given; never invent a version.")


def template(f: dict) -> str:
    fix = f"Upgrade to {f['fixed_in'][-1]}." if f["fixed_in"] else "No fixed version yet; consider replacing it."
    urgency = "CISA lists it as exploited in the wild: fix now." if f["known_exploited"] else f"Severity: {f['severity'] or 'unknown'}."
    return f"{f['package']} {f['version']} is affected by {f['id']}: {f['summary']} {urgency} {fix}"


def summarize(f: dict, client=None) -> str:
    if client is None and not os.environ.get("ANTHROPIC_API_KEY"):
        return template(f)
    try:
        import anthropic
        client = client or anthropic.Anthropic()
        reply = client.messages.create(model=MODEL, max_tokens=250, system=SYSTEM,
                                       messages=[{"role": "user", "content": json.dumps(f)}])
        return reply.content[0].text
    except Exception:
        return template(f)  # the LLM is a nice-to-have, never a single point of failure
