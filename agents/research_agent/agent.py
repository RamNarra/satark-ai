from __future__ import annotations


def run(goal: str, tasks: list[dict]) -> dict:
    text = goal.lower()
    insights: list[str] = []
    context_gaps: list[str] = []

    if "meeting" in text and "attendee" not in text:
        context_gaps.append("Missing attendee list for one or more meetings")
    if "follow-up" in text and not any(t.get("deadline") for t in tasks):
        context_gaps.append("Follow-up tasks do not have explicit deadlines")
    if "week" in text:
        insights.append("Use batching to group deep-work tasks into 2 focus blocks/day")
    if "notes" in text:
        insights.append("Convert summary notes into action bullets to reduce context switching")

    if not insights:
        insights.append("No additional external context required for initial workflow run")

    return {
        "insights": insights,
        "context_gaps": context_gaps,
        "summary": "Research/context pass complete",
    }
