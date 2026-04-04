from __future__ import annotations

from pydantic import BaseModel, Field


class PlanStep(BaseModel):
    step: int
    agent: str
    action: str
    mode: str = "sequential"


class WorkflowPlan(BaseModel):
    intent_tags: list[str] = Field(default_factory=list)
    steps: list[PlanStep] = Field(default_factory=list)
    parallel_groups: list[list[str]] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
