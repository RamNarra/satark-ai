from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class WorkflowContext(BaseModel):
    timezone: str = "UTC"
    notes: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    channel: str = "web-ui"


class WorkflowOptions(BaseModel):
    auto_execute_tools: bool = True
    stream: bool = True


class WorkflowRunRequest(BaseModel):
    session_id: Optional[str] = None
    user_id: str = "demo_user"
    goal: str = Field(min_length=4)
    context: WorkflowContext = Field(default_factory=WorkflowContext)
    options: WorkflowOptions = Field(default_factory=WorkflowOptions)


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    user_id: str = "demo_user"
    message: str = Field(min_length=1)


class WorkflowRunAccepted(BaseModel):
    workflow_id: str
    session_id: str
    status: str
    stream_url: str
    workflow_url: str


class ArtifactApprovalRequest(BaseModel):
    approved_by: str = "operator"


class ArtifactApprovalResponse(BaseModel):
    artifact_id: str
    approval_status: str
    approved_by: str


class SessionSnapshot(BaseModel):
    session_id: str
    user_id: str
    status: str
    workflows: list[dict[str, Any]] = Field(default_factory=list)
