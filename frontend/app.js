const promptInput = document.getElementById("promptInput");
const fileInput = document.getElementById("fileInput");
const filePills = document.getElementById("filePills");
const sendBtn = document.getElementById("sendBtn");
const liveBtn = document.getElementById("liveBtn");
const hero = document.getElementById("hero");
const opsView = document.getElementById("opsView");
const activeCount = document.getElementById("activeCount");
const runState = document.getElementById("runState");
const artifactCount = document.getElementById("artifactCount");
const footerArtifactCount = document.getElementById("footerArtifactCount");
const latencyValue = document.getElementById("latencyValue");
const themeToggle = document.getElementById("themeToggle");
const approveBtn = document.getElementById("approveBtn");

const summaryHeadline = document.getElementById("summaryHeadline");
const summaryText = document.getElementById("summaryText");
const outputTitle = document.getElementById("outputTitle");
const taskCount = document.getElementById("taskCount");
const eventCount = document.getElementById("eventCount");
const noteCount = document.getElementById("noteCount");
const tasksList = document.getElementById("tasksList");
const eventsList = document.getElementById("eventsList");
const notesList = document.getElementById("notesList");
const sessionList = document.getElementById("sessionList");
const approvalTitle = document.getElementById("approvalTitle");
const approvalText = document.getElementById("approvalText");
const mergeFlare = document.getElementById("mergeFlare");

const tasksColumn = document.getElementById("tasksColumn");
const eventsColumn = document.getElementById("eventsColumn");
const notesColumn = document.getElementById("notesColumn");

let files = [];
let activeWorkflowId = null;
let activeSessionId = null;
let firstArtifactId = null;
let eventSource = null;
let runStartedAt = 0;
let isFinalizing = false;
let liveMode = false;

const AGENT_KEYS = ["manager", "memory_agent", "research_agent", "notes_agent", "task_agent", "schedule_agent"];
const STAGGER_MS = {
  manager: 0,
  memory_agent: 220,
  research_agent: 420,
  notes_agent: 650,
  task_agent: 760,
  schedule_agent: 870,
};

function autoGrow() {
  promptInput.style.height = "auto";
  promptInput.style.height = `${Math.min(promptInput.scrollHeight, 220)}px`;
}

function escapeHtml(text) {
  return String(text ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderFiles() {
  filePills.innerHTML = files
    .map((file) => `<div class="file-pill">${escapeHtml(file.name)}</div>`)
    .join("");
}

function updateActiveCount() {
  const activeOrDone = document.querySelectorAll(".agent-card.active, .agent-card.done").length;
  activeCount.textContent = `${activeOrDone} / 6 active`;
}

function setAgentState(agentKey, state, statusText = "") {
  const card = document.querySelector(`.agent-card[data-agent="${agentKey}"]`);
  if (!card) return;

  card.classList.remove("idle", "booting", "active", "done", "waiting");
  card.classList.add(state);

  const status = card.querySelector(".status");
  if (status) {
    status.textContent = statusText || state;
  }

  updateActiveCount();
}

function resetAgents() {
  document.querySelectorAll(".agent-card").forEach((card) => {
    card.classList.remove("booting", "active", "done", "waiting");
    card.classList.add("idle");
    const status = card.querySelector(".status");
    if (status) {
      status.textContent = "Idle";
    }
  });
  updateActiveCount();
}

function pulseMerge() {
  mergeFlare.classList.remove("merge-live");
  void mergeFlare.offsetWidth;
  mergeFlare.classList.add("merge-live");
}

function showOps() {
  hero.classList.add("hero-leave");
  setTimeout(() => {
    hero.classList.add("hidden");
  }, 260);
  opsView.classList.remove("hidden");
}

function resetOutput() {
  outputTitle.textContent = "Awaiting orchestration";
  runState.textContent = "Initializing";
  artifactCount.textContent = "0 artifacts";
  footerArtifactCount.textContent = "0";
  latencyValue.textContent = "0 ms";

  summaryHeadline.textContent = "Mission is spinning up";
  summaryText.textContent = "Manager is parsing your request and waking the right specialists.";

  taskCount.textContent = "0";
  eventCount.textContent = "0";
  noteCount.textContent = "0";

  tasksList.innerHTML = '<div class="empty-artifact">No tasks generated yet.</div>';
  eventsList.innerHTML = '<div class="empty-artifact">No calendar actions yet.</div>';
  notesList.innerHTML = '<div class="empty-artifact">No notes generated yet.</div>';
  sessionList.innerHTML = '<div class="empty-artifact">No replay items yet.</div>';

  tasksColumn.classList.remove("artifact-focus");
  eventsColumn.classList.remove("artifact-focus");
  notesColumn.classList.remove("artifact-focus");

  approvalTitle.textContent = "No approval pending";
  approvalText.textContent = "When an artifact needs confirmation, the action will appear here.";
  approveBtn.disabled = true;
  firstArtifactId = null;
}

function updateArtifactCounters(count) {
  artifactCount.textContent = `${count} artifact${count === 1 ? "" : "s"}`;
  footerArtifactCount.textContent = String(count);
}

function toDictArray(value) {
  if (Array.isArray(value)) {
    return value.filter((item) => item && typeof item === "object");
  }
  return [];
}

function firstNonEmptyArray(candidates) {
  for (const candidate of candidates) {
    const list = toDictArray(candidate);
    if (list.length) {
      return list;
    }
  }
  return [];
}

function normalizeWorkflowPayload(data) {
  const outputs = data?.outputs && typeof data.outputs === "object" ? data.outputs : {};
  const notesOutput = outputs.notes && typeof outputs.notes === "object" ? outputs.notes : {};
  const tasksOutput = outputs.tasks && typeof outputs.tasks === "object" ? outputs.tasks : {};
  const scheduleOutput = outputs.schedule && typeof outputs.schedule === "object" ? outputs.schedule : {};

  let tasks = firstNonEmptyArray([
    data?.tasks,
    data?.task_items,
    data?.summary?.tasks,
    tasksOutput.tasks,
    outputs.tasks,
  ]);

  let events = firstNonEmptyArray([
    data?.events,
    data?.event_items,
    data?.schedule_blocks,
    data?.summary?.events,
    scheduleOutput.events,
    outputs.events,
  ]);

  let notes = firstNonEmptyArray([
    data?.notes,
    data?.note_items,
    data?.summary?.notes,
    notesOutput.notes,
    outputs.notes,
  ]);

  if (!notes.length && notesOutput.summary) {
    notes = [
      {
        title: notesOutput.title || "Workflow Brief",
        summary: notesOutput.summary,
        bullets: Array.isArray(notesOutput.bullets) ? notesOutput.bullets : [],
      },
    ];
  }

  const artifacts = toDictArray(data?.artifacts);
  let artifactIds = Array.isArray(data?.artifact_ids) ? data.artifact_ids : [];
  if (!artifactIds.length && artifacts.length) {
    artifactIds = artifacts.map((item) => item.artifact_id).filter(Boolean);
  }

  return { tasks, events, notes, artifactIds };
}

function animateArtifactReveal(listEl, baseDelay = 0) {
  const items = listEl.querySelectorAll(".artifact-item");
  items.forEach((item, index) => {
    item.classList.add("artifact-reveal");
    item.style.setProperty("--reveal-delay", `${baseDelay + index * 85}ms`);
  });
}

function firstOutputFocus(tasks, events, notes) {
  tasksColumn.classList.remove("artifact-focus");
  eventsColumn.classList.remove("artifact-focus");
  notesColumn.classList.remove("artifact-focus");

  if (tasks.length) {
    tasksColumn.classList.add("artifact-focus");
    return;
  }
  if (events.length) {
    eventsColumn.classList.add("artifact-focus");
    return;
  }
  if (notes.length) {
    notesColumn.classList.add("artifact-focus");
  }
}

function renderTasks(items = []) {
  taskCount.textContent = String(items.length);
  if (!items.length) {
    tasksList.innerHTML = '<div class="empty-artifact">No tasks generated yet.</div>';
    return;
  }

  tasksList.innerHTML = items
    .map((task) => {
      const title = task.title || task.task || "Untitled task";
      const description = task.description || task.summary || "Action extracted from orchestration.";
      const priority = task.priority || task.severity || "normal";
      const deadline = task.deadline || task.due_date || task.when || "";

      return `
      <article class="artifact-item">
        <div class="artifact-item-top">
          <h4>${escapeHtml(title)}</h4>
          <span class="artifact-badge">${escapeHtml(priority)}</span>
        </div>
        <p>${escapeHtml(description)}</p>
        ${deadline ? `<span class="artifact-meta">${escapeHtml(deadline)}</span>` : ""}
      </article>`;
    })
    .join("");

  animateArtifactReveal(tasksList, 0);
}

function renderEvents(items = []) {
  eventCount.textContent = String(items.length);
  if (!items.length) {
    eventsList.innerHTML = '<div class="empty-artifact">No calendar actions yet.</div>';
    return;
  }

  eventsList.innerHTML = items
    .map((eventItem) => {
      const title = eventItem.title || eventItem.name || "Untitled meeting";
      const description = eventItem.description || "Calendar block prepared by Schedule Agent.";
      const status = eventItem.status || "proposed";
      const start = eventItem.start || eventItem.start_time || eventItem.when || "Time pending";

      return `
      <article class="artifact-item">
        <div class="artifact-item-top">
          <h4>${escapeHtml(title)}</h4>
          <span class="artifact-badge">${escapeHtml(status)}</span>
        </div>
        <p>${escapeHtml(description)}</p>
        <span class="artifact-meta">${escapeHtml(start)}</span>
      </article>`;
    })
    .join("");

  animateArtifactReveal(eventsList, 80);
}

function renderNotes(items = []) {
  noteCount.textContent = String(items.length);
  if (!items.length) {
    notesList.innerHTML = '<div class="empty-artifact">No notes generated yet.</div>';
    return;
  }

  notesList.innerHTML = items
    .map((note) => {
      const title = note.title || "Workflow Brief";
      const body = note.summary || note.text || note.content || "Structured note generated from workflow context.";

      return `
      <article class="artifact-item">
        <div class="artifact-item-top">
          <h4>${escapeHtml(title)}</h4>
          <span class="artifact-badge">note</span>
        </div>
        <p>${escapeHtml(body)}</p>
      </article>`;
    })
    .join("");

  animateArtifactReveal(notesList, 160);
}

function renderSessionReplay(items = []) {
  if (!items.length) {
    sessionList.innerHTML = '<div class="empty-artifact">No replay items yet.</div>';
    return;
  }

  sessionList.innerHTML = items
    .map((item) => {
      const workflowId = item.workflow_id || "workflow";
      const status = item.status || "unknown";
      return `
      <button class="replay-item" type="button" data-workflow-id="${escapeHtml(workflowId)}">
        <strong>${escapeHtml(workflowId)}</strong>
        <span>${escapeHtml(status)}</span>
      </button>`;
    })
    .join("");
}

function updateHeadlineFromResults(tasks, events, notes) {
  const t = tasks.length;
  const e = events.length;
  const n = notes.length;

  if (t || e || n) {
    summaryHeadline.textContent = `Generated ${t} task${t === 1 ? "" : "s"}, ${e} meeting${e === 1 ? "" : "s"}, and ${n} note${n === 1 ? "" : "s"}`;
    summaryText.textContent = "Mission complete. Your output is ready, structured, and waiting for operator approval where needed.";
    outputTitle.textContent = "Workflow completed";
    return;
  }

  summaryHeadline.textContent = "Workflow finished with limited output";
  summaryText.textContent = "The system completed orchestration, but there were few structured artifacts to display.";
  outputTitle.textContent = "Workflow finished";
}

function scheduleBootSequence(plannedAgents = []) {
  const set = new Set(plannedAgents.filter(Boolean));
  const ordered = ["memory_agent", "research_agent", "notes_agent", "task_agent", "schedule_agent"];

  ordered.forEach((agentKey) => {
    const willRun = set.size === 0 || set.has(agentKey);
    setTimeout(() => {
      setAgentState(agentKey, willRun ? "booting" : "waiting", willRun ? "Waking up..." : "Standby");
    }, STAGGER_MS[agentKey]);
  });
}

async function runWorkflow() {
  const goal = promptInput.value.trim();
  if (!goal && files.length === 0) return;

  sendBtn.disabled = true;
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  isFinalizing = false;
  activeWorkflowId = null;
  activeSessionId = null;
  runStartedAt = performance.now();

  showOps();
  resetAgents();
  resetOutput();

  setAgentState("manager", "booting", "Parsing goal...");
  runState.textContent = "Submitting";
  outputTitle.textContent = "Launching mission";
  summaryHeadline.textContent = "Submitting request";
  summaryText.textContent = "Passing your goal to the manager agent.";

  const payload = {
    user_id: "web_user",
    goal,
    context: {
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
      notes: files.map((file) => file.name),
      channel: liveMode ? "web-ui-live" : "web-ui",
    },
  };

  try {
    const response = await fetch("/workflow/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error("workflow submit failed");
    }

    const data = await response.json();
    activeWorkflowId = data.workflow_id;
    activeSessionId = data.session_id || null;

    runState.textContent = "Accepted";
    outputTitle.textContent = "Mission in progress";
    summaryHeadline.textContent = "Manager accepted the mission";
    summaryText.textContent = `Workflow ${activeWorkflowId} is live. Specialists are coming online now.`;

    setAgentState("manager", "active", "Routing specialists...");
    openStream(activeWorkflowId);
  } catch (_error) {
    runState.textContent = "Error";
    summaryHeadline.textContent = "Launch failed";
    summaryText.textContent = "The workflow API did not accept the request.";
    setAgentState("manager", "idle", "Failed");
    sendBtn.disabled = false;
  }
}

function attachStreamHandler(eventName, callback) {
  eventSource.addEventListener(eventName, (evt) => {
    let payload = {};
    try {
      payload = JSON.parse(evt.data || "{}");
    } catch (_error) {
      payload = {};
    }
    callback(payload);
  });
}

function openStream(workflowId) {
  eventSource = new EventSource(`/workflow/${workflowId}/stream`);

  attachStreamHandler("run.accepted", () => {
    setAgentState("manager", "active", "Plan forming...");
    runState.textContent = "Accepted";
  });

  attachStreamHandler("run.classified", (payload) => {
    const plan = payload.plan || payload.planner || {};
    const plannedAgents = plan.agents || payload.agents || payload.selected_agents || [];

    setAgentState("manager", "done", "Plan locked");
    pulseMerge();
    runState.textContent = "Planning";
    summaryHeadline.textContent = "Manager built the execution plan";
    summaryText.textContent = payload.message || "Relevant specialists are being activated.";
    scheduleBootSequence(plannedAgents);
  });

  attachStreamHandler("agent.started", (payload) => {
    const agent = payload.agent || payload.agent_name;
    if (!agent) return;
    setAgentState(agent, "active", "Working...");
    runState.textContent = "Agents running";
  });

  attachStreamHandler("agent.completed", (payload) => {
    const agent = payload.agent || payload.agent_name;
    if (!agent) return;
    setAgentState(agent, "done", "Done");
    pulseMerge();
  });

  attachStreamHandler("tool.called", () => {
    runState.textContent = "Tool execution";
  });

  attachStreamHandler("tool.result", () => {
    runState.textContent = "Persisting output";
  });

  const finalizeHandler = async () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    await finalizeWorkflow();
  };

  attachStreamHandler("run.completed", finalizeHandler);
  attachStreamHandler("workflow.completed", finalizeHandler);

  eventSource.onerror = async () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    await finalizeWorkflow();
  };
}

async function finalizeWorkflow() {
  if (!activeWorkflowId || isFinalizing) return;
  isFinalizing = true;

  try {
    const response = await fetch(`/workflow/${activeWorkflowId}`);
    if (!response.ok) {
      throw new Error("workflow fetch failed");
    }

    const data = await response.json();
    console.log("FINAL WORKFLOW", data);

    const { tasks, events, notes, artifactIds } = normalizeWorkflowPayload(data);
    console.log("TASKS/EVENTS/NOTES", tasks, events, notes);

    renderTasks(tasks);
    renderEvents(events);
    renderNotes(notes);
    updateHeadlineFromResults(tasks, events, notes);
    updateArtifactCounters(artifactIds.length);
    firstOutputFocus(tasks, events, notes);

    firstArtifactId = artifactIds[0] || null;
    if (firstArtifactId) {
      approveBtn.disabled = false;
      approvalTitle.textContent = "Approval available";
      approvalText.textContent = "The first artifact is ready for operator confirmation.";
    }

    const latency = Math.round(performance.now() - runStartedAt);
    latencyValue.textContent = `${latency} ms`;
    runState.textContent = data.status || "Completed";
    outputTitle.textContent = "Mission output ready";

    document.querySelectorAll(".agent-card.booting").forEach((card) => {
      card.classList.remove("booting");
      card.classList.add("waiting");
      const status = card.querySelector(".status");
      if (status) {
        status.textContent = "Waiting";
      }
    });

    if (activeSessionId) {
      await loadSession(activeSessionId);
    }
  } catch (_error) {
    summaryHeadline.textContent = "Could not load output";
    summaryText.textContent = "The stream finished, but the final workflow payload did not load cleanly.";
  } finally {
    sendBtn.disabled = false;
    isFinalizing = false;
  }
}

async function loadSession(sessionId) {
  const response = await fetch(`/sessions/${sessionId}`);
  if (!response.ok) return;

  const data = await response.json();
  const items = data.workflows || data.history || data.items || [];
  renderSessionReplay(items);
}

promptInput.addEventListener("input", autoGrow);

fileInput.addEventListener("change", (event) => {
  files = [...files, ...Array.from(event.target.files || [])];
  renderFiles();
  fileInput.value = "";
});

sendBtn.addEventListener("click", runWorkflow);

promptInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    runWorkflow();
  }
});

approveBtn.addEventListener("click", async () => {
  if (!firstArtifactId) return;

  const response = await fetch(`/artifacts/${firstArtifactId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approved_by: "web_operator" }),
  });

  if (!response.ok) return;

  approvalTitle.textContent = "Artifact approved";
  approvalText.textContent = `${firstArtifactId} was approved successfully.`;
  approveBtn.disabled = true;
});

themeToggle.addEventListener("click", () => {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
});

liveBtn.addEventListener("click", () => {
  liveMode = !liveMode;
  liveBtn.classList.toggle("live-enabled", liveMode);
});

document.addEventListener("click", async (event) => {
  const replayButton = event.target.closest(".replay-item");
  if (!replayButton) return;

  const workflowId = replayButton.dataset.workflowId;
  if (!workflowId) return;

  activeWorkflowId = workflowId;
  await finalizeWorkflow();
});

autoGrow();