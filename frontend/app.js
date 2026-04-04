const promptInput = document.getElementById("promptInput");
const fileInput = document.getElementById("fileInput");
const filePills = document.getElementById("filePills");
const sendBtn = document.getElementById("sendBtn");
const hero = document.getElementById("hero");
const opsView = document.getElementById("opsView");
const themeToggle = document.getElementById("themeToggle");

const outputTitle = document.getElementById("outputTitle");
const runState = document.getElementById("runState");
const artifactCount = document.getElementById("artifactCount");
const footerArtifactCount = document.getElementById("footerArtifactCount");
const latencyValue = document.getElementById("latencyValue");

const summaryHeadline = document.getElementById("summaryHeadline");
const summaryText = document.getElementById("summaryText");
const riskCount = document.getElementById("riskCount");
const confidenceCount = document.getElementById("confidenceCount");
const similarCount = document.getElementById("similarCount");

const signalsList = document.getElementById("signalsList");
const osintList = document.getElementById("osintList");
const actionsList = document.getElementById("actionsList");
const approvalTitle = document.getElementById("approvalTitle");
const approvalText = document.getElementById("approvalText");
const copyComplaintBtn = document.getElementById("copyComplaintBtn");
const activeCount = document.getElementById("activeCount");
const mergeFlare = document.getElementById("mergeFlare");

let files = [];
let currentRunId = null;
let currentResultUrl = null;
let currentStream = null;
let complaintDraft = "";
let runStartedAt = 0;

const AGENTS = ["manager", "scam_detector", "audio_analyzer", "apk_analyzer", "osint", "golden_hour"];
const STAGGER = {
  manager: 0,
  scam_detector: 220,
  audio_analyzer: 420,
  apk_analyzer: 620,
  osint: 780,
  golden_hour: 940,
};

function escapeHtml(text) {
  return String(text || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function autoGrow() {
  promptInput.style.height = "auto";
  promptInput.style.height = `${Math.min(promptInput.scrollHeight, 220)}px`;
}

function showOpsView() {
  hero.classList.add("hero-leave");
  setTimeout(() => hero.classList.add("hidden"), 260);
  opsView.classList.remove("hidden");
}

function renderFiles() {
  filePills.innerHTML = files.map((file) => `<div class="file-pill">${escapeHtml(file.name)}</div>`).join("");
}

function setAgentState(agentKey, state, label = "") {
  const card = document.querySelector(`.agent-card[data-agent="${agentKey}"]`);
  if (!card) return;
  card.classList.remove("idle", "booting", "active", "done", "waiting");
  card.classList.add(state);
  const status = card.querySelector(".status");
  if (status) {
    status.textContent = label || state;
  }
  updateActiveCount();
}

function updateActiveCount() {
  const count = document.querySelectorAll(".agent-card.active, .agent-card.done").length;
  activeCount.textContent = `${count} / 6 active`;
}

function resetAgents() {
  AGENTS.forEach((agent) => setAgentState(agent, "idle", "Idle"));
}

function pulseMerge() {
  mergeFlare.classList.remove("merge-live");
  void mergeFlare.offsetWidth;
  mergeFlare.classList.add("merge-live");
}

function resetOutput() {
  outputTitle.textContent = "Awaiting investigation";
  runState.textContent = "Initializing";
  artifactCount.textContent = "0 signals";
  footerArtifactCount.textContent = "0";
  latencyValue.textContent = "0 ms";

  summaryHeadline.textContent = "No verdict yet";
  summaryText.textContent = "Submit content to generate a fraud investigation report.";
  riskCount.textContent = "-";
  confidenceCount.textContent = "-";
  similarCount.textContent = "0";

  signalsList.innerHTML = '<div class="empty-artifact">No signals yet.</div>';
  osintList.innerHTML = '<div class="empty-artifact">No OSINT findings yet.</div>';
  actionsList.innerHTML = '<div class="empty-artifact">No action plan yet.</div>';

  approvalTitle.textContent = "No complaint draft yet";
  approvalText.textContent = "Case draft will appear here after Golden Hour response.";
  copyComplaintBtn.disabled = true;
  complaintDraft = "";
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeReport(data) {
  const recommended = asArray(data.recommended_actions).map((item) => String(item));
  const signals = asArray(data.signals_found).map((item) => String(item));
  return {
    verdict: String(data.verdict || "Needs manual review"),
    summary: String(data.summary || "Analysis completed without a full summary."),
    risk: String(data.risk_level || "UNKNOWN"),
    confidence: Number(data.confidence || 0),
    similar: Number(data.similar_cases || 0),
    scamType: String(data.scam_type || "UNKNOWN"),
    signals,
    osint: data.osint && typeof data.osint === "object" ? data.osint : null,
    actions: recommended.length ? recommended : ["Call 1930 immediately", "File complaint at cybercrime.gov.in"],
    complaintDraft: String(data.complaint_draft?.body || ""),
    caseId: String(data.case_id || "UNKNOWN"),
  };
}

function renderSignals(items) {
  if (!items.length) {
    signalsList.innerHTML = '<div class="empty-artifact">No signals reported.</div>';
    return;
  }
  signalsList.innerHTML = items
    .map((signal) => `
      <article class="artifact-item artifact-reveal">
        <p>${escapeHtml(signal)}</p>
      </article>`)
    .join("");
}

function renderOsint(osint) {
  if (!osint) {
    osintList.innerHTML = '<div class="empty-artifact">No OSINT findings available.</div>';
    return;
  }

  const rows = [
    `Threat Score: ${escapeHtml(String(osint.overall_threat_score || 0))}`,
    `Summary: ${escapeHtml(String(osint.threat_summary || "No summary"))}`,
  ];

  osintList.innerHTML = rows
    .map((line) => `
      <article class="artifact-item artifact-reveal">
        <p>${line}</p>
      </article>`)
    .join("");
}

function renderActions(actions) {
  actionsList.innerHTML = actions
    .map((action) => `
      <article class="artifact-item artifact-reveal">
        <p>${escapeHtml(action)}</p>
      </article>`)
    .join("");
}

function renderReport(data) {
  const report = normalizeReport(data);

  outputTitle.textContent = `Case ${report.caseId}`;
  runState.textContent = "Completed";
  summaryHeadline.textContent = report.verdict;
  summaryText.textContent = `${report.summary} Scam type: ${report.scamType}.`;
  riskCount.textContent = report.risk;
  confidenceCount.textContent = `${report.confidence}%`;
  similarCount.textContent = String(report.similar);

  artifactCount.textContent = `${report.signals.length} signals`;
  footerArtifactCount.textContent = String(report.signals.length);

  renderSignals(report.signals);
  renderOsint(report.osint);
  renderActions(report.actions);

  if (report.complaintDraft) {
    complaintDraft = report.complaintDraft;
    approvalTitle.textContent = "Complaint draft ready";
    approvalText.textContent = report.complaintDraft.slice(0, 180);
    copyComplaintBtn.disabled = false;
  }
}

async function toFilePayload(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      resolve({
        file_name: file.name,
        file_type: file.type || "application/octet-stream",
        content_base64: String(reader.result || ""),
      });
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function pollResult(url, timeoutMs = 70000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const response = await fetch(url);
    if (response.ok) {
      const data = await response.json();
      if (data.status === "completed" || data.verdict) {
        return data;
      }
      if (data.status === "failed") {
        throw new Error(data.error || "Investigation failed");
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1400));
  }
  throw new Error("Timed out waiting for report");
}

function scheduleBoot(planned = []) {
  const planSet = new Set(asArray(planned));
  AGENTS.filter((agent) => agent !== "manager").forEach((agent) => {
    const shouldRun = !planSet.size || planSet.has(agent);
    setTimeout(() => {
      setAgentState(agent, shouldRun ? "booting" : "waiting", shouldRun ? "Waking up..." : "Standby");
    }, STAGGER[agent]);
  });
}

function openStream(streamUrl) {
  if (currentStream) {
    currentStream.close();
    currentStream = null;
  }
  currentStream = new EventSource(streamUrl);

  currentStream.addEventListener("run.accepted", () => {
    setAgentState("manager", "active", "Classifying input");
    runState.textContent = "Accepted";
  });

  currentStream.addEventListener("run.classified", (evt) => {
    let payload = {};
    try {
      payload = JSON.parse(evt.data || "{}");
    } catch (_error) {}

    setAgentState("manager", "done", "Plan locked");
    runState.textContent = "Planning";
    pulseMerge();
    scheduleBoot(payload.selected_agents || payload.agents || []);
  });

  currentStream.addEventListener("agent.started", (evt) => {
    try {
      const payload = JSON.parse(evt.data || "{}");
      const agent = payload.agent;
      if (agent) {
        setAgentState(agent, "active", "Running...");
      }
      runState.textContent = "Agents running";
    } catch (_error) {}
  });

  currentStream.addEventListener("agent.completed", (evt) => {
    try {
      const payload = JSON.parse(evt.data || "{}");
      const agent = payload.agent;
      if (agent) {
        setAgentState(agent, "done", "Done");
      }
      pulseMerge();
    } catch (_error) {}
  });

  currentStream.addEventListener("run.completed", () => {
    runState.textContent = "Finalizing report";
  });

  currentStream.onerror = () => {
    runState.textContent = "Stream interrupted; fetching final report";
    if (currentStream) {
      currentStream.close();
      currentStream = null;
    }
  };
}

async function runInvestigation() {
  const text = promptInput.value.trim();
  if (!text && !files.length) {
    return;
  }

  sendBtn.disabled = true;
  showOpsView();
  resetAgents();
  resetOutput();
  setAgentState("manager", "booting", "Preparing...");

  runStartedAt = performance.now();
  runState.textContent = "Submitting";
  outputTitle.textContent = "Launching investigation";

  try {
    const filePayloads = await Promise.all(files.map(toFilePayload));
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user_input: {
          text,
          files: filePayloads,
        },
        user_context: {
          channel: "ops-ui",
        },
        options: {
          stream: true,
          generate_report: true,
          trigger_mcp_actions: false,
        },
      }),
    });

    if (!response.ok) {
      throw new Error("Submission failed");
    }

    const accepted = await response.json();
    currentRunId = accepted.run_id;
    currentResultUrl = accepted.result_url;
    openStream(accepted.stream_url);

    const result = await pollResult(accepted.result_url);
    renderReport(result);

    const latency = Math.round(performance.now() - runStartedAt);
    latencyValue.textContent = `${latency} ms`;
  } catch (error) {
    runState.textContent = "Error";
    summaryHeadline.textContent = "Investigation failed";
    summaryText.textContent = `Could not complete this run: ${error.message || "unknown error"}`;
  } finally {
    sendBtn.disabled = false;
    if (currentStream) {
      currentStream.close();
      currentStream = null;
    }
  }
}

promptInput.addEventListener("input", autoGrow);

fileInput.addEventListener("change", (event) => {
  files = [...files, ...Array.from(event.target.files || [])];
  renderFiles();
  fileInput.value = "";
});

sendBtn.addEventListener("click", runInvestigation);

promptInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    runInvestigation();
  }
});

copyComplaintBtn.addEventListener("click", async () => {
  if (!complaintDraft) return;
  try {
    await navigator.clipboard.writeText(complaintDraft);
    approvalTitle.textContent = "Complaint draft copied";
  } catch (_error) {
    approvalTitle.textContent = "Copy failed";
  }
});

themeToggle.addEventListener("click", () => {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
});

autoGrow();