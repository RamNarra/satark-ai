const inputText = document.getElementById("inputText");
const inputFile = document.getElementById("inputFile");
const fileName = document.getElementById("fileName");
const submitBtn = document.getElementById("submitBtn");
const statusText = document.getElementById("statusText");
const dropzone = document.getElementById("dropzone");

const reportRoot = document.getElementById("reportRoot");
const answerCard = document.getElementById("answerCard");
const riskBadge = document.getElementById("riskBadge");
const timelineList = document.getElementById("timelineList");
const verdictText = document.getElementById("verdictText");
const summaryText = document.getElementById("summaryText");
const riskText = document.getElementById("riskText");
const confidenceText = document.getElementById("confidenceText");
const scamTypeText = document.getElementById("scamTypeText");
const actionsList = document.getElementById("actionsList");
const signalsList = document.getElementById("signalsList");
const similarCasesText = document.getElementById("similarCasesText");
const goldenHourText = document.getElementById("goldenHourText");
const osintBlock = document.getElementById("osintBlock");
const modalityBlock = document.getElementById("modalityBlock");
const complaintText = document.getElementById("complaintText");
const caseIdText = document.getElementById("caseIdText");
const googleAuthLink = document.getElementById("googleAuthLink");
const googleAuthBtn = document.getElementById("google-auth-btn");

const stepper = document.getElementById("stepper");
const goldenHourProof = document.getElementById("goldenHourProof");
const calendarProofPill = document.getElementById("calendarProofPill");
const calendarProofMeta = document.getElementById("calendarProofMeta");

const chipManager = document.getElementById("chip-manager");
const chipScam = document.getElementById("chip-scam");
const chipOsint = document.getElementById("chip-osint");
const chipModality = document.getElementById("chip-modality");
const chipGolden = document.getElementById("chip-golden");

let eventSource = null;
let runTimeline = [];
let selectedFile = null;
let googleConnected = false;

const SESSION_STORAGE_KEY = "satark_session_id";

function getOrCreateSessionId() {
  const existing = localStorage.getItem(SESSION_STORAGE_KEY);
  if (existing && existing.length >= 6) {
    return existing;
  }

  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const created = `sess_${hex}`;
  localStorage.setItem(SESSION_STORAGE_KEY, created);
  return created;
}

const sessionId = getOrCreateSessionId();

if (googleAuthLink) {
  googleAuthLink.href = `/auth/google/start?session_id=${encodeURIComponent(sessionId)}&next=${encodeURIComponent("/ui")}`;
}

async function checkAuthStatus() {
  if (!googleAuthBtn) return;
  try {
    const res = await fetch("/api/auth/status", { credentials: "same-origin" });
    if (!res.ok) return;
    const data = await res.json();
    const connected = Boolean(data && data.connected);
    if (!connected) return;

    googleConnected = true;

    const email = data && data.email ? String(data.email) : "";
    const label = email ? `✓ ${escapeHtml(email)}` : "✓ Google connected";

    googleAuthBtn.classList.add("connected");
    googleAuthBtn.innerHTML = `
      <span class="auth-email">${label}</span>
      <a href="/auth/google/logout" class="auth-logout">Sign out</a>
    `;
  } catch (_err) {
    // Silent fail.
  }
}

function setStep(stepNumber) {
  if (!stepper) return;
  const steps = stepper.querySelectorAll(".stepper-step");
  steps.forEach((el) => {
    const step = Number(el.getAttribute("data-step") || 0);
    el.classList.toggle("is-active", step === stepNumber);
    el.classList.toggle("is-done", step > 0 && step < stepNumber);
  });
}

setStep(1);

try {
  const params = new URLSearchParams(window.location.search || "");
  if (params.get("google") === "connected") {
    statusText.textContent = "Google connected. Now run an analysis to create the Calendar reminder.";
  }
} catch (_err) {
  // Ignore URL parsing issues.
}

document.addEventListener("DOMContentLoaded", checkAuthStatus);

const DEFAULT_ACTIONS = [
  "Do not click suspicious links",
  "Do not share OTP or PIN",
  "Call 1930 immediately",
  "File complaint at cybercrime.gov.in",
];

inputFile.addEventListener("change", () => {
  const file = inputFile.files && inputFile.files[0];
  selectedFile = file || null;
  fileName.textContent = selectedFile ? `${selectedFile.name} (${Math.round(selectedFile.size / 1024)} KB)` : "No file selected";
});

function openFilePicker() {
  if (inputFile) {
    inputFile.click();
  }
}

if (dropzone) {
  dropzone.addEventListener("click", openFilePicker);
  dropzone.addEventListener("keydown", (evt) => {
    if (evt.key === "Enter" || evt.key === " ") {
      evt.preventDefault();
      openFilePicker();
    }
  });

  dropzone.addEventListener("dragover", (evt) => {
    evt.preventDefault();
    dropzone.classList.add("is-dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("is-dragover");
  });

  dropzone.addEventListener("drop", (evt) => {
    evt.preventDefault();
    dropzone.classList.remove("is-dragover");
    const file = evt.dataTransfer && evt.dataTransfer.files && evt.dataTransfer.files[0];
    if (!file) return;

    selectedFile = file;

    try {
      const dt = new DataTransfer();
      dt.items.add(file);
      inputFile.files = dt.files;
      fileName.textContent = `${file.name} (${Math.round(file.size / 1024)} KB)`;
    } catch (_err) {
      // Fallback: if DataTransfer isn't writable, user can use picker.
      fileName.textContent = `${file.name} (${Math.round(file.size / 1024)} KB)`;
    }
  });
}

submitBtn.addEventListener("click", runAnalysis);

function toDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function listHtml(items) {
  return items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function escapeHtml(text) {
  return String(text || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function clampInt(value, min, max) {
  const num = Number(value);
  if (!Number.isFinite(num)) return null;
  return Math.max(min, Math.min(max, Math.round(num)));
}

function dedupeStrings(items) {
  const seen = new Set();
  const out = [];
  for (const raw of Array.isArray(items) ? items : []) {
    const s = String(raw || "").trim();
    if (!s) continue;
    const k = s.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

function normalizeRiskLevel(value) {
  const raw = String(value || "UNKNOWN").toUpperCase();
  if (raw === "SAFE") return "LOW";
  if (["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(raw)) return raw;
  return "UNKNOWN";
}

function osintHasIntel(osint) {
  if (!osint || typeof osint !== "object") return false;
  const score = Number(osint.overall_threat_score || 0);
  if (Number.isFinite(score) && score > 0) return true;
  const buckets = [osint.domains, osint.ips, osint.urls];
  return buckets.some((b) => b && typeof b === "object" && Object.keys(b).length > 0);
}

function formatOsint(osint) {
  if (!osintHasIntel(osint)) return null;
  const lines = [];
  const summary = String(osint.threat_summary || "").trim();
  if (summary) lines.push(summary);
  const score = Number(osint.overall_threat_score || 0);
  if (Number.isFinite(score) && score > 0) lines.push(`Threat score: ${Math.round(score)}`);

  const addBucket = (label, obj) => {
    if (!obj || typeof obj !== "object") return;
    const keys = Object.keys(obj);
    if (!keys.length) return;
    lines.push(`${label}: ${keys.slice(0, 6).join(", ")}${keys.length > 6 ? "…" : ""}`);
  };
  addBucket("Domains", osint.domains);
  addBucket("IPs", osint.ips);
  addBucket("URLs", osint.urls);
  return lines.join("\n");
}

function formatModality(audioAnalysis, apkAnalysis, riskLevel) {
  const lines = [];
  if (apkAnalysis && typeof apkAnalysis === "object") {
    const isMal = apkAnalysis.is_malicious === true;
    if (isMal) lines.push("APK flagged: malicious indicators present");
    const summary = String(apkAnalysis.summary || "").trim();
    if (summary) lines.push(summary);
  }
  if (audioAnalysis && typeof audioAnalysis === "object") {
    const summary = String(audioAnalysis.summary || "").trim();
    if (summary) lines.push(summary);
  }
  if (!lines.length) return null;
  const risk = normalizeRiskLevel(riskLevel);
  return risk !== "UNKNOWN" ? `${lines.join("\n")}\n\nOverall risk: ${risk}` : lines.join("\n");
}

function normalizeReport(data) {
  const raw = data && typeof data === "object" ? data : {};
  const apkAnalysis = raw.apk_analysis && typeof raw.apk_analysis === "object" ? raw.apk_analysis : null;
  const audioAnalysis = raw.audio_analysis && typeof raw.audio_analysis === "object" ? raw.audio_analysis : null;
  const apkMalicious = apkAnalysis ? apkAnalysis.is_malicious === true : false;

  const followUp = raw.follow_up_actions && typeof raw.follow_up_actions === "object" ? raw.follow_up_actions : {};
  const calendarFromRaw = raw.calendar_event && typeof raw.calendar_event === "object" ? raw.calendar_event : {};
  const calendar_event_created = followUp.calendar_event_created === true || calendarFromRaw.created === true;
  const calendar_attempted = followUp.calendar_attempted === true || calendarFromRaw.attempted === true;
  const calendar_event_id = String(followUp.calendar_event_id || calendarFromRaw.event_id || "").trim() || null;
  const calendar_start_time = String(followUp.calendar_start_time || calendarFromRaw.start_time || "").trim() || null;
  const calendar_error = String(followUp.calendar_error || calendarFromRaw.error || "").trim() || null;

  const risk = normalizeRiskLevel(raw.risk_level);
  const riskLevel = apkMalicious ? "CRITICAL" : risk;

  const confidence = clampInt(raw.confidence, 0, 100);

  let headline = "Needs review";
  if (apkMalicious || riskLevel === "CRITICAL" || riskLevel === "HIGH") headline = apkMalicious ? "Likely malicious" : "Likely scam";
  else if (riskLevel === "LOW") headline = "Likely safe";
  else if (riskLevel === "MEDIUM") headline = "Potential scam";

  const summary = String(raw.summary || "").trim() || "Analysis complete. Please review recommended actions.";

  const recommended = dedupeStrings(raw.recommended_actions);
  const actions = recommended.length ? recommended : DEFAULT_ACTIONS;

  return {
    case_id: String(raw.case_id || raw.run_id || "UNKNOWN"),
    verdict: headline,
    summary,
    scam_type: String(raw.scam_type || "UNKNOWN"),
    confidence,
    risk_level: riskLevel,
    golden_hour_status: String(raw.golden_hour_status || "STANDBY"),
    golden_hour_message: String(raw.golden_hour_message || "Take immediate action if you suspect fraud."),
    signals_found: dedupeStrings(raw.signals_found),
    similar_cases: Number(raw.similar_cases || 0),
    recommended_actions: actions,
    osint: raw.osint && typeof raw.osint === "object" ? raw.osint : null,
    osint_text: formatOsint(raw.osint),
    audio_analysis: audioAnalysis,
    apk_analysis: apkAnalysis,
    modality_text: formatModality(audioAnalysis, apkAnalysis, riskLevel),
    complaint_draft: raw.complaint_draft && typeof raw.complaint_draft === "object" ? raw.complaint_draft : null,
    evidence_summary: dedupeStrings(raw.evidence_summary),
    follow_up_actions: followUp,
    calendar_event: {
      created: calendar_event_created,
      attempted: calendar_attempted,
      event_id: calendar_event_id,
      start_time: calendar_start_time,
      error: calendar_error,
    },
  };
}

function setBadge(riskLevel) {
  if (!riskBadge) return;
  const risk = normalizeRiskLevel(riskLevel);
  riskBadge.textContent = risk;
  riskBadge.classList.remove("badge-danger", "badge-ok", "badge-accent");
  if (risk === "CRITICAL" || risk === "HIGH") {
    riskBadge.classList.add("badge-danger");
  } else if (risk === "LOW") {
    riskBadge.classList.add("badge-ok");
  } else if (risk === "MEDIUM") {
    riskBadge.classList.add("badge-accent");
  }
}

function resetTimeline() {
  runTimeline = [];
  if (timelineList) timelineList.innerHTML = "";
}

function addTimeline(item) {
  runTimeline.push(String(item || ""));
  if (!timelineList) return;
  timelineList.innerHTML = runTimeline.map((t) => `<li>${escapeHtml(t)}</li>`).join("");
}

function setAnalysisRunning(isRunning) {
  if (!reportRoot) return;
  reportRoot.classList.toggle("is-running", Boolean(isRunning));
}

function chipStateEl(chipEl) {
  if (!chipEl) return null;
  return chipEl.querySelector(".agent-chip__state");
}

function setChip(chipEl, state, label) {
  if (!chipEl) return;
  chipEl.dataset.state = state;
  const stateEl = chipStateEl(chipEl);
  if (stateEl) stateEl.textContent = label || state;
}

function agentToChipKey(agentName) {
  const agent = String(agentName || "");
  if (agent === "manager") return "manager";
  if (agent === "scam_detector") return "scam";
  if (agent === "osint") return "osint";
  if (agent === "golden_hour") return "golden";
  if (agent === "audio_analyzer" || agent === "apk_analyzer") return "modality";
  return null;
}

function getChipByKey(key) {
  if (key === "manager") return chipManager;
  if (key === "scam") return chipScam;
  if (key === "osint") return chipOsint;
  if (key === "modality") return chipModality;
  if (key === "golden") return chipGolden;
  return null;
}

function bootChips() {
  setChip(chipManager, "queued", "Queued");
  setChip(chipScam, "queued", "Queued");
  setChip(chipOsint, "queued", "Queued");
  setChip(chipModality, "queued", "Queued");
  setChip(chipGolden, "queued", "Queued");
}

function applySelectedAgents(selectedAgents) {
  const selected = new Set((Array.isArray(selectedAgents) ? selectedAgents : []).map((v) => String(v)));

  const hasAudio = selected.has("audio_analyzer");
  const hasApk = selected.has("apk_analyzer");
  if (chipModality) {
    const label = hasAudio ? "Audio" : hasApk ? "APK" : "APK / Audio";
    const nameEl = chipModality.querySelector(".agent-chip__name");
    if (nameEl) nameEl.textContent = label;
  }

  const expected = {
    manager: true,
    scam_detector: selected.has("scam_detector"),
    osint: selected.has("osint"),
    golden_hour: selected.has("golden_hour"),
    modality: hasAudio || hasApk,
  };

  setChip(chipScam, expected.scam_detector ? "queued" : "skipped", expected.scam_detector ? "Queued" : "Skipped");
  setChip(chipOsint, expected.osint ? "queued" : "skipped", expected.osint ? "Queued" : "Skipped");
  setChip(chipGolden, expected.golden_hour ? "queued" : "skipped", expected.golden_hour ? "Queued" : "Skipped");
  setChip(chipModality, expected.modality ? "queued" : "skipped", expected.modality ? "Queued" : "Skipped");
}

function markAgentStarted(agentName) {
  const key = agentToChipKey(agentName);
  const chip = key ? getChipByKey(key) : null;
  if (!chip) return;
  setChip(chip, "analyzing", "Analyzing");
}

function markAgentCompleted(agentName) {
  const key = agentToChipKey(agentName);
  const chip = key ? getChipByKey(key) : null;
  if (!chip) return;
  setChip(chip, "verified", "Verified");
  window.setTimeout(() => {
    if (chip.dataset.state === "verified") {
      setChip(chip, "done", "Done");
    }
  }, 420);
}

function renderReport(rawData) {
  const report = normalizeReport(rawData);

  reportRoot.classList.remove("hidden");
  verdictText.textContent = report.verdict;
  summaryText.textContent = report.summary;
  riskText.textContent = report.risk_level;
  setBadge(report.risk_level);
  confidenceText.textContent = report.confidence === null ? "—" : `${report.confidence}%`;
  scamTypeText.textContent = report.scam_type;

  answerCard.classList.remove("risk-critical", "risk-high", "risk-medium", "risk-low", "risk-unknown");
  answerCard.classList.add(`risk-${normalizeRiskLevel(report.risk_level).toLowerCase()}`);

  goldenHourText.textContent = `${report.golden_hour_status}: ${report.golden_hour_message}`;

  if (goldenHourProof && calendarProofPill && calendarProofMeta) {
    const cal = report.calendar_event || {};
    const shouldShow = Boolean(cal.attempted || cal.created || cal.event_id || cal.error || report.golden_hour_status === "ACTIVE");
    goldenHourProof.hidden = !shouldShow;

    calendarProofPill.classList.remove("is-ok", "is-bad");
    calendarProofPill.textContent = cal.created ? "CREATED" : cal.attempted && cal.error ? "FAILED" : googleConnected ? "PENDING" : "CONNECT";
    if (cal.created) calendarProofPill.classList.add("is-ok");
    else if (cal.attempted && cal.error) calendarProofPill.classList.add("is-bad");

    const meta = [];
    if (cal.start_time) meta.push(`start: ${cal.start_time}`);
    if (cal.event_id) meta.push(`event_id: ${cal.event_id}`);
    if (cal.error) meta.push(`error: ${cal.error}`);
    if (!meta.length && !googleConnected) meta.push("Sign in with Google to create a Calendar reminder.");
    if (!meta.length && googleConnected) meta.push("Calendar reminder not created for this run.");
    calendarProofMeta.textContent = meta.join("\n");
  }

  actionsList.innerHTML = listHtml(report.recommended_actions);

  const signals = report.signals_found.length ? report.signals_found : report.evidence_summary;
  signalsList.innerHTML = signals.length ? listHtml(signals) : "<li>No strong indicator list available.</li>";
  similarCasesText.textContent = report.similar_cases ? `Similar known cases: ${report.similar_cases}` : "";

  if (osintBlock) {
    const details = osintBlock.closest("details");
    const text = report.osint_text;
    osintBlock.textContent = text || "No network indicators extracted.";
    if (details) details.style.display = text ? "" : "none";
  }

  if (modalityBlock) {
    const details = modalityBlock.closest("details");
    const text = report.modality_text;
    modalityBlock.textContent = text || "No modality-specific findings.";
    if (details) details.style.display = text ? "" : "none";
  }

  const complaintBody = report.complaint_draft?.body || "Complaint draft unavailable. Use case details to file on cybercrime.gov.in.";
  complaintText.textContent = complaintBody;
  caseIdText.textContent = `Case ID: ${report.case_id}`;

  answerCard.classList.add("is-ready");
  setAnalysisRunning(false);
  setStep(3);
}

async function pollResult(resultUrl, timeoutMs = 120000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const response = await fetch(resultUrl);
    if (response.ok) {
      const data = await response.json();
      if (data.status === "completed" || data.verdict || data.summary) {
        return data;
      }
      if (data.status === "failed") {
        throw new Error(data.error || "Analysis failed");
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1400));
  }
  throw new Error("Timed out waiting for final report");
}

function wireStream(streamUrl) {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  eventSource = new EventSource(streamUrl);
  eventSource.addEventListener("run.accepted", () => {
    reportRoot.classList.remove("hidden");
    answerCard.classList.remove("is-ready");
    resetTimeline();
    addTimeline("Evidence received");
    addTimeline("Booting agents");
    bootChips();
    setAnalysisRunning(true);
    setStep(2);
    statusText.textContent = "Starting investigation…";
  });

  eventSource.addEventListener("run.classified", (evt) => {
    try {
      const data = JSON.parse(evt.data || "{}");
      const agents = Array.isArray(data.selected_agents) ? data.selected_agents : [];
      if (agents.length) {
        applySelectedAgents(agents);
        addTimeline("Agents queued");
        statusText.textContent = "Analyzing with specialist agents…";
      }
    } catch (_error) {
      statusText.textContent = "Workflow classified. Running fraud agents…";
    }
  });

  eventSource.addEventListener("agent.started", (evt) => {
    try {
      const data = JSON.parse(evt.data || "{}");
      const agent = String(data.agent || "");
      markAgentStarted(agent);
      if (agent) addTimeline(`${agent.replaceAll("_", " ")} started`);
    } catch (_err) {
      // ignore
    }
  });

  eventSource.addEventListener("agent.completed", (evt) => {
    try {
      const data = JSON.parse(evt.data || "{}");
      const agent = String(data.agent || "");
      markAgentCompleted(agent);
      if (agent) addTimeline(`${agent.replaceAll("_", " ")} completed`);
    } catch (_err) {
      // ignore
    }
  });

  eventSource.addEventListener("run.completed", () => {
    addTimeline("Report assembling");
    statusText.textContent = "Finalizing report…";
  });

  eventSource.onerror = () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    statusText.textContent = "Stream interrupted. Fetching final report...";
  };
}

async function runAnalysis() {
  const text = inputText.value.trim();
  const file = selectedFile;

  if (!text && !file) {
    statusText.textContent = "Please paste suspicious text or upload at least one file.";
    return;
  }

  submitBtn.disabled = true;
  statusText.textContent = "Uploading evidence and starting analysis…";
  reportRoot.classList.remove("hidden");
  answerCard.classList.remove("is-ready");
  setAnalysisRunning(true);
  resetTimeline();
  addTimeline("Preparing upload");
  bootChips();

  try {
    setStep(2);
    const files = [];
    if (file) {
      const dataUrl = await toDataUrl(file);
      files.push({
        file_name: file.name,
        file_type: file.type || "application/octet-stream",
        content_base64: dataUrl,
      });
    }

    const payload = {
      session_id: sessionId,
      user_id: "demo_user",
      user_input: {
        text,
        files,
      },
      user_context: {
        channel: "citizen-ui",
      },
      options: {
        stream: true,
        generate_report: false,
        deep_analysis: false,
        fast_first: true,
        trigger_mcp_actions: false,
      },
    };

    const runResponse = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!runResponse.ok) {
      throw new Error("Could not submit fraud analysis request");
    }

    const accepted = await runResponse.json();
    wireStream(accepted.stream_url);

    const result = await pollResult(accepted.result_url);
    renderReport(result);
    statusText.textContent = "Investigation report is ready.";
  } catch (error) {
    statusText.textContent = `Could not complete analysis: ${error.message || "unknown error"}`;

    setAnalysisRunning(false);

    renderReport({
      verdict: "Needs manual review",
      summary: "We could not complete full automated analysis, but you should still take immediate protective actions.",
      risk_level: "HIGH",
      confidence: 50,
      recommended_actions: DEFAULT_ACTIONS,
      scam_type: "UNKNOWN",
      case_id: "UNAVAILABLE",
    });
  } finally {
    submitBtn.disabled = false;
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  }
}
