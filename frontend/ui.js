const inputText = document.getElementById("inputText");
const inputFile = document.getElementById("inputFile");
const fileName = document.getElementById("fileName");
const submitBtn = document.getElementById("submitBtn");
const statusText = document.getElementById("statusText");

const reportRoot = document.getElementById("reportRoot");
const answerCard = document.getElementById("answerCard");
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

let eventSource = null;

const DEFAULT_ACTIONS = [
  "Do not click suspicious links",
  "Do not share OTP or PIN",
  "Call 1930 immediately",
  "File complaint at cybercrime.gov.in",
];

inputFile.addEventListener("change", () => {
  const file = inputFile.files && inputFile.files[0];
  fileName.textContent = file ? `${file.name} (${Math.round(file.size / 1024)} KB)` : "No file selected";
});

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

function normalizeReport(data) {
  const risk = String(data.risk_level || "UNKNOWN").toUpperCase();
  const confidence = Number(data.confidence || 0);
  const summary = String(data.summary || "Analysis complete. Please review recommended actions.");
  const verdict = String(data.verdict || (confidence >= 60 ? "Likely scam" : "Needs manual review"));
  const recommended = Array.isArray(data.recommended_actions) && data.recommended_actions.length
    ? data.recommended_actions.map((v) => String(v))
    : DEFAULT_ACTIONS;

  return {
    case_id: String(data.case_id || data.run_id || "UNKNOWN"),
    verdict,
    summary,
    scam_type: String(data.scam_type || "UNKNOWN"),
    confidence,
    risk_level: risk,
    golden_hour_status: String(data.golden_hour_status || "STANDBY"),
    golden_hour_message: String(data.golden_hour_message || "Take immediate action if you suspect fraud."),
    signals_found: Array.isArray(data.signals_found) ? data.signals_found.map((v) => String(v)) : [],
    similar_cases: Number(data.similar_cases || 0),
    recommended_actions: recommended,
    osint: data.osint && typeof data.osint === "object" ? data.osint : null,
    audio_analysis: data.audio_analysis && typeof data.audio_analysis === "object" ? data.audio_analysis : null,
    apk_analysis: data.apk_analysis && typeof data.apk_analysis === "object" ? data.apk_analysis : null,
    complaint_draft: data.complaint_draft && typeof data.complaint_draft === "object" ? data.complaint_draft : null,
    evidence_summary: Array.isArray(data.evidence_summary) ? data.evidence_summary.map((v) => String(v)) : [],
  };
}

function renderReport(rawData) {
  const report = normalizeReport(rawData);

  reportRoot.classList.remove("hidden");
  verdictText.textContent = report.verdict;
  summaryText.textContent = report.summary;
  riskText.textContent = report.risk_level;
  confidenceText.textContent = `${report.confidence}%`;
  scamTypeText.textContent = report.scam_type;

  answerCard.classList.remove("risk-critical", "risk-high", "risk-medium", "risk-low", "risk-unknown");
  answerCard.classList.add(`risk-${report.risk_level.toLowerCase()}`);

  goldenHourText.textContent = `${report.golden_hour_status}: ${report.golden_hour_message}`;
  actionsList.innerHTML = listHtml(report.recommended_actions);

  const signals = report.signals_found.length ? report.signals_found : report.evidence_summary;
  signalsList.innerHTML = signals.length ? listHtml(signals) : "<li>No strong indicator list available.</li>";
  similarCasesText.textContent = `Similar known cases: ${report.similar_cases}`;

  osintBlock.textContent = report.osint ? JSON.stringify(report.osint, null, 2) : "No OSINT findings available.";

  const modality = report.audio_analysis || report.apk_analysis;
  modalityBlock.textContent = modality ? JSON.stringify(modality, null, 2) : "No modality-specific findings.";

  const complaintBody = report.complaint_draft?.body || "Complaint draft unavailable. Use case details to file on cybercrime.gov.in.";
  complaintText.textContent = complaintBody;
  caseIdText.textContent = `Case ID: ${report.case_id}`;
}

async function pollResult(resultUrl, timeoutMs = 70000) {
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
    statusText.textContent = "Accepted. Manager is preparing fraud analysis.";
  });

  eventSource.addEventListener("run.classified", (evt) => {
    try {
      const data = JSON.parse(evt.data || "{}");
      const agents = Array.isArray(data.selected_agents) ? data.selected_agents : [];
      if (agents.length) {
        statusText.textContent = `Running agents: ${agents.join(", ")}`;
      }
    } catch (_error) {
      statusText.textContent = "Workflow classified. Running fraud agents.";
    }
  });

  eventSource.addEventListener("run.completed", () => {
    statusText.textContent = "Analysis complete. Building investigation report.";
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
  const file = inputFile.files && inputFile.files[0];

  if (!text && !file) {
    statusText.textContent = "Please paste suspicious text or upload at least one file.";
    return;
  }

  submitBtn.disabled = true;
  statusText.textContent = "Uploading evidence and starting analysis...";

  try {
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
      user_input: {
        text,
        files,
      },
      user_context: {
        channel: "citizen-ui",
      },
      options: {
        stream: true,
        generate_report: true,
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
