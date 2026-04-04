const promptInput = document.getElementById("promptInput");
const fileInput = document.getElementById("fileInput");
const filePills = document.getElementById("filePills");
const sendBtn = document.getElementById("sendBtn");
const liveBtn = document.getElementById("liveBtn");
const hero = document.getElementById("hero");
const composer = document.getElementById("composer");
const opsView = document.getElementById("opsView");
const feed = document.getElementById("feed");
const activeCount = document.getElementById("activeCount");
const runState = document.getElementById("runState");
const themeToggle = document.getElementById("themeToggle");
const tickerUpload = document.getElementById("tickerUpload");
const tickerLatency = document.getElementById("tickerLatency");
const tickerEvidence = document.getElementById("tickerEvidence");

const backendToUiAgent = {
  manager: "manager",
  scam: "scam",
  scam_detector: "scam",
  audio: "audio",
  audio_analyzer: "audio",
  apk: "apk",
  apk_analyzer: "apk",
  osint: "osint",
  golden: "golden",
  golden_hour: "golden",
};

let files = [];
let liveMode = false;
let requestStart = 0;
let activeStream = null;

function autoGrow() {
  promptInput.style.height = "auto";
  promptInput.style.height = `${Math.min(promptInput.scrollHeight, 220)}px`;
}

promptInput.addEventListener("input", autoGrow);

function appendFiles(newFiles) {
  files = [...files, ...newFiles];
  renderFiles();
}

fileInput.addEventListener("change", (e) => {
  appendFiles(Array.from(e.target.files || []));
  fileInput.value = "";
});

function renderFiles() {
  filePills.innerHTML = files
    .map(
      (f, i) =>
        `<div class="file-pill" title="${escapeHtml(f.name)}">${escapeHtml(f.name)} <button data-remove="${i}" aria-label="Remove file">x</button></div>`
    )
    .join("");

  filePills.querySelectorAll("button[data-remove]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.getAttribute("data-remove"));
      files.splice(idx, 1);
      renderFiles();
      updateTicker();
    });
  });

  updateTicker();
}

function appendFeed(title, text) {
  const item = document.createElement("div");
  item.className = "feed-item";
  item.innerHTML = `<strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p>`;
  feed.prepend(item);
}

function resetAgentCards() {
  document.querySelectorAll(".agent-card").forEach((card) => {
    card.classList.remove("booting", "active", "done");
    const status = card.querySelector(".status");
    if (status) {
      status.textContent = "Idle";
    }
  });
  updateActiveCount();
}

function setAgentState(key, state, statusText) {
  const card = document.querySelector(`.agent-card[data-agent="${key}"]`);
  if (!card) {
    return;
  }
  card.classList.remove("booting", "active", "done");
  card.classList.add(state);
  const status = card.querySelector(".status");
  if (status) {
    status.textContent = statusText;
  }
  updateActiveCount();
}

function updateActiveCount() {
  const count = document.querySelectorAll(".agent-card.active, .agent-card.done").length;
  activeCount.textContent = `${count} / 6 active`;
}

function updateTicker() {
  const hasAudio = files.some((f) => /\.(mp3|wav|m4a|ogg)$/i.test(f.name));
  const hasApk = files.some((f) => /\.apk$/i.test(f.name));
  let inputType = "text";

  if (hasAudio && hasApk) {
    inputType = "audio + apk";
  } else if (hasAudio) {
    inputType = "audio";
  } else if (hasApk) {
    inputType = "apk";
  } else if (files.length > 0) {
    inputType = "image/file";
  }

  tickerUpload.textContent = `Input: ${inputType}`;
  tickerEvidence.textContent = `Evidence: ${files.length}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function armUi() {
  hero.classList.add("arming");
  runState.textContent = "Arming interface";
}

function normalizeAgentName(agent) {
  return backendToUiAgent[agent] || agent;
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      if (result.includes(",")) {
        resolve(result.split(",", 2)[1]);
        return;
      }
      resolve(result);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function buildAnalyzePayload() {
  const MAX_INLINE_BYTES = 8 * 1024 * 1024;
  const convertedFiles = [];

  for (const file of files) {
    let content_base64 = null;
    if (file.size <= MAX_INLINE_BYTES) {
      content_base64 = await readFileAsBase64(file);
    } else {
      appendFeed("Attachment", `${file.name} is larger than 8MB. Sending metadata only.`);
    }

    convertedFiles.push({
      file_name: file.name,
      file_type: file.type || null,
      file_url: null,
      content_base64,
    });
  }

  return {
    session_id: (window.crypto && window.crypto.randomUUID && window.crypto.randomUUID()) || null,
    user_input: {
      text: promptInput.value.trim(),
      language_hint: "en",
      files: convertedFiles,
    },
    user_context: {
      location: "unknown",
      channel: "web-ui",
    },
    options: {
      stream: true,
      generate_report: true,
      trigger_mcp_actions: false,
    },
  };
}

function setupOpsScreen() {
  hero.classList.add("hidden");
  opsView.classList.remove("hidden");
  feed.innerHTML = "";
  resetAgentCards();
}

function bindStream(streamUrl, resultUrl) {
  if (activeStream) {
    activeStream.close();
  }

  const stream = new EventSource(streamUrl);
  activeStream = stream;

  const on = (name, handler) => {
    stream.addEventListener(name, (evt) => {
      try {
        const data = JSON.parse(evt.data);
        handler(data);
      } catch (e) {
        appendFeed("Stream", `Could not parse ${name} event`);
      }
    });
  };

  on("run.accepted", (data) => {
    runState.textContent = "Run accepted";
    appendFeed("Run accepted", `Case ${data.case_id || "pending"} accepted by manager.`);
  });

  on("run.classified", (data) => {
    runState.textContent = `Classified: ${data.primary_type || "unknown"}`;
    appendFeed(
      "Classification",
      `Input ${data.primary_type || "unknown"}. Agents: ${(data.selected_agents || []).join(", ")}`
    );
  });

  on("agent.started", (data) => {
    const uiKey = normalizeAgentName(data.agent);
    setAgentState(uiKey, "booting", data.status || "Booting...");
    appendFeed(data.label || data.agent || "Agent", data.message || "Agent started");
  });

  on("agent.progress", (data) => {
    const uiKey = normalizeAgentName(data.agent);
    setAgentState(uiKey, "active", data.step || data.status || "Running");
    appendFeed(data.agent || "Agent", data.message || data.step || "Processing");
  });

  on("tool.called", (data) => {
    appendFeed("Tool call", `${data.agent || "agent"} -> ${data.tool || "tool"}`);
  });

  on("tool.result", (data) => {
    appendFeed("Tool result", `${data.tool || "tool"}: ${data.status || "ok"}`);
  });

  on("agent.completed", (data) => {
    const uiKey = normalizeAgentName(data.agent);
    setAgentState(uiKey, "done", data.status || "Done");
    const summary = (data.output && data.output.summary) || "Completed";
    appendFeed(data.agent || "Agent", summary);
  });

  on("run.completed", async (data) => {
    runState.textContent = "Run completed";
    appendFeed("Run completed", "Final report is ready.");
    stream.close();
    activeStream = null;
    await fetchResult(resultUrl || data.result_url);
  });

  on("run.failed", (data) => {
    runState.textContent = "Run failed";
    appendFeed("Run failed", data.error || "Unknown error");
    stream.close();
    activeStream = null;
  });

  stream.onerror = () => {
    if (activeStream) {
      runState.textContent = "Stream reconnecting";
    }
  };
}

async function fetchResult(resultUrl) {
  if (!resultUrl) {
    return;
  }

  try {
    const response = await fetch(resultUrl);
    const payload = await response.json();

    if (response.status === 202) {
      appendFeed("Result", "Result still processing.");
      return;
    }

    if (payload && payload.summary) {
      appendFeed("Final summary", payload.summary.title || "Summary available");
      appendFeed(
        "Recommended action",
        payload.summary.recommended_action || "Call 1930 and file complaint on cybercrime.gov.in"
      );
    }

    const elapsed = Math.round(performance.now() - requestStart);
    tickerLatency.textContent = `Latency: ${elapsed} ms`;
  } catch (e) {
    appendFeed("Result", "Could not load final report.");
  }
}

async function ignite() {
  const text = promptInput.value.trim();
  if (!text && files.length === 0) {
    return;
  }

  requestStart = performance.now();
  armUi();
  await wait(280);
  setupOpsScreen();
  runState.textContent = "Submitting case";

  try {
    const payload = await buildAnalyzePayload();
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(errText || "Analyze request failed");
    }

    const accepted = await response.json();
    appendFeed("Session armed", `Run ${accepted.run_id} accepted. Listening for live agent updates.`);
    bindStream(accepted.stream_url, accepted.result_url);
  } catch (e) {
    runState.textContent = "Submit failed";
    appendFeed("Submit failed", e.message || "Could not start analysis");
  }
}

sendBtn.addEventListener("click", ignite);

promptInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    ignite();
  }
});

themeToggle.addEventListener("click", () => {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
});

liveBtn.addEventListener("click", () => {
  liveMode = !liveMode;
  liveBtn.classList.toggle("active", liveMode);
  runState.textContent = liveMode ? "Gemini live mode armed" : "Gemini live mode standby";
});

["dragenter", "dragover"].forEach((eventName) => {
  composer.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    composer.classList.add("dragover");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  composer.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    composer.classList.remove("dragover");
  });
});

composer.addEventListener("drop", (e) => {
  const dropped = Array.from((e.dataTransfer && e.dataTransfer.files) || []);
  appendFiles(dropped);
});

updateTicker();