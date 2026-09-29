const API_BASE = "";

/** In-memory file store: [{path, content}] */
let files = [];
let lastReport = null;
let activeAgentFilter = "all";
let activeViewTab = "findings";
let activeCleanFile = null;
let cleanViewMode = "split";

const el = (id) => document.getElementById(id);

// ------------------------------------------------------------ file intake

function addFiles(newFiles) {
  for (const f of newFiles) {
    if (!files.some((existing) => existing.path === f.path)) {
      files.push(f);
    }
  }
  renderFileChips();
}

function removeFile(path) {
  files = files.filter((f) => f.path !== path);
  renderFileChips();
}

function renderFileChips() {
  const row = el("fileChipRow");
  row.innerHTML = "";
  files.forEach((f) => {
    const chip = document.createElement("div");
    chip.className = "file-chip";
    chip.innerHTML = `<span>${f.path}</span>`;
    const btn = document.createElement("button");
    btn.textContent = "×";
    btn.onclick = () => removeFile(f.path);
    chip.appendChild(btn);
    row.appendChild(chip);
  });
  el("runBtn").disabled = files.length === 0;
}

function isProbablyText(name) {
  return /\.(py|java|c|cc|cpp|cxx|h|hh|hpp|txt|md|json|cfg|ini|toml|yaml|yml)$/i.test(name);
}

async function readFileList(fileList) {
  const results = [];
  for (const file of fileList) {
    if (!isProbablyText(file.name)) continue;
    const content = await file.text();
    const path = file.webkitRelativePath || file.name;
    results.push({ path, content });
  }
  return results;
}

const dropzone = el("dropzone");
dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("drag-over");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag-over"));
dropzone.addEventListener("drop", async (e) => {
  e.preventDefault();
  dropzone.classList.remove("drag-over");
  const items = e.dataTransfer.items;
  const collected = [];
  if (items && items.length && items[0].webkitGetAsEntry) {
    for (const item of items) {
      const entry = item.webkitGetAsEntry();
      if (entry) await walkEntry(entry, collected);
    }
  } else {
    collected.push(...(await readFileList(e.dataTransfer.files)));
  }
  addFiles(collected);
});

function walkEntry(entry, out) {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file(async (file) => {
        if (isProbablyText(file.name)) {
          const content = await file.text();
          out.push({ path: entry.fullPath.replace(/^\//, ""), content });
        }
        resolve();
      });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      reader.readEntries(async (entries) => {
        for (const child of entries) await walkEntry(child, out);
        resolve();
      });
    } else {
      resolve();
    }
  });
}

el("pickFolderBtn").onclick = () => el("fileInput").click();
el("pickFilesBtn").onclick = () => el("fileInputFlat").click();
el("fileInput").addEventListener("change", async (e) => addFiles(await readFileList(e.target.files)));
el("fileInputFlat").addEventListener("change", async (e) => addFiles(await readFileList(e.target.files)));

el("sampleBtn").onclick = () => {
  addFiles([
    {
      path: "app.py",
      content: `import os
import subprocess
import pickle
import hashlib

password = "SuperSecret123"


def Db(host, port, user, pw, timeout, retries, verbose):
    if verbose:
        if timeout > 0:
            if retries > 0:
                try:
                    x = 12345678
                    return x
                except:
                    pass


def run_cmd(user_input):
    os.system("ls " + user_input)
    subprocess.call("echo " + user_input, shell=True)


def load_config(raw_bytes):
    return pickle.loads(raw_bytes)


def hash_it(data):
    return hashlib.md5(data).hexdigest()


def query_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def f(a=[], b={}):
    a.append(1)
    return a


class badClassName:
    def BadMethodName(self):
        pass
`,
    },
    {
      path: "utils.py",
      content: `"""Utility helpers for database and config handling."""
import random


def make_token():
    # TODO: replace with a cryptographically secure generator
    return str(random.random())


def db_connection_string(host, port, user):
    """Build a database connection string."""
    return f"postgres://{user}@{host}:{port}/app"
`,
    },
  ]);
};

el("pasteAddBtn").onclick = () => {
  const name = el("pasteFilename").value.trim() || "snippet.py";
  const content = el("pasteContent").value;
  if (!content.trim()) return;
  addFiles([{ path: name, content }]);
  el("pasteContent").value = "";
};

// -------------------------------------------------------------- pipeline

const PIPELINE_STAGES = [
  "ingestion",
  "context_retrieval",
  ["static_analysis", "semantic_review", "security_assessment"],
  "specification_checker",
  "orchestrator_dedup_rank",
];

function resetPipeline() {
  document.querySelectorAll(".pipeline-strip [data-stage]").forEach((n) => {
    n.classList.remove("active", "done");
    const li = n.closest("li");
    if (li) li.classList.remove("active", "done");
  });
}

function setStage(stageName, state) {
  const nodes = document.querySelectorAll(`[data-stage="${stageName}"]`);
  nodes.forEach((n) => {
    n.classList.remove("active", "done");
    n.classList.add(state);
    const li = n.closest("li");
    if (li && li.dataset.stage === stageName) {
      li.classList.remove("active", "done");
      li.classList.add(state);
    }
  });
  // parallel container lights up if any child is active/done
  const parallelLi = document.querySelector('li[data-stage="parallel"]');
  if (parallelLi) {
    const spans = parallelLi.querySelectorAll("span[data-stage]");
    const anyActive = [...spans].some((s) => s.classList.contains("active"));
    const allDone = [...spans].every((s) => s.classList.contains("done"));
    parallelLi.classList.toggle("active", anyActive && !allDone);
    parallelLi.classList.toggle("done", allDone);
  }
}

async function animatePipeline() {
  resetPipeline();
  for (const stage of PIPELINE_STAGES) {
    const stages = Array.isArray(stage) ? stage : [stage];
    stages.forEach((s) => setStage(s, "active"));
    await new Promise((r) => setTimeout(r, 260));
    stages.forEach((s) => setStage(s, "done"));
  }
}

// --------------------------------------------------------------- run

el("runBtn").onclick = async () => {
  if (files.length === 0) return;
  el("pipeline").hidden = false;
  el("results").hidden = true;
  el("runBtn").disabled = true;
  el("runBtn").textContent = "Analyzing…";

  const animation = animatePipeline();

  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        files,
        alpha: 0.7,
        beta: 0.3,
        use_llm: el("useLlm").checked,
      }),
    });
    await animation;
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      alert(`Analysis failed: ${err.detail || res.statusText}`);
      return;
    }
    lastReport = await res.json();
    renderResults(lastReport);
  } catch (e) {
    await animation;
    alert(`Could not reach the RepoGuard AI backend: ${e}`);
  } finally {
    el("runBtn").disabled = false;
    el("runBtn").textContent = "Run analysis";
  }
};

// ---------------------------------------------------------- render results

const SEVERITY_LABEL = { 5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info" };
const SEVERITY_COLOR = { 5: "var(--red)", 4: "var(--red)", 3: "var(--amber)", 2: "var(--teal)", 1: "var(--border)" };
const AGENT_LABEL = {
  static_analysis: "Static Analysis",
  semantic_review: "Semantic Review",
  security_assessment: "Security",
  specification_checker: "Spec Checker",
};

function renderResults(report) {
  el("results").hidden = false;
  el("tabFindingsBadge").textContent = report.findings.length;
  const numClean = (report.cleaned_files || []).length;
  el("tabCleanBadge").textContent = `${numClean} file${numClean === 1 ? '' : 's'}`;

  renderFilters(report);
  renderMetrics(report);
  applyFilters();

  if (report.cleaned_files && report.cleaned_files.length > 0) {
    activeCleanFile = report.cleaned_files[0].path;
  }
  if (activeViewTab === "clean") {
    renderCleanCodeView();
  }
}

function renderFilters(report) {
  const group = el("agentFilters");
  group.innerHTML = "";
  const agents = ["all", ...Object.keys(report.metrics.findings_by_agent)];
  agents.forEach((agent) => {
    const chip = document.createElement("button");
    chip.className = "filter-chip" + (agent === activeAgentFilter ? " active" : "");
    chip.textContent = agent === "all" ? "All" : (AGENT_LABEL[agent] || agent);
    chip.onclick = () => {
      activeAgentFilter = agent;
      renderFilters(report);
      applyFilters();
    };
    group.appendChild(chip);
  });
}

el("searchBox").addEventListener("input", applyFilters);

function applyFilters() {
  if (!lastReport) return;
  const query = el("searchBox").value.trim().toLowerCase();
  let findings = lastReport.findings;
  if (activeAgentFilter !== "all") {
    findings = findings.filter((f) => f.agent === activeAgentFilter);
  }
  if (query) {
    findings = findings.filter(
      (f) =>
        f.title.toLowerCase().includes(query) ||
        f.file.toLowerCase().includes(query) ||
        f.description.toLowerCase().includes(query)
    );
  }
  renderFindings(findings);
}

function renderFindings(findings) {
  const list = el("findingsList");
  list.innerHTML = "";

  if (findings.length === 0) {
    list.innerHTML = `<div class="empty-state"><div class="glyph">◎</div>No findings match the current filter.</div>`;
    return;
  }

  const byFile = {};
  findings.forEach((f) => {
    (byFile[f.file] = byFile[f.file] || []).push(f);
  });

  Object.keys(byFile).forEach((file) => {
    const group = document.createElement("div");
    group.className = "file-group";
    group.innerHTML = `<div class="file-group-header">${file} · ${byFile[file].length} finding${byFile[file].length > 1 ? "s" : ""}</div>`;

    byFile[file].forEach((f) => {
      const card = document.createElement("div");
      card.className = `finding-card sev-${f.severity}`;
      card.innerHTML = `
        <div class="finding-loc">L${f.line || "—"}</div>
        <div class="finding-body">
          <div class="finding-title-row">
            <span class="finding-title">${escapeHtml(f.title)}</span>
            <span class="agent-tag ${f.agent}">${AGENT_LABEL[f.agent] || f.agent}</span>
            ${f.cwe ? `<span class="cwe-tag">${f.cwe}</span>` : ""}
          </div>
          <div class="finding-desc">${escapeHtml(f.description)}</div>
        </div>
        <div class="finding-priority">${f.priority?.toFixed(2) ?? "—"}</div>
      `;
      card.onclick = () => openDetail(f);
      group.appendChild(card);
    });
    list.appendChild(group);
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function renderMetrics(report) {
  const m = report.metrics;
  el("metricTotal").textContent = m.total_findings;
  el("metricCoverage").textContent = `${m.coverage_percent}% file coverage`;
  el("metricDedup").textContent = `${m.deduplicated_count} duplicate finding${m.deduplicated_count === 1 ? "" : "s"} merged`;

  const sevBars = el("sevBars");
  sevBars.innerHTML = "";
  const maxSev = Math.max(1, ...Object.values(m.findings_by_severity));
  [5, 4, 3, 2, 1].forEach((sev) => {
    const count = m.findings_by_severity[String(sev)] || 0;
    sevBars.innerHTML += `
      <div class="bar-row">
        <span class="bar-label">${SEVERITY_LABEL[sev]}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(count / maxSev) * 100}%;background:${SEVERITY_COLOR[sev]}"></div></div>
        <span class="bar-count">${count}</span>
      </div>`;
  });

  const agentBars = el("agentBars");
  agentBars.innerHTML = "";
  const maxAgent = Math.max(1, ...Object.values(m.findings_by_agent));
  Object.entries(m.findings_by_agent).forEach(([agent, count]) => {
    agentBars.innerHTML += `
      <div class="bar-row">
        <span class="bar-label">${(AGENT_LABEL[agent] || agent).split(" ")[0]}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(count / maxAgent) * 100}%;background:var(--teal)"></div></div>
        <span class="bar-count">${count}</span>
      </div>`;
  });

  const timingsList = el("timingsList");
  timingsList.innerHTML = "";
  m.agent_timings.forEach((t) => {
    timingsList.innerHTML += `<div><span>${t.agent}</span><span>${t.milliseconds.toFixed(2)} ms</span></div>`;
  });
  timingsList.innerHTML += `<div><span>total overhead</span><span>${m.coordination_overhead_ms.toFixed(2)} ms</span></div>`;
}

// ------------------------------------------------------------- detail modal

function openDetail(f) {
  const modal = el("detailModal");
  modal.innerHTML = `
    <div class="modal-header">
      <h2 class="detail-title">${escapeHtml(f.title)}</h2>
      <button class="btn-ghost" onclick="closeDetail()">Close</button>
    </div>
    <div class="detail-meta">${f.file}:${f.line || "—"} · ${f.rule_id} · priority ${f.priority?.toFixed(2)}${f.cwe ? " · " + f.cwe : ""}${f.spec_grounded ? " · spec-grounded" : ""}</div>
    <div class="detail-section">
      <h4>Description</h4>
      <p>${escapeHtml(f.description)}</p>
    </div>
    ${
      f.suggestion
        ? `<div class="detail-section"><h4>Suggested fix</h4><div class="suggestion-box">${escapeHtml(f.suggestion)}</div></div>`
        : ""
    }
    <div class="detail-section">
      <h4>Reported by</h4>
      <p>${AGENT_LABEL[f.agent] || f.agent} agent · confidence ${(f.confidence * 100).toFixed(0)}%</p>
    </div>
  `;
  el("detailBackdrop").hidden = false;
}
function closeDetail() {
  el("detailBackdrop").hidden = true;
}
el("detailBackdrop").addEventListener("click", (e) => {
  if (e.target === el("detailBackdrop")) closeDetail();
});

// -------------------------------------------------------------- spec modal

el("specBtn").onclick = async () => {
  const spec = await (await fetch(`${API_BASE}/api/spec`)).json();
  el("specTextarea").value = JSON.stringify(spec, null, 2);
  el("specModalBackdrop").hidden = false;
};
el("specCloseBtn").onclick = () => (el("specModalBackdrop").hidden = true);
el("specModalBackdrop").addEventListener("click", (e) => {
  if (e.target === el("specModalBackdrop")) el("specModalBackdrop").hidden = true;
});
el("specSaveBtn").onclick = async () => {
  try {
    const parsed = JSON.parse(el("specTextarea").value);
    await fetch(`${API_BASE}/api/spec`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed),
    });
    el("specModalBackdrop").hidden = true;
  } catch (e) {
    alert("Invalid JSON: " + e.message);
  }
};
el("specResetBtn").onclick = async () => {
  const spec = await (await fetch(`${API_BASE}/api/spec/reset`, { method: "POST" })).json();
  el("specTextarea").value = JSON.stringify(spec, null, 2);
};

// ------------------------------------------------------------- clean code view

el("tabFindingsBtn").onclick = () => switchViewTab("findings");
el("tabCleanCodeBtn").onclick = () => switchViewTab("clean");

function switchViewTab(tab) {
  activeViewTab = tab;
  el("tabFindingsBtn").classList.toggle("active", tab === "findings");
  el("tabCleanCodeBtn").classList.toggle("active", tab === "clean");
  el("findingsView").hidden = tab !== "findings";
  el("cleanCodeView").hidden = tab !== "clean";
  if (tab === "clean") {
    renderCleanCodeView();
  }
}

el("viewModeToggleBtn").onclick = () => {
  cleanViewMode = cleanViewMode === "split" ? "clean" : "split";
  el("viewModeToggleBtn").textContent = cleanViewMode === "split" ? "Side-by-Side View" : "Clean-Only View";
  renderCleanCodeView();
};

function getActiveCleanContent(cur) {
  if (!cur) return "";
  if (activeStrategy === "deterministic_ast" && cur.variants && cur.variants.deterministic_ast) {
    return cur.variants.deterministic_ast.cleaned_content;
  }
  if (activeStrategy === "neural_llm" && cur.variants && cur.variants.neural_llm) {
    return cur.variants.neural_llm.cleaned_content;
  }
  return cur.cleaned_content;
}

el("copyCleanBtn").onclick = () => {
  if (!lastReport || !lastReport.cleaned_files) return;
  const cur = lastReport.cleaned_files.find((cf) => cf.path === activeCleanFile) || lastReport.cleaned_files[0];
  if (!cur) return;
  const text = getActiveCleanContent(cur);
  navigator.clipboard.writeText(text).then(() => {
    const origText = el("copyCleanBtn").textContent;
    el("copyCleanBtn").textContent = "✓ Copied Clean Code!";
    setTimeout(() => {
      el("copyCleanBtn").textContent = origText;
    }, 1800);
  });
};

el("downloadCleanBtn").onclick = () => {
  if (!lastReport || !lastReport.cleaned_files) return;
  const cur = lastReport.cleaned_files.find((cf) => cf.path === activeCleanFile) || lastReport.cleaned_files[0];
  if (!cur) return;
  const text = getActiveCleanContent(cur);
  const blob = new Blob([text], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `remediated_${activeStrategy}_${cur.path.replace(/\//g, "_")}`;
  a.click();
};

let activeStrategy = "hybrid";

["stratBtnHybrid", "stratBtnDet", "stratBtnNeural"].forEach((id) => {
  const btn = el(id);
  if (!btn) return;
  btn.onclick = () => {
    activeStrategy = btn.dataset.strat;
    document.querySelectorAll(".strat-btn").forEach((b) => b.classList.toggle("active", b === btn));
    renderCleanCodeView();
  };
});

function renderCleanCodeView() {
  if (!lastReport || !lastReport.cleaned_files || lastReport.cleaned_files.length === 0) {
    el("cleanCodeDisplay").innerHTML = `<div class="empty-state">No auto-remediated files available yet. Run analysis first.</div>`;
    return;
  }

  // Render file tabs
  const tabsContainer = el("cleanFileTabs");
  tabsContainer.innerHTML = "";
  lastReport.cleaned_files.forEach((cf) => {
    const btn = document.createElement("button");
    btn.className = `clean-file-tab${cf.path === activeCleanFile ? " active" : ""}`;
    btn.textContent = cf.path;
    btn.onclick = () => {
      activeCleanFile = cf.path;
      renderCleanCodeView();
    };
    tabsContainer.appendChild(btn);
  });

  const cur = lastReport.cleaned_files.find((cf) => cf.path === activeCleanFile) || lastReport.cleaned_files[0];
  if (!cur) return;

  // Resolve content based on selected strategy
  let contentToDisplay = cur.cleaned_content;
  let fixesToDisplay = cur.fixes_applied || [];

  if (activeStrategy === "deterministic_ast" && cur.variants && cur.variants.deterministic_ast) {
    contentToDisplay = cur.variants.deterministic_ast.cleaned_content;
    fixesToDisplay = cur.variants.deterministic_ast.fixes_applied;
  } else if (activeStrategy === "neural_llm" && cur.variants && cur.variants.neural_llm) {
    contentToDisplay = cur.variants.neural_llm.cleaned_content;
    fixesToDisplay = cur.variants.neural_llm.fixes_applied;
  }

  // Update Scorecard
  const sc = el("strategyScorecard");
  if (cur.variants && cur.variants.deterministic_ast && cur.variants.neural_llm) {
    const v1 = cur.variants.deterministic_ast;
    const v2 = cur.variants.neural_llm;
    sc.innerHTML = `
      <div class="scorecard-header">
        <span class="scorecard-title">⚖️ Comparative Strategy Evaluation &amp; Gatekeeper Decision</span>
        <span class="strat-pill pill-best">Selected: ${cur.selected_strategy.toUpperCase()}</span>
      </div>
      <div class="scorecard-reason">
        <strong>Neuro-Symbolic Gatekeeper:</strong> ${escapeHtml(cur.best_strategy_reason)}
      </div>
      <div class="scorecard-grid">
        <div class="scorecard-card ${activeStrategy === 'deterministic_ast' ? 'active-card' : ''}">
          <div class="card-top">
            <span class="card-strategy-name">⚡ Way 1: Deterministic AST &amp; Rules</span>
            <span class="card-score">${v1.quality_score}/100</span>
          </div>
          <div class="card-stats">
            <span>Residual Issues: <strong>${v1.remaining_issues}</strong></span>
            <span>Latency: <strong>${v1.execution_time_ms} ms</strong></span>
            <span>Hallucination: <strong>0%</strong></span>
          </div>
        </div>
        <div class="scorecard-card ${activeStrategy === 'neural_llm' ? 'active-card' : ''}">
          <div class="card-top">
            <span class="card-strategy-name">🧠 Way 2: Contextual Neural / LLM</span>
            <span class="card-score">${v2.quality_score}/100</span>
          </div>
          <div class="card-stats">
            <span>Residual Issues: <strong>${v2.remaining_issues}</strong></span>
            <span>Latency: <strong>${v2.execution_time_ms} ms</strong></span>
            <span>Type Hints: <strong>100%</strong></span>
          </div>
        </div>
      </div>
    `;
    sc.hidden = false;
  } else {
    sc.hidden = true;
  }

  el("cleanStatusPill").textContent = `${fixesToDisplay.length} Fix${fixesToDisplay.length === 1 ? "" : "es"} Applied`;
  el("cleanFilePath").textContent = `${cur.path} · Strategy: ${activeStrategy.replace('_', ' ').toUpperCase()}`;

  const buildLinesHtml = (lines, isClean) => {
    return lines
      .map((line, idx) => {
        const lineNum = idx + 1;
        const isHighlight =
          isClean &&
          (line.includes("CWE-") ||
            line.includes("Safe") ||
            line.includes("PEP 8") ||
            line.includes("DEFAULT_TIMEOUT") ||
            line.includes("connect_db") ||
            line.includes("BadClassName") ||
            line.includes("bad_method_name") ||
            line.includes("os.environ") ||
            line.includes("secrets.token_hex") ||
            line.includes("json.loads") ||
            line.includes("sha256") ||
            line.includes("subprocess.run") ||
            line.includes("except Exception as err"));
        const cls = isHighlight ? "code-line diff-highlight" : "code-line";
        return `<div class="${cls}"><span class="line-num">${lineNum}</span><span class="line-text">${escapeHtml(line)}</span></div>`;
      })
      .join("");
  };

  const origLines = cur.original_content.split("\n");
  const cleanLines = contentToDisplay.split("\n");
  const display = el("cleanCodeDisplay");

  if (cleanViewMode === "split") {
    display.innerHTML = `
      <div class="code-split-grid">
        <div class="code-pane">
          <div class="code-pane-title">
            <span>Original Code (Vulnerable &amp; Non-Compliant)</span>
            <span class="pane-badge badge-orig">Original</span>
          </div>
          <div class="code-box">${buildLinesHtml(origLines, false)}</div>
        </div>
        <div class="code-pane">
          <div class="code-pane-title">
            <span>Clean Code (${activeStrategy.replace('_', ' ').toUpperCase()})</span>
            <span class="pane-badge badge-clean">Remediated</span>
          </div>
          <div class="code-box">${buildLinesHtml(cleanLines, true)}</div>
        </div>
      </div>
    `;
  } else {
    display.innerHTML = `
      <div class="code-split-grid single-view">
        <div class="code-pane">
          <div class="code-pane-title">
            <span>Clean Code (${activeStrategy.replace('_', ' ').toUpperCase()})</span>
            <span class="pane-badge badge-clean">Remediated</span>
          </div>
          <div class="code-box">${buildLinesHtml(cleanLines, true)}</div>
        </div>
      </div>
    `;
  }

  // Render remediation list
  const list = el("remediationList");
  list.innerHTML = "";
  if (!fixesToDisplay || fixesToDisplay.length === 0) {
    list.innerHTML = `<li class="remediation-item">No security or style fixes were required for this file.</li>`;
  } else {
    fixesToDisplay.forEach((fix) => {
      const li = document.createElement("li");
      li.className = "remediation-item";
      li.innerHTML = `<span class="remediation-icon">✓</span> <span>${escapeHtml(fix)}</span>`;
      list.appendChild(li);
    });
  }
}

