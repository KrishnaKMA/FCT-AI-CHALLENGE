const SERVICES = [
  "policy-issuance-service",
  "fraud-screening-service",
  "title-search-service",
  "identity-verification-service",
  "mortgage-processing-service",
  "document-vault-service",
  "property-intelligence-api",
];

const METRIC_DISPLAY = {
  "policy-issuance-service":       { primary: "latency_p99_ms",           label: "P99 Latency",  unit: "ms", warn: 2000,  crit: 5000 },
  "fraud-screening-service":       { primary: "fraud_screen_coverage_pct", label: "Coverage",     unit: "%",  warn: 97,    crit: 95, invert: true },
  "title-search-service":          { primary: "latency_p99_ms",           label: "P99 Latency",  unit: "ms", warn: 5000,  crit: 15000 },
  "identity-verification-service": { primary: "queue_depth",              label: "Queue Depth",  unit: "",   warn: 30,    crit: 80 },
  "mortgage-processing-service":   { primary: "request_rate",             label: "Request Rate", unit: "/m", warn: 400,   crit: 500 },
  "document-vault-service":        { primary: "disk_usage_pct",           label: "Disk Usage",   unit: "%",  warn: 80,    crit: 90 },
  "property-intelligence-api":     { primary: "request_rate",             label: "Request Rate", unit: "/m", warn: 600,   crit: 900 },
};

const SERVICE_SHORT = {
  "policy-issuance-service":       "policy",
  "fraud-screening-service":       "fraud-screen",
  "title-search-service":          "title-search",
  "identity-verification-service": "identity-verify",
  "mortgage-processing-service":   "mortgage-proc",
  "document-vault-service":        "doc-vault",
  "property-intelligence-api":     "prop-intel",
};

const sparklineData   = {};
const sparklineCharts = {};
let activityCache = [];

// ── Init ──────────────────────────────────────────────────

async function init() {
  buildMetricCards();
  await loadScenarios();
  startPolling();
  updateClock();
}

function buildMetricCards() {
  const grid = document.getElementById("metrics-grid");
  grid.innerHTML = "";
  SERVICES.forEach(svc => {
    const cfg   = METRIC_DISPLAY[svc];
    const short = SERVICE_SHORT[svc];
    sparklineData[svc] = [];

    const card = document.createElement("div");
    card.className = "metric-card";
    card.id = `card-${svc}`;
    card.innerHTML = `
      <div class="metric-card-title">
        <span class="metric-card-service">${short}</span>
        <span class="badge badge-blue" id="sla-${svc}" style="font-size:8px">SLA OK</span>
      </div>
      <div class="metric-card-value" id="val-${svc}" style="color:var(--green)">—</div>
      <div class="metric-card-sub" id="sub-${svc}">${cfg.label}</div>
      <div class="metric-card-sub" id="pod-${svc}" style="color:var(--text-dim)">pods: —</div>
      <div class="sparkline-container">
        <canvas id="spark-${svc}" height="36"></canvas>
      </div>
    `;
    grid.appendChild(card);

    const ctx = document.getElementById(`spark-${svc}`).getContext("2d");
    sparklineCharts[svc] = new Chart(ctx, {
      type: "line",
      data: {
        labels: Array(30).fill(""),
        datasets: [{
          data: Array(30).fill(null),
          borderColor: "#3b82f6",
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.3,
          fill: true,
          backgroundColor: "rgba(59,130,246,0.08)",
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false, beginAtZero: false },
        },
      }
    });
  });
}

async function loadScenarios() {
  try {
    const res  = await fetch("/api/scenarios");
    const data = await res.json();
    const sel  = document.getElementById("scenario-select");
    sel.innerHTML = '<option value="">Select scenario...</option>';
    data.forEach(s => {
      const opt = document.createElement("option");
      opt.value       = s.id;
      opt.textContent = s.id.replace(/_/g, " ");
      sel.appendChild(opt);
    });
  } catch(e) {}
}

// ── Polling ───────────────────────────────────────────────

function startPolling() {
  setInterval(poll, 3000);
  poll();
}

async function poll() {
  try {
    const [statusRes, metricsRes, incidentsRes] = await Promise.all([
      fetch("/api/status"),
      fetch("/api/metrics"),
      fetch("/api/incidents"),
    ]);
    const status    = await statusRes.json();
    const metrics   = await metricsRes.json();
    const incidents = await incidentsRes.json();

    updateStatus(status);
    updateMetrics(metrics);
    updateActivityFeed(incidents);
    updateFaultsList(status.active_faults || []);
  } catch(e) {}
}

// ── Status ────────────────────────────────────────────────

function updateStatus(status) {
  const health   = Math.round(status.system_health || 100);
  const healthEl = document.getElementById("health-score");
  healthEl.textContent = health;
  healthEl.style.color = health >= 80 ? "var(--green)" : health >= 60 ? "var(--yellow)" : "var(--red)";

  const ctx = status.business_context || {};
  setDisplay("closing-badge", ctx.closing_day);
  setDisplay("peak-badge",    ctx.peak_window);

  if(ctx.next_peak_description)
    document.getElementById("next-peak").textContent = ctx.next_peak_description;

  const auto = status.autonomous_mode;
  document.getElementById("auto-dot").className    = "toggle-dot" + (auto ? "" : " off");
  document.getElementById("auto-label").textContent = auto ? "Auto ON" : "Auto OFF";
  document.getElementById("mode-badge").textContent = auto ? "AUTONOMOUS" : "MANUAL";
  document.getElementById("mode-badge").className   = auto ? "badge badge-blue" : "badge badge-yellow";

  const compliance = status.compliance || {};
  const hold = compliance.policy_hold || false;
  setDisplay("hold-badge", hold);
  document.getElementById("policy-hold-banner").className =
    "policy-hold-banner" + (hold ? " active" : "");
  document.getElementById("compliance-bar").className =
    "compliance-bar" + (hold ? " breach" : "");

  const cov = (compliance.coverage_pct !== undefined) ? compliance.coverage_pct : 99.8;
  const covEl = document.getElementById("coverage-value");
  covEl.textContent   = cov.toFixed(1) + "%";
  covEl.style.color   = cov >= 97 ? "var(--green)" : cov >= 95 ? "var(--yellow)" : "var(--purple)";
  const fill = document.getElementById("coverage-fill");
  fill.style.width      = Math.min(100, cov) + "%";
  fill.style.background = cov >= 97 ? "var(--green)" : cov >= 95 ? "var(--yellow)" : "var(--purple)";
  document.getElementById("coverage-trend").textContent =
    "Trend: " + (compliance.coverage_trend || "stable");
  document.getElementById("coverage-threshold").textContent =
    "Min: " + (compliance.threshold || 95).toFixed(1) + "%";

  const c = status.counters || {};
  setText("cnt-transactions", fmtNum(c.transactions_today || 0));
  setText("cnt-policies",     fmtNum(c.policies_issued || 0));
  setText("cnt-fraud",        fmtNum(c.fraud_screens_completed || 0));
  setText("cnt-coverage",     (c.fraud_screen_coverage_pct || cov || 99.8).toFixed(1) + "%");
  setText("cnt-at-risk",      fmtNum(ctx.active_transactions_at_risk || 0));
  setText("cnt-resolved",     c.incidents_auto_resolved || 0);
  setText("cnt-escalated",    c.incidents_escalated || 0);

  const protected_ = c.estimated_closings_protected || 0;
  setText("cnt-protected", fmtNum(protected_));
  const wowEl = document.querySelector(".wow-counter");
  if(wowEl) wowEl.classList.toggle("nonzero", protected_ > 0);
}

// ── Metrics ───────────────────────────────────────────────

function updateMetrics(data) {
  const metrics = data.metrics || {};
  const health  = data.health  || {};

  SERVICES.forEach(svc => {
    const m   = metrics[svc] || {};
    const cfg = METRIC_DISPLAY[svc];
    const h   = health[svc] || 100;

    let val = m[cfg.primary];
    if(val === undefined) return;

    let color     = "var(--green)";
    let cardClass = "metric-card";
    let anomalous = false;

    if(cfg.invert) {
      if(val < cfg.crit)      { color = "var(--purple)"; cardClass += " compliance"; anomalous = true; }
      else if(val < cfg.warn) { color = "var(--yellow)"; cardClass += " warning"; }
    } else {
      if(val > cfg.crit)      { color = "var(--red)";    cardClass += " anomalous"; anomalous = true; }
      else if(val > cfg.warn) { color = "var(--yellow)"; cardClass += " warning"; }
    }

    if(svc === "fraud-screening-service") {
      if(val < 95)       cardClass = "metric-card compliance";
      else if(val < 97)  cardClass = "metric-card warning";
    }

    document.getElementById(`card-${svc}`).className = cardClass;

    let displayVal = val;
    let unit = cfg.unit;
    if(cfg.primary === "latency_p99_ms" && val >= 1000) {
      displayVal = (val / 1000).toFixed(1); unit = "s";
    } else if(cfg.primary === "latency_p99_ms") {
      displayVal = Math.round(val); unit = "ms";
    } else if(unit === "%") {
      displayVal = val.toFixed(1);
    } else if(unit === "/m") {
      displayVal = Math.round(val);
    } else {
      displayVal = Number.isInteger(val) ? val : val.toFixed(1);
    }

    const valEl = document.getElementById(`val-${svc}`);
    if(valEl) { valEl.textContent = displayVal + unit; valEl.style.color = color; }

    const subEl = document.getElementById(`sub-${svc}`);
    if(subEl) subEl.textContent = cfg.label;

    const podEl = document.getElementById(`pod-${svc}`);
    if(podEl && m.pod_count !== undefined)
      podEl.textContent = `pods: ${m.pod_count} | err: ${(m.error_rate||0).toFixed(2)}%`;

    const slaEl = document.getElementById(`sla-${svc}`);
    if(slaEl && m.sla_compliance_pct !== undefined) {
      const sla = m.sla_compliance_pct;
      slaEl.textContent = sla >= 99 ? "SLA ✓" : sla >= 95 ? "SLA ~" : "SLA ✗";
      slaEl.className   = sla >= 99 ? "badge badge-green" : sla >= 95 ? "badge badge-yellow" : "badge badge-red";
      slaEl.style.fontSize = "8px";
    }

    sparklineData[svc].push(parseFloat(displayVal));
    if(sparklineData[svc].length > 30) sparklineData[svc].shift();

    const chart = sparklineCharts[svc];
    if(chart) {
      chart.data.datasets[0].data        = [...sparklineData[svc]];
      chart.data.datasets[0].borderColor = color;
      chart.data.datasets[0].backgroundColor = color
        .replace(")", ",0.08)").replace("var(","rgba(")
        .replace("--green","16,185,129").replace("--yellow","245,158,11")
        .replace("--red","239,68,68").replace("--purple","139,92,246");
      chart.update("none");
    }

    updateSVGNode(svc, m, h, anomalous);
  });
}

function updateSVGNode(svc, m, health, anomalous) {
  const rect     = document.getElementById(`rect-${svc}`);
  const metricEl = document.getElementById(`metric-${svc}`);
  if(!rect) return;

  let stroke = "#10b981";
  let fill   = "#111f1a";
  if(health < 60)      { stroke = "#ef4444"; fill = "#1a0f0f"; }
  else if(health < 80) { stroke = "#f59e0b"; fill = "#1a160f"; }

  if(svc === "fraud-screening-service") {
    const cov = m.fraud_screen_coverage_pct || 99.8;
    if(cov < 95)      { stroke = "#ef4444"; fill = "#1a0a1a"; }
    else if(cov < 97) { stroke = "#a78bfa"; fill = "#16112b"; }
    else              { stroke = "#8b5cf6"; fill = "#16112b"; }
  }

  if(svc === "property-intelligence-api" && health >= 80)
    stroke = "#06b6d4";

  rect.setAttribute("stroke", stroke);
  rect.setAttribute("fill",   fill);

  if(anomalous) {
    rect.classList.add("pulsing");
    rect.setAttribute("filter", health < 60 ? "url(#glow-red)" : "url(#glow-green)");
  } else {
    rect.classList.remove("pulsing");
    rect.removeAttribute("filter");
  }

  if(metricEl) {
    const cfg = METRIC_DISPLAY[svc];
    const v   = m[cfg.primary];
    if(v === undefined) return;
    let disp = "";
    if(cfg.primary === "latency_p99_ms")
      disp = v >= 1000 ? `lat: ${(v/1000).toFixed(1)}s` : `lat: ${Math.round(v)}ms`;
    else if(cfg.primary === "fraud_screen_coverage_pct") disp = `cov: ${v.toFixed(1)}%`;
    else if(cfg.primary === "request_rate")   disp = `rate: ${Math.round(v)}/m`;
    else if(cfg.primary === "queue_depth")    disp = `queue: ${Math.round(v)}`;
    else if(cfg.primary === "disk_usage_pct") disp = `disk: ${v.toFixed(1)}%`;
    else disp = `${v.toFixed(1)}`;
    metricEl.textContent = disp;
    metricEl.setAttribute("fill",
      health >= 80 ? "#94a3b8" : (health >= 60 ? "#f59e0b" : "#ef4444"));
  }
}

// ── Activity Feed ─────────────────────────────────────────

function updateActivityFeed(data) {
  const log  = (data.activity_log || []).slice().reverse();
  const feed = document.getElementById("activity-feed");
  if(log.length === 0) return;

  const topId = log[0]?.incident_id;
  if(activityCache.length > 0 && activityCache[0]?.incident_id === topId) {
    activityCache.forEach(item => {
      const outcome = log.find(l => l.incident_id === item.incident_id)?.outcome;
      if(outcome && outcome !== "pending") {
        const el = document.getElementById(`outcome-${item.incident_id}`);
        if(el) {
          el.textContent = outcome;
          el.className   = "outcome-badge badge-" + (outcome === "RESOLVED" ? "green" : outcome === "PARTIAL" ? "yellow" : "red");
        }
      }
    });
    return;
  }

  activityCache  = log;
  feed.innerHTML = "";

  log.slice(0, 30).forEach(item => {
    const el   = document.createElement("div");
    const type = getActivityType(item);
    el.className = `activity-item type-${type}`;
    el.id        = `activity-${item.incident_id}`;
    el.onclick   = () => el.classList.toggle("expanded");

    const time    = formatTime(item.timestamp);
    const actions = (item.actions_taken || []).join(", ");
    const root    = item.rca_result?.root_cause || item.incident_type;
    const conf    = item.rca_result?.confidence;
    const confStr = conf ? `(${(conf * 100).toFixed(0)}%)` : "";
    const outcome = item.outcome || "pending";

    const typeBadgeColor = {
      "proactive":  "badge-blue",
      "autonomous": "badge-red",
      "recommend":  "badge-yellow",
      "compliance": "badge-purple",
      "fraud":      "badge-yellow",
    }[type] || "badge-blue";

    el.innerHTML = `
      <div class="activity-header">
        <span class="activity-id">${item.incident_id}</span>
        <span class="activity-type ${typeBadgeColor}">${item.incident_type || "AGENT"}</span>
        <span id="outcome-${item.incident_id}" class="outcome-badge badge-${outcome === 'RESOLVED' ? 'green' : outcome === 'pending' ? 'blue' : outcome === 'PARTIAL' ? 'yellow' : 'red'}">${outcome}</span>
      </div>
      <div class="activity-root">⇒ ${root} ${confStr}</div>
      <div class="activity-action">${actions || "monitoring"}</div>
      <div class="activity-time">${time}</div>
      <div class="activity-detail">${JSON.stringify(item, null, 2)}</div>
    `;
    feed.appendChild(el);
  });
}

function getActivityType(item) {
  const type = item.incident_type || "";
  if(type === "PROACTIVE_PRESCALE")  return "proactive";
  if(type === "COMPLIANCE_INCIDENT") return "compliance";
  if(type === "FRAUD_SIGNAL")        return "fraud";
  if((item.actions_taken || []).includes("recommend_only")) return "recommend";
  if(item.autonomous)                return "autonomous";
  return "recommend";
}

// ── Faults List ───────────────────────────────────────────

function updateFaultsList(faults) {
  const list = document.getElementById("faults-list");
  if(!faults || faults.length === 0) {
    list.innerHTML = '<div style="font-size:10px;color:var(--text-dim);text-align:center;padding:8px">No active faults</div>';
    return;
  }
  list.innerHTML = "";
  faults.forEach(f => {
    const elapsed = Math.round(f.elapsed_seconds);
    const remain  = Math.max(0, Math.round(f.duration_seconds - elapsed));
    const el = document.createElement("div");
    el.className = "fault-item active";
    el.innerHTML = `
      <div>
        <div class="fault-name">${f.name}</div>
        <div class="fault-timer" style="color:var(--text-dim)">Affects: ${(f.affected_services||[]).join(", ")}</div>
      </div>
      <div style="text-align:right">
        <div class="fault-timer" style="color:var(--red)">${remain}s left</div>
        <div style="font-size:8px;color:var(--text-dim);cursor:pointer"
             onclick="fetch('/api/resolve/${f.scenario_id}',{method:'POST'})">resolve ✕</div>
      </div>
    `;
    list.appendChild(el);
  });
}

// ── Controls ──────────────────────────────────────────────

async function injectSelected() {
  const sel = document.getElementById("scenario-select");
  if(!sel.value) return;
  await fetch(`/api/inject/${sel.value}`, { method: "POST" });
  sel.value = "";
}

async function toggleAutonomous() {
  await fetch("/api/toggle-autonomous", { method: "POST" });
}

// ── Utilities ─────────────────────────────────────────────

function updateClock() {
  const now = new Date();
  const h   = String(now.getUTCHours()).padStart(2, "0");
  const m   = String(now.getUTCMinutes()).padStart(2, "0");
  const s   = String(now.getUTCSeconds()).padStart(2, "0");
  document.getElementById("clock").textContent = `${h}:${m}:${s} UTC`;
  setTimeout(updateClock, 1000);
}

function setDisplay(id, show) {
  const el = document.getElementById(id);
  if(el) el.style.display = show ? "inline-flex" : "none";
}

function setText(id, text) {
  const el = document.getElementById(id);
  if(el) el.textContent = text;
}

function fmtNum(n) {
  if(n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if(n >= 1000)    return (n / 1000).toFixed(1)    + "K";
  return String(Math.round(n));
}

function formatTime(iso) {
  if(!iso) return "";
  try {
    return new Date(iso).toUTCString().slice(17, 25) + " UTC";
  } catch(e) { return iso.slice(11, 19); }
}

init();
