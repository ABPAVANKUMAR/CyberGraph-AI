import { useCallback, useEffect, useRef, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  ReactFlowProvider,
  useNodesState,
  useEdgesState,
} from "reactflow";

import "reactflow/dist/style.css";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";


// Browser-generated alert tones. AudioContext is resumed explicitly because
// browsers may suspend audio until the user interacts with the page.
async function playAlertSound(kind = "critical") {
  if (typeof window === "undefined") return;

  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextClass) {
    console.error("CyberGraph AI sound alerts are not supported by this browser.");
    return;
  }

  const patterns = {
    test: [{ frequency: 660, duration: 0.22, gap: 0.06 }],
    critical: [
      { frequency: 880, duration: 0.18, gap: 0.12 },
      { frequency: 880, duration: 0.18, gap: 0.1 },
    ],
    threshold: [
      { frequency: 440, duration: 0.16, gap: 0.1 },
      { frequency: 440, duration: 0.16, gap: 0.1 },
      { frequency: 440, duration: 0.25, gap: 0.06 },
    ],
    danger: [
      { frequency: 620, duration: 0.18, gap: 0.08 },
      { frequency: 780, duration: 0.18, gap: 0.08 },
      { frequency: 980, duration: 0.3, gap: 0.06 },
    ],
  };

  let context;
  try {
    context = new AudioContextClass();
    if (context.state === "suspended") {
      await context.resume();
    }

    const tones = patterns[kind] || patterns.test;
    let startAt = context.currentTime + 0.05;

    for (const tone of tones) {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = "sine";
      oscillator.frequency.setValueAtTime(tone.frequency, startAt);
      gain.gain.setValueAtTime(0.001, startAt);
      gain.gain.linearRampToValueAtTime(0.28, startAt + 0.02);
      gain.gain.setValueAtTime(0.28, startAt + Math.max(0.03, tone.duration - 0.03));
      gain.gain.linearRampToValueAtTime(0.001, startAt + tone.duration);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(startAt);
      oscillator.stop(startAt + tone.duration + 0.025);
      startAt += tone.duration + tone.gap;
    }

    const totalDurationMs = tones.reduce(
      (sum, tone) => sum + tone.duration + tone.gap,
      0
    ) * 1000;
    window.setTimeout(() => {
      if (context && context.state !== "closed") {
        context.close().catch(() => {});
      }
    }, totalDurationMs + 400);
  } catch (error) {
    console.error("CyberGraph AI could not play an alert sound:", error);
    if (context && context.state !== "closed") {
      context.close().catch(() => {});
    }
  }
}

function hasDangerousCombination(report) {
  if (!report) return false;
  const severity = String(report.alert?.severity || "").toLowerCase();
  const findingsText = (Array.isArray(report.investigation) ? report.investigation : [])
    .map((item) =>
      [item?.title, item?.finding, item?.name, item?.description, item?.evidence]
        .filter(Boolean)
        .join(" ")
    )
    .join(" ")
    .toLowerCase();
  const rawText = JSON.stringify(report).toLowerCase();
  const combinedText = `${findingsText} ${rawText}`;
  const hasVulnerability = combinedText.includes("vulnerab") || combinedText.includes("unpatched");
  const hasCriticalAsset =
    combinedText.includes("critical asset") ||
    combinedText.includes("criticality") ||
    combinedText.includes("financial database");
  return severity === "critical" && hasVulnerability && hasCriticalAsset;
}

const nodeColors = {
  alert: "#fb7185",
  device: "#60a5fa",
  vulnerability: "#fbbf24",
  identity: "#a5b4fc",
  asset: "#34d399",
};

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string" || typeof value === "number") return String(value);
  return value.name || value.hostname || value.username || value.id || "";
}

function makeNode(id, type, title, value, position) {
  const colors = {
    alert: { background: "#351923", color: "#fecdd3", border: nodeColors.alert },
    device: { background: "#142943", color: "#bfdbfe", border: nodeColors.device },
    vulnerability: { background: "#352b17", color: "#fde68a", border: nodeColors.vulnerability },
    identity: { background: "#262044", color: "#ddd6fe", border: nodeColors.identity },
    asset: { background: "#12332b", color: "#a7f3d0", border: nodeColors.asset },
  };
  const palette = colors[type];

  return {
    id,
    position,
    data: { label: `${title}\n${value || "Details unavailable"}` },
    style: {
      background: palette.background,
      color: palette.color,
      border: `1px solid ${palette.border}`,
      borderRadius: 10,
      padding: 12,
      width: 190,
      whiteSpace: "pre-line",
      fontSize: 12,
      lineHeight: 1.5,
    },
  };
}

function makeEdge(id, source, target, label, color) {
  return {
    id,
    source,
    target,
    label,
    animated: label === "AFFECTS" || label === "CONNECTS TO",
    style: { stroke: color, strokeWidth: 2 },
    labelStyle: { fill: "#cbd5e1", fontSize: 10 },
    labelBgStyle: { fill: "#09111e" },
  };
}

function RelationshipGraph({ selectedAlert, currentAlert }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphMessage, setGraphMessage] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadGraph() {
      if (!selectedAlert) {
        setNodes([]);
        setEdges([]);
        setGraphMessage("Select an alert to view its graph.");
        return;
      }

      setGraphLoading(true);
      setGraphMessage("");

      try {
        const response = await fetch(
          `${API_URL}/api/investigations/${encodeURIComponent(selectedAlert)}`
        );

        if (!response.ok) {
          throw new Error(`Graph request failed: HTTP ${response.status}`);
        }

        const payload = await response.json();
        // The backend may return a single row, a list of rows, or a wrapped result.
        const rows = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.investigation)
            ? payload.investigation
            : Array.isArray(payload?.data)
              ? payload.data
              : Array.isArray(payload?.results)
                ? payload.results
                : [payload];
        const row =
          rows.find((item) => item?.alert_id === selectedAlert || item?.id === selectedAlert) ||
          rows[0] ||
          {};

        const alertId = row.alert_id || row.id || selectedAlert;
        const severity = row.severity || currentAlert?.severity || "unknown";
        const description =
          row.description || currentAlert?.description || "No description available";
        const device = displayValue(row.device || row.hostname || row.device_name);
        const vulnerability = displayValue(
          row.vulnerability || row.vulnerability_name
        );
        const identity = displayValue(row.identity || row.username);
        const asset = displayValue(
          row.connected_asset || row.asset || row.asset_name
        );

        const nextNodes = [
          makeNode(
            "alert",
            "alert",
            `ALERT · ${severity.toUpperCase()}`,
            `${alertId}\n${description}`,
            { x: 40, y: 150 }
          ),
        ];
        const nextEdges = [];

        if (device) {
          nextNodes.push(
            makeNode("device", "device", "DEVICE", device, { x: 300, y: 150 })
          );
          nextEdges.push(makeEdge("alert-device", "alert", "device", "AFFECTS", nodeColors.alert));
        }
        if (vulnerability && device) {
          nextNodes.push(
            makeNode(
              "vulnerability",
              "vulnerability",
              "VULNERABILITY",
              vulnerability,
              { x: 560, y: 35 }
            )
          );
          nextEdges.push(
            makeEdge(
              "device-vulnerability",
              "device",
              "vulnerability",
              "HAS VULNERABILITY",
              nodeColors.vulnerability
            )
          );
        }
        if (identity && device) {
          nextNodes.push(
            makeNode("identity", "identity", "IDENTITY", identity, { x: 560, y: 270 })
          );
          nextEdges.push(
            makeEdge("identity-device", "identity", "device", "ACCESSES", nodeColors.identity)
          );
        }
        if (asset && device) {
          nextNodes.push(
            makeNode("asset", "asset", "CONNECTED ASSET", asset, { x: 820, y: 150 })
          );
          nextEdges.push(
            makeEdge("device-asset", "device", "asset", "CONNECTS TO", nodeColors.asset)
          );
        }

        if (!cancelled) {
          setNodes(nextNodes);
          setEdges(nextEdges);
          setGraphMessage(
            nextNodes.length === 1
              ? `No connected entities are recorded for ${selectedAlert}. Showing the alert node only.`
              : `Showing recorded relationships for ${selectedAlert}.`
          );
        }
      } catch (err) {
        if (!cancelled) {
          setNodes([
            makeNode(
              "alert",
              "alert",
              `ALERT · ${(currentAlert?.severity || "unknown").toUpperCase()}`,
              `${selectedAlert}\n${currentAlert?.description || "No description available"}`,
              { x: 40, y: 150 }
            ),
          ]);
          setEdges([]);
          setGraphMessage(
            `Could not load connected entities from the backend (${err.message}). Showing the selected alert only.`
          );
        }
      } finally {
        if (!cancelled) setGraphLoading(false);
      }
    }

    loadGraph();
    return () => {
      cancelled = true;
    };
  }, [selectedAlert, currentAlert, setNodes, setEdges]);

  return (
    <div>
      <div className="graph-canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.2}
          maxZoom={2}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#263449" gap={22} />
          <Controls />
          <MiniMap
            nodeColor={(node) => nodeColors[node.id] || "#64748b"}
            maskColor="rgba(5, 10, 20, 0.7)"
          />
        </ReactFlow>
      </div>
      <p className="graph-footnote">
        {graphLoading ? "Loading graph for the selected alert…" : graphMessage}
      </p>
    </div>
  );
}

function StatCard({ label, value, description, color }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={{ color }}>
        {value}
      </div>
      <div className="stat-description">{description}</div>
    </div>
  );
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState("ALT-002");
  const [report, setReport] = useState(null);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [apiStatus, setApiStatus] = useState("checking");
  const [error, setError] = useState("");
  const [soundEnabled, setSoundEnabled] = useState(false);
  const soundEnabledRef = useRef(false);
  const previousAlertSnapshot = useRef(null);
  const lastDangerAlert = useRef(null);

  useEffect(() => {
    soundEnabledRef.current = soundEnabled;
  }, [soundEnabled]);

  const loadAlerts = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoadingAlerts(true);

    try {
      const response = await fetch(`${API_URL}/api/alerts`);

      if (!response.ok) {
        throw new Error(`Alerts request failed: HTTP ${response.status}`);
      }

      const data = await response.json();
      setAlerts(data);

      const previous = previousAlertSnapshot.current;
      const currentIds = data.map((alert) => alert.alert_id);
      if (previous) {
        const previousIds = new Set(previous.ids);
        const newCriticalAlert = data.some(
          (alert) =>
            (alert.severity || "").toLowerCase() === "critical" &&
            !previousIds.has(alert.alert_id)
        );
        if (soundEnabledRef.current && newCriticalAlert) {
          playAlertSound("critical");
        }
        if (soundEnabledRef.current && previous.count <= 5 && data.length > 5) {
          playAlertSound("threshold");
        }
      }
      previousAlertSnapshot.current = { ids: currentIds, count: data.length };

      setSelectedAlert((current) => {
        if (data.some((alert) => alert.alert_id === current)) {
          return current;
        }

        return data[0]?.alert_id || "";
      });

      setApiStatus("connected");
      setError("");
    } catch (err) {
      setApiStatus("disconnected");
      setError(
        "Cannot connect to the backend. Start FastAPI on http://127.0.0.1:8000 and refresh."
      );
    } finally {
      if (!silent) setLoadingAlerts(false);
    }
  }, []);

  const checkHealth = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/health`);

      if (!response.ok) {
        throw new Error("Backend health check failed");
      }

      setApiStatus("connected");
    } catch {
      setApiStatus("disconnected");
    }
  }, []);

  const investigateAlert = useCallback(async (alertId) => {
    if (!alertId) return;

    setInvestigating(true);
    setError("");
    setReport(null);

    try {
      const response = await fetch(
        `${API_URL}/api/agent/investigate/${encodeURIComponent(alertId)}`
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || `Investigation failed: HTTP ${response.status}`
        );
      }

      setReport(data);
      setApiStatus("connected");
    } catch (err) {
      setError(
        `${err.message}. Check that the FastAPI backend is running and the selected alert exists.`
      );
    } finally {
      setInvestigating(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts();
    checkHealth();
    // Poll quietly so new alerts can trigger a sound without flashing the page.
    const pollId = window.setInterval(() => loadAlerts({ silent: true }), 15000);
    return () => window.clearInterval(pollId);
  }, [loadAlerts, checkHealth]);

  useEffect(() => {
    if (!report) {
      lastDangerAlert.current = null;
      return;
    }
    const reportAlertId = report.alert?.id || report.alert?.alert_id || selectedAlert;
    if (
      hasDangerousCombination(report) &&
      lastDangerAlert.current !== reportAlertId
    ) {
      lastDangerAlert.current = reportAlertId;
      if (soundEnabledRef.current) playAlertSound("danger");
    }
  }, [report, selectedAlert]);

  const toggleSound = () => {
    const nextValue = !soundEnabled;
    setSoundEnabled(nextValue);
    if (nextValue) {
      // If critical alerts are already on screen, sound one immediately.
      // Otherwise play a short test beep. New critical alerts are still
      // detected by loadAlerts() and will sound during the 15-second poll.
      const hasVisibleCriticalAlert = alerts.some(
        (alert) => (alert.severity || "").toLowerCase() === "critical"
      );
      void playAlertSound(hasVisibleCriticalAlert ? "critical" : "test");
    }
  };

  const currentAlert = alerts.find(
    (alert) => alert.alert_id === selectedAlert
  );

  const severity = (
    report?.alert?.severity ||
    currentAlert?.severity ||
    "unknown"
  ).toLowerCase();

  const findings = Array.isArray(report?.investigation)
    ? report.investigation
    : [];

  const connectedEntities = [
    ...new Set(
      findings.flatMap((item) =>
        Array.isArray(item.connected_entities)
          ? item.connected_entities
          : []
      )
    ),
  ];

  const recommendations = [
    ...new Set(
      findings.flatMap((item) =>
        Array.isArray(item.recommended_actions)
          ? item.recommended_actions
          : []
      )
    ),
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">⬡</div>
          <div>
            <h2>CyberGraph AI</h2>
            <p>Security Intelligence</p>
          </div>
        </div>

        <div className="sidebar-section-title">WORKSPACE</div>

        <button className="nav-item active" type="button">
          <span>◈</span> Security Overview
        </button>

        <button
          className="nav-item"
          type="button"
          onClick={() => document.getElementById("alerts-section")?.scrollIntoView({ behavior: "smooth" })}
        >
          <span>⚠</span> Security Alerts
        </button>

        <button
          className="nav-item"
          type="button"
          onClick={() => document.getElementById("graph-section")?.scrollIntoView({ behavior: "smooth" })}
        >
          <span>◎</span> Attack Graph
        </button>

        <button
          className="nav-item"
          type="button"
          onClick={() => document.getElementById("investigation-section")?.scrollIntoView({ behavior: "smooth" })}
        >
          <span>⌕</span> Investigations
        </button>

        <div className="sidebar-bottom">
          <div className="environment-label">DEMO ENVIRONMENT</div>
          <div className="environment-status">
            <span className={`status-dot ${apiStatus}`} />
            {apiStatus === "connected"
              ? "Backend connected"
              : apiStatus === "checking"
                ? "Checking backend..."
                : "Backend disconnected"}
          </div>
          <p className="sidebar-note">
            Synthetic security data. Investigation results require human
            verification.
          </p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
            <h1>Security Overview</h1>
            <p className="page-subtitle">
              Investigate alerts through connected infrastructure relationships.
            </p>
          </div>

          <div className="topbar-actions">
            <span className={`connection-badge ${apiStatus}`}>
              <span className="status-dot" />
              {apiStatus === "connected"
                ? "SYSTEM ONLINE"
                : apiStatus === "checking"
                  ? "CONNECTING"
                  : "SYSTEM OFFLINE"}
            </span>

            <button
              className="secondary-button"
              type="button"
              onClick={toggleSound}
              aria-pressed={soundEnabled}
              title={soundEnabled ? "Disable alert sounds" : "Enable alert sounds and play a test beep"}
            >
              {soundEnabled ? "🔊 Sound On" : "🔇 Enable Sound"}
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => loadAlerts()}
              disabled={loadingAlerts}
            >
              ↻ Refresh
            </button>
          </div>
        </header>

        <section className="hero-panel" aria-label="CyberGraph AI introduction">
          <div className="hero-copy">
            <div className="hero-kicker">GRAPH-POWERED THREAT INTELLIGENCE</div>
            <h2>See the signal. <span>Trace the path.</span></h2>
            <p>Turn isolated security alerts into an understandable map of your infrastructure. Explore relationships, surface possible exposure, and give analysts a clearer place to start.</p>
          </div>
          <div className="hero-orbit" aria-hidden="true">
            <span className="orbit-point one" />
            <span className="orbit-point two" />
            <div className="orbit-core">⌘</div>
          </div>
          <div className="hero-actions">
            <button className="primary-button" type="button" onClick={() => document.getElementById("alerts-section")?.scrollIntoView({ behavior: "smooth" })}>Explore alerts <span aria-hidden="true">↘</span></button>
            <span className="hero-microcopy">Human-reviewed · Read-only demo</span>
          </div>
        </section>

        {error && (
          <div className="error-banner" role="alert">
            <strong>Connection / investigation notice</strong>
            <span>{error}</span>
          </div>
        )}

        <section className="stats-grid">
          <StatCard
            label="TOTAL ALERTS"
            value={loadingAlerts ? "…" : alerts.length}
            description="Alerts loaded from FalkorDB"
            color="#e2e8f0"
          />

          <StatCard
            label="CRITICAL ALERTS"
            value={
              loadingAlerts
                ? "…"
                : alerts.filter(
                    (alert) =>
                      (alert.severity || "").toLowerCase() === "critical"
                  ).length
            }
            description="Require priority review"
            color="#fb7185"
          />

          <StatCard
            label="GRAPH ENTITIES"
            value={connectedEntities.length || "—"}
            description="Entities in latest report"
            color="#60a5fa"
          />

          <StatCard
            label="ACTIONS EXECUTED"
            value="0"
            description="Human approval required"
            color="#34d399"
          />
        </section>

        <section className="card" id="alerts-section">
          <div className="section-heading">
            <div>
              <div className="eyebrow">DETECTION</div>
              <h2>Security Alerts</h2>
            </div>
            <span className="small-muted">
              {alerts.length} alert{alerts.length === 1 ? "" : "s"} found
            </span>
          </div>

          {loadingAlerts ? (
            <p className="empty-state">Loading alerts from the backend…</p>
          ) : alerts.length === 0 ? (
            <p className="empty-state">
              No alerts returned by the backend.
            </p>
          ) : (
            <div className="alert-list">
              {alerts.map((alert) => (
                <button
                  className={`alert-row ${
                    selectedAlert === alert.alert_id ? "selected" : ""
                  }`}
                  key={alert.alert_id}
                  type="button"
                  onClick={() => {
                    setSelectedAlert(alert.alert_id);
                    setReport(null);
                    setError("");
                  }}
                >
                  <span
                    className={`severity-indicator ${(alert.severity || "unknown").toLowerCase()}`}
                  />

                  <span className="alert-main">
                    <strong>{alert.alert_id}</strong>
                    <span>{alert.description || "No description available"}</span>
                  </span>

                  <span
                    className={`severity-badge ${(alert.severity || "unknown").toLowerCase()}`}
                  >
                    {alert.severity || "Unknown"}
                  </span>

                  <span className="alert-arrow">›</span>
                </button>
              ))}
            </div>
          )}

          <div className="investigate-bar">
            <div>
              <strong>Selected alert: {selectedAlert || "None"}</strong>
              <p>
                Run a graph-based investigation using the backend agent.
              </p>
            </div>

            <button
              className="primary-button"
              type="button"
              disabled={!selectedAlert || investigating || apiStatus === "disconnected"}
              onClick={() => investigateAlert(selectedAlert)}
            >
              {investigating ? "Investigating…" : "⌕ Investigate Alert"}
            </button>
          </div>
        </section>

        <section className="card" id="graph-section">
          <div className="section-heading">
            <div>
              <div className="eyebrow">RELATIONSHIP ANALYSIS</div>
              <h2>Infrastructure Relationship Graph</h2>
              <p className="section-description">
                The graph updates automatically when you select a different alert.
              </p>
            </div>

            <span className="graph-legend">
              <span className="legend-dot" /> Synthetic graph
            </span>
          </div>

          <ReactFlowProvider>
            <RelationshipGraph
              selectedAlert={selectedAlert}
              currentAlert={currentAlert}
            />
          </ReactFlowProvider>
        </section>

        <section className="card" id="investigation-section">
          <div className="section-heading">
            <div>
              <div className="eyebrow">AI-ASSISTED TRIAGE</div>
              <h2>Investigation Report</h2>
            </div>

            {report && (
              <span className={`severity-badge ${severity}`}>
                {severity.toUpperCase()}
              </span>
            )}
          </div>

          {!report && !investigating && (
            <div className="empty-state report-empty">
              <div className="empty-icon">⌕</div>
              <h3>No investigation run yet</h3>
              <p>
                Select an alert above and click “Investigate Alert” to request
                a report from your FastAPI backend.
              </p>
            </div>
          )}

          {investigating && (
            <div className="loading-state">
              <div className="loading-spinner" />
              <div>
                <strong>Investigating {selectedAlert}…</strong>
                <p>Checking recorded relationships and recommendations.</p>
              </div>
            </div>
          )}

          {report && (
            <div className="report-content">
              <div className="report-summary">
                <div>
                  <span className="report-label">ALERT ID</span>
                  <strong>
                    {report.alert?.id ||
                      report.alert?.alert_id ||
                      selectedAlert}
                  </strong>
                </div>

                <div>
                  <span className="report-label">SEVERITY</span>
                  <strong className={`severity-text ${severity}`}>
                    {severity.toUpperCase()}
                  </strong>
                </div>

                <div>
                  <span className="report-label">EXECUTION MODE</span>
                  <strong>Read-only analysis</strong>
                </div>
              </div>

              {report.alert?.description && (
                <div className="report-block">
                  <h3>Alert Description</h3>
                  <p>{report.alert.description}</p>
                </div>
              )}

              <div className="report-block">
                <h3>Connected Entities</h3>

                {connectedEntities.length > 0 ? (
                  <div className="entity-chips">
                    {connectedEntities.map((entity, index) => (
                      <span className="entity-chip" key={`${entity}-${index}`}>
                        {typeof entity === "string"
                          ? entity
                          : entity.name ||
                            entity.id ||
                            JSON.stringify(entity)}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="small-muted">
                    The backend did not return a connected entity list.
                  </p>
                )}
              </div>

              <div className="report-block">
                <h3>Findings</h3>

                {findings.length > 0 ? (
                  <ul className="report-list">
                    {findings.map((item, index) => (
                      <li key={index}>
                        <span className="list-marker">✓</span>
                        <div>
                          <strong>
                            {item.title ||
                              item.finding ||
                              item.name ||
                              `Finding ${index + 1}`}
                          </strong>

                          {item.description && <p>{item.description}</p>}

                          {item.evidence && <p>{item.evidence}</p>}

                          {item.connected_entities &&
                            item.connected_entities.length > 0 && (
                              <p>
                                <span className="inline-label">Entities: </span>
                                {item.connected_entities
                                  .map((entity) =>
                                    typeof entity === "string"
                                      ? entity
                                      : entity.name || entity.id
                                  )
                                  .join(", ")}
                              </p>
                            )}
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="small-muted">
                    No detailed findings were returned.
                  </p>
                )}
              </div>

              <div className="report-block">
                <h3>Recommended Actions</h3>

                {recommendations.length > 0 ? (
                  <ol className="recommendation-list">
                    {recommendations.map((action, index) => (
                      <li key={`${action}-${index}`}>
                        <span className="recommendation-number">
                          {index + 1}
                        </span>
                        <span>
                          {typeof action === "string"
                            ? action
                            : action.description ||
                              action.action ||
                              JSON.stringify(action)}
                        </span>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="small-muted">
                    No recommended actions were returned by the backend.
                  </p>
                )}
              </div>

              {report.evidence_note && (
                <div className="evidence-note">
                  <strong>Evidence and limitations</strong>
                  <p>{report.evidence_note}</p>
                </div>
              )}

              <div className="safe-action-notice">
                <span>✓</span>
                <p>
                  <strong>No response actions were executed.</strong> Verify
                  the evidence and obtain authorized human approval before
                  taking action in a real environment.
                </p>
              </div>

              <details className="raw-report">
                <summary>View raw backend response</summary>
                <pre>{JSON.stringify(report, null, 2)}</pre>
              </details>
            </div>
          )}
        </section>

        <footer className="app-footer">
          <span>CyberGraph AI</span>
          <span>Graph-powered security investigation · Demo environment</span>
        </footer>
      </main>
    </div>
  );
}

export default App;