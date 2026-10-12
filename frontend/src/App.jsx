import { useCallback, useEffect, useState } from "react";
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

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8001";

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

function RelationshipGraph({ selectedAlert, currentAlert, token }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphMessage, setGraphMessage] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadGraph() {
      if (!token) {
        setNodes([]);
        setEdges([]);
        setGraphMessage("Sign in to load investigation relationships.");
        return;
      }

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
          `${API_URL}/api/investigations/${encodeURIComponent(selectedAlert)}`,
          { headers: { Authorization: `Bearer ${token}` } }
        );

        if (!response.ok) {
          throw new Error(`Graph request failed: HTTP ${response.status}`);
        }

        const payload = await response.json();
        // FastAPI returns { investigation: [...], note: "..." }.
        // Accept that shape plus common list/wrapped response shapes.
        const rows = Array.isArray(payload?.investigation)
          ? payload.investigation
          : Array.isArray(payload)
            ? payload
            : Array.isArray(payload?.data)
              ? payload.data
              : Array.isArray(payload?.results)
                ? payload.results
                : [payload];

        const validRows = rows.filter((item) => item && typeof item === "object");
        const firstRow =
          validRows.find((item) => item?.alert_id === selectedAlert || item?.id === selectedAlert) ||
          validRows[0] ||
          {};
        const alertId = firstRow.alert_id || firstRow.id || selectedAlert;
        const severity = firstRow.severity || currentAlert?.severity || "unknown";
        const description =
          firstRow.description || currentAlert?.description || "No description available";

        const nextNodes = [
          makeNode(
            "alert",
            "alert",
            `ALERT · ${String(severity).toUpperCase()}`,
            `${alertId}\n${description}`,
            { x: 40, y: 150 }
          ),
        ];
        const nextEdges = [];
        const seenNodes = new Set(["alert"]);
        const addNode = (id, type, title, value, position) => {
          if (value && !seenNodes.has(id)) {
            nextNodes.push(makeNode(id, type, title, value, position));
            seenNodes.add(id);
          }
        };
        const addEdge = (id, source, target, label, color) => {
          if (!nextEdges.some((edge) => edge.id === id)) {
            nextEdges.push(makeEdge(id, source, target, label, color));
          }
        };

        validRows.forEach((row, index) => {
          const device = displayValue(row.device || row.hostname || row.device_name);
          const vulnerability = displayValue(row.vulnerability || row.vulnerability_name);
          const identity = displayValue(row.identity || row.username);
          const asset = displayValue(row.connected_asset || row.asset || row.asset_name);
          const suffix = (value) => String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || String(index);

          if (device) {
            const deviceId = `device-${suffix(device)}`;
            addNode(deviceId, "device", "DEVICE", device, { x: 300, y: 150 + index * 100 });
            addEdge(`alert-${deviceId}`, "alert", deviceId, "AFFECTS", nodeColors.alert);

            if (vulnerability) {
              const vulnId = `vulnerability-${suffix(vulnerability)}`;
              addNode(vulnId, "vulnerability", "VULNERABILITY", vulnerability, { x: 560, y: 35 + index * 90 });
              addEdge(`${deviceId}-${vulnId}`, deviceId, vulnId, "HAS VULNERABILITY", nodeColors.vulnerability);
            }
            if (asset) {
              const assetId = `asset-${suffix(asset)}`;
              addNode(assetId, "asset", "CONNECTED ASSET", asset, { x: 820, y: 150 + index * 100 });
              addEdge(`${deviceId}-${assetId}`, deviceId, assetId, "CONNECTS TO", nodeColors.asset);
            }
            if (identity) {
              const identityId = `identity-${suffix(identity)}`;
              addNode(identityId, "identity", "IDENTITY", identity, { x: 560, y: 270 + index * 90 });
              addEdge(`${identityId}-${deviceId}`, identityId, deviceId, "ACCESSES", nodeColors.identity);
            }
          }
        });

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
  }, [selectedAlert, currentAlert, token, setNodes, setEdges]);

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
  const [activeSection, setActiveSection] = useState("overview-section");
  const [token, setToken] = useState(() => localStorage.getItem("cybergraph_access_token") || "");
  const [authMode, setAuthMode] = useState("login");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState("");
  const [userEmail, setUserEmail] = useState(() => localStorage.getItem("cybergraph_user_email") || "");

  const loadAlerts = useCallback(async () => {
    setLoadingAlerts(true);

    try {
      if (!token) {
        setAlerts([]);
        setApiStatus("checking");
        setLoadingAlerts(false);
        return;
      }

      const response = await fetch(`${API_URL}/api/alerts`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        throw new Error(`Alerts request failed: HTTP ${response.status}`);
      }

      const data = await response.json();
      setAlerts(data);

      setSelectedAlert((current) => {
        if (data.some((alert) => alert.alert_id === current)) {
          return current;
        }

        return data[0]?.alert_id || "";
      });

      setApiStatus("connected");
      setError("");
    } catch (err) {
      if (String(err.message).includes("HTTP 401") || String(err.message).includes("HTTP 403")) {
        localStorage.removeItem("cybergraph_access_token");
        localStorage.removeItem("cybergraph_user_email");
        setToken("");
        setUserEmail("");
        setApiStatus("connected");
        setError("Your session expired. Please sign in again.");
      } else {
        setApiStatus("disconnected");
        setError(
          `${err.message}. Check that the FastAPI backend is running at ${API_URL}.`
        );
      }
    } finally {
      setLoadingAlerts(false);
    }
  }, [token]);

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
        `${API_URL}/api/agent/investigate/${encodeURIComponent(alertId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
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
  }, [token]);

  const submitAuth = async (event) => {
    event.preventDefault();
    setAuthBusy(true);
    setAuthError("");
    setError("");
    try {
      const endpoint = authMode === "login" ? "/api/auth/login" : "/api/auth/register";
      const response = await fetch(`${API_URL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: authEmail.trim(), password: authPassword }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = Array.isArray(data.detail)
          ? data.detail.map((item) => item.msg || JSON.stringify(item)).join(", ")
          : data.detail || data.message || `Authentication failed (HTTP ${response.status})`;
        throw new Error(detail);
      }
      if (!data.access_token) throw new Error("The backend did not return an access token.");
      localStorage.setItem("cybergraph_access_token", data.access_token);
      localStorage.setItem("cybergraph_user_email", data.user?.email || authEmail.trim());
      setToken(data.access_token);
      setUserEmail(data.user?.email || authEmail.trim());
      setAuthPassword("");
      setAuthError("");
    } catch (err) {
      setAuthError(err.message || "Could not sign in. Please try again.");
    } finally {
      setAuthBusy(false);
    }
  };

  const signOut = () => {
    localStorage.removeItem("cybergraph_access_token");
    localStorage.removeItem("cybergraph_user_email");
    setToken("");
    setUserEmail("");
    setAlerts([]);
    setReport(null);
    setError("");
    setAuthMode("login");
  };

  useEffect(() => {
    checkHealth();
    if (token) loadAlerts();
    else {
      setAlerts([]);
      setLoadingAlerts(false);
    }
  }, [loadAlerts, checkHealth, token]);

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


  const escapeReportHtml = (value) =>
    String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

  const getReportHtml = () => {
    const alertId =
      report?.alert?.id || report?.alert?.alert_id || selectedAlert;
    const description = report?.alert?.description || "No alert description was returned.";
    const entityRows = connectedEntities.length
      ? connectedEntities.map((entity) => {
          const value = typeof entity === "string"
            ? entity
            : entity?.name || entity?.id || JSON.stringify(entity);
          return `<li>${escapeReportHtml(value)}</li>`;
        }).join("")
      : "<li>No connected entities were returned by the backend.</li>";
    const findingRows = findings.length
      ? findings.map((item, index) => {
          const title = item?.title || item?.finding || item?.name || `Finding ${index + 1}`;
          const details = [item?.description, item?.evidence].filter(Boolean)
            .map(escapeReportHtml).join("<br>");
          return `<li><strong>${escapeReportHtml(title)}</strong>${details ? `<p>${details}</p>` : ""}</li>`;
        }).join("")
      : "<li>No detailed findings were returned.</li>";
    const actionRows = recommendations.length
      ? recommendations.map((action) => {
          const value = typeof action === "string"
            ? action
            : action?.description || action?.action || JSON.stringify(action);
          return `<li>${escapeReportHtml(value)}</li>`;
        }).join("")
      : "<li>No recommended actions were returned by the backend.</li>";
    const evidenceNote = report?.evidence_note
      ? `<section><h2>Evidence and limitations</h2><p>${escapeReportHtml(report.evidence_note)}</p></section>`
      : "";
    const generatedAt = new Date().toLocaleString();

    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberGraph AI Investigation Report - ${escapeReportHtml(alertId)}</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;color:#172033;line-height:1.55;max-width:900px;margin:36px auto;padding:0 24px}
header{border-bottom:3px solid #2563eb;padding-bottom:18px;margin-bottom:24px}
h1{margin:0 0 6px;font-size:28px}h2{font-size:18px;margin:24px 0 8px;color:#1d4ed8}
.meta{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:18px 0}
.meta div{background:#f1f5f9;padding:12px;border-radius:8px;overflow-wrap:anywhere}
.label{display:block;font-size:11px;letter-spacing:1px;color:#64748b;font-weight:bold;margin-bottom:4px}
.notice{background:#eff6ff;border-left:4px solid #2563eb;padding:12px;margin-top:24px}
li{margin:8px 0}footer{border-top:1px solid #cbd5e1;margin-top:30px;padding-top:12px;color:#64748b;font-size:12px}
@media print{body{margin:0;max-width:none;padding:0 8mm}button{display:none}.meta{break-inside:avoid}section{break-inside:avoid}}
</style></head><body>
<header><h1>CyberGraph AI</h1><div>Security Investigation Report</div></header>
<div class="meta">
<div><span class="label">ALERT ID</span><strong>${escapeReportHtml(alertId)}</strong></div>
<div><span class="label">SEVERITY</span><strong>${escapeReportHtml(severity.toUpperCase())}</strong></div>
<div><span class="label">EXECUTION MODE</span><strong>Read-only analysis</strong></div>
</div>
<section><h2>Alert Description</h2><p>${escapeReportHtml(description)}</p></section>
<section><h2>Connected Entities</h2><ul>${entityRows}</ul></section>
<section><h2>Findings</h2><ul>${findingRows}</ul></section>
<section><h2>Recommended Actions</h2><ol>${actionRows}</ol></section>
${evidenceNote}
<div class="notice"><strong>Safety notice:</strong> No response actions were executed by this report generator. Verify evidence and obtain authorized human approval before acting in a real environment.</div>
<footer>Generated by CyberGraph AI on ${escapeReportHtml(generatedAt)}. This report reflects the data returned by the backend at generation time.</footer>
</body></html>`;
  };

  const downloadReport = () => {
    if (!report) return;
    const html = getReportHtml();
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `CyberGraph-Report-${report?.alert?.id || report?.alert?.alert_id || selectedAlert}.html`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const printReport = () => {
    if (!report) return;
    const reportWindow = window.open("", "_blank", "width=900,height=700");
    if (!reportWindow) {
      setError("The report window was blocked. Allow pop-ups for this site, then try Print / Save PDF again.");
      return;
    }
    reportWindow.document.open();
    reportWindow.document.write(getReportHtml());
    reportWindow.document.close();
    reportWindow.focus();
    reportWindow.onload = () => reportWindow.print();
  };

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

        {[
          { id: "overview-section", icon: "◈", label: "Security Overview" },
          { id: "statistics-section", icon: "▦", label: "Dashboard Statistics" },
          { id: "alerts-section", icon: "⚠", label: "Security Alerts" },
          { id: "graph-section", icon: "◎", label: "Attack Graph" },
          { id: "investigation-section", icon: "⌕", label: "Investigations & Reports" },
        ].map((item) => (
          <button
            key={item.id}
            className={`nav-item ${activeSection === item.id ? "active" : ""}`}
            type="button"
            onClick={() => {
              setActiveSection(item.id);
              document.getElementById(item.id)?.scrollIntoView({
                behavior: "smooth",
                block: "start",
              });
            }}
          >
            <span>{item.icon}</span> {item.label}
          </button>
        ))}

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
        <header className="topbar" id="overview-section">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
            <h1>Security Overview</h1>
            <p className="page-subtitle">
              Investigate alerts through connected infrastructure relationships.
            </p>
          </div>

          <div className="topbar-actions">
            {token && (
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 8 }}>
                <span style={{ color: "#cbd5e1", fontSize: 12 }}>{userEmail}</span>
                <button type="button" className="refresh-button" onClick={signOut}>Sign out</button>
              </div>
            )}
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
              onClick={loadAlerts}
              disabled={loadingAlerts}
            >
              ↻ Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="error-banner" role="alert">
            <strong>Connection / investigation notice</strong>
            <span>{error}</span>
          </div>
        )}

        <section className="stats-grid" id="statistics-section">
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
              token={token}
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
              <div className="report-actions" style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                <span className={`severity-badge ${severity}`}>
                  {severity.toUpperCase()}
                </span>
                <button type="button" className="secondary-button" onClick={downloadReport}>
                  Download HTML Report
                </button>
                <button type="button" className="primary-button" onClick={printReport}>
                  Print / Save PDF
                </button>
              </div>
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

      {!token && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 1000,
          background: "rgba(3, 8, 18, 0.86)", backdropFilter: "blur(8px)",
          display: "grid", placeItems: "center", padding: 20
        }}>
          <form onSubmit={submitAuth} style={{
            width: "min(440px, 100%)", background: "#0f1b2d",
            border: "1px solid #293b54", borderRadius: 18, padding: 30,
            boxShadow: "0 25px 80px rgba(0,0,0,.45)", color: "#e2e8f0"
          }}>
            <div style={{ fontSize: 12, letterSpacing: 2, color: "#60a5fa", fontWeight: 700 }}>
              CYBERGRAPH AI
            </div>
            <h2 style={{ margin: "10px 0 8px", fontSize: 25 }}>
              {authMode === "login" ? "Sign in to your workspace" : "Create your account"}
            </h2>
            <p style={{ color: "#94a3b8", fontSize: 13, lineHeight: 1.6, marginBottom: 22 }}>
              Authentication is required to access alerts and investigation data.
            </p>
            <label style={{ display: "block", fontSize: 12, marginBottom: 7 }}>Email address</label>
            <input
              type="email" required autoComplete="email" value={authEmail}
              onChange={(e) => setAuthEmail(e.target.value)}
              placeholder="you@example.com"
              style={{ boxSizing: "border-box", width: "100%", padding: "12px 13px", borderRadius: 8,
                border: "1px solid #334155", background: "#091321", color: "#f8fafc", marginBottom: 16 }}
            />
            <label style={{ display: "block", fontSize: 12, marginBottom: 7 }}>Password</label>
            <input
              type="password" required autoComplete={authMode === "login" ? "current-password" : "new-password"}
              minLength={authMode === "register" ? 12 : 1} value={authPassword}
              onChange={(e) => setAuthPassword(e.target.value)}
              placeholder={authMode === "register" ? "At least 12 characters" : "Your password"}
              style={{ boxSizing: "border-box", width: "100%", padding: "12px 13px", borderRadius: 8,
                border: "1px solid #334155", background: "#091321", color: "#f8fafc", marginBottom: 12 }}
            />
            {authError && <p role="alert" style={{ color: "#fda4af", fontSize: 13, margin: "8px 0 14px" }}>{authError}</p>}
            <button type="submit" disabled={authBusy} style={{
              width: "100%", padding: "12px 14px", border: 0, borderRadius: 8,
              background: "#2563eb", color: "white", fontWeight: 700, cursor: authBusy ? "wait" : "pointer",
              opacity: authBusy ? 0.7 : 1, marginTop: 5
            }}>
              {authBusy ? "Please wait…" : authMode === "login" ? "Sign in" : "Create account"}
            </button>
            <p style={{ color: "#94a3b8", fontSize: 13, textAlign: "center", marginTop: 18 }}>
              {authMode === "login" ? "Don't have an account?" : "Already registered?"}{" "}
              <button type="button" onClick={() => { setAuthMode(authMode === "login" ? "register" : "login"); setAuthError(""); }}
                style={{ color: "#93c5fd", background: "none", border: 0, cursor: "pointer", fontWeight: 700 }}>
                {authMode === "login" ? "Create one" : "Sign in"}
              </button>
            </p>
            {authMode === "register" && (
              <p style={{ color: "#64748b", fontSize: 11, lineHeight: 1.5, marginBottom: 0 }}>
                The backend requires passwords to contain at least 12 characters.
              </p>
            )}
          </form>
        </div>
      )}
    </div>
  );
}

export default App;

