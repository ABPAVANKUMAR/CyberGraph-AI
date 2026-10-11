import { useCallback, useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlowProvider,
} from "reactflow";
import "reactflow/dist/style.css";
import "./App.css";

// Set VITE_API_URL in Vercel Project Settings → Environment Variables.
// Local development falls back to FastAPI on localhost.
const API_URL = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
  });

  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message =
      typeof body === "object" && body !== null
        ? body.detail || body.message || JSON.stringify(body)
        : body || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return body;
}

function errorMessage(error) {
  return error instanceof Error ? error.message : "An unexpected error occurred.";
}

function severityColor(severity) {
  switch (String(severity || "").toLowerCase()) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#f59e0b";
    case "low": return "#22c55e";
    default: return "#94a3b8";
  }
}

function GraphNode({ data }) {
  const colors = {
    Alert: "#ef4444",
    Device: "#3b82f6",
    Vulnerability: "#f59e0b",
    Identity: "#a855f7",
    Asset: "#10b981",
  };
  const color = colors[data.type] || "#64748b";

  return (
    <div style={{
      minWidth: 150, padding: 14, borderRadius: 12,
      border: `2px solid ${color}`, background: "#111827",
      color: "#f9fafb", boxShadow: `0 0 14px ${color}35`,
    }}>
      <Handle type="target" position={Position.Top} />
      <div style={{
        color, fontSize: 11, fontWeight: 800, textTransform: "uppercase",
        letterSpacing: 1, marginBottom: 7,
      }}>{data.type || "Node"}</div>
      <div style={{ fontSize: 14, fontWeight: 700 }}>{data.label || "Unnamed node"}</div>
      {data.subtitle && <div style={{
        color: "#9ca3af", fontSize: 11, marginTop: 6,
        maxWidth: 180, overflowWrap: "anywhere",
      }}>{data.subtitle}</div>}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

const nodeTypes = { graphNode: GraphNode };

function SummaryCard({ title, value, detail, accent }) {
  return (
    <div style={{ ...panelStyle, minWidth: 0 }}>
      <div style={{ color: "#94a3b8", fontSize: 10, fontWeight: 800, letterSpacing: 1 }}>{title}</div>
      <div style={{ color: accent, fontSize: 27, fontWeight: 800, marginTop: 12, overflowWrap: "anywhere" }}>{value}</div>
      <div style={{ color: "#64748b", fontSize: 11, marginTop: 7 }}>{detail}</div>
    </div>
  );
}

function PanelHeading({ title, subtitle }) {
  return (
    <div style={{ borderBottom: "1px solid #253247", paddingBottom: 14, marginBottom: 16 }}>
      <div style={{ fontSize: 15, fontWeight: 800 }}>{title}</div>
      <div style={{ color: "#94a3b8", fontSize: 11, marginTop: 5, lineHeight: 1.5 }}>{subtitle}</div>
    </div>
  );
}

function DetailRow({ label, value, valueColor }) {
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "minmax(100px, 0.8fr) minmax(0, 1.2fr)",
      gap: 12, paddingBottom: 10, borderBottom: "1px solid #1f2937",
    }}>
      <div style={{ color: "#94a3b8", fontSize: 12 }}>{label}</div>
      <div style={{ color: valueColor || "#e5e7eb", fontSize: 12, fontWeight: 600, overflowWrap: "anywhere" }}>{value || "Unavailable"}</div>
    </div>
  );
}

function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [agentResult, setAgentResult] = useState(null);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [loadingInvestigation, setLoadingInvestigation] = useState(false);
  const [loadingAgent, setLoadingAgent] = useState(false);
  const [backendStatus, setBackendStatus] = useState("checking");
  const [pageError, setPageError] = useState("");
  const [graphError, setGraphError] = useState("");

  const checkBackend = useCallback(async () => {
    try {
      await apiRequest("/api/health");
      setBackendStatus("online");
    } catch {
      setBackendStatus("offline");
    }
  }, []);

  const loadAlerts = useCallback(async () => {
    setLoadingAlerts(true);
    setPageError("");
    try {
      const result = await apiRequest("/api/alerts");
      const list = Array.isArray(result)
        ? result
        : Array.isArray(result?.alerts)
          ? result.alerts
          : Array.isArray(result?.results)
            ? result.results
            : [];
      setAlerts(list);
      setBackendStatus("online");
      setSelectedAlert((current) => {
        if (!list.length) return null;
        if (!current) return list[0];
        return list.find((item) =>
          String(item.alert_id ?? item.id) === String(current.alert_id ?? current.id)
        ) || list[0];
      });
      if (!list.length) {
        setInvestigation(null);
        setAgentResult(null);
      }
    } catch (error) {
      setAlerts([]);
      setSelectedAlert(null);
      setInvestigation(null);
      setAgentResult(null);
      setBackendStatus("offline");
      setPageError(`Could not load alerts from the backend: ${errorMessage(error)}`);
    } finally {
      setLoadingAlerts(false);
    }
  }, []);

  const loadInvestigation = useCallback(async (alert) => {
    const id = alert?.alert_id ?? alert?.id;
    if (id == null) {
      setGraphError("This alert does not contain an alert ID.");
      return;
    }
    setSelectedAlert(alert);
    setLoadingInvestigation(true);
    setInvestigation(null);
    setAgentResult(null);
    setGraphError("");
    try {
      const result = await apiRequest(`/api/investigations/${encodeURIComponent(id)}`);
      setInvestigation(result);
      setBackendStatus("online");
    } catch (error) {
      setGraphError(`Could not load the investigation: ${errorMessage(error)}`);
      setBackendStatus("offline");
    } finally {
      setLoadingInvestigation(false);
    }
  }, []);

  const runAgent = useCallback(async () => {
    const id = selectedAlert?.alert_id ?? selectedAlert?.id;
    if (id == null) {
      setGraphError("Select an alert before starting an investigation.");
      return;
    }
    setLoadingAgent(true);
    setAgentResult(null);
    setGraphError("");
    try {
      const result = await apiRequest(`/api/agent/investigate/${encodeURIComponent(id)}`);
      setAgentResult(result);
      setBackendStatus("online");
    } catch (error) {
      setGraphError(`The investigation agent could not run: ${errorMessage(error)}`);
      setBackendStatus("offline");
    } finally {
      setLoadingAgent(false);
    }
  }, [selectedAlert]);

  useEffect(() => {
    checkBackend();
    loadAlerts();
    const timer = window.setInterval(checkBackend, 30000);
    return () => window.clearInterval(timer);
  }, [checkBackend, loadAlerts]);

  useEffect(() => {
    if (selectedAlert) loadInvestigation(selectedAlert);
  }, [selectedAlert?.alert_id, selectedAlert?.id, loadInvestigation]);

  const records = Array.isArray(investigation?.investigation)
    ? investigation.investigation
    : Array.isArray(investigation?.results)
      ? investigation.results
      : Array.isArray(investigation)
        ? investigation
        : investigation
          ? [investigation]
          : [];

  const record = records.find((item) =>
    String(item.alert_id ?? item.id) === String(selectedAlert?.alert_id ?? selectedAlert?.id)
  ) || records[0];

  const graph = useMemo(() => {
    if (!record) return { nodes: [], edges: [] };
    const defs = [
      { id: "alert", type: "Alert", label: record.alert_id || selectedAlert?.alert_id || "Alert", subtitle: record.description || "Security alert" },
      { id: "device", type: "Device", label: record.device || "Device unavailable", subtitle: "Affected device" },
      { id: "vulnerability", type: "Vulnerability", label: record.vulnerability || "Vulnerability unavailable", subtitle: "Associated vulnerability" },
      { id: "identity", type: "Identity", label: record.identity || "Identity unavailable", subtitle: "Associated identity" },
      { id: "asset", type: "Asset", label: record.connected_asset || "Asset unavailable", subtitle: "Connected asset" },
    ];
    const positions = {
      alert: { x: 300, y: 20 },
      device: { x: 40, y: 210 },
      vulnerability: { x: 300, y: 210 },
      identity: { x: 560, y: 210 },
      asset: { x: 300, y: 410 },
    };
    const nodes = defs.map((item) => ({
      id: item.id, type: "graphNode", position: positions[item.id],
      data: { type: item.type, label: item.label, subtitle: item.subtitle },
    }));
    const links = [
      { source: "alert", target: "device", label: "AFFECTS" },
      { source: "device", target: "vulnerability", label: "HAS_VULNERABILITY" },
      { source: "device", target: "identity", label: "ACCESSES" },
      { source: "identity", target: "asset", label: "CONNECTS_TO" },
    ];
    const edges = links.map((item, index) => ({
      id: `edge-${index}`, ...item, animated: true,
      style: { stroke: "#64748b", strokeWidth: 2 },
      labelStyle: { fill: "#cbd5e1", fontSize: 10, fontWeight: 600 },
      labelBgStyle: { fill: "#111827", fillOpacity: 0.9 },
    }));
    return { nodes, edges };
  }, [record, selectedAlert]);

  return (
    <div style={{
      minHeight: "100vh", background: "#080d18", color: "#e5e7eb",
      fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
    }}>
      <header style={{
        display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between",
        gap: 16, padding: "20px 28px", borderBottom: "1px solid #1f2937", background: "#0b1220",
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 22, fontWeight: 800, letterSpacing: -0.5 }}>
            <span style={{ color: "#38bdf8" }}>◈</span> CyberGraph AI
          </div>
          <div style={{ color: "#94a3b8", fontSize: 12, marginTop: 5 }}>Graph-powered cybersecurity investigation dashboard</div>
        </div>
        <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <div style={{ padding: "8px 12px", border: "1px solid #263449", borderRadius: 8, fontSize: 12, color: "#cbd5e1" }}>
            Backend: <span style={{ color: backendStatus === "online" ? "#4ade80" : backendStatus === "offline" ? "#f87171" : "#facc15", fontWeight: 700 }}>
              {backendStatus === "online" ? "ONLINE" : backendStatus === "offline" ? "OFFLINE" : "CHECKING"}
            </span>
          </div>
          <button onClick={() => { checkBackend(); loadAlerts(); }} disabled={loadingAlerts} style={buttonStyle("#1e293b")}>
            {loadingAlerts ? "Refreshing..." : "↻ Refresh"}
          </button>
        </div>
      </header>

      <main style={{ padding: 24, maxWidth: 1600, margin: "0 auto" }}>
        <div style={{ border: "1px solid #334155", borderRadius: 10, background: "#0f172a", padding: "12px 16px", marginBottom: 22, fontSize: 12, color: "#cbd5e1", lineHeight: 1.6 }}>
          <strong style={{ color: "#38bdf8" }}>Demo environment:</strong> This dashboard uses demonstration data. Graph relationships and investigation recommendations do not independently establish that a real cyberattack occurred. No response actions are executed automatically.
        </div>

        {pageError && <div style={errorStyle}>
          <strong>Backend connection issue</strong>
          <div style={{ marginTop: 5 }}>{pageError}</div>
          <div style={{ marginTop: 8, color: "#cbd5e1", fontSize: 12 }}>Configured API: {API_URL}</div>
        </div>}

        <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 14, marginBottom: 24 }}>
          <SummaryCard title="TOTAL ALERTS" value={loadingAlerts ? "…" : alerts.length} detail="Alerts returned by the API" accent="#38bdf8" />
          <SummaryCard title="CRITICAL ALERTS" value={loadingAlerts ? "…" : alerts.filter((a) => String(a.severity || "").toLowerCase() === "critical").length} detail="Marked critical in alert data" accent="#ef4444" />
          <SummaryCard title="SELECTED ALERT" value={selectedAlert ? selectedAlert.alert_id || selectedAlert.id || "Selected" : "None"} detail={selectedAlert?.severity || "Choose an alert below"} accent="#a78bfa" />
          <SummaryCard title="GRAPH STATUS" value={record ? "Loaded" : "Waiting"} detail="Selected investigation data" accent="#34d399" />
        </section>

        <section className="dashboard-layout" style={{ display: "grid", gridTemplateColumns: "minmax(260px, 340px) minmax(0, 1fr)", gap: 20, alignItems: "start" }}>
          <section style={panelStyle}>
            <PanelHeading title="Security Alerts" subtitle="Select an alert to investigate" />
            {loadingAlerts ? <p style={mutedStyle}>Loading alerts…</p> : alerts.length === 0 ? <p style={mutedStyle}>No alerts were returned by the backend.</p> : (
              <div style={{ display: "grid", gap: 10 }}>
                {alerts.map((alert, index) => {
                  const id = alert.alert_id ?? alert.id ?? `alert-${index}`;
                  const selected = String(id) === String(selectedAlert?.alert_id ?? selectedAlert?.id);
                  return <button key={String(id)} onClick={() => loadInvestigation(alert)} style={{
                    textAlign: "left", cursor: "pointer", borderRadius: 10, padding: 14, color: "#e5e7eb",
                    background: selected ? "#172554" : "#0b1220",
                    border: selected ? "1px solid #3b82f6" : "1px solid #253247",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                      <strong style={{ fontSize: 13 }}>{id}</strong>
                      <span style={{ color: severityColor(alert.severity), fontSize: 10, fontWeight: 800, textTransform: "uppercase" }}>{alert.severity || "Unknown"}</span>
                    </div>
                    <div style={{ color: "#cbd5e1", fontSize: 12, lineHeight: 1.5 }}>{alert.description || "No description available"}</div>
                  </button>;
                })}
              </div>
            )}
          </section>

          <section style={{ ...panelStyle, minWidth: 0 }}>
            <PanelHeading title="Investigation Graph" subtitle={selectedAlert ? `Relationships for ${selectedAlert.alert_id || selectedAlert.id}` : "Choose an alert to explore its relationships"} />
            {loadingInvestigation ? <div style={graphMessageStyle}>Loading graph investigation…</div> : graphError ? <div style={{ ...graphMessageStyle, color: "#fca5a5" }}>{graphError}</div> : graph.nodes.length > 0 ? (
              <div style={{ height: 510, borderRadius: 10, overflow: "hidden", border: "1px solid #263449", background: "#080d18" }}>
                <ReactFlow nodes={graph.nodes} edges={graph.edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.2 }} minZoom={0.3} maxZoom={1.6} proOptions={{ hideAttribution: true }}>
                  <Background color="#263449" gap={22} />
                  <Controls />
                  <MiniMap nodeColor={(node) => ({ Alert: "#ef4444", Device: "#3b82f6", Vulnerability: "#f59e0b", Identity: "#a855f7", Asset: "#10b981" }[node.data?.type] || "#64748b")} style={{ background: "#111827" }} />
                </ReactFlow>
              </div>
            ) : <div style={graphMessageStyle}>Select an alert to load its investigation graph.</div>}
            {investigation?.note && <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: "#111827", color: "#94a3b8", fontSize: 11, lineHeight: 1.6 }}>{investigation.note}</div>}
            {record && <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 14, color: "#94a3b8", fontSize: 11 }}>
              <span style={tagStyle}>5 displayed node types</span><span style={tagStyle}>4 displayed relationship types</span><span style={tagStyle}>Synthetic demonstration data</span>
            </div>}
          </section>
        </section>

        <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 20, marginTop: 20 }}>
          <section style={panelStyle}>
            <PanelHeading title="Investigation Details" subtitle="Information returned by the graph API" />
            {record ? <div style={{ display: "grid", gap: 14 }}>
              <DetailRow label="Alert ID" value={record.alert_id} />
              <DetailRow label="Severity" value={record.severity || "Unknown"} valueColor={severityColor(record.severity)} />
              <DetailRow label="Description" value={record.description} />
              <DetailRow label="Device" value={record.device} />
              <DetailRow label="Vulnerability" value={record.vulnerability} />
              <DetailRow label="Identity" value={record.identity} />
              <DetailRow label="Connected asset" value={record.connected_asset} />
            </div> : <p style={mutedStyle}>Investigation details will appear after an alert is selected.</p>}
          </section>

          <section style={panelStyle}>
            <PanelHeading title="AI Investigation Assistant" subtitle="Request a structured investigation from the backend" />
            <p style={{ color: "#94a3b8", fontSize: 12, lineHeight: 1.7, marginTop: 0 }}>
              Request the configured investigation endpoint for analysis and recommendations. The endpoint may use deterministic rules; this interface does not assume an external LLM is connected.
            </p>
            <button onClick={runAgent} disabled={!selectedAlert || loadingAgent} style={{ ...buttonStyle("#0369a1"), width: "100%", padding: "12px 16px", opacity: !selectedAlert || loadingAgent ? 0.55 : 1, cursor: !selectedAlert || loadingAgent ? "not-allowed" : "pointer" }}>
              {loadingAgent ? "Investigating…" : "Run Investigation"}
            </button>
            {agentResult && <div style={{ marginTop: 16, borderRadius: 10, border: "1px solid #334155", background: "#080d18", padding: 14 }}>
              <div style={{ color: "#34d399", fontSize: 12, fontWeight: 800, marginBottom: 10 }}>Investigation response received</div>
              <pre style={{ margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere", color: "#cbd5e1", fontSize: 11, lineHeight: 1.7, maxHeight: 360, overflow: "auto" }}>{JSON.stringify(agentResult, null, 2)}</pre>
            </div>}
            {!agentResult && <div style={{ marginTop: 14, padding: 12, background: "#111827", borderRadius: 8, fontSize: 11, color: "#94a3b8", lineHeight: 1.6 }}>
              <strong style={{ color: "#e5e7eb" }}>Safety:</strong> Running an investigation retrieves information and recommendations. It does not authorize or execute containment, account suspension, device isolation, or other security actions.
            </div>}
          </section>
        </section>

        <footer style={{ borderTop: "1px solid #1f2937", marginTop: 28, paddingTop: 18, color: "#64748b", fontSize: 11, lineHeight: 1.8 }}>
          CyberGraph AI · Graph-based security investigation prototype<br />
          API endpoint: {API_URL}<br />
          Use only authorized systems and verified security data for real-world investigations.
        </footer>
      </main>
      <style>{`
        @media (max-width: 850px) {
          .dashboard-layout { grid-template-columns: minmax(0, 1fr) !important; }
        }
        button:focus-visible { outline: 2px solid #38bdf8; outline-offset: 3px; }
        button:disabled { cursor: not-allowed; }
      `}</style>
    </div>
  );
}

const panelStyle = {
  border: "1px solid #253247", borderRadius: 12, background: "#0b1220", padding: 18,
};
const mutedStyle = { color: "#94a3b8", fontSize: 12, lineHeight: 1.7 };
const graphMessageStyle = {
  minHeight: 220, display: "flex", alignItems: "center", justifyContent: "center",
  textAlign: "center", padding: 24, color: "#94a3b8", fontSize: 13, lineHeight: 1.7,
  border: "1px dashed #334155", borderRadius: 10,
};
const errorStyle = {
  marginBottom: 20, padding: 16, border: "1px solid #7f1d1d", borderRadius: 10,
  background: "#2a1117", color: "#fca5a5", fontSize: 12, lineHeight: 1.6,
};
const tagStyle = { border: "1px solid #334155", borderRadius: 20, padding: "5px 9px", background: "#111827" };
function buttonStyle(background) {
  return {
    border: "1px solid #334155", borderRadius: 8, padding: "9px 13px",
    background, color: "#f8fafc", fontSize: 12, fontWeight: 700, cursor: "pointer",
  };
}

export default function App() {
  return <ReactFlowProvider><Dashboard /></ReactFlowProvider>;
}
