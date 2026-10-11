import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

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

/* =========================================================
   CONFIGURATION
   ========================================================= */

const API_URL = (
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const TOKEN_KEY = "cybergraph_access_token";
const USER_KEY = "cybergraph_user";

/* =========================================================
   API REQUEST HELPER
   ========================================================= */

async function apiRequest(path, options = {}) {
  const token = localStorage.getItem(TOKEN_KEY);

  const headers = {
    Accept: "application/json",
    ...(token
      ? { Authorization: `Bearer ${token}` }
      : {}),
    ...(options.headers || {}),
  };

  if (
    options.body &&
    !headers["Content-Type"] &&
    !headers["content-type"]
  ) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

  const contentType =
    response.headers.get("content-type") || "";

  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message =
      typeof body === "object" && body !== null
        ? body.detail ||
          body.message ||
          JSON.stringify(body)
        : body || `HTTP ${response.status}`;

    if (
      response.status === 401 &&
      !path.startsWith("/api/auth/")
    ) {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);

      window.dispatchEvent(
        new Event("cybergraph-session-expired")
      );
    }

    throw new Error(message);
  }

  return body;
}

function errorMessage(error) {
  return error instanceof Error
    ? error.message
    : "An unexpected error occurred.";
}

function severityColor(severity) {
  switch (String(severity || "").toLowerCase()) {
    case "critical":
      return "#ef4444";
    case "high":
      return "#f97316";
    case "medium":
      return "#f59e0b";
    case "low":
      return "#22c55e";
    default:
      return "#94a3b8";
  }
}

/* =========================================================
   AUTHENTICATION SCREEN
   ========================================================= */

function AuthScreen({ onAuthenticated }) {
  const [mode, setMode] = useState("welcome");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] =
    useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  function changeMode(nextMode) {
    setMode(nextMode);
    setError("");
    setMessage("");
    setPassword("");
    setConfirmPassword("");
  }

  async function handleSubmit(event) {
    event.preventDefault();

    setError("");
    setMessage("");

    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail || !password) {
      setError("Enter your email address and password.");
      return;
    }

    if (mode === "register") {
      if (password.length < 12) {
        setError(
          "Use a password containing at least 12 characters."
        );
        return;
      }

      if (password !== confirmPassword) {
        setError("Your passwords do not match.");
        return;
      }
    }

    setLoading(true);

    try {
      const endpoint =
        mode === "register"
          ? "/api/auth/register"
          : "/api/auth/login";

      const result = await apiRequest(endpoint, {
        method: "POST",
        body: JSON.stringify({
          email: cleanEmail,
          password,
        }),
      });

      if (mode === "register") {
        if (result.access_token) {
          localStorage.setItem(
            TOKEN_KEY,
            result.access_token
          );

          localStorage.setItem(
            USER_KEY,
            JSON.stringify(result.user || { email: cleanEmail })
          );

          onAuthenticated(
            result.user || { email: cleanEmail }
          );

          return;
        }

        setMessage(
          "Your account was created. You can now sign in."
        );

        setMode("login");
        setPassword("");
        setConfirmPassword("");
        return;
      }

      if (!result.access_token) {
        throw new Error(
          "The server did not return an access token. Check the backend login response."
        );
      }

      localStorage.setItem(
        TOKEN_KEY,
        result.access_token
      );

      const user = result.user || {
        email: cleanEmail,
      };

      localStorage.setItem(
        USER_KEY,
        JSON.stringify(user)
      );

      onAuthenticated(user);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="cg-auth-page">
      <div className="cg-auth-glow cg-auth-glow-one" />
      <div className="cg-auth-glow cg-auth-glow-two" />

      <header className="cg-auth-header">
        <a
          className="cg-brand"
          href="#home"
          onClick={(event) => {
            event.preventDefault();
            changeMode("welcome");
          }}
        >
          <span className="cg-brand-icon">◈</span>
          <span>CyberGraph AI</span>
        </a>

        <span className="cg-header-badge">
          CYBERSECURITY INTELLIGENCE
        </span>
      </header>

      <main className="cg-auth-main">
        <section className="cg-hero">
          <div className="cg-eyebrow">
            <span className="cg-status-dot" />
            GRAPH-POWERED INVESTIGATION
          </div>

          <h1>
            See the connections.
            <br />
            <span>Understand the threat.</span>
          </h1>

          <p className="cg-hero-description">
            Explore security alerts, connect related entities,
            and examine investigation findings through an
            interactive cybersecurity graph.
          </p>

          <div className="cg-feature-grid">
            <article className="cg-feature-card">
              <div className="cg-feature-icon">⌘</div>
              <h3>Graph Intelligence</h3>
              <p>
                Explore relationships between alerts,
                devices, identities, vulnerabilities, and
                connected assets.
              </p>
            </article>

            <article className="cg-feature-card">
              <div className="cg-feature-icon">◎</div>
              <h3>Alert Investigation</h3>
              <p>
                Select an alert and examine the associated
                investigation information.
              </p>
            </article>

            <article className="cg-feature-card">
              <div className="cg-feature-icon">✳</div>
              <h3>Investigation Assistant</h3>
              <p>
                Request structured findings and
                recommendations from the backend.
              </p>
            </article>
          </div>

          <div className="cg-demo-note">
            <span>ⓘ</span>
            <p>
              This prototype uses demonstration data.
              Graph relationships alone do not prove that
              a real cyberattack occurred.
            </p>
          </div>
        </section>

        <section className="cg-auth-card">
          {mode === "welcome" ? (
            <>
              <div className="cg-card-symbol">◈</div>

              <div className="cg-card-eyebrow">
                YOUR INVESTIGATION WORKSPACE
              </div>

              <h2>Welcome to CyberGraph</h2>

              <p className="cg-card-description">
                Sign in to continue to your cybersecurity
                investigation dashboard, or create an account
                to get started.
              </p>

              <button
                className="cg-primary-button"
                onClick={() => changeMode("login")}
              >
                Sign in
                <span>→</span>
              </button>

              <button
                className="cg-secondary-button"
                onClick={() => changeMode("register")}
              >
                Create an account
              </button>

              <div className="cg-card-footer">
                <span className="cg-status-dot" />
                Authentication powered by your backend
              </div>
            </>
          ) : (
            <>
              <button
                className="cg-back-button"
                onClick={() => changeMode("welcome")}
              >
                ← Back
              </button>

              <div className="cg-card-symbol">◈</div>

              <div className="cg-card-eyebrow">
                {mode === "login"
                  ? "WELCOME BACK"
                  : "JOIN THE WORKSPACE"}
              </div>

              <h2>
                {mode === "login"
                  ? "Sign in"
                  : "Create your account"}
              </h2>

              <p className="cg-card-description">
                {mode === "login"
                  ? "Enter your credentials to access your dashboard."
                  : "Create your account to access the investigation workspace."}
              </p>

              {error && (
                <div className="cg-alert cg-alert-error">
                  {error}
                </div>
              )}

              {message && (
                <div className="cg-alert cg-alert-success">
                  {message}
                </div>
              )}

              <form
                className="cg-auth-form"
                onSubmit={handleSubmit}
              >
                <label htmlFor="cg-email">
                  Email address
                </label>

                <input
                  id="cg-email"
                  type="email"
                  autoComplete="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(event) =>
                    setEmail(event.target.value)
                  }
                  required
                />

                <label htmlFor="cg-password">
                  Password
                </label>

                <div className="cg-password-wrapper">
                  <input
                    id="cg-password"
                    type={showPassword ? "text" : "password"}
                    autoComplete={
                      mode === "login"
                        ? "current-password"
                        : "new-password"
                    }
                    placeholder={
                      mode === "register"
                        ? "At least 12 characters"
                        : "Enter your password"
                    }
                    value={password}
                    onChange={(event) =>
                      setPassword(event.target.value)
                    }
                    required
                  />

                  <button
                    type="button"
                    className="cg-password-toggle"
                    onClick={() =>
                      setShowPassword((current) => !current)
                    }
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>

                {mode === "register" && (
                  <>
                    <label htmlFor="cg-confirm-password">
                      Confirm password
                    </label>

                    <input
                      id="cg-confirm-password"
                      type={
                        showPassword ? "text" : "password"
                      }
                      autoComplete="new-password"
                      placeholder="Re-enter your password"
                      value={confirmPassword}
                      onChange={(event) =>
                        setConfirmPassword(event.target.value)
                      }
                      required
                    />
                  </>
                )}

                {mode === "register" && (
                  <p className="cg-password-hint">
                    Use at least 12 characters. Never reuse
                    an important personal password.
                  </p>
                )}

                <button
                  className="cg-primary-button"
                  type="submit"
                  disabled={loading}
                >
                  {loading
                    ? "Please wait..."
                    : mode === "login"
                      ? "Sign in to CyberGraph"
                      : "Create account"}

                  {!loading && <span>→</span>}
                </button>
              </form>

              <div className="cg-switch-mode">
                {mode === "login"
                  ? "New to CyberGraph?"
                  : "Already have an account?"}

                <button
                  onClick={() =>
                    changeMode(
                      mode === "login"
                        ? "register"
                        : "login"
                    )
                  }
                >
                  {mode === "login"
                    ? "Create account"
                    : "Sign in"}
                </button>
              </div>

              <div className="cg-card-footer">
                <span className="cg-status-dot" />
                Secure authentication through the API
              </div>
            </>
          )}
        </section>
      </main>

      <footer className="cg-auth-footer">
        <span>CyberGraph AI</span>
        <span>Graph-based security investigation prototype</span>
        <span>Use only authorized systems</span>
      </footer>
    </div>
  );
}

/* =========================================================
   GRAPH NODE
   ========================================================= */

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
    <div
      style={{
        minWidth: 150,
        padding: 14,
        cursor: "pointer",
        borderRadius: 12,
        border: `2px solid ${color}`,
        background: "#111827",
        color: "#f9fafb",
        boxShadow: `0 0 14px ${color}35`,
      }}
    >
      <Handle type="target" position={Position.Top} />

      <div
        style={{
          color,
          fontSize: 11,
          fontWeight: 800,
          textTransform: "uppercase",
          letterSpacing: 1,
          marginBottom: 7,
        }}
      >
        {data.type || "Node"}
      </div>

      <div style={{ fontSize: 14, fontWeight: 700 }}>
        {data.label || "Unnamed node"}
      </div>

      {data.subtitle && (
        <div
          style={{
            color: "#9ca3af",
            fontSize: 11,
            marginTop: 6,
            maxWidth: 180,
            overflowWrap: "anywhere",
          }}
        >
          {data.subtitle}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

const nodeTypes = {
  graphNode: GraphNode,
};

/* =========================================================
   DASHBOARD COMPONENTS
   ========================================================= */

function SummaryCard({ title, value, detail, accent }) {
  return (
    <div style={{ ...panelStyle, minWidth: 0 }}>
      <div
        style={{
          color: "#94a3b8",
          fontSize: 10,
          fontWeight: 800,
          letterSpacing: 1,
        }}
      >
        {title}
      </div>

      <div
        style={{
          color: accent,
          fontSize: 27,
          fontWeight: 800,
          marginTop: 12,
          overflowWrap: "anywhere",
        }}
      >
        {value}
      </div>

      <div
        style={{
          color: "#64748b",
          fontSize: 11,
          marginTop: 7,
        }}
      >
        {detail}
      </div>
    </div>
  );
}

function PanelHeading({ title, subtitle }) {
  return (
    <div
      style={{
        borderBottom: "1px solid #253247",
        paddingBottom: 14,
        marginBottom: 16,
      }}
    >
      <div style={{ fontSize: 15, fontWeight: 800 }}>
        {title}
      </div>

      <div
        style={{
          color: "#94a3b8",
          fontSize: 11,
          marginTop: 5,
          lineHeight: 1.5,
        }}
      >
        {subtitle}
      </div>
    </div>
  );
}

function DetailRow({ label, value, valueColor }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns:
          "minmax(100px, 0.8fr) minmax(0, 1.2fr)",
        gap: 12,
        paddingBottom: 10,
        borderBottom: "1px solid #1f2937",
      }}
    >
      <div style={{ color: "#94a3b8", fontSize: 12 }}>
        {label}
      </div>

      <div
        style={{
          color: valueColor || "#e5e7eb",
          fontSize: 12,
          fontWeight: 600,
          overflowWrap: "anywhere",
        }}
      >
        {value || "Unavailable"}
      </div>
    </div>
  );
}

/* =========================================================
   MAIN DASHBOARD
   ========================================================= */

function Dashboard({ user, onLogout }) {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [agentResult, setAgentResult] = useState(null);
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);

  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [loadingInvestigation, setLoadingInvestigation] =
    useState(false);
  const [loadingAgent, setLoadingAgent] = useState(false);

  const [backendStatus, setBackendStatus] =
    useState("checking");

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

        return (
          list.find(
            (item) =>
              String(item.alert_id ?? item.id) ===
              String(current.alert_id ?? current.id)
          ) || list[0]
        );
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

      setPageError(
        `Could not load alerts from the backend: ${errorMessage(error)}`
      );
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
    setSelectedGraphNode(null);
    setLoadingInvestigation(true);
    setInvestigation(null);
    setAgentResult(null);
    setGraphError("");

    try {
      const result = await apiRequest(
        `/api/investigations/${encodeURIComponent(id)}`
      );

      setInvestigation(result);
      setBackendStatus("online");
    } catch (error) {
      setGraphError(
        `Could not load the investigation: ${errorMessage(error)}`
      );
      setBackendStatus("offline");
    } finally {
      setLoadingInvestigation(false);
    }
  }, []);

  const runAgent = useCallback(async () => {
    const id = selectedAlert?.alert_id ?? selectedAlert?.id;

    if (id == null) {
      setGraphError(
        "Select an alert before starting an investigation."
      );
      return;
    }

    setLoadingAgent(true);
    setAgentResult(null);
    setGraphError("");

    try {
      const result = await apiRequest(
        `/api/agent/investigate/${encodeURIComponent(id)}`
      );

      setAgentResult(result);
      setBackendStatus("online");
    } catch (error) {
      setGraphError(
        `The investigation agent could not run: ${errorMessage(error)}`
      );
      setBackendStatus("offline");
    } finally {
      setLoadingAgent(false);
    }
  }, [selectedAlert]);

  useEffect(() => {
    checkBackend();
    loadAlerts();

    const timer = window.setInterval(
      checkBackend,
      30000
    );

    return () => window.clearInterval(timer);
  }, [checkBackend, loadAlerts]);

  useEffect(() => {
    if (selectedAlert) {
      loadInvestigation(selectedAlert);
    }
  }, [
    selectedAlert?.alert_id,
    selectedAlert?.id,
    loadInvestigation,
  ]);

  const records = Array.isArray(
    investigation?.investigation
  )
    ? investigation.investigation
    : Array.isArray(investigation?.results)
      ? investigation.results
      : Array.isArray(investigation)
        ? investigation
        : investigation
          ? [investigation]
          : [];

  const record =
    records.find(
      (item) =>
        String(item.alert_id ?? item.id) ===
        String(selectedAlert?.alert_id ?? selectedAlert?.id)
    ) || records[0];

  const graph = useMemo(() => {
    if (!record) {
      return { nodes: [], edges: [] };
    }

    const definitions = [
      {
        id: "alert",
        type: "Alert",
        label:
          record.alert_id ||
          selectedAlert?.alert_id ||
          "Alert",
        subtitle: record.description || "Security alert",
      },
      {
        id: "device",
        type: "Device",
        label: record.device || "Device unavailable",
        subtitle: "Affected device",
      },
      {
        id: "vulnerability",
        type: "Vulnerability",
        label:
          record.vulnerability ||
          "Vulnerability unavailable",
        subtitle: "Associated vulnerability",
      },
      {
        id: "identity",
        type: "Identity",
        label: record.identity || "Identity unavailable",
        subtitle: "Associated identity",
      },
      {
        id: "asset",
        type: "Asset",
        label:
          record.connected_asset || "Asset unavailable",
        subtitle: "Connected asset",
      },
    ];

    const positions = {
      alert: { x: 300, y: 20 },
      device: { x: 40, y: 210 },
      vulnerability: { x: 300, y: 210 },
      identity: { x: 560, y: 210 },
      asset: { x: 300, y: 410 },
    };

    const nodes = definitions.map((item) => ({
      id: item.id,
      type: "graphNode",
      position: positions[item.id],
      data: {
        type: item.type,
        label: item.label,
        subtitle: item.subtitle,
      },
    }));

    const links = [
      {
        source: "alert",
        target: "device",
        label: "AFFECTS",
      },
      {
        source: "device",
        target: "vulnerability",
        label: "HAS_VULNERABILITY",
      },
      {
        source: "device",
        target: "identity",
        label: "ACCESSES",
      },
      {
        source: "identity",
        target: "asset",
        label: "CONNECTS_TO",
      },
    ];

    const edges = links.map((item, index) => ({
      id: `edge-${index}`,
      ...item,
      animated: true,
      style: {
        stroke: "#64748b",
        strokeWidth: 2,
      },
      labelStyle: {
        fill: "#cbd5e1",
        fontSize: 10,
        fontWeight: 600,
      },
      labelBgStyle: {
        fill: "#111827",
        fillOpacity: 0.9,
      },
    }));

    return { nodes, edges };
  }, [record, selectedAlert]);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#080d18",
        color: "#e5e7eb",
        fontFamily:
          "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
      }}
    >
      <header
        data-tour="header"
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 16,
          padding: "20px 28px",
          borderBottom: "1px solid #1f2937",
          background: "#0b1220",
        }}
      >
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              fontSize: 22,
              fontWeight: 800,
              letterSpacing: -0.5,
            }}
          >
            <span style={{ color: "#38bdf8" }}>◈</span>
            CyberGraph AI
          </div>

          <div
            style={{
              color: "#94a3b8",
              fontSize: 12,
              marginTop: 5,
            }}
          >
            Graph-powered cybersecurity investigation
            dashboard
          </div>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <div
            style={{
              padding: "8px 12px",
              border: "1px solid #263449",
              borderRadius: 8,
              fontSize: 12,
              color: "#cbd5e1",
            }}
          >
            Backend:{" "}
            <span
              style={{
                color:
                  backendStatus === "online"
                    ? "#4ade80"
                    : backendStatus === "offline"
                      ? "#f87171"
                      : "#facc15",
                fontWeight: 700,
              }}
            >
              {backendStatus === "online"
                ? "ONLINE"
                : backendStatus === "offline"
                  ? "OFFLINE"
                  : "CHECKING"}
            </span>
          </div>

          <button
            onClick={() => {
              checkBackend();
              loadAlerts();
            }}
            disabled={loadingAlerts}
            style={buttonStyle("#1e293b")}
          >
            {loadingAlerts ? "Refreshing..." : "↻ Refresh"}
          </button>

          <div className="cg-user-badge">
            {user?.email || "Signed in"}
          </div>

          <button
            onClick={onLogout}
            style={buttonStyle("#7f1d1d")}
          >
            Sign out
          </button>
        </div>
      </header>

      <main
        style={{
          padding: 24,
          maxWidth: 1600,
          margin: "0 auto",
        }}
      >
        <div
          style={{
            border: "1px solid #334155",
            borderRadius: 10,
            background: "#0f172a",
            padding: "12px 16px",
            marginBottom: 22,
            fontSize: 12,
            color: "#cbd5e1",
            lineHeight: 1.6,
          }}
        >
          <strong style={{ color: "#38bdf8" }}>
            Demo environment:
          </strong>{" "}
          This dashboard uses demonstration data. Graph
          relationships and investigation recommendations
          do not independently establish that a real
          cyberattack occurred. No response actions are
          executed automatically.
        </div>

        {pageError && (
          <div style={errorStyle}>
            <strong>Backend connection issue</strong>

            <div style={{ marginTop: 5 }}>
              {pageError}
            </div>

            <div
              style={{
                marginTop: 8,
                color: "#cbd5e1",
                fontSize: 12,
              }}
            >
              Configured API: {API_URL}
            </div>
          </div>
        )}

        <section
          data-tour="overview"
          style={{
            display: "grid",
            gridTemplateColumns:
              "repeat(auto-fit, minmax(190px, 1fr))",
            gap: 14,
            marginBottom: 24,
          }}
        >
          <SummaryCard
            title="TOTAL ALERTS"
            value={loadingAlerts ? "…" : alerts.length}
            detail="Alerts returned by the API"
            accent="#38bdf8"
          />

          <SummaryCard
            title="CRITICAL ALERTS"
            value={
              loadingAlerts
                ? "…"
                : alerts.filter(
                    (alert) =>
                      String(alert.severity || "")
                        .toLowerCase() === "critical"
                  ).length
            }
            detail="Marked critical in alert data"
            accent="#ef4444"
          />

          <SummaryCard
            title="SELECTED ALERT"
            value={
              selectedAlert
                ? selectedAlert.alert_id ||
                  selectedAlert.id ||
                  "Selected"
                : "None"
            }
            detail={
              selectedAlert?.severity ||
              "Choose an alert below"
            }
            accent="#a78bfa"
          />

          <SummaryCard
            title="GRAPH STATUS"
            value={record ? "Loaded" : "Waiting"}
            detail="Selected investigation data"
            accent="#34d399"
          />
        </section>

        <section
          className="dashboard-layout"
          style={{
            display: "grid",
            gridTemplateColumns:
              "minmax(260px, 340px) minmax(0, 1fr)",
            gap: 20,
            alignItems: "start",
          }}
        >
          <section style={panelStyle} data-tour="alerts">
            <PanelHeading
              title="Security Alerts"
              subtitle="Select an alert to investigate"
            />

            {loadingAlerts ? (
              <p style={mutedStyle}>
                Loading alerts…
              </p>
            ) : alerts.length === 0 ? (
              <p style={mutedStyle}>
                No alerts were returned by the backend.
              </p>
            ) : (
              <div style={{ display: "grid", gap: 10 }}>
                {alerts.map((alert, index) => {
                  const id =
                    alert.alert_id ??
                    alert.id ??
                    `alert-${index}`;

                  const selected =
                    String(id) ===
                    String(
                      selectedAlert?.alert_id ??
                        selectedAlert?.id
                    );

                  return (
                    <button
                      key={String(id)}
                      onClick={() =>
                        loadInvestigation(alert)
                      }
                      style={{
                        textAlign: "left",
                        cursor: "pointer",
                        borderRadius: 10,
                        padding: 14,
                        color: "#e5e7eb",
                        background: selected
                          ? "#172554"
                          : "#0b1220",
                        border: selected
                          ? "1px solid #3b82f6"
                          : "1px solid #253247",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          gap: 8,
                          marginBottom: 8,
                        }}
                      >
                        <strong style={{ fontSize: 13 }}>
                          {id}
                        </strong>

                        <span
                          style={{
                            color: severityColor(
                              alert.severity
                            ),
                            fontSize: 10,
                            fontWeight: 800,
                            textTransform: "uppercase",
                          }}
                        >
                          {alert.severity || "Unknown"}
                        </span>
                      </div>

                      <div
                        style={{
                          color: "#cbd5e1",
                          fontSize: 12,
                          lineHeight: 1.5,
                        }}
                      >
                        {alert.description ||
                          "No description available"}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </section>

          <section
            data-tour="graph"
            style={{ ...panelStyle, minWidth: 0 }}
          >
            <PanelHeading
              title="Investigation Graph"
              subtitle={
                selectedAlert
                  ? `Relationships for ${
                      selectedAlert.alert_id ||
                      selectedAlert.id
                    }`
                  : "Choose an alert to explore its relationships"
              }
            />

            {loadingInvestigation ? (
              <div style={graphMessageStyle}>
                Loading graph investigation…
              </div>
            ) : graphError ? (
              <div
                style={{
                  ...graphMessageStyle,
                  color: "#fca5a5",
                }}
              >
                {graphError}
              </div>
            ) : graph.nodes.length > 0 ? (
              <div
                style={{
                  height: 510,
                  borderRadius: 10,
                  overflow: "hidden",
                  border: "1px solid #263449",
                  background: "#080d18",
                }}
              >
                <ReactFlow
                  nodes={graph.nodes}
                  edges={graph.edges}
                  nodeTypes={nodeTypes}
                  onNodeClick={(_, node) => setSelectedGraphNode(node)}
                  fitView
                  fitViewOptions={{ padding: 0.2 }}
                  minZoom={0.3}
                  maxZoom={1.6}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background
                    color="#263449"
                    gap={22}
                  />

                  <Controls />

                  <MiniMap
                    nodeColor={(node) =>
                      ({
                        Alert: "#ef4444",
                        Device: "#3b82f6",
                        Vulnerability: "#f59e0b",
                        Identity: "#a855f7",
                        Asset: "#10b981",
                      }[node.data?.type] || "#64748b")
                    }
                    style={{ background: "#111827" }}
                  />
                </ReactFlow>
              </div>
            ) : (
              <div style={graphMessageStyle}>
                Select an alert to load its investigation
                graph.
              </div>
            )}

            {selectedGraphNode && (
              <div
                aria-live="polite"
                style={{
                  marginTop: 14,
                  padding: 14,
                  borderRadius: 10,
                  border: "1px solid #0ea5e9",
                  background: "#0c1d30",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                  <div>
                    <div style={{ color: "#7dd3fc", fontSize: 10, fontWeight: 800, letterSpacing: 1 }}>
                      SELECTED GRAPH NODE · {selectedGraphNode.data?.type || "ENTITY"}
                    </div>
                    <div style={{ color: "#f8fafc", fontSize: 15, fontWeight: 800, marginTop: 6, overflowWrap: "anywhere" }}>
                      {selectedGraphNode.data?.label || selectedGraphNode.id}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedGraphNode(null)}
                    style={buttonStyle("#1e293b")}
                  >
                    Clear selection
                  </button>
                </div>
                <p style={{ color: "#cbd5e1", fontSize: 12, lineHeight: 1.7, marginBottom: 0 }}>
                  {selectedGraphNode.data?.subtitle || "No additional description is available for this node."}
                </p>
                <div style={{ color: "#64748b", fontSize: 10, marginTop: 8 }}>
                  Node ID: {selectedGraphNode.id}. This is demonstration graph data; validate relationships against trusted evidence.
                </div>
              </div>
            )}

            {investigation?.note && (
              <div
                style={{
                  marginTop: 12,
                  padding: 12,
                  borderRadius: 8,
                  background: "#111827",
                  color: "#94a3b8",
                  fontSize: 11,
                  lineHeight: 1.6,
                }}
              >
                {investigation.note}
              </div>
            )}

            {record && (
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: 8,
                  marginTop: 14,
                  color: "#94a3b8",
                  fontSize: 11,
                }}
              >
                <span style={tagStyle}>
                  5 displayed node types
                </span>

                <span style={tagStyle}>
                  4 displayed relationship types
                </span>

                <span style={tagStyle}>
                  Synthetic demonstration data
                </span>
              </div>
            )}
          </section>
        </section>

        <section
          style={{
            display: "grid",
            gridTemplateColumns:
              "repeat(auto-fit, minmax(280px, 1fr))",
            gap: 20,
            marginTop: 20,
          }}
        >
          <section style={panelStyle} data-tour="details">
            <PanelHeading
              title="Investigation Details"
              subtitle="Information returned by the graph API"
            />

            {record ? (
              <div style={{ display: "grid", gap: 14 }}>
                <DetailRow
                  label="Alert ID"
                  value={record.alert_id}
                />

                <DetailRow
                  label="Severity"
                  value={record.severity || "Unknown"}
                  valueColor={severityColor(record.severity)}
                />

                <DetailRow
                  label="Description"
                  value={record.description}
                />

                <DetailRow
                  label="Device"
                  value={record.device}
                />

                <DetailRow
                  label="Vulnerability"
                  value={record.vulnerability}
                />

                <DetailRow
                  label="Identity"
                  value={record.identity}
                />

                <DetailRow
                  label="Connected asset"
                  value={record.connected_asset}
                />
              </div>
            ) : (
              <p style={mutedStyle}>
                Investigation details will appear after an
                alert is selected.
              </p>
            )}
          </section>

          <section style={panelStyle} data-tour="ai-investigation">
            <PanelHeading
              title="AI Investigation Assistant"
              subtitle="Request a structured investigation from the backend"
            />

            <p
              style={{
                color: "#94a3b8",
                fontSize: 12,
                lineHeight: 1.7,
                marginTop: 0,
              }}
            >
              Request the configured investigation endpoint
              for analysis and recommendations. The endpoint
              may use deterministic rules; this interface
              does not assume an external LLM is connected.
            </p>

            <button
              onClick={runAgent}
              disabled={!selectedAlert || loadingAgent}
              style={{
                ...buttonStyle("#0369a1"),
                width: "100%",
                padding: "12px 16px",
                opacity:
                  !selectedAlert || loadingAgent
                    ? 0.55
                    : 1,
                cursor:
                  !selectedAlert || loadingAgent
                    ? "not-allowed"
                    : "pointer",
              }}
            >
              {loadingAgent
                ? "Investigating…"
                : "Run Investigation"}
            </button>

            {agentResult && (
              <div
                style={{
                  marginTop: 16,
                  borderRadius: 10,
                  border: "1px solid #334155",
                  background: "#080d18",
                  padding: 14,
                }}
              >
                <div
                  style={{
                    color: "#34d399",
                    fontSize: 12,
                    fontWeight: 800,
                    marginBottom: 10,
                  }}
                >
                  Investigation response received
                </div>

                <pre
                  style={{
                    margin: 0,
                    whiteSpace: "pre-wrap",
                    overflowWrap: "anywhere",
                    color: "#cbd5e1",
                    fontSize: 11,
                    lineHeight: 1.7,
                    maxHeight: 360,
                    overflow: "auto",
                  }}
                >
                  {JSON.stringify(agentResult, null, 2)}
                </pre>
              </div>
            )}

            {!agentResult && (
              <div
                style={{
                  marginTop: 14,
                  padding: 12,
                  background: "#111827",
                  borderRadius: 8,
                  fontSize: 11,
                  color: "#94a3b8",
                  lineHeight: 1.6,
                }}
              >
                <strong style={{ color: "#e5e7eb" }}>
                  Safety:
                </strong>{" "}
                Running an investigation retrieves information
                and recommendations. It does not authorize or
                execute containment, account suspension,
                device isolation, or other security actions.
              </div>
            )}
          </section>
        </section>

        <footer
          style={{
            borderTop: "1px solid #1f2937",
            marginTop: 28,
            paddingTop: 18,
            color: "#64748b",
            fontSize: 11,
            lineHeight: 1.8,
          }}
        >
          CyberGraph AI · Graph-based security investigation
          prototype
          <br />
          API endpoint: {API_URL}
          <br />
          Use only authorized systems and verified security
          data for real-world investigations.
        </footer>
      </main>

      <style>{`
        @media (max-width: 850px) {
          .dashboard-layout {
            grid-template-columns: minmax(0, 1fr) !important;
          }
        }

        button:focus-visible {
          outline: 2px solid #38bdf8;
          outline-offset: 3px;
        }

        button:disabled {
          cursor: not-allowed;
        }
      `}</style>
    </div>
  );
}

/* =========================================================
   CYBERGUIDE: GUIDED TOUR + FLOATING HELP
   ========================================================= */

const TOUR_STEPS = [
  {
    target: "header",
    title: "Welcome to CyberGraph AI",
    text: "This is your cybersecurity investigation workspace. You can check backend status, refresh alert data, see which account is signed in, and sign out securely.",
  },
  {
    target: "overview",
    title: "Dashboard overview",
    text: "These summary cards show the alerts returned by the API, the number marked critical, your selected alert, and whether investigation data is loaded.",
  },
  {
    target: "alerts",
    title: "Review security alerts",
    text: "Choose an alert from this list to load its investigation. Severity helps you prioritize review, but it should be considered alongside validated evidence and your organization's procedures.",
  },
  {
    target: "graph",
    title: "Explore the investigation graph",
    text: "The graph displays connected entities such as alerts, devices, vulnerabilities, identities, and assets. Drag to explore, zoom, and use the controls. A displayed relationship is not proof of an attack by itself.",
  },
  {
    target: "details",
    title: "Read investigation details",
    text: "This panel shows the details returned for the selected alert. Check missing or unexpected values against trusted logs and other evidence.",
  },
  {
    target: "ai-investigation",
    title: "Run an investigation",
    text: "Use Run Investigation to request the backend's structured analysis. Review its output critically. This prototype does not automatically isolate devices, suspend accounts, or execute containment actions.",
  },
  {
    target: null,
    title: "You're ready to explore",
    text: "That's the tour! You can restart it from the CyberGuide button at any time. For questions, open the floating help assistant in the bottom-right corner.",
  },
];

function GuidedTour({ onClose, onRestart }) {
  const [stepIndex, setStepIndex] = useState(0);
  const step = TOUR_STEPS[stepIndex];

  useEffect(() => {
    if (!step?.target) return;
    const target = document.querySelector(`[data-tour="${step.target}"]`);
    if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [stepIndex, step]);

  const finish = () => {
    localStorage.setItem("cybergraph_tour_completed", "true");
    onClose();
  };

  return (
    <div className="cg-tour-backdrop" role="presentation">
      <section className="cg-tour-card" role="dialog" aria-modal="true" aria-labelledby="cg-tour-title">
        <div className="cg-tour-topline">
          <span className="cg-tour-mark">◈</span>
          <span>CYBERGUIDE · GETTING STARTED</span>
          <button className="cg-tour-close" onClick={finish} aria-label="Skip tour">×</button>
        </div>
        <div className="cg-tour-progress-label">STEP {stepIndex + 1} OF {TOUR_STEPS.length}</div>
        <div className="cg-tour-progress"><span style={{ width: `${((stepIndex + 1) / TOUR_STEPS.length) * 100}%` }} /></div>
        <h2 id="cg-tour-title">{step.title}</h2>
        <p className="cg-tour-copy">{step.text}</p>
        <div className="cg-tour-actions">
          <button className="cg-tour-text-button" onClick={onRestart}>Restart</button>
          <div className="cg-tour-action-right">
            <button className="cg-tour-secondary" onClick={() => setStepIndex((n) => Math.max(0, n - 1))} disabled={stepIndex === 0}>Previous</button>
            {stepIndex < TOUR_STEPS.length - 1 ? (
              <button className="cg-tour-primary" onClick={() => setStepIndex((n) => Math.min(TOUR_STEPS.length - 1, n + 1))}>Next →</button>
            ) : (
              <button className="cg-tour-primary" onClick={finish}>Finish tour ✓</button>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

const GUIDE_TOPICS = [
  { label: "How do I investigate an alert?", answer: "Select an item in Security Alerts. CyberGraph AI will request the investigation details and display the related entities in the graph. Confirm important findings against trusted evidence before taking action." },
  { label: "How do I read the graph?", answer: "Each node represents an entity, such as an alert, device, vulnerability, identity, or asset. Lines represent relationships returned or represented by this prototype. A connection alone does not establish causation or prove malicious activity." },
  { label: "What does Run Investigation do?", answer: "It calls the configured backend investigation endpoint and displays the response. The endpoint may use deterministic rules; the interface does not assume an external language model is connected, and it does not execute containment actions." },
  { label: "Why are alerts missing?", answer: "Check that the backend is running, the status says ONLINE, and the signed-in session is valid. Use Refresh to request the alert list again. If the issue continues, inspect the backend terminal and API documentation for the error." },
  { label: "How do I restart the tour?", answer: "Choose Restart tour from the CyberGuide help panel, or use the CyberGuide button in the bottom-right corner whenever you want to review the walkthrough." },
];

function CyberGuideAssistant({ onStartTour }) {
  const [open, setOpen] = useState(false);
  const [selectedTopic, setSelectedTopic] = useState(null);

  return (
    <>
      {open && (
        <aside className="cg-help-panel" aria-label="CyberGuide help assistant">
          <div className="cg-help-header">
            <div className="cg-help-avatar">◈</div>
            <div><strong>CyberGuide</strong><span>CyberGraph workspace help</span></div>
            <button onClick={() => { setOpen(false); setSelectedTopic(null); }} aria-label="Close help panel">×</button>
          </div>
          <div className="cg-help-intro">Hi! I can explain the dashboard and help you find your way around.</div>
          <div className="cg-help-topics">
            {GUIDE_TOPICS.map((topic) => (
              <button key={topic.label} className={selectedTopic?.label === topic.label ? "selected" : ""} onClick={() => setSelectedTopic(topic)}>{topic.label}<span>›</span></button>
            ))}
          </div>
          {selectedTopic && <div className="cg-help-answer"><strong>{selectedTopic.label}</strong><p>{selectedTopic.answer}</p></div>}
          <button className="cg-help-tour-button" onClick={() => { setOpen(false); setSelectedTopic(null); onStartTour(); }}>▶ Start / restart guided tour</button>
          <div className="cg-help-disclaimer">Guidance for this prototype only. Verify security findings before taking action.</div>
        </aside>
      )}
      <button className="cg-help-launcher" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-label={open ? "Close CyberGuide assistant" : "Open CyberGuide assistant"}>
        <span>◈</span><span>{open ? "Close" : "CyberGuide"}</span>
      </button>
    </>
  );
}

function AuthenticatedApp({ user, onLogout }) {
  const [showTour, setShowTour] = useState(() => localStorage.getItem("cybergraph_tour_completed") !== "true");
  const [tourKey, setTourKey] = useState(0);

  const startTour = () => {
    setTourKey((key) => key + 1);
    setShowTour(true);
  };

  return (
    <ReactFlowProvider>
      <Dashboard user={user} onLogout={onLogout} />
      <CyberGuideAssistant onStartTour={startTour} />
      {showTour && <GuidedTour key={tourKey} onClose={() => setShowTour(false)} onRestart={() => setTourKey((key) => key + 1)} />}
      <style>{`
        .cg-tour-backdrop{position:fixed;inset:0;z-index:10000;display:flex;align-items:flex-end;justify-content:center;padding:24px;background:rgba(2,6,23,.58);backdrop-filter:blur(3px)}
        .cg-tour-card{width:min(560px,100%);background:#0b1220;color:#e5e7eb;border:1px solid #334155;border-radius:18px;padding:24px;box-shadow:0 24px 90px #0009}
        .cg-tour-topline{display:flex;align-items:center;gap:10px;color:#7dd3fc;font-size:10px;font-weight:800;letter-spacing:1.2px}.cg-tour-mark{font-size:23px}.cg-tour-close{margin-left:auto;border:0;background:transparent;color:#94a3b8;font-size:25px;cursor:pointer}
        .cg-tour-progress-label{margin-top:22px;color:#94a3b8;font-size:10px;font-weight:800;letter-spacing:1px}.cg-tour-progress{height:5px;background:#1e293b;border-radius:10px;margin-top:8px;overflow:hidden}.cg-tour-progress span{display:block;height:100%;background:#38bdf8;transition:width .2s}
        .cg-tour-card h2{font-size:23px;margin:20px 0 10px;letter-spacing:-.5px}.cg-tour-copy{color:#cbd5e1;font-size:13px;line-height:1.8;margin:0 0 24px}.cg-tour-actions{display:flex;align-items:center;justify-content:space-between;gap:12px}.cg-tour-action-right{display:flex;gap:8px}.cg-tour-primary,.cg-tour-secondary,.cg-tour-text-button{border-radius:9px;padding:10px 13px;font-size:12px;font-weight:700;cursor:pointer}.cg-tour-primary{background:#0284c7;color:white;border:1px solid #0ea5e9}.cg-tour-secondary{background:#111827;color:#e2e8f0;border:1px solid #334155}.cg-tour-secondary:disabled{opacity:.4;cursor:not-allowed}.cg-tour-text-button{background:transparent;border:0;color:#94a3b8}
        .cg-help-launcher{position:fixed;right:22px;bottom:22px;z-index:9000;display:flex;align-items:center;gap:9px;border:1px solid #38bdf8;border-radius:999px;padding:12px 17px;background:#082f49;color:#e0f2fe;font-weight:800;font-size:12px;box-shadow:0 8px 30px #0006;cursor:pointer}.cg-help-launcher span:first-child{font-size:18px}
        .cg-help-panel{position:fixed;right:22px;bottom:82px;z-index:9000;width:min(370px,calc(100vw - 28px));max-height:min(650px,calc(100vh - 120px));overflow:auto;border:1px solid #334155;border-radius:16px;background:#0b1220;color:#e5e7eb;box-shadow:0 20px 60px #0008}
        .cg-help-header{display:flex;align-items:center;gap:10px;padding:15px;border-bottom:1px solid #253247}.cg-help-avatar{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:#082f49;color:#7dd3fc;font-size:22px}.cg-help-header div:nth-child(2){display:grid;gap:3px}.cg-help-header strong{font-size:14px}.cg-help-header span{font-size:10px;color:#94a3b8}.cg-help-header>button{margin-left:auto;border:0;background:transparent;color:#94a3b8;font-size:24px;cursor:pointer}.cg-help-intro{margin:14px;padding:12px;border-radius:10px;background:#111827;color:#cbd5e1;font-size:12px;line-height:1.7}.cg-help-topics{display:grid;gap:7px;padding:0 14px}.cg-help-topics button{display:flex;justify-content:space-between;gap:10px;text-align:left;padding:10px 11px;border-radius:9px;border:1px solid #253247;background:#0f172a;color:#e2e8f0;font-size:11px;line-height:1.5;cursor:pointer}.cg-help-topics button.selected{border-color:#38bdf8;background:#082f49}.cg-help-topics button span{color:#7dd3fc;font-size:18px}.cg-help-answer{margin:12px 14px;padding:12px;border:1px solid #1e3a5f;border-radius:10px;background:#0c1d30}.cg-help-answer strong{font-size:11px;color:#7dd3fc}.cg-help-answer p{margin:7px 0 0;color:#cbd5e1;font-size:11px;line-height:1.75}.cg-help-tour-button{margin:12px 14px;width:calc(100% - 28px);padding:11px;border-radius:9px;border:1px solid #0ea5e9;background:#0369a1;color:white;font-size:11px;font-weight:800;cursor:pointer}.cg-help-disclaimer{padding:0 15px 15px;color:#64748b;font-size:10px;line-height:1.6}.cg-help-launcher:focus-visible,.cg-help-panel button:focus-visible,.cg-tour-card button:focus-visible{outline:2px solid #7dd3fc;outline-offset:3px}
        @media(max-width:600px){.cg-tour-backdrop{padding:12px}.cg-tour-card{padding:18px}.cg-tour-card h2{font-size:20px}.cg-tour-actions{align-items:flex-start}.cg-tour-action-right{gap:6px}.cg-tour-primary,.cg-tour-secondary{padding:10px}.cg-help-launcher{right:14px;bottom:14px}.cg-help-panel{right:14px;bottom:72px}}
      `}</style>
    </ReactFlowProvider>
  );
}

/* =========================================================
   APPLICATION ENTRY POINT
   ========================================================= */

export default function App() {
  const [user, setUser] = useState(null);
  const [checkingSession, setCheckingSession] =
    useState(true);

  const [sessionError, setSessionError] = useState("");

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);

    setUser(null);
    setSessionError("");
  }, []);

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const token = localStorage.getItem(TOKEN_KEY);

      if (!token) {
        if (active) {
          setCheckingSession(false);
        }
        return;
      }

      try {
        const result = await apiRequest("/api/auth/me");

        if (active) {
          const restoredUser =
            result.user ||
            result ||
            JSON.parse(
              localStorage.getItem(USER_KEY) || "{}"
            );

          setUser(restoredUser);

          localStorage.setItem(
            USER_KEY,
            JSON.stringify(restoredUser)
          );
        }
      } catch {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);

        if (active) {
          setUser(null);
        }
      } finally {
        if (active) {
          setCheckingSession(false);
        }
      }
    }

    restoreSession();

    const handleExpiredSession = () => {
      if (active) {
        logout();
        setSessionError(
          "Your session expired. Please sign in again."
        );
      }
    };

    window.addEventListener(
      "cybergraph-session-expired",
      handleExpiredSession
    );

    return () => {
      active = false;

      window.removeEventListener(
        "cybergraph-session-expired",
        handleExpiredSession
      );
    };
  }, [logout]);

  if (checkingSession) {
    return (
      <div className="cg-loading-screen">
        <div className="cg-loading-logo">◈</div>
        <h2>CyberGraph AI</h2>
        <p>Preparing your investigation workspace…</p>
        <div className="cg-loading-bar">
          <span />
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <>
        {sessionError && (
          <div className="cg-session-notice">
            {sessionError}
          </div>
        )}

        <AuthScreen
          onAuthenticated={(authenticatedUser) => {
            setUser(authenticatedUser);
            setSessionError("");
          }}
        />
      </>
    );
  }

  return (
    <AuthenticatedApp
      user={user}
      onLogout={logout}
    />
  );
}

/* =========================================================
   SHARED DASHBOARD STYLES
   ========================================================= */

const panelStyle = {
  border: "1px solid #253247",
  borderRadius: 12,
  background: "#0b1220",
  padding: 18,
};

const mutedStyle = {
  color: "#94a3b8",
  fontSize: 12,
  lineHeight: 1.7,
};

const graphMessageStyle = {
  minHeight: 220,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  textAlign: "center",
  padding: 24,
  color: "#94a3b8",
  fontSize: 13,
  lineHeight: 1.7,
  border: "1px dashed #334155",
  borderRadius: 10,
};

const errorStyle = {
  marginBottom: 20,
  padding: 16,
  border: "1px solid #7f1d1d",
  borderRadius: 10,
  background: "#2a1117",
  color: "#fca5a5",
  fontSize: 12,
  lineHeight: 1.6,
};

const tagStyle = {
  border: "1px solid #334155",
  borderRadius: 20,
  padding: "5px 9px",
  background: "#111827",
};

function buttonStyle(background) {
  return {
    border: "1px solid #334155",
    borderRadius: 8,
    padding: "9px 13px",
    background,
    color: "#f8fafc",
    fontSize: 12,
    fontWeight: 700,
    cursor: "pointer",
  };
}