import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from falkordb import FalkorDB

from agent import investigate_alert as run_investigation


# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="CyberGraph AI API",
    description="Graph-powered cybersecurity investigation platform",
    version="1.3.0",
)


# --------------------------------------------------
# CORS CONFIGURATION
# --------------------------------------------------

# Local development origins
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:5175",
    "http://127.0.0.1:5175",
    "http://localhost:5176",
    "http://127.0.0.1:5176",
]

# Optional production frontend URL.
# Configure FRONTEND_URL in Render after deploying the frontend.
frontend_url = os.getenv("FRONTEND_URL")

if frontend_url:
    allowed_origins.append(frontend_url.rstrip("/"))


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# FALKORDB CONFIGURATION
# --------------------------------------------------

DB_HOST = os.getenv("FALKORDB_HOST", "localhost")
DB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
DB_USERNAME = os.getenv("FALKORDB_USERNAME")
DB_PASSWORD = os.getenv("FALKORDB_PASSWORD")
GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "CyberGraph")


def get_graph():
    """Connect to the configured FalkorDB graph."""

    connection_options = {
        "host": DB_HOST,
        "port": DB_PORT,
    }

    if DB_USERNAME:
        connection_options["username"] = DB_USERNAME

    if DB_PASSWORD:
        connection_options["password"] = DB_PASSWORD

    database = FalkorDB(**connection_options)

    return database.select_graph(GRAPH_NAME)


# --------------------------------------------------
# ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "application": "CyberGraph AI",
        "version": "1.3.0",
        "status": "running",
        "docs": "/docs",
    }


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/api/health")
def health_check():
    try:
        graph = get_graph()
        graph.query("RETURN 1 AS connection_test")

        return {
            "api": "healthy",
            "database": "connected",
        }

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail={
                "api": "healthy",
                "database": "disconnected",
                "error": str(error),
            },
        )


# --------------------------------------------------
# GET ALL SECURITY ALERTS
# --------------------------------------------------

@app.get("/api/alerts")
def get_alerts():
    try:
        graph = get_graph()

        result = graph.query(
            """
            MATCH (a:Alert)
            RETURN
                a.id AS alert_id,
                a.severity AS severity,
                a.description AS description
            ORDER BY a.id
            """
        )

        alerts = []

        for row in result.result_set:
            alerts.append(
                {
                    "alert_id": row[0],
                    "severity": row[1],
                    "description": row[2],
                }
            )

        return alerts

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Could not retrieve alerts: {str(error)}",
        )


# --------------------------------------------------
# GET CONNECTED ENTITIES FOR AN ALERT
# --------------------------------------------------

@app.get("/api/investigations/{alert_id}")
def get_investigation(alert_id: str):
    try:
        graph = get_graph()

        result = graph.query(
            """
            MATCH (a:Alert {id: $alert_id})
            OPTIONAL MATCH (a)-[:AFFECTS]->(d:Device)
            OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            OPTIONAL MATCH (i:Identity)-[:ACCESSES]->(d)
            OPTIONAL MATCH (d)-[:CONNECTS_TO]->(asset:Asset)
            RETURN
                a.id AS alert_id,
                a.severity AS severity,
                a.description AS description,
                d.hostname AS device,
                v.name AS vulnerability,
                i.username AS identity,
                asset.name AS connected_asset
            """,
            {"alert_id": alert_id},
        )

        if not result.result_set:
            raise HTTPException(
                status_code=404,
                detail=f"Alert {alert_id} was not found.",
            )

        investigations = []

        for row in result.result_set:
            investigations.append(
                {
                    "alert_id": row[0],
                    "severity": row[1],
                    "description": row[2],
                    "device": row[3],
                    "vulnerability": row[4],
                    "identity": row[5],
                    "connected_asset": row[6],
                }
            )

        return {
            "investigation": investigations,
            "note": (
                "Relationships are based on synthetic demonstration "
                "data. They do not establish that an attack occurred."
            ),
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation query failed: {str(error)}",
        )


# --------------------------------------------------
# AI AGENT INVESTIGATION
# --------------------------------------------------

@app.get("/api/agent/investigate/{alert_id}")
def investigate_with_agent(alert_id: str):
    try:
        result = run_investigation(alert_id)

        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"No investigation result for {alert_id}.",
            )

        if result.get("status") == "not_found":
            raise HTTPException(
                status_code=404,
                detail=result.get(
                    "message",
                    f"No matching alert was found for {alert_id}.",
                ),
            )

        return result

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Agent investigation failed: {str(error)}",
        )