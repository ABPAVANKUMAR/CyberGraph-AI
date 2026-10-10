
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
    version="1.2.0",
)


# --------------------------------------------------
# CORS CONFIGURATION
# Allows the React frontend to communicate with FastAPI
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# FALKORDB CONFIGURATION
# Must match build_graph.py exactly
# --------------------------------------------------

DB_HOST = "localhost"
DB_PORT = 6379
GRAPH_NAME = "CyberGraph"


def get_graph():
    """Connect to the CyberGraph graph database."""
    database = FalkorDB(
        host=DB_HOST,
        port=DB_PORT,
    )

    return database.select_graph(GRAPH_NAME)


# --------------------------------------------------
# ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "application": "CyberGraph AI",
        "version": "1.2.0",
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
# Uses a.id because build_graph.py stores the ID
# in the "id" property, not "alert_id".
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
            {
                "alert_id": alert_id,
            },
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

        return result

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Agent investigation failed: {str(error)}",
        )

