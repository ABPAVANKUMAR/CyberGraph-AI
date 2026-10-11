import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from pwdlib import PasswordHash

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field

from falkordb import FalkorDB
from agent import investigate_alert as run_investigation


# ==================================================
# FASTAPI APPLICATION
# ==================================================

app = FastAPI(
    title="CyberGraph AI API",
    description="Graph-powered cybersecurity investigation platform",
    version="2.0.0",
)


# ==================================================
# CORS CONFIGURATION
# ==================================================

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

frontend_url = os.getenv("FRONTEND_URL")

if frontend_url:
    allowed_origins.append(frontend_url.rstrip("/"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# ==================================================
# AUTHENTICATION CONFIGURATION
# ==================================================

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is missing. Set it in your environment "
        "before starting CyberGraph AI."
    )

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

BASE_DIR = Path(__file__).resolve().parent
AUTH_DB_PATH = BASE_DIR / "users.db"

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)


# ==================================================
# USER DATABASE
# ==================================================

def get_auth_connection():
    connection = sqlite3.connect(
        AUTH_DB_PATH,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    return connection


def initialize_auth_db():
    with get_auth_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


initialize_auth_db()


# ==================================================
# REQUEST MODELS
# ==================================================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


# ==================================================
# JWT TOKEN GENERATION
# ==================================================

def create_access_token(user_id: int, email: str) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        ),
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


# ==================================================
# CURRENT USER VERIFICATION
# ==================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
):
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Please log in to continue.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        user_id = int(payload["sub"])

    except (
        jwt.InvalidTokenError,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise HTTPException(
            status_code=401,
            detail="Your session is invalid or expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    with get_auth_connection() as connection:
        user = connection.execute(
            """
            SELECT id, email, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Account not found. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return dict(user)


# ==================================================
# REGISTRATION
# ==================================================

@app.post("/api/auth/register", status_code=201)
def register_user(data: RegisterRequest):
    email = str(data.email).strip().lower()

    hashed_password = password_hash.hash(data.password)

    try:
        with get_auth_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    email,
                    password_hash,
                    created_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    email,
                    hashed_password,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

            user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    token = create_access_token(user_id, email)

    return {
        "message": "Registration successful.",
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user_id,
            "email": email,
        },
    }


# ==================================================
# LOGIN
# ==================================================

@app.post("/api/auth/login")
def login_user(data: LoginRequest):
    email = str(data.email).strip().lower()

    with get_auth_connection() as connection:
        user = connection.execute(
            """
            SELECT id, email, password_hash
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

    if user is None or not password_hash.verify(
        data.password,
        user["password_hash"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    token = create_access_token(
        user["id"],
        user["email"],
    )

    return {
        "message": "Login successful.",
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user["id"],
            "email": user["email"],
        },
    }


# ==================================================
# CURRENT ACCOUNT
# ==================================================

@app.get("/api/auth/me")
def get_my_account(
    user=Depends(get_current_user),
):
    return {
        "user": user,
    }


# ==================================================
# ROOT ENDPOINT
# ==================================================

@app.get("/")
def home():
    return {
        "application": "CyberGraph AI",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
    }


# ==================================================
# FALKORDB CONFIGURATION
# ==================================================

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


# ==================================================
# HEALTH CHECK
# ==================================================

@app.get("/api/health")
def health_check():
    try:
        graph = get_graph()
        graph.query("RETURN 1 AS connection_test")

        return {
            "api": "healthy",
            "database": "connected",
        }

    except Exception:
        # Do not expose database credentials or internal errors.
        raise HTTPException(
            status_code=503,
            detail={
                "api": "running",
                "database": "disconnected",
            },
        )


# ==================================================
# GET SECURITY ALERTS — LOGIN REQUIRED
# ==================================================

@app.get("/api/alerts")
def get_alerts(
    user=Depends(get_current_user),
):
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

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve alerts.",
        )


# ==================================================
# INVESTIGATION DETAILS — LOGIN REQUIRED
# ==================================================

@app.get("/api/investigations/{alert_id}")
def get_investigation(
    alert_id: str,
    user=Depends(get_current_user),
):
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

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Investigation query failed.",
        )


# ==================================================
# AI AGENT INVESTIGATION — LOGIN REQUIRED
# ==================================================

@app.get("/api/agent/investigate/{alert_id}")
def investigate_with_agent(
    alert_id: str,
    user=Depends(get_current_user),
):
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

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Agent investigation failed.",
        )