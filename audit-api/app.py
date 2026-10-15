import asyncio
import os
import time

import asyncpg
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from jose import JWTError, jwt
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field

ISSUER = os.getenv("KEYCLOAK_ISSUER", "").rstrip("/")
JWKS_URL = os.getenv("KEYCLOAK_JWKS_URL") or f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "")
WRITER_ROLE = os.getenv("WRITER_ROLE", "audit-writer")
READER_ROLE = os.getenv("READER_ROLE", "audit-reader")

DB_HOST = os.getenv("DB_HOST", "")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "audit")
DB_USER = os.getenv("DB_USER", "audit")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DDL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
)
"""

app = FastAPI(title="audit-api")
Instrumentator().instrument(app).expose(app, include_in_schema=False)

# ---------- JWT validation (Keycloak JWKS, fetched lazily and cached) ----------
_jwks = {"keys": [], "fetched": 0.0}
_jwks_lock = asyncio.Lock()


async def get_signing_key(kid):
    def find():
        return next((k for k in _jwks["keys"] if k.get("kid") == kid), None)

    key = find()
    if key:
        return key
    async with _jwks_lock:
        key = find()
        if key:
            return key
        if time.time() - _jwks["fetched"] > 30:
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.get(JWKS_URL)
                    r.raise_for_status()
                _jwks["keys"] = r.json().get("keys", [])
                _jwks["fetched"] = time.time()
            except httpx.HTTPError:
                raise HTTPException(503, "Keycloak JWKS unavailable")
        key = find()
    if not key:
        raise HTTPException(401, "Unknown signing key")
    return key


async def current_claims(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except JWTError:
        raise HTTPException(401, "Malformed token")
    key = await get_signing_key(kid)
    try:
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE or None,
            options={"verify_aud": bool(AUDIENCE)},
        )
    except JWTError as e:
        raise HTTPException(401, f"Invalid token: {e}")


def require_role(role: str):
    async def dep(claims: dict = Depends(current_claims)) -> dict:
        roles = claims.get("realm_access", {}).get("roles", [])
        if role not in roles:
            raise HTTPException(403, f"Role '{role}' required")
        return claims

    return dep


# ---------- Postgres (pool created lazily on first use) ----------
_pool = None
_pool_lock = asyncio.Lock()


async def get_pool():
    global _pool
    if _pool is not None:
        return _pool
    async with _pool_lock:
        if _pool is None:
            if not DB_HOST:
                raise HTTPException(503, "Database is not configured")
            pool = None
            try:
                pool = await asyncpg.create_pool(
                    host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
                    database=DB_NAME, min_size=1, max_size=5, timeout=5,
                )
                await pool.execute(DDL)
                _pool = pool
            except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
                if pool is not None:
                    await pool.close()
                raise HTTPException(503, "Database unavailable")
    return _pool


# ---------- API ----------
class EventIn(BaseModel):
    action: str = Field(min_length=1, max_length=100)
    detail: str = Field(default="", max_length=1000)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/events", status_code=201)
async def create_event(ev: EventIn, claims: dict = Depends(require_role(WRITER_ROLE))):
    pool = await get_pool()
    user = claims.get("preferred_username") or claims.get("sub")
    row = await pool.fetchrow(
        "INSERT INTO audit_events (username, action, detail) VALUES ($1, $2, $3) RETURNING id, ts",
        user, ev.action, ev.detail,
    )
    return {"id": row["id"], "ts": row["ts"].isoformat(), "username": user}


@app.get("/events")
async def list_events(limit: int = Query(50, ge=1, le=500), claims: dict = Depends(require_role(READER_ROLE))):
    pool = await get_pool()
    rows = await pool.fetch(
        "SELECT id, ts, username, action, detail FROM audit_events ORDER BY id DESC LIMIT $1", limit
    )
    return [
        {"id": r["id"], "ts": r["ts"].isoformat(), "username": r["username"],
         "action": r["action"], "detail": r["detail"]}
        for r in rows
    ]
