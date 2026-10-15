import html
import os
import secrets
import time
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt
from prometheus_fastapi_instrumentator import Instrumentator
from starlette.middleware.sessions import SessionMiddleware

ISSUER = os.getenv("KEYCLOAK_ISSUER", "").rstrip("/")
CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "sso-portal")
CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8000").rstrip("/")
AUDIT_API_URL = os.getenv("AUDIT_API_URL", "http://audit-api:8000").rstrip("/")
SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_urlsafe(32)

app = FastAPI(title="sso-portal")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=PUBLIC_URL.startswith("https://"),
)
Instrumentator().instrument(app).expose(app, include_in_schema=False)

# Metadata from Keycloak is fetched lazily on the first login,
# so the portal starts fine even when Keycloak is not deployed yet.
oauth = OAuth()
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

# Tokens are kept server-side (cookie holds only a session id): Keycloak tokens
# are too big for a 4 KB cookie. One replica is enough for this setup.
SESSIONS: dict[str, dict] = {}

HEAD = (
    "<!doctype html><html><head><meta charset='utf-8'><title>SSO portal</title>"
    "<style>body{font-family:sans-serif;max-width:760px;margin:40px auto;padding:0 16px}"
    "table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:4px 8px}"
    "button{padding:6px 12px}</style></head><body><h1>SSO portal</h1>"
)
TAIL = "</body></html>"


def page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(HEAD + body + TAIL, status_code=status)


def esc(value) -> str:
    return html.escape(str(value))


def get_session(request: Request):
    sid = request.session.get("sid")
    return SESSIONS.get(sid) if sid else None


async def fresh_access_token(request: Request):
    s = get_session(request)
    if not s:
        return None
    if s["expires_at"] - 15 > time.time():
        return s["access_token"]
    if not s.get("refresh_token"):
        return None
    try:
        meta = await oauth.keycloak.load_server_metadata()
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": s["refresh_token"],
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                },
            )
            r.raise_for_status()
        data = r.json()
    except Exception:
        return None
    s["access_token"] = data["access_token"]
    s["refresh_token"] = data.get("refresh_token", s["refresh_token"])
    s["expires_at"] = time.time() + data.get("expires_in", 300)
    return s["access_token"]


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    s = get_session(request)
    if not s:
        return page("<p>You are not signed in.</p><p><a href='/login'>Sign in with Keycloak</a></p>")
    info = s["userinfo"]
    roles = jwt.get_unverified_claims(s["access_token"]).get("realm_access", {}).get("roles", [])
    return page(
        f"<p>Signed in as <b>{esc(info.get('preferred_username', info.get('sub', '?')))}</b>"
        f" ({esc(info.get('email', 'no email'))})</p>"
        f"<p>Roles: {esc(', '.join(roles) or 'none')}</p>"
        "<form method='post' action='/send'><button>Send audit event</button></form>"
        "<p><a href='/events'>Show audit events</a> | <a href='/logout'>Sign out</a></p>"
    )


@app.get("/login")
async def login(request: Request):
    return await oauth.keycloak.authorize_redirect(request, f"{PUBLIC_URL}/callback")


@app.get("/callback")
async def callback(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except Exception as e:
        return page(f"<p>Login failed: {esc(e)}</p><p><a href='/login'>Try again</a></p>", 400)
    sid = secrets.token_urlsafe(24)
    SESSIONS[sid] = {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token"),
        "id_token": token.get("id_token"),
        "expires_at": token.get("expires_at", time.time() + 300),
        "userinfo": dict(token.get("userinfo") or {}),
    }
    request.session["sid"] = sid
    return RedirectResponse("/")


@app.post("/send", response_class=HTMLResponse)
async def send(request: Request):
    access = await fresh_access_token(request)
    if not access:
        return RedirectResponse("/login", status_code=303)
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{AUDIT_API_URL}/events",
                json={"action": "portal.button_click", "detail": time.strftime("%Y-%m-%d %H:%M:%S")},
                headers={"Authorization": f"Bearer {access}"},
            )
    except httpx.HTTPError as e:
        return page(f"<p>audit-api unreachable: {esc(e)}</p><p><a href='/'>Back</a></p>", 502)
    return page(f"<p>audit-api answered {r.status_code}</p><pre>{esc(r.text)}</pre><p><a href='/'>Back</a></p>")


@app.get("/events", response_class=HTMLResponse)
async def events(request: Request):
    access = await fresh_access_token(request)
    if not access:
        return RedirectResponse("/login")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{AUDIT_API_URL}/events", headers={"Authorization": f"Bearer {access}"})
    except httpx.HTTPError as e:
        return page(f"<p>audit-api unreachable: {esc(e)}</p><p><a href='/'>Back</a></p>", 502)
    if r.status_code != 200:
        return page(f"<p>audit-api answered {r.status_code}</p><pre>{esc(r.text)}</pre><p><a href='/'>Back</a></p>")
    rows = "".join(
        f"<tr><td>{esc(e['id'])}</td><td>{esc(e['ts'])}</td><td>{esc(e['username'])}</td>"
        f"<td>{esc(e['action'])}</td><td>{esc(e['detail'])}</td></tr>"
        for e in r.json()
    )
    return page(
        "<table><tr><th>id</th><th>time</th><th>user</th><th>action</th><th>detail</th></tr>"
        f"{rows}</table><p><a href='/'>Back</a></p>"
    )


@app.get("/logout")
async def logout(request: Request):
    s = SESSIONS.pop(request.session.get("sid"), None)
    request.session.clear()
    if s and s.get("id_token"):
        try:
            meta = await oauth.keycloak.load_server_metadata()
            endpoint = meta.get("end_session_endpoint")
        except Exception:
            endpoint = None
        if endpoint:
            q = urlencode({"id_token_hint": s["id_token"], "post_logout_redirect_uri": f"{PUBLIC_URL}/"})
            return RedirectResponse(f"{endpoint}?{q}")
    return RedirectResponse("/")
