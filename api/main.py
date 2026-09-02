import os
import html as html_mod
import re
import hmac
import sqlite3
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from time import time as _time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "data" / "feest.db"
PHOTOS_DIR = BASE_DIR / "data" / "photos"
ADMIN_USER = os.getenv("ADMIN_USER", "feestadmin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "")
if not ADMIN_PASS:
    raise RuntimeError("ADMIN_PASS must be set in the environment")
SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set in the environment")

SESSION_TTL_HOURS = 8
SLUG_PATTERN = re.compile(r"^[a-z0-9-]+$")
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 900
_login_attempts: dict[str, list[float]] = {}

# ─────────────────────────────────────────
# DB helpers
# ─────────────────────────────────────────
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS members (
            slug        TEXT PRIMARY KEY,
            full_name   TEXT NOT NULL,
            role        TEXT,
            phone       TEXT,
            email       TEXT,
            linkedin    TEXT,
            photo_ext   TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            route       TEXT NOT NULL,
            ip          TEXT,
            user_agent  TEXT,
            referer     TEXT,
            scanned_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            expires_at  TEXT NOT NULL
        );
    """)
    db.commit()

    # Seed team members (INSERT OR IGNORE so re-deploys don't clobber edits)
    members = [
        ("damilare", "Damilare Adebisi",  "Head of Marketing", "09037379543",  "dami@usefeest.com",   "https://www.linkedin.com/in/adebisi-oluwadamilare-7575111a3"),
        ("fejulo",   "Fejulo Afolabi",    "Head of Finance",   "09060740993",  "fejulo@usefeest.com", "https://www.linkedin.com/in/afofej"),
        ("melvin",   "Melvin Senne-Aya",  "Co-Founder & COO",  "09135572082",  "melvin@usefeest.com", "https://www.linkedin.com/in/melvin-ogh"),
        ("gift",     "Gift Akobundu",     "Co-Founder & CEO",  "09130387630",  "ghift@usefeest.com",  "https://www.linkedin.com/in/gh-ft"),
    ]
    db.executemany("""
        INSERT OR IGNORE INTO members (slug, full_name, role, phone, email, linkedin)
        VALUES (?,?,?,?,?,?)
    """, members)
    db.commit()
    db.close()

# ─────────────────────────────────────────
# Session helpers
# ─────────────────────────────────────────
def make_session_token():
    return secrets.token_urlsafe(48)

def create_session(db):
    token = make_session_token()
    expires = (datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    db.execute("INSERT INTO sessions (token, expires_at) VALUES (?,?)", (token, expires))
    db.commit()
    return token

def validate_session(token: str) -> bool:
    if not token:
        return False
    db = get_db()
    row = db.execute(
        "SELECT expires_at FROM sessions WHERE token=?", (token,)
    ).fetchone()
    db.close()
    if not row:
        return False
    return datetime.fromisoformat(row["expires_at"]) > datetime.utcnow()

def require_admin(session: str = Cookie(default=None)):
    if not validate_session(session or ""):
        raise HTTPException(status_code=302, headers={"Location": "/xadmin/login"})
    return True

# ─────────────────────────────────────────
# Slug validation
# ─────────────────────────────────────────
def validate_slug(slug: str) -> str:
    s = slug.lower()
    if not SLUG_PATTERN.match(s):
        raise HTTPException(status_code=400, detail="Invalid slug")
    return s

# ─────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────
def _client_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "")

def _check_rate_limit(ip: str):
    now = _time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=302, headers={
            "Location": "/xadmin/login?error=Too+many+attempts.+Try+again+in+15+minutes."
        })

def _record_failed_login(ip: str):
    _login_attempts.setdefault(ip, []).append(_time())

def _clear_login_attempts(ip: str):
    _login_attempts.pop(ip, None)

# ─────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(lifespan=lifespan)

# ─────────────────────────────────────────
# Tracking helper
# ─────────────────────────────────────────
def log_scan(route: str, request: Request):
    db = get_db()
    db.execute(
        "INSERT INTO scans (route, ip, user_agent, referer) VALUES (?,?,?,?)",
        (
            route,
            request.headers.get("x-forwarded-for", request.client.host if request.client else ""),
            request.headers.get("user-agent", ""),
            request.headers.get("referer", ""),
        )
    )
    db.commit()
    db.close()

# ─────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────
FONT = "https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800&display=swap"

COLORS = """
:root {
  --primary:      #F7715B;
  --primary-dark: #e55a44;
  --bg:           #FFF6E8;
  --surface:      #FFFFFF;
  --text:         #2F2F2F;
  --muted:        #9E9E9E;
  --border:       rgba(247,113,91,0.18);
  --shadow:       0 4px 24px rgba(247,113,91,0.10);
  --shadow-hover: 0 8px 32px rgba(247,113,91,0.22);
  --r:            16px;
}
"""

def base_head(title: str, og_title: str = "", og_description: str = "", og_image: str = "") -> str:
    esc_title = html_mod.escape(title)
    og_block = ""
    if og_title or og_description or og_image:
        og_block = f"""
  <meta property="og:title" content="{html_mod.escape(og_title or title)}"/>
  <meta property="og:description" content="{html_mod.escape(og_description)}"/>
  <meta property="og:image" content="{html_mod.escape(og_image)}"/>"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>{esc_title}</title>{og_block}
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="{FONT}" rel="stylesheet"/>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    {COLORS}
    body{{font-family:'Montserrat',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:48px 20px 40px}}
    a{{text-decoration:none}}
  </style>
</head>
<body>
"""

STATIC_DIR = BASE_DIR / "static"
FALLBACK_INDEX = BASE_DIR.parent / "index.html"

# ─────────────────────────────────────────
# Routes — Homepage
# ─────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root_page(request: Request):
    log_scan("homepage", request)
    index_path = STATIC_DIR / "index.html" if (STATIC_DIR / "index.html").exists() else FALLBACK_INDEX
    return FileResponse(str(index_path))

# ─────────────────────────────────────────
# Routes — Tracking redirects
# ─────────────────────────────────────────
@app.get("/brnch")
async def brochure_scan(request: Request):
    log_scan("brochure", request)
    return RedirectResponse(url="https://link.usefeest.com/", status_code=302)

@app.get("/rlpban")
async def rollup_banner_scan(request: Request):
    log_scan("rollup_banner", request)
    return RedirectResponse(url="https://link.usefeest.com/", status_code=302)

# ─────────────────────────────────────────
# Routes — Card pages
# ─────────────────────────────────────────
@app.get("/card/{slug}", response_class=HTMLResponse)
async def card_page(slug: str, request: Request):
    slug = validate_slug(slug)
    log_scan(f"card/{slug}", request)

    db = get_db()
    member = db.execute(
        "SELECT * FROM members WHERE lower(slug)=?", (slug.lower(),)
    ).fetchone()
    db.close()

    if not member:
        raise HTTPException(status_code=404, detail="Not found")

    m = dict(member)
    name_raw = m["full_name"]
    role_raw = m["role"] or ""
    phone_raw = m["phone"]
    email_raw = m["email"]
    linkedin_raw = m["linkedin"]
    slug_l = m["slug"]

    esc = html_mod.escape
    name = esc(name_raw)
    role = esc(role_raw)
    phone = esc(phone_raw) if phone_raw else ""
    email = esc(email_raw) if email_raw else ""
    linkedin = esc(linkedin_raw) if linkedin_raw else ""
    slug_esc = esc(slug_l)

    # Photo
    photo_ext = m.get("photo_ext")
    if photo_ext and (PHOTOS_DIR / f"{slug_l}.{photo_ext}").exists():
        photo_html = f'<img src="/api/card-photo/{slug_esc}" alt="{name}" class="avatar"/>'
    else:
        initials = esc("".join(w[0].upper() for w in name_raw.split()[:2]))
        photo_html = f'<div class="avatar-initials">{initials}</div>'

    # Buttons
    btns = []
    if phone_raw:
        wa_num = "234" + phone_raw.lstrip("0")
        btns.append(f"""
        <a class="btn primary" href="https://wa.me/{esc(wa_num)}" target="_blank" rel="noopener">
          {icon_wa()} Chat on WhatsApp
        </a>""")
        btns.append(f"""
        <a class="btn" href="tel:{phone}">
          {icon_phone()} Call
        </a>""")
    if email_raw:
        btns.append(f"""
        <a class="btn" href="mailto:{email}">
          {icon_email()} Email
        </a>""")
    if linkedin_raw:
        btns.append(f"""
        <a class="btn" href="{linkedin}" target="_blank" rel="noopener">
          {icon_linkedin()} LinkedIn
        </a>""")

    btns.append(f"""
    <a class="btn outline" href="/card/{slug_esc}/vcard" download="{esc(name_raw.replace(' ','_'))}.vcf">
      {icon_contact()} Save Contact
    </a>""")

    btns_html = "\n".join(btns)

    og_image = f"https://link.usefeest.com/api/card-photo/{slug_esc}" if photo_ext else "https://link.usefeest.com/logo.png"
    return base_head(
        f"{name} — Feest",
        og_title=name_raw,
        og_description=f"{role_raw} at Feest",
        og_image=og_image,
    ) + f"""
<style>
  .card{{width:100%;max-width:420px;display:flex;flex-direction:column;align-items:center;gap:0}}
  .avatar,.avatar-initials{{width:108px;height:108px;border-radius:50%;object-fit:cover;border:3px solid var(--primary);box-shadow:var(--shadow);margin-bottom:16px}}
  .avatar-initials{{background:var(--primary);color:#fff;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:800}}
  h1{{font-size:22px;font-weight:800;letter-spacing:-.5px;text-align:center}}
  .role{{font-size:13px;font-weight:600;color:var(--muted);margin:4px 0 28px;text-align:center}}
  .links{{width:100%;display:flex;flex-direction:column;gap:12px;margin-bottom:32px}}
  .btn{{display:flex;align-items:center;gap:14px;width:100%;padding:15px 20px;background:var(--surface);border:1.5px solid var(--border);border-radius:var(--r);color:var(--text);font-family:'Montserrat',sans-serif;font-size:14px;font-weight:600;box-shadow:var(--shadow);transition:transform .18s,box-shadow .18s,border-color .18s;cursor:pointer}}
  .btn:hover{{transform:translateY(-2px);box-shadow:var(--shadow-hover);border-color:var(--primary)}}
  .btn:active{{transform:scale(.98)}}
  .btn.primary{{background:var(--primary);border-color:var(--primary);color:#fff}}
  .btn.primary:hover{{background:var(--primary-dark);border-color:var(--primary-dark)}}
  .btn.outline{{background:transparent;border:1.5px solid var(--primary);color:var(--primary);box-shadow:var(--shadow)}}
  .btn.outline:hover{{background:rgba(247,113,91,.06)}}
  .btn svg{{width:20px;height:20px;flex-shrink:0}}
  .feest-link{{margin-top:8px;font-size:12px;color:var(--muted);font-weight:500}}
  .feest-link a{{color:var(--primary)}}
  .feest-link a:hover{{text-decoration:underline}}
  @media(max-width:380px){{body{{padding:32px 16px 48px}};h1{{font-size:20px}}}}
</style>
<div class="card">
  {photo_html}
  <h1>{name}</h1>
  <p class="role">{role} · Feest</p>
  <div class="links">
    {btns_html}
  </div>
  <p class="feest-link">Powered by <a href="https://link.usefeest.com">Feest</a></p>
</div>
</body></html>
"""

# ─────────────────────────────────────────
# Routes — Photo serving
# ─────────────────────────────────────────
@app.get("/api/card-photo/{slug}")
async def card_photo(slug: str):
    slug = validate_slug(slug)
    db = get_db()
    row = db.execute("SELECT photo_ext FROM members WHERE slug=?", (slug,)).fetchone()
    db.close()
    if not row or not row["photo_ext"]:
        raise HTTPException(status_code=404)
    path = PHOTOS_DIR / f"{slug}.{row['photo_ext']}"
    if not path.exists():
        raise HTTPException(status_code=404)
    return FileResponse(str(path))

# ─────────────────────────────────────────
# Routes — vCard download
# ─────────────────────────────────────────
@app.get("/card/{slug}/vcard")
async def vcard(slug: str):
    slug = validate_slug(slug)
    db = get_db()
    m = db.execute("SELECT * FROM members WHERE lower(slug)=?", (slug,)).fetchone()
    db.close()
    if not m:
        raise HTTPException(status_code=404)
    m = dict(m)
    lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"FN:{m['full_name']}",
        f"ORG:Feest",
        f"TITLE:{m['role'] or ''}",
    ]
    if m["phone"]:
        lines.append(f"TEL;TYPE=CELL:{m['phone']}")
    if m["email"]:
        lines.append(f"EMAIL:{m['email']}")
    if m["linkedin"]:
        lines.append(f"URL:{m['linkedin']}")
    lines.append("END:VCARD")
    content = "\r\n".join(lines)
    name_safe = m["full_name"].replace(" ", "_")
    return Response(
        content=content,
        media_type="text/vcard",
        headers={"Content-Disposition": f'attachment; filename="{name_safe}.vcf"'}
    )

# ─────────────────────────────────────────
# Routes — Admin login
# ─────────────────────────────────────────
@app.get("/xadmin/login")
async def login_page(error: str = ""):
    err_html = f'<p class="err">{html_mod.escape(error)}</p>' if error else ""
    csrf_token = secrets.token_urlsafe(32)
    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin — Feest</title>
  <link href="{FONT}" rel="stylesheet"/>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Montserrat',sans-serif;background:#FFF6E8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}}
    .box{{background:#fff;border-radius:20px;padding:40px 36px;width:100%;max-width:380px;box-shadow:0 4px 32px rgba(247,113,91,.13)}}
    h1{{font-size:20px;font-weight:800;margin-bottom:6px}}
    .sub{{font-size:13px;color:#9E9E9E;margin-bottom:28px}}
    label{{display:block;font-size:12px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#9E9E9E;margin-bottom:6px}}
    input{{width:100%;padding:12px 14px;border:1.5px solid rgba(247,113,91,.2);border-radius:10px;font-family:'Montserrat',sans-serif;font-size:14px;outline:none;transition:border-color .18s;margin-bottom:16px}}
    input:focus{{border-color:#F7715B}}
    button{{width:100%;padding:14px;background:#F7715B;color:#fff;border:none;border-radius:10px;font-family:'Montserrat',sans-serif;font-size:15px;font-weight:700;cursor:pointer;transition:background .18s}}
    button:hover{{background:#e55a44}}
    .err{{color:#e55a44;font-size:13px;font-weight:600;margin-bottom:16px;text-align:center}}
  </style>
</head>
<body>
<div class="box">
  <h1>Admin Login</h1>
  <p class="sub">Feest Links Dashboard</p>
  {err_html}
  <form method="POST" action="/xadmin/login">
    <input type="hidden" name="csrf_token" value="{csrf_token}"/>
    <label>Username</label>
    <input name="username" type="text" autocomplete="username" required/>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" required/>
    <button type="submit">Sign In</button>
  </form>
</div>
</body></html>"""
    resp = HTMLResponse(content=body)
    resp.set_cookie(
        "csrf_token", csrf_token,
        httponly=True, samesite="strict", secure=True, max_age=600,
    )
    return resp

@app.post("/xadmin/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    csrf_cookie: str = Cookie(default="", alias="csrf_token"),
):
    if not csrf_token or not csrf_cookie or csrf_token != csrf_cookie:
        return RedirectResponse(url="/xadmin/login?error=Invalid+request", status_code=302)

    ip = _client_ip(request)
    _check_rate_limit(ip)

    if username == ADMIN_USER and password == ADMIN_PASS:
        _clear_login_attempts(ip)
        db = get_db()
        token = create_session(db)
        db.close()
        resp = RedirectResponse(url="/xadmin", status_code=302)
        resp.set_cookie(
            "session", token,
            httponly=True, samesite="lax", secure=True,
            max_age=SESSION_TTL_HOURS * 3600
        )
        resp.delete_cookie("csrf_token")
        return resp

    _record_failed_login(ip)
    return RedirectResponse(url="/xadmin/login?error=Invalid+credentials", status_code=302)

@app.get("/xadmin/logout")
async def logout(response: Response, session: str = Cookie(default=None)):
    if session:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token=?", (session,))
        db.commit()
        db.close()
    resp = RedirectResponse(url="/xadmin/login", status_code=302)
    resp.delete_cookie("session")
    return resp

# ─────────────────────────────────────────
# Routes — Admin dashboard
# ─────────────────────────────────────────
@app.get("/xadmin", response_class=HTMLResponse)
async def admin_dashboard(_=Depends(require_admin)):
    db = get_db()

    # Total scans per route
    route_rows = db.execute("""
        SELECT route, COUNT(*) as total,
               MAX(scanned_at) as last_scan
        FROM scans
        GROUP BY route
        ORDER BY total DESC
    """).fetchall()

    # Scans in last 7 days by day
    daily_rows = db.execute("""
        SELECT date(scanned_at) as day, COUNT(*) as cnt
        FROM scans
        WHERE scanned_at >= datetime('now', '-7 days')
        GROUP BY day
        ORDER BY day
    """).fetchall()

    # Recent scans
    recent = db.execute("""
        SELECT route, ip, user_agent, scanned_at
        FROM scans
        ORDER BY scanned_at DESC
        LIMIT 30
    """).fetchall()

    db.close()

    total_all = sum(r["total"] for r in route_rows)

    esc = html_mod.escape

    # Build route table rows
    route_html = ""
    for r in route_rows:
        label = esc(_route_label(r["route"]))
        pct = round(r["total"] / total_all * 100) if total_all else 0
        last = esc(r["last_scan"][:16].replace("T", " ")) if r["last_scan"] else "—"
        route_html += f"""
        <tr>
          <td><span class="badge">{esc(r['route'])}</span></td>
          <td>{label}</td>
          <td><strong>{r['total']}</strong></td>
          <td>
            <div class="bar-wrap"><div class="bar" style="width:{pct}%"></div></div>
          </td>
          <td class="muted">{last}</td>
        </tr>"""

    # Build daily chart data
    daily_labels = [r["day"] for r in daily_rows]
    daily_counts = [r["cnt"] for r in daily_rows]

    # Recent scans table
    recent_html = ""
    for r in recent:
        ua_short = r["user_agent"][:48] + "…" if r["user_agent"] and len(r["user_agent"]) > 48 else (r["user_agent"] or "—")
        ts = esc(r["scanned_at"][:16].replace("T", " "))
        recent_html += f"""
        <tr>
          <td><span class="badge">{esc(r['route'])}</span></td>
          <td class="muted">{esc(r['ip'] or '—')}</td>
          <td class="muted small">{esc(ua_short)}</td>
          <td class="muted">{ts}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin — Feest Links</title>
  <link href="{FONT}" rel="stylesheet"/>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Montserrat',sans-serif;background:#F5F5F5;color:#2F2F2F;min-height:100vh}}
    header{{background:#fff;border-bottom:1px solid #eee;padding:16px 32px;display:flex;align-items:center;justify-content:space-between}}
    header h1{{font-size:18px;font-weight:800}}header h1 span{{color:#F7715B}}
    header a{{font-size:13px;font-weight:600;color:#9E9E9E;text-decoration:none}}
    header a:hover{{color:#F7715B}}
    .main{{max-width:1100px;margin:0 auto;padding:32px 24px;display:flex;flex-direction:column;gap:28px}}
    .stats-row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}}
    .stat-card{{background:#fff;border-radius:16px;padding:20px 24px;box-shadow:0 2px 12px rgba(0,0,0,.05)}}
    .stat-card .val{{font-size:32px;font-weight:800;color:#F7715B}}
    .stat-card .lbl{{font-size:12px;font-weight:600;color:#9E9E9E;margin-top:4px}}
    .panel{{background:#fff;border-radius:16px;padding:24px;box-shadow:0 2px 12px rgba(0,0,0,.05)}}
    .panel h2{{font-size:15px;font-weight:700;margin-bottom:20px}}
    table{{width:100%;border-collapse:collapse;font-size:13px}}
    th{{text-align:left;font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#9E9E9E;padding-bottom:12px;border-bottom:1px solid #f0f0f0}}
    td{{padding:10px 0;border-bottom:1px solid #f8f8f8;vertical-align:middle}}
    tr:last-child td{{border:none}}
    .badge{{background:#FFF6E8;color:#F7715B;font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px;display:inline-block}}
    .bar-wrap{{background:#f5f5f5;border-radius:999px;height:6px;width:120px}}
    .bar{{background:#F7715B;border-radius:999px;height:6px;transition:width .4s}}
    .muted{{color:#9E9E9E}}
    .small{{font-size:12px}}
    canvas{{max-height:200px}}
    @media(max-width:600px){{.main{{padding:20px 14px}};header{{padding:14px 16px}}}}
  </style>
</head>
<body>
<header>
  <h1>Feest <span>Links</span> Admin</h1>
  <a href="/xadmin/logout">Sign out</a>
</header>
<div class="main">

  <!-- Stat cards -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="val">{total_all}</div>
      <div class="lbl">Total Scans</div>
    </div>
    <div class="stat-card">
      <div class="val">{len(route_rows)}</div>
      <div class="lbl">Active Routes</div>
    </div>
    <div class="stat-card">
      <div class="val">{sum(r['cnt'] for r in daily_rows)}</div>
      <div class="lbl">Last 7 Days</div>
    </div>
  </div>

  <!-- Daily chart -->
  <div class="panel">
    <h2>Scans — Last 7 Days</h2>
    <canvas id="chart"></canvas>
  </div>

  <!-- Per-route breakdown -->
  <div class="panel">
    <h2>Scans by Route</h2>
    <table>
      <thead><tr><th>Route</th><th>Label</th><th>Total</th><th>Share</th><th>Last Scan</th></tr></thead>
      <tbody>{route_html or '<tr><td colspan=5 class="muted">No scans yet.</td></tr>'}</tbody>
    </table>
  </div>

  <!-- Recent scans -->
  <div class="panel">
    <h2>Recent Scans (last 30)</h2>
    <table>
      <thead><tr><th>Route</th><th>IP</th><th>User Agent</th><th>Time (UTC)</th></tr></thead>
      <tbody>{recent_html or '<tr><td colspan=4 class="muted">No scans yet.</td></tr>'}</tbody>
    </table>
  </div>

</div>
<script>
new Chart(document.getElementById('chart'), {{
  type: 'bar',
  data: {{
    labels: {daily_labels},
    datasets: [{{
      label: 'Scans',
      data: {daily_counts},
      backgroundColor: '#F7715B',
      borderRadius: 6,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ beginAtZero: true, ticks: {{ precision: 0 }} }},
      x: {{ grid: {{ display: false }} }}
    }}
  }}
}});
</script>
</body></html>"""

def _route_label(route: str) -> str:
    labels = {
        "brochure":     "Brochure",
        "rollup_banner":"Rollup Banner",
        "card/damilare":"Damilare's Card",
        "card/fejulo":  "Fejulo's Card",
        "card/melvin":  "Melvin's Card",
        "card/gift":    "Gift's Card",
    }
    return labels.get(route, route.replace("/", " / ").title())

# ─────────────────────────────────────────
# Inline SVG icons
# ─────────────────────────────────────────
def icon_wa():
    return """<svg viewBox="0 0 24 24" fill="white"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 0C5.373 0 0 5.373 0 12c0 2.104.547 4.08 1.504 5.797L.057 23.886a.5.5 0 00.619.61l6.241-1.637A11.945 11.945 0 0012 24c6.627 0 12-5.373 12-12S18.627 0 12 0zm0 22a9.944 9.944 0 01-5.088-1.393l-.365-.218-3.782.992.992-3.688-.236-.382A9.944 9.944 0 012 12C2 6.477 6.477 2 12 2s10 4.477 10 10-4.477 10-10 10z"/></svg>"""

def icon_phone():
    return """<svg viewBox="0 0 24 24" fill="none" stroke="#F7715B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.81a19.79 19.79 0 01-3.07-8.68A2 2 0 012 1h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.09 8.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/></svg>"""

def icon_email():
    return """<svg viewBox="0 0 24 24" fill="none" stroke="#F7715B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>"""

def icon_linkedin():
    return """<svg viewBox="0 0 24 24" fill="#F7715B"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>"""

def icon_contact():
    return """<svg viewBox="0 0 24 24" fill="none" stroke="#F7715B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>"""
