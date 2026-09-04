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

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Form, Cookie, UploadFile, File
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
  /* ── Card shell ── */
  body {{ padding: 0 !important; background: #F5F5F5 !important; align-items: stretch !important; }}

  .card-page {{
    min-height: 100vh;
    background: #F5F5F5;
    display: flex;
    flex-direction: column;
    align-items: center;
  }}

  /* ── Brand header ── */
  .brand-header {{
    width: 100%;
    background: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px 24px 20px;
    border-bottom: 1px solid #EFEFEF;
  }}

  .brand-logo {{
    height: 32px;
    width: auto;
  }}

  /* ── White card body ── */
  .card-body {{
    width: 100%;
    max-width: 480px;
    background: #fff;
    flex: 1;
    padding: 32px 24px 48px;
    display: flex;
    flex-direction: column;
  }}

  /* ── Avatar ── */
  .avatar-wrap {{
    margin-bottom: 20px;
  }}

  .avatar, .avatar-initials {{
    width: 100px;
    height: 100px;
    border-radius: 50%;
    object-fit: cover;
    border: 3px solid #EFEFEF;
  }}

  .avatar-initials {{
    background: var(--primary);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 32px;
    font-weight: 800;
    border: 3px solid #EFEFEF;
  }}

  /* ── Name block ── */
  .name-block {{
    margin-bottom: 28px;
  }}

  .name-block h1 {{
    font-size: 28px;
    font-weight: 600;
    letter-spacing: -0.5px;
    color: #1A1A1A;
    line-height: 1.2;
    margin-bottom: 6px;
  }}

  .name-block .job-title {{
    font-size: 15px;
    font-weight: 500;
    color: #666;
    line-height: 1.5;
  }}

  .name-block .company {{
    font-size: 15px;
    font-weight: 600;
    color: #444;
  }}

  /* ── Contact rows ── */
  .contact-rows {{
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 32px;
  }}

  .contact-row {{
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 14px 0;
    border-bottom: 1px solid #F2F2F2;
    text-decoration: none;
    color: inherit;
    transition: opacity .15s;
  }}

  .contact-row:last-child {{ border-bottom: none; }}
  .contact-row:hover {{ opacity: 0.75; }}

  .row-icon {{
    width: 46px;
    height: 46px;
    border-radius: 50%;
    background: var(--primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }}

  .row-icon svg {{
    width: 20px;
    height: 20px;
  }}

  .row-text {{
    display: flex;
    flex-direction: column;
    gap: 2px;
  }}

  .row-label {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #999;
  }}

  .row-value {{
    font-size: 15px;
    font-weight: 600;
    color: #1A1A1A;
  }}

  /* ── Save Contact CTA ── */
  .save-btn {{
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    padding: 17px 24px;
    background: var(--primary);
    color: #fff;
    border: none;
    border-radius: 999px;
    font-family: 'Montserrat', sans-serif;
    font-size: 16px;
    font-weight: 700;
    text-decoration: none;
    cursor: pointer;
    transition: background .18s, transform .15s;
    margin-top: auto;
  }}

  .save-btn:hover {{ background: var(--primary-dark); transform: translateY(-1px); }}
  .save-btn:active {{ transform: scale(.98); }}
  .save-btn svg {{ width: 20px; height: 20px; flex-shrink: 0; }}

  /* ── Footer ── */
  .card-footer {{
    text-align: center;
    padding: 20px 0 8px;
    font-size: 12px;
    color: #bbb;
    font-weight: 500;
  }}

  .card-footer a {{ color: var(--primary); text-decoration: none; }}
</style>

<div class="card-page">

  <div class="brand-header">
    <img src="/logo.png" alt="Feest" class="brand-logo"/>
  </div>

  <div class="card-body">

    <div class="avatar-wrap">
      {photo_html}
    </div>

    <div class="name-block">
      <h1>{name}</h1>
      <p class="job-title">{role}</p>
      <p class="company">Feest</p>
    </div>

    <div class="contact-rows">
      {''.join([
        f'''<a class="contact-row" href="tel:{phone}">
          <div class="row-icon">{icon_phone_white()}</div>
          <div class="row-text">
            <span class="row-label">Phone</span>
            <span class="row-value">{phone}</span>
          </div>
        </a>''' if phone_raw else '',

        f'''<a class="contact-row" href="https://wa.me/234{esc(phone_raw.lstrip('0'))}" target="_blank" rel="noopener">
          <div class="row-icon">{icon_wa_white()}</div>
          <div class="row-text">
            <span class="row-label">WhatsApp</span>
            <span class="row-value">Chat on WhatsApp</span>
          </div>
        </a>''' if phone_raw else '',

        f'''<a class="contact-row" href="mailto:{email}">
          <div class="row-icon">{icon_email_white()}</div>
          <div class="row-text">
            <span class="row-label">Email</span>
            <span class="row-value">{email}</span>
          </div>
        </a>''' if email_raw else '',

        f'''<a class="contact-row" href="{linkedin}" target="_blank" rel="noopener">
          <div class="row-icon">{icon_linkedin_white()}</div>
          <div class="row-text">
            <span class="row-label">LinkedIn</span>
            <span class="row-value">Connect on LinkedIn</span>
          </div>
        </a>''' if linkedin_raw else '',
      ])}
    </div>

    <a class="save-btn" href="/card/{slug_esc}/vcard" download="{esc(name_raw.replace(' ','_'))}.vcf">
      {icon_contact_white()} Save Contact
    </a>

    <p class="card-footer">Powered by <a href="https://link.usefeest.com">Feest</a></p>

  </div>

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
    body{{font-family:'Montserrat',sans-serif;background:#1C1C1E;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}}
    .box{{background:#fff;border-radius:16px;padding:36px 32px 32px;width:100%;max-width:340px;box-shadow:0 8px 40px rgba(0,0,0,.45)}}
    .logo-wrap{{display:flex;justify-content:center;margin-bottom:24px}}
    .logo-wrap img{{height:28px;width:auto}}
    label{{display:block;font-size:11px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:#999;margin-bottom:6px}}
    input{{width:100%;padding:12px 14px;border:1.5px solid #E4E4E7;border-radius:10px;font-family:'Montserrat',sans-serif;font-size:14px;outline:none;transition:border-color .18s;margin-bottom:16px;color:#111}}
    input:focus{{border-color:#F7715B}}
    button{{width:100%;padding:14px;background:#F7715B;color:#fff;border:none;border-radius:10px;font-family:'Montserrat',sans-serif;font-size:14px;font-weight:700;cursor:pointer;transition:background .18s;margin-top:4px}}
    button:hover{{background:#e55a44}}
    .err{{color:#e55a44;font-size:12px;font-weight:600;margin-bottom:16px;text-align:center}}
  </style>
</head>
<body>
<div class="box">
  <div class="logo-wrap">
    <img src="/logo.png" alt="Feest"/>
  </div>
  {err_html}
  <form method="POST" action="/xadmin/login">
    <input type="hidden" name="csrf_token" value="{csrf_token}"/>
    <label>Username</label>
    <input name="username" type="text" autocomplete="username" required/>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" required/>
    <button type="submit">Sign in</button>
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
# Routes — Member management
# ─────────────────────────────────────────
ALLOWED_PHOTO_TYPES = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}

def _member_edit_page(slug: str, member: dict, saved: bool = False, error: str = "") -> str:
    esc = html_mod.escape
    saved_banner = '<div class="banner success">Changes saved successfully.</div>' if saved else ""
    error_banner = f'<div class="banner error">{esc(error)}</div>' if error else ""
    photo_html = ""
    if member.get("photo_ext"):
        photo_html = f'<img src="/api/card-photo/{esc(slug)}" class="current-photo" alt="Current photo"/>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Edit {esc(member['full_name'])} · Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="{FONT}" rel="stylesheet"/>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    :root{{--coral:#F7715B;--dark:#111;--bg:#F4F4F5;--surface:#fff;--border:#E4E4E7;--muted:#A1A1AA;--text:#18181B;--r:14px}}
    body{{font-family:'Montserrat',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
    header{{background:var(--dark);padding:0 32px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}}
    .header-brand{{display:flex;align-items:center;gap:12px}}
    .header-logo{{height:28px;width:auto}}
    .back-link{{font-size:12px;font-weight:600;color:var(--muted);text-decoration:none;padding:6px 14px;border:1px solid #333;border-radius:8px;transition:color .15s,border-color .15s}}
    .back-link:hover{{color:#fff;border-color:#666}}
    .main{{max-width:640px;margin:0 auto;padding:32px 24px 64px;display:flex;flex-direction:column;gap:24px}}
    .page-title{{font-size:20px;font-weight:800;letter-spacing:-.5px}}
    .page-sub{{font-size:13px;color:var(--muted);margin-top:4px}}
    .panel{{background:var(--surface);border-radius:var(--r);border:1px solid var(--border);overflow:hidden}}
    .panel-header{{padding:20px 24px 0;margin-bottom:20px}}
    .panel-title{{font-size:14px;font-weight:700}}
    form{{padding:0 24px 24px;display:flex;flex-direction:column;gap:16px}}
    .field{{display:flex;flex-direction:column;gap:6px}}
    label{{font-size:11px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--muted)}}
    input[type=text],input[type=email],input[type=tel]{{width:100%;padding:11px 14px;border:1.5px solid var(--border);border-radius:10px;font-family:'Montserrat',sans-serif;font-size:14px;outline:none;transition:border-color .18s;background:#fff;color:var(--text)}}
    input:focus{{border-color:var(--coral)}}
    .photo-section{{display:flex;flex-direction:column;gap:10px}}
    .current-photo{{width:80px;height:80px;border-radius:50%;object-fit:cover;border:3px solid var(--border)}}
    input[type=file]{{font-family:'Montserrat',sans-serif;font-size:13px;color:var(--muted)}}
    .photo-hint{{font-size:11px;color:var(--muted)}}
    .btn-row{{display:flex;gap:12px;margin-top:8px}}
    .btn-save{{padding:12px 28px;background:var(--coral);color:#fff;border:none;border-radius:10px;font-family:'Montserrat',sans-serif;font-size:14px;font-weight:700;cursor:pointer;transition:background .18s}}
    .btn-save:hover{{background:#e55a44}}
    .btn-cancel{{padding:12px 20px;background:transparent;color:var(--muted);border:1.5px solid var(--border);border-radius:10px;font-family:'Montserrat',sans-serif;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center}}
    .banner{{padding:12px 16px;border-radius:10px;font-size:13px;font-weight:600;margin-bottom:4px}}
    .banner.success{{background:#F0FDF4;color:#16A34A;border:1px solid #BBF7D0}}
    .banner.error{{background:#FFF1F2;color:#E11D48;border:1px solid #FECDD3}}
    @media(max-width:640px){{.main{{padding:20px 16px 48px}};header{{padding:0 16px}}}}
  </style>
</head>
<body>
<header>
  <div class="header-brand">
    <img src="/logo.png" alt="Feest" class="header-logo"/>
  </div>
  <a class="back-link" href="/xadmin/members">&#8592; All Members</a>
</header>
<div class="main">
  <div>
    <h1 class="page-title">Edit {esc(member['full_name'])}</h1>
    <p class="page-sub">Updates go live immediately on their card page.</p>
  </div>
  {saved_banner}{error_banner}
  <div class="panel">
    <div class="panel-header"><p class="panel-title">Profile Details</p></div>
    <form method="POST" enctype="multipart/form-data">
      <div class="field">
        <label>Full Name</label>
        <input type="text" name="full_name" value="{esc(member['full_name'])}" required/>
      </div>
      <div class="field">
        <label>Role / Job Title</label>
        <input type="text" name="role" value="{esc(member['role'] or '')}"/>
      </div>
      <div class="field">
        <label>Phone</label>
        <input type="tel" name="phone" value="{esc(member['phone'] or '')}"/>
      </div>
      <div class="field">
        <label>Email</label>
        <input type="email" name="email" value="{esc(member['email'] or '')}"/>
      </div>
      <div class="field">
        <label>LinkedIn URL</label>
        <input type="text" name="linkedin" value="{esc(member['linkedin'] or '')}"/>
      </div>
      <div class="field">
        <label>Profile Photo</label>
        <div class="photo-section">
          {photo_html}
          <input type="file" name="photo" accept="image/jpeg,image/png,image/webp"/>
          <p class="photo-hint">JPG, PNG or WebP · Max 5 MB · Will be cropped to a circle on the card</p>
        </div>
      </div>
      <div class="btn-row">
        <button class="btn-save" type="submit">Save Changes</button>
        <a class="btn-cancel" href="/xadmin/members">Cancel</a>
      </div>
    </form>
  </div>
</div>
</body></html>"""

@app.get("/xadmin/members", response_class=HTMLResponse)
async def members_list(_=Depends(require_admin)):
    db = get_db()
    rows = db.execute("SELECT * FROM members ORDER BY full_name").fetchall()
    db.close()
    esc = html_mod.escape
    cards_html = ""
    for m in rows:
        slug = m["slug"]
        photo_tag = f'<img src="/api/card-photo/{esc(slug)}" class="member-avatar" alt="{esc(m["full_name"])}"/>' \
            if m["photo_ext"] else \
            f'<div class="member-avatar initials">{esc("".join(w[0].upper() for w in m["full_name"].split()[:2]))}</div>'
        cards_html += f"""
        <div class="member-card">
          {photo_tag}
          <div class="member-info">
            <p class="member-name">{esc(m['full_name'])}</p>
            <p class="member-role">{esc(m['role'] or '—')}</p>
            <p class="member-meta">{esc(m['email'] or '—')}</p>
          </div>
          <a class="edit-btn" href="/xadmin/members/{esc(slug)}/edit">Edit</a>
        </div>"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Members · Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="{FONT}" rel="stylesheet"/>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    :root{{--coral:#F7715B;--dark:#111;--bg:#F4F4F5;--surface:#fff;--border:#E4E4E7;--muted:#A1A1AA;--text:#18181B;--r:14px}}
    body{{font-family:'Montserrat',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
    header{{background:var(--dark);padding:0 32px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}}
    .header-brand{{display:flex;align-items:center;gap:12px}}
    .header-logo{{height:28px;width:auto}}
    .back-link{{font-size:12px;font-weight:600;color:var(--muted);text-decoration:none;padding:6px 14px;border:1px solid #333;border-radius:8px;transition:color .15s,border-color .15s}}
    .back-link:hover{{color:#fff;border-color:#666}}
    .main{{max-width:640px;margin:0 auto;padding:32px 24px 64px;display:flex;flex-direction:column;gap:24px}}
    .page-title{{font-size:20px;font-weight:800;letter-spacing:-.5px}}
    .page-sub{{font-size:13px;color:var(--muted);margin-top:4px}}
    .panel{{background:var(--surface);border-radius:var(--r);border:1px solid var(--border);overflow:hidden}}
    .member-card{{display:flex;align-items:center;gap:16px;padding:16px 24px;border-bottom:1px solid var(--border)}}
    .member-card:last-child{{border-bottom:none}}
    .member-avatar{{width:48px;height:48px;border-radius:50%;object-fit:cover;border:2px solid var(--border);flex-shrink:0}}
    .member-avatar.initials{{background:var(--coral);color:#fff;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;border:none}}
    .member-info{{flex:1;min-width:0}}
    .member-name{{font-size:14px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
    .member-role{{font-size:12px;color:var(--muted);margin-top:2px}}
    .member-meta{{font-size:11px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
    .edit-btn{{flex-shrink:0;padding:7px 16px;background:var(--coral);color:#fff;border-radius:8px;font-size:12px;font-weight:700;text-decoration:none;transition:background .15s}}
    .edit-btn:hover{{background:#e55a44}}
    @media(max-width:640px){{.main{{padding:20px 16px 48px}};header{{padding:0 16px}}}}
  </style>
</head>
<body>
<header>
  <div class="header-brand">
    <img src="/logo.png" alt="Feest" class="header-logo"/>
  </div>
  <a class="back-link" href="/xadmin">&#8592; Dashboard</a>
</header>
<div class="main">
  <div>
    <h1 class="page-title">Team Members</h1>
    <p class="page-sub">Update names, roles, contact info, and photos for each card.</p>
  </div>
  <div class="panel">{cards_html}</div>
</div>
</body></html>"""

@app.get("/xadmin/members/{slug}/edit", response_class=HTMLResponse)
async def member_edit_get(slug: str, saved: str = "", _=Depends(require_admin)):
    slug = validate_slug(slug)
    db = get_db()
    row = db.execute("SELECT * FROM members WHERE slug=?", (slug,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(status_code=404)
    return _member_edit_page(slug, dict(row), saved=bool(saved))

@app.post("/xadmin/members/{slug}/edit", response_class=HTMLResponse)
async def member_edit_post(
    slug: str,
    full_name: str = Form(...),
    role: str = Form(""),
    phone: str = Form(""),
    email: str = Form(""),
    linkedin: str = Form(""),
    photo: UploadFile = File(None),
    _=Depends(require_admin),
):
    slug = validate_slug(slug)
    db = get_db()
    row = db.execute("SELECT * FROM members WHERE slug=?", (slug,)).fetchone()
    if not row:
        db.close()
        raise HTTPException(status_code=404)
    member = dict(row)

    # Handle photo upload
    new_ext = None
    if photo and photo.filename:
        ctype = photo.content_type or ""
        if ctype not in ALLOWED_PHOTO_TYPES:
            db.close()
            return _member_edit_page(slug, member, error="Photo must be JPG, PNG or WebP.")
        data = await photo.read()
        if len(data) > 5 * 1024 * 1024:
            db.close()
            return _member_edit_page(slug, member, error="Photo too large — max 5 MB.")
        new_ext = ALLOWED_PHOTO_TYPES[ctype]
        PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
        # Remove any old photo for this slug
        for old in PHOTOS_DIR.glob(f"{slug}.*"):
            old.unlink(missing_ok=True)
        (PHOTOS_DIR / f"{slug}.{new_ext}").write_bytes(data)

    db.execute("""
        UPDATE members
        SET full_name=?, role=?, phone=?, email=?, linkedin=?
            {photo_clause}
        WHERE slug=?
    """.replace("{photo_clause}", ", photo_ext=?" if new_ext else ""),
        ([full_name.strip(), role.strip(), phone.strip(), email.strip(), linkedin.strip()]
         + ([new_ext] if new_ext else [])
         + [slug])
    )
    db.commit()
    db.close()
    return RedirectResponse(url=f"/xadmin/members/{slug}/edit?saved=1", status_code=302)

# ─────────────────────────────────────────
# Routes — Admin dashboard
# ─────────────────────────────────────────
@app.get("/xadmin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, page: int = 1, _=Depends(require_admin)):
    db = get_db()
    PAGE_SIZE = 25
    page = max(1, page)
    offset = (page - 1) * PAGE_SIZE

    route_rows = db.execute("""
        SELECT route, COUNT(*) as total,
               MAX(scanned_at) as last_scan
        FROM scans
        GROUP BY route
        ORDER BY total DESC
    """).fetchall()

    daily_rows = db.execute("""
        SELECT date(scanned_at) as day, COUNT(*) as cnt
        FROM scans
        WHERE scanned_at >= datetime('now', '-7 days')
        GROUP BY day
        ORDER BY day
    """).fetchall()

    total_recent = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_pages  = max(1, -(-total_recent // PAGE_SIZE))  # ceiling div

    recent = db.execute("""
        SELECT route, ip, user_agent, scanned_at
        FROM scans
        ORDER BY scanned_at DESC
        LIMIT ? OFFSET ?
    """, (PAGE_SIZE, offset)).fetchall()

    db.close()

    total_all  = sum(r["total"] for r in route_rows)
    last7_total = sum(r["cnt"] for r in daily_rows)

    # Fill in all 7 days (so chart always shows full week, not just days with data)
    day_map = {r["day"]: r["cnt"] for r in daily_rows}
    chart_labels = []
    chart_counts = []
    for i in range(6, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        chart_labels.append(d)
        chart_counts.append(day_map.get(d, 0))

    # Pagination controls for Recent Scans
    start_row  = offset + 1 if total_recent > 0 else 0
    end_row    = min(offset + PAGE_SIZE, total_recent)
    pg_info    = f"Showing {start_row}–{end_row} of {total_recent}"

    def pg_link(p):
        return f"/xadmin?page={p}"

    # Prev / Next
    prev_cls = "pg-btn" if page > 1 else "pg-btn disabled"
    next_cls = "pg-btn" if page < total_pages else "pg-btn disabled"
    prev_btn = f'<a class="{prev_cls}" href="{pg_link(page-1)}">&#8592; Prev</a>'
    next_btn = f'<a class="{next_cls}" href="{pg_link(page+1)}">Next &#8594;</a>'

    # Page number buttons — show at most 5 around current page
    pg_btns = ""
    window_start = max(1, min(page - 2, total_pages - 4))
    window_end   = min(total_pages, window_start + 4)
    if window_start > 1:
        pg_btns += f'<a class="pg-btn" href="{pg_link(1)}">1</a>'
        if window_start > 2:
            pg_btns += '<span class="pg-btn disabled" style="border:none;padding:0 4px">…</span>'
    for p in range(window_start, window_end + 1):
        cls = "pg-btn active" if p == page else "pg-btn"
        pg_btns += f'<a class="{cls}" href="{pg_link(p)}">{p}</a>'
    if window_end < total_pages:
        if window_end < total_pages - 1:
            pg_btns += '<span class="pg-btn disabled" style="border:none;padding:0 4px">…</span>'
        pg_btns += f'<a class="pg-btn" href="{pg_link(total_pages)}">{total_pages}</a>'

    pagination_html = f"""
    <div class="pagination">
      <span class="pagination-info">{pg_info}</span>
      <div class="pagination-btns">
        {prev_btn}
        {pg_btns}
        {next_btn}
      </div>
    </div>"""

    esc = html_mod.escape

    # Route table rows
    route_html = ""
    for r in route_rows:
        label = esc(_route_label(r["route"]))
        pct   = round(r["total"] / total_all * 100) if total_all else 0
        last  = esc(r["last_scan"][:16].replace("T", " ")) if r["last_scan"] else "—"
        route_html += f"""
        <tr>
          <td><span class="badge">{esc(r['route'])}</span></td>
          <td class="td-label">{label}</td>
          <td class="td-num">{r['total']}</td>
          <td class="td-share">
            <div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>
            <span class="pct-label">{pct}%</span>
          </td>
          <td class="td-date">{last}</td>
        </tr>"""

    # Recent scans rows — parse UA into something readable
    recent_html = ""
    for r in recent:
        ua = r["user_agent"] or ""
        # Extract device hint from UA
        if "curl" in ua.lower():
            ua_display = "curl"
        elif "Android" in ua:
            ua_display = "Android"
        elif "iPhone" in ua:
            ua_display = "iPhone"
        elif "Windows" in ua:
            ua_display = "Windows"
        elif "Mac" in ua:
            ua_display = "Mac"
        elif "Linux" in ua:
            ua_display = "Linux"
        else:
            ua_display = ua[:32] + "…" if len(ua) > 32 else (ua or "—")

        ts    = esc(r["scanned_at"][:16].replace("T", " ")) if r["scanned_at"] else "—"
        ip    = esc(r["ip"] or "—")
        recent_html += f"""
        <tr>
          <td><span class="badge">{esc(r['route'])}</span></td>
          <td class="td-ip">{ip}</td>
          <td><span class="ua-pill">{esc(ua_display)}</span></td>
          <td class="td-date">{ts}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin · Feest Links</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="{FONT}" rel="stylesheet"/>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --coral:   #F7715B;
      --dark:    #111111;
      --bg:      #F4F4F5;
      --surface: #FFFFFF;
      --border:  #E4E4E7;
      --muted:   #A1A1AA;
      --text:    #18181B;
      --r:       14px;
    }}

    body {{
      font-family: 'Montserrat', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }}

    /* ── Header ── */
    header {{
      background: var(--dark);
      padding: 0 32px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 10;
    }}

    .header-brand {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .header-logo {{
      height: 28px;
      width: auto;
      display: block;
    }}

    .header-title {{
      font-size: 15px;
      font-weight: 700;
      color: #fff;
    }}

    .header-title span {{ color: var(--coral); }}

    .signout {{
      font-size: 12px;
      font-weight: 600;
      color: var(--muted);
      text-decoration: none;
      padding: 6px 14px;
      border: 1px solid #333;
      border-radius: 8px;
      transition: color .15s, border-color .15s;
    }}

    .signout:hover {{ color: #fff; border-color: #666; }}

    /* ── Layout ── */
    .main {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 32px 24px 64px;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }}

    .page-title {{
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.5px;
    }}

    .page-subtitle {{
      font-size: 13px;
      color: var(--muted);
      margin-top: 4px;
    }}

    /* ── Stat cards ── */
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
    }}

    .stat-card {{
      background: var(--surface);
      border-radius: var(--r);
      padding: 22px 24px;
      border: 1px solid var(--border);
    }}

    .stat-icon {{
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: #FFF1EE;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 14px;
    }}

    .stat-icon svg {{ width: 18px; height: 18px; }}

    .stat-num {{
      font-size: 30px;
      font-weight: 600;
      color: var(--dark);
      line-height: 1;
    }}

    .stat-lbl {{
      font-size: 12px;
      font-weight: 600;
      color: var(--muted);
      margin-top: 6px;
      text-transform: uppercase;
      letter-spacing: 0.6px;
    }}

    /* ── Panels ── */
    .panel {{
      background: var(--surface);
      border-radius: var(--r);
      border: 1px solid var(--border);
      overflow: hidden;
    }}

    .panel-header {{
      padding: 20px 24px 0;
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      margin-bottom: 20px;
    }}

    .panel-title {{
      font-size: 14px;
      font-weight: 700;
    }}

    .panel-meta {{
      font-size: 12px;
      color: var(--muted);
      font-weight: 500;
    }}

    .chart-wrap {{
      padding: 0 24px 24px;
    }}

    /* ── Tables ── */
    .table-scroll {{
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
    }}

    thead th {{
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.7px;
      text-transform: uppercase;
      color: var(--muted);
      padding: 0 24px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}

    tbody tr {{
      transition: background .1s;
    }}

    tbody tr:hover {{ background: #FAFAFA; }}

    tbody td {{
      padding: 13px 24px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
      vertical-align: middle;
    }}

    tbody tr:last-child td {{ border-bottom: none; }}

    /* Column widths */
    .td-label {{ font-weight: 600; color: var(--text); }}
    .td-num   {{ font-size: 15px; font-weight: 800; color: var(--dark); width: 60px; }}
    .td-date  {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
    .td-ip    {{ color: var(--muted); font-size: 12px; font-family: monospace; white-space: nowrap; }}

    .td-share {{
      display: flex;
      align-items: center;
      gap: 10px;
      white-space: nowrap;
    }}

    .bar-track {{
      flex: 1;
      max-width: 100px;
      height: 5px;
      background: #F0F0F0;
      border-radius: 999px;
      overflow: hidden;
    }}

    .bar-fill {{
      height: 5px;
      background: var(--coral);
      border-radius: 999px;
    }}

    .pct-label {{
      font-size: 11px;
      font-weight: 700;
      color: var(--muted);
      min-width: 28px;
    }}

    /* ── Badges ── */
    .badge {{
      display: inline-block;
      background: #F4F4F5;
      color: #52525B;
      font-size: 11px;
      font-weight: 700;
      padding: 3px 9px;
      border-radius: 6px;
      letter-spacing: 0.2px;
      white-space: nowrap;
    }}

    .ua-pill {{
      display: inline-block;
      background: #EFF6FF;
      color: #3B82F6;
      font-size: 11px;
      font-weight: 700;
      padding: 3px 9px;
      border-radius: 6px;
    }}

    .empty {{
      padding: 40px 24px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
    }}

    /* ── Pagination ── */
    .pagination {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 24px;
      border-top: 1px solid var(--border);
    }}

    .pagination-info {{
      font-size: 12px;
      font-weight: 500;
      color: var(--muted);
    }}

    .pagination-btns {{
      display: flex;
      gap: 8px;
    }}

    .pg-btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      height: 32px;
      min-width: 32px;
      padding: 0 12px;
      border-radius: 8px;
      font-family: 'Montserrat', sans-serif;
      font-size: 12px;
      font-weight: 700;
      text-decoration: none;
      border: 1px solid var(--border);
      color: var(--text);
      background: var(--surface);
      transition: background .12s, border-color .12s;
    }}

    .pg-btn:hover {{ background: #F4F4F5; border-color: #D4D4D8; }}
    .pg-btn.active {{ background: var(--coral); color: #fff; border-color: var(--coral); }}
    .pg-btn.disabled {{ opacity: 0.35; pointer-events: none; }}

    @media (max-width: 640px) {{
      .main {{ padding: 20px 16px 48px; }}
      header {{ padding: 0 16px; }}
      /* Stat cards — horizontal snap carousel on mobile */
      .stats-grid {{
        display: flex;
        overflow-x: auto;
        scroll-snap-type: x mandatory;
        -webkit-overflow-scrolling: touch;
        gap: 12px;
        padding-bottom: 4px;
        /* hide scrollbar */
        scrollbar-width: none;
      }}
      .stats-grid::-webkit-scrollbar {{ display: none; }}
      .stat-card {{
        flex: 0 0 calc(50% - 6px);
        scroll-snap-align: start;
        min-width: 0;
      }}
      thead th, tbody td {{ padding-left: 16px; padding-right: 16px; }}
      .td-share {{ display: none; }}
    }}
  </style>
</head>
<body>

<header>
  <div class="header-brand">
    <img src="/logo.png" alt="Feest" class="header-logo"/>
  </div>
  <div style="display:flex;gap:10px;align-items:center">
    <a class="signout" href="/xadmin/members" style="color:#fff;border-color:#555">Team</a>
    <a class="signout" href="/xadmin/logout">Sign out</a>
  </div>
</header>

<div class="main">

  <div>
    <h1 class="page-title">Dashboard</h1>
    <p class="page-subtitle">QR scan analytics for all active routes</p>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-icon">
        <svg viewBox="0 0 20 20" fill="none" stroke="#F7715B" stroke-width="1.8" stroke-linecap="round">
          <path d="M10 2v16M2 10h16"/>
        </svg>
      </div>
      <div class="stat-num">{total_all}</div>
      <div class="stat-lbl">Total Scans</div>
    </div>
    <div class="stat-card">
      <div class="stat-icon">
        <svg viewBox="0 0 20 20" fill="none" stroke="#F7715B" stroke-width="1.8" stroke-linecap="round">
          <rect x="3" y="3" width="14" height="14" rx="2"/>
          <path d="M7 10h6M10 7v6"/>
        </svg>
      </div>
      <div class="stat-num">{len(route_rows)}</div>
      <div class="stat-lbl">Active Routes</div>
    </div>
    <div class="stat-card">
      <div class="stat-icon">
        <svg viewBox="0 0 20 20" fill="none" stroke="#F7715B" stroke-width="1.8" stroke-linecap="round">
          <rect x="2" y="4" width="16" height="14" rx="2"/>
          <path d="M14 2v4M6 2v4M2 9h16"/>
        </svg>
      </div>
      <div class="stat-num">{last7_total}</div>
      <div class="stat-lbl">Last 7 Days</div>
    </div>
  </div>

  <!-- Chart -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Scan Activity</span>
      <span class="panel-meta">Last 7 days</span>
    </div>
    <div class="chart-wrap">
      <canvas id="chart" style="max-height:180px"></canvas>
    </div>
  </div>

  <!-- Routes table -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Scans by Route</span>
      <span class="panel-meta">{len(route_rows)} route{"s" if len(route_rows) != 1 else ""}</span>
    </div>
    {"<div class='table-scroll'><table><thead><tr><th>Route</th><th>Label</th><th>Total</th><th>Share</th><th>Last Scan</th></tr></thead><tbody>" + route_html + "</tbody></table></div>" if route_rows else '<div class="empty">No scans recorded yet.</div>'}
  </div>

  <!-- Recent scans -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Recent Scans</span>
      <span class="panel-meta">Page {page} of {total_pages}</span>
    </div>
    {("<div class='table-scroll'><table><thead><tr><th>Route</th><th>IP</th><th>Device</th><th>Time (UTC)</th></tr></thead><tbody>" + recent_html + "</tbody></table></div>" + pagination_html) if recent else '<div class="empty">No scans recorded yet.</div>'}
  </div>

</div>

<script>
new Chart(document.getElementById('chart'), {{
  type: 'bar',
  data: {{
    labels: {chart_labels},
    datasets: [{{
      label: 'Scans',
      data: {chart_counts},
      backgroundColor: '#F7715B',
      hoverBackgroundColor: '#e55a44',
      borderRadius: 6,
      borderSkipped: false,
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: true,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{
        backgroundColor: '#111',
        titleColor: '#fff',
        bodyColor: '#aaa',
        padding: 10,
        cornerRadius: 8,
        callbacks: {{
          title: (items) => items[0].label,
          label: (item) => `  ${{item.raw}} scan${{item.raw !== 1 ? 's' : ''}}`,
        }}
      }}
    }},
    scales: {{
      y: {{
        beginAtZero: true,
        ticks: {{ precision: 0, color: '#A1A1AA', font: {{ family: 'Montserrat', size: 11 }} }},
        grid: {{ color: '#F0F0F0' }},
        border: {{ display: false }}
      }},
      x: {{
        ticks: {{ color: '#A1A1AA', font: {{ family: 'Montserrat', size: 11 }}, maxRotation: 0 }},
        grid: {{ display: false }},
        border: {{ display: false }}
      }}
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
# Inline SVG icons — white versions (for coral circle backgrounds)
# ─────────────────────────────────────────
def icon_wa_white():
    return """<svg viewBox="0 0 24 24" fill="white"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 0C5.373 0 0 5.373 0 12c0 2.104.547 4.08 1.504 5.797L.057 23.886a.5.5 0 00.619.61l6.241-1.637A11.945 11.945 0 0012 24c6.627 0 12-5.373 12-12S18.627 0 12 0zm0 22a9.944 9.944 0 01-5.088-1.393l-.365-.218-3.782.992.992-3.688-.236-.382A9.944 9.944 0 012 12C2 6.477 6.477 2 12 2s10 4.477 10 10-4.477 10-10 10z"/></svg>"""

def icon_phone_white():
    return """<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.81a19.79 19.79 0 01-3.07-8.68A2 2 0 012 1h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.09 8.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/></svg>"""

def icon_email_white():
    return """<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>"""

def icon_linkedin_white():
    return """<svg viewBox="0 0 24 24" fill="white"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>"""

def icon_contact_white():
    return """<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>"""

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
