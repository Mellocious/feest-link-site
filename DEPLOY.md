# Feest Link Site — Deploy Guide

## Structure

```
feest-link-site/
├── index.html          ← Main links page (static)
├── logo.png            ← Feest logo
├── Caddyfile           ← Caddy routing config
├── docker-compose.yml  ← Runs Caddy + FastAPI together
├── .env.example        ← Copy to .env and fill in secrets
├── data/               ← Created on first run (gitignored)
│   ├── feest.db        ← SQLite database
│   └── photos/         ← Team member photos
└── api/
    ├── main.py         ← FastAPI app
    ├── requirements.txt
    └── Dockerfile
```

---

## First-Time Deploy (on the Lightsail server)

```bash
# 1. Stop the old Caddy container if running
cd /home/ubuntu/whatsapp-bot
docker compose down   # or: docker-compose down

# 2. Clone the repo
git clone https://github.com/Mellocious/feest-link-site.git link-site
cd link-site

# 3. Create your .env from the example (REQUIRED — app won't start without it)
cp .env.example .env
nano .env   # ADMIN_PASS and SECRET_KEY are mandatory

# 4. Start everything
docker compose up -d --build

# 5. Check it's running
docker compose logs -f
```

Caddy auto-provisions the SSL certificate for `link.usefeest.com`.

---

## Adding Team Photos

Drop photos into the `data/photos/` folder on the server, named exactly:

```
data/photos/damilare.jpg
data/photos/fejulo.jpg
data/photos/melvin.jpg
data/photos/gift.jpg
```

Then update the database to tell the API the extension:

```bash
docker compose exec api python3 - <<'EOF'
import sqlite3
db = sqlite3.connect("/app/data/feest.db")
db.execute("UPDATE members SET photo_ext='jpg' WHERE slug='damilare'")
db.execute("UPDATE members SET photo_ext='jpg' WHERE slug='fejulo'")
db.execute("UPDATE members SET photo_ext='jpg' WHERE slug='melvin'")
db.execute("UPDATE members SET photo_ext='jpg' WHERE slug='gift'")
db.commit()
db.close()
print("Done")
EOF
```

Supported extensions: `jpg`, `jpeg`, `png`, `webp`

---

## Updating the Site

```bash
cd /home/ubuntu/whatsapp-bot/link-site
git pull
docker compose up -d --build
```

---

## Routes

| URL | What it does |
|---|---|
| `link.usefeest.com/` | Main Feest links page (tracked) |
| `link.usefeest.com/card/Melvin` | Melvin's bio card |
| `link.usefeest.com/card/Gift` | Gift's bio card |
| `link.usefeest.com/card/Damilare` | Damilare's bio card |
| `link.usefeest.com/card/Fejulo` | Fejulo's bio card |
| `link.usefeest.com/brnch` | Logs brochure scan → redirects to `/` |
| `link.usefeest.com/rlpban` | Logs rollup banner scan → redirects to `/` |
| `link.usefeest.com/xadmin` | Admin dashboard (login required) |

---

## Admin Dashboard

Visit: `https://link.usefeest.com/xadmin`

Login with the `ADMIN_USER` / `ADMIN_PASS` from your `.env` file.

Shows:
- Total scans per route (including homepage visits)
- Last 7 days bar chart
- Recent scans with IP + user agent

### Security notes

- `ADMIN_PASS` and `SECRET_KEY` are **required** environment variables — the app refuses to start without them.
- The API container runs as a non-root user (`appuser`). If the `./data` volume has restrictive permissions, ensure the container user can write to it: `chmod 777 data/` on first deploy.
- Login is rate-limited to 5 attempts per IP per 15 minutes.
- Login form uses CSRF protection (double-submit cookie).

---

## Updating the WhatsApp number (main page)

Edit `index.html` — find the `wa.me` link and update the number.
Then `git add index.html && git commit -m "update WA number" && git push`.
On server: `git pull` (no rebuild needed for static changes).
