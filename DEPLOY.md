# Deploy Instructions

## First-time setup (run on the Lightsail server)

```bash
# Clone the repo into the Caddy-served directory
cd /home/ubuntu/whatsapp-bot
git clone https://github.com/Mellocious/feest-link-site.git link-site
```

That's it. Caddy is already serving `/home/ubuntu/whatsapp-bot/link-site/` at `https://link.usefeest.com`.

---

## Update the site going forward

```bash
cd /home/ubuntu/whatsapp-bot/link-site
git pull
```

---

## Files

- `index.html` — the full page (edit links, text, etc. here)
- `logo.png` — Feest official mono logo 2026
