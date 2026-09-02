#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
step()  { echo -e "\n${GREEN}───${NC} $1 ${GREEN}───${NC}"; }

# ─────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────
step "Pre-flight checks"

if ! command -v docker &>/dev/null; then
    error "Docker is not installed. Install it first: https://docs.docker.com/engine/install/"
    exit 1
fi
info "Docker found"

if ! docker compose version &>/dev/null; then
    error "Docker Compose v2 not found. Install it: https://docs.docker.com/compose/install/"
    exit 1
fi
info "Docker Compose found"

if ! docker info &>/dev/null 2>&1; then
    error "Docker daemon is not running. Start it first."
    exit 1
fi
info "Docker daemon running"

# ─────────────────────────────────────────
# .env setup
# ─────────────────────────────────────────
step "Environment configuration"

if [ ! -f .env ]; then
    warn ".env file not found — creating from .env.example"
    cp .env.example .env

    read -rp "Enter ADMIN_PASS (admin dashboard password): " admin_pass
    if [ -z "$admin_pass" ]; then
        error "ADMIN_PASS cannot be empty"
        exit 1
    fi

    secret_key=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")

    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|^ADMIN_PASS=.*|ADMIN_PASS=${admin_pass}|" .env
        sed -i '' "s|^SECRET_KEY=.*|SECRET_KEY=${secret_key}|" .env
    else
        sed -i "s|^ADMIN_PASS=.*|ADMIN_PASS=${admin_pass}|" .env
        sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${secret_key}|" .env
    fi

    info ".env created with your password and an auto-generated SECRET_KEY"
else
    info ".env file exists"

    # Validate that required vars are set
    source .env
    if [ -z "${ADMIN_PASS:-}" ]; then
        error "ADMIN_PASS is empty in .env — set it before deploying"
        exit 1
    fi
    if [ -z "${SECRET_KEY:-}" ] || [ "${SECRET_KEY:-}" = "generate_with_openssl_rand_hex_32" ]; then
        error "SECRET_KEY is not set in .env — run: openssl rand -hex 32"
        exit 1
    fi
    info ".env variables validated"
fi

# ─────────────────────────────────────────
# Data directory permissions
# ─────────────────────────────────────────
step "Data directory"

mkdir -p data/photos
chmod -R 777 data 2>/dev/null || true
info "data/ directory ready"

# ─────────────────────────────────────────
# Pull latest code (if in a git repo)
# ─────────────────────────────────────────
if [ -d .git ]; then
    step "Pulling latest code"
    if git pull --ff-only 2>/dev/null; then
        info "Code updated"
    else
        warn "git pull failed (maybe local changes?) — deploying current state"
    fi
fi

# ─────────────────────────────────────────
# Build and deploy
# ─────────────────────────────────────────
step "Building and starting containers"

docker compose build --no-cache
info "Build complete"

docker compose up -d
info "Containers started"

# ─────────────────────────────────────────
# Health check
# ─────────────────────────────────────────
step "Health check"

echo -n "Waiting for API to be ready"
for i in $(seq 1 15); do
    if docker compose exec -T api python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/xadmin/login')" &>/dev/null; then
        echo ""
        info "API is healthy"
        break
    fi
    echo -n "."
    sleep 2
    if [ "$i" -eq 15 ]; then
        echo ""
        error "API did not become healthy in time. Check logs:"
        echo "  docker compose logs api"
        exit 1
    fi
done

# ─────────────────────────────────────────
# Summary
# ─────────────────────────────────────────
step "Deploy complete"

echo ""
echo -e "  ${GREEN}Links page:${NC}   https://link.usefeest.com/"
echo -e "  ${GREEN}Admin panel:${NC}  https://link.usefeest.com/xadmin"
echo ""
echo -e "  Useful commands:"
echo -e "    docker compose logs -f        ${YELLOW}# watch logs${NC}"
echo -e "    docker compose ps             ${YELLOW}# check status${NC}"
echo -e "    docker compose down            ${YELLOW}# stop everything${NC}"
echo -e "    docker compose up -d --build  ${YELLOW}# rebuild & restart${NC}"
echo ""
