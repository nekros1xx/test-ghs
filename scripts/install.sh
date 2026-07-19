#!/usr/bin/env bash
# ghascan installer — builds the Docker image and installs a `ghascan` command
# that drives the whole dockerized pipeline behind a single classic-style call:
#
#     ghascan --org microsoft --pdf microsoft.pdf
#
# Usage (from a fresh clone):
#     ./scripts/install.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN_DIR:-$HOME/.local/bin}"

echo "▶ Repo: $REPO"

# 1. Prerequisites
command -v docker >/dev/null || { echo "✗ Docker no está instalado."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "✗ 'docker compose' (v2) no disponible."; exit 1; }

# 2. .env (secrets stay local — never committed)
if [ ! -f "$REPO/.env" ]; then
  cp "$REPO/.env.example" "$REPO/.env"
  echo "⚠  Creé $REPO/.env desde la plantilla. EDÍTALO y pon tu GITHUB_TOKEN antes de escanear."
fi

# 3. Build the image
echo "▶ Construyendo la imagen (esto tarda la primera vez)…"
( cd "$REPO" && docker compose build )

# 4. Install a tiny shim on PATH that points at this repo
mkdir -p "$BIN"
cat > "$BIN/ghascan" <<EOF
#!/usr/bin/env bash
export GHASCAN_HOME="$REPO"
exec "$REPO/scripts/ghascan" "\$@"
EOF
chmod +x "$BIN/ghascan"

echo "✔ Instalado: $BIN/ghascan  (GHASCAN_HOME=$REPO)"
case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) echo "⚠  $BIN no está en tu PATH. Agrégalo:  export PATH=\"$BIN:\$PATH\"" ;;
esac
echo
echo "Siguiente paso:"
echo "  1) edita $REPO/.env con tu GITHUB_TOKEN"
echo "  2) ghascan --org microsoft --pdf microsoft.pdf"
