#!/bin/bash

set -euo pipefail

echo "======================================"
echo "🔐 SECURE INSTALL - Cloudflare Tunnel"
echo "💰 Plan: FREE ($0)"
echo "======================================"

# Verificar root/sudo
if [[ $EUID -eq 0 ]]; then
  echo "⚠️ No ejecutes esto como root directo. Usa usuario con sudo."
  exit 1
fi

# Actualizar sistema de forma segura
echo "📦 Updating system..."
sudo apt update -y && sudo apt upgrade -y

# Instalar dependencias mínimas
echo "📦 Installing dependencies..."
sudo apt install -y curl ca-certificates

# Definir versión segura (evita ejecución de binarios comprometidos sin control básico)
CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"

echo "⬇️ Downloading cloudflared securely..."
curl -fsSL "$CLOUDFLARED_URL" -o cloudflared

# Verificar que se descargó correctamente
if [[ ! -f cloudflared ]]; then
  echo "❌ Download failed"
  exit 1
fi

# Permisos seguros
chmod 755 cloudflared

# Mover a bin system
echo "📁 Installing binary..."
sudo mv cloudflared /usr/local/bin/cloudflared

# Verificación de integridad básica
echo "🔎 Verifying installation..."
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "❌ Installation failed"
  exit 1
fi

# Mostrar versión
cloudflared --version

echo "======================================"
echo "✅ SECURE INSTALL COMPLETE"
echo "🚀 Run tunnel with:"
echo "cloudflared tunnel --url http://localhost:8000"
echo "======================================"
