#!/bin/bash
set -e

# ── Display virtuel ──────────────────────────────────────────
Xvfb :1 -screen 0 1280x900x24 -ac +extension GLX +render -noreset &
export DISPLAY=:1
sleep 1

# ── Window manager léger ─────────────────────────────────────
openbox &

# ── Serveur VNC ──────────────────────────────────────────────
x11vnc -display :1 -passwd "${VNC_PASSWORD:-EqimaVNC2026}" \
       -forever -shared -quiet -noxdamage &

# ── noVNC (interface web) ────────────────────────────────────
websockify --web /usr/share/novnc 6080 localhost:5900 &

sleep 2

# ── ZAP GUI ──────────────────────────────────────────────────
exec zap.sh \
  -config api.key="${ZAP_API_KEY:-changeme}" \
  -config api.addrs.addr.name=".*" \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=false