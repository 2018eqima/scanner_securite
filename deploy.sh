#!/bin/bash
set -e

# ── Config ────────────────────────────────────────────────────
DEPLOY_DIR="/opt/eqimasecurity"
NGINX_SITE="security.eqima.org"
DOMAIN="security.eqima.org"

echo "==> Création du répertoire de déploiement..."
mkdir -p "$DEPLOY_DIR"

echo "==> Copie des fichiers..."
cp docker-compose.yml "$DEPLOY_DIR/"
cp .env "$DEPLOY_DIR/"

echo "==> Configuration Nginx..."
cp nginx/security.eqima.org /etc/nginx/sites-available/$NGINX_SITE
ln -sf /etc/nginx/sites-available/$NGINX_SITE /etc/nginx/sites-enabled/$NGINX_SITE
nginx -t && systemctl reload nginx

echo "==> Génération du certificat Let's Encrypt..."
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@eqima.org --redirect

echo "==> Démarrage des containers..."
cd "$DEPLOY_DIR"
docker compose up -d

echo ""
echo "✓ Déploiement terminé !"
echo "  ZAP API : https://$DOMAIN"
echo "  Test    : curl -s https://$DOMAIN/JSON/core/view/version/?apikey=\$(grep ZAP_API_KEY .env | cut -d= -f2)"