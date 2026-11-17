#!/usr/bin/env bash
# =============================================================================
# Démarrage de la pile — construit l'image de base puis lance les 6 conteneurs
# =============================================================================
set -e
cd "$(dirname "$0")/.."

echo "[1/3] Construction de l'image de base (scikit-learn 1.6.1 + torch CPU)…"
docker build -f docker/Dockerfile.base -t agentic-base:latest .

echo "[2/3] Construction et démarrage des services…"
docker compose -f docker/docker-compose.yml up -d --build

echo "[3/3] Attente de la disponibilité des services…"
for i in $(seq 1 30); do
    if curl -fs http://localhost:8000/health > /dev/null 2>&1; then break; fi
    sleep 2
done

echo
echo "=== État des services ==="
for p in 8000:bus 9001:collect 9003:anonymization 9004:decision; do
    port="${p%%:*}"; nom="${p##*:}"
    etat=$(curl -fs "http://localhost:$port/health" 2>/dev/null || echo "en cours de démarrage")
    printf "  %-14s %s\n" "$nom" "$etat"
done

echo
echo "Dashboard : http://localhost:8000/"
echo
echo "Le modèle Ollama doit être téléchargé une première fois :"
echo "    docker exec agentic-ollama ollama pull llama3.1"
echo
echo "Les sondes s'installent NATIVEMENT sur les machines surveillées :"
echo "    services/sonde_windows.py  (poste Windows)"
echo "    services/sonde_cloud.py    (instance cible du mirroring AWS)"
