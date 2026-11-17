#!/usr/bin/env python3
"""
Lance le bus réseau + le dashboard.
Usage : python run_bus.py [port]
Puis ouvrir http://127.0.0.1:8000/ dans un navigateur.

Pour la vraie géolocalisation : déposer une base .mmdb (MaxMind GeoLite2,
DB-IP Lite ou IPLocate) et renseigner GEO_MMDB_PATH ci-dessous.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import uvicorn

# chemin optionnel vers une vraie base géo (.mmdb). Si absent -> mode démo.
os.environ.setdefault("GEO_MMDB_PATH", "")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"Bus réseau + dashboard sur http://127.0.0.1:{port}/")
    uvicorn.run("bus.server:app", host="0.0.0.0", port=port, log_level="info")
