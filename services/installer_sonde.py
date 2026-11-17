"""
=============================================================================
INSTALLATEUR DE SONDE — Windows
=============================================================================
Un seul exécutable qui installe TOUT ce dont la sonde a besoin, puis la
déploie en service Windows.

CE QU'IL INSTALLE
    1. Sysmon        — journalisation système (pilote noyau Microsoft)
    2. Npcap         — capture réseau (pilote, fourni avec Wireshark)
    3. CICFlowMeter  — PCAP → 76 features (Java)
    4. la sonde      — service Windows démarrant automatiquement

POURQUOI UN INSTALLATEUR ET NON UN SIMPLE .EXE
    Un exécutable Python ne peut pas embarquer de PILOTE NOYAU. Sysmon et
    Npcap en sont, et doivent être installés par leurs propres programmes,
    avec droits administrateur. Cet installateur les télécharge et les lance
    à ta place — d'où « une seule exécution » du point de vue de l'usage.

EMPAQUETAGE
    pip install pyinstaller
    pyinstaller --onefile --uac-admin --name installer_sonde ^
                --add-data "sonde_windows.py;." installer_sonde.py
    → dist/installer_sonde.exe

USAGE
    installer_sonde.exe                     installation complète
    installer_sonde.exe --sans-reseau       Sysmon et sonde seulement
    installer_sonde.exe --verifier          état de l'installation
    installer_sonde.exe --desinstaller      retrait de la sonde
=============================================================================
"""
from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

RACINE = r"C:\AgenticSonde"
DOSSIER_CICFM = os.path.join(RACINE, "CICFlowMeter")
NOM_SERVICE = "AgenticSonde"

URL_SYSMON = "https://download.sysinternals.com/files/Sysmon.zip"
URL_CONFIG_SYSMON = ("https://raw.githubusercontent.com/SwiftOnSecurity/"
                     "sysmon-config/master/sysmonconfig-export.xml")
URL_NPCAP = "https://npcap.com/dist/npcap-1.79.exe"
URL_CICFM = "https://github.com/ahlashkari/CICFlowMeter/archive/refs/heads/master.zip"


# -----------------------------------------------------------------------------
def est_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def titre(texte: str) -> None:
    print(f"\n{'=' * 66}\n  {texte}\n{'=' * 66}", flush=True)


def etape(n: int, total: int, texte: str) -> None:
    print(f"\n[{n}/{total}] {texte}", flush=True)


def telecharger(url: str, destination: str, libelle: str) -> bool:
    """Télécharge avec indicateur de progression."""
    print(f"  téléchargement de {libelle}…", flush=True)

    def progression(bloc, taille_bloc, total):
        if total > 0:
            pct = min(100, bloc * taille_bloc * 100 // total)
            print(f"\r    {pct}%", end="", flush=True)

    try:
        urllib.request.urlretrieve(url, destination, progression)
        print("\r    terminé  ", flush=True)
        return True
    except Exception as e:
        print(f"\r    ÉCHEC : {str(e)[:120]}", flush=True)
        return False


# -----------------------------------------------------------------------------
# 1. SYSMON
# -----------------------------------------------------------------------------
def sysmon_present() -> bool:
    r = subprocess.run(["sc", "query", "Sysmon64"], capture_output=True)
    if r.returncode == 0:
        return True
    return subprocess.run(["sc", "query", "Sysmon"], capture_output=True).returncode == 0


def installer_sysmon() -> bool:
    if sysmon_present():
        print("  Sysmon déjà installé.")
        return True

    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "Sysmon.zip")
        if not telecharger(URL_SYSMON, archive, "Sysmon (Microsoft Sysinternals)"):
            return False
        with zipfile.ZipFile(archive) as z:
            z.extractall(tmp)

        # configuration de référence : sans elle, Sysmon journalise très peu
        config = os.path.join(tmp, "sysmonconfig.xml")
        avec_config = telecharger(URL_CONFIG_SYSMON, config,
                                  "configuration SwiftOnSecurity")

        exe = os.path.join(tmp, "Sysmon64.exe")
        if not os.path.exists(exe):
            exe = os.path.join(tmp, "Sysmon.exe")
        cmd = [exe, "-accepteula", "-i"] + ([config] if avec_config else [])
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode == 0 or sysmon_present():
            print("  Sysmon installé et démarré.")
            return True
        print(f"  ÉCHEC : {r.stderr.decode(errors='ignore')[:160]}")
        return False


# -----------------------------------------------------------------------------
# 2. NPCAP (capture réseau)
# -----------------------------------------------------------------------------
def npcap_present() -> bool:
    return any(os.path.exists(p) for p in (
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Wireshark\dumpcap.exe"))


def installer_npcap() -> bool:
    if npcap_present():
        print("  Npcap/Wireshark déjà présent.")
        return True
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "npcap.exe")
        if not telecharger(URL_NPCAP, exe, "Npcap (pilote de capture)"):
            return False
        print("  lancement de l'installateur Npcap…")
        print("  → suivre les fenêtres qui s'ouvrent (pilote noyau : "
              "l'installation ne peut pas être silencieuse)")
        subprocess.run([exe], check=False)
        return npcap_present()


# -----------------------------------------------------------------------------
# 3. CICFLOWMETER
# -----------------------------------------------------------------------------
def java_present() -> bool:
    return shutil.which("java") is not None


def cicflowmeter_present() -> bool:
    return os.path.isdir(DOSSIER_CICFM) and bool(os.listdir(DOSSIER_CICFM))


def installer_cicflowmeter() -> bool:
    if not java_present():
        print("  Java absent — CICFlowMeter en a besoin.")
        print("  → installer un JRE : https://adoptium.net/")
        return False
    if cicflowmeter_present():
        print("  CICFlowMeter déjà présent.")
        return True

    os.makedirs(DOSSIER_CICFM, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "cfm.zip")
        if not telecharger(URL_CICFM, archive, "CICFlowMeter V4"):
            return False
        with zipfile.ZipFile(archive) as z:
            z.extractall(tmp)
        source = next((os.path.join(tmp, d) for d in os.listdir(tmp)
                       if d.startswith("CICFlowMeter")), None)
        if source is None:
            print("  ÉCHEC : archive inattendue.")
            return False
        for item in os.listdir(source):
            shutil.move(os.path.join(source, item),
                        os.path.join(DOSSIER_CICFM, item))
    print(f"  CICFlowMeter installé dans {DOSSIER_CICFM}")
    print("  NOTE : le dépôt fournit les sources ; si aucun .jar n'est présent,")
    print("         le compiler avec gradlew, ou déposer un jar pré-construit.")
    return True


# -----------------------------------------------------------------------------
# 4. LA SONDE
# -----------------------------------------------------------------------------
def installer_sonde() -> bool:
    os.makedirs(RACINE, exist_ok=True)

    # la sonde est embarquée dans l'exécutable (PyInstaller) ou à côté du script
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    source = os.path.join(base, "sonde_windows.py")
    cible = os.path.join(RACINE, "sonde_windows.py")
    if os.path.exists(source):
        shutil.copy2(source, cible)
        print(f"  sonde déposée : {cible}")
    elif not os.path.exists(cible):
        print("  ÉCHEC : sonde_windows.py introuvable.")
        return False

    # script de lancement, avec les variables d'environnement utiles
    lanceur = os.path.join(RACINE, "demarrer_sonde.bat")
    with open(lanceur, "w", encoding="utf-8") as f:
        f.write(f"""@echo off
REM Lancement de la sonde. L'adresse du système est découverte
REM automatiquement ; la forcer ici si nécessaire :
REM   set COLLECT_URL=http://192.168.56.1:9001
REM   set ANON_URL=http://192.168.56.1:9003
set CICFLOWMETER_HOME={DOSSIER_CICFM}
cd /d {RACINE}
python sonde_windows.py %*
""")
    print(f"  lanceur créé : {lanceur}")

    # tâche planifiée : démarrage automatique, plus simple qu'un vrai service
    subprocess.run(["schtasks", "/Create", "/TN", NOM_SERVICE,
                    "/TR", f'"{lanceur}"', "/SC", "ONSTART",
                    "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"],
                   capture_output=True)
    print(f"  démarrage automatique configuré (tâche « {NOM_SERVICE} »)")
    return True


def desinstaller() -> None:
    titre("Désinstallation de la sonde")
    subprocess.run(["schtasks", "/Delete", "/TN", NOM_SERVICE, "/F"],
                   capture_output=True)
    print("  tâche planifiée supprimée")
    if os.path.isdir(RACINE):
        shutil.rmtree(RACINE, ignore_errors=True)
        print(f"  {RACINE} supprimé")
    print("\n  Sysmon et Npcap n'ont PAS été retirés : d'autres outils peuvent")
    print("  en dépendre. Pour Sysmon :  Sysmon64.exe -u")


# -----------------------------------------------------------------------------
def verifier() -> bool:
    titre("État de l'installation")
    controles = [
        ("Sysmon", sysmon_present(), "journalisation système"),
        ("Npcap/Wireshark", npcap_present(), "capture réseau"),
        ("Java", java_present(), "requis par CICFlowMeter"),
        ("CICFlowMeter", cicflowmeter_present(), "PCAP → 76 features"),
        ("Sonde", os.path.exists(os.path.join(RACINE, "sonde_windows.py")),
         "programme de collecte"),
    ]
    for nom, present, role in controles:
        print(f"  [{'OK' if present else ' X'}] {nom:18s} {role}")

    voie_logs = controles[0][1] and controles[4][1]
    voie_reseau = all(c[1] for c in controles[1:4])
    print(f"\n  Voie journal Sysmon : {'opérationnelle' if voie_logs else 'indisponible'}")
    print(f"  Voie capture réseau : {'opérationnelle' if voie_reseau else 'indisponible'}")
    if voie_logs and not voie_reseau:
        print("\n  La sonde fonctionnera en mode journal seul : la détection")
        print("  VPN/Tor par GNN sera indisponible (le lookup reste actif).")
    return voie_logs or voie_reseau


def main() -> None:
    p = argparse.ArgumentParser(description="Installateur de sonde Windows")
    p.add_argument("--sans-reseau", action="store_true",
                   help="ne pas installer la capture réseau")
    p.add_argument("--verifier", action="store_true")
    p.add_argument("--desinstaller", action="store_true")
    args = p.parse_args()

    if args.verifier:
        sys.exit(0 if verifier() else 1)

    if not est_admin():
        print("Droits administrateur requis (pilotes noyau à installer).")
        print("→ clic droit sur l'exécutable, « Exécuter en tant "
              "qu'administrateur ».")
        sys.exit(1)

    if args.desinstaller:
        desinstaller()
        return

    titre("Installation de la sonde Agentic Security")
    total = 3 if args.sans_reseau else 5
    n = 0

    n += 1; etape(n, total, "Sysmon (journalisation système)")
    ok_sysmon = installer_sysmon()

    if not args.sans_reseau:
        n += 1; etape(n, total, "Npcap (capture réseau)")
        installer_npcap()
        n += 1; etape(n, total, "CICFlowMeter (features de flux)")
        installer_cicflowmeter()

    n += 1; etape(n, total, "Sonde")
    ok_sonde = installer_sonde()

    n += 1; etape(n, total, "Vérification")
    verifier()

    titre("Installation terminée" if (ok_sysmon and ok_sonde)
          else "Installation incomplète")
    print(f"  Démarrer maintenant : {os.path.join(RACINE, 'demarrer_sonde.bat')}")
    print("  Vérifier la liaison  : installer_sonde.exe --verifier")
    print()
    print("  La sonde découvre seule l'adresse du système. Si elle ne la")
    print("  trouve pas, la VM a probablement besoin d'une carte réseau")
    print("  « hôte uniquement » — le NAT seul ne permet pas de joindre l'hôte.")


if __name__ == "__main__":
    main()
