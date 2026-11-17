#!/usr/bin/env bash
# =============================================================================
# INSTALLATEUR DE SONDE — CLOUD (instance cible du Traffic Mirroring)
# =============================================================================
# Pendant cloud de `installer_sonde.py`. À exécuter sur l'instance EC2 qui
# reçoit le trafic mirroré et lit les logs CloudTrail.
#
# CE QU'IL INSTALLE
#     1. tshark / dumpcap   — capture du trafic mirroré
#     2. Java + CICFlowMeter — PCAP → 76 features
#     3. boto3               — lecture des logs CloudTrail dans S3
#     4. la sonde            — service systemd démarrant automatiquement
#
# POURQUOI UN SCRIPT ET NON UN .EXE
#     La cible est une instance Linux : les exécutables Windows n'y ont pas
#     cours. L'équivalent d'un installateur y est un script shell — c'est la
#     forme attendue sur cette plateforme.
#
# ⚠️ CONTRAINTES AWS VÉRIFIÉES
#     - Instance SOURCE du mirroring : T3 / T3a / T4g. **T2 N'EST PAS
#       SUPPORTÉ** — piège classique, t2.micro étant l'instance free tier.
#     - Instance CIBLE (celle-ci) : 2 vCPU / 2 Gio minimum.
#     - Le trafic mirroré arrive encapsulé en VXLAN sur UDP/4789 ; la sonde
#       le décapsule, faute de quoi CICFlowMeter analyserait l'enveloppe.
#     - Facturation HORAIRE par session active, plus le transfert de données.
#       Elle court tant que la session EXISTE : SUPPRIMER les sessions, ne pas
#       se contenter de détacher l'interface réseau.
#
# USAGE
#     sudo bash installer_sonde_cloud.sh --bucket mon-bucket-cloudtrail
#     sudo bash installer_sonde_cloud.sh --sans-reseau     # CloudTrail seul
#     bash installer_sonde_cloud.sh --verifier
#     sudo bash installer_sonde_cloud.sh --desinstaller
# =============================================================================
set -uo pipefail

RACINE="/opt/agentic-sonde"
CICFM_HOME="/opt/CICFlowMeter"
SERVICE="agentic-sonde"
URL_CICFM="https://github.com/ahlashkari/CICFlowMeter/archive/refs/heads/master.zip"

BUCKET=""
SANS_RESEAU=0

rouge() { printf "\033[31m%s\033[0m\n" "$*"; }
vert()  { printf "\033[32m%s\033[0m\n" "$*"; }
jaune() { printf "\033[33m%s\033[0m\n" "$*"; }
titre() { echo; echo "======================================================================"; echo "  $*"; echo "======================================================================"; }

est_root() { [ "$(id -u)" -eq 0 ]; }

gestionnaire_paquets() {
    command -v apt-get > /dev/null && { echo apt; return; }
    command -v yum     > /dev/null && { echo yum; return; }
    command -v dnf     > /dev/null && { echo dnf; return; }
    echo inconnu
}

# -----------------------------------------------------------------------------
installer_capture() {
    if command -v dumpcap > /dev/null || command -v tshark > /dev/null; then
        vert "  tshark/dumpcap déjà présent"
        return 0
    fi
    case "$(gestionnaire_paquets)" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq
             DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark iproute2 ;;
        yum|dnf) $(gestionnaire_paquets) install -y -q wireshark-cli iproute ;;
        *) rouge "  gestionnaire de paquets inconnu — installer tshark manuellement"; return 1 ;;
    esac
    command -v dumpcap > /dev/null || command -v tshark > /dev/null
}

installer_java() {
    if command -v java > /dev/null; then
        vert "  java déjà présent ($(java -version 2>&1 | head -1))"
        return 0
    fi
    case "$(gestionnaire_paquets)" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq default-jre-headless ;;
        yum|dnf) $(gestionnaire_paquets) install -y -q java-11-openjdk-headless ;;
        *) rouge "  installer un JRE manuellement"; return 1 ;;
    esac
    command -v java > /dev/null
}

installer_cicflowmeter() {
    if [ -d "$CICFM_HOME" ] && [ -n "$(ls -A "$CICFM_HOME" 2>/dev/null)" ]; then
        vert "  CICFlowMeter déjà présent"
        return 0
    fi
    command -v unzip > /dev/null || {
        case "$(gestionnaire_paquets)" in
            apt) apt-get install -y -qq unzip ;;
            yum|dnf) $(gestionnaire_paquets) install -y -q unzip ;;
        esac
    }
    local tmp; tmp=$(mktemp -d)
    echo "  téléchargement de CICFlowMeter V4…"
    if ! curl -fsSL "$URL_CICFM" -o "$tmp/cfm.zip"; then
        rouge "  échec du téléchargement"; rm -rf "$tmp"; return 1
    fi
    unzip -q "$tmp/cfm.zip" -d "$tmp"
    mkdir -p "$CICFM_HOME"
    cp -r "$tmp"/CICFlowMeter*/. "$CICFM_HOME"/
    rm -rf "$tmp"
    vert "  CICFlowMeter installé dans $CICFM_HOME"
    jaune "  NOTE : le dépôt fournit les SOURCES. Si aucun .jar n'est présent,"
    jaune "         le compiler (./gradlew) ou déposer un jar pré-construit."
}

installer_boto3() {
    python3 -c "import boto3" 2>/dev/null && { vert "  boto3 déjà présent"; return 0; }
    pip3 install --quiet boto3 2>/dev/null || {
        case "$(gestionnaire_paquets)" in
            apt) apt-get install -y -qq python3-boto3 ;;
            yum|dnf) $(gestionnaire_paquets) install -y -q python3-boto3 ;;
        esac
    }
    python3 -c "import boto3" 2>/dev/null
}

installer_sonde() {
    mkdir -p "$RACINE"
    local ici; ici="$(cd "$(dirname "$0")" && pwd)"
    for f in sonde_cloud.py; do
        if [ -f "$ici/$f" ]; then
            cp "$ici/$f" "$RACINE/"
            vert "  $f déposé dans $RACINE"
        elif [ ! -f "$RACINE/$f" ]; then
            rouge "  $f introuvable — le placer à côté de ce script"
            return 1
        fi
    done

    # service systemd : redémarrage automatique et au boot
    cat > "/etc/systemd/system/${SERVICE}.service" << EOF
[Unit]
Description=Sonde Agentic Security (CloudTrail + trafic mirrore)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${RACINE}
Environment=CICFLOWMETER_HOME=${CICFM_HOME}
# L'adresse du systeme est decouverte automatiquement ; la forcer si besoin :
# Environment=COLLECT_URL=http://10.0.1.20:9001
# Environment=ANON_URL=http://10.0.1.20:9003
ExecStart=/usr/bin/python3 ${RACINE}/sonde_cloud.py ${BUCKET:+--bucket ${BUCKET}} --interface eth0
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE" > /dev/null 2>&1
    vert "  service systemd « $SERVICE » configuré (démarrage automatique)"
}

# -----------------------------------------------------------------------------
verifier() {
    titre "État de l'installation"
    local ok_ct=1 ok_mir=1

    echo "VOIE 1 — CloudTrail"
    if python3 -c "import boto3" 2>/dev/null; then vert "  [OK] boto3"; else rouge "  [X]  boto3"; ok_ct=0; fi
    if [ -n "$BUCKET" ]; then
        if aws s3 ls "s3://$BUCKET" > /dev/null 2>&1; then
            vert "  [OK] bucket accessible : $BUCKET"
        else
            jaune "  [!]  bucket $BUCKET inaccessible — vérifier le rôle IAM"
        fi
    fi

    echo
    echo "VOIE 2 — trafic mirroré"
    if command -v dumpcap > /dev/null || command -v tshark > /dev/null; then
        vert "  [OK] capture"; else rouge "  [X]  tshark/dumpcap"; ok_mir=0; fi
    if command -v java > /dev/null; then vert "  [OK] java"; else rouge "  [X]  java"; ok_mir=0; fi
    if [ -d "$CICFM_HOME" ] && [ -n "$(ls -A "$CICFM_HOME" 2>/dev/null)" ]; then
        vert "  [OK] CICFlowMeter"; else rouge "  [X]  CICFlowMeter"; ok_mir=0; fi
    if est_root; then vert "  [OK] droits root (VXLAN + capture)"; else jaune "  [!]  root requis à l'exécution"; fi

    echo
    echo "Sonde"
    if [ -f "$RACINE/sonde_cloud.py" ]; then vert "  [OK] $RACINE/sonde_cloud.py"; else rouge "  [X]  sonde absente"; fi
    if systemctl is-enabled "$SERVICE" > /dev/null 2>&1; then
        vert "  [OK] service actif au démarrage ($(systemctl is-active $SERVICE))"
    else
        jaune "  [!]  service non configuré"
    fi

    echo
    [ "$ok_ct" -eq 1 ]  && vert "  Voie CloudTrail : opérationnelle" || jaune "  Voie CloudTrail : indisponible"
    [ "$ok_mir" -eq 1 ] && vert "  Voie mirroring  : opérationnelle" || jaune "  Voie mirroring  : indisponible"
    if [ "$ok_ct" -eq 1 ] && [ "$ok_mir" -eq 0 ]; then
        echo
        jaune "  Sans la voie mirroring, la détection VPN/Tor par GNN est"
        jaune "  indisponible : CloudTrail ne porte aucune statistique de flux."
        jaune "  Le lookup d'IP connues reste actif."
    fi
    [ "$ok_ct" -eq 1 ] || [ "$ok_mir" -eq 1 ]
}

desinstaller() {
    titre "Désinstallation"
    systemctl stop "$SERVICE" 2>/dev/null
    systemctl disable "$SERVICE" 2>/dev/null
    rm -f "/etc/systemd/system/${SERVICE}.service"
    systemctl daemon-reload
    rm -rf "$RACINE"
    vert "  sonde et service supprimés"
    jaune "  tshark, Java et CICFlowMeter conservés (d'autres outils peuvent en dépendre)"
    echo
    rouge "  RAPPEL AWS : supprimer aussi les SESSIONS de Traffic Mirroring,"
    rouge "  sinon la facturation horaire continue :"
    echo "    aws ec2 describe-traffic-mirror-sessions"
    echo "    aws ec2 delete-traffic-mirror-session --traffic-mirror-session-id <id>"
}

# -----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --bucket)       BUCKET="${2:-}"; shift 2 ;;
        --sans-reseau)  SANS_RESEAU=1; shift ;;
        --verifier)     verifier; exit $? ;;
        --desinstaller) est_root || { rouge "root requis"; exit 1; }; desinstaller; exit 0 ;;
        --aide|-h)      sed -n '3,30p' "$0"; exit 0 ;;
        *) rouge "option inconnue : $1"; exit 1 ;;
    esac
done

est_root || { rouge "Droits root requis (paquets système, service, VXLAN)."; echo "→ sudo bash $0 $*"; exit 1; }

titre "Installation de la sonde cloud"
total=$([ "$SANS_RESEAU" -eq 1 ] && echo 3 || echo 5); n=0

n=$((n+1)); echo; echo "[$n/$total] boto3 (lecture CloudTrail)"; installer_boto3
if [ "$SANS_RESEAU" -eq 0 ]; then
    n=$((n+1)); echo; echo "[$n/$total] tshark (capture du trafic mirroré)"; installer_capture
    n=$((n+1)); echo; echo "[$n/$total] Java"; installer_java
    n=$((n+1)); echo; echo "[$n/$total] CICFlowMeter"; installer_cicflowmeter
fi
n=$((n+1)); echo; echo "[$n/$total] Sonde"; installer_sonde

verifier

titre "Installation terminée"
echo "  Démarrer      : sudo systemctl start $SERVICE"
echo "  Journaux      : journalctl -u $SERVICE -f"
echo "  Vérifier      : bash $0 --verifier"
echo
echo "  La sonde découvre seule l'adresse du système. Si l'instance ne le"
echo "  joint pas, vérifier le groupe de sécurité (ports 9001 et 9003)."
echo
jaune "  Rappel : la facturation du mirroring court tant que la SESSION existe."
