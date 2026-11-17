"""
=============================================================================
SERVICE — AGENT DECISION
=============================================================================
Point d'entrée exécutable de l'agent Decision, destiné à son conteneur.
Dernier maillon du Niveau 1 : il corrèle, tranche, et route.

CE QUE FAIT CE SERVICE
    1. charge la base défensive ATT&CK (mitigations réelles)
    2. connecte Ollama pour la formulation des actions (optionnel)
    3. se connecte au bus — Decision est ÉMETTEUR de `reanalyze` vers Analysis
       (re-sollicitation avant escalade) ; il n'enregistre aucun handler
    4. expose :
         POST /ingest   ← Analysis et Anonymization y poussent leurs verdicts
         POST /decide   ← déclenche une décision sur les signaux accumulés
         POST /handle   ← le bus y relaie d'éventuelles requêtes
         GET  /health   ← sonde de santé
         GET  /stats    ← compteurs, exécutions, réévaluations
    5. publie les attaques au bus (dashboard) et route vers le Niveau 2

⚠️ POLITIQUE D'ACTION — GARDE-FOU HUMAIN
    `ACTION_POLICY` contrôle l'autonomie du système :
        manual               rien n'est exécuté, tout attend une validation
        auto_immediate_only  seules les actions « immediate » sont exécutées
        autonomous           toutes les actions recommandées sont exécutées

    Le défaut est `manual`, volontairement. La doctrine SOC établie
    (« automate the routine, escalate the consequential ») réserve à l'humain
    les actions irréversibles et le confinement de systèmes critiques. Un
    système qui isole une machine de production sur un faux positif coûte plus
    cher que l'attaque qu'il prétend arrêter.

⚠️ CORRÉLATION PAR LOTS
    Decision ne décide pas verdict par verdict : il CORRÈLE des signaux de
    sources différentes (menace, anonymisation, intégrité) autour d'une même
    entité. Les verdicts reçus sont donc accumulés dans un tampon, et la
    décision est prise sur l'ensemble — sinon la corrélation ne peut pas
    rapprocher une menace d'une anonymisation arrivée séparément.

VARIABLES D'ENVIRONNEMENT
    BUS_URL, AGENT_URL, MODELS_DIR, PORT
    OLLAMA_URL, OLLAMA_MODEL, ENABLE_LLM
    ACTION_POLICY    manual | auto_immediate_only | autonomous
    DECIDE_INTERVAL  secondes entre deux décisions automatiques (0 = manuel)
=============================================================================
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.environ.get("SYSTEM_ROOT", os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
for _p in (_ROOT,
           os.path.join(_ROOT, "agents", "4_decision_agent"),
           os.path.join(_ROOT, "agentic_layer")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from decision_agent.decision_agent import DecisionAgent
from agentic_layer.agent_bus_http import AgentBusHTTP
from agentic_layer.agentic_decision import AgenticDecisionAgent, ActionPolicy

BUS_URL         = os.environ.get("BUS_URL", "http://bus:8000")
AGENT_URL       = os.environ.get("AGENT_URL", "http://decision:9004")
MODELS_DIR      = os.environ.get("MODELS_DIR", os.path.join(_ROOT, "models"))
PORT            = int(os.environ.get("PORT", "9004"))
OLLAMA_URL      = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL", "llama3.1")
ENABLE_LLM      = os.environ.get("ENABLE_LLM", "1") == "1"
ACTION_POLICY   = os.environ.get("ACTION_POLICY", "manual")
DECIDE_INTERVAL = int(os.environ.get("DECIDE_INTERVAL", "10"))
# Durée pendant laquelle un signal reste disponible à la corrélation.
# Doit couvrir l'écart d'arrivée entre les agents : Anonymization répond en
# secondes, Analysis peut prendre plus d'une minute avec l'interprétation LLM.
CORRELATION_WINDOW = int(os.environ.get("CORRELATION_WINDOW", "300"))

AGENT_NAME = "decision"


def _cle_stable(decision: dict, dossier: dict) -> str:
    """
    Identifiant REPRODUCTIBLE d'un incident, pour l'affichage au dashboard.

    Ni `entity_key` (UUID régénéré à chaque corrélation) ni `dossier_id` ne
    conviennent : ils changent à chaque cycle et multiplient les entrées.
    On s'appuie sur ce qui caractérise durablement l'incident — l'hôte, ou
    à défaut les IP impliquées.
    """
    hote = decision.get("host")
    if hote:
        return str(hote)
    ips = sorted(map(str, dossier.get("anonymized_ips") or []))
    if ips:
        return "ips:" + ",".join(ips)
    return "inconnu"


def post_json(url: str, payload: dict, timeout: float = 30.0):
    import urllib.request
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except Exception:
        return None


class OllamaClient:
    """Client LLM pour la formulation des actions (protocole `generate`)."""

    def __init__(self, base_url: str, model: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def available(self) -> bool:
        import urllib.request
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=5) as r:
                return r.status == 200
        except Exception:
            return False

    def generate(self, prompt: str) -> str:
        res = post_json(f"{self.base_url}/api/generate", {
            "model": self.model, "prompt": prompt, "stream": False,
        }, self.timeout)
        return "" if res is None else res.get("response", "")


def build_action_generator(llm):
    """
    Générateur d'actions : LLM + base de connaissances défensive ATT&CK.
    None si indisponible — l'agent décide et escalade quand même, il ne
    formule simplement pas les actions en langage naturel.
    """
    try:
        from decision_agent.action_generator import ActionGenerator
        from decision_agent.defense_loader import build_defense_db, load_db

        serialisee = os.path.join(_ROOT, "agents", "4_decision_agent",
                                  "defenses_attack.json")
        stix = os.path.join(MODELS_DIR, "enterprise-attack.json")
        if os.path.exists(serialisee):
            kb = load_db(serialisee)          # rapide : évite de reparser 52 Mo
        elif os.path.exists(stix):
            kb = build_defense_db(stix)
        else:
            print(f"[{AGENT_NAME}] base défensive absente — actions non formulées",
                  flush=True)
            return None

        n_tech = len(kb.db)
        n_mit = sum(len(t.attack_mitigations) for t in kb.db.values())
        print(f"[{AGENT_NAME}] base défensive : {n_tech} techniques, "
              f"{n_mit} mitigations ATT&CK", flush=True)
        return ActionGenerator(llm=llm, knowledge_base=kb)
    except Exception as e:
        print(f"[{AGENT_NAME}] générateur d'actions indisponible ({e})", flush=True)
        return None


# -----------------------------------------------------------------------------
class ServiceState:
    def __init__(self):
        self.llm = OllamaClient(OLLAMA_URL, OLLAMA_MODEL) if ENABLE_LLM else None
        self.llm_ok = bool(self.llm and self.llm.available())
        if ENABLE_LLM and not self.llm_ok:
            print(f"[{AGENT_NAME}] Ollama injoignable ({OLLAMA_URL}) — "
                  f"décision et escalade actives, actions non formulées", flush=True)
        elif self.llm_ok:
            print(f"[{AGENT_NAME}] Ollama connecté ({OLLAMA_MODEL})", flush=True)

        self.generator = build_action_generator(self.llm) if self.llm_ok else None
        self.decision = DecisionAgent(action_generator=self.generator)

        try:
            self.policy = ActionPolicy(ACTION_POLICY)
        except ValueError:
            print(f"[{AGENT_NAME}] politique inconnue '{ACTION_POLICY}' — "
                  f"repli sur 'manual'", flush=True)
            self.policy = ActionPolicy.MANUAL
        print(f"[{AGENT_NAME}] politique d'action : {self.policy.value}", flush=True)

        self.bus = AgentBusHTTP(bus_url=BUS_URL, agent_url=AGENT_URL,
                                agent_name=AGENT_NAME)
        self.bus_ready = self._wait_for_bus()
        self.agentic = (AgenticDecisionAgent(self.decision, self.bus)
                        if self.bus_ready else None)
        # le registre du bus est en mémoire : se réinscrire s'il redémarre
        if self.bus_ready:
            self.bus.surveiller_enregistrement()
        if self.agentic is not None:
            try:
                self.agentic.config.action_policy = self.policy
            except Exception:
                pass
        print(f"[{AGENT_NAME}] " + ("coopération active" if self.bus_ready
                                    else "MODE DÉGRADÉ — bus injoignable"), flush=True)

        # tampon de signaux : la corrélation a besoin de VOIR ensemble des
        # signaux arrivés séparément (menace d'Analysis, anonymisation de
        # l'agent Anonymization) pour les rapprocher d'une même entité.
        # signaux horodatés : [(instant_de_reception, signal), …]
        self.buffer_ts: dict[str, list] = {
            "threat_verdicts": [], "anon_verdicts": [],
            "gap_findings": [], "integrity_flags": []}
        self.lock = threading.Lock()
        self.messages_niveau2: list = []   # historique des escalades
        # ⚠️ Avec une fenêtre de corrélation, les mêmes signaux sont réévalués
        #    à chaque cycle. Sans cette mémoire, la même attaque serait
        #    republiée au dashboard et réescaladée toutes les 10 secondes.
        self.deja_publies: set = set()
        # ⚠️ ÉTAT COURANT par entité, distinct des compteurs cumulatifs.
        #    « confirmed=9 pour 5 entités » est illisible : le chiffre mélange
        #    les réévaluations successives d'une même entité et les exécutions
        #    précédentes. Ce registre répond à la vraie question — COMBIEN
        #    D'ENTITÉS sont actuellement dans quel état.
        #      { host : {"certainty":…, "mission":…, "score":…} }
        self.entites: dict = {}
        # ⚠️ NOMS EXPLICITES. « threats: 7, confirmed: 9 » pour 5 entités
        #    était indéchiffrable : on ne savait pas si le chiffre comptait
        #    des signaux, des entités ou des passages de boucle. Chaque nom
        #    dit désormais CE QUI est compté et SUR QUELLE PÉRIODE.
        self.counters = {
            "signaux_menace_recus": 0,      # un par séquence détectée
            "signaux_anon_recus": 0,        # un par flux classé tor/vpn
            "signaux_integrite_recus": 0,   # un par falsification détectée
            "cycles_decision": 0,           # passages de la boucle, pas décisions
            "entites_confirmees_cumul": 0,  # cumul depuis le démarrage
            "entites_escaladees_cumul": 0,
            "plans_action": 0,
        }
        self.started_at = time.time()

    def _wait_for_bus(self, retries: int = 30, delay: float = 2.0) -> bool:
        for i in range(retries):
            if self.bus.health():
                return True
            print(f"[{AGENT_NAME}] bus indisponible, tentative {i+1}/{retries}…",
                  flush=True)
            time.sleep(delay)
        return False

    # --- réception des signaux ------------------------------------------------
    def ingest(self, body: dict) -> dict:
        maintenant = time.time()
        with self.lock:
            for cle in self.buffer_ts:
                recus = body.get(cle) or []
                if isinstance(recus, list):
                    self.buffer_ts[cle].extend((maintenant, s) for s in recus)
            self.counters["signaux_menace_recus"] += len(body.get("threat_verdicts") or [])
            self.counters["signaux_anon_recus"] += len(body.get("anon_verdicts") or [])
            self.counters["signaux_integrite_recus"] += len(body.get("integrity_flags") or [])
            tailles = {k: len(v) for k, v in self.buffer_ts.items()}
        return {"buffered": tailles}

    # --- décision sur les signaux accumulés -----------------------------------
    def decide(self) -> dict:
        """
        Décide sur les signaux d'une FENÊTRE TEMPORELLE, pas d'un instantané.

        ⚠️ POURQUOI UNE FENÊTRE
            Les signaux d'une même attaque n'arrivent pas simultanément :
            l'agent Anonymization classe un flux en quelques secondes, tandis
            qu'Analysis peut prendre une minute ou plus (interprétation LLM).

            Vider le tampon à chaque cycle faisait consommer les verdicts
            d'anonymisation par un cycle, et la menace par un autre : le
            corrélateur ne voyait JAMAIS les deux ensemble et ne pouvait pas
            les rapprocher, malgré une IP commune. L'escalade
            « geolocation » devenait impossible.

            Les signaux sont donc CONSERVÉS pendant `CORRELATION_WINDOW`
            secondes, puis expirés. Un signal peut ainsi participer à
            plusieurs cycles — le temps que son pendant arrive.
        """
        maintenant = time.time()
        with self.lock:
            # purger les signaux plus vieux que la fenêtre
            for cle, horodates in self.buffer_ts.items():
                self.buffer_ts[cle] = [(t, s) for t, s in horodates
                                       if maintenant - t <= CORRELATION_WINDOW]

            # ⚠️ NE DÉCIDER QUE S'IL Y A DU CONTENU NOUVEAU.
            #    La fenêtre garde les signaux disponibles à la corrélation,
            #    mais rejouer un lot inchangé à chaque cycle relancerait
            #    indéfiniment les mêmes décisions et les mêmes demandes de
            #    réanalyse.
            #
            #    ⚠️ Comparer les TAILLES du tampon ne convient pas : les
            #    signaux arrivent en continu, et deux instants différents
            #    peuvent donner le même compte tout en portant des signaux
            #    distincts. Le cycle était alors sauté, et le résultat final
            #    dépendait de l'instant où la boucle tournait — d'où des runs
            #    identiques donnant 4 ou 5 entités confirmées.
            #
            #    On suit donc l'horodatage du signal le plus récent : il
            #    change dès qu'une donnée nouvelle entre, jamais autrement.
            recent = max((t for h in self.buffer_ts.values() for t, _ in h),
                         default=0.0)
            if recent == getattr(self, "_dernier_signal", None):
                return {"decided": 0, "detail": "aucun signal nouveau"}
            self._dernier_signal = recent

            lot = {cle: [s for _, s in horodates]
                   for cle, horodates in self.buffer_ts.items()}

        if not any(lot.values()):
            return {"decided": 0, "detail": "aucun signal dans la fenêtre"}

        processor = self.agentic if self.agentic is not None else self.decision
        outputs = processor.decide(**lot)

        confirmes = list(outputs.confirmed())
        escalades = list(outputs.escalated())
        plans = list(outputs.action_plans())
        dossiers = list(outputs.level2_dossiers())
        self.counters["cycles_decision"] += 1

        # ⚠️ Les compteurs sont incrémentés APRÈS dédoublonnage.
        #    Avec la fenêtre de corrélation, une même entité est réévaluée à
        #    chaque cycle tant que ses signaux restent dans la fenêtre :
        #    compter avant produisait des totaux gonflés (20 « confirmées »
        #    pour 5 entités réelles), incohérents avec les dossiers émis.

        # ⚠️ `entity_key` est RÉGÉNÉRÉ à chaque corrélation (uuid) : s'en servir
        #    comme clé de dédoublonnage ne dédoublonne rien. On identifie une
        #    décision par ce qui reste stable — l'hôte et le niveau de
        #    certitude atteint.
        def _cle(o):
            d = o.to_dict() if hasattr(o, "to_dict") else {}
            dec = d.get("decision", d) or {}
            return f"{dec.get('host')}:{dec.get('certainty')}:{dec.get('mission')}"

        nouveaux = [o for o in confirmes + escalades
                    if _cle(o) not in self.deja_publies]
        for o in nouveaux:
            self.deja_publies.add(_cle(o))
        if len(self.deja_publies) > 1000:
            self.deja_publies.clear()

        # compter APRÈS dédoublonnage : ce sont les entités réellement
        # nouvelles qui comptent, pas les réévaluations d'une même entité
        cles_conf = {_cle(o) for o in confirmes}
        cles_esc = {_cle(o) for o in escalades}
        cles_nouv = {_cle(o) for o in nouveaux}
        self.counters["entites_confirmees_cumul"] += len(cles_conf & cles_nouv)
        self.counters["entites_escaladees_cumul"] += len(cles_esc & cles_nouv)
        self.counters["plans_action"] += len(plans)

        # registre d'état : une entrée par entité, écrasée à chaque
        # réévaluation — il reflète la SITUATION, pas l'historique
        for o in confirmes + escalades:
            b = o.to_dict() if hasattr(o, "to_dict") else {}
            dec = b.get("decision", b) or {}
            hote = dec.get("host")
            if not hote:
                continue
            # ⚠️ `level2_dossier` n'existe que pour les entités ESCALADÉES, et
            #    son `threat_score` n'est pas toujours renseigné. Le score fait
            #    autorité dans l'entité corrélée (`threat_signal.severity`) —
            #    c'est la même source que celle utilisée pour la publication.
            doss = b.get("level2_dossier") or {}
            score = float(doss.get("threat_score", 0.0) or 0.0)
            if not score:
                ent = getattr(o, "entity", None)
                sig = getattr(ent, "threat_signal", None) if ent else None
                score = float(getattr(sig, "severity", 0.0) or 0.0)
            # ⚠️ NE PAS DÉGRADER UNE ESCALADE DÉJÀ CONSTATÉE.
            #    Le registre est réécrit à chaque cycle. Or les signaux
            #    n'expirent pas ensemble : quand les verdicts d'anonymisation
            #    sortent de la fenêtre de corrélation alors que la menace y
            #    reste, la décision retombe à « mission=none, escalate=False ».
            #    Écraser sans condition remplaçait donc une escalade
            #    « geolocation » avérée par un état appauvri, simplement parce
            #    qu'un signal avait expiré. On conserve la mission et
            #    l'escalade une fois qu'elles ont été établies.
            ancien = self.entites.get(hote, {})
            mission = str(dec.get("mission", "none"))
            escalade = bool(dec.get("escalate", False))
            if mission == "none" and ancien.get("mission", "none") != "none":
                mission = ancien["mission"]
            escalade = escalade or bool(ancien.get("escalate", False))

            self.entites[hote] = {
                "certainty": str(dec.get("certainty", "")),
                "mission": mission,
                "escalate": escalade,
                "score": round(score, 2) or ancien.get("score", 0.0),
            }

        self._publish(nouveaux)
        # ⚠️ Dédoublonner par ENTITÉ, pas par dossier_id : un identifiant de
        #    dossier est régénéré à chaque cycle, donc toujours inédit. Avec la
        #    fenêtre de corrélation, la même entité serait escaladée à chaque
        #    passage tant que ses signaux restent dans la fenêtre.
        retenus = []
        for d in dossiers:
            dd = d.to_dict() if hasattr(d, "to_dict") else {}
            # `entity_key` est régénéré à chaque corrélation : on identifie
            # l'escalade par ce qui reste STABLE — l'hôte, la mission et les
            # IP concernées.
            ips = ','.join(sorted(map(str, dd.get('anonymized_ips') or [])))
            cle = f"n2:{dd.get('host')}:{dd.get('mission')}:{ips}"
            if cle not in self.deja_publies:
                self.deja_publies.add(cle)
                retenus.append(d)
        dossiers = retenus
        messages = [self._message_niveau2(d) for d in dossiers]
        for m in messages:
            print(m["texte"], flush=True)
            self.messages_niveau2.append(m)
            # ⚠️ Compléter le registre depuis le DOSSIER émis : c'est le seul
            #    moment où la mission et le score sont certains. Au moment de
            #    la décision, une entité peut encore être en cours de
            #    corrélation — `mission` vaut alors « none » et le score 0,
            #    ce qui rendait le résumé trompeur (« confirmed / none / 0.00 »
            #    pour une entité en réalité escaladée en géolocalisation).
            hote = m.get("host")
            if hote and hote in self.entites:
                dd = m.get("donnees") or {}
                self.entites[hote].update({
                    "mission": m.get("mission") or self.entites[hote]["mission"],
                    "escalate": True,
                    "score": round(float(dd.get("threat_score", 0.0) or 0.0), 2)
                             or self.entites[hote]["score"],
                })

        return {"confirmed": len(confirmes), "escalated": len(escalades),
                "action_plans": len(plans),
                "dossiers_niveau2": len(dossiers),
                "messages_niveau2": messages}

    def _message_niveau2(self, dossier) -> dict:
        """
        Message d'escalade vers le Niveau 2 : ce qui est transmis, et POURQUOI.

        Le Niveau 1 ne calcule pas la géolocalisation — il transmet un dossier
        et justifie l'escalade. Le message expose donc les DONNÉES envoyées et
        les MOTIFS de la décision, pour qu'un analyste puisse la contester.
        """
        d = dossier.to_dict() if hasattr(dossier, "to_dict") else dict(dossier)

        mission = str(d.get("mission", "?"))
        motifs = []
        if d.get("anonymized_ips"):
            types = ", ".join(str(t) for t in (d.get("anonymization_types") or [])) or "inconnu"
            motifs.append(f"origine anonymisée ({types}) : la géolocalisation "
                          f"directe est impossible au Niveau 1")
        if float(d.get("threat_score", 0) or 0) > 0:
            motifs.append(f"score de menace {float(d.get('threat_score', 0)):.2f}")
        if d.get("techniques"):
            motifs.append(f"techniques MITRE : {', '.join(map(str, d['techniques']))}")
        if d.get("integrity_context"):
            motifs.append(f"signaux d'intégrité : {len(d['integrity_context'])} "
                          f"(traces possiblement altérées)")
        if not motifs:
            motifs.append("menace ambiguë sans corroboration : investigation requise")

        lignes = [
            "",
            "=" * 68,
            f"  ESCALADE VERS LE NIVEAU 2 — mission : {mission}",
            "=" * 68,
            f"  dossier   : {d.get('dossier_id', '?')}",
            f"  entité    : {d.get('entity_key', '?')}",
            f"  hôte      : {d.get('host') or 'inconnu'}",
            f"  créé le   : {d.get('created_at', '?')}",
            "",
            "  DONNÉES TRANSMISES",
            f"    score de menace     : {float(d.get('threat_score', 0) or 0):.2f}",
            f"    hypothèse           : {d.get('hypothesis') or '(aucune)'}",
            f"    techniques MITRE    : {', '.join(map(str, d.get('techniques') or [])) or '(aucune)'}",
            f"    artefacts observés  : {len(d.get('observed_artifacts') or [])}",
            f"    IP à géolocaliser   : {', '.join(map(str, d.get('anonymized_ips') or [])) or '(aucune)'}",
            f"    types d'anonymisation : {', '.join(map(str, d.get('anonymization_types') or [])) or '(aucun)'}",
            f"    contexte d'intégrité: {len(d.get('integrity_context') or [])} signal(aux)",
            "",
            "  JUSTIFICATIFS DE L'ESCALADE",
        ]
        lignes += [f"    - {m}" for m in motifs]
        lignes += [
            "",
            "  Le Niveau 1 ne calcule pas l'attribution : il transmet ce dossier.",
            "=" * 68,
        ]

        return {"dossier_id": d.get("dossier_id"), "mission": mission,
                "entity_key": d.get("entity_key"), "host": d.get("host"),
                "donnees": d, "justificatifs": motifs,
                "texte": "\n".join(lignes)}

    def _publish(self, outcomes) -> None:
        """
        Publie les décisions au bus, pour le dashboard.

        ⚠️ `EntityOutcome.to_dict()` IMBRIQUE les champs sous « decision » :
        les lire à la racine donnerait des valeurs par défaut, et le bus
        rejetterait la publication — les attaques n'apparaîtraient jamais
        dans le dashboard alors que Decision les a bien confirmées.
        """
        try:
            for o in outcomes:
                brut = o.to_dict() if hasattr(o, "to_dict") else {}
                d = brut.get("decision", brut)          # ← champs réels
                dossier = brut.get("level2_dossier") or {}

                # le score de menace et les IP vivent dans l'entité corrélée
                entite = getattr(o, "entity", None)
                score = float(dossier.get("threat_score", 0.0) or 0.0)
                if not score and entite is not None:
                    signal = getattr(entite, "threat_signal", None)
                    score = float(getattr(signal, "severity", 0.0) or 0.0)

                post_json(f"{BUS_URL}/publish/attack", {
                    # ⚠️ Le bus indexe les attaques par `entity_key`. Or cette
                    #    clé est un UUID RÉGÉNÉRÉ à chaque corrélation : avec
                    #    la fenêtre de corrélation, une même entité produit une
                    #    nouvelle clé à chaque cycle et le dashboard affiche
                    #    autant d'attaques distinctes.
                    #
                    #    On publie donc une clé STABLE. Le repli ne doit PAS
                    #    être `entity_key` (instable par nature) : à défaut
                    #    d'hôte, on dérive la clé des IP concernées, qui
                    #    identifient l'incident de façon reproductible.
                    "entity_key": _cle_stable(d, dossier),
                    "host_id": d.get("host") or "unknown",
                    "threat_score": score,
                    "certainty": str(d.get("certainty", "")),
                    "escalate": bool(d.get("escalate", False)),
                    "mission": str(d.get("mission", "none")),
                    "triggered_rules": list(d.get("triggered_rules", []) or []),
                    "anonymized_ips": list(dossier.get("anonymized_ips", []) or []),
                })

                # ⚠️ L'ÉTAT DE L'HÔTE DOIT REFLÉTER LA CERTITUDE RÉELLE.
                #    Analysis publie `under_attack` dès qu'il détecte quelque
                #    chose, sans distinguer une attaque confirmée d'un simple
                #    doute. Un poste sain signalé par un faux positif du
                #    détecteur apparaissait donc au même niveau qu'une machine
                #    réellement compromise — visuellement trompeur, alors que
                #    la décision interne, elle, distingue bien les deux.
                #
                #    Decision est le seul à connaître la certitude : c'est donc
                #    à lui de corriger l'état publié.
                etats = {"confirmed": "under_attack",
                         "doubtful": "under_investigation",
                         "monitored": "monitored",
                         "normal": "normal"}
                etat = etats.get(str(d.get("certainty", "")).lower())
                hote = d.get("host")
                if etat and hote:
                    post_json(f"{BUS_URL}/publish/host", {
                        "host_id": hote, "security": etat,
                        "detail": f"{d.get('certainty')} — menace {score:.2f}",
                    })
        except Exception as e:
            print(f"[{AGENT_NAME}] publication ignorée : {e}", flush=True)

    # --- boucle de décision périodique ----------------------------------------
    def boucle(self) -> None:
        while True:
            time.sleep(DECIDE_INTERVAL)
            try:
                res = self.decide()
                if res.get("confirmed") or res.get("escalated"):
                    print(f"[{AGENT_NAME}] {res}", flush=True)
            except Exception as e:
                print(f"[{AGENT_NAME}] erreur de décision : {e}", flush=True)

    def reset(self) -> dict:
        """
        Remet les compteurs et l'état interne à zéro.

        ⚠️ Nécessaire pour mesurer un run ISOLÉ. Sans cela, les compteurs
        cumulent depuis le démarrage du conteneur et les états rémanents
        (files d'attente, caches, fenêtres de corrélation) font déborder
        un run sur le suivant.
        """
        avant = dict(self.counters)
        for k in self.counters:
            self.counters[k] = 0
        for v in self.buffer_ts.values():
            v.clear()
        self.entites.clear()
        self.deja_publies.clear()
        self.messages_niveau2.clear()
        self._dernier_signal = None
        return {"ok": True, "compteurs_avant": avant}

    def stats(self) -> dict:
        """
        Compteurs du service.

        TAXONOMIE — ce que chaque compteur mesure exactement :

          threats    signaux de menace REÇUS d'Analysis (un par séquence
                     détectée). Cumulatif depuis le démarrage du service.
          anon       verdicts d'anonymisation reçus (un par flux classé
                     tor/vpn). Cumulatif — un trafic dense en produit
                     beaucoup, sans qu'aucun ne soit forcément lié à une
                     menace.
          integrity  signaux de falsification reçus du Collect.
          decisions  nombre de CYCLES de décision exécutés, pas de décisions
                     rendues. La boucle tourne toutes les DECIDE_INTERVAL
                     secondes dès qu'un signal nouveau arrive.
          confirmed  entités DISTINCTES portées au niveau « confirmed ».
                     Dédoublonné par (hôte, certitude, mission) : une entité
                     réévaluée plusieurs fois dans la fenêtre de corrélation
                     n'est comptée qu'une fois. Cumulatif entre exécutions.
          escalated  entités DISTINCTES escaladées vers le Niveau 2, même
                     règle de dédoublonnage.
          actions    plans d'action générés (0 si ACTION_POLICY=manual).

        ⚠️ Ces compteurs sont CUMULATIFS depuis le démarrage du conteneur.
           Pour l'état courant, se référer au dashboard (`/state` du bus) ou
           à `/niveau2`, qui reflètent la situation et non l'historique.
        """
        with self.lock:
            attente = {k: len(v) for k, v in self.buffer_ts.items()}
        return {"agent": AGENT_NAME,
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "counters": self.counters,
                # --- ÉTAT COURANT : ce que le système constate MAINTENANT ---
                "entites": self.entites,
                "resume": {
                    "entites_suivies": len(self.entites),
                    "confirmees": sum(1 for e in self.entites.values()
                                      if e["certainty"] == "confirmed"),
                    "en_investigation": sum(1 for e in self.entites.values()
                                            if e["certainty"] == "doubtful"),
                    "escaladees": sum(1 for e in self.entites.values()
                                      if e["escalate"]),
                },
                "en_attente": attente,
                "correlation_window_s": CORRELATION_WINDOW,
                "action_policy": self.policy.value,
                "llm": {"enabled": ENABLE_LLM, "connected": self.llm_ok},
                "action_generator": self.generator is not None,
                "bus_ready": self.bus_ready,
                "executions": (self.agentic.execution_report() if self.agentic else []),
                "reassessments": (self.agentic.reassessment_report() if self.agentic else []),
                "messages_niveau2": self.messages_niveau2[-10:]}


# -----------------------------------------------------------------------------
STATE: ServiceState | None = None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # l'émetteur a fermé la connexion avant la réponse (délai dépassé
            # de son côté). Le traitement a eu lieu : inutile de polluer le
            # journal avec une trace complète.
            pass

    def do_GET(self):
        if self.path == "/health":
            if STATE is None:
                self._send(503, {"status": "initialisation", "agent": AGENT_NAME})
                return
            self._send(200, {"status": "ok", "agent": AGENT_NAME,
                             "policy": STATE.policy.value,
                             "action_generator": STATE.generator is not None})
        elif self.path == "/stats":
            if STATE is None:
                self._send(503, {"status": "initialisation"})
                return
            self._send(200, STATE.stats())
        elif self.path == "/niveau2":
            # messages d'escalade : données transmises + justificatifs
            if STATE is None:
                self._send(503, {"status": "initialisation", "messages": []})
            else:
                self._send(200, {"messages": STATE.messages_niveau2})
        else:
            self._send(404, {"detail": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"detail": "JSON invalide"})
            return

        if STATE is None:
            self._send(503, {"detail": "service en cours d'initialisation"})
            return

        if self.path == "/handle":
            self._send(200, STATE.bus.handle_incoming(body))
        elif self.path == "/reset":
            if STATE is None:
                self._send(503, {"detail": "service en cours d'initialisation"})
            else:
                self._send(200, STATE.reset())
        elif self.path == "/ingest":
            self._send(200, {"ok": True, **STATE.ingest(body)})
        elif self.path == "/decide":
            self._send(200, {"ok": True, **STATE.decide()})
        else:
            self._send(404, {"detail": "not found"})

    def log_message(self, *args):
        pass


def _initialiser() -> None:
    """
    Construit l'état du service sans bloquer l'écoute HTTP, puis lance la
    boucle de décision.

    ⚠️ La boucle DOIT démarrer ici, et non dans main() : l'initialisation étant
    asynchrone, STATE vaut encore None quand main() s'exécute. La lancer trop
    tôt produirait `AttributeError: 'NoneType' object has no attribute 'boucle'`
    et le conteneur redémarrerait en boucle.
    """
    global STATE
    STATE = ServiceState()
    print(f"[{AGENT_NAME}] initialisation terminée", flush=True)
    if DECIDE_INTERVAL > 0:
        threading.Thread(target=STATE.boucle, daemon=True).start()
        print(f"[{AGENT_NAME}] décision automatique toutes les "
              f"{DECIDE_INTERVAL}s", flush=True)


def main() -> None:
    print(f"[{AGENT_NAME}] démarrage — bus={BUS_URL} port={PORT} "
          f"policy={ACTION_POLICY}", flush=True)
    # Le serveur écoute AVANT l'initialisation : l'attente du bus peut
    # durer jusqu'à 60 s, pendant lesquelles le HEALTHCHECK de
    # docker-compose déclarerait sinon le conteneur défaillant.
    # ⚠️ MULTI-THREAD OBLIGATOIRE. Un serveur mono-thread ne peut
    #    répondre à rien pendant qu'il traite une requête. Analysis
    #    attend Ollama des dizaines de secondes sur CPU : /health,
    #    /stats et surtout /handle (coopération inter-agents)
    #    devenaient injoignables — le bus affichait « agent
    #    injoignable » alors que l'agent fonctionnait.
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=_initialiser, daemon=True).start()
    print(f"[{AGENT_NAME}] à l'écoute sur 0.0.0.0:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"[{AGENT_NAME}] arrêt", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
