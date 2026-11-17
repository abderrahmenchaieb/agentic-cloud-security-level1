"""
=============================================================================
ÉVALUATION D'INTÉGRITÉ PAR FENÊTRE — branchement de l'autoencodeur
=============================================================================
L'autoencodeur d'intégrité (recall 0.975, precision 0.994) était CHARGÉ mais
JAMAIS SOLLICITÉ : ni par le service, ni par les expériences.

⚠️ POURQUOI IL N'ÉTAIT PAS BRANCHÉ
    Les interfaces sont incompatibles, et ce n'est pas un oubli de câblage :

      CollectAgent  attend  .score(log)      → un verdict par LOG
      l'autoencodeur fournit .is_suspect(X)  → un verdict par FENÊTRE de 50

    C'est la méthode AutoLog : le modèle apprend le PROFIL STATISTIQUE d'une
    fenêtre — comptes par catégorie, ratios, écarts temporels, diversité. Un
    log isolé ne possède aucune de ces propriétés. Le brancher log par log
    n'aurait aucun sens.

CE QUE CE MODULE APPORTE
    Les deux étages deviennent complémentaires :

      règles forensiques  →  INCOHÉRENCES ponctuelles (horodatage aberrant,
                             désordre, trou de numérotation)
      autoencodeur        →  DÉFORMATION DU PROFIL (trop d'événements d'un
                             type, ratios inhabituels, rythme anormal)

    Une injection de faux logs ne crée aucune incohérence — c'est pourquoi
    les règles la manquent entièrement. Mais elle DÉFORME le profil de la
    fenêtre, ce que l'autoencodeur mesure précisément.

⚠️ LES 22 FEATURES REPRODUISENT EXACTEMENT CELLES DE L'ENTRAÎNEMENT
    Ordre, nommage et mode de calcul sont repris du notebook d'entraînement.
    Toute divergence produirait un décalage entre apprentissage et inférence
    — le modèle recevrait des valeurs sans rapport avec ce qu'il a appris, et
    ses sorties seraient ininterprétables sans qu'aucune erreur n'apparaisse.
=============================================================================
"""
from __future__ import annotations

from collections import Counter

# Correspondance EventID Sysmon → catégorie, reprise de l'entraînement.
_CATEGORIE = {
    "1": "process", "3": "network", "7": "dll", "8": "inject",
    "10": "procaccess", "11": "file", "12": "registry", "13": "registry",
    "15": "file",
}
CATEGORIES = ["process", "network", "dll", "inject", "procaccess",
              "file", "registry", "other"]

# Ordre exact attendu par le modèle (config['score_names']).
NOMS_SCORES = (
    [f"n_{c}" for c in CATEGORIES] +
    [f"r_{c}" for c in CATEGORIES] +
    ["n_types", "gap_mean", "gap_std", "gap_max", "proc_name_len", "n_guid"]
)

TAILLE_FENETRE = 50


def categorie(event_id) -> str:
    return _CATEGORIE.get(str(event_id), "other")


def fenetre_vers_scores(logs: list) -> list[float]:
    """
    Résume une fenêtre de logs en 22 scores numériques.

    `logs` : liste de CanonicalLog (ou d'objets exposant sysmon_event_id,
    event_time et le nom de processus).
    """
    n = len(logs)
    if n == 0:
        return [0.0] * len(NOMS_SCORES)

    eids = [_event_id(l) for l in logs]
    cats = [categorie(e) for e in eids]
    c = Counter(cats)

    comptes = [float(c.get(k, 0)) for k in CATEGORIES]
    ratios = [v / n for v in comptes]
    n_types = float(len(set(cats)))

    # écarts entre événements successifs, en secondes
    temps = sorted(t for t in (getattr(l, "event_time", None) for l in logs)
                   if t is not None)
    if len(temps) > 1:
        ecarts = [(temps[i + 1] - temps[i]).total_seconds()
                  for i in range(len(temps) - 1)]
        moyenne = sum(ecarts) / len(ecarts)
        variance = sum((e - moyenne) ** 2 for e in ecarts) / len(ecarts)
        gap_mean, gap_std, gap_max = moyenne, variance ** 0.5, max(ecarts)
    else:
        gap_mean = gap_std = gap_max = 0.0

    noms = [_nom_processus(l) for l in logs]
    longueurs = [len(x) for x in noms if x]
    proc_name_len = (sum(longueurs) / len(longueurs)) if longueurs else 0.0

    guids = {_guid(l) for l in logs}
    guids.discard("")
    n_guid = float(len(guids))

    return comptes + ratios + [n_types, gap_mean, gap_std, gap_max,
                               proc_name_len, n_guid]


# --- accès tolérants aux champs, quelle que soit la forme du log -----------
def _event_id(log) -> str:
    """
    ⚠️ `CanonicalLog.event_id` est un UUID interne, PAS l'EventID Sysmon.
    Ce dernier est conservé dans `extra['sysmon_event_id']` — le confondre
    ferait tomber tous les événements dans la catégorie « other », et le
    profil de fenêtre n'aurait plus aucun rapport avec celui appris.
    """
    extra = getattr(log, "extra", None) or {}
    v = extra.get("sysmon_event_id")
    if v not in (None, ""):
        return str(v)
    return str(getattr(log, "sysmon_event_id", "") or "")


def _contexte(log):
    """Le processus vit dans `process_context`, pas dans `actor`."""
    return getattr(log, "process_context", None)


def _nom_processus(log) -> str:
    pc = _contexte(log)
    return str(getattr(pc, "process_name", "") or "") if pc else ""


def _guid(log) -> str:
    pc = _contexte(log)
    return str(getattr(pc, "process_guid", "") or "") if pc else ""


# =============================================================================
class EvaluateurFenetre:
    """
    Applique l'autoencodeur d'intégrité par fenêtre glissante.

    ⚠️ Le verdict porte sur la FENÊTRE, pas sur un log précis. C'est cohérent
    avec l'usage réel : un analyste cherche la ZONE du journal à ne pas
    croire, pas l'événement exact qui a été modifié.

    ⚠️ LE SEUIL DOIT ÊTRE CALIBRÉ SUR LE CORPUS DE DÉPLOIEMENT.
        Le seuil livré avec le modèle est le 98e percentile des erreurs
        observées SUR SES DONNÉES D'ENTRAÎNEMENT. L'appliquer tel quel à un
        autre environnement suppose que les deux produisent la même
        distribution d'erreur — hypothèse fausse en général.

        Mesuré : modèle entraîné sur COMISET Real (seuil 0,0239), appliqué à
        COMISET Lab dont l'erreur MÉDIANE sur des fenêtres parfaitement
        saines vaut 5,71 — soit 240 fois le seuil. Résultat : 100 % des
        fenêtres saines signalées, précision 0,345, TN = 0.

        Ce n'est pas un défaut du modèle : il reconstruit correctement ce
        qu'il connaît. C'est un seuil transporté hors de son domaine de
        validité, exactement comme RecordGapDetector appliqué à une séquence
        non ordonnée. `calibrer()` recalcule le seuil sur un échantillon
        réputé sain du corpus visé.
    """

    def __init__(self, autoencodeur, taille: int = TAILLE_FENETRE,
                 seuil: float | None = None):
        self.ae = autoencodeur
        self.taille = taille
        # le seuil vient de la calibration d'entraînement ; le redéfinir
        # invaliderait les métriques annoncées (0.975 / 0.994)
        # ⚠️ L'attribut se nomme `seuil` dans CollectAutoencoder, pas
        #    `threshold` : c'est la valeur calibrée à l'entraînement,
        #    celle qui donne les 0.975 / 0.994 annoncés.
        self.seuil = (seuil if seuil is not None
                      else getattr(autoencodeur, "seuil", None))

    def calibrer(self, logs_sains: list, percentile: float = 95.0,
                 marge: float = 1.0) -> float:
        """
        Recalcule le seuil sur un échantillon RÉPUTÉ SAIN du corpus visé.

        `percentile` : proportion de fenêtres saines qu'on accepte de NE PAS
        signaler. 95 accepte 5 % de faux positifs — compromis usuel pour un
        signal d'intégrité qui alimente une corrélation, pas une alerte
        directe.

        `marge` : facteur multiplicatif appliqué au seuil obtenu (>1 pour
        être plus permissif).

        ⚠️ `logs_sains` doit être réellement intègre. Y laisser des
        falsifications reviendrait à apprendre qu'elles sont normales et
        relèverait le seuil au point de ne plus rien détecter.
        """
        import numpy as np

        erreurs = [v["erreur"] for v in self.evaluer(logs_sains)
                   if v.get("erreur") is not None]
        if not erreurs:
            return self.seuil
        nouveau = float(np.percentile(erreurs, percentile)) * marge
        self.seuil = nouveau
        return nouveau

    def evaluer(self, logs: list) -> list[dict]:
        """
        Découpe en fenêtres non chevauchantes et renvoie un verdict par
        fenêtre : indices couverts, erreur de reconstruction, suspect ou non.
        """
        import numpy as np

        verdicts = []
        for debut in range(0, len(logs), self.taille):
            bloc = logs[debut:debut + self.taille]
            if len(bloc) < max(5, self.taille // 5):
                continue        # fenêtre trop courte : profil non significatif
            X = np.array([fenetre_vers_scores(bloc)], dtype=float)
            try:
                erreur = float(self.ae.reconstruction_error(X)[0])
                # ⚠️ Comparer à `self.seuil`, PAS appeler `ae.is_suspect()`.
                #    `is_suspect()` applique le seuil interne du modèle, figé
                #    à l'entraînement — toute recalibration sur le corpus de
                #    déploiement (voir `calibrer()`) serait alors ignorée
                #    silencieusement, et le verdict resterait celui d'un
                #    seuil hors de son domaine de validité.
                suspect = bool(erreur >= self.seuil) if self.seuil is not None \
                    else bool(self.ae.is_suspect(X)[0])
            except Exception as e:
                verdicts.append({"debut": debut, "fin": debut + len(bloc),
                                 "erreur": None, "suspect": False,
                                 "echec": str(e)[:80]})
                continue
            verdicts.append({"debut": debut, "fin": debut + len(bloc),
                             "n_logs": len(bloc),
                             "erreur": round(erreur, 5), "suspect": suspect})
        return verdicts


def charger_evaluateur(voie: str = "windows", racine: str = "models"):
    """Charge l'autoencodeur d'intégrité et l'enveloppe pour l'usage fenêtré."""
    import os
    from model_loader import load_collect_autoencoder

    fichiers = {
        "windows": ("collect_autoencoder_final.pt",
                    "collect_autoencoder_final_config.pkl"),
        "cloud": ("collect_cloud_ae_final.pt",
                  "collect_cloud_ae_final_config.pkl"),
    }
    modele, config = fichiers[voie]
    ae = load_collect_autoencoder(os.path.join(racine, modele),
                                  os.path.join(racine, config))
    taille = getattr(ae, "window_size", None) or TAILLE_FENETRE
    return EvaluateurFenetre(ae, taille=taille)
