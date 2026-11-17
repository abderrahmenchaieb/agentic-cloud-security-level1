# =============================================================================
# DÉTECTION DE GAPS (4e falsification : SUPPRESSION)
# =============================================================================
# Une suppression de logs laisse un VIDE, pas une trace. On la détecte
# indirectement par deux mécanismes complémentaires :
#
#   A. SAUT DE NUMÉRO (RecordNumber) — déterministe, haute fidélité.
#      Les logs Windows/Sysmon sont numérotés séquentiellement par la source.
#      Un numéro manquant = un log a été supprimé (ou perdu).
#
#   B. SILENCE ANORMAL (rythme) — statistique.
#      Une source qui émet régulièrement puis se tait soudainement = gap
#      possible (suppression en masse, ou source coupée par l'attaquant).
#
# Le Collect Agent SIGNALE le gap ; il ne décide pas si c'est une panne ou
# une attaque (c'est le rôle de l'aval).
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class GapType(str, Enum):
    RECORD_GAP = "record_gap"        # saut de numéro d'enregistrement
    SILENCE_GAP = "silence_gap"      # silence anormal d'une source


@dataclass
class GapFinding:
    gap_type: GapType
    source_key: str                  # host:provider
    detail: str
    severity_score: float            # 0.0 - 1.0
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    missing_estimate: Optional[int] = None   # nb de logs estimés manquants


# =============================================================================
# A. DÉTECTION PAR SAUT DE RECORDNUMBER (déterministe)
# =============================================================================

class RecordGapDetector:
    """
    Suit le dernier RecordNumber vu par source. Un saut (> +1) signale des
    enregistrements manquants entre deux logs consécutifs.

    ⚠️ PRÉCONDITION : LA SÉQUENCE DOIT ÊTRE ORDONNÉE PAR RecordNumber.
        Ce détecteur compare chaque numéro au précédent. Si les logs
        arrivent dans un AUTRE ordre (typiquement triés par horodatage,
        ou tels qu'exportés depuis Elasticsearch), les numéros ne se
        suivent pas et CHAQUE log produit un faux saut.

        Mesuré sur COMISET Lab trié chronologiquement : 2 942 fausses
        alertes sur 20 000 logs, saturant 100 % des fenêtres saines — alors
        que le détecteur de silence n'en produisait que 8. Le détecteur
        n'était pas en cause : sa précondition n'était pas remplie, et rien
        ne le signalait.

        Il SURVEILLE donc désormais l'ordre de ce qu'il reçoit. Au-delà de
        `seuil_desordre` de reculs, il se DÉSACTIVE pour cette source et
        cesse d'émettre : mieux vaut ne rien dire que noyer l'analyse sous
        des alertes que la donnée d'entrée rend inévitables.

        `min_echantillon` est volontairement BAS (15) : c'est le nombre de
        logs observés avant de pouvoir juger de l'ordre. Trop haut, le
        détecteur émet du bruit pendant tout l'apprentissage (26 fausses
        alertes mesurées avec un seuil à 50) ; trop bas, une rafale
        atypique suffirait à le désactiver à tort.

        Un journal Windows lu dans son ordre natif ne déclenche jamais cette
        protection — les deux horloges y sont cohérentes. C'est l'export qui
        les dissocie (58,9 % de reculs mesurés).
    """
    def __init__(self, seuil_desordre: float = 0.10, min_echantillon: int = 15):
        self._last_record: dict[str, int] = {}
        self._reculs: dict[str, int] = {}
        self._vus: dict[str, int] = {}
        self._desactive: dict[str, bool] = {}
        self.seuil_desordre = seuil_desordre
        self.min_echantillon = min_echantillon

    def sequence_desordonnee(self, source_key: str) -> bool:
        """Le détecteur s'est-il désactivé faute de séquence ordonnée ?"""
        return self._desactive.get(source_key, False)

    def diagnostic(self) -> dict:
        """Taux de recul par source — pour expliquer une désactivation."""
        return {k: {"reculs": self._reculs.get(k, 0),
                    "vus": self._vus.get(k, 0),
                    "taux": round(self._reculs.get(k, 0) / v, 4) if v else 0.0,
                    "desactive": self._desactive.get(k, False)}
                for k, v in self._vus.items()}

    def check(self, source_key: str, record_number: Optional[int]) -> Optional[GapFinding]:
        if record_number is None:
            return None
        last = self._last_record.get(source_key)
        self._last_record[source_key] = record_number
        self._vus[source_key] = self._vus.get(source_key, 0) + 1

        if last is None:
            return None  # premier log de la source, rien à comparer

        delta = record_number - last

        # --- surveillance de l'ordre --------------------------------------
        if delta < 0:
            self._reculs[source_key] = self._reculs.get(source_key, 0) + 1
        vus = self._vus[source_key]
        if vus >= self.min_echantillon and not self._desactive.get(source_key):
            taux = self._reculs.get(source_key, 0) / vus
            if taux > self.seuil_desordre:
                self._desactive[source_key] = True
        if self._desactive.get(source_key):
            return None      # séquence non ordonnée : on n'émet plus

        if delta > 1:
            missing = delta - 1
            # sévérité croît avec le nombre de logs manquants (borne à 1.0)
            severity = min(1.0, missing / 100)
            return GapFinding(
                gap_type=GapType.RECORD_GAP,
                source_key=source_key,
                detail=f"{missing} enregistrement(s) manquant(s) entre #{last} et #{record_number}",
                severity_score=severity,
                missing_estimate=missing,
            )
        return None


# =============================================================================
# B. DÉTECTION PAR SILENCE ANORMAL (statistique, baseline temporelle)
# =============================================================================

class SilenceGapDetector:
    """
    Apprend le rythme normal d'émission de chaque source (intervalle moyen
    entre logs, via une moyenne mobile exponentielle) et signale un silence
    anormalement long.

    Deux modes :
      - check_on_log()  : appelé à chaque log, met à jour la baseline et
                          détecte un intervalle anormal a posteriori.
      - check_silence() : appelé périodiquement (timer) pour détecter une
                          source qui S'EST TUE (aucun log récent) — c'est le
                          cas le plus important : une source coupée n'émet
                          plus rien, donc aucun log ne déclenchera check_on_log.
    """
    def __init__(self, k_sigma: float = 4.0, min_samples: int = 5,
                 alpha: float = 0.3, quantile: float = 0.995,
                 facteur_quantile: float = 3.0, fenetre_hist: int = 500):
        """
        ⚠️ SEUIL PAR QUANTILE EMPIRIQUE, PAS PAR moyenne + k·σ
            L'ancien seuil `moyenne + k·écart-type` suppose une distribution
            à peu près symétrique. Or le rythme d'un journal Windows est
            fortement ASYMÉTRIQUE : ~85 % d'intervalles très courts (rafales
            d'activité) et ~15 % de pauses naturelles bien plus longues.

            Sur une telle distribution, la moyenne est tirée vers le bas par
            les rafales et l'écart-type ne décrit aucune réalité — le seuil
            se retrouve sous les pauses NORMALES, qui sont alors toutes
            signalées. Mesuré : 6,7 % de fausses alertes sur du trafic
            parfaitement sain en simulation, et 100 % des fenêtres saines
            saturées sur COMISET Lab (3 746 déclenchements, 291 justes,
            précision 0.078) — `gap` était le SEUL détecteur à polluer la
            mesure, les huit autres règles étant à précision 1.000.

            Un quantile empirique élevé (99,5 %) décrit directement « au-delà
            de quelle durée un silence est inhabituel pour CETTE source »,
            sans hypothèse sur la forme de la distribution. Le facteur
            multiplicatif ajoute une marge : on ne signale qu'un silence
            nettement plus long que le plus long silence habituel.

        `k_sigma` et `alpha` sont conservés pour compatibilité (l'EWMA
        alimente encore `check_silence`), mais ne pilotent plus le seuil.
        """
        self.k_sigma = k_sigma
        self.min_samples = min_samples
        self.alpha = alpha
        self.quantile = quantile
        self.facteur_quantile = facteur_quantile
        self.fenetre_hist = fenetre_hist
        # état par source :
        self._last_time: dict[str, datetime] = {}
        self._ewma_interval: dict[str, float] = {}   # intervalle moyen (s)
        self._ewma_var: dict[str, float] = {}        # variance de l'intervalle
        self._count: dict[str, int] = {}
        # historique borné des intervalles, pour le quantile empirique
        self._historique: dict[str, list] = {}

    def _expected_max_silence(self, key: str) -> Optional[float]:
        hist = self._historique.get(key)
        if not hist or len(hist) < self.min_samples:
            return None
        ordonnes = sorted(hist)
        i = min(len(ordonnes) - 1,
                int(self.quantile * (len(ordonnes) - 1)))
        # marge multiplicative au-dessus du plus long silence habituel
        return max(ordonnes[i] * self.facteur_quantile, 1.0)

    def check_on_log(self, source_key: str, event_time: datetime) -> Optional[GapFinding]:
        last = self._last_time.get(source_key)
        self._last_time[source_key] = event_time

        finding = None
        if last is not None:
            interval = (event_time - last).total_seconds()
            if interval < 0:
                return None  # recul temporel → réordonnancement, pas gap

            threshold = self._expected_max_silence(source_key)
            if threshold is not None and interval > threshold:
                severity = min(1.0, interval / (threshold * 2))
                finding = GapFinding(
                    gap_type=GapType.SILENCE_GAP,
                    source_key=source_key,
                    detail=f"intervalle {interval:.0f}s > seuil {threshold:.0f}s (silence anormal)",
                    severity_score=severity,
                )

            # mise à jour de la baseline (EWMA de la moyenne et de la variance)
            self._update_baseline(source_key, interval)
        return finding

    def _update_baseline(self, key: str, interval: float):
        # historique borné : sert au quantile empirique (seuil principal)
        hist = self._historique.setdefault(key, [])
        hist.append(interval)
        if len(hist) > self.fenetre_hist:
            del hist[0]        # fenêtre glissante, mémoire bornée

        if key not in self._ewma_interval:
            self._ewma_interval[key] = interval
            self._ewma_var[key] = 0.0
            self._count[key] = 1
        else:
            prev_mean = self._ewma_interval[key]
            new_mean = (1 - self.alpha) * prev_mean + self.alpha * interval
            # variance EWMA
            self._ewma_var[key] = (1 - self.alpha) * self._ewma_var[key] + \
                                  self.alpha * (interval - prev_mean) * (interval - new_mean)
            self._ewma_interval[key] = new_mean
            self._count[key] += 1

    def check_silence(self, now: datetime) -> list[GapFinding]:
        """
        Appelé périodiquement. Détecte les sources qui se sont tues :
        aucune activité depuis plus longtemps que leur seuil attendu.
        C'est ICI qu'on attrape une source coupée par un attaquant.
        """
        findings = []
        for key, last in self._last_time.items():
            threshold = self._expected_max_silence(key)
            if threshold is None:
                continue
            silence = (now - last).total_seconds()
            if silence > threshold:
                findings.append(GapFinding(
                    gap_type=GapType.SILENCE_GAP,
                    source_key=key,
                    detail=f"source silencieuse depuis {silence:.0f}s (seuil {threshold:.0f}s)",
                    severity_score=min(1.0, silence / (threshold * 2)),
                ))
        return findings


# =============================================================================
# ORCHESTRATEUR
# =============================================================================

class GapDetectionEngine:
    def __init__(self):
        self.record_detector = RecordGapDetector()
        self.silence_detector = SilenceGapDetector()

    def analyze_log(self, source_key: str, record_number: Optional[int],
                    event_time: datetime) -> list[GapFinding]:
        findings = []
        f_rec = self.record_detector.check(source_key, record_number)
        if f_rec:
            findings.append(f_rec)
        f_sil = self.silence_detector.check_on_log(source_key, event_time)
        if f_sil:
            findings.append(f_sil)
        return findings

    def check_silence(self, now: datetime) -> list[GapFinding]:
        return self.silence_detector.check_silence(now)

    def diagnostic_ordre(self) -> dict:
        """
        État de la surveillance d'ordre du détecteur déterministe.

        ⚠️ À CONSULTER avant d'interpréter une absence de `record_gap` :
        un détecteur désactivé faute de séquence ordonnée ne signale RIEN,
        ce qui ne veut pas dire qu'il n'y a pas de trou — seulement qu'on
        ne peut pas le savoir sur cette entrée.
        """
        return self.record_detector.diagnostic()
