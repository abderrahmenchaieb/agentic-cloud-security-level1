# =============================================================================
# GÉNÉRATEUR DE FALSIFICATIONS CONTRÔLÉES
# =============================================================================
# Prend un corpus de logs INTÈGRES et y injecte des falsifications connues,
# en gardant une VÉRITÉ TERRAIN PARFAITE (on sait exactement quel log a été
# falsifié, comment, et à quel index).
#
# But : créer le jeu de test pour évaluer les détecteurs (règles forensiques
# aujourd'hui, ML demain). Aucune circularité — c'est NOUS qui falsifions.
#
# Méthodologie inspirée de TALL-Detect : ratios de falsification contrôlés
# (5 / 10 / 20 / 30 %), 4 types de falsification.
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import random
import copy

from .canonical_schema import CanonicalLog


class FalsificationType(str, Enum):
    MODIFICATION = "modification"        # altérer un champ (ex : timestomping)
    SUPPRESSION = "suppression"          # retirer des logs (→ gap)
    REORDERING = "reordering"            # casser l'ordre chronologique
    INJECTION = "injection"              # insérer un faux log


@dataclass
class GroundTruthEntry:
    """Vérité terrain : ce qu'on a falsifié et comment."""
    falsification_type: FalsificationType
    original_index: Optional[int]        # index dans le corpus original
    technique: str                       # technique précise appliquée
    detail: str
    # ⚠️ AJOUTÉ — indispensable pour associer une entrée de vérité terrain à
    #    un event_id précis. Sans lui, un appelant devait reconstituer le
    #    lien par un tri arbitraire (falsifies_ids trié alphabétiquement)
    #    supposé aligné sur l'ordre de génération de `ground_truth` — ce qui
    #    est FAUX (les event_id ne sont pas dans l'ordre alphabétique de
    #    leur génération) et associait silencieusement de mauvais types à de
    #    mauvais logs. Détecté lors d'une mesure croisée règles/autoencodeur
    #    par type de falsification (E3), où le décompte affichait 0 injection
    #    manquée par les règles alors que le tableau par type, lui, mesurait
    #    correctement 235/235 manquées.
    event_id: str = ""


@dataclass
class FalsifiedDataset:
    """Résultat : le corpus falsifié + la vérité terrain."""
    logs: list[CanonicalLog]                     # corpus après falsification
    ground_truth: list[GroundTruthEntry]         # ce qui a été falsifié
    tampered_event_ids: set[str] = field(default_factory=set)  # ids des logs falsifiés
    original_count: int = 0

    def stats(self) -> dict:
        by_type: dict[str, int] = {}
        for gt in self.ground_truth:
            by_type[gt.falsification_type.value] = by_type.get(gt.falsification_type.value, 0) + 1
        return {
            "original_count": self.original_count,
            "final_count": len(self.logs),
            "n_falsifications": len(self.ground_truth),
            "by_type": by_type,
        }


class FalsificationGenerator:
    """
    Applique des falsifications contrôlées à un corpus intègre.
    Chaque type de falsification reproduit une technique anti-forensique réelle.
    """

    # époque utilisée pour le timestomping (comme les vrais outils anti-forensiques)
    STOMP_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)  # reproductibilité

    def generate(
        self,
        corpus: list[CanonicalLog],
        ratio: float = 0.10,
        types: Optional[list[FalsificationType]] = None,
    ) -> FalsifiedDataset:
        """
        corpus : logs intègres (déjà normalisés).
        ratio  : proportion de logs à falsifier (0.05 à 0.30).
        types  : quels types de falsification appliquer (par défaut : les 4).
        """
        if types is None:
            types = list(FalsificationType)

        logs = [copy.deepcopy(l) for l in corpus]  # ne pas modifier l'original
        original_count = len(logs)
        n_to_falsify = max(1, int(original_count * ratio))

        # indices candidats (on évite de falsifier deux fois le même)
        candidate_indices = list(range(len(logs)))
        self.rng.shuffle(candidate_indices)
        selected = candidate_indices[:n_to_falsify]

        ground_truth: list[GroundTruthEntry] = []
        tampered_ids: set[str] = set()

        # On traite les suppressions/injections à part (elles changent la taille)
        to_delete: set[int] = set()
        injections: list[tuple[int, CanonicalLog, GroundTruthEntry]] = []

        for idx in selected:
            ftype = self.rng.choice(types)

            if ftype == FalsificationType.MODIFICATION:
                gt = self._apply_modification(logs[idx], idx)
                ground_truth.append(gt)
                tampered_ids.add(logs[idx].event_id)

            elif ftype == FalsificationType.REORDERING:
                gt = self._apply_reordering(logs[idx], idx)
                ground_truth.append(gt)
                tampered_ids.add(logs[idx].event_id)

            elif ftype == FalsificationType.INJECTION:
                fake, gt = self._make_injection(logs[idx], idx)
                injections.append((idx, fake, gt))

            elif ftype == FalsificationType.SUPPRESSION:
                to_delete.add(idx)
                ground_truth.append(GroundTruthEntry(
                    falsification_type=FalsificationType.SUPPRESSION,
                    original_index=idx,
                    technique="log_deletion",
                    detail=f"log #{idx} (event {logs[idx].event_id}) supprimé",
                    event_id=logs[idx].event_id,
                ))

        # appliquer les injections (insérer les faux logs)
        for idx, fake, gt in injections:
            logs.insert(idx, fake)
            ground_truth.append(gt)
            tampered_ids.add(fake.event_id)

        # appliquer les suppressions (en fin, indices décroissants pour ne pas décaler)
        for idx in sorted(to_delete, reverse=True):
            # attention : les injections ont pu décaler les indices ; on retire par event_id
            pass
        if to_delete:
            delete_ids = {corpus[i].event_id for i in to_delete}
            logs = [l for l in logs if l.event_id not in delete_ids]

        return FalsifiedDataset(
            logs=logs,
            ground_truth=ground_truth,
            tampered_event_ids=tampered_ids,
            original_count=original_count,
        )

    # -------------------------------------------------------------------------
    # Techniques de falsification concrètes
    # -------------------------------------------------------------------------

    def _apply_modification(self, log: CanonicalLog, idx: int) -> GroundTruthEntry:
        """Modification : timestomping (le cas le plus courant et détectable)."""
        old_time = log.event_time
        log.event_time = self.STOMP_EPOCH  # stompé à 1970
        return GroundTruthEntry(
            falsification_type=FalsificationType.MODIFICATION,
            original_index=idx,
            technique="timestomping",
            detail=f"event_time {old_time.isoformat()} → {log.event_time.isoformat()}",
            event_id=log.event_id,
        )

    def _apply_reordering(self, log: CanonicalLog, idx: int) -> GroundTruthEntry:
        """Réordonnancement : reculer le timestamp dans le passé."""
        old_time = log.event_time
        log.event_time = old_time - timedelta(hours=1)  # recul d'1h
        return GroundTruthEntry(
            falsification_type=FalsificationType.REORDERING,
            original_index=idx,
            technique="timestamp_backdate",
            detail=f"event_time reculé de 1h ({old_time.isoformat()} → {log.event_time.isoformat()})",
            event_id=log.event_id,
        )

    def _make_injection(self, ref: CanonicalLog, idx: int) -> tuple[CanonicalLog, GroundTruthEntry]:
        """Injection : créer un faux log avec une incohérence (self-parent)."""
        fake = copy.deepcopy(ref)
        fake.event_id = f"INJECTED-{self.rng.randint(10000, 99999)}"
        # incohérence caractéristique : le faux log est son propre parent
        if fake.process_context:
            fake.process_context.parent_process_guid = fake.process_context.process_guid
        # + clock skew anormal (injecté tardivement)
        fake.event_time = fake.ingest_time - timedelta(days=2)
        gt = GroundTruthEntry(
            falsification_type=FalsificationType.INJECTION,
            original_index=idx,
            technique="fake_log_self_parent",
            detail=f"faux log injecté à l'index {idx} (event {fake.event_id})",
            event_id=fake.event_id,
        )
        return fake, gt
