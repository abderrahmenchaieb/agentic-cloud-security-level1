# =============================================================================
# GEOLOCATION AGENT — assemblage complet
# =============================================================================
# Orchestre les deux étapes :
#
#   flux
#    │
#    ▼  ÉTAPE 1 — lookup (IP connue ?)
#    │     └── connu → verdict immédiat (VPN/Tor, conf 0.99)  [STOP]
#    ▼  ÉTAPE 2 — E-GraphSAGE (supervisé) sur les flux inconnus
#    │     └── verdict : normal / VPN / Tor
#    ▼  (optionnel) Anomal-E en filet :
#          si E-GraphSAGE dit "normal" MAIS Anomal-E dit "anormal"
#          → flag "anonymisation inconnue possible"
#
# E-GraphSAGE décide, Anomal-E surveille les angles morts.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import numpy as np
import torch

from .flow_schema import NetworkFlow, AnonymizationVerdict, AnonymizationLabel
from .lookup_engine import LookupEngine
from .graph_builder import GraphBuilder, FlowGraph
from .egraphsage import EGraphSAGE, graph_to_tensors
from .anomale import AnomalEDetector


_INT_TO_LABEL = {
    0: AnonymizationLabel.NORMAL,
    1: AnonymizationLabel.VPN,
    2: AnonymizationLabel.TOR,
}


@dataclass
class AnonymizationDetectionConfig:
    use_anomale_safety_net: bool = False   # activer le filet Anomal-E
    gnn_confidence_floor: float = 0.5


class AnonymizationDetectionAgent:
    """
    Agent de détection d'anonymisation.
    Étape 1 (lookup) + Étape 2 (E-GraphSAGE), Anomal-E optionnel en filet.
    """

    def __init__(self, lookup: LookupEngine,
                 egraphsage_model: Optional[EGraphSAGE] = None,
                 graph_builder: Optional[GraphBuilder] = None,
                 anomale_detector: Optional[AnomalEDetector] = None,
                 config: Optional[AnonymizationDetectionConfig] = None,
                 device: str = "cpu"):
        self.lookup = lookup
        self.gnn = egraphsage_model
        self.builder = graph_builder or GraphBuilder()
        self.anomale = anomale_detector
        self.config = config or AnonymizationDetectionConfig()
        self.device = device

    # -------------------------------------------------------------------------
    def analyze_batch(self, flows: list[NetworkFlow]) -> list[AnonymizationVerdict]:
        """
        Traite un lot de flux. D'abord le lookup (par flux) ; les flux
        inconnus sont regroupés et passés au GNN en une fois (le GNN a besoin
        du graphe complet).
        """
        verdicts: dict[str, AnonymizationVerdict] = {}
        unknown_flows: list[NetworkFlow] = []

        # --- ÉTAPE 1 : lookup ---
        for flow in flows:
            v = self.lookup.analyze(flow)
            if v is not None:
                verdicts[flow.flow_id] = v
            else:
                unknown_flows.append(flow)

        # --- ÉTAPE 2 : GNN sur les inconnus ---
        if unknown_flows and self.gnn is not None:
            gnn_verdicts = self._run_gnn(unknown_flows)
            verdicts.update(gnn_verdicts)
        elif unknown_flows:
            # pas de GNN dispo → verdict "unknown"
            for flow in unknown_flows:
                verdicts[flow.flow_id] = AnonymizationVerdict(
                    flow_id=flow.flow_id, external_ip=flow.external_ip(),
                    label=AnonymizationLabel.UNKNOWN, confidence=0.0,
                    method="none", detail="pas de GNN disponible",
                )

        # retourner dans l'ordre d'entrée
        return [verdicts[f.flow_id] for f in flows]

    # -------------------------------------------------------------------------
    def _run_gnn(self, flows: list[NetworkFlow]) -> dict[str, AnonymizationVerdict]:
        graph = self.builder.build(flows, normalize=True)
        edge_index, edge_feat, _ = graph_to_tensors(graph, self.device)

        self.gnn.eval()
        with torch.no_grad():
            logits = self.gnn(edge_index, edge_feat, graph.n_nodes)
            probs = torch.softmax(logits, dim=1).cpu().numpy()
        preds = probs.argmax(axis=1)

        # filet Anomal-E (optionnel)
        anomale_flags = None
        if self.config.use_anomale_safety_net and self.anomale is not None:
            anomale_flags = self.anomale.predict_anomaly(graph, self.device)

        result: dict[str, AnonymizationVerdict] = {}
        for i, flow in enumerate(flows):
            label = _INT_TO_LABEL.get(int(preds[i]), AnonymizationLabel.UNKNOWN)
            conf = float(probs[i, preds[i]])
            detail = "classé par E-GraphSAGE"
            method = "gnn_supervised"

            # filet : E-GraphSAGE dit normal mais Anomal-E dit anormal
            if anomale_flags is not None and label == AnonymizationLabel.NORMAL and anomale_flags[i]:
                detail = "E-GraphSAGE=normal mais Anomal-E=anormal → anonymisation inconnue possible"
                method = "gnn_supervised+anomale_flag"

            result[flow.flow_id] = AnonymizationVerdict(
                flow_id=flow.flow_id, external_ip=flow.external_ip(),
                label=label, confidence=conf, method=method, detail=detail,
            )
        return result

    # -------------------------------------------------------------------------
    def summarize(self, verdicts: list[AnonymizationVerdict]) -> dict:
        by_label: dict[str, int] = {}
        by_method: dict[str, int] = {}
        for v in verdicts:
            by_label[v.label.value] = by_label.get(v.label.value, 0) + 1
            by_method[v.method] = by_method.get(v.method, 0) + 1
        return {"total": len(verdicts), "by_label": by_label, "by_method": by_method}
