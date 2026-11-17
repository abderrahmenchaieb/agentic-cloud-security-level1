"""Boucle fermée corrigée : corpus intègre réaliste (racine sans self-parent)."""
from datetime import datetime, timezone, timedelta
from collect_agent.canonical_schema import CanonicalLog, SourceType, ActivityCategory, Outcome, ProcessContext
from collect_agent.falsification_generator import FalsificationGenerator, FalsificationType
from collect_agent.forensic_rules import ForensicRuleEngine

T0 = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

def build_clean_corpus(n=50):
    corpus = []
    for i in range(n):
        # le processus racine (i=0) a un parent DIFFERENT (pas self-parent)
        parent = f"{{guid-root}}" if i == 0 else f"{{guid-{i-1:03d}}}"
        corpus.append(CanonicalLog(
            source_type=SourceType.ENDPOINT, source_provider="sysmon",
            event_time=T0 + timedelta(seconds=i * 2),
            ingest_time=T0 + timedelta(seconds=i * 2 + 1),
            activity=ActivityCategory.PROCESS, action_name="ProcessCreate",
            outcome=Outcome.SUCCESS, host="VM-01",
            process_context=ProcessContext(
                process_guid=f"{{guid-{i:03d}}}",
                parent_process_guid=parent,
                process_name="proc.exe"),
            extra={"seq": i},
        ))
    return corpus

corpus = build_clean_corpus(50)

# Contrôle : corpus intègre = 0 détection
engine_check = ForensicRuleEngine()
fp = sum(1 for log in corpus if engine_check.analyze(log))
print(f"Corpus intègre (50 logs) : {fp} détection sur logs sains -> {'OK PROPRE' if fp == 0 else 'ECHEC'}")

# Boucle fermée sur plusieurs ratios
print("\n" + "=" * 62)
print("ÉVALUATION multi-ratios (rappel des règles forensiques)")
print("=" * 62)
print(f"{'Ratio':<8}{'Modif':<14}{'Reorder':<14}{'Inject':<14}{'Global'}")
print("-" * 62)

for ratio in [0.05, 0.10, 0.20, 0.30]:
    gen = FalsificationGenerator(seed=7)
    ds = gen.generate(corpus, ratio=ratio)

    engine = ForensicRuleEngine()
    detected_ids = {log.event_id for log in ds.logs if engine.analyze(log)}

    # compter détectés par type
    total = {"modification": 0, "reordering": 0, "injection": 0}
    detect = {"modification": 0, "reordering": 0, "injection": 0}
    for gt in ds.ground_truth:
        t = gt.falsification_type.value
        if t in total:
            total[t] += 1
            if gt.falsification_type == FalsificationType.INJECTION:
                # id injecté present dans le corpus falsifié
                inj_detected = any(l.event_id.startswith("INJECTED") and l.event_id in detected_ids
                                   for l in ds.logs)
            else:
                eid = corpus[gt.original_index].event_id
                if eid in detected_ids:
                    detect[t] += 1
    # recompter injection proprement
    detect["injection"] = sum(1 for l in ds.logs
                              if l.event_id.startswith("INJECTED") and l.event_id in detected_ids)

    def rate(t):
        return f"{detect[t]}/{total[t]}" + (f" ({detect[t]/total[t]*100:.0f}%)" if total[t] else " (-)")
    global_total = sum(total.values())
    global_det = sum(detect.values())
    grate = f"{global_det/global_total*100:.0f}%" if global_total else "-"
    print(f"{ratio*100:<8.0f}{rate('modification'):<14}{rate('reordering'):<14}{rate('injection'):<14}{grate}")

print("\n[OK] Boucle fermée validée : générer -> détecter -> mesurer.")
print("La vérité terrain est parfaite (auto-générée), donc le rappel est mesurable sans ambiguïté.")
