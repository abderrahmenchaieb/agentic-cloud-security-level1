"""
=============================================================================
TEST D'INTÉGRATION DU SYSTÈME COMPLET — les 4 agents chaînés bout à bout
=============================================================================
Scénario : une attaque réelle traverse toute la chaîne.
  Word → PowerShell encodé → C2 (via une IP Tor) → svchost → reconnaissance,
  + falsification de logs (l'attaquant efface ses traces).

Flux testé :
  Sysmon bruts → [COLLECT] → enriched + flows + gaps
       enriched → [ANALYSIS] → ThreatVerdict (menace + techniques + artefacts)
       flows    → [ANONYMIZATION] → AnonymizationVerdict (Tor ?)
       tout     → [DECISION] → décision + actions + dossier Niveau 2
=============================================================================
"""
import os
import sys
from datetime import datetime, timezone, timedelta

# --- rendre les 4 agents importables ---
BASE = os.environ.get("REPO_ROOT", ".") + "/agents"
for agent_dir in ["1_collect_agent", "2_analysis_agent",
                  "3_anonymization_detection_agent", "4_decision_agent"]:
    sys.path.insert(0, f"{BASE}/{agent_dir}")

print("="*76)
print("TEST D'INTÉGRATION — SYSTÈME COMPLET (4 agents chaînés)")
print("="*76)

# =========================================================================
# ÉTAPE 0 : générer des logs Sysmon bruts (le scénario d'attaque)
# =========================================================================
now = datetime.now(timezone.utc)
base = now.strftime("%Y-%m-%d %H:%M")

# une IP Tor connue (pour que l'anonymization la détecte par lookup)
TOR_IP = "185.220.101.47"

sysmon_logs = [
    # Word ouvre un document
    {"EventID":1,"UtcTime":f"{base}:00.100","Computer":"VM-01","ProcessGuid":"{P-word}",
     "ProcessId":"1000","Image":"winword.exe","CommandLine":"winword.exe invoice.docx",
     "ParentProcessGuid":"{P-explorer}","ParentImage":"explorer.exe","RecordNumber":"500"},
    # Word lance PowerShell encodé
    {"EventID":1,"UtcTime":f"{base}:02.200","Computer":"VM-01","ProcessGuid":"{P-ps}",
     "ProcessId":"2000","Image":"powershell.exe",
     "CommandLine":"powershell.exe -nop -w hidden -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAA==",
     "ParentProcessGuid":"{P-word}","ParentImage":"winword.exe","RecordNumber":"501"},
    # PowerShell se connecte au C2 (IP Tor)
    {"EventID":3,"UtcTime":f"{base}:03.500","Computer":"VM-01","ProcessGuid":"{P-ps}",
     "Image":"powershell.exe","SourceIp":"10.0.0.5","DestinationIp":TOR_IP,
     "DestinationPort":"443","Protocol":"tcp","RecordNumber":"502"},
    # svchost (masquerading) lancé par PowerShell
    {"EventID":1,"UtcTime":f"{base}:05.000","Computer":"VM-01","ProcessGuid":"{P-svc}",
     "ProcessId":"3000","Image":"svchost.exe","CommandLine":"svchost.exe",
     "ParentProcessGuid":"{P-ps}","ParentImage":"powershell.exe","RecordNumber":"503"},
    # reconnaissance : whoami
    {"EventID":1,"UtcTime":f"{base}:07.000","Computer":"VM-01","ProcessGuid":"{P-who}",
     "ProcessId":"4000","Image":"whoami.exe","CommandLine":"whoami /priv",
     "ParentProcessGuid":"{P-svc}","ParentImage":"svchost.exe","RecordNumber":"504"},
    # reconnaissance : net group (SAUT de RecordNumber 504→508 = gap = logs supprimés)
    {"EventID":1,"UtcTime":f"{base}:09.000","Computer":"VM-01","ProcessGuid":"{P-net}",
     "ProcessId":"5000","Image":"net.exe","CommandLine":"net group \"Domain Admins\" /domain",
     "ParentProcessGuid":"{P-svc}","ParentImage":"svchost.exe","RecordNumber":"508"},
    # un log FALSIFIÉ : timestamp stompé à 1970 (l'attaquant modifie un log)
    {"EventID":1,"UtcTime":"1970-01-01 00:00:00.000","Computer":"VM-01","ProcessGuid":"{P-evil}",
     "Image":"evil.exe","ParentProcessGuid":"{P-svc}","RecordNumber":"509"},
    # du bruit normal (navigateur)
    {"EventID":1,"UtcTime":f"{base}:04.000","Computer":"VM-01","ProcessGuid":"{P-chrome}",
     "ProcessId":"6000","Image":"chrome.exe","CommandLine":"chrome.exe",
     "ParentProcessGuid":"{P-explorer}","ParentImage":"explorer.exe","RecordNumber":"505"},
]
print(f"\n[0] {len(sysmon_logs)} logs Sysmon bruts générés (attaque + falsif + bruit)")

# =========================================================================
# ÉTAPE 1 : COLLECT AGENT
# =========================================================================
from collect_agent import CollectAgent
collect = CollectAgent()
collect_out = collect.process_batch(sysmon_logs)

print(f"\n[1] COLLECT AGENT")
print(f"    stats: {collect.stats}")
print(f"    sorties: {collect_out.summary()}")
print(f"    → {len(collect_out.enriched)} logs enriched, {len(collect_out.flows)} flows, "
      f"{len(collect_out.gaps)} gaps, {len(collect_out.rejected)} rejetés")
# montrer les falsifications détectées
falsif = [(e.log.event_id, a.detail) for e in collect_out.enriched
          for a in e.annotations if a.kind=="tampering_rule"]
if falsif:
    print(f"    falsifications détectées: {len(falsif)}")
if collect_out.gaps:
    print(f"    gaps détectés: {[g.detail for g in collect_out.gaps]}")

print("\n[OK ÉTAPE 1] Le Collect Agent a produit enriched + flows + gaps.")

# =========================================================================
# CÂBLAGE 1→2 : enriched (Collect) → Event (Analysis)
# =========================================================================
from analysis_agent import Event as AnalysisEvent, EventCategory

def enriched_to_analysis_events(enriched_logs):
    """Convertit les logs enriched du Collect en Event pour l'Analysis Agent."""
    cat_map = {
        "process": EventCategory.PROCESS,
        "network_connection": EventCategory.NETWORK,
        "file": EventCategory.FILE,
        "registry": EventCategory.REGISTRY,
        "module_load": EventCategory.MODULE_LOAD,
        "process_access": EventCategory.PROCESS_ACCESS,
    }
    events = []
    for e in enriched_logs:
        log = e.log
        pc = log.process_context
        events.append(AnalysisEvent(
            event_id=str(log.event_id),
            event_time=log.event_time,
            category=cat_map.get(log.activity.value, EventCategory.OTHER),
            host=log.host,
            process_guid=pc.process_guid if pc else None,
            parent_process_guid=pc.parent_process_guid if pc else None,
            process_name=pc.process_name if pc else None,
            command_line=pc.command_line if pc else None,
            destination_ip=log.target.destination_ip if log.target else None,
            destination_port=log.target.destination_port if log.target else None,
            # hériter les flags d'intégrité (falsification) du Collect
            integrity_flags=[a.detail for a in e.annotations if a.kind=="tampering_rule"],
        ))
    return events

analysis_events = enriched_to_analysis_events(collect_out.enriched)
print(f"\n[CÂBLAGE 1→2] {len(collect_out.enriched)} enriched → {len(analysis_events)} Event pour Analysis")

# =========================================================================
# ÉTAPE 2 : ANALYSIS AGENT
# =========================================================================
from analysis_agent import (SequenceDetector, SequenceBuilder, MitreRAG,
    InterpretationEngine, AnalysisAgent, Sequence)
from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES

# entraîner rapidement le détecteur (en prod : Windows-APT 2025)
import random
rng = random.Random(0)
def _mk(eid,sec,cat,guid,pguid,pname,cmd=None,dst=None):
    from datetime import datetime as dt, timezone as tz, timedelta as td
    T0 = dt(2025,1,1,tzinfo=tz.utc)
    return AnalysisEvent(eid,T0+td(seconds=sec),cat,"VM-01",process_guid=guid,
        parent_process_guid=pguid,process_name=pname,command_line=cmd,destination_ip=dst)
def _atk(i):
    b=rng.randint(0,900)
    return Sequence(f"a{i}",[_mk(f"a{i}1",b,EventCategory.PROCESS,f"{{A{i}1}}","{r}","winword.exe","winword.exe d.docx"),
        _mk(f"a{i}2",b+2,EventCategory.PROCESS,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe","powershell -enc "+"Q"*40),
        _mk(f"a{i}3",b+3,EventCategory.NETWORK,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe",dst="1.2.3.4"),
        _mk(f"a{i}4",b+6,EventCategory.PROCESS,f"{{A{i}3}}",f"{{A{i}2}}","whoami.exe","whoami /priv")])
def _nrm(i):
    b=rng.randint(0,900)
    return Sequence(f"n{i}",[_mk(f"n{i}1",b,EventCategory.PROCESS,f"{{N{i}1}}","{r}","chrome.exe","chrome.exe")])
train=[_atk(i) for i in range(40)]+[_nrm(i) for i in range(160)]
detector = SequenceDetector(recall_threshold=0.3).fit(train,[1]*40+[0]*160)

# RAG + LLM simulé (en prod : Ollama Qwen3/Phi-4)
rag = MitreRAG(); rag.index(SAMPLE_TECHNIQUES)
class SimLLM:
    def generate(self, prompt):
        return '''```json
{"hypothesis":"Document piégé a lancé un PowerShell encodé vers un C2 externe, puis reconnaissance de privilèges et de groupes de domaine via un processus masqué.",
 "techniques":[{"technique_id":"T1059.001","confidence":"high"},
               {"technique_id":"T1071.001","confidence":"medium"},
               {"technique_id":"T1033","confidence":"high"},
               {"technique_id":"T1069.002","confidence":"high"},
               {"technique_id":"T1036.005","confidence":"medium"}]}
```'''
analysis = AnalysisAgent(detector=detector,
    interpreter=InterpretationEngine(SimLLM(), rag), builder=SequenceBuilder())

analysis_out = analysis.analyze(analysis_events)
print(f"\n[2] ANALYSIS AGENT")
print(f"    stats: {analysis_out.stats}")
threats = analysis_out.attacks()
for t in threats:
    print(f"    MENACE sur {t.host}: score={t.attack_score:.2f}")
    print(f"      hypothèse: {t.hypothesis[:80]}...")
    print(f"      techniques: {[tech.technique_id for tech in t.techniques]}")
    print(f"      artefacts observés: {t.observed_artifacts}")
    print(f"      flags d'intégrité hérités: {len(t.integrity_flags)} (falsification vue par Collect)")
print("\n[OK ÉTAPE 2] L'Analysis Agent a produit des ThreatVerdict avec artefacts.")

# =========================================================================
# CÂBLAGE 1→3 : flows (Collect) → NetworkFlow (Anonymization)
# =========================================================================
from anonymization_detection_agent import (NetworkFlow, FlowFeatures,
    AnonymizationLabel, LookupEngine, TorExitList, VpnRangeDb,
    AnonymizationDetectionAgent)

def flows_to_network_flows(flow_records):
    """Convertit les FlowRecord du Collect en NetworkFlow pour l'Anonymization Agent."""
    nfs = []
    for i, f in enumerate(flow_records):
        nfs.append(NetworkFlow(
            flow_id=f"flow-{i}-{f.event_id}",
            src_ip=f.source_ip or "0.0.0.0",
            dst_ip=f.destination_ip or "0.0.0.0",
            dst_port=f.destination_port,
            protocol=f.protocol,
            timestamp=f.event_time,
            features=FlowFeatures(),  # features CICFlowMeter vides ici (lookup suffit pour Tor)
        ))
    return nfs

network_flows = flows_to_network_flows(collect_out.flows)
print(f"\n[CÂBLAGE 1→3] {len(collect_out.flows)} flows → {len(network_flows)} NetworkFlow pour Anonymization")
for nf in network_flows:
    print(f"    flow: {nf.src_ip} → {nf.dst_ip}:{nf.dst_port}")

# =========================================================================
# ÉTAPE 3 : ANONYMIZATION DETECTION AGENT
# =========================================================================
# charger l'IP Tor de l'attaque dans la liste Tor (en prod : vraie liste Tor mise à jour)
tor_list = TorExitList()
tor_list.add(TOR_IP)
lookup = LookupEngine(tor_list=tor_list, vpn_db=VpnRangeDb())

# mode lookup seul (pas de GNN) : suffit pour l'IP Tor connue
anon_agent = AnonymizationDetectionAgent(lookup=lookup)
anon_verdicts = anon_agent.analyze_batch(network_flows)

print(f"\n[3] ANONYMIZATION DETECTION AGENT")
print(f"    résumé: {anon_agent.summarize(anon_verdicts)}")
for v in anon_verdicts:
    print(f"    flow {v.flow_id}: {v.label.value.upper()} (confiance {v.confidence:.2f}, méthode {v.method})")
    print(f"      IP: {v.external_ip} — {v.detail}")
print("\n[OK ÉTAPE 3] L'Anonymization Agent a détecté l'anonymisation.")

# =========================================================================
# CÂBLAGE 2+3+1→4 : tout converge vers le Decision Agent
# =========================================================================
from decision_agent import (DecisionAgent, ActionGenerator, DefenseKnowledgeBase)

# Le Decision Agent reçoit :
#   - les ThreatVerdict de l'Analysis (menace + techniques + artefacts)
#   - les AnonymizationVerdict de l'Anonymization (Tor)
#   - les integrity_flags du Collect (falsification — car le sequence builder
#     a isolé le log evil.exe, la falsification transite ici directement)

# extraire les falsifications du Collect en (host, detail)
integrity_flags = []
for e in collect_out.enriched:
    for a in e.annotations:
        if a.kind == "tampering_rule":
            integrity_flags.append((e.log.host, a.detail))
# ajouter les gaps comme signaux d'intégrité aussi
for g in collect_out.gaps:
    # le gap porte un host via source_key (ex "VM-01:sysmon")
    host = g.source_key.split(":")[0] if hasattr(g, "source_key") and ":" in g.source_key else "VM-01"

print(f"\n[CÂBLAGE →4] Decision reçoit:")
print(f"    {len(threats)} menace(s) (Analysis)")
print(f"    {len(anon_verdicts)} verdict(s) anonymisation (Anonymization)")
print(f"    {len(integrity_flags)} flag(s) de falsification (Collect)")

# LLM simulé pour le générateur d'actions (en prod : Ollama)
class DecisionLLM:
    def generate(self, prompt):
        return '''```json
{"summary":"Attaque PowerShell/C2 confirmée sur VM-01 avec effacement de traces. Contenir immédiatement la connexion sortante et le processus.",
 "actions":[
   {"action_id":"D3-OTF","priority":"immediate","reason":"Bloquer le trafic C2 sortant vers l'IP Tor"},
   {"action_id":"D3-NTA","priority":"high","reason":"Analyser le trafic réseau du processus"},
   {"action_id":"D3-PSEP","priority":"high","reason":"Analyser le processus PowerShell/svchost suspect"}
 ]}
```'''

decision = DecisionAgent(
    action_generator=ActionGenerator(DecisionLLM(), DefenseKnowledgeBase())
)

decision_out = decision.decide(
    threat_verdicts=threats,
    anon_verdicts=anon_verdicts,
    integrity_flags=integrity_flags,
)

print(f"\n[4] DECISION AGENT")
print(f"    stats: {decision_out.stats}")
for o in decision_out.outcomes:
    d = o.decision
    print(f"\n    ENTITÉ host={d.host}:")
    print(f"      CERTITUDE: {d.certainty.value.upper()}  |  ESCALADE: {d.escalate}"
          + (f" → {d.mission.value}" if d.escalate else ""))
    print(f"      règles déclenchées: {d.triggered_rules}")
    print(f"      rationale: {d.rationale}")
    if o.action_plan:
        print(f"      ACTIONS PROPOSÉES À L'UTILISATEUR:")
        print(f"        « {o.action_plan.summary} »")
        for a in o.action_plan.actions:
            print(f"        [{a.priority:9}] {a.action_id} — {a.name}")
    if o.level2_dossier:
        dos = o.level2_dossier
        print(f"      DOSSIER NIVEAU 2 (mission: {dos.mission}):")
        print(f"        IPs anonymisées à percer: {dos.anonymized_ips} ({dos.anonymization_types})")
        print(f"        contexte falsification: {dos.integrity_context}")
        print(f"        calculs demandés: {dos.requested_computations}")

print("\n[OK ÉTAPE 4] Le Decision Agent a décidé de bout en bout.")

# =========================================================================
# VÉRIFICATIONS FINALES DU SYSTÈME COMPLET
# =========================================================================
print("\n" + "="*76)
print("VÉRIFICATIONS DU SYSTÈME COMPLET (bout en bout)")
print("="*76)
vm01 = next((o for o in decision_out.outcomes if o.decision.host=="VM-01"), None)
checks = [
    ("[1 Collect] falsification détectée", len(falsif) > 0),
    ("[1 Collect] gap détecté (logs supprimés)", len(collect_out.gaps) > 0),
    ("[1 Collect] flux réseau extrait", len(collect_out.flows) > 0),
    ("[2 Analysis] menace détectée sur VM-01", any(t.host=="VM-01" for t in threats)),
    ("[2 Analysis] techniques MITRE attribuées", len(threats)>0 and len(threats[0].techniques)>0),
    ("[2 Analysis] artefacts observés exposés", len(threats)>0 and len(threats[0].observed_artifacts)>0),
    ("[3 Anon] IP Tor détectée", any(v.label.value=="tor" for v in anon_verdicts)),
    ("[4 Decision] attaque CONFIRMÉE", vm01 and vm01.decision.certainty.value=="confirmed"),
    ("[4 Decision] actions générées (contenir)", vm01 and vm01.action_plan and len(vm01.action_plan.actions)>0),
    ("[4 Decision] escalade GÉOLOC (percer le Tor)", vm01 and vm01.decision.escalate and vm01.level2_dossier),
    ("[4 Decision] IP Tor transmise au Niveau 2", vm01 and vm01.level2_dossier and TOR_IP in vm01.level2_dossier.anonymized_ips),
    ("[4 Decision] contexte falsification dans le dossier", vm01 and vm01.level2_dossier and len(vm01.level2_dossier.integrity_context)>0),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")

print("\n" + "="*76)
if all_ok:
    print("  ✓✓✓  SYSTÈME COMPLET VALIDÉ — les 4 agents fonctionnent CHAÎNÉS  ✓✓✓")
else:
    print("  ✗  DES ÉCHECS À CORRIGER")
print("="*76)
