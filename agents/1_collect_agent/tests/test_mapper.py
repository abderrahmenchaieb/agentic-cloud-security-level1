"""Test du mapper Sysmon : cas valides + détection de malformés."""
from collect_agent.sysmon_mapper import map_sysmon_event

# ============ CAS VALIDES ============
valides = {
    "EID 1 - ProcessCreate (PowerShell encode)": {
        "EventID": 1, "UtcTime": "2025-01-15 10:02:19.123", "Computer": "VM-WIN-01",
        "ProcessGuid": "{a1b2-0001}", "ProcessId": "3400", "Image": "C:\\Windows\\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA...", "User": "CORP\\jdoe", "LogonId": "0x3E7",
        "ParentProcessGuid": "{a1b2-0000}", "ParentProcessId": "1200", "ParentImage": "winword.exe",
        "IntegrityLevel": "Medium", "RecordNumber": "50123",
    },
    "EID 3 - NetworkConnect (vers IP externe)": {
        "EventID": 3, "UtcTime": "2025-01-15 10:02:20.456", "Computer": "VM-WIN-01",
        "ProcessGuid": "{a1b2-0001}", "ProcessId": "3400", "Image": "powershell.exe",
        "SourceIp": "10.0.0.5", "DestinationIp": "185.220.101.47", "DestinationPort": "443",
        "Protocol": "tcp", "RecordNumber": "50124",
    },
    "EID 10 - ProcessAccess (injection potentielle)": {
        "EventID": 10, "UtcTime": "2025-01-15 10:02:25.789", "Computer": "VM-WIN-01",
        "ProcessGuid": "{a1b2-0009}", "ProcessId": "5600", "Image": "svchost.exe",
        "TargetImage": "lsass.exe", "TargetProcessGuid": "{a1b2-0002}", "RecordNumber": "50130",
    },
}

# ============ CAS MALFORMÉS ============
malformes = {
    "Champ obligatoire manquant (Computer absent)": {
        "EventID": 1, "UtcTime": "2025-01-15 10:02:19.123", "Image": "cmd.exe",
    },
    "UtcTime invalide": {
        "EventID": 1, "UtcTime": "pas-une-date", "Computer": "VM-WIN-01",
    },
    "EventID non supporte (99)": {
        "EventID": 99, "UtcTime": "2025-01-15 10:02:19.123", "Computer": "VM-WIN-01",
    },
    "EventID non numerique": {
        "EventID": "abc", "UtcTime": "2025-01-15 10:02:19.123", "Computer": "VM-WIN-01",
    },
    "Champ vide (UtcTime vide)": {
        "EventID": 1, "UtcTime": "", "Computer": "VM-WIN-01",
    },
}

print("=" * 60)
print("CAS VALIDES (doivent etre acceptes)")
print("=" * 60)
for nom, raw in valides.items():
    r = map_sysmon_event(raw)
    status = "OK ACCEPTE" if r.is_valid else f"REJETE ({r.rejection_reason})"
    print(f"\n[{status}] {nom}")
    if r.is_valid:
        log = r.log
        print(f"   activity     : {log.activity.value}")
        print(f"   action       : {log.action_name}")
        print(f"   process_guid : {log.process_context.process_guid}")
        if log.target.destination_ip:
            print(f"   dest_ip      : {log.target.destination_ip}:{log.target.destination_port} -> Geolocation")
        if log.process_context.parent_process_guid:
            print(f"   filiation    : {log.process_context.parent_process_guid} -> {log.process_context.process_guid}")

print("\n" + "=" * 60)
print("CAS MALFORMES (doivent etre rejetes = detection d'integrite)")
print("=" * 60)
for nom, raw in malformes.items():
    r = map_sysmon_event(raw)
    status = "OK REJETE" if not r.is_valid else "PROBLEME: accepte a tort!"
    print(f"[{status}] {nom}")
    if not r.is_valid:
        print(f"          motif -> {r.rejection_reason}")

# Bilan
n_val_ok = sum(1 for raw in valides.values() if map_sysmon_event(raw).is_valid)
n_mal_ok = sum(1 for raw in malformes.values() if not map_sysmon_event(raw).is_valid)
print("\n" + "=" * 60)
print(f"BILAN : {n_val_ok}/{len(valides)} valides acceptes | {n_mal_ok}/{len(malformes)} malformes rejetes")
print("=" * 60)
