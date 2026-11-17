from __future__ import annotations
import math
from .sequence_schema import Sequence, EventCategory


SHELL_PROCS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bash.exe", "pwsh.exe"}
OFFICE_PROCS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
RECON_PROCS = {"whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "ipconfig.exe",
               "nltest.exe", "netstat.exe", "arp.exe", "quser.exe", "tasklist.exe"}
LOLBIN_PROCS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe",
                "bitsadmin.exe", "msbuild.exe", "installutil.exe"}

FEATURE_NAMES = [
    "n_events", "n_unique_processes", "duration_seconds",
    "has_office_to_shell", "has_shell_to_recon", "n_recon_procs", "n_lolbins",
    "max_cmdline_entropy", "max_cmdline_length", "has_encoded_command",
    "has_external_network", "n_external_ips", "has_integrity_flags",
    "process_chain_depth",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_external_ip(ip: str) -> bool:
    return not (ip.startswith("10.") or ip.startswith("192.168.")
                or ip.startswith("172.") or ip.startswith("127."))


def extract_sequence_features(seq: Sequence) -> list[float]:
    procs = [e.process_name.lower() for e in seq.events if e.process_name]
    proc_set = set(procs)
    cmdlines = [e.command_line for e in seq.events if e.command_line]

    has_office_to_shell = 0.0
    has_shell_to_recon = 0.0
    guid_to_name = {e.process_guid: (e.process_name or "").lower()
                    for e in seq.events if e.process_guid}
    for e in seq.events:
        child = (e.process_name or "").lower()
        parent = guid_to_name.get(e.parent_process_guid, "")
        if parent in OFFICE_PROCS and child in SHELL_PROCS:
            has_office_to_shell = 1.0
        if parent in SHELL_PROCS and child in RECON_PROCS:
            has_shell_to_recon = 1.0

    n_recon = sum(1 for p in procs if p in RECON_PROCS)
    n_lolbins = sum(1 for p in procs if p in LOLBIN_PROCS)
    max_entropy = max((_entropy(c) for c in cmdlines), default=0.0)
    max_len = max((len(c) for c in cmdlines), default=0)
    has_encoded = 1.0 if any(
        ("-enc" in c.lower() or "-e " in c.lower() or "frombase64" in c.lower()
         or "base64" in c.lower()) for c in cmdlines) else 0.0
    ext_ips = [ip for ip in seq.external_ips() if _is_external_ip(ip)]
    has_external = 1.0 if ext_ips else 0.0
    has_integrity = 1.0 if seq.integrity_flags() else 0.0
    depth = _chain_depth(seq)

    return [
        float(seq.n_events), float(len(proc_set)), float(seq.duration_seconds),
        has_office_to_shell, has_shell_to_recon, float(n_recon), float(n_lolbins),
        float(max_entropy), float(max_len), has_encoded,
        has_external, float(len(ext_ips)), has_integrity, float(depth),
    ]


def _chain_depth(seq: Sequence) -> int:
    children: dict[str, list[str]] = {}
    guids = {e.process_guid for e in seq.events if e.process_guid}
    for e in seq.events:
        if e.process_guid and e.parent_process_guid in guids:
            children.setdefault(e.parent_process_guid, []).append(e.process_guid)

    def depth_from(guid: str, seen: set) -> int:
        if guid in seen:
            return 0
        seen.add(guid)
        kids = children.get(guid, [])
        return 1 + max((depth_from(k, seen) for k in kids), default=0)

    roots = [g for g in guids if all(g not in v for v in children.values())]
    return max((depth_from(r, set()) for r in roots), default=1)


def extract_matrix(sequences: list[Sequence]) -> list[list[float]]:
    return [extract_sequence_features(s) for s in sequences]
