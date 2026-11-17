"""Test des features cloud sur des séquences réalistes (inspirées d'Invictus)."""
import sys
sys.path.insert(0, "/home/claude/cloud_features")
from cloud_sequence_features import extract_cloud_features, FEATURE_NAMES

# Mini-objets imitant Event et Sequence (pour tester sans toute la stack)
class Event:
    def __init__(self, action, service, outcome="success"):
        self.process_name = action
        self.extra = {"cloud_service": service, "outcome": outcome}
class Sequence:
    def __init__(self, events, duration=60.0, integrity=False):
        self.events = events
        self.duration_seconds = duration
        self._integ = integrity
    def integrity_flags(self):
        return ["gap"] if self._integ else []

print("="*72)
print("TEST — Features cloud (CloudTrail)")
print("="*72)

# --- Séquence ATTAQUE (inspirée d'Invictus : recon → vol secrets → persistance → évasion)
attaque = Sequence([
    Event("GetCallerIdentity", "sts"),           # recon
    Event("ListSecrets", "secretsmanager"),      # recon
    Event("DescribeParameters", "ssm"),          # recon
    Event("GetSecretValue", "secretsmanager"),   # credential access
    Event("GetSecretValue", "secretsmanager"),   # credential access
    Event("GetPasswordData", "ec2"),             # credential access
    Event("Decrypt", "kms"),                     # credential access
    Event("AttachUserPolicy", "iam"),            # privilege escalation
    Event("CreateAccessKey", "iam"),             # persistence
    Event("StopLogging", "cloudtrail"),          # defense evasion !
    Event("PutUserPolicy", "iam", outcome="AccessDenied"),  # tâtonnement
], duration=45.0)

# --- Séquence BÉNIGNE (Terraform monte de l'infra : surtout des Describe/lecture)
benigne = Sequence([
    Event("DescribeInstances", "ec2"),
    Event("DescribeNatGateways", "ec2"),
    Event("DescribeVpcs", "ec2"),
    Event("ListTagsForResource", "ec2"),
    Event("DescribeSecurityGroups", "ec2"),
    Event("GetParameter", "ssm"),                # une lecture de param (légitime)
], duration=120.0)

def afficher(nom, seq):
    feats = extract_cloud_features(seq)
    print(f"\n--- {nom} ---")
    for name, val in zip(FEATURE_NAMES, feats):
        marque = ""
        if name.startswith("has_") and val > 0:
            marque = " ⚠"
        print(f"    {name:26s} = {val:.3f}{marque}")
    return feats

f_att = afficher("ATTAQUE (recon→secrets→escalade→évasion)", attaque)
f_ben = afficher("BÉNIGNE (Terraform infra)", benigne)

print("\n" + "="*72)
print("VÉRIFICATIONS — les features distinguent-elles attaque et bénin ?")
print("="*72)
idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
checks = [
    ("Attaque : credential access détecté", f_att[idx["has_credential_access"]] == 1.0),
    ("Attaque : escalade de privilèges détectée", f_att[idx["has_privilege_escalation"]] == 1.0),
    ("Attaque : persistance détectée", f_att[idx["has_persistence"]] == 1.0),
    ("Attaque : évasion défensive détectée (StopLogging)", f_att[idx["has_defense_evasion"]] == 1.0),
    ("Attaque : erreurs détectées (tâtonnement)", f_att[idx["n_errors"]] > 0),
    ("Attaque : plus de services touchés que bénin",
     f_att[idx["n_distinct_services"]] > f_ben[idx["n_distinct_services"]]),
    ("Bénin : PAS d'évasion défensive", f_ben[idx["has_defense_evasion"]] == 0.0),
    ("Bénin : PAS d'escalade de privilèges", f_ben[idx["has_privilege_escalation"]] == 0.0),
    ("Bénin : ratio de reconnaissance élevé (lecture)", f_ben[idx["recon_ratio"]] > 0.7),
    ("Bénin : profil crédentiel FAIBLE (1 appel, sans escalade/évasion)", f_ben[idx["n_credential_calls"]] < f_att[idx["n_credential_calls"]] and f_ben[idx["has_defense_evasion"]] == 0.0),
]
all_ok = all(ok for _, ok in checks)
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — les features cloud distinguent attaque et bénin' if all_ok else 'ÉCHECS'}")
