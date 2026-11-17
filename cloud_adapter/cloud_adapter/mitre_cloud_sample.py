"""
Échantillon de techniques MITRE ATT&CK for CLOUD (matrice IaaS/Cloud).

Utilisé par le RAG de l'Analysis Agent quand la source est le plan de contrôle
cloud (CloudTrail), à la place de l'échantillon Windows (mitre_sample.py).

En production : remplacer par la matrice MITRE ATT&CK for Cloud complète
(enterprise-attack, plateforme IaaS/SaaS), chargée depuis le STIX officiel.

Les techniques ci-dessous sont celles réellement observables dans CloudTrail
et couvrent les tactiques d'une compromission cloud typique :
Initial Access → Discovery → Privilege Escalation → Persistence →
Defense Evasion → Collection → Exfiltration → Impact.

IMPORTANT (même discipline que le RAG Windows) :
  - le RAG ne fait que RÉCUPÉRER des techniques candidates réelles ;
  - le LLM choisit parmi elles (il n'invente pas) ;
  - le parsing filtre tout ID hors de cette base (anti-hallucination).
"""
from analysis_agent.mitre_rag import MitreTechnique


SAMPLE_CLOUD_TECHNIQUES = [
    # --- Initial Access ---
    MitreTechnique("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access",
        "Adversaries obtain and abuse credentials of cloud accounts to gain access, "
        "often via stolen access keys.",
        ["stolen credentials", "access key", "cloud account", "compromised key",
         "GetCallerIdentity", "valid accounts"]),
    MitreTechnique("T1190", "Exploit Public-Facing Application", "Initial Access",
        "Adversaries exploit a weakness in an internet-facing host or application to "
        "gain initial access to the cloud environment.",
        ["exploit", "public facing", "web application", "vulnerability"]),

    # --- Discovery ---
    MitreTechnique("T1580", "Cloud Infrastructure Discovery", "Discovery",
        "Adversaries enumerate cloud infrastructure such as instances, storage, and "
        "compute resources to map the environment.",
        ["DescribeInstances", "ListBuckets", "discovery", "enumeration",
         "infrastructure", "ec2 describe"]),
    MitreTechnique("T1087.004", "Account Discovery: Cloud Account", "Discovery",
        "Adversaries enumerate cloud accounts, users and roles to find targets for "
        "escalation.",
        ["ListUsers", "ListRoles", "GetAccountAuthorizationDetails", "account discovery",
         "iam enumeration", "who am i"]),
    MitreTechnique("T1069.003", "Permission Groups Discovery: Cloud Groups", "Discovery",
        "Adversaries enumerate cloud groups and their permissions to find privileged access.",
        ["ListGroups", "permission groups", "cloud groups", "policy discovery"]),

    # --- Privilege Escalation ---
    MitreTechnique("T1098.001", "Account Manipulation: Additional Cloud Credentials",
        "Privilege Escalation",
        "Adversaries add credentials (access keys, login profiles) to a cloud account "
        "to maintain or escalate access.",
        ["CreateAccessKey", "CreateLoginProfile", "add credentials", "access key",
         "account manipulation"]),
    MitreTechnique("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
        "Privilege Escalation",
        "Adversaries abuse IAM policies or role assumption to elevate privileges, e.g. "
        "attaching an administrator policy to a controlled user.",
        ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "AdministratorAccess",
         "privilege escalation", "iam policy", "assume role"]),

    # --- Persistence ---
    MitreTechnique("T1136.003", "Create Account: Cloud Account", "Persistence",
        "Adversaries create new cloud accounts or IAM users to maintain persistent access.",
        ["CreateUser", "CreateRole", "create account", "persistence", "backdoor account"]),

    # --- Defense Evasion ---
    MitreTechnique("T1562.008", "Impair Defenses: Disable Cloud Logs", "Defense Evasion",
        "Adversaries disable or delete cloud logging (e.g. CloudTrail) to evade detection "
        "and cover their tracks.",
        ["StopLogging", "DeleteTrail", "UpdateTrail", "disable logging", "cloudtrail",
         "impair defenses", "anti-forensics", "cover tracks"]),

    # --- Collection / Exfiltration ---
    MitreTechnique("T1530", "Data from Cloud Storage", "Collection",
        "Adversaries access data objects from cloud storage such as S3 buckets, often "
        "sensitive data.",
        ["GetObject", "s3", "bucket", "cloud storage", "data collection", "download object"]),
    MitreTechnique("T1537", "Transfer Data to Cloud Account", "Exfiltration",
        "Adversaries exfiltrate data by transferring it to another cloud account they control, "
        "e.g. sharing a snapshot or bucket.",
        ["ModifySnapshotAttribute", "share snapshot", "PutBucketPolicy", "exfiltration",
         "transfer to account", "cross-account"]),

    # --- Impact ---
    MitreTechnique("T1485", "Data Destruction", "Impact",
        "Adversaries delete cloud resources or data to disrupt operations.",
        ["DeleteBucket", "TerminateInstances", "DeleteDBInstance", "destruction",
         "delete resource", "impact"]),
    MitreTechnique("T1496", "Resource Hijacking", "Impact",
        "Adversaries hijack cloud compute resources (e.g. launching instances for crypto "
        "mining).",
        ["RunInstances", "resource hijacking", "cryptomining", "compute abuse"]),
]
