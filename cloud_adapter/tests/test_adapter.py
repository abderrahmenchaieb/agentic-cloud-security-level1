"""Test de l'adaptateur cloud sur du CloudTrail au format réel."""
import json
from cloud_adapter import AwsCloudTrailAdapter, CloudAdapterRegistry
from collect_agent.canonical_schema import SourceType, ActivityCategory, Outcome

# ---- échantillon CloudTrail au FORMAT RÉEL (attaque cloud multi-étapes) ----
# scénario : credentials volés → reconnaissance → escalade IAM → exfiltration
#            + tentative d'arrêt du logging (défense évasion)
cloudtrail = {
    "Records": [
        # 1. l'attaquant vérifie son identité (reconnaissance)
        {"eventVersion":"1.09","eventTime":"2024-03-06T21:22:00Z",
         "eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity",
         "awsRegion":"us-east-1","sourceIPAddress":"185.220.101.47",
         "userAgent":"aws-cli/2.13.5","eventID":"e1",
         "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/stolen",
             "accountId":"999","userName":"stolen","accessKeyId":"AKIA_STOLEN",
             "sessionContext":{"attributes":{"creationDate":"2024-03-06T21:20:00Z","mfaAuthenticated":"false"}}}},
        # 2. énumération des utilisateurs (discovery)
        {"eventVersion":"1.09","eventTime":"2024-03-06T21:22:30Z",
         "eventSource":"iam.amazonaws.com","eventName":"ListUsers",
         "awsRegion":"us-east-1","sourceIPAddress":"185.220.101.47",
         "userAgent":"aws-cli/2.13.5","eventID":"e2",
         "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/stolen",
             "accountId":"999","userName":"stolen","accessKeyId":"AKIA_STOLEN",
             "sessionContext":{"attributes":{"creationDate":"2024-03-06T21:20:00Z"}}}},
        # 3. escalade : s'attacher une policy admin (config change)
        {"eventVersion":"1.09","eventTime":"2024-03-06T21:23:00Z",
         "eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy",
         "awsRegion":"us-east-1","sourceIPAddress":"185.220.101.47",
         "userAgent":"aws-cli/2.13.5","eventID":"e3",
         "requestParameters":{"userName":"stolen","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},
         "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/stolen",
             "accountId":"999","userName":"stolen","accessKeyId":"AKIA_STOLEN",
             "sessionContext":{"attributes":{"creationDate":"2024-03-06T21:20:00Z"}}}},
        # 4. exfiltration : lecture d'un objet S3 sensible
        {"eventVersion":"1.09","eventTime":"2024-03-06T21:24:00Z",
         "eventSource":"s3.amazonaws.com","eventName":"GetObject",
         "awsRegion":"us-east-1","sourceIPAddress":"185.220.101.47",
         "userAgent":"aws-cli/2.13.5","eventID":"e4",
         "requestParameters":{"bucketName":"secret-data","key":"customers.db"},
         "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/stolen",
             "accountId":"999","userName":"stolen","accessKeyId":"AKIA_STOLEN",
             "sessionContext":{"attributes":{"creationDate":"2024-03-06T21:20:00Z"}}}},
        # 5. défense évasion : arrêt du logging CloudTrail (surveillé par Collect)
        {"eventVersion":"1.09","eventTime":"2024-03-06T21:25:00Z",
         "eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging",
         "awsRegion":"us-east-1","sourceIPAddress":"185.220.101.47",
         "userAgent":"aws-cli/2.13.5","eventID":"e5",
         "requestParameters":{"name":"main-trail"},
         "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/stolen",
             "accountId":"999","userName":"stolen","accessKeyId":"AKIA_STOLEN",
             "sessionContext":{"attributes":{"creationDate":"2024-03-06T21:20:00Z"}}}},
        # 6. une action ÉCHOUÉE (errorCode) — signal fort
        {"eventVersion":"1.09","eventTime":"2024-03-06T21:26:00Z",
         "eventSource":"iam.amazonaws.com","eventName":"DeleteUser",
         "awsRegion":"us-east-1","sourceIPAddress":"185.220.101.47",
         "userAgent":"aws-cli/2.13.5","eventID":"e6","errorCode":"AccessDenied",
         "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/stolen",
             "accountId":"999","userName":"stolen","accessKeyId":"AKIA_STOLEN",
             "sessionContext":{"attributes":{"creationDate":"2024-03-06T21:20:00Z"}}}},
    ]
}

print("="*72)
print("TEST — Adaptateur CloudTrail → schéma canonique")
print("="*72)

adapter = AwsCloudTrailAdapter()
logs = adapter.parse(json.dumps(cloudtrail))

print(f"\n{len(cloudtrail['Records'])} événements CloudTrail → {len(logs)} CanonicalLog\n")
for log in logs:
    print(f"  [{log.event_time.strftime('%H:%M:%S')}] {log.action_name:20} "
          f"({log.activity.value:20}) {log.outcome.value}")
    print(f"       acteur={log.actor.user_name} | IP={log.actor.source_ip} | "
          f"session={log.actor.session_id}")
    if log.cloud_context:
        print(f"       cloud: {log.cloud_context.service}/{log.cloud_context.api_call}"
              + (f" → {log.target.name}" if log.target.name else ""))

# --- clé de corrélation cloud : tous ces événements = MÊME session ---
sessions = set(log.actor.session_id for log in logs)
principals = set(log.actor.user_id for log in logs)

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
checks = [
    ("6 événements traduits", len(logs)==6),
    ("Tous en source CLOUD_CONTROL", all(l.source_type==SourceType.CLOUD_CONTROL for l in logs)),
    ("Provider aws_cloudtrail", all(l.source_provider=="aws_cloudtrail" for l in logs)),
    ("IP source préservée (pour Anonymization)",
     all(l.actor.source_ip=="185.220.101.47" for l in logs)),
    ("Clé de corrélation: 1 seule session (remplace ProcessGUID)", len(sessions)==1),
    ("Escalade IAM → CONFIG_CHANGE",
     any(l.action_name=="AttachUserPolicy" and l.activity==ActivityCategory.CONFIG_CHANGE for l in logs)),
    ("Exfiltration S3 → FILE avec cible",
     any(l.action_name=="GetObject" and l.target.name=="secret-data" for l in logs)),
    ("StopLogging capturé (défense évasion → Collect)",
     any(l.action_name=="StopLogging" for l in logs)),
    ("Action échouée → outcome FAILURE",
     any(l.action_name=="DeleteUser" and l.outcome==Outcome.FAILURE for l in logs)),
    ("api_call cloud renseigné",
     all(l.cloud_context and l.cloud_context.api_call for l in logs)),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")

# registre multi-cloud
reg = CloudAdapterRegistry()
print(f"\n  Registre d'adaptateurs: {reg.providers()} (extensible: Azure/GCP)")
print(f"\n{'TOUS OK — adaptateur cloud fonctionne' if all_ok else 'ÉCHECS'}")
