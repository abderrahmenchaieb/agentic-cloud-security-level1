"""Test : le même schéma canonique accueille Windows/Sysmon ET cloud/CloudTrail."""
from datetime import datetime, timezone
from collect_agent.canonical_schema import (
    CanonicalLog, SourceType, ActivityCategory, Outcome,
    Actor, Target, ProcessContext, CloudContext
)

# --- CAS 1 : log ENDPOINT (Sysmon EID 1 - ProcessCreate) ---
log_endpoint = CanonicalLog(
    source_type=SourceType.ENDPOINT,
    source_provider="sysmon",
    event_time=datetime(2025, 1, 15, 10, 2, 19, tzinfo=timezone.utc),
    activity=ActivityCategory.PROCESS,
    action_name="ProcessCreate",
    outcome=Outcome.SUCCESS,
    host="VM-WIN-01",
    actor=Actor(user_name="jdoe", session_id="0x3E7", source_ip=None),
    process_context=ProcessContext(
        process_guid="{a1b2c3d4-0001}",
        process_id=3400,
        process_name="powershell.exe",
        command_line="powershell.exe -enc SQBFAFgAKABuAGV3...",
        parent_process_guid="{a1b2c3d4-0000}",
        parent_process_name="winword.exe",
    ),
)

# --- CAS 2 : log CLOUD (AWS CloudTrail - AssumeRole depuis une IP externe) ---
log_cloud = CanonicalLog(
    source_type=SourceType.CLOUD_CONTROL,
    source_provider="aws_cloudtrail",
    event_time=datetime(2025, 1, 15, 10, 5, 0, tzinfo=timezone.utc),
    activity=ActivityCategory.AUTHENTICATION,
    action_name="AssumeRole",
    outcome=Outcome.SUCCESS,
    actor=Actor(
        user_id="AIDAEXAMPLE",
        principal_type="IAMUser",
        account_id="123456789012",
        source_ip="185.220.101.47",   # IP externe → ira au Geolocation Agent
        user_agent="aws-cli/2.0",
    ),
    target=Target(type="iam_role", name="AdminRole"),
    cloud_context=CloudContext(
        provider="aws", region="us-east-1", service="sts",
        api_call="AssumeRole", resource_arn="arn:aws:iam::123456789012:role/AdminRole",
    ),
)

print("=== CAS 1 : ENDPOINT (Sysmon) ===")
print(f"  source_type      : {log_endpoint.source_type.value}")
print(f"  activity         : {log_endpoint.activity.value}")
print(f"  process_guid     : {log_endpoint.process_context.process_guid}")
print(f"  parent (filiation): {log_endpoint.process_context.parent_process_guid}")
print(f"  command_line     : {log_endpoint.process_context.command_line[:40]}...")
print(f"  cloud_context    : {log_endpoint.cloud_context}  <- None, normal (endpoint)")

print("\n=== CAS 2 : CLOUD (CloudTrail) ===")
print(f"  source_type      : {log_cloud.source_type.value}")
print(f"  activity         : {log_cloud.activity.value}")
print(f"  actor.source_ip  : {log_cloud.actor.source_ip}  <- ira au Geolocation")
print(f"  api_call         : {log_cloud.cloud_context.api_call}")
print(f"  process_context  : {log_cloud.process_context}  <- None, normal (cloud)")

print("\n=== PREUVE : même structure, sortie JSON uniforme ===")
print("Endpoint ->", log_endpoint.model_dump_json()[:90], "...")
print("Cloud    ->", log_cloud.model_dump_json()[:90], "...")

print("\n[OK] Le meme schema canonique accueille les deux sources.")
