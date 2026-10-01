from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import Event

ADMIN_MARKERS = ("administratoraccess", "action': '*'", '"action": "*"', "iam:*")
PRIVILEGE_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion", "UpdateAssumeRolePolicy"}


def _target_name(request: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if request.get(key):
            return str(request[key]).split("/")[-1]
    return "unknown"


def build_iam_inventory(events: list[Event]) -> dict[str, list[dict[str, Any]]]:
    """Build an IAM inventory and relationship model from CloudTrail events."""
    identities: dict[str, dict[str, Any]] = {}
    roles: dict[str, dict[str, Any]] = {}
    policies: dict[str, dict[str, Any]] = {}
    access_keys: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_relationships: set[tuple[str, str, str]] = set()
    event_counts: dict[str, int] = defaultdict(int)

    for event in events:
        event_counts[event.principal] += 1
        profile = identities.setdefault(event.principal, {"name": event.principal, "type": event.principal_type, "events": 0, "last_seen": event.timestamp.isoformat(), "source_ips": set(), "regions": set()})
        profile["events"] = event_counts[event.principal]
        profile["last_seen"] = max(profile["last_seen"], event.timestamp.isoformat())
        profile["source_ips"].add(event.source_ip)
        profile["regions"].add(event.region)
        request_text = str(event.request).lower()

        if event.event_name == "AssumeRole":
            role = _target_name(event.request, "roleArn", "roleName")
            roles.setdefault(role, {"name": role, "assumptions": 0, "last_assumed": event.timestamp.isoformat()})
            roles[role]["assumptions"] += 1
            roles[role]["last_assumed"] = event.timestamp.isoformat()
            relation = (event.principal, "assumed", role)
            if relation not in seen_relationships:
                relationships.append({"source": event.principal, "relationship": "assumed", "target": role, "timestamp": event.timestamp.isoformat()})
                seen_relationships.add(relation)

        if event.event_name in {"AttachUserPolicy", "AttachRolePolicy"}:
            target = _target_name(event.request, "userName", "roleName")
            policy = _target_name(event.request, "policyArn", "policyName")
            policies.setdefault(policy, {"name": policy, "attachments": 0, "administrative": False})
            policies[policy]["attachments"] += 1
            policies[policy]["administrative"] |= any(marker in request_text for marker in ADMIN_MARKERS)
            relation = (target, "has policy", policy)
            if relation not in seen_relationships:
                relationships.append({"source": target, "relationship": "has policy", "target": policy, "timestamp": event.timestamp.isoformat()})
                seen_relationships.add(relation)

        if event.event_name == "CreateAccessKey":
            access_keys.append({"owner": _target_name(event.request, "userName") if event.request else event.principal, "created_by": event.principal, "created_at": event.timestamp.isoformat(), "source_ip": event.source_ip, "status": "Active" if event.success else "Failed"})

        if event.event_name in PRIVILEGE_EVENTS and event.success:
            administrative = any(marker in request_text for marker in ADMIN_MARKERS)
            findings.append({"severity": "Critical" if administrative else "High", "principal": event.principal, "action": event.event_name, "reason": "Administrative permissions granted" if administrative else "IAM permissions changed", "timestamp": event.timestamp.isoformat(), "source_ip": event.source_ip})

    identity_rows = []
    for profile in identities.values():
        profile["source_ips"] = ", ".join(sorted(profile["source_ips"]))
        profile["regions"] = ", ".join(sorted(profile["regions"]))
        identity_rows.append(profile)
    return {"identities": identity_rows, "roles": list(roles.values()), "policies": list(policies.values()), "access_keys": access_keys, "relationships": relationships, "findings": findings}
