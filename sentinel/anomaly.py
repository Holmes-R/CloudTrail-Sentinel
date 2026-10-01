from __future__ import annotations

from collections import Counter, defaultdict

from .models import Alert, Event


def detect_behavior_anomalies(events: list[Event]) -> list[Alert]:
    """Explainable cold-start anomaly model based on per-user location/IP novelty."""
    history: dict[str, list[Event]] = defaultdict(list)
    alerts: list[Alert] = []
    for event in events:
        previous = history[event.principal]
        known_ips = {item.source_ip for item in previous}
        known_regions = {item.region for item in previous}
        sensitive = event.event_name in {"ConsoleLogin", "AssumeRole", "CreateAccessKey", "AttachUserPolicy"}
        if len(previous) >= 3 and event.success and sensitive:
            new_ip = event.source_ip not in known_ips
            new_region = event.region not in known_regions
            if new_ip or new_region:
                reasons = []
                if new_ip:
                    reasons.append(f"new IP {event.source_ip}")
                if new_region:
                    reasons.append(f"new region {event.region}")
                score = 55 + (15 if new_ip and new_region else 0)
                alerts.append(Alert(
                    id=f"BEHAVIOR-NOVELTY:{event.id}", rule_id="BEHAVIOR-NOVELTY",
                    title="Unusual identity activity", severity="high" if score >= 70 else "medium",
                    score=score, principal=event.principal, timestamp=event.timestamp,
                    technique_id="T1078.004", technique="Valid Accounts: Cloud Accounts",
                    description="Successful sensitive activity from " + " and ".join(reasons) + ".",
                    evidence=[event.to_dict()],
                ))
        previous.append(event)
    return alerts


def user_baselines(events: list[Event]) -> dict[str, dict[str, object]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.principal].append(event)
    return {
        principal: {
            "events": len(items),
            "usual_ips": [value for value, _ in Counter(item.source_ip for item in items).most_common(3)],
            "usual_regions": [value for value, _ in Counter(item.region for item in items).most_common(3)],
        }
        for principal, items in grouped.items()
    }

