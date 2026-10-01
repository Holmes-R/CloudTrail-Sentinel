from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .models import Alert, Event

SEVERITY_SCORE = {"low": 20, "medium": 40, "high": 70, "critical": 90}


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    rules = data.get("rules", data if isinstance(data, list) else [])
    if not isinstance(rules, list):
        raise ValueError("Rules file must contain a 'rules' list")
    return [rule for rule in rules if rule.get("enabled", True)]


def _matches(event: Event, rule: dict[str, Any]) -> bool:
    match = rule.get("match", {})
    if match.get("event_names") and event.event_name not in match["event_names"]:
        return False
    if match.get("success") is not None and event.success != match["success"]:
        return False
    request_any = match.get("request_contains_any", [])
    request_text = str(event.request).lower()
    if request_any and not any(str(value).lower() in request_text for value in request_any):
        return False
    return True


def evaluate_rules(events: list[Event], rules: list[dict[str, Any]]) -> list[Alert]:
    alerts: list[Alert] = []
    by_principal: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_principal[event.principal].append(event)

    for rule in rules:
        for principal, principal_events in by_principal.items():
            candidates = [event for event in principal_events if _matches(event, rule)]
            threshold = int(rule.get("threshold", 1))
            window = timedelta(minutes=int(rule.get("window_minutes", 60)))
            emitted: set[str] = set()
            for end_event in candidates:
                evidence = [event for event in candidates if timedelta(0) <= end_event.timestamp - event.timestamp <= window]
                if len(evidence) < threshold or end_event.id in emitted:
                    continue
                emitted.update(event.id for event in evidence)
                severity = str(rule.get("severity", "medium")).lower()
                alerts.append(Alert(
                    id=f"{rule['id']}:{end_event.id}", rule_id=rule["id"], title=rule["title"],
                    severity=severity, score=int(rule.get("score", SEVERITY_SCORE.get(severity, 40))),
                    principal=principal, timestamp=end_event.timestamp,
                    technique_id=rule.get("mitre", {}).get("id", ""),
                    technique=rule.get("mitre", {}).get("name", ""),
                    description=rule.get("description", ""),
                    evidence=[event.to_dict() for event in evidence],
                ))
    return sorted(alerts, key=lambda alert: alert.timestamp, reverse=True)

