from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .anomaly import detect_behavior_anomalies, user_baselines
from .iam import build_iam_inventory
from .models import Alert, Event
from .parser import parse_cloudtrail
from .rules import evaluate_rules, load_rules


@dataclass
class HuntResult:
    events: list[Event]
    alerts: list[Alert]
    users: dict[str, dict[str, Any]]
    attack_chains: list[dict[str, Any]]
    iam: dict[str, list[dict[str, Any]]]

    @property
    def risk_scores(self) -> dict[str, int]:
        scores: dict[str, int] = {}
        for alert in self.alerts:
            current = scores.get(alert.principal, 0)
            scores[alert.principal] = min(100, current + round(alert.score * (1 - current / 100)))
        return dict(sorted(scores.items(), key=lambda item: item[1], reverse=True))


def _correlate(events: list[Event], alerts: list[Alert]) -> list[dict[str, Any]]:
    stages = {
        "ConsoleLogin": "Initial access", "AssumeRole": "Role assumption",
        "CreateAccessKey": "Persistence", "AttachUserPolicy": "Privilege escalation",
        "AttachRolePolicy": "Privilege escalation", "PutUserPolicy": "Privilege escalation",
        "StopLogging": "Defense evasion", "DeleteTrail": "Defense evasion",
        "UpdateTrail": "Defense evasion",
    }
    chains = []
    for principal in sorted({event.principal for event in events}):
        related = [event for event in events if event.principal == principal and event.event_name in stages]
        if len({stages[event.event_name] for event in related}) >= 2:
            chains.append({
                "principal": principal,
                "risk_score": next((score for user, score in HuntResult(events, alerts, {}, [], {}).risk_scores.items() if user == principal), 0),
                "start": related[0].timestamp.isoformat(), "end": related[-1].timestamp.isoformat(),
                "stages": [{"stage": stages[event.event_name], **event.to_dict()} for event in related],
            })
    return chains


class ThreatHunter:
    def __init__(self, rules_path: str | Path | None = None):
        default = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yml"
        self.rules = load_rules(rules_path or default)

    def hunt(self, source: Any) -> HuntResult:
        events = parse_cloudtrail(source)
        alerts = evaluate_rules(events, self.rules) + detect_behavior_anomalies(events)
        alerts.sort(key=lambda alert: alert.timestamp, reverse=True)
        result = HuntResult(events, alerts, user_baselines(events), [], build_iam_inventory(events))
        result.attack_chains = _correlate(events, alerts)
        return result

