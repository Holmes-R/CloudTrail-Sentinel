from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Event:
    id: str
    timestamp: datetime
    event_name: str
    event_source: str
    principal: str
    principal_type: str
    source_ip: str
    user_agent: str
    region: str
    success: bool
    error_code: str = ""
    request: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.isoformat()
        return value


@dataclass(slots=True)
class Alert:
    id: str
    rule_id: str
    title: str
    severity: str
    score: int
    principal: str
    timestamp: datetime
    technique_id: str
    technique: str
    description: str
    evidence: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.isoformat()
        return value

