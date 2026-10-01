from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable

from .models import Event


def _read(source: str | Path | BinaryIO | dict[str, Any] | list[Any]) -> Any:
    if isinstance(source, (dict, list)):
        return source
    if hasattr(source, "read"):
        content = source.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig")
        return json.loads(content)
    return json.loads(Path(source).read_text(encoding="utf-8-sig"))


def _principal(record: dict[str, Any]) -> tuple[str, str]:
    identity = record.get("userIdentity") or {}
    principal_type = identity.get("type", "Unknown")
    session = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    name = identity.get("userName") or session.get("userName")
    if not name:
        arn = identity.get("arn") or identity.get("principalId") or "unknown"
        name = str(arn).split("/")[-1]
    return str(name), str(principal_type)


def _timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_cloudtrail(source: str | Path | BinaryIO | dict[str, Any] | list[Any]) -> list[Event]:
    """Parse AWS CloudTrail JSON (Records wrapper or a raw event list)."""
    payload = _read(source)
    records: Iterable[dict[str, Any]]
    if isinstance(payload, dict):
        records = payload.get("Records", [payload])
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError("CloudTrail input must be an object or array")

    events: list[Event] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not record.get("eventName"):
            continue
        principal, principal_type = _principal(record)
        event_id = record.get("eventID") or hashlib.sha256(
            f"{record.get('eventTime')}:{record.get('eventName')}:{principal}:{index}".encode()
        ).hexdigest()[:20]
        events.append(Event(
            id=str(event_id),
            timestamp=_timestamp(record.get("eventTime")),
            event_name=str(record.get("eventName", "Unknown")),
            event_source=str(record.get("eventSource", "")),
            principal=principal,
            principal_type=principal_type,
            source_ip=str(record.get("sourceIPAddress", "unknown")),
            user_agent=str(record.get("userAgent", "unknown")),
            region=str(record.get("awsRegion", "unknown")),
            success=not bool(record.get("errorCode")),
            error_code=str(record.get("errorCode", "")),
            request=record.get("requestParameters") or {},
            raw=record,
        ))
    return sorted(events, key=lambda event: event.timestamp)

