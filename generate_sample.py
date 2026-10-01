from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def event(at, name, user="alice", ip="203.0.113.77", region="us-east-1", error=None, request=None, source="iam.amazonaws.com"):
    return {"eventVersion": "1.09", "eventTime": at.isoformat().replace("+00:00", "Z"), "eventSource": source,
            "eventName": name, "awsRegion": region, "sourceIPAddress": ip, "userAgent": "aws-cli/2.15",
            "userIdentity": {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::111122223333:user/{user}"},
            "requestParameters": request or {}, **({"errorCode": error} if error else {})}


base = datetime(2026, 9, 30, 8, 0, tzinfo=timezone.utc)
records = [event(base + timedelta(days=i), "ListBuckets", ip="198.51.100.10", source="s3.amazonaws.com") for i in range(3)]
records += [event(base + timedelta(days=3, minutes=i), "ConsoleLogin", error="Failed authentication", source="signin.amazonaws.com") for i in range(3)]
records += [
    event(base + timedelta(days=3, minutes=5), "ConsoleLogin", region="ap-southeast-1", source="signin.amazonaws.com"),
    event(base + timedelta(days=3, minutes=7), "CreateAccessKey", request={"userName": "alice"}),
    event(base + timedelta(days=3, minutes=10), "AttachUserPolicy", request={"userName": "alice", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
    event(base + timedelta(days=3, minutes=14), "StopLogging", request={"name": "organization-trail"}, source="cloudtrail.amazonaws.com"),
]
target = Path(__file__).parent / "data" / "sample_attack.json"
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps({"Records": records}, indent=2), encoding="utf-8")
print(target)

