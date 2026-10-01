import json
from datetime import datetime, timedelta, timezone

from sentinel import ThreatHunter
from sentinel.parser import parse_cloudtrail
from sentinel.reporting import alerts_csv, incident_pdf


def record(name, minute=0, error=None, request=None, ip="10.0.0.1", region="us-east-1"):
    value = {"eventTime": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minute)).isoformat(),
             "eventName": name, "eventSource": "iam.amazonaws.com", "sourceIPAddress": ip,
             "awsRegion": region, "userAgent": "pytest", "userIdentity": {"type": "IAMUser", "userName": "alice"},
             "requestParameters": request or {}}
    if error:
        value["errorCode"] = error
    return value


def test_parser_normalizes_records():
    events = parse_cloudtrail({"Records": [record("ListUsers")]})
    assert events[0].principal == "alice"
    assert events[0].success is True


def test_benign_activity_has_no_alerts():
    result = ThreatHunter().hunt({"Records": [record("ListUsers"), record("GetUser", 1)]})
    assert result.alerts == []
    assert result.risk_scores == {}


def test_attack_chain_and_risk_are_detected():
    records = [record("ConsoleLogin", i, error="AccessDenied") for i in range(3)]
    records += [record("CreateAccessKey", 4),
                record("AttachUserPolicy", 5, request={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
                record("StopLogging", 6)]
    result = ThreatHunter().hunt({"Records": records})
    rule_ids = {alert.rule_id for alert in result.alerts}
    assert {"AUTH-001", "IAM-001", "IAM-002", "DEFENSE-001"} <= rule_ids
    assert result.risk_scores["alice"] >= 95
    assert len(result.attack_chains) == 1
    assert result.iam["access_keys"][0]["owner"] == "alice"
    assert result.iam["policies"][0]["administrative"] is True
    assert result.iam["findings"][0]["severity"] == "Critical"


def test_role_relationship_is_added_to_iam_inventory():
    result = ThreatHunter().hunt({"Records": [record("AssumeRole", request={"roleArn": "arn:aws:iam::123456789012:role/SecurityAdmin"})]})
    assert result.iam["roles"][0]["name"] == "SecurityAdmin"
    assert result.iam["relationships"][0]["relationship"] == "assumed"


def test_new_location_behavior_alert():
    records = [record("ListUsers", i, ip="10.0.0.1") for i in range(3)]
    records.append(record("ConsoleLogin", 4, ip="198.51.100.9", region="eu-west-1"))
    result = ThreatHunter().hunt({"Records": records})
    assert any(alert.rule_id == "BEHAVIOR-NOVELTY" for alert in result.alerts)


def test_reports_are_generated():
    result = ThreatHunter().hunt({"Records": [record("CreateAccessKey")]})
    assert b"IAM-001" in alerts_csv(result)
    assert incident_pdf(result).startswith(b"%PDF")

