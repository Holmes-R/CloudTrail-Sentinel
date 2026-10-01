# CloudTrail Sentinel

**Explainable IAM Privilege-Escalation Threat Hunting**

CloudTrail Sentinel turns AWS CloudTrail JSON into explainable detections, identity risk scores, correlated attack timelines, IAM relationship graphs, MITRE ATT&CK coverage, and downloadable incident reports. It runs entirely locally and includes a synthetic attack simulation—an AWS account is optional.

## What it detects

- Repeated failed console authentication
- New access-key creation
- Administrative policy attachment
- Sensitive role assumption
- CloudTrail logging tampering
- Sensitive activity from a new IP address or region
- Multi-stage IAM attack chains
- IAM identity, role, policy, and access-key inventory
- Identity-to-role and identity-to-policy relationship mapping
- Risky IAM permission-change findings

The included scenario models:

`failed logins → successful login → access-key creation → admin policy attachment → logging disabled`

## Quick start

Requires Python 3.10 or newer.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python generate_sample.py
streamlit run app.py
```

Open the URL shown by Streamlit (normally `http://localhost:8501`). The synthetic attack is loaded automatically. Upload a CloudTrail export at any time from the sidebar.

## Run tests

```powershell
pytest -q
```

## Project layout

```text
app.py                       Streamlit investigation dashboard
generate_sample.py           Safe synthetic CloudTrail scenario
rules/default_rules.yml      Human-readable detection rules
sentinel/parser.py           CloudTrail normalization
sentinel/rules.py            Threshold and time-window rule engine
sentinel/anomaly.py          Explainable user behavior anomaly detection
sentinel/iam.py              IAM inventory and permission relationship analysis
sentinel/engine.py           Correlation and identity risk scoring
sentinel/reporting.py        PDF and CSV reporting
tests/                       Benign and malicious scenario tests
```

## Rule format

Rules are ordinary YAML and support event-name matching, outcome filtering, request-parameter keywords, thresholds, time windows, severity, risk contribution, and MITRE mapping.

```yaml
- id: DEFENSE-001
  title: CloudTrail logging tampered with
  severity: critical
  score: 95
  match:
    event_names: [StopLogging, DeleteTrail, UpdateTrail]
    success: true
  mitre: {id: T1562.008, name: "Impair Defenses: Disable or Modify Cloud Logs"}
```

## Risk model

Each alert contributes its configured score using diminishing returns: `new = current + score × (1 - current/100)`. This keeps risk bounded at 100 while allowing several related findings to raise confidence. Every score remains traceable to its alerts and raw supporting events.

## Security and privacy

Analysis runs in-process. The dashboard does not require AWS keys, make AWS API calls, or send logs to an external service. Treat exported reports as sensitive because they can contain usernames, IP addresses, and request parameters.

## License

MIT
