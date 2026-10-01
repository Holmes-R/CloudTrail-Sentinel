from __future__ import annotations

from pathlib import Path

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from sentinel import ThreatHunter
from sentinel.reporting import alerts_csv, incident_pdf

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "data" / "sample_attack.json"

st.set_page_config(page_title="CloudTrail Sentinel", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
  .block-container {padding-top: 2rem;}
  [data-testid="stMetric"] {background:#0f172a;border:1px solid #263449;border-radius:12px;padding:16px}
  [data-testid="stMetricLabel"], [data-testid="stMetricValue"] {color:#e2e8f0}
  .severity-critical {color:#fb7185;font-weight:700}.severity-high {color:#fb923c;font-weight:700}
</style>
""", unsafe_allow_html=True)


@st.cache_data(show_spinner=False)
def analyze(content: bytes):
    return ThreatHunter().hunt(__import__("json").loads(content))


def graph_figure(result):
    graph = nx.Graph()
    for event in result.events:
        graph.add_node(event.principal, kind="identity")
        graph.add_node(event.source_ip, kind="ip")
        graph.add_edge(event.principal, event.source_ip)
    for relation in result.iam["relationships"]:
        target_kind = "policy" if relation["relationship"] == "has policy" else "role"
        if relation["source"] not in graph:
            graph.add_node(relation["source"], kind="identity")
        graph.add_node(relation["target"], kind=target_kind)
        graph.add_edge(relation["source"], relation["target"], relationship=relation["relationship"])
    pos = nx.spring_layout(graph, seed=7)
    edges_x, edges_y = [], []
    for left, right in graph.edges():
        x0, y0 = pos[left]; x1, y1 = pos[right]
        edges_x += [x0, x1, None]; edges_y += [y0, y1, None]
    edge_trace = go.Scatter(x=edges_x, y=edges_y, mode="lines", line=dict(color="#334155", width=1), hoverinfo="skip")
    palette = {"identity": "#38bdf8", "ip": "#f97316", "role": "#a78bfa", "policy": "#22c55e"}
    nodes = list(graph.nodes())
    node_trace = go.Scatter(x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text",
        text=nodes, textposition="bottom center", hovertext=[graph.nodes[n]["kind"] for n in nodes],
        marker=dict(size=18, color=[palette[graph.nodes[n]["kind"]] for n in nodes], line=dict(width=1, color="#fff")))
    fig = go.Figure([edge_trace, node_trace])
    fig.update_layout(showlegend=False, margin=dict(l=10, r=10, t=10, b=10), xaxis=dict(visible=False), yaxis=dict(visible=False), height=430)
    return fig


with st.sidebar:
    st.title("🛡️ Sentinel")
    st.caption("Explainable AWS IAM threat hunting")
    uploaded = st.file_uploader("Upload CloudTrail JSON", type=["json"])
    use_sample = st.button("Load attack simulation", width="stretch")
    st.divider()
    st.caption("All analysis runs locally. No AWS credentials or log uploads to external services.")

if use_sample or (uploaded is None and SAMPLE.exists()):
    content = SAMPLE.read_bytes()
    source_name = "Synthetic attack simulation"
elif uploaded:
    content = uploaded.getvalue()
    source_name = uploaded.name
else:
    st.title("CloudTrail Sentinel")
    st.info("Upload a CloudTrail JSON file or generate the included sample with `python generate_sample.py`.")
    st.stop()

try:
    result = analyze(content)
except Exception as exc:
    st.error(f"Could not parse this file: {exc}")
    st.stop()

st.title("CloudTrail Sentinel")
st.caption(f"Investigation · {source_name}")
critical = sum(alert.severity == "critical" for alert in result.alerts)
high_risk = sum(score >= 70 for score in result.risk_scores.values())
cols = st.columns(4)
cols[0].metric("Events analyzed", len(result.events))
cols[1].metric("Detections", len(result.alerts), f"{critical} critical")
cols[2].metric("High-risk identities", high_risk)
cols[3].metric("Attack chains", len(result.attack_chains))

overview, alerts_tab, iam_tab, timeline_tab, graph_tab, coverage_tab = st.tabs(["Overview", "Alerts", "IAM inventory", "Attack timeline", "IAM graph", "MITRE coverage"])

with overview:
    left, right = st.columns([1, 1.6])
    with left:
        st.subheader("Identity risk")
        risk_df = pd.DataFrame([{"principal": user, "risk": score} for user, score in result.risk_scores.items()])
        if not risk_df.empty:
            st.plotly_chart(px.bar(risk_df, x="risk", y="principal", orientation="h", range_x=[0, 100], color="risk", color_continuous_scale=["#22c55e", "#f59e0b", "#ef4444"]), width="stretch")
        else:
            st.info("No identity risk identified.")
    with right:
        st.subheader("Activity over time")
        event_df = pd.DataFrame([event.to_dict() for event in result.events])
        if not event_df.empty:
            st.plotly_chart(px.scatter(event_df, x="timestamp", y="event_name", color="success", hover_data=["principal", "source_ip", "region"]), width="stretch")

with alerts_tab:
    controls = st.columns([1, 1, 2])
    severity = controls[0].multiselect("Severity", ["critical", "high", "medium", "low"], default=["critical", "high", "medium", "low"])
    principals = sorted({alert.principal for alert in result.alerts})
    selected_users = controls[1].multiselect("Principal", principals, default=principals)
    filtered = [alert for alert in result.alerts if alert.severity in severity and alert.principal in selected_users]
    for alert in filtered:
        with st.expander(f"{alert.severity.upper()}  ·  {alert.title}  ·  {alert.principal}"):
            st.write(alert.description)
            a, b, c = st.columns(3)
            a.metric("Risk contribution", alert.score)
            b.write(f"**MITRE:** {alert.technique_id} — {alert.technique}")
            c.write(f"**Observed:** {alert.timestamp.isoformat()}")
            st.dataframe(pd.DataFrame(alert.evidence)[["timestamp", "event_name", "source_ip", "region", "success"]], width="stretch", hide_index=True)
    d1, d2, _ = st.columns([1, 1, 2])
    d1.download_button("Download alert CSV", alerts_csv(result), "sentinel-alerts.csv", "text/csv", width="stretch")
    d2.download_button("Download incident PDF", incident_pdf(result), "sentinel-report.pdf", "application/pdf", width="stretch")

with iam_tab:
    st.subheader("Identity and access management")
    st.caption("IAM resources and permission changes reconstructed from the uploaded CloudTrail events.")
    i1, i2, i3, i4 = st.columns(4)
    i1.metric("Identities", len(result.iam["identities"]))
    i2.metric("Roles observed", len(result.iam["roles"]))
    i3.metric("Policies observed", len(result.iam["policies"]))
    i4.metric("Access keys created", len(result.iam["access_keys"]))
    identities_section, roles_section, policies_section, keys_section, findings_section = st.tabs(["Identities", "Roles", "Policies", "Access keys", "Risky changes"])
    with identities_section:
        if result.iam["identities"]:
            identity_df = pd.DataFrame(result.iam["identities"])
            identity_df["risk_score"] = identity_df["name"].map(result.risk_scores).fillna(0).astype(int)
            st.dataframe(identity_df, width="stretch", hide_index=True)
        else:
            st.info("No IAM identities were found.")
    with roles_section:
        st.dataframe(pd.DataFrame(result.iam["roles"]), width="stretch", hide_index=True) if result.iam["roles"] else st.info("No role assumptions were found.")
    with policies_section:
        st.dataframe(pd.DataFrame(result.iam["policies"]), width="stretch", hide_index=True) if result.iam["policies"] else st.info("No policy attachments were found.")
    with keys_section:
        st.dataframe(pd.DataFrame(result.iam["access_keys"]), width="stretch", hide_index=True) if result.iam["access_keys"] else st.info("No access-key creation was found.")
    with findings_section:
        st.dataframe(pd.DataFrame(result.iam["findings"]), width="stretch", hide_index=True) if result.iam["findings"] else st.success("No risky IAM changes were identified.")

with timeline_tab:
    if not result.attack_chains:
        st.info("No multi-stage chains detected.")
    for chain in result.attack_chains:
        st.subheader(f"{chain['principal']} · risk {chain['risk_score']}/100")
        stages = pd.DataFrame(chain["stages"])
        st.plotly_chart(px.scatter(stages, x="timestamp", y="stage", color="stage", hover_data=["event_name", "source_ip"], size_max=18), width="stretch")
        st.dataframe(stages[["timestamp", "stage", "event_name", "source_ip", "region"]], hide_index=True, width="stretch")

with graph_tab:
    st.caption("Blue: identity · Orange: source IP · Purple: assumed role · Green: attached policy")
    st.plotly_chart(graph_figure(result), width="stretch")

with coverage_tab:
    techniques = {}
    for rule in ThreatHunter().rules:
        technique = rule.get("mitre", {})
        techniques[technique.get("id", "Unmapped")] = {"Technique": technique.get("name", "Unmapped"), "Rule": rule["title"], "Triggered": any(alert.rule_id == rule["id"] for alert in result.alerts)}
    coverage = pd.DataFrame([{"ID": key, **value} for key, value in techniques.items()])
    st.dataframe(coverage, width="stretch", hide_index=True, column_config={"Triggered": st.column_config.CheckboxColumn()})

