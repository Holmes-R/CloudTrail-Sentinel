from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .engine import HuntResult


def alerts_csv(result: HuntResult) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "severity", "score", "principal", "rule_id", "title", "mitre_technique", "source_ips"])
    for alert in result.alerts:
        ips = sorted({item["source_ip"] for item in alert.evidence})
        writer.writerow([alert.timestamp.isoformat(), alert.severity, alert.score, alert.principal, alert.rule_id, alert.title, alert.technique_id, "; ".join(ips)])
    return output.getvalue().encode("utf-8")


def incident_pdf(result: HuntResult) -> bytes:
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("CloudTrail Sentinel — Investigation Report", styles["Title"]),
             Paragraph(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]), Spacer(1, 8)]
    summary = [["Events", "Alerts", "Identities", "Attack chains"], [len(result.events), len(result.alerts), len(result.users), len(result.attack_chains)]]
    table = Table(summary, colWidths=[40 * mm] * 4)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172554")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .5, colors.grey), ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story += [table, Spacer(1, 14), Paragraph("Identity risk", styles["Heading2"])]
    story.append(Table([["Principal", "Risk"]] + [[user, score] for user, score in result.risk_scores.items()], colWidths=[120 * mm, 30 * mm], style=[("GRID", (0, 0), (-1, -1), .5, colors.grey)]))
    story += [PageBreak(), Paragraph("Alerts", styles["Heading1"])]
    for alert in result.alerts:
        story += [Paragraph(f"{alert.severity.upper()} · {alert.title}", styles["Heading3"]),
                  Paragraph(f"{alert.timestamp.isoformat()} · {alert.principal} · {alert.technique_id} {alert.technique}", styles["Normal"]),
                  Paragraph(alert.description, styles["BodyText"]), Spacer(1, 8)]
    doc.build(story)
    return output.getvalue()

