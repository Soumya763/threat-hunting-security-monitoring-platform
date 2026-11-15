"""
Report generation. Both JSON and PDF are rendered only from stored data
(the analysis record, its notes, its incident links, or an incident and its
alerts and investigation notes). Nothing is re-fetched while a report is built.

The PDF is produced with ReportLab. Text is XML-escaped before being placed in
Paragraphs, so file names and URLs cannot inject markup.
"""

import io
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

DISCLAIMER = (
    "This report summarises automated checks and external intelligence at the time they ran. "
    "A detection or a low score is a triage aid, not proof. No result in this report means a file "
    "or URL is safe unless it is explicitly classified as 'Clean', and even then the check is not a guarantee."
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def analysis_report_json(detail: dict[str, Any], notes: list[dict[str, Any]],
                         incidents: list[dict[str, Any]], generated_by: str) -> dict[str, Any]:
    result = detail.get("result") or {}
    return {
        "report_type": "analysis",
        "generated_at": _now_iso(),
        "generated_by": generated_by,
        "disclaimer": DISCLAIMER,
        "analysis": {k: v for k, v in detail.items() if k != "result"},
        "risk": {
            "level": detail.get("risk_level"),
            "label": result.get("classification_label"),
            "score": detail.get("risk_score"),
            "factors": result.get("factors", []),
            "caveats": result.get("caveats", []),
        },
        "findings": {k: result.get(k) for k in (
            "identification", "static", "strings", "yara", "file", "detections",
            "submitted_url", "normalized_url", "final_url", "host", "registrable_domain",
            "dns", "redirect_chain", "http_status", "tls", "tls_problem", "page",
            "phishing_indicators", "lookalike_of", "rdap", "indicator_type", "indicator",
            "local",
        ) if k in result},
        "providers": result.get("providers", {}),
        "steps": result.get("steps", []),
        "recommendations": result.get("recommendations", []),
        "notes": notes,
        "linked_incidents": incidents,
    }


def incident_report_json(incident: dict[str, Any], alerts: list[dict[str, Any]],
                         notes: list[dict[str, Any]], analyses: list[dict[str, Any]],
                         generated_by: str) -> dict[str, Any]:
    return {
        "report_type": "incident",
        "generated_at": _now_iso(),
        "generated_by": generated_by,
        "disclaimer": DISCLAIMER,
        "incident": incident,
        "alerts": alerts,
        "investigation_notes": notes,
        "linked_analyses": analyses,
    }


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=18, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4,
                             textColor=colors.HexColor("#1f4e79")),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=8.5, leading=11),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontSize=7.5, leading=9.5,
                                textColor=colors.HexColor("#555555")),
    }


def _p(text: Any, style) -> Paragraph:
    return Paragraph(escape("" if text is None else str(text)), style)


def _table(rows: list[list[Any]], styles, col_widths=None) -> Table:
    data = [[_p(c, styles["body"]) for c in row] for row in rows]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbbbbb")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3f8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _render(story_builder) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title="Threat Hunting Platform report", author="Threat Hunting Platform")
    styles = _styles()
    story = story_builder(styles)
    story.append(Spacer(1, 6))
    story.append(Paragraph(escape(DISCLAIMER), styles["small"]))
    doc.build(story)
    return buffer.getvalue()


def analysis_report_pdf(report: dict[str, Any]) -> bytes:
    a = report["analysis"]
    risk = report["risk"]

    def build(styles):
        s = [
            _p("Security analysis report", styles["title"]),
            _p(f"Generated {report['generated_at']} by {report['generated_by']}", styles["small"]),
            Spacer(1, 6),
            _p("Analysis details", styles["h2"]),
            _table([
                ["Field", "Value"],
                ["Name / indicator", a.get("display_name") or a.get("indicator_value")],
                ["Type", f"{a.get('kind')} ({a.get('indicator_type')})"],
                ["Status", a.get("status")],
                ["Submitted", a.get("created_at")],
                ["Completed", a.get("completed_at")],
                ["File size (bytes)", a.get("file_size")],
                ["SHA-256", a.get("sha256")],
                ["Quarantine retention until", a.get("retention_until") or "not applicable"],
            ], styles, col_widths=[45 * mm, 125 * mm]),
            _p("Risk", styles["h2"]),
            _p(f"Classification: {risk.get('label') or risk.get('level')}. Score: {risk.get('score')} / 100.", styles["body"]),
        ]
        if risk.get("factors"):
            rows = [["Points", "Factor", "Reason"]] + [[f["points"], f["label"], f["reason"]] for f in risk["factors"]]
            s += [Spacer(1, 4), _table(rows, styles, col_widths=[16 * mm, 50 * mm, 104 * mm])]
        else:
            s.append(_p("No factors contributed to the score.", styles["body"]))
        if risk.get("caveats"):
            s += [_p("Caveats", styles["h2"])] + [_p("- " + c, styles["body"]) for c in risk["caveats"]]

        providers = report.get("providers") or {}
        if providers:
            rows = [["Provider", "Status", "Detections", "Message"]]
            for name, r in providers.items():
                det = r.get("detection")
                rows.append([name, r.get("status"),
                             f"{det['positives']} of {det['total']}" if det else "-",
                             r.get("message") or ""])
            s += [_p("Provider results", styles["h2"]), _table(rows, styles, col_widths=[40 * mm, 28 * mm, 26 * mm, 76 * mm])]

        findings = report.get("findings") or {}
        s.append(_p("Findings", styles["h2"]))
        if "identification" in findings:
            ident = findings["identification"]
            s.append(_p(f"Detected type: {ident.get('detected_family') or 'unrecognised'}. "
                        f"Declared extension: .{ident.get('declared_extension') or '-'}. "
                        f"Extension matches content: {ident.get('extension_matches')}.", styles["body"]))
        if findings.get("yara", {}) and findings["yara"].get("matches"):
            rows = [["YARA rule", "Severity", "Description"]] + [
                [m["rule"], m["severity"], m["description"]] for m in findings["yara"]["matches"]]
            s += [_table(rows, styles, col_widths=[45 * mm, 22 * mm, 103 * mm])]
        static = findings.get("static") or {}
        if static.get("indicators"):
            s.append(_p("PDF indicators: " + ", ".join(f"{i['code']} ({i['count']})" for i in static["indicators"]), styles["body"]))
        if static.get("suspicious_imports"):
            s.append(_p("Suspicious imports: " + ", ".join(i["function"] for i in static["suspicious_imports"]), styles["body"]))
        if static.get("auto_exec_keywords"):
            s.append(_p("Macro auto-execution keywords: " + ", ".join(static["auto_exec_keywords"]), styles["body"]))
        if (findings.get("strings") or {}).get("categories"):
            s.append(_p("Suspicious string categories: " + ", ".join(
                c["category"] for c in findings["strings"]["categories"]), styles["body"]))
        if findings.get("normalized_url"):
            s.append(_p(f"Normalised URL: {findings['normalized_url']}", styles["body"]))
            s.append(_p(f"Final URL: {findings.get('final_url') or 'not retrieved'}", styles["body"]))
            s.append(_p(f"Host: {findings.get('host')}   Resolved IPs: {', '.join((findings.get('dns') or {}).get('public_addresses', [])) or 'none public'}", styles["body"]))
        if findings.get("redirect_chain"):
            rows = [["#", "URL", "Status", "Note"]] + [
                [i + 1, h.get("url"), h.get("status") or "-", h.get("blocked") or h.get("error") or h.get("location") or ""]
                for i, h in enumerate(findings["redirect_chain"])]
            s += [Spacer(1, 3), _table(rows, styles, col_widths=[8 * mm, 100 * mm, 18 * mm, 44 * mm])]
        tls = findings.get("tls")
        if tls:
            s.append(_p(f"TLS: subject {tls.get('subject')}, issuer {tls.get('issuer')}, expires {tls.get('not_after')}.", styles["body"]))
        if findings.get("tls_problem"):
            s.append(_p(f"TLS problem: {findings['tls_problem']}", styles["body"]))
        if findings.get("phishing_indicators"):
            s += [_p("Phishing-related findings", styles["h2"])] + [_p("- " + p, styles["body"]) for p in findings["phishing_indicators"]]
        rdap = findings.get("rdap")
        if rdap and rdap.get("status") == "ok":
            s.append(_p(f"Registered {rdap.get('registered_at')} ({rdap.get('age_days')} days ago). Registrar: {rdap.get('registrar') or 'unknown'}.", styles["body"]))

        s.append(_p("Recommended actions", styles["h2"]))
        s += [_p("- " + r, styles["body"]) for r in report.get("recommendations", [])] or [_p("None.", styles["body"])]

        notes = report.get("notes") or []
        if notes:
            s.append(_p("Analyst notes", styles["h2"]))
            s += [_p(f"[{n.get('created_at')}] {n.get('author')}: {n.get('content')}", styles["body"]) for n in notes]
        incidents = report.get("linked_incidents") or []
        if incidents:
            s.append(_p("Linked incidents", styles["h2"]))
            s += [_p(f"Incident #{i['id']}: {i['title']} ({i['status']})", styles["body"]) for i in incidents]
        return s

    return _render(build)


def incident_report_pdf(report: dict[str, Any]) -> bytes:
    inc = report["incident"]

    def build(styles):
        s = [
            _p(f"Incident report #{inc['id']}", styles["title"]),
            _p(f"Generated {report['generated_at']} by {report['generated_by']}", styles["small"]),
            _p("Incident", styles["h2"]),
            _table([
                ["Field", "Value"],
                ["Title", inc.get("title")],
                ["Severity", inc.get("severity")],
                ["Status", inc.get("status")],
                ["Assigned to", inc.get("assigned_username") or "unassigned"],
                ["Created", inc.get("created_at")],
                ["Description", inc.get("description")],
            ], styles, col_widths=[40 * mm, 130 * mm]),
            _p("Linked alerts", styles["h2"]),
        ]
        alerts = report.get("alerts") or []
        if alerts:
            rows = [["ID", "Event type", "Severity", "Source IP", "Created"]] + [
                [a["id"], a["event_type"], a["severity"], a.get("source_ip") or "-", a.get("created_at")] for a in alerts]
            s.append(_table(rows, styles, col_widths=[12 * mm, 60 * mm, 22 * mm, 30 * mm, 46 * mm]))
        else:
            s.append(_p("No linked alerts.", styles["body"]))
        analyses = report.get("linked_analyses") or []
        s.append(_p("Linked analyses", styles["h2"]))
        if analyses:
            rows = [["ID", "Type", "Indicator", "Risk", "Score"]] + [
                [a["id"], a["kind"], a.get("display_name") or a["indicator_value"], a.get("risk_level") or "-", a.get("risk_score") or "-"]
                for a in analyses]
            s.append(_table(rows, styles, col_widths=[12 * mm, 22 * mm, 88 * mm, 40 * mm, 18 * mm]))
        else:
            s.append(_p("No analyses linked.", styles["body"]))
        notes = report.get("investigation_notes") or []
        s.append(_p("Investigation notes", styles["h2"]))
        s += [_p(f"[{n['created_at']}] {n['author']}: {n['content']}", styles["body"]) for n in notes] or [_p("None.", styles["body"])]
        return s

    return _render(build)
