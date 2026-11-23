"""Create case-scoped report snapshots and render private local exports."""
from collections import Counter
import hashlib
from html import escape
from io import BytesIO
import json

import streamlit as st

from .evidence import utc
from .investigation import Investigation
from .jobs import JobStore
from .lab_ui import comparison_rows
from .ui import action, advanced, panel, provenance, show_frame


def build_case_report(registry, case, correlation, archived):
    info = next((row for row in registry.list("cases") if row["id"] == case), None)
    if info is None:
        raise ValueError("Unknown investigation")
    workspace = Investigation(registry)
    evidence = registry.list("evidence", case)
    allowed = {item["sha256"] for item in evidence}
    history = registry.list("audit", case)
    last_checks = {details["id"]: {"passed": details["valid"], "checked_utc": entry["stamp"]}
                   for entry in history if entry["action"] == "integrity_checked"
                   for details in [json.loads(entry["details"])]}
    provenance = [{key: item[key] for key in ("id", "name", "sha256", "size", "created", "storage")}
                  | {"last_integrity_check": last_checks.get(item["id"])} for item in evidence]
    jobs = [job for job in JobStore(registry).list(case, limit=100) if job.result]
    runs = [job for job in jobs if job.kind == "evaluation"]
    case_correlation = None
    references = {row["sha256"] for row in correlation.get("inputs", {}).values()}
    if references and references <= allowed:
        case_correlation = {key: correlation[key] for key in (
            "inputs", "auth_key_status", "process_window_seconds")}
    archival_models = []
    for key in ("lanl", "process"):
        run = archived.get(key, {})
        if run.get("archive_sha256") not in allowed:
            continue
        entry = {"dataset": key, "archive_sha256": run["archive_sha256"]}
        if key == "lanl":
            entry["models"] = run["models"]
        else:
            entry["performance"] = run["performance"]
        archival_models.append(entry)
    return {
        "schema_version": 1, "generated_utc": utc(),
        "investigation": {key: info[key] for key in ("id", "name", "status", "created")},
        "evidence": provenance, "findings": workspace.findings(case),
        "correlation": case_correlation,
        "correlation_runs": [{"id": job.id, **job.result} for job in jobs if job.kind == "correlate_lanl"],
        "privacy_profiles": workspace.profiles(case),
        "privacy_protection": [json.loads(entry["details"]) for entry in history
                               if entry["action"] == "privacy_transform"],
        "evaluations": [
            {"id": job.id, "parent_id": job.parent_id, "configuration": job.config,
             "completed_utc": job.finished, "result": job.result} for job in runs
        ],
        "comparisons": comparison_rows(runs),
        "ingestion": [{"id": job.id, **job.result} for job in jobs if job.kind == "ingest_lanl"],
        "forensic_runs": [{"id": job.id, "sha256": job.result["archive_sha256"], "dataset": job.config["dataset"],
                           "findings_scored": len(job.result["findings"]),
                           "performance": job.result.get("cohort_performance", job.result.get("performance"))}
                          for job in jobs if job.kind == "forensic_analysis"],
        "archived_lanl_evaluation": archival_models,
        "audit": {"chain_valid": registry.checked_audit(),
                  "operations": dict(Counter(entry["action"] for entry in history))},
    }


def _decimal(value, digits=3):
    return "—" if value is None else f"{value:.{digits}f}"


@st.cache_data(max_entries=12, show_spinner=False)
def case_pdf(document):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

    output = BytesIO()
    page_width, page_height = A4
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=47, leftMargin=47,
                            topMargin=66, bottomMargin=48, title="PrivForensics Investigation Report",
                            author="PrivForensics")
    ink, muted, border = map(colors.HexColor, ("#132439", "#526274", "#CAD5E0"))
    pale = colors.HexColor("#F4F7FA")
    teal = colors.HexColor("#136960")
    normal = ParagraphStyle("Text", fontName="Helvetica", fontSize=9.5, leading=14, textColor=ink)
    fine = ParagraphStyle("Fine", parent=normal, fontSize=8.5, leading=12, textColor=muted)
    technical = ParagraphStyle("Technical", parent=normal, fontName="Courier", fontSize=7.6, leading=10,
                               textColor=ink, splitLongWords=True)
    title = ParagraphStyle("Title", parent=normal, fontName="Helvetica-Bold", fontSize=24, leading=29, spaceAfter=8)
    section_style = ParagraphStyle("Section", parent=normal, fontName="Helvetica-Bold", fontSize=13, leading=18,
                                   spaceBefore=16, spaceAfter=6, keepWithNext=True)
    header_style = ParagraphStyle("Table header", parent=fine, fontName="Helvetica-Bold", textColor=ink)
    numeric = ParagraphStyle("Numeric", parent=normal, fontSize=8.5, alignment=TA_RIGHT)
    story = []

    def paragraph(value, style=normal):
        return Paragraph(escape(str(value)).replace("\n", "<br/>"), style)

    def section(label):
        story.append(paragraph(label, section_style))

    def table(headers, rows, widths, code=(), right=()):
        cells = [[paragraph(label, header_style) for label in headers]]
        for row in rows:
            cells.append([paragraph(text, technical if i in code else numeric if i in right else normal)
                          for i, text in enumerate(row)])
        t = LongTable(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E4EDF4")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, pale]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, 0), .65, border),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    info = document["investigation"]
    story.extend([paragraph("Investigation report", title), paragraph(info["name"]),
                  paragraph(f'{info["status"]} · {document["generated_utc"][:19].replace("T", " ")} UTC', fine),
                  Spacer(1, 5), paragraph(info["id"], technical)])
    section("Evidence and integrity")
    if document["evidence"]:
        rows = []
        for item in document["evidence"]:
            check = item["last_integrity_check"]
            state = "Awaiting check" if check is None else "Match" if check["passed"] else "Failed"
            rows.append((item["name"], item["sha256"], f"{item['size']:,}", state))
        table(["Evidence", "SHA-256", "Bytes", "Last check"], rows, [120, 225, 77, 79], code=(1,), right=(2,))
    else:
        story.append(paragraph("No evidence was registered when the report was generated.", fine))

    section("Saved findings")
    if document["findings"]:
        for row in document["findings"]:
            story.extend([paragraph(row["title"], header_style), paragraph(row["summary"], fine)])
            table(["Feed", "Source line", "Evidence SHA-256"],
                  [(ref["role"], str(ref["source_line"]), ref["sha256"]) for ref in row["references"]],
                  [110, 81, 310], code=(2,), right=(1,))
            story.append(Spacer(1, 7))
    else:
        story.append(paragraph("No investigation findings have been saved.", fine))
    if document["correlation"]:
        links = document["correlation"]
        story.append(paragraph(f"Authentication match counts by disposition · "
                               f"{', '.join(f"{k.replace('_', ' ')} {v}" for k, v in links['auth_key_status'].items())}. "
                               f"Process events use shared account and endpoint within ±{links['process_window_seconds']} seconds.", fine))

    if document["privacy_profiles"] or document["privacy_protection"]:
        section("Privacy assessment and protection")
        for profile in document["privacy_profiles"][:5]:
            detail = (f'{profile["quasi_identifier_singletons"]:,} quasi-identifier singletons · '
                      f'{profile["groups_under_five_rows"]:,} rows in groups below five'
                      if "quasi_identifier_singletons" in profile else f'{len(profile["fields"]):,} sensitive fields')
            story.append(paragraph(f'{profile["rows"]:,} rows profiled · {detail}', fine))
        for control in document["privacy_protection"][:10]:
            story.append(paragraph(f"{control['dataset']} · {control['mechanism']} · {control['rows']:,} rows", fine))

    section("Privacy–utility evaluation")
    if document["comparisons"]:
        rows = []
        for row in document["comparisons"]:
            if "f1" in row:
                metric = f"F1 {_decimal(row['f1'])}"
            else:
                metric = f"Observed AP {_decimal(row.get('observed_label_average_precision'))}"
            rows.append((row["Variant"], metric, _decimal(row["epsilon"]),
                         _decimal(row["membership_auc"]), _decimal(row["train_seconds"])))
        table(["Run variant", "Holdout utility", "Epsilon", "Membership AUC", "Train (s)"], rows,
              [160, 103, 57, 101, 80], right=(2, 3, 4))
        for run in document["evaluations"]:
            meta = run["result"]
            story.append(Spacer(1, 6))
            story.append(paragraph(f'Run {run["id"][:8]} · {meta["cohort"]["split_method"]}', header_style))
            story.append(paragraph(meta["cohort"]["label_definition"], fine))
            if any("epsilon_spent" in variant["privacy"] for variant in meta["variants"]):
                story.append(paragraph(meta["scope"]["dp"], fine))
        story.append(paragraph("Membership and linkage figures are aggregate diagnostics on generated records.", fine))
    else:
        story.append(paragraph("No completed case evaluations were available.", fine))

    if document["ingestion"] or document["forensic_runs"] or document.get("correlation_runs"):
        section("Processing and analysis")
        for job in document["ingestion"]:
            story.append(paragraph(f'{job["dataset"]} · {job["valid_records"]:,} accepted of {job["lines_read"]:,} '
                                   f'source lines · {job["elapsed_seconds"]:.3f} s · {job["scope"]}', fine))
        for job in document.get("correlation_runs", []):
            story.append(paragraph(f'Case correlation · {job["id"][:8]} · '
                                   f'±{job["process_window_seconds"]} seconds · {job["auth_key_status"]}', fine))
        for job in document["forensic_runs"]:
            story.append(paragraph(f'{job["dataset"]} · {job["findings_scored"]:,} stored ranked results · {job["id"][:8]}', fine))

    section("Audit and scope")
    state = "valid" if document["audit"]["chain_valid"] else "verification failed"
    count = sum(document["audit"]["operations"].values())
    story.append(paragraph(f"{count:,} case operations at generation · Local audit chain {state}."))
    story.append(paragraph("Forensic research workspace. Local administrators with database write access can alter the audit chain.", fine))

    def decorate(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(ink)
        canvas.rect(0, page_height - 40, page_width, 40, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(47, page_height - 25, "PRIVFORENSICS")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(page_width - 47, page_height - 25, "INVESTIGATION RECORD")
        canvas.setStrokeColor(teal)
        canvas.line(47, 33, page_width - 47, 33)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(47, 20, "Local evidence and research record")
        canvas.drawRightString(page_width - 47, 20, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return output.getvalue()


def _rows_for(category, document):
    if category == "Investigation overview":
        info = document["investigation"]
        return [{"Investigation": info["name"], "Case ID": info["id"], "Status": info["status"],
                 "Evidence items": len(document["evidence"]), "Saved findings": len(document["findings"]),
                 "Completed evaluations": len(document["evaluations"]),
                 "Generated (UTC)": document["generated_utc"]}]
    if category == "Evidence integrity":
        return [{k: row[k] for k in ("id", "name", "sha256", "size", "storage")}
                | {"last_integrity_check": (row["last_integrity_check"] or {}).get("passed")}
                for row in document["evidence"]]
    if category in ("Suspicious activity", "Event correlation"):
        kind = "Model finding" if category == "Suspicious activity" else category
        return [{k: finding[k] for k in ("id", "title", "timestamp_s", "summary", "score")}
                | ref for finding in document["findings"] if finding["kind"] == kind
                for ref in finding["references"]]
    if category == "Privacy assessment":
        return [{k: row.get(k) for k in ("source_sha256", "rows", "scope", "quasi_identifier_singletons",
                                          "groups_under_five_rows")}
                for row in document["privacy_profiles"]]
    rows = document["comparisons"]
    if category == "Privacy diagnostics":
        fields = ("Variant", "identifier_cells_unchanged", "synthetic_linkage_success",
                  "membership_auc", "membership_advantage", "epsilon", "delta")
        return [{k: row[k] for k in fields} for row in rows if row["membership_auc"] is not None
                or row["synthetic_linkage_success"] is not None]
    if category == "Performance":
        fields = ("Variant", "feature_prep_seconds", "train_seconds", "inference_seconds", "train_peak_rss_mib",
                  "train_mean_cpu_percent", "inference_records_per_second")
        return [{k: row[k] for k in fields} for row in rows]
    return rows


def render_reports(registry, case, processed, archived, require_case, safe_csv):
    st.caption("Create a dated record of the investigation, then review the sections before exporting.")
    if not require_case(case):
        action("Open investigations", "Investigations", key="reports_no_case")
        return
    workspace = Investigation(registry)
    if st.button("Generate investigation report", type="primary",
                 help="Capture the case's evidence, findings and measurements at the current time."):
        path = processed / "correlation/manifest.json"
        correlation = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        document = build_case_report(registry, case, correlation, archived)
        st.session_state[f"report_focus_{case}"] = workspace.save_report(case, document)
        st.rerun()
    history = workspace.reports(case)
    if not history:
        evidence_items = registry.list("evidence", case)
        st.info("No report snapshots yet. Generate the first report to open the preview.")
        if not evidence_items:
            st.caption("Add evidence first if you want the report to include verification details.")
            action("Open evidence", "Evidence Management", key="reports_evidence")
        return
    by_id = {row["id"]: row for row in history}
    key = f"report_selected_{case}"
    if focus := st.session_state.pop(f"report_focus_{case}", None):
        st.session_state[key] = focus
    selection, preview = st.columns([1, 1.55], gap="large")
    with selection:
        st.header("Report snapshots")
        report_id = st.selectbox("Report snapshot", list(by_id), key=key, format_func=lambda identifier: (
            f"{by_id[identifier]['created'][:19].replace('T', ' ')} UTC · {identifier[:8]}"))
        category = st.selectbox("Report section", ["Investigation overview", "Evidence integrity", "Suspicious activity",
                                                   "Event correlation", "Privacy assessment", "Privacy–utility evaluation",
                                                   "Privacy diagnostics", "Performance"])
        document = workspace.report(case, report_id)
        if advanced():
            with st.expander("Snapshot history"):
                show_frame([{"Snapshot": row["id"][:8], "Generated (UTC)": row["created"]} for row in history])
        st.caption("PDF and JSON contain the whole snapshot. CSV contains the selected section.")
    with preview:
        st.header("Preview")
        info = document["investigation"]
        st.html(f"""
        <article class="pf-paper" aria-label="Report cover preview">
          <p>PrivForensics investigation record</p>
          <h2>{escape(info["name"])}</h2>
          <p>{escape(document["generated_utc"][:19].replace("T", " "))} UTC · {escape(info["status"])}</p>
          <p class="pf-paper-rule">{len(document["evidence"])} evidence items · {len(document["findings"])} saved findings
            · {len(document["evaluations"])} completed evaluations</p>
        </article>
        """)
        rows = _rows_for(category, document)
        if rows:
            show_frame(rows, height=min(280, 92 + 32 * len(rows)))
        else:
            st.caption("This snapshot contains no entries for the selected section.")
    st.header("Export")
    panel("Export review", [("Evidence locations", "Paths excluded"),
                            ("LANL account and computer values", "Excluded from case snapshots"),
                            ("Included evidence references", "SHA-256 and physical source lines")])

    def download(column, label, format, data, mime, *, disabled=False):
        column.download_button(label, data, f"privforensics-{report_id[:8]}.{format}", mime, disabled=disabled,
                               on_click=registry.record,
                               args=(case, "report_exported", {"report_id": report_id, "format": format,
                                                               "section": category if format == "csv" else "all"}))

    columns = st.columns(3)
    try:
        pdf = case_pdf(document)
        download(columns[0], "Download investigation PDF", "pdf", pdf, "application/pdf")
        if advanced():
            provenance(hashlib.sha256(pdf).hexdigest(), source="Rendered PDF", key=f"report_{report_id}")
    except ModuleNotFoundError as exc:
        if exc.name != "reportlab":
            raise
        columns[0].info("Install the project requirements to enable PDF export.")
    download(columns[1], "Download investigation JSON", "json",
             json.dumps(document, indent=2, allow_nan=False), "application/json")
    download(columns[2], "Download section CSV", "csv", safe_csv(rows), "text/csv", disabled=not rows)
    if not rows:
        st.caption("Choose a populated section to export a CSV.")
