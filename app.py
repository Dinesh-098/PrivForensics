"""PrivForensics local investigation console."""
import json
import os
import platform
from math import ceil
from datetime import date
from pathlib import Path

import pandas as pd
import psutil
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
import streamlit as st

from modules.analysis_models import score_auth_group
from modules.evidence import Registry
from modules.evidence_ui import browse_case_exports, browse_lanl, render_evidence
from modules.investigation import Investigation
from modules.jobs import JobStore, launch_worker
from modules.lab import synthetic_fingerprint
from modules.lab_ui import LAB_PAGE, comparison_rows, job_label, job_status, render_lab
from modules.reporting import render_reports
from modules.overview_ui import render_overview
from modules.shell import render_shell
from modules.ui import (APP_ROOT, CONCEPTS, action, advanced, definitions, panel,
                        provenance, show_frame, source_note, style_guide, visible_label)
from modules.lanl_correlation import authentication_context
from modules.privacy_ui import render_protection
from modules.timeline_ui import render_timeline
from modules.privacy import assess, protect, sensitive_inventory, text_privacy


ROOT = Path(os.environ.get("PRIVFORENSICS_PROJECT_ROOT", Path(__file__).resolve().parent))
PROCESSED = ROOT / "dataset/processed/lanl-v1"
RESULTS = Path(os.environ.get("PRIVFORENSICS_RESULTS", ROOT / "reports/experiments"))
AUTH_MODEL = Path(os.environ.get("PRIVFORENSICS_AUTH_MODEL", ROOT / "models/lanl_auth.json"))
STATE = Path(os.environ.get("PRIVFORENSICS_STATE_DIR", ROOT / ".privforensics"))
st.set_page_config(page_title="PrivForensics", page_icon=str(APP_ROOT / "assets/brand/favicon-32.png"),
                   layout="wide")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def evidence_meta():
    return {kind: read_json(PROCESSED / kind / "manifest.json") for kind in ("auth", "proc", "redteam")}


@st.cache_data
def synthetic(path, mtime):
    return pd.read_csv(path)


def example_frame():
    path = ROOT / "dataset/forensic_auth_logs.csv"
    return synthetic(str(path), path.stat().st_mtime_ns)



def require_case(case):
    if not case:
        st.info("Use the investigation switcher to choose a case, or create one in Investigations.")
        return False
    return True


def flattened(models, section):
    return pd.DataFrame([{"model": run["model"], **run[section]} for run in models])


def safe_csv(rows):
    frame = pd.DataFrame(rows)
    for column in frame.select_dtypes(include=["object", "string"]):
        frame[column] = frame[column].map(lambda x: "'" + x if isinstance(x, str)
                                         and x.lstrip().startswith(("=", "+", "-", "@")) else x)
    return frame.to_csv(index=False).encode("utf-8")


def record(registry, case, action, details):
    registry.record(case, action, details)


rows_panel = panel


def recent_entries(registry, case=None):
    entries = []
    for row in reversed(registry.list("audit", case)):
        details = json.loads(row["details"])
        evidence = details.get("evidence_id") or details.get("id")
        status = "Failed" if details.get("valid") is False else "Recorded"
        if details.get("valid") is True:
            status = "Verified"
        entries.append({"UTC": row["stamp"][:19].replace("T"," "), "Action": row["action"].replace("_"," "),
                        "Evidence": evidence or "", "Investigation": row["case_id"] or "",
                        "Job or finding": details.get("job_id") or details.get("finding_id") or "",
                        "Actor": "Local workspace", "Status": status})
    return entries


@st.cache_data
def correlation_index(path, modified):
    return pq.read_table(path).to_pandas()


def investigations(registry, case):
    workspace = Investigation(registry)
    cases = registry.list("cases")
    listing, detail = st.columns([1.05, 1.4], gap="large")
    with listing:
        st.header("Find an investigation")
        query = st.text_input("Search investigations", placeholder="Name, owner or case ID")
        status = st.selectbox("Case status filter", ["All", "Open", "Closed"], key="case_filter")
        rows = [row for row in cases
                if (status == "All" or row["status"] == status)
                and query.casefold() in " ".join(str(row[k]) for k in ("name", "id", "owner", "description")).casefold()]
        if rows:
            show_frame([{"Investigation": row["name"], "Status": row["status"], "Evidence": row["evidence_count"],
                         "Case ID": row["id"][:8]} for row in rows], height=235)
            choice = st.selectbox("Open investigation", [row["id"] for row in rows],
                                  format_func={row["id"]: row["name"] for row in rows}.get)
            st.button("Set as current investigation", on_click=lambda: st.session_state.update(pending_case=choice),
                      disabled=choice == case)
        else:
            st.caption("No investigations match these filters." if cases else "No investigations yet.")
        with st.expander("New investigation", expanded=not cases or not case):
            with st.form("new_investigation", clear_on_submit=True):
                name = st.text_input("Investigation name", max_chars=120, placeholder="Example: Login activity review")
                description = st.text_area("Case notes", max_chars=2000) if advanced() else ""
                owner = st.text_input("Investigator", max_chars=120) if advanced() else ""
                if st.form_submit_button("Create investigation", type="primary"):
                    st.session_state.pending_case = registry.case(name, description, owner)
                    st.rerun()
    with detail:
        active = next((row for row in cases if row["id"] == case), None)
        if active is None:
            st.info("Create or select an investigation to see its evidence, findings and reports.")
            return
        st.header(active["name"])
        tabs = st.tabs(["Summary", "Evidence", "Findings", "Experiments", "Reports", "Activity"])
        with tabs[0]:
            rows_panel("Case details", [("Investigator", active["owner"]), ("Case ID", case),
                                        ("Created", active["created"]), ("Status", active["status"])])
            if active["description"]:
                st.text(active["description"])
            with st.expander("Edit investigation"):
                with st.form(f"edit_{case}"):
                    title = st.text_input("Title", active["name"], max_chars=120)
                    owner = st.text_input("Investigator", active["owner"], max_chars=120)
                    notes = st.text_area("Case notes", active["description"], max_chars=2000)
                    new_status = st.selectbox("Case status", ["Open", "Closed"], index=int(active["status"] == "Closed"))
                    confirmed = st.checkbox("Confirm any case status change")
                    if st.form_submit_button("Save investigation"):
                        if new_status != active["status"] and not confirmed:
                            st.error("Confirm the status change to save the investigation.")
                        else:
                            registry.update_case(case, name=title, owner=owner, description=notes, status=new_status)
                            st.rerun()
        with tabs[1]:
            items = registry.list("evidence", case)
            if items:
                show_frame([{"File": row["name"], "Bytes": row["size"], "Storage": row["storage"]}
                            for row in items])
            else:
                st.caption("No evidence has been added to this investigation.")
            action("Open evidence", "Evidence Management", key="case_evidence")
        with tabs[2]:
            findings = workspace.findings(case)
            if findings:
                chosen = st.selectbox("Saved finding", findings, format_func=lambda row: row["title"])
                st.caption(chosen["summary"])
                show_frame(chosen["references"])
            else:
                st.caption("Save a finding from Event Correlation or AI Analysis.")
        with tabs[3]:
            jobs = [job for job in JobStore(registry).list(case, "evaluation", limit=15) if job.result]
            if jobs:
                show_frame([{"Model": job.config["model"], "Run": job.id[:8], "Status": job.status.title()} for job in jobs])
            else:
                st.caption("Run an experiment to compare privacy and detection performance.")
            action("Open Evaluation Lab", LAB_PAGE, key="case_lab")
        with tabs[4]:
            reports = workspace.reports(case)
            if reports:
                show_frame([{"Snapshot": item["id"][:8], "Generated": item["created"]} for item in reports])
            else:
                st.caption("Generate a report to save a dated case snapshot.")
            action("Open reports", "Reports", key="case_reports")
        with tabs[5]:
            entries = recent_entries(registry, case)
            if entries:
                show_frame(entries[:12])
            else:
                st.caption("Recorded operations will appear here.")


def explorer(registry, case):
    view = st.radio("Data source", ["LANL", "Synthetic authentication", "Registered evidence", "Case LANL exports"], horizontal=True)
    limit = st.slider("Rows to inspect", 10, 200, 50)
    if view == "Synthetic authentication":
        st.dataframe(protect(example_frame().head(limit), "mask"), hide_index=True)
    elif view == "Registered evidence":
        if not require_case(case):
            return
        items = [item for item in registry.list("evidence", case)
                 if Path(item["name"]).suffix.lower() in {".csv", ".tsv"} and item["storage"] == "vault"]
        if not items:
            st.info("Upload a CSV or TSV to inspect its structure.")
            return
        index = st.selectbox("Evidence", list(range(len(items))), format_func=lambda i: items[i]["name"])
        if st.button("Verify and inspect table"):
            item = items[index]
            if not registry.verify(item["id"]):
                st.error("Integrity check failed.")
                return
            sep = "\t" if item["name"].lower().endswith(".tsv") else ","
            frame = pd.read_csv(item["path"], sep=sep, nrows=limit, dtype="string")
            st.dataframe([{"column": column, "present": int(frame[column].notna().sum()),
                           "distinct": int(frame[column].nunique())} for column in frame], hide_index=True)
            record(registry, case, "table_structure_inspected", {"evidence_id": item["id"], "rows": len(frame)})
    elif view == "Case LANL exports":
        if require_case(case):
            browse_case_exports(registry, case, limit, rows_panel)
    else:
        kind = st.selectbox("LANL feed", ["auth", "proc", "redteam"])
        file = PROCESSED / kind / "events.parquet"
        browse_lanl(file, read_json(file.with_name("manifest.json")), limit, f"shipped_{kind}", rows_panel)


def privacy_threat(registry, case):
    st.caption("Find identifier fields and review rules that flag possible privacy exposure.")
    source = st.radio("Privacy profile source", ["Synthetic authentication", "LANL sample", "Registered CSV / TSV"],
                      horizontal=True)
    if source == "Synthetic authentication":
        frame = example_frame()
        profile = assess(frame)
        layout = st.columns(3)
        layout[0].metric("Synthetic records", profile["rows"])
        layout[1].metric("Unique quasi-identifier rows", profile["quasi_identifier_singletons"])
        layout[2].metric("Rows in groups below five", profile["groups_under_five_rows"])
        inventory = sensitive_inventory(frame)
        show_frame([{**row, "Detector": "Structured field name", "Suggested action": "Mask or replace"}
                    for row in inventory])
        rows_panel("Exposure and controls", [
            ("Direct exposure", "Mask or pseudonymize direct identifiers"),
            ("Quasi-identifier linkage", "Generalize low-frequency combinations"),
            ("Training membership", "Evaluate a row-level privacy budget"),
        ])
        with st.expander("Heuristic · how this profile is scored"):
            st.caption("A field is flagged when its name matches an identifier rule. Populated cells are counted.")
            st.caption("Linkability is flagged when combinations of hour, access type, device type and location "
                       "occur once or fewer than five times in the synthetic table.")
            st.caption("Retention, sharing and training risks depend on how the investigator uses the data.")
        if case and st.button("Save synthetic privacy profile"):
            digest = synthetic_fingerprint(ROOT)
            reference = ROOT / "dataset/forensic_auth_logs.csv"
            registry.register_reference(case, reference, expected=digest, source="Bundled synthetic authentication")
            Investigation(registry).save_profile(case, digest, {**profile, "scope": "Bundled synthetic CSV"})
            st.success("Case privacy profile saved.")
    elif source == "LANL sample":
        kind = st.selectbox("Feed to profile", ["auth", "proc", "redteam"])
        path = PROCESSED / kind / "events.parquet"
        if path.is_file():
            with pq.ParquetFile(path) as parquet:
                batch = next(parquet.iter_batches(batch_size=250), None)
            if batch:
                st.dataframe(sensitive_inventory(batch.to_pandas(), lanl=True), hide_index=True)
                st.caption("This bounded profile measures de-identified account, computer and process fields.")
        else:
            st.info("Prepare a LANL export to profile this feed.")
    elif require_case(case):
        allowed = {item["id"]: item for item in registry.list("evidence", case)
                   if item["storage"] == "vault" and Path(item["name"]).suffix.lower() in {".csv", ".tsv"}}
        if allowed:
            selected = st.selectbox("Evidence to profile", list(allowed),
                                    format_func=lambda value: allowed[value]["name"])
            item = allowed[selected]
            extra = st.text_input("Additional sensitive columns", max_chars=500,
                                  help="Use comma-separated column names to extend the structured rules.")
            if st.button("Verify and profile evidence"):
                if not registry.verify(selected):
                    st.error("Evidence integrity verification failed.")
                else:
                    delimiter = "\t" if item["name"].lower().endswith(".tsv") else ","
                    frame = pd.read_csv(item["path"], sep=delimiter, nrows=500, dtype="string")
                    profile = {"rows": len(frame), "scope": "First 500 rows of registered table",
                               "fields": sensitive_inventory(frame, {name.strip() for name in extra.split(",")})}
                    Investigation(registry).save_profile(case, item["sha256"], profile)
                    st.session_state["structured_profile"] = (case, selected, profile)
            saved = st.session_state.get("structured_profile")
            if saved and saved[:2] == (case, selected):
                st.dataframe(saved[2]["fields"], hide_index=True)
                st.caption(f'{saved[2]["rows"]:,} sampled rows. The investigation retains aggregate field counts.')
        else:
            st.info("Upload a CSV or TSV in Evidence Management to profile it.")
    with st.expander("Inspect sample text with Presidio", expanded=advanced()):
        if st.session_state.get("ui_presentation"):
            st.caption("Text inspection input is hidden in presentation mode.")
        else:
            text = st.text_area("Text to inspect locally", placeholder="Enter synthetic sample text", max_chars=5000)
            if st.button("Find and mask identifiers", disabled=not text.strip()):
                entities, masked = text_privacy(text)
                if entities:
                    show_frame(entities)
                    st.code(masked, language=None)
                else:
                    st.info("The selected detectors did not find a matching identifier.")
                record(registry, case, "presidio_analysis", {"entities_found": len(entities), "characters": len(text)})
    action("Open privacy protection", "Privacy Protection", key="assessment_protect")


def forensic(registry, case, results):
    st.caption("Rank activity for review, then check the events that support a finding.")
    preset = "Standard analysis"
    if advanced():
        choice = st.radio("Forensic analysis source", ["Authentication", "Process execution"], horizontal=True)
    else:
        preset = st.selectbox("Analysis preset", ["Standard analysis", "Anomaly detection", "Privacy-aware analysis"],
                              help="Choose known-pattern detection, unusual process activity, or a privacy comparison.")
        if preset == "Privacy-aware analysis":
            st.info("Compare a baseline with differentially private training on the synthetic authentication dataset.")
            action("Configure privacy-aware analysis", LAB_PAGE, key="analysis_private", primary=True,
                   lab_start_private=True, **({f"lab_view_pending_{case}": "Configure"} if case else {}))
            definitions("Differential privacy", "Epsilon and delta")
            return
        choice = "Authentication" if preset == "Standard analysis" else "Process execution"
        st.caption("Standard analysis ranks authentication events with a Random Forest."
                   if choice == "Authentication" else CONCEPTS["Anomaly detection"])
    definitions("Anomaly detection", "Risk score", title="How to read the findings")
    dataset = "auth" if choice == "Authentication" else "proc"
    result = results["lanl" if dataset == "auth" else "process"]
    artifact = AUTH_MODEL if dataset == "auth" else None
    if case:
        store = JobStore(registry)
        sha = evidence_meta().get(dataset, {}).get("archive_sha256")
        item = next((row for row in registry.list("evidence", case) if row["sha256"] == sha), None)
        setup = st.container(border=True)
        with setup:
            if item is None:
                st.caption("Add the matching prepared archive to this case to start an analysis.")
                action("Add analysis evidence", "Evidence Management", key="analysis_evidence")
            elif st.button("Queue forensic analysis" if advanced() else "Run analysis", type="primary"):
                _, created = store.submit(case, "forensic_analysis",
                                          {"dataset": dataset, "evidence_id": item["id"], "seed": 42})
                if created:
                    launch_worker(registry, ROOT)
                st.rerun()
            jobs = [job for job in store.list(case, "forensic_analysis", limit=25)
                    if job.config["dataset"] == dataset]
            if jobs:
                by_id = {job.id: job for job in jobs}
                selected = st.selectbox("Analysis run", [*by_id, None],
                                        format_func=lambda key: job_label(by_id[key]) if key else "Archived project benchmark")
                if selected:
                    job = by_id[selected]
                    job_status(store, case, job, ROOT)
                    if not job.result:
                        return
                    result = job.result
                    artifact = registry.root / "models" / f"{job.id}.json" if dataset == "auth" else None
                    st.success("Analysis completed. Review the ranked observations below.")
    elif not advanced():
        st.info("Choose an investigation to queue analysis and save findings.")
        action("Open investigations", "Investigations", key="analysis_case")
        return
    if not advanced() and artifact == AUTH_MODEL:
        st.caption("Archived project benchmark. Run this preset to collect measurements for the current case.")
    if not result:
        st.info("Queue a forensic analysis for the selected dataset.")
        return
    if choice == "Authentication":
        if advanced():
            with st.expander("Cohort splits"):
                show_frame(result["splits"], hide_index=False)
        models = {model["model"]: model for model in result["models"]}
        model = st.selectbox("Model", list(models)) if advanced() else "Random Forest"
        selected = models[model]
        rows_panel("Model validation", [("Observed average precision", f'{selected["observed_label_average_precision"]:.1%}'),
                   ("Known-positive recall", f'{selected["observed_positive_recall"]:.1%}'),
                   ("Unlabelled flag rate", f'{selected["unlabelled_flag_rate"]:.1%}')])
        with st.expander("Global feature importance"):
            importance = selected["top_feature_importance"]
            if importance:
                st.bar_chart(pd.Series(importance,name="Feature importance"),color="#4c8dce",horizontal=True)
            else:
                st.caption("This fitted pipeline does not expose global feature importance.")
        findings = [row for row in result["findings"] if row["model"] == model]
        if st.checkbox("Show flagged findings only"):
            findings = [row for row in findings if row["flagged"]]
        st.caption("Observed-label metrics compare supplied red-team matches and sampled unlabelled records.")
    else:
        findings = result["findings"]
        st.caption("Process Isolation Forest ranks unlabelled events by rarity, relative hour and action.")
    lookup, category = st.columns([1,1])
    query = lookup.text_input("Find source line", placeholder="Filter by source line")
    dataset = "auth" if choice == "Authentication" else "proc"
    kind = "orientation" if dataset == "auth" else "action"
    classification = lambda row: str(row.get("evidence_summary", row).get(kind, "Unknown"))
    available = sorted({classification(item) for item in findings})
    event_type = category.selectbox("Event category", ["All", *available])
    if query:
        findings = [item for item in findings if query.strip() in str(item["source_line"])]
    if event_type != "All":
        findings = [item for item in findings if classification(item) == event_type]
    if findings:
        dates = min(row["timestamp_s"] for row in findings), max(row["timestamp_s"] for row in findings)
        if dates[0] < dates[1]:
            since, until = st.slider("Event time range (LANL relative seconds)", *dates, dates)
            findings = [row for row in findings if since <= row["timestamp_s"] <= until]
    with st.expander("Filter by account or computer"):
        identifier = st.text_input("LANL account or computer identifier", key=f"finding_actor_{dataset}")
    if identifier.strip():
        needle = identifier.strip().casefold()
        raw = archive_records(dataset, [item["source_line"] for item in findings])
        allowed = {row["source_line"] for row in raw if any(needle in str(value).casefold()
                   for field,value in row.items() if "account" in field or "computer" in field)}
        findings = [item for item in findings if item["source_line"] in allowed]
    if findings:
        score_range = min(item["risk_score"] for item in findings), max(item["risk_score"] for item in findings)
        if score_range[0] < score_range[1]:
            lo,hi = st.slider("Score range", *map(float,score_range), tuple(map(float,score_range)))
            findings = [item for item in findings if lo <= item["risk_score"] <= hi]
    show_frame([{"Source line": item["source_line"],
                 "Type": "Red-team reference" if item["ground_truth"] == "known red team" else "Model ranking",
                 "Risk score": item["risk_score"],
                 "Review status": "Flagged by model" if item.get("flagged") else "Ranked observation",
                 **({"Time (s)": item["timestamp_s"], "Model": item.get("model", "Isolation Forest")} if advanced() else {})}
                for item in findings],
               column_config={"Risk score": st.column_config.NumberColumn(format="%.4f", help=CONCEPTS["Risk score"])})
    if not findings:
        st.caption("No ranked observations match the current filters.")
    if findings:
        line = st.selectbox("Inspect finding", [item["source_line"] for item in findings],index=None)
        if line is not None:
            item = next(row for row in findings if row["source_line"]==line)
            provenance(result["archive_sha256"], source=dataset.upper(), line=line, key=f"ai_{dataset}_{line}")
            rows_panel("Finding details", [(k.replace("_"," ").capitalize(),v)
                       for k,v in item.items() if k!="evidence_summary"])
            if "evidence_summary" in item:
                st.dataframe([item["evidence_summary"]],hide_index=True)
                st.caption(f'Flagging threshold for this model is {selected["validation_95th_percentile_threshold"]:.4f}.')
            if dataset == "auth":
                st.button("Inspect related process events", on_click=lambda: st.session_state.update(
                    navigation="Event Correlation", open_auth_context=True, context_lookup_line=int(line)))
            attached = case and any(row["sha256"] == result["archive_sha256"]
                                    for row in registry.list("evidence", case))
            if st.button("Save model finding to investigation", disabled=not attached,
                         help="Requires the corresponding source evidence in the active investigation."):
                title = f"{item.get('model', 'Isolation Forest')} · {dataset} line {line}"
                summary = f"Model score {item['risk_score']:.6f}. Reference status {item['ground_truth']}."
                Investigation(registry).add_finding(
                    case, "Model finding", title, item["timestamp_s"], summary,
                    [(result["archive_sha256"], int(line), dataset)], score=item["risk_score"])
                st.success("Source-linked finding saved.")
    source_note("Prepared LANL evidence", digest=result["archive_sha256"])
    if case:
        action("Continue to privacy protection", "Privacy Protection", key="analysis_protect")
    if advanced() and artifact and artifact.is_file() and artifact.suffix == ".json":
        with st.expander("Score another authentication sample"):
            parquet = pq.ParquetFile(PROCESSED / "auth/events.parquet")
            group = st.number_input("Authentication row group", min_value=0,
                                    max_value=parquet.num_row_groups-1, value=0)
            limit = st.slider("Records to score", min_value=25, max_value=500, value=100)
            if st.button("Score selected records"):
                scored = score_auth_group(PROCESSED, artifact, model, group, limit)
                show_frame(scored)
                record(registry, case, "authentication_scored",
                       {"model": model, "group": group, "rows": len(scored),
                        "archive_sha256": result["archive_sha256"]})


def archive_records(kind, lines, path=None):
    """Read records by evidence line reference with row-group statistics."""
    requested = set(map(int,lines))
    if not requested:
        return []
    parquet = pq.ParquetFile(path or (PROCESSED / kind / "events.parquet"))
    index = parquet.schema_arrow.get_field_index("source_line")
    records = []
    for i in range(parquet.num_row_groups):
        stats = parquet.metadata.row_group(i).column(index).statistics
        if stats and stats.has_min_max and not any(stats.min <= line <= stats.max for line in requested):
            continue
        table = parquet.read_row_group(i)
        mask = pc.is_in(table["source_line"], value_set=pa.array(sorted(requested), type=pa.int64()))
        found = table.filter(mask).to_pylist()
        records.extend(found)
        requested.difference_update(row["source_line"] for row in found)
        if not requested:
            break
    return records


def _correlation_sources(registry, case):
    default = (PROCESSED / "correlation",
               {kind: PROCESSED / kind / "events.parquet" for kind in ("auth", "proc", "redteam")})
    if not case:
        return default
    basis = st.radio("Correlation data", ["Prepared LANL feeds", "Case ingestions"], horizontal=True)
    if basis == "Prepared LANL feeds":
        return default
    store = JobStore(registry)
    feeds = [job for job in store.list(case, "ingest_lanl", limit=100) if job.result]
    with st.expander("Correlate completed case ingestions", expanded=True):
        selection = {}
        for kind in ("auth", "proc", "redteam"):
            options = {job.id: job for job in feeds if job.result["dataset"] == kind}
            value = st.selectbox(f"{kind.title()} ingestion", list(options),
                                 format_func=lambda key: f"{key[:8]} · {options[key].result['valid_records']:,} records")
            if value:
                selection[kind] = value
        window = st.number_input("Correlation interval (seconds)", 0, 3600, 60)
        if st.button("Queue event correlation", disabled=len(selection) != 3):
            _, created = store.submit(case, "correlate_lanl", {"inputs": selection, "window": window})
            if created:
                launch_worker(registry, ROOT)
            st.rerun()
    jobs = {job.id: job for job in store.list(case, "correlate_lanl")}
    if not jobs:
        st.info("Ingest each of the three feeds in Evidence Management to build a case timeline.")
        return None
    focus = st.selectbox("Correlation operation", list(jobs), format_func=lambda key: job_label(jobs[key]))
    selected = jobs[focus]
    job_status(store, case, selected, ROOT)
    if not selected.result:
        return None
    return (registry.root / "correlations" / selected.id,
            {kind: registry.root / "processed" / identifier / "events.parquet"
             for kind, identifier in selected.config["inputs"].items()})


def _authentication_timeline(registry, case, root, feeds):
    with st.form("authentication_timeline"):
        line = st.number_input("Authentication source line", 1, 3_000_000_000,
                               value=st.session_state.get("context_lookup_line", 1))
        window = st.number_input("Process context within seconds", 0, 3600, 60)
        if st.form_submit_button("Find related process events", type="primary"):
            rows = archive_records("auth", [line], feeds["auth"])
            if not rows:
                st.session_state.pop("authentication_context", None)
                st.info("The selected export has no accepted record at that source line.")
                return
            context = authentication_context(feeds["proc"], rows[0], window=window)
            st.session_state["authentication_context"] = (case, str(root), line, window, rows[0], context)
    saved = st.session_state.get("authentication_context")
    if not saved or saved[:2] != (case, str(root)):
        st.caption("Enter a source line from Dataset Explorer or a scored authentication event.")
        return
    _, _, source, seconds, authentication, context = saved
    st.caption(f'{context["total_matches"]:,} exact account/endpoint matches within ±{seconds} seconds '
               f'of authentication line {source:,}. Displaying up to 200 nearest process events.')
    show_frame([authentication], redact=not advanced())
    if context["rows"]:
        show_frame(context["rows"], redact=not advanced())
    else:
        st.info("No process events meet the account, endpoint and time criteria.")
    if case:
        digest = {kind: pq.read_schema(feeds[kind]).metadata[b"archive_sha256"].decode()
                  for kind in ("auth", "proc")}
        refs = [(digest["auth"], int(source), "auth")] + [
            (digest["proc"], event["source_line"], "proc") for event in context["rows"]]
        registered = {item["sha256"] for item in registry.list("evidence", case)}
        if st.button("Save contextual finding", disabled=not all(value in registered for value, _, _ in refs)):
            description = (f"Exact account and endpoint match within ±{seconds} seconds. "
                           f"{context['total_matches']} process events met the rule. "
                           f"{len(context['rows'])} nearest process references saved.")
            Investigation(registry).add_finding(case, "Event correlation", f"Authentication context · line {source}",
                                               authentication["timestamp_s"], description, refs)
            st.success("Contextual finding saved.")


def correlation(registry, case):
    st.caption("Review how authentication and process events relate to stored evidence.")
    selection = _correlation_sources(registry, case)
    if not selection:
        return
    root, feeds = selection
    location = st.radio("Timeline source", ["Red-team reference", "Authentication context"], horizontal=True,
                        index=int(bool(st.session_state.pop("open_auth_context", False))))
    if location == "Authentication context":
        _authentication_timeline(registry, case, root, feeds)
        return
    summary = read_json(root / "manifest.json")
    if not summary:
        st.info("Run LANL correlation before exploring red-team timelines.")
        return
    counts = summary["auth_key_status"]
    rows_panel("Exact authentication matching", [(key.replace("_"," ").capitalize(),n) for key,n in counts.items()])
    path = root / "auth_matches.parquet"
    matches = correlation_index(str(path), path.stat().st_mtime_ns)
    if matches.empty:
        st.info("No red-team reference keys are available in the selected exports.")
        return
    anchors = pq.read_table(feeds["redteam"]).to_pandas().set_index("source_line")
    joined = matches.join(anchors[["account","source_computer","destination_computer"]], on="redteam_anchor_line")
    filters = st.columns([1,1,1])
    status = filters[0].selectbox("Match disposition", ["All", *counts])
    account = filters[1].text_input("Red-team account", placeholder="Filter identifier")
    machine = filters[2].text_input("Source or destination computer", placeholder="Filter identifier")
    time_min, time_max = int(joined.timestamp_s.min()), int(joined.timestamp_s.max())
    low, high = (st.slider("LANL time range (relative seconds)", time_min, time_max, (time_min, time_max))
                 if time_min < time_max else (time_min, time_max))
    mask = joined.timestamp_s.between(low,high)
    if account:
        mask &= joined.account.str.contains(account.strip(),case=False,regex=False,na=False)
    if machine:
        mask &= (joined.source_computer.str.contains(machine.strip(),case=False,regex=False,na=False)
                 | joined.destination_computer.str.contains(machine.strip(),case=False,regex=False,na=False))
    if status != "All":
        mask &= joined.status.eq(status)
    filtered = joined[mask].sort_values("timestamp_s")
    show_frame(filtered[["timestamp_s", "status", "account", "source_computer",
                         "destination_computer", "redteam_anchor_line"]].rename(columns={
                             "timestamp_s": "Relative time (s)", "status": "Match",
                             "redteam_anchor_line": "Red-team source line"}),
               redact=not advanced(), height=240)
    if filtered.empty:
        st.info("No red-team keys match these filters.")
        return
    anchors = filtered.redteam_anchor_line.tolist()
    linked_anchor = st.query_params.get("anchor", "")
    requested = int(linked_anchor) if linked_anchor.isascii() and linked_anchor.isdecimal() and len(linked_anchor) <= 12 else None
    anchor = st.selectbox("Inspect event timeline", anchors,
                          index=anchors.index(requested) if requested in anchors else None)
    if anchor is None:
        st.caption("Select a red-team source line to see the linked events and evidence references.")
        return
    selected = filtered.loc[filtered.redteam_anchor_line.eq(anchor)].iloc[0]
    linked = pq.read_table(root / "process_context.parquet",
                          filters=[("redteam_anchor_line","=",int(anchor))]).to_pylist()
    kinds = st.multiselect("Timeline event types", ["Red team","Authentication","Process execution"],
                           default=["Red team","Authentication","Process execution"])
    refs = {"redteam": list(selected.redteam_source_lines),
            "auth": list(selected.auth_candidate_lines), "proc": [row["process_source_line"] for row in linked]}
    digests = {kind: information["sha256"] for kind, information in summary["inputs"].items()}
    display = {"redteam": "Red team", "auth": "Authentication", "proc": "Process execution"}
    window = summary["process_window_seconds"]
    matches_by_line = {item["process_source_line"]: item for item in linked}
    criteria = {}
    for line in refs["auth"]:
        criteria["auth", line] = [{"Criterion": "Source account and both endpoints match", "Window": "Same second"},
                                  {"Criterion": "Authentication disposition", "Window": selected.status.replace("_", " ")}]
    for line in refs["proc"]:
        link = matches_by_line[line]
        criteria["proc", line] = [
            {"Criterion": "Shared account and endpoint", "Window": link["host_role"]},
            {"Criterion": "Offset from annotation", "Window": f"{link['offset_seconds']:+,} s within ±{window} s"},
        ]
    limit = 200
    events = [(row["timestamp_s"], kind, row) for kind, lines in refs.items() if display[kind] in kinds
              for row in archive_records(kind, lines[:limit], feeds[kind])]
    events.sort(key=lambda event: (event[0], event[2]["source_line"]))
    model_findings = [row for row in Investigation(registry).findings(case)
                      if row["kind"] == "Model finding"] if case else []
    render_timeline(events, digests, selected_anchor=anchor, window=window,
                    criteria=criteria, models=model_findings)
    if case:
        reference_rows = [(digests[kind], int(line), kind) for kind, lines in refs.items() for line in lines]
        registered = {item["sha256"] for item in registry.list("evidence", case)}
        has_sources = all(digest in registered for digest, _, _ in reference_rows)
        if not has_sources:
            st.caption("Register the referenced archives in this investigation to save the finding.")
        if advanced():
            with st.expander("Finding details"):
                title = st.text_input("Finding title", f"Red-team anchor · line {anchor}", max_chars=160)
                notes = st.text_area("Investigator notes", max_chars=600)
        else:
            title, notes = f"Red-team anchor · line {anchor}", ""
        if st.button("Save timeline finding", disabled=not has_sources or not title.strip(), type="primary"):
            description = (f"{selected.status.replace('_', ' ').capitalize()} on the exact authentication key. "
                           f"Process context uses a shared account and endpoint within ±{window} seconds.")
            if notes.strip():
                description += " Investigator notes · " + notes.strip()
            Investigation(registry).add_finding(case, "Event correlation", title,
                                               int(selected.timestamp_s), description, reference_rows)
            st.success("Timeline finding and source references saved.")


def attack(registry, case, results):
    st.caption("Review controlled linkage and membership measurements from synthetic evaluation runs.")
    if not case:
        st.info("Choose an investigation to see its privacy diagnostics.")
    if case:
        cases = [job for job in JobStore(registry).list(case, "evaluation")
                 if job.result and job.config["dataset"] == "synthetic"]
        if cases:
            by_id = {job.id: job for job in cases}
            selected = st.selectbox("Evaluation run", list(by_id), format_func=lambda key: job_label(by_id[key]))
            job = by_id[selected]
            linkage = []
            members = []
            for variant in job.result["variants"]:
                metrics = variant["privacy"]
                if metrics["synthetic_linkage"]:
                    link = {key: value for key, value in metrics["synthetic_linkage"].items() if key != "protection"}
                    linkage.append({"Variant": variant["id"], **link})
                if metrics["membership"]:
                    members.append({"Variant": variant["id"], **metrics["membership"]})
            provenance(job.config["dataset_sha256"], source="Synthetic authentication", key=f"diagnostics_{selected}",
                       metadata={"Run": selected, "Seed": job.config["seed"]})
            one, two = st.tabs(["Record linkage", "Membership inference"])
            with one:
                st.markdown("**Study assumptions**")
                st.caption(job.result["scope"]["linkage"])
                show_frame(linkage)
                definitions("Re-identification", title="About record linkage")
            with two:
                st.markdown("**Study assumptions**")
                st.caption(job.result["scope"]["membership"])
                groups = job.result["cohort"]["splits"]
                if "nonmembers" in groups:
                    st.caption(f"{groups['train']['rows']:,} training records · "
                               f"{groups['nonmembers']['rows']:,} in the separate nonmember pool.")
                if members:
                    table = pd.DataFrame(members).rename(columns={"roc_auc": "ROC AUC",
                                                                   "advantage": "Advantage", "accuracy": "Accuracy"})
                    show_frame(table[["Variant", "ROC AUC", "Advantage", "Accuracy", "held_out_queries"]])
                    st.bar_chart(table.set_index("Variant")[["ROC AUC", "Advantage"]],
                                 y_label="Measured score", x_label="Configuration")
                else:
                    st.info("Run a probability-based synthetic model to collect this diagnostic.")
                definitions("Membership inference", title="About membership inference")
            with st.expander("Study limitations"):
                st.caption("The measurements apply to the stored synthetic diagnostic and its stated query assumptions.")
        else:
            st.info("Run a synthetic evaluation to collect this investigation's diagnostic measurements.")
        st.button("Open Evaluation Lab", on_click=lambda: st.session_state.update(navigation=LAB_PAGE))
    data = results["synthetic"]
    if data and advanced():
        with st.expander("Archived project privacy benchmark"):
            st.dataframe(data["linkage"], hide_index=True)
            st.dataframe(flattened(data["models"], "membership"), hide_index=True)
            st.caption("Auxiliary information and identities are generated for this benchmark.")


def utility(results):
    data = results["synthetic"]
    if not data:
        st.info("Run the synthetic experiment to populate utility measurements.")
        return
    frame = flattened(data["models"], "utility")
    for name in ("epsilon_target", "epsilon_spent", "delta"):
        frame[name] = [model[name] for model in data["models"]]
    st.dataframe(frame.drop(columns="advantage"), hide_index=True)
    st.bar_chart(frame.set_index("model")[["f1", "recall", "roc_auc"]])
    dp = frame.dropna(subset=["epsilon_spent"])
    if not dp.empty:
        st.line_chart(dp.set_index("epsilon_spent")[["f1","accuracy"]], x_label="Accounted epsilon",
                      y_label="Synthetic holdout metric", color=["#4c8dce","#43b5a0"])
    transforms = data.get("data_transforms", [])
    if transforms:
        st.dataframe([{"Mechanism":row["mechanism"],"Records compared":row["rows"],
                       "Identical model inputs":row["model_inputs_preserved"]} for row in transforms],hide_index=True)
    st.caption("DP-SGD uses one synthetic training row as the privacy unit. Utility measures recovery of synthetic rules.")


def performance(registry, case, results, sources):
    st.caption("Compare measured training, inference and ingestion costs.")
    with st.expander("Current environment"):
        rows_panel("Workspace environment", [
            ("Operating system", platform.platform()), ("Python", platform.python_version()),
            ("CPU", f"{platform.machine()} · {psutil.cpu_count(logical=True)} logical cores"),
            ("Memory", f"{psutil.virtual_memory().total / 1024**3:.1f} GiB"),
        ])
    if case:
        jobs = [job for job in JobStore(registry).list(case, limit=25) if job.result]
        evaluation = [job for job in jobs if job.kind == "evaluation"]
        ingestion = [job for job in jobs if job.kind == "ingest_lanl"]
        if evaluation or ingestion:
            st.header("Investigation measurements")
        if evaluation:
            index = {job.id: job for job in evaluation}
            selected = st.selectbox("Evaluation run", list(index), format_func=lambda key: job_label(index[key]))
            costs = pd.DataFrame([{"Variant": row["Variant"], "Training (s)": row["train_seconds"],
                                   "Inference (s)": row["inference_seconds"], "Peak RSS (MiB)": row["train_peak_rss_mib"],
                                   "Training CPU (%)": row["train_mean_cpu_percent"]}
                                  for row in comparison_rows([index[selected]])])
            show_frame(costs)
            st.bar_chart(costs[["Variant", "Training (s)", "Inference (s)"]].set_index("Variant"),
                         x_label="Configuration", y_label="Elapsed time (seconds)")
        if ingestion:
            show_frame([{"Run": job.id[:8], "Feed": job.result["dataset"],
                         "Seconds": job.result["elapsed_seconds"], "Accepted rows": job.result["valid_records"],
                         "Rows/s": round(job.result["valid_records"] / job.result["elapsed_seconds"])
                         if job.result["elapsed_seconds"] > 0 else None} for job in ingestion])
        if not evaluation and not ingestion:
            st.info("No completed measurements are available for this investigation.")
            action("Open Evaluation Lab", LAB_PAGE, key="performance_lab")
    if not advanced():
        return
    st.caption("Archived project measurements")
    events = [{"stage": f"LANL {kind} export", "seconds": m.get("elapsed_seconds"),
               "events per second": round(m["valid_records"]/max(m["elapsed_seconds"], .001)),
               "peak RSS MiB": round(m.get("peak_process_rss_bytes", 0)/1024**2, 1)}
              for kind, m in sources.items() if m]
    st.header("Ingestion")
    st.dataframe(events, hide_index=True)
    st.header("Model training and analysis")
    training = [{"stage": model["model"], **model["performance"]}
                for category in ("synthetic", "lanl") for model in results[category].get("models", [])]
    training.extend({"stage": f"Synthetic {row['mechanism']} transform", **row["performance"]}
                    for row in results["synthetic"].get("data_transforms", []))
    if results["lanl"]:
        training.append({"stage": "LANL cohort sampling", **results["lanl"]["cohort_performance"]})
    if results["process"]:
        training.append({"stage": "Process sampling and anomaly analysis", **results["process"]["performance"]})
    if training:
        st.dataframe(training, hide_index=True)
        st.bar_chart(pd.DataFrame(training).set_index("stage")["seconds"])


def settings(registry, case):
    st.caption("Adjust how the workspace displays data and review local configuration.")
    st.header("Appearance")
    left, right = st.columns(2)
    with left:
        st.session_state.density_setting = st.session_state.ui_density
        st.selectbox("Table density", ["Compact", "Default", "Comfortable"], key="density_setting",
                     on_change=lambda: st.session_state.update(ui_density=st.session_state.density_setting))
    with right:
        st.session_state.motion_setting = st.session_state.ui_motion
        st.toggle("Reduce motion", key="motion_setting",
                  on_change=lambda: st.session_state.update(ui_motion=st.session_state.motion_setting),
                  help="Disables interface transitions. Your system reduced-motion setting is also respected.")
        st.caption("Use Present in the toolbar to mask identifiers in supported views.")
    st.header("Local configuration")
    rows_panel("Workspace", [
        ("HMAC key", "Configured" if os.environ.get("PRIVFORENSICS_HMAC_KEY") else "Unavailable"),
        ("Storage", str(STATE)), ("Browser uploads", "128 MiB"), ("Bind address", "Loopback"),
        ("Audit chain", "Valid" if registry.checked_audit() else "Verification failed"),
    ])
    if case:
        workspace = Investigation(registry)
        defaults = workspace.privacy_defaults(case)
        with st.form(f"privacy_defaults_{case}"):
            st.header("Investigation protection defaults")
            mechanism = st.selectbox("Default protection", ["mask", "hmac"],
                                     index=int(defaults["mechanism"] == "hmac"))
            scope = st.selectbox("Default HMAC scope", ["workspace", "case"],
                                 index=int(defaults["scope"] == "case"))
            if st.form_submit_button("Save protection defaults"):
                workspace.set_privacy_defaults(case, mechanism, scope)
                st.success("Investigation defaults saved.")
    st.caption("Keys are supplied by the local environment and are never displayed here.")


def audit_history(registry, case):
    st.caption("Check custody, job and report actions recorded by the local workspace.")
    rows_panel("Audit integrity", [("Stored chain", "Valid" if registry.checked_audit() else "Verification failed")])
    entries = recent_entries(registry, case)
    query = st.text_input("Search audit history", placeholder="Action, evidence ID or case ID")
    if not entries:
        st.info("There are no audit entries for this selection.")
        return
    first, second = st.columns(2)
    statuses = first.multiselect("Operation status", ["Recorded", "Verified", "Failed"])
    actions = second.multiselect("Operation", sorted({item["Action"] for item in entries}))
    with st.expander("Date filter"):
        days = [date.fromisoformat(item["UTC"][:10]) for item in entries]
        interval = st.date_input("Dates (UTC)", (min(days), max(days)), min_value=min(days), max_value=max(days))
    filtered = [item for item in entries if (not statuses or item["Status"] in statuses)
                and (not actions or item["Action"] in actions)
                and (len(interval) != 2 or interval[0] <= date.fromisoformat(item["UTC"][:10]) <= interval[1])
                and query.casefold() in " ".join(map(str, item.values())).casefold()]
    if not filtered:
        st.info("No audit entries match these filters.")
        return
    page = st.number_input("Audit page", 1, ceil(len(filtered) / 25), 1)
    shown = filtered[(page - 1) * 25:page * 25]
    show_frame(shown, height=365)
    with st.expander("Inspect an audit entry"):
        index = st.selectbox("Audit entry", list(range(len(shown))),
                             format_func=lambda i: f"{shown[i]['UTC']} · {shown[i]['Action']}")
        item = shown[index]
        rows_panel("Recorded details", [(name, value) for name, value in item.items() if value])
        if case and item["Evidence"]:
            action("Open evidence record", "Evidence Management", key="audit_evidence",
                   **{f"inspect_evidence_{case}": item["Evidence"]})
    st.download_button("Download audit CSV", safe_csv(filtered), "audit-history.csv", "text/csv", on_click="ignore")

def main():
    registry = Registry(STATE)
    page, case = render_shell(registry)
    sources = evidence_meta()
    results = {key: read_json(RESULTS / f"{key}.json") for key in ("synthetic", "lanl", "process")}
    st.title("Investigation Overview" if page == "Dashboard" else LAB_PAGE if page == LAB_PAGE else visible_label(page))
    pages = {
        "Dashboard": lambda:render_overview(registry,case,sources,recent_entries),
        "Investigations": lambda:investigations(registry,case),
        "Evidence Management": lambda:render_evidence(registry,case,sources,ROOT,require_case,rows_panel,recent_entries),
        "Dataset Explorer": lambda:explorer(registry,case),
        "Event Correlation": lambda:correlation(registry,case),
        "Privacy Threat Analysis": lambda:privacy_threat(registry,case),
        "AI Forensic Analysis": lambda:forensic(registry,case,results),
        "Attack Simulation": lambda:attack(registry,case,results),
        "Privacy Protection": lambda:render_protection(registry,case,PROCESSED,example_frame,safe_csv),
        LAB_PAGE: lambda:render_lab(registry,case,ROOT,sources,lambda:utility(results)),
        "Performance Analysis": lambda:performance(registry,case,results,sources),
        "Reports": lambda:render_reports(registry,case,PROCESSED,results,require_case,safe_csv),
        "Audit History": lambda:audit_history(registry,case),
        "Settings": lambda:settings(registry,case),
        "Design system": style_guide,
    }
    try:
        pages[page]()
    except (ValueError, OSError) as exc:
        st.error(str(exc))
    data_scope = "Case records and stored measurements" if case else "Workspace overview"
    st.html(f'<div class="pf-statusbar"><span>Local registry connected</span><span>{data_scope}</span></div>')


if __name__ == "__main__":
    main()
