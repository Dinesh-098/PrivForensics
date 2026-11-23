"""Evidence registration, integrity jobs and derived data browsing."""
import json
from itertools import islice
from math import ceil
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import streamlit as st

from .jobs import JobStore, launch_worker
from .lab_ui import job_status
from .processing import PROCESSING_LABELS
from .ui import CONCEPTS, action, advanced, definitions, empty_state, provenance, show_frame, source_note


def _submit(store, case, kind, configuration, root, *, parent_id=None):
    job_id, created = store.submit(case, kind, configuration, parent_id=parent_id)
    if created:
        launch_worker(store.registry, root)
    st.session_state[f"evidence_focus_{case}"] = job_id
    st.rerun()


def _jobs(store, case, root):
    history = [job for job in store.list(case, limit=100) if job.kind in PROCESSING_LABELS]
    if not history:
        return
    st.header("Processing history")
    by_id = {job.id: job for job in history}
    key = f"evidence_job_{case}"
    if focus := st.session_state.pop(f"evidence_focus_{case}", None):
        st.session_state[key] = focus
    selected = st.selectbox("Inspect operation", list(by_id), key=key, format_func=lambda value: (
        f"{PROCESSING_LABELS[by_id[value].kind]} · {by_id[value].status} · {value[:8]}"))
    job = by_id[selected]
    job_status(store, case, job, root)
    if job.result:
        if job.kind == "verify_evidence":
            message = ("Evidence matches the registered SHA-256."
                       if job.result["matches"] else "Evidence is missing, changed, or differs from the registered SHA-256.")
            st.success(message) if job.result["matches"] else st.error(message)
        elif job.kind == "ingest_lanl":
            st.success(f"{job.result['valid_records']:,} valid records published to Parquet.")
            st.caption(f"{job.result['lines_read']:,} physical source lines · {job.result['elapsed_seconds']:.3f} s")
            st.button("Browse exports", on_click=lambda: st.session_state.update(navigation="Dataset Explorer"))
        else:
            st.success("Evidence registered. File details and the fingerprint are ready to review.")
    if job.status in {"failed", "interrupted", "cancelled"}:
        if st.button("Retry this operation", key=f"retry_{job.id}"):
            _submit(store, case, job.kind, job.config, root, parent_id=job.id)


def _size(size):
    for value, unit in ((1024**3, "GiB"), (1024**2, "MiB"), (1024, "KiB")):
        if size >= value:
            return f"{size / value:,.1f} {unit}"
    return f"{size:,} B"


def render_evidence(registry, case, sources, root, require_case, rows_panel, recent_entries):
    if not require_case(case):
        st.button("Open Investigations", on_click=lambda: st.session_state.update(navigation="Investigations"))
        rows_panel("Available LANL sources", [(f"{kind}.txt.gz", "Processed" if info else "Unavailable")
                   for kind, info in sources.items()])
        return
    store = JobStore(registry)
    st.header("Register evidence")
    st.caption("Upload a small file or register a dataset already on this computer.")
    if advanced():
        method = st.radio("Registration method", ["Upload", "Local file reference", "Prepared LANL archives"],
                          horizontal=True)
    else:
        method = st.radio("Registration method", ["Upload", "Register existing data"], horizontal=True)
        if method == "Register existing data":
            method = st.selectbox("Local data", ["Prepared LANL archives", "Local file reference"],
                                  format_func={"Prepared LANL archives": "Prepared LANL dataset",
                                               "Local file reference": "File on this computer"}.get)
    if method == "Upload":
        upload = st.file_uploader("Upload evidence", help="The browser upload limit is 128 MiB.")
        with st.expander("Source and acquisition"):
            origin = st.text_input("Evidence source", max_chars=250)
            acquisition = st.text_area("Acquisition details", max_chars=2000)
        if st.button("Preserve and register upload", disabled=upload is None):
            upload.seek(0)
            identifier = registry.upload(case, upload.name, upload, source=origin, acquisition=acquisition)
            st.success(f"Evidence registered · {identifier}")
    elif method == "Local file reference":
        with st.form("register_reference"):
            path = st.text_input("Absolute file path", placeholder="/path/to/authorized/logs.txt.gz", max_chars=4096)
            origin = st.text_input("Evidence source", max_chars=250)
            acquisition = st.text_area("Acquisition details", max_chars=2000)
            if st.form_submit_button("Queue local reference registration", type="primary"):
                if not Path(path.strip()).is_absolute():
                    st.error("Enter an absolute path to the evidence file.")
                else:
                    _submit(store, case, "register_reference",
                            {"path": path.strip(), "source": origin, "acquisition": acquisition}, root)
        st.caption("The worker streams SHA-256 from the original file and saves a reference.")
    else:
        feeds = {kind: manifest["archive_sha256"] for kind, manifest in sources.items() if manifest}
        chosen = st.multiselect("Archives to register", list(feeds),
                                default=["redteam"] if "redteam" in feeds else [],
                                format_func=lambda kind: f"{kind}.txt.gz")
        if st.button("Queue LANL archive registration", disabled=not chosen):
            _submit(store, case, "register_lanl", {"feeds": {kind: feeds[kind] for kind in chosen}}, root)
        st.caption("The worker checks each archive against the existing export fingerprint.")

    items = registry.list("evidence", case)
    if not items:
        empty_state("No evidence has been added to this investigation.", "Choose a registration method above to get started.")
        _jobs(store, case, root)
        return
    entries = recent_entries(registry, case)
    history = registry.list("audit", case)
    checked = {details["id"]: (details["valid"], row["stamp"][:19].replace("T", " ") + " UTC")
               for row in history if row["action"] == "integrity_checked"
               for details in [json.loads(row["details"])]}
    evidence_rows = []
    for item in items:
        passed, stamp = checked.get(item["id"], (None, "—"))
        row = {"File": item["name"], "Size": _size(item["size"]), "Evidence": "Registered",
               "Integrity": {True: "Verified", False: "Mismatch", None: "Awaiting check"}[passed],
               "Last checked": stamp}
        if advanced():
            row.update({"Source": item["source"], "Evidence ID": item["id"], "Storage": item["storage"]})
        evidence_rows.append(row)
    show_frame(evidence_rows, height=min(94 + 32 * len(evidence_rows), 350))
    indexed = {item["id"]: item for item in items}
    current = st.selectbox("Inspect evidence", list(indexed),
                           format_func=lambda item: f"{indexed[item]['name']} · {item[:8]}",
                           key=f"inspect_evidence_{case}")
    item = indexed[current]
    with st.container(border=True, key="evidence_inspector"):
        st.header(item["name"])
        passed, _ = checked.get(item["id"], (None, "—"))
        if passed is False:
            st.error("Integrity check failed. Confirm the file path and compare with the original evidence before using this file.")
        elif passed:
            st.caption("Last check matched the registered fingerprint.")
        else:
            st.caption("This file is registered. Verify it before relying on it in an investigation.")
        cols = st.columns([1, 2], vertical_alignment="center")
        with cols[0]:
            if st.button("Queue SHA-256 verification" if advanced() else "Verify file integrity",
                         key=f"verify_{item['id']}", type="primary", help=CONCEPTS["Evidence integrity"]):
                _submit(store, case, "verify_evidence", {"evidence_id": item["id"]}, root)
        with cols[1]:
            provenance(item["sha256"], source="Registered file", key=item["id"],
                       metadata={"Evidence ID": item["id"], "Storage": item["storage"]})
        with st.expander("File details and custody"):
            rows_panel("Evidence metadata", [("File size", _size(item["size"])),
                      ("Source", item["source"] or "Unspecified"), ("Registration", item["created"])])
            if item["acquisition"]:
                st.text(item["acquisition"])
            operations = [row for row in entries if row["Evidence"] == item["id"]]
            if operations:
                show_frame([{"Time (UTC)": row["UTC"], "Actor": row["Actor"],
                             "Action": row["Action"].capitalize(), "Status": row["Status"]} for row in operations])
            else:
                st.caption("No custody entries.")
        if passed:
            action("Continue to AI analysis", "AI Forensic Analysis", key="evidence_to_analysis")
    definitions("Evidence integrity", "SHA-256", title="How file verification works")
    if advanced():
        st.caption("Custody history is an application audit record.")
    if item["name"].casefold().endswith(".gz"):
        with st.expander("Ingest registered LANL gzip"):
            kind = st.selectbox("LANL schema", ["auth", "proc", "redteam"])
            full = st.checkbox("Ingest the entire archive", value=False,
                               help="Full runs can take significant time and disk space.")
            limit = None if full else st.number_input("Maximum source lines", 1, 1_000_000, 10_000, step=1000)
            if st.button("Queue LANL ingestion", key=f"ingest_{item['id']}"):
                _submit(store, case, "ingest_lanl", {"evidence_id": item["id"],
                                                    "dataset": kind, "limit": limit}, root)
    _jobs(store, case, root)


@st.cache_data(max_entries=32, show_spinner=False)
def _read_page(filename, stamp, group, columns, limit, page):
    del stamp
    with pq.ParquetFile(filename) as parquet:
        # Read through only the preceding batches in the selected row group.
        batches = parquet.iter_batches(batch_size=limit, row_groups=[group], columns=columns)
        batch = next(islice(batches, page - 1, page), None)
    return batch.to_pandas() if batch else pa.table({col: [] for col in columns}).to_pandas()


def browse_lanl(file, manifest, limit, key, rows_panel):
    if not file.is_file():
        st.info("The Parquet export is unavailable.")
        return
    with pq.ParquetFile(file) as parquet:
        schema = parquet.schema_arrow
        groups = parquet.num_row_groups
        total = parquet.metadata.num_rows
        if groups:
            group = st.number_input("Parquet row group", 0, groups - 1, 0, key=f"group_{key}")
            count = parquet.metadata.row_group(group).num_rows
        else:
            group, count = 0, 0
    visible = tuple(name for name in schema.names
                    if "account" not in name and "computer" not in name and name != "process")
    st.caption(f"Read budget · up to {limit} records per page from one Parquet row group.")
    sample, schema_tab, distributions, quality, trace = st.tabs(
        ["Sample records", "Schema", "Distributions", "Validation", "Provenance"])
    bounded = None
    with sample:
        if not count:
            st.info("This export contains no accepted records.")
        else:
            page = st.number_input("Page within row group", 1, ceil(count / limit), 1,
                                   key=f"page_{key}_{group}_{limit}")
            bounded = _read_page(str(file), file.stat().st_mtime_ns, group, visible, limit, page)
            filtered = bounded
            times = bounded.timestamp_s
            with st.expander("Filter this page"):
                search = st.text_input("Find a visible value", key=f"search_{key}")
                if search.strip():
                    mask = bounded.astype("string").apply(
                        lambda series: series.str.contains(search.strip(), regex=False, case=False, na=False)).any(axis=1)
                    filtered = filtered.loc[mask]
                if len(times) and times.min() < times.max():
                    bounds = int(times.min()), int(times.max())
                    start, end = st.slider("Relative time in seconds", *bounds, bounds, key=f"time_{key}_{group}_{page}")
                    filtered = filtered[filtered.timestamp_s.between(start, end)]
            show_frame(filtered, height=min(350, 85 + 32 * len(filtered)))
            source_note("Bounded page from the prepared export", sample=len(bounded),
                        digest=schema.metadata[b"archive_sha256"].decode())
            st.caption(f"{len(filtered):,} matching rows on this page · {total:,} accepted across this export.")
    with schema_tab:
        descriptions = {"source_line": "One-based physical source line",
                        "timestamp_s": "Seconds since the LANL dataset epoch"}
        show_frame([{"Field": field.name, "Type": str(field.type),
                     "Nulls on page": int(bounded[field.name].isna().sum()) if bounded is not None
                     and field.name in bounded else None,
                     "Sensitivity": "Identifier" if field.name not in visible else "Event metadata",
                     "Meaning": descriptions.get(field.name, field.name.replace("_", " ").capitalize())}
                    for field in schema])
    with distributions:
        if bounded is not None and not bounded.empty:
            histogram = (bounded.timestamp_s // 3600).value_counts().sort_index().rename("Events")
            st.bar_chart(histogram, x_label="Relative hour", y_label="Events on this page", color="#4C8DCE")
            source_note("Sample page distribution", sample=len(bounded))
        else:
            st.caption("Choose a page of records to see its event distribution.")
    with quality:
        rejected = manifest.get("rejected_by_reason", {})
        rows_panel("Validation", [("Read through gzip EOF", str(manifest.get("gzip_read_through_eof", False))),
                   ("Source rows", manifest.get("lines_read", "Unavailable")),
                   ("Rejected rows", sum(rejected.values()))])
        if rejected:
            show_frame([{"Reason": reason, "Rows": n} for reason, n in rejected.items()])
            path = file.with_name("rejections.jsonl")
            if path.is_file():
                with path.open(encoding="utf-8") as stream:
                    errors = [json.loads(entry) for entry in islice(stream, 25)]
                if errors:
                    with st.expander("First 25 rejected source lines"):
                        show_frame(errors)
    with trace:
        rows_panel("Source metadata", [("Scope", manifest.get("scope", "Unavailable")),
                   ("Compressed bytes", manifest.get("archive_bytes", "Unavailable")),
                   ("Schema version", manifest.get("schema_version", "Unavailable"))])
        provenance(schema.metadata[b"archive_sha256"].decode(), source="Original archive", key=f"browse_{key}")


def browse_case_exports(registry, case, limit, rows_panel):
    jobs = [job for job in JobStore(registry).list(case, "ingest_lanl", limit=100) if job.result]
    if not jobs:
        st.info("Queue a LANL ingestion job in Evidence Management to browse its export.")
        return
    by_id = {job.id: job for job in jobs}
    selected = st.selectbox("Completed ingestion", list(by_id), format_func=lambda key: (
        f"{by_id[key].result['dataset']} · {by_id[key].result['valid_records']:,} rows · {key[:8]}"))
    job = by_id[selected]
    browse_lanl(registry.root / "processed" / job.id / "events.parquet",
                job.result, limit, job.id, rows_panel)
