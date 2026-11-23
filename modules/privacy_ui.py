"""Apply existing privacy transforms and preview their output safely."""
from time import perf_counter
from pathlib import Path
import os

import pandas as pd
import pyarrow.parquet as pq
import streamlit as st

from .investigation import Investigation
from .jobs import JobStore
from .lab_ui import LAB_PAGE
from .privacy import IDENTIFIERS, protect, protect_lanl
from .ui import CONCEPTS, action, advanced, definitions, panel, redacted_preview, show_frame


@st.dialog("Export transformed records")
def _export(registry, case, request, output, csv_bytes):
    _, dataset, _, policy, _ = request
    st.caption(f"{len(output):,} records from {dataset}. "
               "The export applies the field actions shown below. Other event attributes remain in the file.")
    show_frame([{"Field": field, "Action": name} for field, name in policy])
    confirmed = st.checkbox("I reviewed the fields in this export")
    st.download_button("Download protected CSV", csv_bytes(output.to_dict("records")),
                       "protected-records.csv", "text/csv", disabled=not confirmed,
                       on_click=registry.record, args=(case, "protected_data_exported",
                             {"dataset": dataset, "rows": len(output), "fields": dict(policy)}))


def _private_training(registry, case):
    st.caption("Differential privacy applies during model training.")
    action("Open Evaluation Lab", LAB_PAGE, key="protection_dp_lab", lab_start_private=True)
    definitions("Differential privacy", "Epsilon and delta")
    if case:
        runs = [job for job in JobStore(registry).list(case, "evaluation", limit=25) if job.result]
        rows = [{"Run": job.id[:8], "Variant": variant["id"],
                 "Privacy budget ε": variant["privacy"]["epsilon_spent"],
                 "Delta": variant["privacy"]["delta"], "Noise multiplier": variant["privacy"]["noise_multiplier"]}
                for job in runs for variant in job.result["variants"] if "epsilon_spent" in variant["privacy"]]
        if rows:
            show_frame(rows)
            return
    st.info("Completed private training runs appear here.")


def render_protection(registry, case, processed, example_frame, csv_bytes):
    workspace = st.radio("Protection workspace", ["Record transforms", "Differential privacy"], horizontal=True)
    if workspace == "Differential privacy":
        _private_training(registry, case)
        return
    defaults = Investigation(registry).privacy_defaults(case)
    st.caption("Preview how selected identifiers change before exporting records.")
    source = st.selectbox("Records to protect", ["Synthetic authentication", "LANL auth", "LANL proc", "LANL redteam"])
    configured = bool(os.environ.get("PRIVFORENSICS_HMAC_KEY"))
    kind = source.split()[1] if source.startswith("LANL") else None
    file = Path(processed) / kind / "events.parquet" if kind else None
    group, digest, fields = 0, None, list(IDENTIFIERS)
    if file and not file.is_file():
        st.info("This feed is unavailable. Select a prepared feed or the synthetic dataset.")
        return
    if file:
        with pq.ParquetFile(file) as reader:
            if not reader.num_row_groups:
                st.info("This feed has no accepted records to transform.")
                return
            digest = reader.schema_arrow.metadata[b"archive_sha256"].decode()
            fields = [name for name in reader.schema_arrow.names if any(
                word in name for word in ("account", "computer", "process"))]
            if advanced():
                group = st.number_input("Source row group", 0, reader.num_row_groups - 1, 0)
        st.caption("A LANL preview covers up to 250 records from the selected group.")

    builder, preview, impact = st.columns([1.08, 1.38, .85], gap="medium")
    with builder:
        st.header("Field policy")
        captions = {"mask": "Mask", "hmac": "Replace with keyed token", "drop": "Omit"}
        if advanced():
            available = ["mask", "hmac", "drop"] if configured else ["mask", "drop"]
            policy = {field: st.selectbox(field.replace("_", " "), available,
                                          index=available.index(defaults["mechanism"]) if defaults["mechanism"] in available else 0,
                                          format_func=captions.get, key=f"policy_{source}_{field}")
                      for field in fields}
        else:
            modes = ["mask", "hmac"] if configured else ["mask"]
            mode = st.radio("Protection mechanism", modes,
                            index=modes.index(defaults["mechanism"]) if defaults["mechanism"] in modes else 0,
                            format_func=captions.get)
            policy = dict.fromkeys(fields, mode)
        if not configured:
            st.caption("Keyed tokens become available when an HMAC key is configured for this workspace.")
        scope = None
        if "hmac" in policy.values() and case:
            choice = st.selectbox("Token linking scope", ["workspace", "case"],
                                  index=int(defaults["scope"] == "case"),
                                  format_func={"workspace": "Within this workspace", "case": "Within this investigation"}.get,
                                  help=CONCEPTS["Pseudonymization"])
            scope = f"investigation/{case}" if choice == "case" else None
        request = (case, source, group, tuple(policy.items()), scope)
        if st.button("Protect selected records", type="primary"):
            start = perf_counter()
            if file:
                with pq.ParquetFile(file) as reader:
                    frame = next(reader.iter_batches(batch_size=250, row_groups=[group])).to_pandas()
                transform = protect_lanl
            else:
                frame = example_frame()
                transform = protect
            output = frame
            for name in ("mask", "hmac"):
                columns = [field for field, value in policy.items() if value == name]
                if columns:
                    output = transform(output, name, fields=columns, scope=scope)
            output = output.drop(columns=["source_line", *(field for field, name in policy.items() if name == "drop")],
                                 errors="ignore")
            preview_rows = []
            for field, method in policy.items():
                original = frame[field].dropna()
                if original.empty:
                    before, after = "No populated value", "—"
                else:
                    original_index = original.index[0]
                    before = redacted_preview(original.iloc[0])
                    after = ("Omitted" if method == "drop" else
                             str(output.at[original_index, field])[:16] + "…" if method == "hmac" else
                             str(output.at[original_index, field]))
                preview_rows.append({"Field": field, "Before · redacted": before, "After": after})
            st.session_state.protected_sample = (request, output, preview_rows)
            methods = sorted(set(policy.values()))
            details = {"mechanism": " + ".join(methods), "dataset": source, "scope": "case" if scope else "workspace",
                       "rows": len(output), "seconds": round(perf_counter() - start, 4), "fields": policy}
            if digest:
                details.update(archive_sha256=digest, row_group=group)
            registry.record(case, "privacy_transform", details)
    saved = st.session_state.get("protected_sample")
    with preview:
        st.header("Safe preview")
        if saved and saved[0] == request and len(saved) == 3:
            _, output, rows = saved
            if st.session_state.get("ui_presentation"):
                rows = [{**row, "Before · redacted": "••••", "After": "••••"} for row in rows]
            show_frame(rows, height=min(280, 82 + 32 * len(rows)))
            st.success(f"Applied the selected field actions to {len(output):,} records.")
            if advanced():
                with st.expander("Sample transformed records"):
                    show_frame(output.head(30))
            if st.button("Review CSV export"):
                _export(registry, case, request, output, csv_bytes)
        else:
            st.info("Apply the field policy to see examples of the changed values.")
    with impact:
        panel("Expected scope", [("Fields selected", len(fields)), ("Mask", list(policy.values()).count("mask")),
                                 ("Keyed tokens", list(policy.values()).count("hmac")),
                                 ("Omit", list(policy.values()).count("drop")),
                                 ("HMAC key", "Configured" if configured else "Unavailable")])
        st.caption("Repeated keyed tokens can still link records within their scope.")
    definitions("Masking", "Pseudonymization", title="How these transformations work")
