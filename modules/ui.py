"""Shared presentation components for the investigation console."""
import base64
from functools import lru_cache
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st


APP_ROOT = Path(__file__).resolve().parents[1]
CONCEPTS = {
    "SHA-256": "A fingerprint calculated from a file's bytes. The same bytes produce the same fingerprint.",
    "Evidence integrity": "An integrity check recomputes the fingerprint and compares it with the registered one.",
    "Masking": "Masking replaces selected values with placeholders.",
    "Pseudonymization": "A secret key generates replacement identifiers. Repeated values can still be linked within the selected scope.",
    "Differential privacy": "DP-SGD clips per-record gradients and adds noise during training. The accounted bound applies to the training mechanism and its stated privacy unit.",
    "Epsilon and delta": "Epsilon (ε) and delta (δ) describe a privacy bound. Lower epsilon generally gives a stronger bound when delta, privacy unit and other assumptions are comparable.",
    "Anomaly detection": "An anomaly model ranks unusual observations. An investigator reviews them against supporting evidence.",
    "Risk score": "A model's score orders records for review. The scoring scale and threshold depend on the model.",
    "Precision": "Of the labelled records flagged by the model, the fraction labelled positive.",
    "Recall": "Of the known positive records, the fraction flagged by the model.",
    "F1": "The harmonic mean of precision and recall. It is high when both are high.",
    "Membership inference": "A controlled diagnostic measures whether model confidence separates training records from held-out records.",
    "Re-identification": "A controlled linkage diagnostic measures when auxiliary information matches records to known test identities.",
}

LABELS = {
    "Dashboard": "Overview", "Evidence Management": "Evidence",
    "AI Forensic Analysis": "AI analysis", "Privacy Protection": "Privacy protection",
    "Privacy–Utility Evaluation Lab": "Evaluation Lab", "Performance Analysis": "Performance",
    "Attack Simulation": "Privacy diagnostics", "Privacy Threat Analysis": "Privacy assessment",
}
DENSITIES = {"Compact": 28, "Default": 32, "Comfortable": 40}
DISPLAY_IDS = {"account", "computer", "process", "pid", "process_id", "userid", "user_id",
               "email", "email_address", "ip_address", "phone", "phone_number", "device_id",
               "source_account", "destination_account", "source_computer", "destination_computer"}


@lru_cache(maxsize=1)
def font_faces():
    declarations = []
    for stem, name, weight in (
        ("inter-latin", "Inter", "100 900"),
        ("ibm-plex-mono-latin", "IBM Plex Mono", "400"),
    ):
        path = APP_ROOT / "assets/fonts" / f"{stem}.woff2"
        if path.is_file():
            encoded = base64.b64encode(path.read_bytes()).decode()
            declarations.append(f"@font-face{{font-family:'{name}';font-style:normal;font-weight:{weight};"
                                f"font-display:swap;src:url(data:font/woff2;base64,{encoded}) format('woff2');}}")
    return "<style>" + "".join(declarations) + "</style>" if declarations else ""


def visible_label(page):
    return LABELS.get(page, page)


def advanced():
    return st.session_state.get("ui_mode") == "Advanced"


def row_height():
    return DENSITIES.get(st.session_state.get("ui_density"), 32)


def go(page, **state):
    st.session_state.update(navigation=page, **state)


def action(label, page, *, key, primary=False, **state):
    return st.button(label, key=key, on_click=go, args=(page,), kwargs=state,
                     type="primary" if primary else "secondary")


def empty_state(title, detail=None):
    st.info(title)
    if detail:
        st.caption(detail)


def panel(title, rows):
    values = "".join(f'<div class="pf-row"><span>{escape(str(label))}</span>'
                     f'<strong>{escape(str(value))}</strong></div>' for label, value in rows)
    st.html(f'<section class="pf-surface"><h2>{escape(title)}</h2>{values}</section>')


def definitions(*terms, title="About these terms"):
    with st.expander(title):
        for term in terms:
            st.markdown(f"**{term}**  \n{CONCEPTS[term]}")


def provenance(digest, *, source="Evidence", line=None, key, metadata=None):
    label = source + (f" · line {int(line):,}" if line is not None else "")
    if digest:
        label += f" · {digest[:8]}…{digest[-4:]}"
    with st.popover(label, key=f"source_{key}", help="Inspect the source reference and copy the full fingerprint"):
        st.markdown("**Provenance**")
        st.text(source)
        if line is not None:
            st.caption(f"Physical source line {int(line):,}")
        if digest:
            st.code(digest, language=None, wrap_lines=True)
        for name, value in (metadata or {}).items():
            st.caption(f"{name} · {value}")


def redacted_preview(value):
    if pd.isna(value):
        return None
    value = str(value)
    return ("••••" if len(value) < 5 else f"{value[:2]}••••{value[-1:]}")


def show_frame(data, *, redact=False, **options):
    frame = data.copy() if isinstance(data, pd.DataFrame) else pd.DataFrame(data)
    if redact or st.session_state.get("ui_presentation"):
        for column in frame.columns:
            if str(column).casefold() in DISPLAY_IDS:
                frame[column] = frame[column].astype("object").where(frame[column].isna(), "••••")
    options.setdefault("hide_index", True)
    options.setdefault("row_height", row_height())
    return st.dataframe(frame, **options)


def source_note(source, *, sample=None, seed=None, digest=None):
    parts = [source]
    if sample is not None:
        parts.append(f"n = {sample:,}")
    if seed is not None:
        parts.append(f"seed {seed}")
    if digest:
        parts.append(f"SHA-256 {digest[:12]}…")
    st.caption(" · ".join(parts))


def style_guide():
    st.caption("Shared controls, colour, typography and status patterns used in the investigation console.")
    st.header("Surfaces and state")
    st.html("""
    <div class="pf-swatches" aria-label="Design colours">
      <span style="--sample:#111923">Workspace</span><span style="--sample:#172230">Panel</span>
      <span style="--sample:#4C8DCE">Action</span><span style="--sample:#43B5A0">Verified</span>
      <span style="--sample:#D9A441">Needs review</span><span style="--sample:#D96868">Failed</span>
    </div>
    """)
    panel("Metadata pattern", [("Text", "Inter"), ("Technical values", "IBM Plex Mono"),
                                ("Row density", st.session_state.get("ui_density", "Default"))])
    st.header("Evidence types")
    show_frame([{"Type": "Exact identifier", "Symbol": "●", "Line": "Solid"},
                {"Type": "Temporal association", "Symbol": "■", "Line": "Dashed"},
                {"Type": "Heuristic", "Symbol": "▲", "Line": "Dotted"},
                {"Type": "Known reference", "Symbol": "◆", "Line": "Solid"},
                {"Type": "Model prediction", "Symbol": "○", "Line": "Long dash"}])
    st.header("Navigation and glossary")
    action("Back to overview", "Dashboard", key="guide_overview", primary=True)
    definitions("Evidence integrity", "Masking", "Epsilon and delta", "F1")
