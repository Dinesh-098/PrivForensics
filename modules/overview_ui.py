"""The case overview and its guided investigation checklist."""
from html import escape
from urllib.parse import urlencode

import streamlit as st

from .investigation import Investigation
from .jobs import ACTIVE, JobStore
from .lab_ui import LAB_PAGE
from .shell import SLUGS
from .ui import action, advanced, panel, show_frame


def _stepper(steps, first_pending):
    cards = []
    params = dict(st.query_params)
    for index, (title, page, done, _, _) in enumerate(steps):
        state = "is-complete" if done else "is-current" if index == first_pending else ""
        status = "Done" if done else "Next" if index == first_pending else "To do"
        url = "?" + urlencode({**params, "page": SLUGS[page]})
        cards.append(
            f'<li class="{state}"><a href="{escape(url, quote=True)}" target="_self">'
            f'<strong>{escape(title)}</strong><small>{status}</small></a></li>'
        )
    st.html('<ol class="pf-stepper" aria-label="Investigation checklist">' + "".join(cards) + "</ol>")


def render_overview(registry, case, sources, activity):
    cases = registry.list("cases")
    selected = next((item for item in cases if item["id"] == case), None)
    if selected is None:
        st.header("Start with an investigation")
        if not cases:
            st.caption("No investigations yet. Create your first investigation to begin.")
            action("Start investigation", "Investigations", key="overview_start", primary=True)
            steps = [
                ("Create investigation", "Investigations", False, "", ""),
                ("Add evidence", "Evidence Management", False, "", ""),
                ("Analyze activity", "AI Forensic Analysis", False, "", ""),
                ("Apply privacy protection", "Privacy Protection", False, "", ""),
                ("View results", LAB_PAGE, False, "", ""),
                ("Generate report", "Reports", False, "", ""),
            ]
            _stepper(steps, 0)
            st.caption("Add a file and check its integrity before reviewing activity.")
        else:
            st.caption("Choose a case in the investigation switcher or start a new one.")
            action("Start investigation", "Investigations", key="overview_new", primary=True)
            show_frame([{"Investigation": item["name"], "Status": item["status"],
                         "Evidence": item["evidence_count"]} for item in cases], height=220)
        return

    workspace = Investigation(registry)
    store = JobStore(registry)
    evidence = registry.list("evidence", case)
    audit = activity(registry, case)
    findings = workspace.findings(case)
    jobs = store.list(case)
    evaluations = [job for job in jobs if job.kind == "evaluation" and job.result]
    analyses = [job for job in jobs if job.kind == "forensic_analysis" and job.result]
    applied = [entry for entry in audit if entry["Action"] == "privacy transform"]
    reports = workspace.reports(case)
    latest = audit[0]["UTC"] + " UTC" if audit else "No activity yet"
    checked = {}
    for row in reversed(audit):
        if row["Action"] == "integrity checked":
            checked[row["Evidence"]] = row["Status"]
    verified = {key for key, value in checked.items() if value == "Verified"}
    st.html(f"""
    <div class="pf-context">
      <strong>{escape(selected["name"])}</strong>
      <span class="pf-status">{escape(selected["status"])}</span>
      <code>{escape(case[:8])}</code><span>Last activity {escape(latest)}</span>
    </div>
    """)
    analyzed = bool(analyses or evaluations or any(row["Action"] == "authentication scored" for row in audit))
    steps = [
        ("Create investigation", "Investigations", True,
         "Review the case owner, notes and saved findings.", "Open investigation"),
        ("Add evidence", "Evidence Management", bool(evidence),
         "Upload a small file or register a prepared dataset. Verify its integrity after registration.", "Add evidence"),
        ("Analyze activity", "AI Forensic Analysis", analyzed,
         "Choose a detection preset to rank activity for review.", "Choose analysis"),
        ("Apply privacy protection", "Privacy Protection", bool(applied),
         "Mask values or replace them with keyed identifiers before sharing a dataset.", "Protect records"),
        ("View results", LAB_PAGE, bool(evaluations),
         "Run a baseline and privacy comparison to measure what the protection changes.", "Open Evaluation Lab"),
        ("Generate report", "Reports", bool(reports),
         "Generate a dated record of evidence, findings and measured results.", "Generate report"),
    ]
    first_pending = next((index for index, step in enumerate(steps) if not step[2]), None)
    st.header("Investigation checklist")
    _stepper(steps, first_pending)
    next_step = steps[first_pending] if first_pending is not None else steps[-1]
    label = "Next step" if first_pending is not None else "Checklist complete"
    main, aside = st.columns([1.6, 1], gap="large")
    with main:
        st.html(f'<div class="pf-handoff"><strong>{label} · {escape(next_step[0])}</strong>'
                f'<p>{escape(next_step[3])}</p></div>')
        action(next_step[4] if first_pending is not None else "Review report snapshots",
               next_step[1], key="overview_next", primary=True)
        if evidence and not verified:
            st.caption("Your evidence is registered. A file integrity check is available in Evidence.")
        st.header("Recent activity")
        if audit:
            show_frame([{"Time (UTC)": row["UTC"], "Operation": row["Action"].capitalize(),
                         "Status": row["Status"]} for row in audit[:6]], height=230)
        else:
            st.caption("Case operations appear here as they are recorded.")
    with aside:
        panel("Case status", [
            ("Evidence registered", len(evidence)), ("Evidence verified", len(verified)),
            ("Analysis", "Completed" if analyzed else "Awaiting run"),
            ("Saved findings", len(findings)), ("Privacy transformations", len(applied)),
            ("Jobs queued or running", sum(job.status in ACTIVE for job in jobs)),
        ])
        st.header("Saved findings")
        if findings:
            show_frame([{"Finding": row["title"], "Type": row["kind"]} for row in findings[:4]])
            action("Review saved findings", "Investigations", key="overview_findings")
        else:
            st.caption("Save a finding from AI analysis or an event timeline.")
        st.header("Latest experiments")
        if evaluations:
            show_frame([{"Model": job.config["model"], "Variants": len(job.result["variants"]),
                         "Run": job.id[:8]} for job in evaluations[:3]])
            action("View evaluation results", LAB_PAGE, key="overview_lab",
                   **{f"lab_pending_{case}": evaluations[0].id})
        else:
            st.caption("Completed case experiments will appear here.")
    if advanced():
        with st.expander("Prepared project data"):
            show_frame([{"Feed": kind, "Accepted rows": item["valid_records"],
                         "Scope": item["scope"], "Fingerprint": item["archive_sha256"][:12]}
                        for kind, item in sources.items() if item])
