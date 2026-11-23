"""Case-aware navigation, workspace search and job feedback."""
import base64
from datetime import datetime, timezone
from html import escape
import re
from time import monotonic

import streamlit as st

from .jobs import ACTIVE, JobStore
from .lab_ui import LAB_PAGE, job_label
from .ui import APP_ROOT, DENSITIES, advanced, font_faces, go, visible_label


PRIMARY = ("Dashboard", "Investigations", "Evidence Management", "AI Forensic Analysis",
           "Privacy Protection", LAB_PAGE, "Reports")
TOOLS = ("Dataset Explorer", "Event Correlation", "Privacy Threat Analysis", "Attack Simulation",
         "Performance Analysis", "Audit History", "Settings", "Design system")
PAGES = (*PRIMARY, *TOOLS)
SLUGS = dict(zip(PAGES, ("overview", "investigations", "evidence", "analysis", "protection", "evaluation",
                        "reports", "datasets", "correlation", "privacy-assessment", "privacy-diagnostics",
                        "performance", "audit", "settings", "design-system"), strict=True))
GROUPS = {**dict.fromkeys(PRIMARY[:3], "Investigate"),
          "Dataset Explorer": "Investigate", "Event Correlation": "Investigate",
          "Privacy Threat Analysis": "Protect", "Privacy Protection": "Protect",
          **dict.fromkeys(("AI Forensic Analysis", LAB_PAGE, "Attack Simulation", "Performance Analysis"), "Analyze"),
          "Reports": "Record", "Audit History": "Record"}
MORE = "Specialist tools"


def _initialise(cases):
    if st.session_state.get("shell_initialized"):
        return
    url_page = st.query_params.get("page")
    if not url_page and getattr(st.context, "url", None):
        from urllib.parse import urlsplit
        url_page = urlsplit(st.context.url).path.strip("/")
    st.session_state.update(
        shell_initialized=True,
        navigation=next((page for page, slug in SLUGS.items() if slug == url_page), "Dashboard"),
        active_case=(case if (case := st.query_params.get("case")) in cases else None),
        ui_mode="Advanced" if st.query_params.get("mode") == "advanced" else "Simple",
        ui_density=next((kind for kind in DENSITIES if kind.lower() == st.query_params.get("density")), "Default"),
        ui_motion=st.query_params.get("motion") == "reduce",
        ui_presentation=st.query_params.get("presentation") == "on",
        ui_rail=st.query_params.get("rail") == "compact",
    )


def _sync_url(page, case):
    settings = {
        "page": SLUGS[page],
        "case": case,
        "mode": "advanced" if advanced() else None,
        "density": st.session_state.ui_density.lower() if st.session_state.ui_density != "Default" else None,
        "motion": "reduce" if st.session_state.ui_motion else None,
        "presentation": "on" if st.session_state.ui_presentation else None,
        "rail": "compact" if st.session_state.ui_rail else None,
    }
    for name, value in settings.items():
        if value and st.query_params.get(name) != value:
            st.query_params[name] = value
        elif not value and name in st.query_params:
            del st.query_params[name]


def _change_primary():
    choice = st.session_state.nav_primary
    if choice == MORE:
        go(st.session_state.get("nav_tool", TOOLS[0]))
    else:
        go(choice)


def _change_tool():
    go(st.session_state.nav_tool)


def _sidebar(page):
    mark = base64.b64encode((APP_ROOT / "assets/brand/favicon-32.png").read_bytes()).decode()
    st.sidebar.html(f'<div class="pf-brand"><img src="data:image/png;base64,{mark}" alt="" width="28" height="28">'
                    '<span><b>Priv</b>Forensics</span></div>')
    if page in TOOLS:
        st.session_state.nav_tool = page
    st.session_state.nav_primary = MORE if page in TOOLS else page
    st.sidebar.radio("Primary navigation", [*PRIMARY, MORE], key="nav_primary", format_func=visible_label,
                     on_change=_change_primary, label_visibility="collapsed")
    if page in TOOLS:
        st.sidebar.selectbox("Specialist tools", TOOLS, key="nav_tool", on_change=_change_tool,
                             format_func=visible_label)
    rail_label = "Expand navigation" if st.session_state.ui_rail else "Compact navigation"
    st.sidebar.button(rail_label, key="rail_toggle", type="tertiary",
                      on_click=lambda: st.session_state.update(ui_rail=not st.session_state.ui_rail))
    st.sidebar.html('<p class="pf-local">Local research workspace</p>')


def _run_command(page, case, value, kind):
    if kind == "case":
        go("Investigations", pending_case=value)
    elif kind == "evidence":
        go("Evidence Management", **{f"inspect_evidence_{case}": value})
    elif kind == "experiment":
        go(LAB_PAGE, **{f"lab_pending_{case}": value})
    else:
        go(page)
    st.session_state.command_center = False


def _palette(registry, cases, case):
    with st.popover("Search", key="command_center", on_change="rerun", icon=":material/search:",
                    help="Search pages, investigations, evidence and experiments. Command or Control + K.",
                    type="tertiary"):
        if st.session_state.get("command_center"):
            query = st.text_input("Search workspace", key="command_query",
                                  placeholder="Find a page, investigation, file or run",
                                  help="Press Enter after typing to update the results.")
            if not query.strip():
                st.caption("Type a search, then press Enter to find matching pages and case records.")
                return
            matches = [(f"Page · {visible_label(page)}", page, None, "page") for page in PAGES]
            matches.extend((f"Investigation · {item['name']} · {key[:8]}", "Investigations", key, "case")
                           for key, item in cases.items())
            if case:
                matches.extend((f"Evidence · {item['name']} · {item['id'][:8]}", "Evidence Management",
                                item["id"], "evidence") for item in registry.list("evidence", case))
                matches.extend((f"Experiment · {job_label(job)}", LAB_PAGE, job.id, "experiment")
                               for job in JobStore(registry).list(case, "evaluation", limit=20))
            terms = query.casefold().split()
            matches = [item for item in matches if all(term in item[0].casefold() for term in terms)]
            if matches:
                item = st.selectbox("Search results", matches[:20], format_func=lambda result: result[0])
                st.button("Open result", key="open_command", on_click=_run_command,
                          args=(item[1], case, item[2], item[3]), type="primary")
            else:
                st.info("No matching pages or case records. Try a shorter search.")


@st.fragment(run_every="3s")
def _job_tray(registry, case):
    if not case:
        with st.popover("Jobs", key="tray_no_case", icon=":material/schedule:", type="tertiary"):
            st.caption("Choose an investigation to see its background jobs.")
        return
    store = JobStore(registry)
    active = [job for status in ACTIVE for job in store.by_status(case, status)]
    label = f"Jobs ({len(active)})" if active else "Jobs"
    with st.popover(label, key=f"tray_{case}", icon=":material/schedule:", type="tertiary"):
        jobs = active or store.list(case, limit=4)
        if not jobs:
            st.caption("Background work will appear here once you queue a job.")
            return
        for job in jobs:
            st.markdown(f"**{job_label(job)}**")
            st.caption(f"{job.status.title()} · {job.phase}")
            if job.status in ACTIVE:
                st.progress(job.progress, text=job.phase)
                if job.started:
                    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(job.started)).total_seconds()
                    st.caption(f"Elapsed {int(max(0, elapsed)):,} s")
                    details = hash_rate(job)
                    if details:
                        st.caption(details)
                if st.button("Cancel at next checkpoint", key=f"tray_cancel_{job.id}",
                             disabled=job.cancel_requested):
                    store.cancel(case, job.id)
                    st.rerun()
            if job.error:
                st.warning(job.error)
            destinations = {"evaluation": LAB_PAGE, "forensic_analysis": "AI Forensic Analysis",
                            "correlate_lanl": "Event Correlation"}
            st.button("Open job workspace", key=f"tray_open_{job.id}", on_click=go,
                      args=(destinations.get(job.kind, "Evidence Management"),),
                      kwargs={f"lab_pending_{case}": job.id} if job.kind == "evaluation" else {})


def hash_rate(job):
    """Estimate a scan rate from consecutive reported byte counts."""
    match = re.fullmatch(r"SHA-256 · ([\d,]+) of ([\d,]+) MiB", job.phase)
    if not match:
        return None
    done, total = (int(value.replace(",", "")) for value in match.groups())
    now = monotonic()
    key = f"job_rate_{job.id}"
    previous = st.session_state.get(key)
    if previous is None or now - previous[2] >= 1:
        st.session_state[key] = (done, total, now)
    if previous and total == previous[1] and done > previous[0] and now - previous[2] >= 1:
        rate = (done - previous[0]) / (now - previous[2])
        return f"{rate:,.0f} MiB/s over the last sample · about {max(0, round((total - done) / rate)):,} s left in this scan"
    return None


def _shortcuts():
    with st.popover("Keys", key="shortcut_center", type="tertiary", icon=":material/keyboard:"):
        st.markdown("**Keyboard shortcuts**")
        st.caption("Command or Control + K and / open search. ? opens this sheet.")
        st.caption("Press G then O for overview, I for investigations, E for evidence, A for analysis, "
                   "P for privacy, L for the Lab or R for reports.")
        st.caption("Focused tables support arrow keys. J and K also move through rows where the active table handles arrow navigation.")


def render_shell(registry):
    cases = {item["id"]: item for item in registry.list("cases")}
    _initialise(cases)
    if pending := st.session_state.pop("pending_case", None):
        st.session_state.active_case = pending if pending in cases else None
    page = st.session_state.navigation
    if page not in PAGES:
        page = st.session_state.navigation = "Dashboard"
    st.html(APP_ROOT / "console.css")
    if font_faces():
        st.html(font_faces())
    classes = ["pf-display"]
    if st.session_state.ui_motion:
        classes.append("pf-reduced")
    if st.session_state.ui_presentation:
        classes.append("pf-presentation")
    if st.session_state.ui_rail:
        classes.append("pf-rail-compact")
    st.html(f'<span class="{" ".join(classes)}" aria-hidden="true"></span>')
    st.html(APP_ROOT / "assets/keys.html", unsafe_allow_javascript=True)
    _sidebar(page)
    with st.container(key="shell_toolbar"):
        context, active, views = st.columns([1.5, 1.8, 1.45], vertical_alignment="center")
        with context:
            title = escape(visible_label(page))
            group = escape(GROUPS.get(page, "Workspace"))
            st.html(f'<div class="pf-breadcrumb" aria-label="Current section">{group}<b> / </b>{title}</div>')
        with active:
            case = st.selectbox("Investigation", [None, *cases], key="active_case",
                                format_func=lambda key: cases[key]["name"] if key in cases else "Choose an investigation",
                                label_visibility="collapsed")
        with views:
            st.segmented_control("Interface mode", ["Simple", "Advanced"], required=True, key="ui_mode",
                                 label_visibility="collapsed", help="Advanced adds research configuration and provenance detail.")
        c1, c2, c3, c4, c5 = st.columns([1.8, 1, 1, 1, 1], vertical_alignment="center")
        with c1:
            scope = f'<code>{case[:8]}</code>' if case else "No case selected"
            st.html(f'<div class="pf-toolbar-meta">{scope}<span>Local workspace</span></div>')
        with c2:
            _palette(registry, cases, case)
        with c3:
            _job_tray(registry, case)
        with c4:
            _shortcuts()
        with c5:
            st.toggle("Present", key="ui_presentation", help="Hide identifiers in supported data views and enlarge text.")
    _sync_url(page, case)
    return page, case
