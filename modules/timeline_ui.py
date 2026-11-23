"""Bounded timeline and source inspector backed by stored correlation criteria."""
import altair as alt
import pandas as pd
import streamlit as st

from .ui import advanced, provenance, show_frame


LABELS = {"redteam": "Red-team reference", "auth": "Authentication",
          "proc": "Process execution", "model": "Model prediction"}
_TYPES = ["Known reference", "Exact identifier", "Temporal association", "Model prediction"]
_COLOURS = ["#D96868", "#43B5A0", "#4C8DCE", "#B8C4D2"]
_SHAPES = ["diamond", "circle", "square", "cross"]


def render_timeline(events, digests, *, selected_anchor, window, criteria, models=()):
    points = []
    records = {}
    for timestamp, kind, row in events[:200]:
        identifier = f"{kind}_{row['source_line']}"
        typ = {"redteam": _TYPES[0], "auth": _TYPES[1], "proc": _TYPES[2]}[kind]
        points.append({"ID": identifier, "Time": timestamp, "Lane": LABELS[kind],
                       "Criterion": typ, "Source line": int(row["source_line"])})
        records[identifier] = (kind, row)
    if not points:
        st.info("No events meet the current timeline filters.")
        return
    bounds = min(point["Time"] for point in points), max(point["Time"] for point in points)
    for finding in models:
        time = finding["timestamp_s"]
        if not bounds[0] <= time <= bounds[1]:
            continue
        reference = next((row for row in finding["references"] if row["sha256"] in digests.values()), None)
        if reference:
            identifier = f"model_{finding['id']}"
            points.append({"ID": identifier, "Time": time, "Lane": LABELS["model"],
                           "Criterion": _TYPES[3], "Source line": reference["source_line"]})
            records[identifier] = ("model", {**reference, "summary": finding["summary"]})
    data = pd.DataFrame(points)
    colour = alt.Color("Criterion:N", scale=alt.Scale(domain=_TYPES, range=_COLOURS),
                       legend=alt.Legend(orient="bottom", title=None))
    shape = alt.Shape("Criterion:N", scale=alt.Scale(domain=_TYPES, range=_SHAPES), legend=None)
    base_x = alt.X("Time:Q", title="LANL relative time (seconds)", scale=alt.Scale(zero=False))
    lanes = list(LABELS.values())
    base_y = alt.Y("Lane:N", title=None, sort=lanes, axis=alt.Axis(labelLimit=110))
    brush = alt.selection_interval(name="window", encodings=["x"])
    marks = alt.Chart(data).mark_point(filled=True, stroke="#E8EEF5", strokeWidth=.6, size=92).encode(
        x=alt.X("Time:Q", title="LANL relative time (seconds)", scale=alt.Scale(domain=brush, zero=False)),
        y=base_y, color=colour, shape=shape,
        tooltip=[alt.Tooltip("Lane:N"), alt.Tooltip("Time:Q", format=","),
                 alt.Tooltip("Source line:Q", format=","), alt.Tooltip("Criterion:N")],
    ).properties(height=164)
    minimap = alt.Chart(data).mark_tick().encode(x=base_x,
            color=alt.Color("Criterion:N", scale=alt.Scale(domain=_TYPES, range=_COLOURS), legend=None)).properties(height=38)
    chart = alt.vconcat(marks, minimap.add_params(brush)).resolve_scale(x="independent")
    left, right = st.columns([1.6, 1], gap="large")
    with left:
        st.header("Evidence timeline")
        if bounds[0] < bounds[1]:
            first, last = st.slider("Timeline range (seconds)", int(bounds[0]), int(bounds[1]),
                                    tuple(map(int, bounds)), key=f"timeline_zoom_{selected_anchor}",
                                    help="Use the arrow keys when a range handle is focused.")
            clipped = data[data["Time"].between(first, last)]
            chart = alt.vconcat(marks.transform_filter(alt.FieldRangePredicate(field="Time", range=[first, last])),
                                minimap.add_params(brush)).resolve_scale(x="independent")
        else:
            clipped = data
        st.altair_chart(chart, alt="Events arranged by evidence source. Use the range slider or drag on the lower strip.")
        st.caption(f"{len(clipped):,} recorded marks within the slider range · drag on the lower strip to zoom.")
        with st.expander("View timeline data"):
            show_frame(data.drop(columns="ID"))
    with right:
        st.header("Inspect event")
        ids = {row["ID"]: row for row in points}
        anchor = f"redteam_{selected_anchor}"
        names = list(ids)
        selection = st.selectbox("Event on timeline", names, index=names.index(anchor) if anchor in names else 0,
                                 format_func=lambda key: f"{ids[key]['Lane']} · line {ids[key]['Source line']:,}",
                                 key=f"timeline_event_{selected_anchor}")
        kind, row = records[selection]
        digest = row.get("sha256") if kind == "model" else digests[kind]
        provenance(digest, source=LABELS[kind], line=row["source_line"], key=selection)
        if kind == "model":
            st.caption(row["summary"])
            st.caption("The model finding appears within this time range. It has its own evidence reference.")
        else:
            show_frame([row], redact=not advanced())
            with st.expander("Why these records appear together", expanded=True):
                show_frame(criteria.get((kind, row["source_line"]), [
                    {"Criterion": "Supplied red-team annotation", "Window": "—"}]))
                if kind == "proc":
                    st.caption(f"Process context was searched within ±{window} seconds of the supplied anchor.")
