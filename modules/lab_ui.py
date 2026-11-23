"""Streamlit views for configuring, inspecting and comparing measured lab runs."""
import json
from math import exp, pi, sqrt
import re
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from .jobs import ACTIVE, JobStore, launch_worker
from .lab import (CONFIGURATIONS, DATASETS, MODELS, SYNTHETIC, evaluation_config,
                  synthetic_fingerprint)
from .ui import CONCEPTS, action, advanced, definitions, empty_state, panel, provenance, show_frame, source_note


LAB_PAGE = "Privacy–Utility Evaluation Lab"


def job_label(job):
    if job.kind == "evaluation":
        return f"{job.created[:16].replace('T', ' ')} UTC · {job.config['model']} · {job.id[:8]}"
    return f"{job.kind.replace('_', ' ').title()} · {job.id[:8]}"


def _job_state(store, case, job_id):
    job = store.get(case, job_id)
    if job.status in ACTIVE:
        st.progress(job.progress, text=f"{job.status.capitalize()} · {job.phase}")
        cancel_label = "Cancellation requested" if job.cancel_requested else "Cancel at next checkpoint"
        if st.button(cancel_label, disabled=job.cancel_requested, key=f"cancel_{job_id}"):
            store.cancel(case, job_id)
            st.rerun()
    elif job.status != "succeeded":
        st.warning(job.error or job.status.capitalize())


def job_status(store, case, job, root):
    if job.status in ACTIVE:
        st.button("Refresh status", key=f"refresh_{job.id}")
        if st.button("Resume local worker", key=f"resume_{job.id}",
                     help="Use after a worker process has stopped. Interrupted work can be rerun."):
            launch_worker(store.registry, root)

        @st.fragment(run_every="2s")
        def monitor():
            current = store.get(case, job.id)
            if current.status not in ACTIVE:
                st.rerun(scope="app")
            _job_state(store, case, job.id)

        monitor()
    else:
        _job_state(store, case, job.id)


_METHODS = {
    "Baseline only": ["E0"],
    "Mask identifiers": ["E0", "E1"],
    "Replace identifiers with keyed tokens": ["E0", "E2"],
    "Combine masking and keyed tokens": ["E0", "E3"],
    "Differentially private training": ["E0", "E4"],
    "Compare all supported methods": list(CONFIGURATIONS),
}


def _noise_illustration(clip):
    with st.expander("Illustration of gradient noise"):
        scale = st.slider("Illustration noise multiplier", .2, 3., 1., step=.1,
                          help="The illustration changes independently of the experiment configuration.")
        sd = clip * scale
        grid = [sd * number / 12 for number in range(-45, 46)]
        chart_data = pd.DataFrame({"Offset": grid, "Density": [exp(-.5 * (x / sd)**2) / (sd * sqrt(2 * pi))
                                                               for x in grid]})
        chart = alt.Chart(chart_data).mark_line(color="#43B5A0").encode(
            x=alt.X("Offset:Q", title="Illustrative noise offset"), y=alt.Y("Density:Q", title="Illustrative probability density"),
            tooltip=[alt.Tooltip("Offset:Q", format=".3f"), alt.Tooltip("Density:Q", format=".3f")]).properties(height=134)
        st.altair_chart(chart, alt="Gaussian mechanism illustration. Training and privacy results are measured after a run.")
        st.caption(f"Illustration of the mechanism · standard deviation {sd:.2f} · "
                   "the measured privacy bound and actual noise multiplier appear after training.")


def _simple_configuration(dataset):
    choices = [name for name in _METHODS if dataset == "synthetic" or name != "Differentially private training"]
    if st.session_state.pop("lab_start_private", False) and dataset == "synthetic":
        st.session_state.lab_method = "Differentially private training"
    method = st.selectbox("Privacy method", choices, index=1, key="lab_method",
                          help="The Lab always includes a baseline for the selected model.")
    codes = [code for code in _METHODS[method] if dataset == "synthetic" or code != "E4"]
    models = (["Neural Network"] if "E4" in codes else list(MODELS[dataset]))
    model = st.selectbox("Detection model", models, key=f"simple_model_{dataset}_{method}")
    if "E4" in codes:
        st.caption("Differentially private training is available for the synthetic neural network.")
    settings = {}
    if model == "Neural Network":
        preset = st.selectbox("Experiment preset", ["Research comparison", "Quick trial"],
                              help="Research comparison uses eight training passes. Quick trial uses two.")
        settings["epochs"] = 8 if preset == "Research comparison" else 2
        if "E4" in codes:
            settings["budgets"] = [4.0, 8.0]
    else:
        st.caption("Uses the saved research configuration and fixed cohort seed.")
    return model, codes, 42, settings


def _advanced_configuration(dataset):
    model = st.selectbox("Detection model", MODELS[dataset], key=f"lab_model_{dataset}")
    available = [code for code in CONFIGURATIONS if code != "E4" or model == "Neural Network"]
    codes = st.multiselect("Privacy configurations", available, default=available,
                           format_func=lambda code: f"{code} · {CONFIGURATIONS[code]}",
                           key=f"lab_variants_{dataset}_{model}")
    with st.expander("Compatibility"):
        show_frame([{"Configuration": f"{code} · {label}", "Availability":
                     "Available" if code in available else "Requires the synthetic neural network"}
                    for code, label in CONFIGURATIONS.items()])
    seed = st.number_input("Random seed", min_value=0, max_value=2**32-2, value=42)
    settings = {}
    if model == "Neural Network":
        with st.expander("Training and privacy parameters", expanded="E4" in codes):
            a, b = st.columns(2)
            settings = {"epochs": a.number_input("Training epochs", 1, 40, 8),
                        "batch_size": b.selectbox("Batch size", [64, 128, 256, 512], index=2)}
            if "E4" in codes:
                settings["targets"] = st.text_input("Target epsilons", "4, 8",
                                                    help=CONCEPTS["Epsilon and delta"])
                settings["delta"] = a.number_input("Delta", 1e-8, 1e-4, 1e-5, step=1e-6, format="%.8f")
                settings["clip"] = b.number_input("Clipping norm", .1, 5., 1., step=.1)
                st.caption("Opacus RDP accountant · Poisson row sampling · seeded research randomness")
        if "E4" in codes:
            _noise_illustration(settings["clip"])
    return model, codes, seed, settings


def _configure(store, registry, case, root, sources):
    left, right = st.columns([1.4, 1], gap="large")
    with left:
        st.header("Set up an experiment")
        dataset = st.selectbox("Prepared dataset", list(DATASETS), format_func=DATASETS.get)
        model, codes, seed, settings = (_advanced_configuration(dataset) if advanced()
                                        else _simple_configuration(dataset))
    with right:
        panel("Run plan", [("Dataset", DATASETS[dataset]), ("Model", model),
                           ("Compare", ", ".join(codes) or "Choose configurations"), ("Seed", seed)])
        digest = (synthetic_fingerprint(root) if dataset == "synthetic"
                  else sources.get("auth", {}).get("archive_sha256"))
        evidence = next((item for item in registry.list("evidence", case) if item["sha256"] == digest), None)
        if evidence:
            st.success(f"Registered source · {evidence['name']}")
        elif dataset == "synthetic" and digest:
            st.info("Add the bundled synthetic dataset to this case before running an experiment.")
            if st.button("Register synthetic dataset"):
                registry.register_reference(case, Path(root) / SYNTHETIC, expected=digest)
                st.rerun()
        elif digest:
            st.info("Register the prepared LANL authentication archive in this case.")
            action("Open Evidence", "Evidence Management", key="lab_missing_auth")
        else:
            st.info("The prepared LANL export is unavailable. Choose the synthetic dataset.")
        if digest:
            provenance(digest, source=DATASETS[dataset], key=f"lab_config_{dataset}")
        if dataset == "synthetic":
            st.caption("The synthetic labels come from generator rules. The run measures how well the model recovers them.")
        else:
            st.caption("Unique red-team matches are observed positives. Other sampled LANL events remain unlabelled.")
        if "E4" in codes:
            definitions("Differential privacy", "Epsilon and delta", title="About the privacy budget")
    if not evidence or not codes:
        st.caption("Register the source and choose at least one configuration to run.")
    if st.button("Queue evaluation run" if advanced() else "Run experiment", type="primary",
                 disabled=not evidence or not codes):
        try:
            if "targets" in settings:
                settings["budgets"] = [float(x.strip()) for x in settings.pop("targets").split(",")]
            config = evaluation_config(root, evidence, dataset, model, codes, seed=int(seed), **settings)
            job_id, created = store.submit(case, "evaluation", config)
            if created:
                launch_worker(registry, root)
            st.session_state[f"lab_pending_{case}"] = job_id
            st.rerun()
        except (ValueError, OSError) as exc:
            st.error(f"Experiment could not start. {exc}")

def comparison_rows(jobs):
    rows = []
    for job in jobs:
        for variant in job.result["variants"]:
            privacy = variant["privacy"]
            elapsed = variant["phase_metrics"]
            utility = {key: value for key, value in variant["utility"].items() if key != "confusion"}
            rows.append({
                "Variant": f"{job.config['model']} · {variant['id']} · {job.id[:6]}",
                "Configuration": CONFIGURATIONS[variant["configuration"]],
                **utility, "epsilon": privacy.get("epsilon_spent"), "delta": privacy.get("delta"),
                "membership_auc": (privacy.get("membership") or {}).get("roc_auc"),
                "membership_advantage": (privacy.get("membership") or {}).get("advantage"),
                "synthetic_linkage_success": (privacy.get("synthetic_linkage") or {}).get("success_rate"),
                "identifier_cells_unchanged": privacy["unchanged_fraction"],
                "feature_prep_seconds": elapsed["prepare"]["seconds"],
                "train_seconds": elapsed["train"]["seconds"], "inference_seconds": elapsed["inference"]["seconds"],
                "train_peak_rss_mib": round(elapsed["train"]["sampled_peak_rss_bytes"] / 1024**2, 2),
                "train_mean_cpu_percent": elapsed["train"]["mean_process_cpu_percent"],
                "inference_records_per_second": elapsed["inference"]["records_per_second"],
            })
    return rows


_PALETTE = ["#4C8DCE", "#43B5A0", "#D9A441", "#D96868", "#8FA3BF", "#C9B8A0"]
_SCORES = {
    "accuracy": "Accuracy", "precision": "Precision", "recall": "Recall", "f1": "F1",
    "roc_auc": "ROC AUC", "average_precision": "PR AUC (AP)",
    "false_positive_rate": "False-positive rate", "false_negative_rate": "False-negative rate",
    "known_positive_recall": "Known-positive recall", "observed_label_average_precision": "Observed-label AP",
    "unlabelled_flag_rate": "Unlabelled flag rate", "flagged": "Flagged",
}
_RESOURCE = {"train_seconds": "Training (s)", "inference_seconds": "Inference (s)",
             "train_peak_rss_mib": "Peak training RSS (MiB)", "train_mean_cpu_percent": "Training CPU (%)",
             "inference_records_per_second": "Inference (records/s)", "feature_prep_seconds": "Preparation (s)"}


def _display_frame(jobs):
    rows = comparison_rows(jobs)
    variants = [(job, row) for job in jobs for row in job.result["variants"]]
    for values, (job, variant) in zip(rows, variants, strict=True):
        code = variant["id"].replace(" eps ", " ε ")
        baseline = next((row for row in job.result["variants"] if row["configuration"] == "E0"), None)
        values.update({"Variant label": code if len(jobs) == 1 else f"{job.id[:6]} · {code}",
                       "Holdout records": job.result["cohort"]["splits"]["test"]["rows"]})
        if baseline and "f1" in values:
            values["F1 change"] = values["f1"] - baseline["utility"]["f1"]
    return pd.DataFrame(rows)


def _note(jobs):
    job = jobs[0]
    source_note(DATASETS[job.config["dataset"]], sample=job.result["cohort"]["splits"]["test"]["rows"],
                seed=job.config["seed"], digest=job.config["dataset_sha256"])


def _scatter(frame, x, y, x_title, y_title, *, frontier=False):
    data = frame.dropna(subset=[x, y])
    if data.empty:
        return
    dots = alt.Chart(data).mark_point(size=100, filled=True, stroke="#E8EEF5", strokeWidth=.55).encode(
        x=alt.X(f"{x}:Q", title=x_title, scale=alt.Scale(zero=False)),
        y=alt.Y(f"{y}:Q", title=y_title, scale=alt.Scale(zero=False)),
        color=alt.Color("Configuration:N", legend=alt.Legend(orient="bottom"), scale=alt.Scale(range=_PALETTE)),
        shape=alt.Shape("Configuration:N", legend=None),
        tooltip=[alt.Tooltip("Variant:N"), alt.Tooltip("Holdout records:Q"),
                 alt.Tooltip(f"{x}:Q", title=x_title, format=".4g"),
                 alt.Tooltip(f"{y}:Q", title=y_title, format=".4g")])
    if frontier and len(data) >= 2:
        ordered = data.sort_values([x, y], ascending=[True, False])
        best = float("-inf")
        non_dominated = []
        for _, row in ordered.iterrows():
            if row[y] > best:
                non_dominated.append(row)
                best = row[y]
        if len(non_dominated) > 1:
            line = alt.Chart(pd.DataFrame(non_dominated)).mark_line(color="#43B5A0", strokeDash=[7, 3]).encode(
                x=alt.X(f"{x}:Q", title=x_title, scale=alt.Scale(zero=False)),
                y=alt.Y(f"{y}:Q", title=y_title, scale=alt.Scale(zero=False)))
            dots = line + dots
    st.altair_chart(dots.properties(height=235),
                    alt=f"Measured results comparing {x_title} and {y_title} across stored experiment variants.")


def _bars(data, metric, label, *, color="#4C8DCE", height=210):
    chart = alt.Chart(data.dropna(subset=[metric])).mark_bar(color=color).encode(
        y=alt.Y("Variant label:N", title="Configuration", sort=None,
                axis=alt.Axis(labelLimit=144)),
        x=alt.X(f"{metric}:Q", title=label),
        tooltip=[alt.Tooltip("Variant:N"), alt.Tooltip(f"{metric}:Q", title=label, format=".4g"),
                 alt.Tooltip("Holdout records:Q")]).properties(height=height)
    st.altair_chart(chart, alt=f"{label} measured for each displayed configuration.")


def _plain_summary(jobs):
    for job in jobs:
        variants = job.result["variants"]
        baseline = next((row for row in variants if row["configuration"] == "E0"), None)
        protected = [row for row in variants if row["configuration"] != "E0"]
        if not baseline or not protected:
            continue
        selected = next((row for row in protected if row["configuration"] == "E4"), protected[0])
        label = CONFIGURATIONS[selected["configuration"]]
        recall_key = "recall" if job.config["dataset"] == "synthetic" else "known_positive_recall"
        old, new = baseline["utility"][recall_key], selected["utility"][recall_key]
        relation = "matched" if old == new else "changed"
        st.markdown(f"**{label} {relation} baseline recall.** "
                    f"Baseline {old:.1%} · {selected['id']} {new:.1%}.")
        original = baseline["privacy"]["unchanged_fraction"]
        here = selected["privacy"]["unchanged_fraction"]
        if original is not None and here is not None:
            st.caption(f"Identifier values left unchanged · baseline {original:.1%} · {selected['id']} {here:.1%}.")
        break


def _overhead(jobs, data):
    st.header("Measured processing cost")
    compare = st.selectbox("Cost metric", list(_RESOURCE), format_func=_RESOURCE.get, key="lab_cost_metric")
    _bars(data, compare, _RESOURCE[compare], color="#43B5A0", height=230)
    _note(jobs)
    with st.expander("View measured cost data"):
        show_frame(data[["Variant", *_RESOURCE]].rename(columns=_RESOURCE))
        st.caption("Peak RSS is sampled every 20 ms, including resident libraries and data. "
                   "Process CPU percentage can exceed 100% across cores.")


def _frontier(jobs, data):
    st.header("Privacy–Utility Frontier")
    if "f1" not in data or not data["epsilon"].notna().any():
        empty_state("No accounted DP results in this selection.",
                    "Run differentially private training on the synthetic dataset, then select the completed run.")
        return
    st.markdown("**F1 versus accounted epsilon**")
    _scatter(data, "epsilon", "f1", "Privacy budget ε (accounted)", "Holdout F1", frontier=True)
    _note(jobs)
    st.caption("The frontier keeps variants for which no measured point has lower or equal ε and higher or equal F1. "
               "A line appears when at least two distinct frontier points are available.")
    with st.expander("View frontier data"):
        show_frame(data.loc[data["epsilon"].notna(), ["Variant", "epsilon", "delta", "f1", "Holdout records"]]
                   .rename(columns={"epsilon": "Accounted ε", "delta": "δ", "f1": "F1"}))
    definitions("Epsilon and delta", "F1", title="Reading the frontier")


def _display_comparison(jobs):
    data = _display_frame(jobs)
    synthetic = jobs[0].config["dataset"] == "synthetic"
    _plain_summary(jobs)
    _note(jobs)
    visible = (["f1", "precision", "recall"] if synthetic else
               ["observed_label_average_precision", "known_positive_recall", "unlabelled_flag_rate"])
    metric = visible[0]
    st.header("Detection results")
    summary = data[["Variant label", *visible]].copy()
    if synthetic and "F1 change" in data:
        summary["F1 change"] = data["F1 change"]
    show_frame(summary.rename(columns={**_SCORES, "Variant label": "Configuration"}),
               column_config={name: st.column_config.NumberColumn(format="%.3f")
                              for name in [*(_SCORES[key] for key in visible), "F1 change"]})
    _bars(data, metric, _SCORES[metric], height=max(140, min(265, 28 * len(data))))
    definitions("Precision", "Recall", "F1", title="Understand the detection metrics")
    detailed = advanced() or st.toggle("Advanced details", key="lab_detail_toggle")
    if detailed:
        metric_view, privacy_view, resource_view = st.tabs(["Full detection metrics", "Privacy measures", "Compute cost"])
        with metric_view:
            show_frame(data[["Variant", *(key for key in _SCORES if key in data)]].rename(columns=_SCORES))
            if synthetic:
                st.markdown("**Confusion counts on the utility holdout**")
                show_frame([{"Variant": f"{job.id[:6]} · {variant['id']}", **variant["utility"]["confusion"]}
                            for job in jobs for variant in job.result["variants"]])
                if data["epsilon"].notna().any():
                    st.markdown("**F1 versus accounted epsilon**")
                    _scatter(data, "epsilon", "f1", "Accounted epsilon", "Holdout F1")
            else:
                st.caption(jobs[0].result["cohort"]["label_definition"])
        with privacy_view:
            show_frame(data[["Variant", "identifier_cells_unchanged", "synthetic_linkage_success",
                             "membership_auc", "membership_advantage", "epsilon", "delta"]].rename(columns={
                                 "epsilon": "Privacy budget ε", "delta": "δ",
                                 "identifier_cells_unchanged": "Identifier cells unchanged",
                                 "synthetic_linkage_success": "Synthetic linkage success",
                                 "membership_auc": "Membership ROC AUC", "membership_advantage": "Membership advantage"}))
            if synthetic:
                _scatter(data, "identifier_cells_unchanged", "f1", "Unchanged identifier fraction", "Holdout F1")
                st.caption(jobs[0].result["scope"]["membership"])
                st.caption(jobs[0].result["scope"]["linkage"])
            st.caption(jobs[0].result["scope"]["identifiers"])
        with resource_view:
            show_frame(data[["Variant", *_RESOURCE]].rename(columns=_RESOURCE))
    with st.expander("Study assumptions"):
        st.caption(jobs[0].result["cohort"]["split_method"])
        st.caption(jobs[0].result["cohort"]["label_definition"])
        if data["epsilon"].notna().any():
            st.caption(jobs[0].result["scope"]["dp"])
    return data.drop(columns=["Variant label", "Holdout records"])

def run_exports(registry, case, jobs, frame, *, prefix):
    payload = [{"run_id": job.id, "investigation_id": case, "configuration": job.config,
                "created_utc": job.created, "finished_utc": job.finished, "result": job.result} for job in jobs]
    cols = st.columns(2)
    for column, (fmt, data, mime) in zip(cols, (
        ("csv", frame.to_csv(index=False), "text/csv"),
        ("json", json.dumps(payload, indent=2, allow_nan=False), "application/json"),
    )):
        column.download_button(f"Download {fmt.upper()}",
                               data, f"privforensics-evaluation.{fmt}", mime,
                               key=f"{prefix}_{fmt}",
                               on_click=registry.record,
                               args=(case, "report_exported", {"format": fmt, "jobs": [job.id for job in jobs]}))


def _run_detail(store, registry, case, job, root):
    job_status(store, case, job, root)
    provenance(job.config["dataset_sha256"], source=DATASETS[job.config["dataset"]], key=f"lab_run_{job.id}",
               metadata={"Run ID": job.id, "Seed": job.config["seed"]})
    st.caption(f"Run {job.id} · {DATASETS[job.config['dataset']]} · {job.config['model']} · seed {job.config['seed']}")
    if job.parent_id:
        st.caption(f"Rerun of {job.parent_id}")
    if job.status not in ACTIVE:
        if st.button("Rerun saved configuration", key=f"rerun_{job.id}"):
            job_id, new = store.submit(case, "evaluation", job.config, parent_id=job.id)
            if new:
                launch_worker(registry, root)
            st.session_state[f"lab_pending_{case}"] = job_id
            st.rerun()
    if not job.result:
        with st.expander("Saved configuration"):
            st.json(job.config)
        return
    frame = _display_comparison([job])
    private = [variant for variant in job.result["variants"] if "epsilon_spent" in variant["privacy"]]
    if private:
        with st.expander("Privacy accounting and composition"):
            fields = ["epsilon_target", "epsilon_spent", "delta", "clip_norm", "noise_multiplier",
                      "epochs", "optimizer_steps", "expected_batch_size", "sample_rate", "accountant"]
            st.dataframe([{"Variant": variant["id"], **{key: variant["privacy"][key] for key in fields}}
                          for variant in private], hide_index=True)
            ledger = store.private_training_ledger(job.config["dataset_sha256"])
            st.caption(f"Basic composition across {ledger['fits']} completed Lab fits on this source fingerprint. "
                       f"Σ ε = {ledger['epsilon_sum']:.4f} · Σ δ = {ledger['delta_sum']:.4g}.")
            st.caption(job.result["scope"]["dp"])
            st.caption("The sums describe recorded training mechanisms. The diagnostic and baseline outputs "
                       "do not inherit a privacy bound from the DP runs.")
    with st.expander("Reproduce · run manifest"):
        st.caption(job.result["cohort"]["label_definition"])
        st.caption(job.result["cohort"]["split_method"])
        st.dataframe([{"Split": name, **values} for name, values in job.result["cohort"]["splits"].items()],
                     hide_index=True)
        st.json({"configuration": job.config, "feature_version": job.result["feature_version"],
                 "environment": job.result["environment"]}, expanded=False)
    run_exports(registry, case, [job], frame, prefix="lab_detail")


def _history(store, registry, case, root):
    jobs = store.list(case, "evaluation", limit=50)
    if not jobs:
        empty_state("No evaluation results are available.", "Run an experiment to compare privacy and detection performance.")
        return
    by_id = {job.id: job for job in jobs}
    show_frame([{"Run": job.id[:8], "Status": job.status.capitalize(),
                   "Dataset": DATASETS[job.config["dataset"]], "Model": job.config["model"],
                   "Configurations": ", ".join(job.config["configurations"]), "Queued (UTC)": job.created[:19]}
                  for job in jobs], hide_index=True, height=180)
    key = f"lab_selected_{case}"
    if pending := st.session_state.pop(f"lab_focus_{case}", None):
        st.session_state[key] = pending
    job = st.selectbox("Inspect evaluation run", list(by_id), format_func=lambda value: job_label(by_id[value]),
                       key=key)
    if job:
        _run_detail(store, registry, case, by_id[job], root)


def _compare(store, registry, case, view):
    complete = {job.id: job for job in store.list(case, "evaluation", limit=50) if job.status == "succeeded"}
    if not complete:
        st.info("Complete an evaluation run to compare measured variants.")
        return
    defaults = (next((key for key, job in complete.items() if any(
        "epsilon_spent" in variant["privacy"] for variant in job.result["variants"])), None)
        if view == "Frontier" else None)
    ids = st.multiselect("Completed runs", list(complete), default=[defaults] if defaults else list(complete)[:1],
                         max_selections=4, key=f"lab_compare_{view}_{case}",
                         format_func=lambda key: job_label(complete[key]))
    if not ids:
        return
    jobs = [complete[key] for key in ids]
    first = jobs[0]
    if any((job.config["dataset_sha256"], job.result["feature_version"], job.result["cohort"]["splits"])
           != (first.config["dataset_sha256"], first.result["feature_version"], first.result["cohort"]["splits"])
           for job in jobs[1:]):
        st.warning("Select runs with the same dataset fingerprint, feature version and cohort splits.")
        return
    if view == "Compare":
        frame = _display_comparison(jobs)
    else:
        frame = _display_frame(jobs)
        if view == "Frontier":
            _frontier(jobs, frame)
        else:
            _overhead(jobs, frame)
    run_exports(registry, case, jobs, frame, prefix=f"lab_{view}")


def render_lab(registry, case, root, sources, archived):
    st.caption("Compare detection utility, identifier exposure and compute cost on the same forensic cohort.")
    if not case:
        st.info("Select an investigation to configure experiments and retain their evidence references.")
        st.button("Open Investigations", on_click=lambda: st.session_state.update(navigation="Investigations"))
        return
    store = JobStore(registry)
    view_key = f"lab_view_{case}"
    if pending := st.session_state.pop(f"lab_pending_{case}", None):
        st.session_state[view_key] = "Run history"
        st.session_state[f"lab_focus_{case}"] = pending
    if pending_view := st.session_state.pop(f"lab_view_pending_{case}", None):
        st.session_state[view_key] = pending_view
    views = ["Configure", "Run history", "Compare", "Frontier", "Overhead"]
    names = {"Configure": "Run", "Run history": "Results and reproduce"}
    view = st.radio("Lab workspace", views, format_func=lambda value: names.get(value, value),
                    horizontal=True, label_visibility="collapsed", key=view_key)
    if view == "Configure":
        _configure(store, registry, case, root, sources)
        if advanced():
            with st.expander("Archived project benchmark"):
                st.caption("Measurements from the original command-line study.")
                archived()
    elif view == "Run history":
        _history(store, registry, case, root)
    else:
        _compare(store, registry, case, view)
