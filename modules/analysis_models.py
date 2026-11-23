"""Reproducible forensic model evaluation for synthetic and LANL cohorts."""
from contextlib import contextmanager
import json
from pathlib import Path
import secrets
from tempfile import NamedTemporaryFile
from threading import Event, Thread
from time import perf_counter

import numpy as np
import pandas as pd
import psutil
import pyarrow.parquet as pq
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder

from .forest_artifact import FORMAT, freeze_forest, score_forest
from .privacy import binary_metrics, linkage_benchmark, protect


SEED = 42
CATEGORICAL = {
    "Access_Type": ("Web", "VPN", "SSH", "Database"),
    "Device_Type": ("Laptop", "Desktop", "Mobile", "Tablet"),
    "Location": ("India", "USA", "UK", "Germany", "Singapore"),
}
AUTH_COLUMNS = ["source_line", "timestamp_s", "authentication_type", "logon_type",
                "orientation", "result"]


@contextmanager
def measure(record, *, sample_peak=False):
    process = psutil.Process()
    start = perf_counter()
    initial = process.cpu_times()
    memory = process.memory_info().rss
    peak = memory
    done = Event()

    def sample():
        nonlocal peak
        while not done.wait(.02):
            peak = max(peak, process.memory_info().rss)

    sampler = Thread(target=sample, daemon=True) if sample_peak else None
    if sampler:
        sampler.start()
    try:
        yield
    finally:
        elapsed = perf_counter() - start
        final = process.cpu_times()
        end_memory = process.memory_info().rss
        if sampler:
            done.set()
            sampler.join()
            record["sampled_peak_rss_bytes"] = max(peak, end_memory)
        cpu = final.user + final.system - initial.user - initial.system
        record.update(seconds=round(elapsed, 4), cpu_seconds=round(cpu, 4),
                      mean_process_cpu_percent=round(100 * cpu / max(elapsed, 1e-9), 2),
                      rss_start_bytes=memory, rss_end_bytes=end_memory)


def write_json(path, result):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        pending = Path(stream.name)
        try:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            pending.replace(path)
        finally:
            pending.unlink(missing_ok=True)


def synthetic_features(frame):
    hour = pd.to_numeric(frame["Login_Hour"]).clip(0, 23)
    attempts = pd.to_numeric(frame["Failed_Attempts"]).clip(0, 8)
    features = [hour/23, attempts/8]
    for column, values in CATEGORICAL.items():
        features.extend(frame[column].eq(value).astype(float) for value in values)
    return np.asarray(np.column_stack(features), dtype=np.float32)


def _utility(y, probs):
    labels = (probs >= .5).astype(int)
    return {**binary_metrics(y, labels), "f1": float(f1_score(y, labels, zero_division=0)),
            "roc_auc": float(roc_auc_score(y, probs))}


def _membership(y, probabilities, train_idx, nonmember_idx, seed):
    # Known true labels, confidence scores and equal member/nonmember priors.
    rng = np.random.default_rng(seed)
    m = min(len(train_idx), len(nonmember_idx))
    members = rng.choice(train_idx, m, replace=False)
    others = rng.choice(nonmember_idx, m, replace=False)
    indices = np.concatenate([members, others])
    targets = np.repeat([1, 0], m)
    confidence = np.where(y[indices] == 1, probabilities[indices], 1-probabilities[indices])
    cal, test = train_test_split(np.arange(len(indices)), test_size=.5,
                                stratify=targets, random_state=seed)
    thresholds = np.unique(np.quantile(confidence[cal], np.linspace(0, 1, 101)))
    threshold = max(thresholds, key=lambda t: binary_metrics(
        targets[cal], (confidence[cal] >= t).astype(int))["advantage"])
    predicted = (confidence[test] >= threshold).astype(int)
    return {**binary_metrics(targets[test], predicted), "threshold": float(threshold),
            "held_out_queries": len(test),
            "roc_auc": float(roc_auc_score(targets[test], confidence[test]))}


def synthetic_experiment(frame, seed=SEED, budgets=(4., 8.), epochs=8):
    import torch
    from opacus import PrivacyEngine
    from torch.utils.data import DataLoader, TensorDataset

    features = synthetic_features(frame)
    transforms = []
    ephemeral_key = secrets.token_bytes(32)
    for protection in ("mask", "hmac"):
        overhead = {}
        with measure(overhead):
            protected = protect(frame, protection, ephemeral_key)
        unchanged = np.array_equal(features, synthetic_features(protected))
        if not unchanged:
            raise ValueError("Identifier protection changed the model features")
        transforms.append({"mechanism": protection, "rows": len(frame),
                           "model_inputs_preserved": unchanged, "performance": overhead})
    targets = frame["Status"].to_numpy(dtype=np.int64, copy=True)
    train, rest = train_test_split(np.arange(len(frame)), test_size=.4,
                                  stratify=targets, random_state=seed)
    test, nonmembers = train_test_split(rest, test_size=.5, stratify=targets[rest],
                                      random_state=seed)
    x, y = torch.from_numpy(features), torch.from_numpy(targets)
    delta = 1e-5
    model_runs = []
    # Fitting the same fixed, per-record transform uses no training-set statistics.
    torch.set_num_threads(2)
    for budget in (None, *budgets):
        torch.manual_seed(seed)
        network = torch.nn.Sequential(torch.nn.Linear(x.shape[1], 24), torch.nn.ReLU(),
                                      torch.nn.Linear(24, 2))
        optimizer = torch.optim.SGD(network.parameters(), lr=.4)
        loader = DataLoader(TensorDataset(x[train], y[train]), batch_size=256, shuffle=True)
        performance = {}
        engine = None
        with measure(performance):
            if budget is not None:
                engine = PrivacyEngine(accountant="rdp")
                network, optimizer, loader = engine.make_private_with_epsilon(
                    module=network, optimizer=optimizer, data_loader=loader,
                    target_epsilon=budget, target_delta=delta, epochs=epochs, max_grad_norm=1.,
                )
            network.train()
            for _ in range(epochs):
                for batch, labels in loader:
                    optimizer.zero_grad()
                    loss = torch.nn.functional.cross_entropy(network(batch), labels, reduction="sum")
                    if len(batch):
                        loss = loss / len(batch)
                    loss.backward()
                    optimizer.step()
            epsilon = float(engine.get_epsilon(delta)) if engine else None
        network.eval()
        with torch.no_grad():
            predictions = network(x).softmax(-1)[:, 1].numpy()
        model_runs.append({"model": "Baseline MLP" if budget is None else f"DP-SGD target {budget:g}",
                           "epsilon_target": budget, "epsilon_spent": epsilon,
                           "delta": delta if budget is not None else None,
                           "noise_multiplier": float(optimizer.noise_multiplier) if engine else None,
                           "utility": _utility(targets[test], predictions[test]),
                           "membership": _membership(targets, predictions, train, nonmembers, seed),
                           "performance": performance})
    return {"seed": seed, "epochs": epochs, "training_rows": len(train), "test_rows": len(test),
            "membership_nonmembers": len(nonmembers),
            "privacy_unit": "one training row", "secure_rng": False,
            "label_definition": "Rules from dataset/generate_dataset.py",
            "models": model_runs, "linkage": linkage_benchmark(seed), "data_transforms": transforms}


def _cohort(root, seed, *, include_identifiers=False, progress=None):
    auth = pq.ParquetFile(root / "auth/events.parquet")
    annotations = pq.read_table(root / "correlation/auth_matches.parquet").to_pylist()
    known = {row["auth_candidate_lines"][0] for row in annotations if row["status"] == "unique_match"}
    excluded = {line for row in annotations for line in row["auth_candidate_lines"]}
    if not known:
        raise ValueError("No uniquely matched red-team events")
    positives = np.asarray(sorted(known))
    last_time = max(int(row["timestamp_s"]) for row in annotations)
    rng = np.random.default_rng(seed)
    source = auth.schema_arrow.get_field_index("source_line")
    time = auth.schema_arrow.get_field_index("timestamp_s")
    groups = []
    for index in range(auth.num_row_groups):
        stats = auth.metadata.row_group(index).column(time).statistics
        if stats.min <= last_time:
            groups.append(index)
    picks = set(np.linspace(0, len(groups)-1, min(144, len(groups)), dtype=int))
    parts = []
    columns = list(AUTH_COLUMNS)
    if include_identifiers:
        columns.extend(["source_account", "destination_account", "source_computer", "destination_computer"])
    for position, idx in enumerate(groups):
        if progress and position % 20 == 0:
            progress(position, len(groups))
        stats = auth.metadata.row_group(idx).column(source).statistics
        offset = np.searchsorted(positives, stats.min)
        has_positive = offset < len(positives) and positives[offset] <= stats.max
        if not has_positive and position not in picks:
            continue
        table = auth.read_row_group(idx, columns=columns).to_pandas()
        if position in picks:
            size = min(240, len(table))
            selected = table.iloc[rng.choice(len(table), size, replace=False)]
            parts.append(selected[~selected.source_line.isin(excluded)])
        if has_positive:
            parts.append(table[table.source_line.isin(known)])
    if not parts:
        raise ValueError("The authentication export has no records in the annotated interval")
    frame = pd.concat(parts, ignore_index=True).sort_values("timestamp_s", kind="stable")
    frame = frame[frame.timestamp_s.le(last_time)].copy()
    frame["positive"] = frame.source_line.isin(known)
    frame["hour_in_day"] = (frame.timestamp_s // 3600) % 24
    day = frame.timestamp_s // 86400
    bounds = np.quantile(frame.loc[frame.positive, "timestamp_s"] // 86400, [.60, .80], method="nearest")
    if bounds[0] == bounds[1]:
        raise ValueError("Insufficient distinct days for chronological validation")
    frame["split"] = np.select([day < bounds[0], day < bounds[1]], ["train", "validation"], default="test")
    return frame, [int(bound) for bound in bounds]


def fit_lanl_model(train, name, seed):
    features = [*AUTH_COLUMNS[2:], "hour_in_day"]
    encoding = ColumnTransformer([
        ("category", OneHotEncoder(handle_unknown="ignore"), AUTH_COLUMNS[2:]),
        ("hour", "passthrough", ["hour_in_day"]),
    ])
    if name == "Random Forest":
        estimator = RandomForestClassifier(
            n_estimators=100, max_depth=12, min_samples_leaf=5, class_weight="balanced",
            random_state=seed, n_jobs=2)
        return make_pipeline(encoding, estimator).fit(train[features], train.positive)
    if name == "Isolation Forest":
        estimator = IsolationForest(n_estimators=80, max_samples=2048, random_state=seed, n_jobs=2)
        return make_pipeline(encoding, estimator).fit(train.loc[~train.positive, features])
    raise ValueError("Unsupported LANL model")


def lanl_experiment(root, seed=SEED, model_path=None, *, progress=None):
    performance = {}
    with measure(performance):
        frame, boundaries = _cohort(Path(root), seed, progress=(
            lambda done, total: progress(8 + int(62 * done / max(total, 1)), "Sampling chronological event groups")
            if progress else None))
    train, validation, test = [frame[frame.split.eq(k)] for k in ("train", "validation", "test")]
    if any(part.positive.nunique() != 2 for part in (train, validation, test)):
        raise ValueError("A chronological LANL split lacks one observed class")
    categorical = AUTH_COLUMNS[2:]
    features = [*categorical, "hour_in_day"]

    model_runs = []
    findings = []
    trained = {}
    for index, name in enumerate(("Random Forest", "Isolation Forest")):
        if progress:
            progress(72 + index * 11, f"Fitting {name}")
        overhead = {}
        with measure(overhead):
            pipeline = fit_lanl_model(train, name, seed)
        estimator = pipeline[-1]
        if name == "Random Forest":
            scores = pipeline.predict_proba(test[features])[:, 1]
            validation_scores = pipeline.predict_proba(validation[features])[:, 1]
            explanation = dict(zip(pipeline[0].get_feature_names_out().tolist(),
                                   map(float, estimator.feature_importances_)))
            explanation = dict(sorted(explanation.items(), key=lambda item: -item[1])[:8])
        else:
            scores = -pipeline.score_samples(test[features])
            validation_scores = -pipeline.score_samples(validation[features])
            explanation = {}
        threshold = float(np.quantile(validation_scores, .95))
        flagged = scores >= threshold
        if model_path is not None:
            trained[name] = {"predictor": freeze_forest(pipeline, name), "threshold": threshold}
        positives = test.positive.to_numpy()
        model_runs.append({
            "model": name, "observed_label_average_precision": float(average_precision_score(positives, scores)),
            "observed_positive_recall": float(flagged[positives].mean()),
            "unlabelled_flag_rate": float(flagged[~positives].mean()),
            "validation_95th_percentile_threshold": threshold, "top_feature_importance": explanation,
            "performance": overhead,
        })
        for i in np.argsort(-scores, kind="stable")[:100]:
            event = test.iloc[int(i)]
            findings.append({
                "model": name, "source_line": int(event.source_line),
                "timestamp_s": int(event.timestamp_s), "risk_score": float(scores[i]),
                "flagged": bool(flagged[i]),
                "ground_truth": "known red team" if positives[i] else "unlabelled",
                "evidence_summary": {k: str(event[k]) for k in features},
            })
    archive_hash = pq.ParquetFile(Path(root) / "auth/events.parquet").schema_arrow.metadata[b"archive_sha256"].decode()
    if model_path is not None:
        if Path(model_path).suffix != ".json":
            raise ValueError("Use a .json output path for the numeric forest artifact")
        write_json(model_path, {"schema_version": FORMAT, "archive_sha256": archive_hash,
                                "fit_seed": seed, "models": trained})
    return {"seed": seed, "split_boundary_days": boundaries,
            "splits": {name: {"rows": len(part), "known_positives": int(part.positive.sum())}
                       for name, part in [("train", train), ("validation", validation), ("test", test)]},
            "archive_sha256": archive_hash,
            "models": model_runs, "findings": findings, "cohort_performance": performance}


def score_auth_group(root, artifact, model, group, limit=200):
    """Score a bounded range in an existing local LANL Parquet row group."""
    if not 1 <= limit <= 500:
        raise ValueError("Score between 1 and 500 records per request")
    parquet = pq.ParquetFile(Path(root) / "auth/events.parquet")
    if not 0 <= group < parquet.num_row_groups:
        raise ValueError("Unknown Parquet row group")
    digest = parquet.schema_arrow.metadata[b"archive_sha256"].decode()
    batch = next(parquet.iter_batches(
        columns=AUTH_COLUMNS, row_groups=[group], batch_size=limit,
    ), None)
    if batch is None:
        raise ValueError("The selected row group contains no events")
    frame = batch.to_pandas()
    frame["hour_in_day"] = (frame.timestamp_s // 3600) % 24
    values, threshold = score_forest(artifact, digest, model, frame, AUTH_COLUMNS[2:])
    frame["risk_score"] = values
    frame["flagged"] = frame["risk_score"].ge(threshold)
    frame["ground_truth"] = "unchecked"
    return frame.sort_values("risk_score", ascending=False)


def process_experiment(root, seed=SEED, *, progress=None):
    parquet = pq.ParquetFile(Path(root) / "proc/events.parquet")
    rng = np.random.default_rng(seed)
    parts = []
    overhead = {}
    columns = ["source_line", "timestamp_s", "process", "action"]
    with measure(overhead):
        groups = np.linspace(0, parquet.num_row_groups-1, min(28, parquet.num_row_groups), dtype=int)
        if not len(groups):
            raise ValueError("The process export has no accepted rows")
        for index, group in enumerate(groups):
            if progress:
                progress(8 + int(62 * index / len(groups)), "Sampling process event groups")
            part = parquet.read_row_group(int(group), columns=columns).to_pandas()
            parts.append(part.iloc[rng.choice(len(part), min(len(part), 280), replace=False)])
        frame = pd.concat(parts).sort_values("timestamp_s", kind="stable")
        cut = int(len(frame)*.75)
        train, test = frame.iloc[:cut].copy(), frame.iloc[cut:].copy()
        counts = train.process.value_counts()
        for split in (train, test):
            split["training_frequency"] = split.process.map(counts).fillna(0).astype(int)
            split["frequency"] = np.log1p(split["training_frequency"])
            split["hour"] = (split.timestamp_s // 3600) % 24
            split["start"] = split.action.eq("Start").astype(int)
        variables = ["frequency", "hour", "start"]
        if progress:
            progress(78, "Fitting process Isolation Forest")
        estimator = IsolationForest(n_estimators=80, random_state=seed, n_jobs=2).fit(train[variables])
        scores = -estimator.score_samples(test[variables])
        order = np.argsort(-scores, kind="stable")[:50]
    return {"training_rows": len(train), "test_rows": len(test), "performance": overhead,
            "archive_sha256": parquet.schema_arrow.metadata[b"archive_sha256"].decode(),
            "findings": [{"source_line": int(test.iloc[int(i)].source_line),
                          "timestamp_s": int(test.iloc[int(i)].timestamp_s),
                          "risk_score": float(scores[i]), "action": str(test.iloc[int(i)].action),
                          "training_sample_frequency": int(test.iloc[int(i)].training_frequency),
                          "ground_truth": "unlabelled"} for i in order]}
