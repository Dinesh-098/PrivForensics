"""Case-linked experiments with comparable splits, aggregate privacy checks and provenance."""
from dataclasses import dataclass
import hashlib
from importlib import import_module, metadata
from io import BytesIO
import math
from pathlib import Path
import platform
import re
import secrets

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

from .analysis_models import AUTH_COLUMNS, _cohort, _membership, fit_lanl_model, measure, synthetic_features
from .evidence import digest_file, utc
from .lanl_parquet import open_export
from .privacy import IDENTIFIERS, LANL_IDENTIFIERS, QUASI, binary_metrics, linkage_benchmark, protect, protect_lanl


DATASETS = {"synthetic": "Synthetic authentication", "lanl": "LANL authentication"}
MODELS = {
    "synthetic": ("Neural Network", "Random Forest", "Isolation Forest"),
    "lanl": ("Random Forest", "Isolation Forest"),
}
CONFIGURATIONS = {
    "E0": "Standard baseline", "E1": "Masked", "E2": "Pseudonymized",
    "E3": "Masked and pseudonymized", "E4": "DP-SGD",
}
SYNTHETIC = Path("dataset/forensic_auth_logs.csv")
PROCESSED = Path("dataset/processed/lanl-v1")
MAX_SYNTHETIC_BYTES = 16 * 1024**2
RECIPE = "privforensics-lab-v1"
FEATURE_VERSIONS = {"synthetic": "fixed-synthetic-auth-v1", "lanl": "lanl-chronological-auth-v1"}


@dataclass(frozen=True, slots=True)
class Cohort:
    frame: pd.DataFrame
    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray
    nonmembers: np.ndarray
    targets: np.ndarray
    details: dict


def code_fingerprint():
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for name in ("analysis_models.py", "lab.py", "privacy.py"):
        digest.update((source / name).read_bytes())
    return digest.hexdigest()


def synthetic_fingerprint(project):
    return hashlib.sha256(_read_synthetic(project)).hexdigest()


def _read_synthetic(project):
    with (Path(project) / SYNTHETIC).open("rb") as stream:
        data = stream.read(MAX_SYNTHETIC_BYTES + 1)
    if len(data) > MAX_SYNTHETIC_BYTES:
        raise ValueError("The bundled synthetic CSV exceeds the lab's 16 MiB input limit")
    return data


def _lanl_sources(project):
    root = Path(project) / PROCESSED
    manifest, parquet = open_export(root, "auth")
    parquet.close()
    return {
        "archive_sha256": manifest["archive_sha256"],
        "export_manifest_sha256": digest_file(root / "auth/manifest.json"),
        "correlation_sha256": digest_file(root / "correlation/auth_matches.parquet"),
        "correlation_manifest_sha256": digest_file(root / "correlation/manifest.json"),
    }


def _environment(model):
    names = ["numpy", "pandas", "scikit-learn", "psutil", "pyarrow"]
    if model == "Neural Network":
        names.extend(["torch", "opacus"])
    return {"python": platform.python_version(), "platform": platform.platform(),
            "packages": {name: metadata.version(name) for name in names}}


def evaluation_config(project, evidence, dataset, model, configurations, *, seed=42,
                      epochs=8, batch_size=256, budgets=(4., 8.), delta=1e-5, clip=1.):
    if dataset not in DATASETS or not evidence:
        raise ValueError("Choose an available dataset and register its evidence in this investigation")
    codes = tuple(dict.fromkeys(configurations))
    prepared = _lanl_sources(project) if dataset == "lanl" else {}
    expected = synthetic_fingerprint(project) if dataset == "synthetic" else prepared["archive_sha256"]
    if evidence["sha256"] != expected:
        raise ValueError("The registered evidence fingerprint differs from the prepared dataset")
    config = {
        "recipe": RECIPE, "code_sha256": code_fingerprint(), "dataset": dataset,
        "dataset_sha256": expected, "evidence_id": evidence["id"], "model": model,
        "configurations": sorted(codes), "seed": seed, "environment": _environment(model),
    }
    if dataset == "lanl":
        config["derived_sources"] = prepared
    if model == "Neural Network":
        config["neural"] = {"epochs": epochs, "batch_size": batch_size, "learning_rate": .4}
    if "E4" in codes:
        config["dp"] = {"target_epsilons": sorted(set(budgets)), "delta": delta,
                        "clip_norm": clip, "accountant": "rdp", "secure_rng": False}
    validate_config(config)
    return config


def validate_config(config):
    dataset, model, codes = (config[name] for name in ("dataset", "model", "configurations"))
    if dataset not in MODELS or model not in MODELS[dataset]:
        raise ValueError("This model is unavailable for the selected dataset")
    if not codes or any(code not in CONFIGURATIONS for code in codes) or len(set(codes)) != len(codes):
        raise ValueError("Select one or more distinct experimental configurations")
    if "E4" in codes and model != "Neural Network":
        raise ValueError("DP-SGD requires the synthetic neural network")
    if not isinstance(config["seed"], int) or not 0 <= config["seed"] <= 2**32-2:
        raise ValueError("The seed must be an integer from 0 to 4,294,967,294")
    if not re.fullmatch("[a-f0-9]{64}", config["dataset_sha256"]):
        raise ValueError("Invalid dataset fingerprint")
    if config["recipe"] != RECIPE or config["code_sha256"] != code_fingerprint():
        raise ValueError("This configuration needs the original lab code version")
    if config["environment"] != _environment(model):
        raise ValueError("Use the original dependency versions and platform for an exact rerun")
    if model == "Neural Network":
        neural = config["neural"]
        if not 1 <= neural["epochs"] <= 40 or neural["batch_size"] not in (64, 128, 256, 512):
            raise ValueError("Use 1–40 epochs and a supported batch size")
    if "E4" in codes:
        dp = config["dp"]
        budgets = dp["target_epsilons"]
        if not 1 <= len(budgets) <= 4 or any(not 1 <= eps <= 20 for eps in budgets):
            raise ValueError("Use up to four target epsilons from 1 to 20")
        if not 1e-8 <= dp["delta"] <= 1e-4 or not .1 <= dp["clip_norm"] <= 5:
            raise ValueError("Use delta from 1e-8 to 1e-4 and a clipping norm from 0.1 to 5")


def _synthetic_cohort(project, config):
    raw = _read_synthetic(project)
    if hashlib.sha256(raw).hexdigest() != config["dataset_sha256"]:
        raise ValueError("The synthetic source changed after this experiment was configured")
    frame = pd.read_csv(BytesIO(raw))
    required = {*IDENTIFIERS, *QUASI, "Failed_Attempts", "Status"}
    if not required <= set(frame.columns) or not 200 <= len(frame) <= 100_000:
        raise ValueError("The synthetic CSV schema or row count is outside the supported range")
    numeric = frame[["Login_Hour", "Failed_Attempts", "Status"]].apply(pd.to_numeric)
    if (not np.isfinite(numeric.to_numpy()).all()
            or not numeric.Status.isin([0, 1]).all() or not numeric.Login_Hour.between(0, 23).all()
            or not numeric.Failed_Attempts.ge(0).all() or numeric.Status.value_counts().min() < 20
            or numeric.Status.nunique() != 2):
        raise ValueError("The synthetic CSV has invalid values or too few rows in one class")
    targets = numeric.Status.to_numpy(dtype=int)
    seed = config["seed"]
    train, remainder = train_test_split(np.arange(len(frame)), test_size=.4, stratify=targets,
                                        random_state=seed)
    validation, remainder = train_test_split(remainder, train_size=.25, stratify=targets[remainder],
                                             random_state=seed)
    test, nonmembers = train_test_split(remainder, test_size=.5, stratify=targets[remainder],
                                       random_state=seed)
    return Cohort(frame, train, validation, test, nonmembers, targets, {
        "split_method": "stratified 60% fit, 10% validation, 15% test, 15% membership nonmembers",
        "label_definition": "Rule-derived labels from the synthetic authentication generator",
        "privacy_unit": "one synthetic training row",
    })


def _lanl_cohort(project, config, checkpoint):
    if _lanl_sources(project) != config["derived_sources"]:
        raise ValueError("The prepared LANL manifests or correlation data changed after configuration")
    frame, bounds = _cohort(Path(project) / PROCESSED, config["seed"], include_identifiers=True,
                            progress=lambda done, total: checkpoint(
                                5 + int(12 * done / max(1, total)), "Sampling chronological LANL row groups"))
    if _lanl_sources(project) != config["derived_sources"]:
        raise ValueError("The prepared LANL dataset changed during cohort preparation")
    train, val, test = [np.flatnonzero(frame.split.eq(name)) for name in ("train", "validation", "test")]
    targets = frame.positive.to_numpy(dtype=int)
    if any(np.unique(targets[index]).size != 2 for index in (train, val, test)):
        raise ValueError("Each chronological split requires a unique red-team match and unlabelled events")
    return Cohort(frame, train, val, test, np.empty(0, dtype=int), targets, {
        "split_method": "LANL day boundaries with unique red-team reference matches",
        "split_boundary_days": bounds,
        "label_definition": "Unique red-team matches are observed positives. Other sampled events are unlabelled.",
    })


def _split_manifest(cohort):
    result = {}
    for name in ("train", "validation", "test", "nonmembers"):
        index = getattr(cohort, name)
        if not len(index):
            continue
        refs = (cohort.frame.iloc[index].source_line.to_numpy() if "source_line" in cohort.frame
                else index + 2)
        result[name] = {
            "rows": len(index), "positives": int(cohort.targets[index].sum()),
            "source_lines_sha256": hashlib.sha256(np.asarray(refs, dtype="<i8").tobytes()).hexdigest(),
        }
    return result


def _transform(frame, dataset, code, key):
    if code in ("E0", "E4"):
        return frame
    protect_frame = protect if dataset == "synthetic" else protect_lanl
    if code == "E1":
        return protect_frame(frame, "mask")
    if code == "E2":
        return protect_frame(frame, "hmac", key, scope="research")
    hmac_fields = ("User_ID",) if dataset == "synthetic" else tuple(
        field for field, scope in LANL_IDENTIFIERS.items() if scope == "lanl.account")
    fields = IDENTIFIERS if dataset == "synthetic" else LANL_IDENTIFIERS
    masked = protect_frame(frame, "mask", fields=set(fields) - set(hmac_fields))
    return protect_frame(masked, "hmac", key, fields=hmac_fields, scope="research")


def _exposure(original, transformed, dataset):
    identifiers = IDENTIFIERS if dataset == "synthetic" else LANL_IDENTIFIERS
    fields = {}
    for name in identifiers:
        if name not in original:
            continue
        present = original[name].notna()
        unchanged = original[name].eq(transformed[name]).fillna(False) & present
        fields[name] = {"present": int(present.sum()), "unchanged": int(unchanged.sum())}
    n = sum(item["present"] for item in fields.values())
    return {"fields": fields, "identifier_cells": n,
            "unchanged_fraction": sum(item["unchanged"] for item in fields.values()) / n if n else None}


def _train_neural(features, cohort, config, budget, progress):
    import torch
    from opacus import PrivacyEngine
    from torch.utils.data import DataLoader, TensorDataset

    seed = config["seed"]
    neural = config["neural"]
    if len(cohort.train) < neural["batch_size"]:
        raise ValueError("Batch size exceeds the number of training rows")
    torch.set_num_threads(2)
    torch.manual_seed(seed)
    x, y = torch.from_numpy(features), torch.from_numpy(cohort.targets.astype(np.int64))
    network = torch.nn.Sequential(torch.nn.Linear(x.shape[1], 24), torch.nn.ReLU(), torch.nn.Linear(24, 2))
    optimizer = torch.optim.SGD(network.parameters(), lr=neural["learning_rate"])
    loader = DataLoader(TensorDataset(x[cohort.train], y[cohort.train]),
                        batch_size=neural["batch_size"], shuffle=True)
    engine = None
    report = {}
    if budget is not None:
        dp = config["dp"]
        if dp["delta"] >= 1 / len(cohort.train):
            raise ValueError("Set delta below the reciprocal of the training row count")
        engine = PrivacyEngine(accountant=dp["accountant"], secure_mode=dp["secure_rng"])
        network, optimizer, loader = engine.make_private_with_epsilon(
            module=network, optimizer=optimizer, data_loader=loader, target_epsilon=budget,
            target_delta=dp["delta"], epochs=neural["epochs"], max_grad_norm=dp["clip_norm"],
            poisson_sampling=True,
        )
    network.train()
    steps = 0
    for epoch in range(neural["epochs"]):
        progress(epoch, neural["epochs"])
        for data, labels in loader:
            optimizer.zero_grad()
            loss = torch.nn.functional.cross_entropy(network(data), labels, reduction="sum") / max(len(data), 1)
            loss.backward()
            optimizer.step()
            steps += 1
    if engine:
        report = {"epsilon_target": budget, "epsilon_spent": float(engine.get_epsilon(dp["delta"])),
                  "delta": dp["delta"], "noise_multiplier": float(optimizer.noise_multiplier),
                  "clip_norm": dp["clip_norm"], "epochs": neural["epochs"], "optimizer_steps": steps,
                  "expected_batch_size": optimizer.expected_batch_size, "sample_rate": loader.sample_rate,
                  "accountant": dp["accountant"], "secure_rng": dp["secure_rng"],
                  "sampling": "Poisson row sampling", "privacy_unit": "one synthetic training row"}
    network.eval()

    def score(indices):
        with torch.inference_mode():
            return network(x[indices]).softmax(-1)[:, 1].numpy()

    return score, report


def _fit(frame, features, cohort, config, budget, progress):
    model, seed = config["model"], config["seed"]
    if model == "Neural Network":
        return _train_neural(features, cohort, config, budget, progress)
    if config["dataset"] == "lanl":
        trained = fit_lanl_model(frame.iloc[cohort.train], model, seed)
    elif model == "Random Forest":
        trained = RandomForestClassifier(n_estimators=100, min_samples_leaf=3, class_weight="balanced",
                                         random_state=seed, n_jobs=2)
        trained.fit(features[cohort.train], cohort.targets[cohort.train])
    else:
        trained = IsolationForest(n_estimators=80, max_samples=1024, random_state=seed, n_jobs=2)
        trained.fit(features[cohort.train])

    def score(indices):
        rows = features.iloc[indices] if isinstance(features, pd.DataFrame) else features[indices]
        return trained.predict_proba(rows)[:, 1] if model == "Random Forest" else -trained.score_samples(rows)

    return score, {}


def _metrics(cohort, scores, threshold, dataset):
    truth = cohort.targets[cohort.test]
    prediction = (scores >= threshold).astype(int)
    average_precision = float(average_precision_score(truth, scores))
    if dataset == "lanl":
        return {"observed_label_average_precision": average_precision,
                "known_positive_recall": float(prediction[truth == 1].mean()),
                "unlabelled_flag_rate": float(prediction[truth == 0].mean()),
                "flagged": int(prediction.sum())}
    utility = binary_metrics(truth, prediction)
    utility.pop("advantage")
    counts = confusion_matrix(truth, prediction, labels=[0, 1]).ravel()
    return {**utility, "f1": float(f1_score(truth, prediction, zero_division=0)),
            "roc_auc": float(roc_auc_score(truth, scores)), "average_precision": average_precision,
            "confusion": dict(zip(("tn", "fp", "fn", "tp"), map(int, counts)))}


def _variant(cohort, config, code, budget, key, exposure_benchmark, phase):
    dataset = config["dataset"]
    timings = {stage: {} for stage in ("prepare", "train", "inference")}
    phase(0, "Preparing features")
    with measure(timings["prepare"], sample_peak=True):
        frame = _transform(cohort.frame, dataset, code, key)
        features = (synthetic_features(frame) if dataset == "synthetic"
                    else frame[[*AUTH_COLUMNS[2:], "hour_in_day"]])
    phase(.15, "Training")
    with measure(timings["train"], sample_peak=True):
        score, accounting = _fit(frame, features, cohort, config, budget,
                                 lambda epoch, total: phase(.15 + .65 * epoch / total,
                                                            f"Training epoch {epoch + 1}/{total}"))
    phase(.84, "Scoring held-out records")
    with measure(timings["inference"], sample_peak=True):
        scores = score(cohort.test)
    threshold = (.5 if dataset == "synthetic" and config["model"] != "Isolation Forest"
                 else float(np.quantile(score(cohort.validation), .95)))
    membership = None
    if dataset == "synthetic" and config["model"] != "Isolation Forest":
        ids = np.concatenate([cohort.train, cohort.nonmembers])
        probabilities = np.zeros(len(cohort.frame))
        probabilities[ids] = score(ids)
        membership = _membership(cohort.targets, probabilities, cohort.train, cohort.nonmembers, config["seed"])
    timings["inference"]["rows"] = len(cohort.test)
    timings["inference"]["records_per_second"] = (
        round(len(cohort.test) / timings["inference"]["seconds"], 1)
        if timings["inference"]["seconds"] else None)
    return {
        "id": code if budget is None else f"{code} eps {budget:g}", "configuration": code,
        "threshold": threshold, "phase_metrics": timings, "utility": _metrics(cohort, scores, threshold, dataset),
        "privacy": {**accounting, **_exposure(cohort.frame, frame, dataset),
                    "membership": membership, "synthetic_linkage": exposure_benchmark.get(code)},
    }


def run_evaluation(project, registry, job, checkpoint):
    config = job.config
    validate_config(config)
    if not any(row["id"] == config["evidence_id"] and row["sha256"] == config["dataset_sha256"]
               for row in registry.list("evidence", job.case_id)):
        raise ValueError("The source evidence is unavailable in this investigation")
    dataset = config["dataset"]
    checkpoint(4, "Preparing reproducible cohort")
    preparation = {}
    with measure(preparation, sample_peak=True):
        cohort = (_synthetic_cohort(project, config) if dataset == "synthetic"
                  else _lanl_cohort(project, config, checkpoint))
    key = secrets.token_bytes(32)
    benchmarks = {}
    environment_startup = {}
    if config["model"] == "Neural Network":
        with measure(environment_startup, sample_peak=True):
            # Exclude one-time Python and optimizer imports from the first fit.
            import torch
            torch.set_num_threads(2)
            torch.optim.SGD(torch.nn.Linear(1, 1).parameters(), lr=.4)
            import_module("opacus")
    if dataset == "synthetic":
        baseline, masked, hmac, _ = linkage_benchmark(config["seed"])
        benchmarks = {"E0": baseline, "E1": masked, "E2": hmac, "E3": hmac, "E4": baseline}
    schedules = [(code, budget) for code in config["configurations"]
                 for budget in (config["dp"]["target_epsilons"] if code == "E4" else [None])]
    variants = []
    for i, (code, budget) in enumerate(schedules):
        label = code if budget is None else f"{code} ε {budget:g}"

        def phase(fraction, stage):
            checkpoint(18 + math.floor(78 * (i + fraction) / len(schedules)), f"{label} · {stage}")

        variants.append(_variant(cohort, config, code, budget, key, benchmarks, phase))
    checkpoint(98, "Saving measured results")
    return {
        "recipe": RECIPE, "dataset_sha256": config["dataset_sha256"],
        "feature_version": FEATURE_VERSIONS[dataset], "finished_utc": utc(),
        "model_version": config["code_sha256"], "cohort": {**cohort.details, "splits": _split_manifest(cohort)},
        "cohort_preparation": preparation, "variants": variants,
        "worker_startup": environment_startup, "environment": config["environment"],
        "scope": {
            "dp": "RDP estimates cover DP-SGD training on one synthetic event row per privacy unit. "
                  "Secure RNG is disabled. Models and aggregate training diagnostics remain inside the local study.",
            "membership": "Aggregate true-label confidence separation on the bundled synthetic data only. "
                          "Balanced member and disjoint nonmember queries use separate calibration and evaluation folds.",
            "linkage": "Separate generated auxiliary-data fixture with 2,000 targets, half known. "
                       "E1–E3 keep the same quasi-identifiers, and E4 changes training only.",
            "identifiers": ("Identifier cells are excluded from model features. Data protection may leave scores unchanged."
                            if dataset == "synthetic" else
                            "De-identified account and computer identifiers are excluded from the model features."),
        },
    }
