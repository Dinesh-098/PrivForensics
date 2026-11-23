"""Bounded JSON format for previously trained LANL forest predictors."""
from functools import lru_cache
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd


FORMAT = "privforensics-lanl-forest-v1"
MAX_BYTES = 24 * 1024**2
MAX_NODES = 8192


def _average_path_length(samples):
    samples = np.asarray(samples, dtype=float)
    length = np.zeros(samples.shape, dtype=float)
    length[samples == 2] = 1
    larger = samples > 2
    n = samples[larger]
    length[larger] = 2 * (np.log(n - 1) + np.euler_gamma) - 2 * (n - 1) / n
    return length


def freeze_forest(pipeline, model):
    encoder = pipeline[0].named_transformers_["category"]
    categories = [[None if pd.isna(value) else str(value) for value in group] for group in encoder.categories_]
    estimator = pipeline[-1]
    isolation = model == "Isolation Forest"
    trees = []
    for i, fitted in enumerate(estimator.estimators_):
        tree = fitted.tree_
        feature = tree.feature.copy()
        if isolation:
            used = feature >= 0
            feature[used] = estimator.estimators_features_[i][feature[used]]
            leaf_value = _average_path_length(tree.n_node_samples)
        else:
            counts = tree.value[:, 0, :]
            leaf_value = counts[:, 1] / counts.sum(axis=1)
        # Leaf values on internal nodes and split thresholds on leaves are unused.
        leaf = tree.children_left == -1
        trees.append({
            "left": tree.children_left.tolist(), "right": tree.children_right.tolist(),
            "feature": feature.tolist(), "threshold": np.where(leaf, 0, tree.threshold).tolist(),
            "leaf_value": np.where(leaf, leaf_value, 0).tolist(),
        })
    return {"categories": categories, "trees": trees, "normalizer": (
        float(_average_path_length(estimator.max_samples_)) if isolation else None)}


def _validate_tree(tree, width, isolation):
    left, right, features = [np.asarray(tree[key]) for key in ("left", "right", "feature")]
    threshold, values = [np.asarray(tree[key], dtype=float) for key in ("threshold", "leaf_value")]
    n = left.size
    if (not 1 <= n <= MAX_NODES
            or any(array.shape != (n,) for array in (left, right, features, threshold, values))
            or any(array.dtype.kind not in "iu" for array in (left, right, features))
            or not np.isfinite(threshold).all() or not np.isfinite(values).all()
            or (values < 0).any() or (values > (MAX_NODES if isolation else 1)).any()):
        raise ValueError("Invalid forest node arrays")
    leaf = left == -1
    inner = ~leaf
    index = np.arange(n)[inner]
    descendants = np.concatenate([left[inner], right[inner]])
    if (not np.array_equal(leaf, right == -1)
            or np.any(left[inner] <= index) or np.any(right[inner] <= index)
            or not np.array_equal(np.sort(descendants), np.arange(1, n))
            or np.any((features[inner] < 0) | (features[inner] >= width))):
        raise ValueError("Invalid forest tree structure")
    return left, right, features, threshold, values


@lru_cache(maxsize=2)
def _read_forest(path, mtime_ns, size, digest, model, field_count):
    del mtime_ns
    if not 0 < size <= MAX_BYTES:
        raise ValueError("Forest artifact size is outside the supported range")
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) != size:
        raise ValueError("Forest artifact changed while reading")
    try:
        bundle = json.loads(data)
        if bundle["schema_version"] != FORMAT or bundle["archive_sha256"] != digest:
            raise ValueError("Model bundle and source archive provenance do not match")
        entry = bundle["models"][model]
        cutoff = float(entry["threshold"])
        fit = entry["predictor"]
        categories = fit["categories"]
        if (not math.isfinite(cutoff) or len(categories) != field_count
                or any(not 1 <= len(group) <= 256 or not all(
                    value is None or isinstance(value, str) and len(value) <= 256 for value in group)
                    or len(group) != len(set(group)) for group in categories)):
            raise ValueError("Invalid forest feature schema")
        width = sum(map(len, categories)) + 1
        isolation = model == "Isolation Forest"
        normalizer = float(fit["normalizer"]) if isolation else None
        if isolation and (not math.isfinite(normalizer) or normalizer < 0):
            raise ValueError("Invalid forest path-length normalizer")
        if not 1 <= len(fit["trees"]) <= 256:
            raise ValueError("Invalid forest estimator count")
        trees = [_validate_tree(tree, width, isolation) for tree in fit["trees"]]
    except (KeyError, TypeError, OverflowError, RecursionError) as exc:
        raise ValueError("Invalid JSON forest artifact") from exc
    return categories, cutoff, normalizer, trees


def score_forest(path, digest, model, frame, categorical_fields):
    path = Path(path).resolve(strict=True)
    info = path.stat()
    categories, cutoff, normalizer, trees = _read_forest(
        str(path), info.st_mtime_ns, info.st_size, digest, model, len(categorical_fields))
    columns = []
    for field, group in zip(categorical_fields, categories, strict=True):
        values = frame[field]
        columns.extend(values.isna() if category is None else values.eq(category).fillna(False)
                       for category in group)
    columns.append(frame["hour_in_day"])
    x = np.asarray(np.column_stack(columns), dtype=np.float32)
    score = np.zeros(len(frame), dtype=float)
    for left, right, feature, threshold, values in trees:
        nodes = np.zeros(len(frame), dtype=int)
        depth = np.zeros(len(frame), dtype=int)
        while (mask := left[nodes] != -1).any():
            active = nodes[mask]
            rows = np.flatnonzero(mask)
            nodes[mask] = np.where(x[rows, feature[active]] <= threshold[active], left[active], right[active])
            depth[mask] += 1
        score += values[nodes] if normalizer is None else values[nodes] + depth
    score /= len(trees)
    if normalizer is not None:
        score = np.exp2(-score / normalizer) if normalizer else np.full_like(score, .5)
    return score, cutoff
