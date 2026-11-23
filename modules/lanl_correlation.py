"""Correlate LANL red-team keys with authentication and process evidence."""

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from .lanl_parquet import open_export


ENDPOINTS = ("source_computer", "destination_computer")


def _batches(parquet, columns, start, end):
    """Prune by time bounds without assuming globally sorted events."""
    time_index = parquet.schema_arrow.get_field_index("timestamp_s")
    for index in range(parquet.num_row_groups):
        stats = parquet.metadata.row_group(index).column(time_index).statistics
        if stats and stats.has_min_max and (stats.max < start or stats.min > end):
            continue
        yield from parquet.iter_batches(
            columns=columns, row_groups=[index], batch_size=131_072
        )


def _auth_candidates(parquet, keys, checkpoint=None):
    candidates = defaultdict(list)
    destination_only = Counter()
    times = sorted({key[0] for key in keys})
    if not times:
        return candidates, destination_only
    columns = ["source_line", "timestamp_s", "source_account", "destination_account", *ENDPOINTS]
    time_values = pa.array(times, type=pa.int64())
    for i, batch in enumerate(_batches(parquet, columns, times[0], times[-1]), 1):
        if checkpoint and i % 16 == 1:
            checkpoint(25, f"Matching authentication · batch {i:,}")
        batch = batch.filter(pc.is_in(batch["timestamp_s"], value_set=time_values))
        if not batch.num_rows:
            continue
        values = batch.to_pydict()
        for line, time, source, destination, src_host, dst_host in zip(
            *(values[column] for column in columns)
        ):
            source_key = (time, source, src_host, dst_host)
            if source_key in keys:
                candidates[source_key].append(line)
            else:
                destination_key = (time, destination, src_host, dst_host)
                if destination_key in keys:
                    destination_only[destination_key] += 1
    return candidates, destination_only


def _process_links(parquet, keys, window, checkpoint=None):
    account_hosts = defaultdict(list)
    for (time, account, src_host, dst_host), lines in keys.items():
        if src_host == dst_host:
            account_hosts[account, src_host].append((time, lines[0], "both"))
        else:
            account_hosts[account, src_host].append((time, lines[0], "source"))
            account_hosts[account, dst_host].append((time, lines[0], "destination"))
    account_hosts = {
        pair: sorted(anchors)
        for pair, anchors in account_hosts.items()
        if None not in pair
    }
    if not account_hosts:
        return
    indexed = {pair: ([a[0] for a in items], items) for pair, items in account_hosts.items()}
    accounts = pa.array(sorted({pair[0] for pair in indexed}), type=pa.string())
    hosts = pa.array(sorted({pair[1] for pair in indexed}), type=pa.string())
    times = np.array(sorted({a[0] for items in account_hosts.values() for a in items}), dtype=np.int64)
    low, high = max(1, int(times[0]) - window), int(times[-1]) + window
    columns = ["source_line", "timestamp_s", "account", "computer"]
    for i, batch in enumerate(_batches(parquet, columns, low, high), 1):
        if checkpoint and i % 16 == 1:
            checkpoint(65, f"Linking process context · batch {i:,}")
        batch = batch.filter(pc.and_(
            pc.is_in(batch["account"], value_set=accounts),
            pc.is_in(batch["computer"], value_set=hosts),
        ))
        if not batch.num_rows:
            continue
        time_values = batch["timestamp_s"].to_numpy()
        ahead = np.searchsorted(times, time_values)
        before = times[np.maximum(ahead - 1, 0)]
        after = times[np.minimum(ahead, len(times) - 1)]
        batch = batch.filter(pa.array(
            (np.abs(time_values - before) <= window)
            | (np.abs(after - time_values) <= window)
        ))
        values = batch.to_pydict()
        for line, time, account, host in zip(*(values[name] for name in columns)):
            pair = (account, host)
            if pair in indexed:
                anchor_times, anchors = indexed[pair]
                start = bisect_left(anchor_times, time - window)
                end = bisect_right(anchor_times, time + window)
                for anchor_time, anchor_line, role in anchors[start:end]:
                    yield {
                        "redteam_anchor_line": anchor_line, "process_source_line": line,
                        "host_role": role, "offset_seconds": time - anchor_time,
                    }


def correlate(exports, output, *, window=60, checkpoint=None):
    """Publish red-team anchors, auth candidates and contextual process links."""
    if not 0 <= window <= 86_400:
        raise ValueError("window must be between 0 and 86400 seconds")
    exports, output = Path(exports), Path(output)
    if os.path.lexists(output):
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    auth, proc, red = [open_export(exports, kind) for kind in ("auth", "proc", "redteam")]
    keys = defaultdict(list)
    incomplete = 0
    for batch in red[1].iter_batches():
        for row in batch.to_pylist():
            key = (row["timestamp_s"], row["account"], *(row[name] for name in ENDPOINTS))
            keys[key].append(row["source_line"])
            incomplete += int(None in key)
    candidates, destination_only = _auth_candidates(
        auth[1], {key for key in keys if None not in key}, checkpoint
    )
    metadata = {
        f"{manifest['dataset']}_sha256".encode("ascii"): manifest["archive_sha256"].encode("ascii")
        for manifest, _ in (auth, proc, red)
    }
    auth_schema = pa.schema([
        ("redteam_anchor_line", pa.int64()), ("redteam_source_lines", pa.list_(pa.int64())),
        ("timestamp_s", pa.int64()), ("auth_candidate_lines", pa.list_(pa.int64())),
        ("destination_only_candidates", pa.int64()), ("status", pa.string()),
    ], metadata=metadata)
    proc_schema = pa.schema([
        ("redteam_anchor_line", pa.int64()), ("process_source_line", pa.int64()),
        ("host_role", pa.string()), ("offset_seconds", pa.int32()),
    ], metadata={**metadata, b"window_seconds": str(window).encode("ascii")})

    rows = []
    statuses = Counter()
    for key, lines in keys.items():
        matches = candidates[key]
        status = "incomplete_key"
        if None not in key:
            status = {0: "no_match", 1: "unique_match"}.get(len(matches), "ambiguous_match")
        statuses[status] += 1
        rows.append({
            "redteam_anchor_line": lines[0], "redteam_source_lines": lines,
            "timestamp_s": key[0], "auth_candidate_lines": matches,
            "destination_only_candidates": destination_only[key], "status": status,
        })

    context_count = 0
    context_anchors = set()
    with TemporaryDirectory(dir=output.parent) as temporary:
        stage = Path(temporary) / "correlation"
        stage.mkdir()
        auth_path, proc_path = stage / "auth_matches.parquet", stage / "process_context.parquet"
        pq.write_table(pa.Table.from_pylist(rows, schema=auth_schema), auth_path, compression="zstd")
        with pq.ParquetWriter(proc_path, proc_schema, compression="zstd") as writer:
            batch = []
            for link in _process_links(proc[1], keys, window, checkpoint):
                context_anchors.add(link["redteam_anchor_line"])
                context_count += 1
                batch.append(link)
                if len(batch) == 65_536:
                    writer.write_table(pa.Table.from_pylist(batch, schema=proc_schema))
                    batch.clear()
            if batch:
                writer.write_table(pa.Table.from_pylist(batch, schema=proc_schema))
        if pq.read_metadata(auth_path).num_rows != len(keys) or pq.read_metadata(proc_path).num_rows != context_count:
            raise ValueError("Correlation output row counts are inconsistent")

        manifest = {
            "inputs": {item["dataset"]: {"scope": item["scope"], "sha256": item["archive_sha256"]}
                       for item, _ in (auth, proc, red)},
            "redteam_rows": red[0]["valid_records"], "distinct_redteam_keys": len(keys),
            "duplicate_redteam_rows": red[0]["valid_records"] - len(keys),
            "redteam_rows_with_incomplete_key": incomplete,
            "auth_key_status": dict(sorted(statuses.items())),
            "source_role_auth_candidates": sum(map(len, candidates.values())),
            "destination_only_auth_candidates": sum(destination_only.values()),
            "unmatched_auth_semantics": "unlabelled",
            "process_window_seconds": window, "process_context_links": context_count,
            "redteam_keys_with_process_context": len(context_anchors),
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        if checkpoint:
            checkpoint(98, "Publishing validated correlation output")
        if os.path.lexists(output):
            raise FileExistsError(output)
        stage.rename(output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exports", type=Path, help="directory with auth, proc and redteam exports")
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("--window", type=int, default=60)
    args = parser.parse_args()
    try:
        result = correlate(args.exports, args.output, window=args.window)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    print(json.dumps(result, indent=2), flush=True)


def authentication_context(proc_path, authentication, *, window=60, limit=200):
    """Return the nearest bounded process context by exact account/endpoint pair."""
    from heapq import heappop, heappush, heapreplace

    if not 0 <= window <= 3600 or not 1 <= limit <= 500:
        raise ValueError("Use a time window up to an hour and at most 500 events")
    roles = defaultdict(list)
    for side in ("source", "destination"):
        pair = authentication[f"{side}_account"], authentication[f"{side}_computer"]
        if None not in pair:
            roles[pair].append(side)
    if not roles:
        return {"rows": [], "total_matches": 0}
    timestamp = int(authentication["timestamp_s"])
    low, high = max(1, timestamp - window), min((1 << 63) - 1, timestamp + window)
    columns = ["source_line", "timestamp_s", "account", "computer", "process", "action"]
    accounts = pa.array(sorted({pair[0] for pair in roles}), type=pa.string())
    hosts = pa.array(sorted({pair[1] for pair in roles}), type=pa.string())
    selected = []
    found = 0
    with pq.ParquetFile(proc_path) as parquet:
        for batch in _batches(parquet, columns, low, high):
            time = batch["timestamp_s"]
            candidates = batch.filter(
                pc.and_(pc.and_(pc.greater_equal(time, low), pc.less_equal(time, high)),
                        pc.and_(pc.is_in(batch["account"], value_set=accounts),
                                pc.is_in(batch["computer"], value_set=hosts))))
            for row in candidates.to_pylist():
                matching = roles.get((row["account"], row["computer"]))
                if matching:
                    offset = row["timestamp_s"] - timestamp
                    row.update(endpoint_role=" and ".join(matching), offset_seconds=offset)
                    priority = (-abs(offset), -row["source_line"], row)
                    found += 1
                    if len(selected) < limit:
                        heappush(selected, priority)
                    elif priority[:2] > selected[0][:2]:
                        heapreplace(selected, priority)
    rows = [heappop(selected)[2] for _ in range(len(selected))]
    rows.sort(key=lambda row: (row["timestamp_s"], row["source_line"]))
    return {"rows": rows, "total_matches": found}


if __name__ == "__main__":
    main()
