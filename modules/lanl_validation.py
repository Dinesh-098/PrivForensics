"""Verify that Parquet rows and the rejection log cover every ingested source line."""

import argparse
from collections import Counter
import json
from pathlib import Path

import numpy as np

from .lanl_parquet import open_export
from .lanl_reader import SCHEMAS


def _rejections(stream, lines_read, counts):
    previous = 0
    for record in stream:
        row = json.loads(record)
        line = row["source_line"]
        if not previous < line <= lines_read:
            raise ValueError("Rejection source lines are out of order or out of range")
        counts[row["reason"]] += 1
        previous = line
        yield line


def validate_export(root, dataset):
    manifest, parquet = open_export(Path(root), dataset)
    lines_read = manifest["lines_read"]
    count = 0
    previous = 0
    minimum_time = maximum_time = None
    previous_time = 0
    timestamps_nondecreasing = True
    rejection_counts = Counter()
    with (Path(root) / dataset / "rejections.jsonl").open(encoding="utf-8") as stream:
        rejected = _rejections(stream, lines_read, rejection_counts)
        next_rejection = next(rejected, None)
        for batch in parquet.iter_batches(
            columns=["source_line", "timestamp_s"], batch_size=262_144,
        ):
            if batch["source_line"].null_count or batch["timestamp_s"].null_count:
                raise ValueError("Null source line or timestamp")
            lines = batch["source_line"].to_numpy()
            times = batch["timestamp_s"].to_numpy()
            last = int(lines[-1])
            if lines[0] <= previous or last > lines_read or np.any(lines[1:] <= lines[:-1]):
                raise ValueError("Parquet source lines are out of order or out of range")
            while next_rejection is not None and next_rejection <= last:
                index = lines.searchsorted(next_rejection)
                if lines[index] == next_rejection:
                    raise ValueError("A source line occurs in Parquet and the rejection log")
                next_rejection = next(rejected, None)
            if times[0] < previous_time or np.any(times[1:] < times[:-1]):
                timestamps_nondecreasing = False
            previous_time = int(times[-1])
            low, high = int(times.min()), int(times.max())
            if low < 1:
                raise ValueError("Invalid relative timestamp")
            minimum_time = low if minimum_time is None else min(minimum_time, low)
            maximum_time = high if maximum_time is None else max(maximum_time, high)
            previous = last
            count += len(lines)
        if next_rejection is not None:
            for _ in rejected:
                pass
    if (
        count != manifest["valid_records"]
        or dict(rejection_counts) != manifest["rejected_by_reason"]
        or count + sum(rejection_counts.values()) != lines_read
    ):
        raise ValueError("Parquet rows and rejections do not cover all processed source lines")

    return {
        "dataset": dataset, "scope": manifest["scope"],
        "archive_sha256": manifest["archive_sha256"],
        "lines_verified": lines_read, "parquet_rows_verified": count,
        "rejected_by_reason": dict(rejection_counts),
        "min_timestamp_s": minimum_time, "max_timestamp_s": maximum_time,
        "source_line_partition_verified": True,
        "timestamps_nondecreasing": timestamps_nondecreasing,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exports", type=Path)
    parser.add_argument("dataset", choices=SCHEMAS, nargs="+")
    args = parser.parse_args()
    try:
        results = [validate_export(args.exports, kind) for kind in args.dataset]
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    print(json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    main()
