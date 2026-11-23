"""Export LANL gzip evidence to traceable Parquet in bounded batches."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
from io import BytesIO
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
import zlib

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as arrow_csv
import pyarrow.parquet as pq

from .evidence import stream_sha256
from .lanl_reader import MAX_LINE_BYTES, SCHEMAS, Event, _signature, iter_records


BLOCK_BYTES = 16 * 1024 * 1024
SCHEMA_VERSION = 1


def parquet_schema(dataset, digest):
    columns = SCHEMAS[dataset]
    return pa.schema(
        [pa.field("source_line", pa.int64(), nullable=False),
         pa.field(columns[0], pa.int64(), nullable=False)]
        + [pa.field(name, pa.string()) for name in columns[1:]],
        metadata={
            b"archive_sha256": digest.encode("ascii"),
            b"dataset": dataset.encode("ascii"),
            b"schema_version": str(SCHEMA_VERSION).encode("ascii"),
        },
    )


def _blocks(stream, block_bytes):
    while head := stream.read(block_bytes):
        if not head.endswith(b"\n"):
            tail = stream.readline(MAX_LINE_BYTES + 1)
            head += tail
            if len(tail) > MAX_LINE_BYTES and not tail.endswith(b"\n"):
                while tail and not tail.endswith(b"\n"):
                    tail = stream.readline(MAX_LINE_BYTES + 1)
                if tail.endswith(b"\n"):
                    head += b"\n"
        yield head


def _parse_block(block, dataset, schema, first_line, line_count):
    columns = SCHEMAS[dataset]
    try:
        newline_offsets = np.flatnonzero(np.frombuffer(block, dtype=np.uint8) == 10)
        if (
            block.startswith(b"\xef\xbb\xbf")
            or np.diff(newline_offsets, prepend=-1, append=len(block) - 1).max() > MAX_LINE_BYTES
        ):
            raise ValueError("oversize line")
        parsed = arrow_csv.read_csv(
            pa.BufferReader(block),
            read_options=arrow_csv.ReadOptions(
                column_names=columns, block_size=len(block), use_threads=False
            ),
            parse_options=arrow_csv.ParseOptions(quote_char=False, ignore_empty_lines=False),
            convert_options=arrow_csv.ConvertOptions(
                column_types={name: pa.string() for name in columns},
                null_values=["?"], strings_can_be_null=True,
            ),
        )
        times = parsed.column(0)
        digits = pc.match_substring_regex(times, r"^[0-9]{1,19}$")
        if parsed.num_rows != line_count or not pc.all(pc.fill_null(digits, False)).as_py():
            raise ValueError("invalid timestamp or physical line count")
        timestamps = pc.cast(times, pa.int64())
        if pc.min(timestamps).as_py() < 1:
            raise ValueError("invalid timestamp")
        source_lines = pa.array(np.arange(first_line, first_line + line_count, dtype=np.int64))
        return pa.Table.from_arrays(
            [source_lines, timestamps, *parsed.columns[1:]], schema=schema
        ), []
    except (pa.ArrowInvalid, ValueError):
        # Use the reference parser for exact rejection reasons and physical offsets.
        arrays = [[] for _ in schema]
        rejected = []
        with BytesIO(gzip.compress(block, compresslevel=1)) as archive:
            for record in iter_records(archive, dataset):
                line = first_line + record.source_line - 1
                if isinstance(record, Event):
                    for values, value in zip(arrays, (line, record.timestamp_s, *record.fields)):
                        values.append(value)
                else:
                    rejected.append({"source_line": line, "reason": record.reason})
        return pa.Table.from_arrays(arrays, schema=schema), rejected


def _peak_rss_bytes():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def export_archive(path, dataset, output, *, limit=None, expected_sha256=None,
                   block_bytes=BLOCK_BYTES, reserve_bytes=0, progress=None):
    """Publish a new directory only after an export has passed its checks."""
    if dataset not in SCHEMAS:
        raise ValueError("Unknown LANL feed")
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    if not 1 <= block_bytes <= BLOCK_BYTES:
        raise ValueError(f"block_bytes must be between 1 and {BLOCK_BYTES}")
    if reserve_bytes < 0:
        raise ValueError("reserve_bytes must be nonnegative")
    path, output = Path(path).resolve(), Path(output).absolute()
    if os.path.lexists(output):
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    started = perf_counter()
    started_utc = datetime.now(timezone.utc).isoformat()
    lines_read = valid = 0
    reasons = Counter()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as raw, TemporaryDirectory(dir=output.parent) as temporary:
        before = os.fstat(raw.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Input must be a regular gzip file")
        if raw.read(2) != b"\x1f\x8b":
            raise gzip.BadGzipFile("Missing gzip header")
        raw.seek(0)
        digest = stream_sha256(raw, before.st_size, (
            lambda consumed, total: progress("hash", consumed, total)) if progress else None)
        if expected_sha256 and digest != expected_sha256.lower():
            raise ValueError(f"SHA-256 mismatch for {path}")
        raw.seek(0)
        stage = Path(temporary) / "export"
        stage.mkdir()
        data = stage / "events.parquet"
        schema = parquet_schema(dataset, digest)
        with (
            (stage / "rejections.jsonl").open("w", encoding="utf-8") as rejects,
            gzip.GzipFile(fileobj=raw, mode="rb") as stream,
            pq.ParquetWriter(
                data, schema, compression="zstd", compression_level=3,
                use_dictionary=list(SCHEMAS[dataset][1:]),
                column_encoding={
                    "source_line": "DELTA_BINARY_PACKED", "timestamp_s": "DELTA_BINARY_PACKED"
                },
            ) as writer,
        ):
            for block in _blocks(stream, block_bytes):
                line_count = block.count(b"\n") + int(not block.endswith(b"\n"))
                if limit is not None and line_count > limit - lines_read:
                    line_count = limit - lines_read
                    block = b"\n".join(block.split(b"\n", line_count)[:line_count]) + b"\n"
                if shutil.disk_usage(stage).free < reserve_bytes:
                    raise OSError("Free disk space fell below the configured reserve")
                table, rejected = _parse_block(
                    block, dataset, schema, lines_read + 1, line_count
                )
                if table.num_rows + len(rejected) != line_count:
                    raise ValueError("Parsed and rejected rows do not account for every line")
                for rejection in rejected:
                    rejects.write(json.dumps(rejection) + "\n")
                    reasons[rejection["reason"]] += 1
                if table.num_rows:
                    writer.write_table(table, row_group_size=262_144)
                lines_read += line_count
                valid += table.num_rows
                if progress:
                    progress("records", lines_read, limit)
                if lines_read == limit:
                    break
        if (
            _signature(before) != _signature(os.fstat(raw.fileno()))
            or _signature(before) != _signature(path.stat())
        ):
            raise OSError(f"Evidence changed during export: {path}")
        footer = pq.ParquetFile(data)
        if footer.metadata.num_rows != valid or not footer.schema_arrow.equals(schema, check_metadata=True):
            raise ValueError("Parquet footer does not match ingested records")
        manifest = {
            "dataset": dataset, "archive": str(path), "archive_bytes": before.st_size,
            "archive_sha256": digest, "schema_version": SCHEMA_VERSION,
            "source_line": "one-based physical line in the decompressed evidence",
            "started_utc": started_utc, "scope": "full" if limit is None else "sample",
            "gzip_read_through_eof": limit is None, "source_line_limit": limit,
            "lines_read": lines_read, "valid_records": valid, "rejected_by_reason": dict(reasons),
            "row_groups": footer.metadata.num_row_groups, "parquet_bytes": data.stat().st_size,
            "rejection_log_bytes": (stage / "rejections.jsonl").stat().st_size,
            "block_bytes": block_bytes, "elapsed_seconds": round(perf_counter() - started, 3),
            "peak_process_rss_bytes": _peak_rss_bytes(),
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        if progress:
            progress("publish", lines_read, limit)
        if os.path.lexists(output):
            raise FileExistsError(output)
        stage.rename(output)
    return manifest


def open_export(root, dataset):
    directory = Path(root) / dataset
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    parquet = pq.ParquetFile(directory / "events.parquet")
    expected_schema = parquet_schema(dataset, manifest["archive_sha256"])
    if (
        manifest["schema_version"] != SCHEMA_VERSION
        or manifest["dataset"] != dataset
        or not parquet.schema_arrow.equals(expected_schema, check_metadata=True)
        or parquet.metadata.num_rows != manifest["valid_records"]
    ):
        raise ValueError(f"Inconsistent {dataset} export provenance")
    return manifest, parquet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=SCHEMAS)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--limit", type=int)
    scope.add_argument("--full", action="store_true")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--reserve-gib", type=int, default=0)
    parser.add_argument("--block-mib", type=int, default=16, choices=range(1, 17), metavar="1-16")
    args = parser.parse_args()
    try:
        manifest = export_archive(
            args.archive, args.dataset, args.output, limit=args.limit,
            expected_sha256=args.expected_sha256, reserve_bytes=args.reserve_gib * 1024**3,
            block_bytes=args.block_mib * 1024**2,
        )
    except (OSError, ValueError, EOFError, zlib.error) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    print(json.dumps(manifest, indent=2), flush=True)


if __name__ == "__main__":
    main()
