"""Stream and inspect the three LANL cyber1 evidence archives."""

import argparse
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
import gzip
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
from typing import BinaryIO, Iterator
import zlib


SCHEMAS = {
    "auth": (
        "timestamp_s", "source_account", "destination_account", "source_computer",
        "destination_computer", "authentication_type", "logon_type",
        "orientation", "result",
    ),
    "proc": ("timestamp_s", "account", "computer", "process", "action"),
    "redteam": (
        "timestamp_s", "account", "source_computer", "destination_computer",
    ),
}
MAX_LINE_BYTES = 64 * 1024
MAX_TIMESTAMP = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class Event:
    source_line: int
    timestamp_s: int
    fields: tuple[str | None, ...]


@dataclass(frozen=True, slots=True)
class RejectedLine:
    source_line: int
    reason: str


def iter_records(archive: BinaryIO, dataset: str) -> Iterator[Event | RejectedLine]:
    """Yield one result per physical line from a seekable archive at byte 0.

    Event.fields follows SCHEMAS[dataset][1:]. Keep source_line together with
    the archive SHA-256 to identify a record in the original evidence.
    """
    field_count = len(SCHEMAS[dataset])
    if archive.read(2) != b"\x1f\x8b":
        raise gzip.BadGzipFile("Missing gzip header")
    archive.seek(0)

    read_size = MAX_LINE_BYTES + 1
    with gzip.GzipFile(fileobj=archive, mode="rb") as stream:
        for source_line, raw in enumerate(iter(lambda: stream.readline(read_size), b""), 1):
            if len(raw) > MAX_LINE_BYTES:
                while raw and not raw.endswith(b"\n"):
                    raw = stream.readline(read_size)
                yield RejectedLine(source_line, "line_too_long")
                continue

            try:
                columns = raw.decode("utf-8").rstrip("\r\n").split(",")
            except UnicodeDecodeError:
                yield RejectedLine(source_line, "invalid_utf8")
                continue
            if len(columns) != field_count:
                yield RejectedLine(source_line, "field_count")
                continue
            time = columns[0]
            if not (1 <= len(time) <= 19 and time.isascii() and time.isdecimal()):
                yield RejectedLine(source_line, "invalid_timestamp")
                continue
            timestamp_s = int(time)
            if not 1 <= timestamp_s <= MAX_TIMESTAMP:
                yield RejectedLine(source_line, "invalid_timestamp")
                continue
            fields = tuple(None if value == "?" else value for value in columns[1:])
            yield Event(source_line, timestamp_s, fields)


def _signature(stat: os.stat_result) -> tuple[int, ...]:
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def inspect_archive(
    path: Path, dataset: str, *, limit: int | None = 10, include_sha256: bool = False
) -> dict:
    """Count parsed and rejected lines, optionally fingerprinting compressed bytes."""
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    path = path.resolve()
    valid = 0
    rejected: Counter[str] = Counter()
    with path.open("rb") as archive:
        before = os.fstat(archive.fileno())
        with closing(iter_records(archive, dataset)) as records:
            for record in islice(records, limit):
                if isinstance(record, RejectedLine):
                    rejected[record.reason] += 1
                else:
                    valid += 1
        sha256 = None
        if include_sha256:
            archive.seek(0)
            sha256 = hashlib.file_digest(archive, "sha256").hexdigest()
        if (
            _signature(before) != _signature(os.fstat(archive.fileno()))
            or _signature(before) != _signature(path.stat())
        ):
            raise OSError(f"Evidence changed during inspection: {path}")

    return {
        "dataset": dataset,
        "archive": str(path),
        "size_bytes": before.st_size,
        "sha256": sha256,
        "scope": "full" if limit is None else "sample",
        "line_limit": limit,
        "lines_read": valid + sum(rejected.values()),
        "valid_records": valid,
        "rejected_lines": dict(rejected),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=SCHEMAS)
    parser.add_argument("archive", type=Path)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--limit", type=int, default=10, help="source lines to inspect")
    scope.add_argument("--all", action="store_true", help="parse through gzip EOF")
    parser.add_argument(
        "--sha256", action="store_true", help="read and fingerprint all compressed bytes"
    )
    args = parser.parse_args()
    try:
        report = inspect_archive(
            args.archive, args.dataset,
            limit=None if args.all else args.limit,
            include_sha256=args.sha256,
        )
    except (OSError, EOFError, ValueError, zlib.error) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
