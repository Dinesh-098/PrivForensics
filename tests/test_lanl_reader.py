import gzip
import hashlib
from io import BytesIO

import pytest

from modules.lanl_reader import (
    MAX_LINE_BYTES, Event, RejectedLine, inspect_archive, iter_records,
)


@pytest.mark.parametrize(
    ("dataset", "row", "fields"),
    [
        ("auth", b"1,MACHINE$@DOM,SYSTEM@C1,C1,C2,?,Network,LogOff,Success\r\n",
         ("MACHINE$@DOM", "SYSTEM@C1", "C1", "C2", None, "Network", "LogOff", "Success")),
        ("proc", b"1,LOCAL SERVICE@C1,C1,P16,End\n",
         ("LOCAL SERVICE@C1", "C1", "P16", "End")),
        ("redteam", b"1,U123@DOM,C1,C2", ("U123@DOM", "C1", "C2")),
    ],
)
def test_dataset_layouts(dataset, row, fields):
    archive = BytesIO(gzip.compress(row))
    assert list(iter_records(archive, dataset)) == [Event(1, 1, fields)]
    assert not archive.closed


def test_rejections_preserve_physical_line_numbers():
    raw = (
        b"x" * (2 * MAX_LINE_BYTES) + b"\n"
        b"1,U1,C1\n"
        b"0,U1,C1,C2\n"
        b"9223372036854775808,U1,C1,C2\n"
        b"2,U1,C1,\xff\n"
        b"3,U1,C1,C2\n"
        b"3,U1,C1,C2\n"
    )
    assert list(iter_records(BytesIO(gzip.compress(raw)), "redteam")) == [
        RejectedLine(1, "line_too_long"),
        RejectedLine(2, "field_count"),
        RejectedLine(3, "invalid_timestamp"),
        RejectedLine(4, "invalid_timestamp"),
        RejectedLine(5, "invalid_utf8"),
        Event(6, 3, ("U1", "C1", "C2")),
        Event(7, 3, ("U1", "C1", "C2")),
    ]


def test_sample_bounds_and_fingerprint(tmp_path):
    path = tmp_path / "redteam.txt.gz"
    payload = gzip.compress(b"1,U1,C1,C2\nmalformed\n2,U1,C1,C2\n", mtime=0)
    path.write_bytes(payload)
    assert inspect_archive(path, "redteam", limit=2, include_sha256=True) == {
        "dataset": "redteam",
        "archive": str(path.resolve()),
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "scope": "sample",
        "line_limit": 2,
        "lines_read": 2,
        "valid_records": 1,
        "rejected_lines": {"field_count": 1},
    }
    full = inspect_archive(path, "redteam", limit=None)
    assert (full["scope"], full["lines_read"], full["valid_records"]) == ("full", 3, 2)
    assert path.read_bytes() == payload


def test_truncated_archive_detected_at_eof(tmp_path):
    path = tmp_path / "redteam.txt.gz"
    path.write_bytes(gzip.compress(b"1,U1,C1,C2\n")[:-4])
    assert inspect_archive(path, "redteam", limit=1)["scope"] == "sample"
    with pytest.raises(EOFError):
        inspect_archive(path, "redteam", limit=None)


def test_rejects_nongzip_source():
    with pytest.raises(gzip.BadGzipFile):
        list(iter_records(BytesIO(b""), "redteam"))


def test_rejects_nonpositive_limit(tmp_path):
    with pytest.raises(ValueError, match="positive"):
        inspect_archive(tmp_path / "redteam.txt.gz", "redteam", limit=0)
