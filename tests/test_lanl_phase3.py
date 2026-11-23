import gzip
import hashlib
import json
from itertools import islice

import pyarrow.parquet as pq
import pytest

from modules.lanl_correlation import correlate
from modules.lanl_parquet import export_archive
from modules.lanl_reader import Event, MAX_LINE_BYTES, RejectedLine, iter_records


def archive(tmp_path, kind, rows):
    path = tmp_path / f"{kind}.txt.gz"
    path.write_bytes(gzip.compress(rows, mtime=0))
    return path


def test_export_matches_reference_across_block_boundaries(tmp_path):
    source = archive(
        tmp_path, "auth",
        b"1,MACHINE$@DOM,SYSTEM@C1,C1,C2,?,Network,LogOff,Success\r\n"
        b"2,BAD\n"
        b"2,U@DOM,U@DOM,C1,C2,NTLM,Network,LogOn,Fail\n"
        b"0,U@DOM,U@DOM,C1,C2,NTLM,Network,LogOn,Fail\n"
        b"5,\xff,U@DOM,C1,C2,NTLM,Network,LogOn,Fail\n"
        b"5,A,B,C1,C2,NTLM,Network,LogOn," + b"x" * (3 * MAX_LINE_BYTES) + b"\n"
        b"7,U@DOM,U@DOM,C1,C2,NTLM,Network,LogOn,Success",
    )
    with source.open("rb") as evidence:
        records = list(iter_records(evidence, "auth"))
    baseline = hashlib.sha256(source.read_bytes()).hexdigest()
    expected = [(row.source_line, row.timestamp_s, *row.fields)
                for row in records if isinstance(row, Event)]
    for size in (23, 128, 1_000_000):
        output = tmp_path / str(size)
        manifest = export_archive(source, "auth", output, expected_sha256=baseline, block_bytes=size)
        assert manifest["archive_sha256"] == baseline
        assert manifest["gzip_read_through_eof"]
        assert manifest["valid_records"] == len(expected)
        table = pq.read_table(output / "events.parquet")
        assert list(zip(*table.to_pydict().values())) == expected
        rejects = [json.loads(row) for row in (output / "rejections.jsonl").read_text().splitlines()]
        assert rejects == [{"source_line": row.source_line, "reason": row.reason}
                           for row in records if isinstance(row, RejectedLine)]


def test_batch_matches_reference_and_respects_physical_limit(tmp_path):
    source = archive(
        tmp_path, "proc",
        b"1,A@DOM,C1,P1,Start\n2,A@DOM,C1,?,End\n3,A@DOM,C1,,Start\n"
        b"4,A@DOM,C1,P2,End\n5,A@DOM,C2,P3,Start\n",
    )
    output = tmp_path / "sample"
    manifest = export_archive(source, "proc", output, limit=3, block_bytes=104)
    with source.open("rb") as evidence:
        expected = [(row.source_line, row.timestamp_s, *row.fields)
                    for row in islice(iter_records(evidence, "proc"), 3)]
    assert list(zip(*pq.read_table(output / "events.parquet").to_pydict().values())) == expected
    assert manifest["scope"] == "sample"
    assert not manifest["gzip_read_through_eof"]


def test_invalid_source_never_publishes_output(tmp_path):
    source = archive(tmp_path, "proc", b"1,A@DOM,C1,P1,Start\n")
    output = tmp_path / "full"
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        export_archive(source, "proc", output, expected_sha256="0" * 64)
    assert not output.exists()
    source.write_bytes(source.read_bytes()[:-4])
    with pytest.raises(EOFError):
        export_archive(source, "proc", output)
    assert not output.exists()


def test_output_directory_cannot_be_overwritten(tmp_path):
    source = archive(tmp_path, "redteam", b"1,U@DOM,C1,C2\n")
    output = tmp_path / "full"
    export_archive(source, "redteam", output)
    with pytest.raises(FileExistsError):
        export_archive(source, "redteam", output)
    assert pq.read_metadata(output / "events.parquet").num_rows == 1


def test_correlation_duplicate_ambiguous_and_context_semantics(tmp_path):
    exports = tmp_path / "exports"
    forms = {
        "redteam": b"100,U@DOM,C1,C2\n100,U@DOM,C1,C2\n110,U@DOM,C1,C2\n120,V@DOM,C2,C2\n",
        "auth": (
            b"100,U@DOM,Y@DOM,C1,C2,NTLM,Network,LogOn,Success\n"
            b"110,U@DOM,Y@DOM,C1,C2,NTLM,Network,LogOn,Success\n"
            b"110,U@DOM,Y@DOM,C1,C2,NTLM,Network,LogOff,Success\n"
            b"120,Y@DOM,V@DOM,C2,C2,NTLM,Network,LogOn,Success\n"
            b"120,V@DOM,Y@DOM,C3,C2,NTLM,Network,LogOn,Success\n"
        ),
        "proc": (
            b"95,U@DOM,C1,P1,Start\n105,U@DOM,C2,P2,Start\n"
            b"106,U@DOM,C9,P3,Start\n120,V@DOM,C2,P1,End\n"
        ),
    }
    for kind, rows in forms.items():
        export_archive(archive(tmp_path, kind, rows), kind, exports / kind)
    output = tmp_path / "links"
    result = correlate(exports, output, window=5)
    assert result["duplicate_redteam_rows"] == 1
    assert result["auth_key_status"] == {"ambiguous_match": 1, "no_match": 1, "unique_match": 1}
    assert result["source_role_auth_candidates"] == 3
    assert result["destination_only_auth_candidates"] == 1
    rows = pq.read_table(output / "auth_matches.parquet").to_pylist()
    assert rows[0]["redteam_source_lines"] == [1, 2]
    assert rows[0]["auth_candidate_lines"] == [1]
    assert rows[1]["auth_candidate_lines"] == [2, 3]
    process = pq.read_table(output / "process_context.parquet")
    assert list(zip(*process.to_pydict().values())) == [
        (1, 1, "source", -5), (1, 2, "destination", 5), (3, 2, "destination", -5),
        (4, 4, "both", 0),
    ]


def test_validation_checks_complete_line_partition(tmp_path):
    from modules.lanl_validation import validate_export

    source = archive(tmp_path, "proc", b"bad\n1,U@DOM,C1,P1,Start\nbad\n1,U@DOM,C1,P1,End\nbad")
    output = tmp_path / "proc"
    export_archive(source, "proc", output, block_bytes=19)
    results = validate_export(tmp_path, "proc")
    assert results["source_line_partition_verified"]
    assert results["lines_verified"] == 5
    assert results["parquet_rows_verified"] == 2
    (output / "rejections.jsonl").write_text(
        '{"source_line": 1, "reason": "field_count"}\n'
        '{"source_line": 2, "reason": "field_count"}\n'
        '{"source_line": 5, "reason": "field_count"}\n'
    )
    with pytest.raises(ValueError, match="occurs in Parquet"):
        validate_export(tmp_path, "proc")


def test_context_uses_exact_endpoint_and_bounded_nearest_rows(tmp_path):
    from modules.lanl_correlation import authentication_context

    source = archive(tmp_path, "proc", b"91,U@D,C1,P2,Start\n99,U@D,C3,P2,Start\n"
                     b"103,V@D,C2,P2,End\n105,U@D,C1,P3,Start\n111,U@D,C1,P4,End\n")
    output = tmp_path / "process"
    export_archive(source, "proc", output)
    auth = {"timestamp_s": 100, "source_account": "U@D", "source_computer": "C1",
            "destination_account": "V@D", "destination_computer": "C2"}
    result = authentication_context(output / "events.parquet", auth, window=10, limit=2)
    assert result["total_matches"] == 3
    assert [row["source_line"] for row in result["rows"]] == [3, 4]
    assert result["rows"][0]["endpoint_role"] == "destination"
