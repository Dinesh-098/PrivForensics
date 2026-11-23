import gzip
from io import BytesIO

import pyarrow.parquet as pq

from modules.evidence import Registry
from modules.jobs import JobStore
from modules.worker import drain


def test_register_verify_and_ingest_with_source_references(tmp_path):
    registry = Registry(tmp_path / "state")
    case = registry.case("LANL sample")
    source = tmp_path / "small.txt.gz"
    source.write_bytes(gzip.compress(b"bad\n4,U4@D,C7,P2,Start\n5,U4@D,C7,P2,End\n"))
    store = JobStore(registry)
    reference, _ = store.submit(case, "register_reference", {
        "path": str(source), "source": "Test generator", "acquisition": "Created locally",
    })
    drain(registry, tmp_path)
    item = registry.list("evidence", case)[0]
    assert store.get(case, reference).result["evidence_id"] == item["id"]
    assert item["source"] == "Test generator" and not list(registry.vault.iterdir())
    verify, _ = store.submit(case, "verify_evidence", {"evidence_id": item["id"]})
    ingest, _ = store.submit(case, "ingest_lanl", {"evidence_id": item["id"], "dataset": "proc", "limit": None})
    drain(registry, tmp_path)
    assert store.get(case, verify).result["matches"]
    result = store.get(case, ingest).result
    assert result["valid_records"] == 2 and result["rejected_by_reason"] == {"field_count": 1}
    assert result["archive_sha256"] == item["sha256"]
    rows = pq.read_table(registry.root / "processed" / ingest / "events.parquet")
    assert rows["source_line"].to_pylist() == [2, 3]
    source.write_bytes(b"changed")
    second, _ = store.submit(case, "verify_evidence", {"evidence_id": item["id"]}, parent_id=verify)
    drain(registry, tmp_path)
    assert store.get(case, second).result["matches"] is False
    assert registry.checked_audit()


def test_processing_cannot_read_other_case_evidence(tmp_path):
    registry = Registry(tmp_path / "state")
    one, two = registry.case("First"), registry.case("Second")
    evidence = registry.upload(one, "file.gz", BytesIO(gzip.compress(b"1,U4@D,C7,P2,Start\n")))
    store = JobStore(registry)
    identifier, _ = store.submit(two, "ingest_lanl", {"evidence_id": evidence, "dataset": "proc", "limit": 12})
    drain(registry, tmp_path)
    assert store.get(two, identifier).status == "failed"
    assert not (registry.root / "processed").exists()


def test_case_correlation_uses_linked_ingestions(tmp_path, prepared_project):
    registry = Registry(tmp_path / "state")
    case = registry.case("Correlation workflow")
    store = JobStore(registry)
    feeds = {}
    for kind in ("auth", "proc", "redteam"):
        item = registry.register_reference(case, prepared_project / "dataset/lanl" / f"{kind}.txt.gz")
        feeds[kind], _ = store.submit(case, "ingest_lanl", {"evidence_id": item, "dataset": kind, "limit": 1000})
    job, _ = store.submit(case, "correlate_lanl", {"inputs": feeds, "window": 3})
    drain(registry, prepared_project)
    result = store.get(case, job)
    assert result.status == "succeeded", result.error
    assert result.result["auth_key_status"] == {"unique_match": 10}
    assert pq.read_metadata(registry.root / "correlations" / job / "process_context.parquet").num_rows == 20
    assert registry.checked_audit()
