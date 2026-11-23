"""Evidence jobs and derived LANL export publication."""
import json
from pathlib import Path

from .lanl_reader import SCHEMAS


PROCESSING_LABELS = {
    "register_reference": "Register local evidence",
    "register_lanl": "Register LANL archives",
    "verify_evidence": "Verify evidence",
    "ingest_lanl": "Ingest LANL gzip",
}


def _hash_progress(checkpoint, begin=0, span=98):
    def scanned(done, total):
        checkpoint(begin + int(span * done / max(total, 1)),
                   f"SHA-256 · {done / 1024**2:,.0f} of {total / 1024**2:,.0f} MiB")
    return scanned


def _register_lanl(registry, project, job, checkpoint):
    exports = Path(project) / "dataset/processed/lanl-v1"
    feeds = job.config["feeds"]
    if not feeds or set(feeds) - set(SCHEMAS):
        raise ValueError("Select valid LANL feeds")
    registered = []
    for index, kind in enumerate(feeds):
        manifest = json.loads((exports / kind / "manifest.json").read_text(encoding="utf-8"))
        digest = manifest["archive_sha256"]
        if digest != feeds[kind]:
            raise ValueError("The LANL manifest changed after this work was queued")
        file = Path(project) / "dataset/lanl" / f"{kind}.txt.gz"
        evidence_id = registry.register_reference(
            job.case_id, file, expected=digest, source="LANL Comprehensive Multi-Source Cyber-Security Events",
            acquisition="Local copy compared against the existing processed export fingerprint",
            progress=_hash_progress(checkpoint, int(98 * index / len(feeds)), int(98 / len(feeds))),
        )
        registry.record(job.case_id, "processed_export_recorded", {
            "evidence_id": evidence_id, "dataset": kind, "source_rows": manifest["lines_read"],
            "valid_rows": manifest["valid_records"], "gzip_eof": manifest["gzip_read_through_eof"],
        })
        registered.append({"dataset": kind, "evidence_id": evidence_id, "sha256": digest})
    return {"registered": registered}


def _ingest(registry, job, checkpoint):
    from .lanl_parquet import export_archive

    item = registry.evidence(job.case_id, job.config["evidence_id"])
    kind, limit = job.config["dataset"], job.config["limit"]
    if kind not in SCHEMAS or (limit is not None and not 1 <= limit <= 1_000_000):
        raise ValueError("Invalid LANL feed or sample size")
    destination = registry.root / "processed" / job.id

    def progress(phase, done, total):
        if phase == "hash":
            _hash_progress(checkpoint, 1, 26)(done, total)
        elif phase == "publish":
            checkpoint(98, "Publishing validated Parquet")
        elif total is not None:
            checkpoint(28 + int(68 * done / total), f"Validated {done:,} of {total:,} source lines")
        else:
            checkpoint(40, f"Validated {done:,} source lines")

    try:
        manifest = export_archive(item["path"], kind, destination, limit=limit,
                                  expected_sha256=item["sha256"], reserve_bytes=1024**3,
                                  progress=progress)
    except EOFError as exc:
        raise ValueError("The input gzip stream ended before its checksum could be verified") from exc
    registry.record(job.case_id, "evidence_processed", {
        "evidence_id": item["id"], "dataset": kind, "scope": manifest["scope"],
        "source_rows": manifest["lines_read"], "job_id": job.id,
    })
    return {key: value for key, value in manifest.items() if key != "archive"}


def run_processing(registry, project, job, checkpoint):
    config = job.config
    if job.kind == "register_reference":
        if not Path(config["path"]).is_absolute():
            raise ValueError("Use the full absolute path to the authorized evidence file")
        evidence_id = registry.register_reference(
            job.case_id, config["path"], source=config["source"], acquisition=config["acquisition"],
            progress=_hash_progress(checkpoint),
        )
        item = registry.evidence(job.case_id, evidence_id)
        return {"evidence_id": evidence_id, "sha256": item["sha256"], "bytes": item["size"]}
    if job.kind == "register_lanl":
        return _register_lanl(registry, project, job, checkpoint)
    if job.kind == "verify_evidence":
        evidence_id = config["evidence_id"]
        registry.evidence(job.case_id, evidence_id)
        return {"evidence_id": evidence_id, "matches": registry.verify(evidence_id, progress=_hash_progress(checkpoint))}
    if job.kind == "ingest_lanl":
        return _ingest(registry, job, checkpoint)
    raise ValueError("Unknown background operation")


def run_forensic_analysis(registry, project, job, checkpoint):
    from .analysis_models import lanl_experiment, process_experiment
    from .lanl_parquet import open_export

    config = job.config
    kind = config["dataset"]
    item = registry.evidence(job.case_id, config["evidence_id"])
    if kind not in ("auth", "proc"):
        raise ValueError("Choose authentication or process for forensic analysis")
    root = Path(project) / "dataset/processed/lanl-v1"
    manifest, parquet = open_export(root, kind)
    parquet.close()
    if manifest["archive_sha256"] != item["sha256"]:
        raise ValueError("The registered archive differs from the prepared data")
    checkpoint(8, "Sampling event records")
    if kind == "auth":
        model_path = registry.root / "models" / f"{job.id}.json"
        result = lanl_experiment(root, seed=config["seed"], model_path=model_path, progress=checkpoint)
    else:
        result = process_experiment(root, seed=config["seed"], progress=checkpoint)
    checkpoint(98, "Saving scored findings")
    registry.record(job.case_id, "evidence_analyzed",
                    {"evidence_id": item["id"], "job_id": job.id, "dataset": kind})
    return result


def run_case_correlation(registry, job, checkpoint):
    from tempfile import TemporaryDirectory
    from .jobs import JobStore
    from .lanl_correlation import correlate

    inputs = job.config["inputs"]
    if set(inputs) != set(SCHEMAS):
        raise ValueError("Correlation requires processed authentication, process and red-team feeds")
    state = registry.root.resolve()
    target = state / "correlations" / job.id
    target.parent.mkdir(parents=True, exist_ok=True)
    store = JobStore(registry)
    with TemporaryDirectory(dir=target.parent) as temporary:
        working = Path(temporary)
        for name, identifier in inputs.items():
            ingested = store.get(job.case_id, identifier)
            if ingested.kind != "ingest_lanl" or not ingested.result or ingested.result["dataset"] != name:
                raise ValueError("Select a completed case ingestion for each feed")
            (working / name).symlink_to(state / "processed" / ingested.id, target_is_directory=True)
        checkpoint(8, "Opening completed case ingestions")
        result = correlate(working, target, window=job.config["window"], checkpoint=checkpoint)
    return result
