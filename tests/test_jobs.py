from concurrent.futures import ThreadPoolExecutor

import pytest

from modules.evidence import Registry
from modules.jobs import JobStore
from modules.worker import drain


def test_queue_deduplicates_and_scopes_results(tmp_path):
    registry = Registry(tmp_path)
    case, other = registry.case("First"), registry.case("Other")
    store = JobStore(registry)
    with ThreadPoolExecutor(max_workers=4) as workers:
        requests = list(workers.map(lambda _: store.submit(case, "sample", {"seed": 42}), range(6)))
    job_id = requests[0][0]
    assert {job for job, _ in requests} == {job_id}
    assert sum(created for _, created in requests) == 1
    assert store.list(other) == []
    with pytest.raises(ValueError, match="does not belong"):
        store.cancel(other, job_id)

    def sample(_, __, job, progress):
        progress(30, "Sampling")
        return {"seed": job.config["seed"]}

    drain(registry, tmp_path, sample)
    assert store.get(case, job_id).result == {"seed": 42}
    assert store.get(case, job_id).progress == 100
    rerun, created = store.submit(case, "sample", {"seed": 42}, parent_id=job_id)
    assert created and rerun != job_id
    assert store.get(case, rerun).parent_id == job_id
    assert registry.checked_audit()


def test_cancel_failure_and_interruption(tmp_path):
    registry = Registry(tmp_path)
    case = registry.case("Example")
    store = JobStore(registry)
    interrupted, _ = store.submit(case, "sample", {"n": 0})
    assert store.claim().id == interrupted
    queued, _ = store.submit(case, "sample", {"n": 1})
    store.cancel(case, queued)
    running, _ = store.submit(case, "sample", {"n": 2})
    failed, _ = store.submit(case, "sample", {"n": 3})

    def sample(_, __, job, progress):
        if job.id == running:
            store.cancel(case, job.id)
            progress(40, "Stopping")
            pytest.fail("A cancellation checkpoint should have stopped the job")
        raise ValueError("Invalid sample")

    drain(registry, tmp_path, sample)
    assert store.get(case, interrupted).status == "interrupted"
    assert store.get(case, queued).status == store.get(case, running).status == "cancelled"
    assert store.get(case, failed).error == "Invalid sample"
    assert registry.checked_audit()
