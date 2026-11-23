"""Run queued PrivForensics work in a single local background process."""
import argparse
from pathlib import Path
import traceback

from .evidence import Registry
from .jobs import JobCancelled, JobStore, worker_lock


def execute(registry, project, job, checkpoint):
    if job.kind == "evaluation":
        from .lab import run_evaluation
        return run_evaluation(project, registry, job, checkpoint)
    if job.kind == "forensic_analysis":
        from .processing import run_forensic_analysis
        return run_forensic_analysis(registry, project, job, checkpoint)
    if job.kind == "correlate_lanl":
        from .processing import run_case_correlation
        return run_case_correlation(registry, job, checkpoint)
    from .processing import run_processing
    return run_processing(registry, project, job, checkpoint)


def drain(registry, project, handler=execute):
    store = JobStore(registry)
    with worker_lock(registry.root):
        store.recover_running()
        while job := store.claim():
            try:
                def checkpoint(percent, phase):
                    store.progress(job, percent, phase)

                checkpoint(0, "Opening input")
                result = handler(registry, project, job, checkpoint)
                store.finish(job, "succeeded", result=result)
            except JobCancelled:
                store.finish(job, "cancelled")
            except (ValueError, OSError) as exc:
                store.finish(job, "failed", error=str(exc)[:400] or type(exc).__name__)
            except Exception as exc:
                traceback.print_exc()
                store.finish(job, "failed", error=f"{type(exc).__name__}. See the local worker log.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    args = parser.parse_args()
    drain(Registry(args.state), args.project)


if __name__ == "__main__":
    main()
