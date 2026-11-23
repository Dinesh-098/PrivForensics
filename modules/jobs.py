"""Durable, case-scoped background processing for the local console."""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from .evidence import Registry, utc


ACTIVE = ("queued", "running")


class JobCancelled(Exception):
    """Raised at a checkpoint where a job can safely stop."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True, slots=True)
class Job:
    id: str
    case_id: str
    kind: str
    status: str
    config: dict
    parent_id: str | None
    created: str
    started: str | None
    finished: str | None
    progress: int
    phase: str
    cancel_requested: bool
    result: dict | None
    error: str | None

    @classmethod
    def from_row(cls, row):
        fields = dict(row)
        fields.pop("request_key")
        for field in ("config", "result"):
            if fields[field] is not None:
                fields[field] = json.loads(fields[field])
        fields["cancel_requested"] = bool(fields["cancel_requested"])
        return cls(**fields)


class JobStore:
    def __init__(self, registry: Registry):
        self.registry = registry
        with registry.session() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs(
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(id),
                    kind TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    config TEXT NOT NULL,
                    parent_id TEXT REFERENCES jobs(id),
                    status TEXT NOT NULL CHECK(status IN
                        ('queued','running','succeeded','failed','cancelled','interrupted')),
                    created TEXT NOT NULL,
                    started TEXT,
                    finished TEXT,
                    progress INTEGER NOT NULL DEFAULT 0 CHECK(progress BETWEEN 0 AND 100),
                    phase TEXT NOT NULL DEFAULT 'Awaiting worker',
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    result TEXT,
                    error TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS active_job_request
                    ON jobs(case_id, kind, request_key) WHERE status IN ('queued','running');
                CREATE INDEX IF NOT EXISTS jobs_case_created ON jobs(case_id, created DESC);
                CREATE INDEX IF NOT EXISTS jobs_status_created ON jobs(status, created);
            """)

    def submit(self, case_id, kind, config, *, parent_id=None):
        encoded = _json(config)
        fingerprint = hashlib.sha256(encoded.encode()).hexdigest()
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            if not case_id or not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("Select an investigation before queuing work")
            if parent_id is not None:
                parent = db.execute("SELECT * FROM jobs WHERE id=? AND case_id=?", (parent_id, case_id)).fetchone()
                if parent is None or parent["kind"] != kind or parent["config"] != encoded:
                    raise ValueError("Reruns must use the saved investigation and configuration")
                if parent["status"] in ACTIVE:
                    raise ValueError("Wait for the original run to finish")
            previous = db.execute("""
                SELECT id FROM jobs
                WHERE case_id=? AND kind=? AND request_key=? AND status IN ('queued','running')
            """, (case_id, kind, fingerprint)).fetchone()
            if previous:
                return previous["id"], False
            job_id = uuid4().hex
            db.execute("""
                INSERT INTO jobs(id,case_id,kind,request_key,config,parent_id,status,created)
                VALUES(?,?,?,?,?,?,'queued',?)
            """, (job_id, case_id, kind, fingerprint, encoded, parent_id, utc()))
            self.registry._audit(db, "job_queued", case_id, {
                "job_id": job_id, "kind": kind, "parent_id": parent_id,
            })
        return job_id, True

    def get(self, case_id, job_id):
        with self.registry.session() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=? AND case_id=?", (job_id, case_id)).fetchone()
        if row is None:
            raise ValueError("Job does not belong to this investigation")
        return Job.from_row(row)

    def list(self, case_id, kind=None, *, limit=100, offset=0):
        with self.registry.session() as db:
            rows = db.execute("""
                SELECT * FROM jobs WHERE case_id=? AND (? IS NULL OR kind=?)
                ORDER BY created DESC LIMIT ? OFFSET ?
            """, (case_id, kind, kind, limit, offset)).fetchall()
        return [Job.from_row(row) for row in rows]

    def by_status(self, case_id, status, *, limit=100):
        with self.registry.session() as db:
            rows = db.execute("""
                SELECT * FROM jobs WHERE case_id=? AND status=? ORDER BY created DESC LIMIT ?
            """, (case_id, status, limit)).fetchall()
        return [Job.from_row(row) for row in rows]

    def claim(self):
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created, id LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("""
                UPDATE jobs SET status='running', started=?, phase='Starting' WHERE id=?
            """, (utc(), row["id"]))
            self.registry._audit(db, "job_started", row["case_id"], {"job_id": row["id"], "kind": row["kind"]})
            return Job.from_row(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())

    def progress(self, job, percent, phase):
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status, cancel_requested FROM jobs WHERE id=?", (job.id,)).fetchone()
            if row["status"] != "running" or row["cancel_requested"]:
                raise JobCancelled()
            db.execute("UPDATE jobs SET progress=MAX(progress,?), phase=? WHERE id=?",
                       (max(0, min(99, percent)), phase, job.id))

    def cancel(self, case_id, job_id):
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id=? AND case_id=?", (job_id, case_id)).fetchone()
            if row is None:
                raise ValueError("Job does not belong to this investigation")
            job = Job.from_row(row)
            if job.status == "queued":
                self._finish(db, job, "cancelled", None, None)
            elif job.status == "running" and not job.cancel_requested:
                db.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job.id,))
                self.registry._audit(db, "job_cancel_requested", case_id, {"job_id": job.id, "kind": job.kind})

    def finish(self, job, status, *, result=None, error=None):
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            self._finish(db, job, status, result, error)

    def _finish(self, db, job, status, result, error):
        db.execute("""
            UPDATE jobs SET status=?, progress=CASE WHEN ?='succeeded' THEN 100 ELSE progress END,
            phase=?, finished=?, result=?, error=? WHERE id=? AND status=?
        """, (status, status, status.capitalize(), utc(), _json(result) if result is not None else None,
              error, job.id, job.status))
        if db.execute("SELECT changes()").fetchone()[0] == 1:
            self.registry._audit(db, f"job_{status}", job.case_id, {"job_id": job.id, "kind": job.kind})

    def recover_running(self):
        """Call only while holding the exclusive worker lock."""
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM jobs WHERE status='running'").fetchall()
            for row in rows:
                job = Job.from_row(row)
                self._finish(db, job, "interrupted", None, "The worker exited. Rerun the saved configuration.")

    def private_training_ledger(self, dataset_sha256):
        """Conservative accounting across completed lab jobs for one dataset."""
        with self.registry.session() as db:
            rows = db.execute("""
                SELECT result FROM jobs WHERE kind='evaluation' AND status='succeeded'
                AND json_extract(config, '$.dataset_sha256')=?
            """, (dataset_sha256,)).fetchall()
        privacy = [variant["privacy"] for row in rows for variant in json.loads(row["result"])["variants"]
                   if variant["privacy"].get("epsilon_spent") is not None]
        return {"fits": len(privacy), "epsilon_sum": sum(row["epsilon_spent"] for row in privacy),
                "delta_sum": sum(row["delta"] for row in privacy)}


@contextmanager
def worker_lock(root):
    with (Path(root) / "worker.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def launch_worker(registry, project_root):
    """Start a separate process so a browser rerun or closed tab cannot stop a job."""
    code_root = Path(__file__).resolve().parents[1]
    command = [sys.executable, "-B", "-m", "modules.worker", "--state",
               str(registry.root.resolve()), "--project", str(Path(project_root).resolve())]
    log_path = registry.root / "worker.log"
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "ab") as log:
        return subprocess.Popen(command, cwd=code_root, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
