"""Local investigation registry, evidence vault and audit history."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from tempfile import NamedTemporaryFile
from uuid import uuid4


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stream_sha256(stream, size, progress=None):
    if progress is None:
        return hashlib.file_digest(stream, "sha256").hexdigest()
    digest = hashlib.sha256()
    position = 0
    next_update = 0
    while data := stream.read(4 * 1024**2):
        digest.update(data)
        position += len(data)
        if position >= next_update:
            progress(position, size)
            next_update = position + 64 * 1024**2
    progress(position, size)
    return digest.hexdigest()


def file_fingerprint(path, progress=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Evidence must be a regular file")
        fingerprint = stream_sha256(stream, before.st_size, progress)
        if (Registry._stamp(before) != Registry._stamp(os.fstat(stream.fileno()))
                or Registry._stamp(before) != Registry._stamp(path.lstat())):
            raise ValueError("Evidence changed during hashing")
        return fingerprint, before.st_size


class Registry:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.vault = self.root / "vault"
        self.vault.mkdir(mode=0o700, exist_ok=True)
        with self.session() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS cases(
                id TEXT PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS case_details(
                case_id TEXT PRIMARY KEY REFERENCES cases(id), description TEXT NOT NULL,
                owner TEXT NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence(
                id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases(id) NOT NULL,
                name TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL,
                sha256 TEXT NOT NULL, storage TEXT NOT NULL, created TEXT NOT NULL,
                UNIQUE(case_id, sha256));
            CREATE TABLE IF NOT EXISTS evidence_context(
                evidence_id TEXT PRIMARY KEY REFERENCES evidence(id),
                source TEXT NOT NULL, acquisition TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS evidence_by_case ON evidence(case_id, created);
            CREATE TABLE IF NOT EXISTS audit(
                seq INTEGER PRIMARY KEY, stamp TEXT NOT NULL, case_id TEXT,
                action TEXT NOT NULL, details TEXT NOT NULL,
                previous TEXT NOT NULL, digest TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS audit_by_case ON audit(case_id,seq);
            """)

    @contextmanager
    def session(self):
        db = sqlite3.connect(self.root / "registry.sqlite3", timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _audit(db, action, case_id, details):
        previous = db.execute("SELECT digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = previous[0] if previous else "0" * 64
        stamp = utc()
        payload = json.dumps(details, sort_keys=True, separators=(",", ":"))
        digest = Registry._entry_hash(stamp, case_id, action, payload, prev)
        db.execute(
            "INSERT INTO audit(stamp,case_id,action,details,previous,digest) VALUES (?,?,?,?,?,?)",
            (stamp, case_id, action, payload, prev, digest),
        )

    @staticmethod
    def _entry_hash(stamp, case_id, action, payload, prev):
        return hashlib.sha256(json.dumps([stamp, case_id, action, payload, prev]).encode()).hexdigest()

    def case(self, name, description="", owner="Local investigator"):
        name = name.strip()
        if not 1 <= len(name) <= 120:
            raise ValueError("Investigation name must be 1–120 characters")
        case_id = uuid4().hex
        with self.session() as db:
            db.execute("INSERT INTO cases VALUES (?,?,?)", (case_id, name, utc()))
            db.execute("INSERT INTO case_details VALUES (?,?,?,?)",
                       (case_id, description.strip(), owner.strip() or "Local investigator", "Open"))
            self._audit(db, "case_created", case_id, {})
        return case_id

    def _register(self, case_id, name, path, size, digest, storage, source="", acquisition=""):
        if len(source) > 250 or len(acquisition) > 2000:
            raise ValueError("Evidence source or acquisition details exceed the supported length")
        with self.session() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT id FROM evidence WHERE case_id=? AND sha256=?", (case_id, digest)
            ).fetchone()
            if previous:
                return previous[0]
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("Unknown investigation")
            evidence_id = uuid4().hex
            db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                       (evidence_id, case_id, name, str(path), size, digest, storage, utc()))
            db.execute("INSERT INTO evidence_context VALUES (?,?,?)", (evidence_id, source.strip(), acquisition.strip()))
            self._audit(db, "hash_calculated", case_id, {
                "evidence_id": evidence_id, "sha256": digest, "algorithm": "SHA-256",
            })
            self._audit(db, "evidence_registered", case_id, {
                "evidence_id": evidence_id, "sha256": digest, "storage": storage,
            })
            return evidence_id

    def register_reference(self, case_id, path, *, expected=None, source="", acquisition="", progress=None):
        path = Path(path).resolve(strict=True)
        digest, size = file_fingerprint(path, progress)
        if expected and digest != expected:
            raise ValueError("Archive differs from the verified fingerprint")
        return self._register(case_id, path.name, path, size, digest, "reference", source, acquisition)

    @staticmethod
    def _stamp(info):
        return info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def upload(self, case_id, name, stream, *, source="", acquisition=""):
        with self.session() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("Unknown investigation")
        name = Path(name.replace(chr(92), "/")).name[:120] or "upload"
        sha = hashlib.sha256()
        size = 0
        with NamedTemporaryFile(dir=self.vault, delete=False) as temporary:
            pending = Path(temporary.name)
            try:
                while block := stream.read(1024**2):
                    size += len(block)
                    if size > 128 * 1024**2:
                        raise ValueError("Use local reference registration for evidence over 128 MiB")
                    temporary.write(block)
                    sha.update(block)
                temporary.flush()
                os.fsync(temporary.fileno())
                digest = sha.hexdigest()
                destination = self.vault / digest
                pending.chmod(0o400)
                try:
                    os.link(pending, destination)
                except FileExistsError:
                    if digest_file(destination) != digest:
                        raise ValueError("Existing vault object failed verification")
            finally:
                pending.unlink(missing_ok=True)
        return self._register(case_id, name, destination, size, digest, "vault", source, acquisition)

    def evidence(self, case_id, evidence_id):
        with self.session() as db:
            row = db.execute("SELECT * FROM evidence WHERE id=? AND case_id=?",
                             (evidence_id, case_id)).fetchone()
        if row is None:
            raise ValueError("Evidence does not belong to this investigation")
        return dict(row)

    def verify(self, evidence_id, *, progress=None):
        with self.session() as db:
            item = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if item is None:
            raise ValueError("Unknown evidence")
        try:
            fingerprint, _ = file_fingerprint(item["path"], progress)
            valid = fingerprint == item["sha256"]
        except (OSError, ValueError):
            valid = False
        self.record(item["case_id"], "integrity_checked", {"id": evidence_id, "valid": valid})
        return valid

    def record(self, case_id, action, details):
        with self.session() as db:
            db.execute("BEGIN IMMEDIATE")
            self._audit(db, action, case_id, details)

    def list(self, table, case_id=None):
        if table not in {"cases", "evidence", "audit"}:
            raise ValueError("Unknown table")
        if table == "cases":
            with self.session() as db:
                return [dict(row) for row in db.execute("""
                    SELECT c.*, COALESCE(d.description, '') AS description,
                           COALESCE(d.owner, 'Local investigator') AS owner,
                           COALESCE(d.status, 'Open') AS status,
                           (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) AS evidence_count
                    FROM cases c LEFT JOIN case_details d ON d.case_id=c.id ORDER BY c.created
                """)]
        sql = ("SELECT e.*, COALESCE(c.source, '') AS source, "
               "COALESCE(c.acquisition, '') AS acquisition FROM evidence e "
               "LEFT JOIN evidence_context c ON e.id=c.evidence_id" if table == "evidence"
               else "SELECT * FROM audit")
        args = ()
        if case_id is not None and table != "cases":
            sql += " WHERE case_id=?"
            args = (case_id,)
        sql += " ORDER BY " + ("seq" if table == "audit" else "created")
        with self.session() as db:
            return [dict(row) for row in db.execute(sql, args)]

    def update_case_status(self, case_id, status):
        self.update_case(case_id, status=status)

    def update_case(self, case_id, *, name=None, owner=None, description=None, status=None):
        if status is not None and status not in {"Open", "Closed"}:
            raise ValueError("Unknown investigation status")
        if name is not None and not 1 <= len(name.strip()) <= 120:
            raise ValueError("Investigation name must be 1–120 characters")
        if (owner is not None and len(owner) > 120) or (description is not None and len(description) > 2000):
            raise ValueError("Owner or description exceeds the supported length")
        with self.session() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("Unknown investigation")
            details = db.execute("SELECT * FROM case_details WHERE case_id=?", (case_id,)).fetchone()
            current = dict(details) if details else {
                "description": "", "owner": "Local investigator", "status": "Open",
            }
            if name is not None:
                db.execute("UPDATE cases SET name=? WHERE id=?", (name.strip(), case_id))
            db.execute("""
                INSERT INTO case_details(case_id, description, owner, status) VALUES (?,?,?,?)
                ON CONFLICT(case_id) DO UPDATE SET description=excluded.description,
                   owner=excluded.owner, status=excluded.status
            """, (case_id, current["description"] if description is None else description.strip(),
                  current["owner"] if owner is None else owner.strip() or "Local investigator",
                  status or current["status"]))
            if any(value is not None for value in (name, owner, description)):
                self._audit(db, "case_details_updated", case_id, {})
            if status is not None:
                self._audit(db, "case_status_updated", case_id, {"status": status})

    def checked_audit(self):
        previous = "0" * 64
        for index, row in enumerate(self.list("audit"), 1):
            if row["seq"] != index or row["previous"] != previous:
                return False
            expected = self._entry_hash(row["stamp"], row["case_id"], row["action"],
                                        row["details"], previous)
            if expected != row["digest"]:
                return False
            previous = expected
        return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path(".privforensics"))
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("create").add_argument("name")
    reference = actions.add_parser("register")
    reference.add_argument("case")
    reference.add_argument("path", type=Path)
    reference.add_argument("--expected-sha256")
    actions.add_parser("verify").add_argument("evidence_id")
    actions.add_parser("audit")
    args = parser.parse_args()
    registry = Registry(args.state)
    if args.action == "create":
        result = {"case": registry.case(args.name)}
    elif args.action == "register":
        result = {"evidence_id": registry.register_reference(
            args.case, args.path, expected=args.expected_sha256)}
    elif args.action == "verify":
        result = {"valid": registry.verify(args.evidence_id)}
    else:
        result = {"valid": registry.checked_audit(), "entries": registry.list("audit")}
    print(json.dumps(result, indent=2))
    if result.get("valid") is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
