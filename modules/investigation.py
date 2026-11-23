"""Case-linked findings, privacy settings, assessments and report snapshots."""
import hashlib
import json
from uuid import uuid4

from .evidence import utc


def _encode(value):
    return json.dumps(value, sort_keys=True, allow_nan=False)


class Investigation:
    def __init__(self, registry):
        self.registry = registry
        with registry.session() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS findings(
                    id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                    kind TEXT NOT NULL, title TEXT NOT NULL, timestamp_s INTEGER NOT NULL,
                    summary TEXT NOT NULL, score REAL, fingerprint TEXT NOT NULL,
                    created TEXT NOT NULL, UNIQUE(case_id, fingerprint));
                CREATE TABLE IF NOT EXISTS finding_refs(
                    finding_id TEXT NOT NULL REFERENCES findings(id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(id),
                    source_line INTEGER NOT NULL CHECK(source_line >= 1),
                    role TEXT NOT NULL, PRIMARY KEY(finding_id, evidence_id, source_line));
                CREATE TABLE IF NOT EXISTS privacy_profiles(
                    id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                    source_sha256 TEXT NOT NULL, profile TEXT NOT NULL, created TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS privacy_settings(
                    case_id TEXT PRIMARY KEY REFERENCES cases(id),
                    mechanism TEXT NOT NULL CHECK(mechanism IN ('mask','hmac')),
                    scope TEXT NOT NULL CHECK(scope IN ('case','workspace')));
                CREATE TABLE IF NOT EXISTS reports(
                    id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                    document TEXT NOT NULL, created TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS findings_by_case ON findings(case_id, created DESC);
                CREATE INDEX IF NOT EXISTS profiles_by_case ON privacy_profiles(case_id, created DESC);
                CREATE INDEX IF NOT EXISTS reports_by_case ON reports(case_id, created DESC);
            """)

    def add_finding(self, case, kind, title, timestamp, summary, references, *, score=None):
        if kind not in ("Model finding", "Event correlation"):
            raise ValueError("Unknown finding category")
        if not 1 <= len(references) <= 1000 or not 1 <= len(title) <= 160 or len(summary) > 1200:
            raise ValueError("Finding details or reference count are outside the supported range")
        references = sorted(set(references))
        if any(not isinstance(line, int) or line < 1 for _, line, _ in references):
            raise ValueError("A reference requires a one-based source line")
        key = hashlib.sha256(_encode([kind, title, references]).encode()).hexdigest()
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            attached = {row["sha256"]: row["id"] for row in db.execute(
                "SELECT id,sha256 FROM evidence WHERE case_id=?", (case,))}
            if not {digest for digest, _, _ in references} <= set(attached):
                raise ValueError("Register the referenced sources in this investigation to save the finding")
            previous = db.execute("SELECT id FROM findings WHERE case_id=? AND fingerprint=?",
                                  (case, key)).fetchone()
            if previous:
                return previous["id"]
            finding_id = uuid4().hex
            db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                       (finding_id, case, kind, title, int(timestamp), summary, score, key, utc()))
            db.executemany("INSERT INTO finding_refs VALUES (?,?,?,?)", [
                (finding_id, attached[digest], line, role) for digest, line, role in references
            ])
            self.registry._audit(db, "finding_saved", case, {"finding_id": finding_id, "category": kind})
        return finding_id

    def findings(self, case):
        with self.registry.session() as db:
            rows = db.execute("""
                SELECT id, kind, title, timestamp_s, summary, score, created FROM findings
                WHERE case_id=? ORDER BY created DESC LIMIT 250
            """, (case,)).fetchall()
            result = [dict(row) for row in rows]
            for row in result:
                row["references"] = [dict(ref) for ref in db.execute("""
                    SELECT e.id AS evidence_id, e.sha256, r.source_line, r.role
                    FROM finding_refs r JOIN evidence e ON r.evidence_id=e.id
                    WHERE r.finding_id=? ORDER BY r.role, r.source_line
                """, (row["id"],))]
        return result

    def save_profile(self, case, source_sha256, profile):
        identifier = uuid4().hex
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM evidence WHERE case_id=? AND sha256=?",
                              (case, source_sha256)).fetchone():
                raise ValueError("Register the profiled dataset in this investigation first")
            db.execute("INSERT INTO privacy_profiles VALUES (?,?,?,?,?)",
                       (identifier, case, source_sha256, _encode(profile), utc()))
            self.registry._audit(db, "privacy_profile_saved", case, {"profile_id": identifier})
        return identifier

    def profiles(self, case):
        with self.registry.session() as db:
            rows = db.execute("SELECT * FROM privacy_profiles WHERE case_id=? ORDER BY created DESC LIMIT 25",
                              (case,)).fetchall()
        return [{"id": row["id"], "source_sha256": row["source_sha256"],
                 "created": row["created"], **json.loads(row["profile"])} for row in rows]

    def privacy_defaults(self, case):
        with self.registry.session() as db:
            row = db.execute("SELECT mechanism, scope FROM privacy_settings WHERE case_id=?", (case,)).fetchone()
        return dict(row) if row else {"mechanism": "mask", "scope": "workspace"}

    def set_privacy_defaults(self, case, mechanism, scope):
        if mechanism not in ("mask", "hmac") or scope not in ("case", "workspace"):
            raise ValueError("Unknown protection settings")
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                INSERT INTO privacy_settings VALUES (?,?,?) ON CONFLICT(case_id)
                DO UPDATE SET mechanism=excluded.mechanism, scope=excluded.scope
            """, (case, mechanism, scope))
            self.registry._audit(db, "privacy_defaults_saved", case, {"mechanism": mechanism, "scope": scope})

    def save_report(self, case, document):
        identifier = uuid4().hex
        with self.registry.session() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO reports VALUES (?,?,?,?)",
                       (identifier, case, _encode(document), document["generated_utc"]))
            self.registry._audit(db, "report_created", case, {"report_id": identifier})
        return identifier

    def reports(self, case):
        with self.registry.session() as db:
            return [dict(row) for row in db.execute("""
                SELECT id,created FROM reports WHERE case_id=? ORDER BY created DESC LIMIT 50
            """, (case,))]

    def report(self, case, report_id):
        with self.registry.session() as db:
            row = db.execute("SELECT document FROM reports WHERE id=? AND case_id=?", (report_id, case)).fetchone()
        if row is None:
            raise ValueError("Report does not belong to this investigation")
        return json.loads(row["document"])
