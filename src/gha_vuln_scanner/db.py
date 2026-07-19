"""
Central SQLite datastore for ghascan.

Lives ONLY on the producer/collector node — distributed workers never touch it.
Stores per-repo known blob hashes (for incremental ``git_sparse`` checkouts),
findings, and scan-run history. Replaces the old ``~/.ghascan/scan_history.json``.

Schema
------
- ``repos``        one row per scanned repo (metadata + last scan time)
- ``known_blobs``  the blob hash currently recorded for each (repo, path);
                   the union of these hashes is passed to ``git_sparse`` as
                   ``known_files`` so unchanged workflows are never re-downloaded
- ``findings``     latest analysis result per (repo, path), findings JSON blob
- ``scan_runs``    audit log of enqueue runs (target, counts, timing)
"""

import contextlib
import json
import os
import sqlite3
import threading
from datetime import datetime

_DB_DIR = os.path.join(os.path.expanduser("~"), ".ghascan")
_DB_FILE = os.path.join(_DB_DIR, "ghascan.db")

# One connection per thread (sqlite3 connections are not shareable across threads).
_local = threading.local()


def db_path() -> str:
    """Return the SQLite file path (override with GHASCAN_DB env var)."""
    return os.environ.get("GHASCAN_DB", _DB_FILE)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS repos (
    full_name       TEXT PRIMARY KEY,
    owner           TEXT,
    stars           INTEGER DEFAULT 0,
    org_type        TEXT,
    source          TEXT,
    last_scanned_at TEXT
);

CREATE TABLE IF NOT EXISTS known_blobs (
    repo      TEXT NOT NULL,
    path      TEXT NOT NULL,
    blob_hash TEXT NOT NULL,
    PRIMARY KEY (repo, path)
);
CREATE INDEX IF NOT EXISTS idx_known_blobs_repo ON known_blobs(repo);

CREATE TABLE IF NOT EXISTS findings (
    repo         TEXT NOT NULL,
    path         TEXT NOT NULL,
    severity     TEXT,
    confidence   TEXT,
    signals      TEXT,
    finding_json TEXT,
    updated_at   TEXT,
    PRIMARY KEY (repo, path)
);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo);

CREATE TABLE IF NOT EXISTS scan_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT,
    kind          TEXT,
    repos_scanned INTEGER DEFAULT 0,
    findings      INTEGER DEFAULT 0,
    started_at    TEXT,
    finished_at   TEXT
);

CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _conn() -> sqlite3.Connection:
    """Thread-local connection, schema ensured on first use.

    WAL + busy_timeout let the producer, several workers (in db-sink mode) and the
    read-only UI all share one SQLite file on a mounted volume without clobbering
    each other — writers are serialized, readers stay concurrent."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        path = db_path()
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.executescript(_SCHEMA)
        # Migrate pre-existing DBs that lack the signals column.
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("ALTER TABLE findings ADD COLUMN signals TEXT")
        conn.commit()
        _local.conn = conn
    return conn


def init_db() -> None:
    """Create the database file and schema if they do not exist."""
    _conn()


# ── known blobs (the incremental-skip mechanism) ─────────────────────

def known_hashes_for_repo(repo: str) -> list[str]:
    """All blob hashes recorded for ``repo`` — passed to git_sparse.known_files."""
    cur = _conn().execute("SELECT blob_hash FROM known_blobs WHERE repo = ?", (repo,))
    return [r["blob_hash"] for r in cur.fetchall()]


def upsert_blob(repo: str, path: str, blob_hash: str) -> None:
    """Record the current blob hash for a (repo, path)."""
    conn = _conn()
    conn.execute(
        "INSERT INTO known_blobs (repo, path, blob_hash) VALUES (?, ?, ?) "
        "ON CONFLICT(repo, path) DO UPDATE SET blob_hash = excluded.blob_hash",
        (repo, path, blob_hash),
    )
    conn.commit()


# ── findings ─────────────────────────────────────────────────────────

def signal_counts(finding_dict: dict) -> dict:
    """Compact per-signal counts for a finding — cheap badges without full JSON."""
    return {
        "expr": len(finding_dict.get("vulnerable_expressions") or []),
        "env": len(finding_dict.get("env_injections") or []),
        "indirect": len(finding_dict.get("indirect_injections") or []),
        "ai": len(finding_dict.get("ai_risk") or []),
        "unpinned": len(finding_dict.get("unpinned_actions") or []),
    }


def upsert_finding(repo: str, path: str, finding_dict: dict) -> None:
    """Store/replace the latest analysis result for a (repo, path)."""
    conn = _conn()
    conn.execute(
        "INSERT INTO findings (repo, path, severity, confidence, signals, finding_json, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(repo, path) DO UPDATE SET "
        "severity = excluded.severity, confidence = excluded.confidence, "
        "signals = excluded.signals, finding_json = excluded.finding_json, "
        "updated_at = excluded.updated_at",
        (
            repo,
            path,
            finding_dict.get("severity", ""),
            finding_dict.get("confidence", ""),
            json.dumps(signal_counts(finding_dict)),
            json.dumps(finding_dict),
            datetime.now().isoformat(),
        ),
    )
    conn.commit()


def get_finding(repo: str, path: str) -> dict | None:
    """Return the full stored finding dict for a (repo, path), or None."""
    row = _conn().execute(
        "SELECT finding_json FROM findings WHERE repo = ? AND path = ?", (repo, path)
    ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["finding_json"])
    except (json.JSONDecodeError, TypeError):
        return None


def iter_findings(repo: str | None = None, org: str | None = None,
                  severities: set[str] | None = None):
    """Yield stored finding dicts, optionally filtered by repo/org/severity."""
    sql = "SELECT repo, finding_json FROM findings"
    clauses, params = [], []
    if repo:
        clauses.append("repo = ?")
        params.append(repo)
    if org:
        clauses.append("repo LIKE ?")
        params.append(f"{org}/%")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    for row in _conn().execute(sql, params):
        try:
            fd = json.loads(row["finding_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        if severities and fd.get("severity") not in severities:
            continue
        yield fd


# ── repo metadata + run history ──────────────────────────────────────

def record_repo(full_name: str, owner: str, stars: int, org_type: str, source: str) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO repos (full_name, owner, stars, org_type, source, last_scanned_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(full_name) DO UPDATE SET "
        "owner = excluded.owner, stars = excluded.stars, org_type = excluded.org_type, "
        "source = excluded.source, last_scanned_at = excluded.last_scanned_at",
        (full_name, owner, stars, org_type, source, datetime.now().isoformat()),
    )
    conn.commit()


def mark_scanned(repo: str) -> None:
    """Record that a repo was actually processed (by the collector), stamping its scan
    time. Preserves owner/stars/source if the producer already inserted it."""
    owner = repo.split("/", 1)[0]
    conn = _conn()
    conn.execute(
        "INSERT INTO repos (full_name, owner, source, last_scanned_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(full_name) DO UPDATE SET last_scanned_at = excluded.last_scanned_at",
        (repo, owner, "scan", datetime.now().isoformat()),
    )
    conn.commit()


def record_run(target: str, kind: str, repos_scanned: int,
               started_at: str, finished_at: str | None = None) -> None:
    conn = _conn()
    findings_total = _conn().execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
    conn.execute(
        "INSERT INTO scan_runs (target, kind, repos_scanned, findings, started_at, finished_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (target, kind, repos_scanned, findings_total,
         started_at, finished_at or datetime.now().isoformat()),
    )
    conn.commit()


def get_state(key: str, default: str | None = None) -> str | None:
    """Read a small persisted value (e.g. the YOLO enumeration cursor)."""
    row = _conn().execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_state(key: str, value: str) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )
    conn.commit()


def counts_by_severity() -> dict:
    """Findings grouped by severity — for the live dashboard."""
    rows = _conn().execute(
        "SELECT COALESCE(NULLIF(severity, ''), 'UNKNOWN') AS sev, COUNT(*) AS n "
        "FROM findings GROUP BY sev"
    ).fetchall()
    return {r["sev"]: r["n"] for r in rows}


def recent_findings(limit: int = 100) -> list[dict]:
    """Most-recently-updated findings (repo, path, severity, signals, updated_at)."""
    rows = _conn().execute(
        "SELECT repo, path, severity, signals, updated_at FROM findings "
        "ORDER BY updated_at DESC LIMIT ?", (limit,)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["signals"] = json.loads(d["signals"]) if d["signals"] else {}
        except (json.JSONDecodeError, TypeError):
            d["signals"] = {}
        out.append(d)
    return out


def totals() -> dict:
    """Top-line counters for the dashboard header."""
    c = _conn()
    return {
        "repos": c.execute("SELECT COUNT(*) AS n FROM repos").fetchone()["n"],
        "findings": c.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"],
        "blobs": c.execute("SELECT COUNT(*) AS n FROM known_blobs").fetchone()["n"],
    }


def list_scanned() -> list[dict]:
    """Return per-repo scan summary (repo, stars, last_scanned_at, findings count)."""
    rows = _conn().execute(
        "SELECT r.full_name, r.owner, r.stars, r.source, r.last_scanned_at, "
        "       (SELECT COUNT(*) FROM findings f WHERE f.repo = r.full_name) AS findings "
        "FROM repos r ORDER BY r.last_scanned_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def flush(org: str | None = None) -> int:
    """Remove stored state. If ``org`` is given, only rows for that org/repo;
    otherwise wipe everything. Returns the number of repos removed."""
    conn = _conn()
    if org:
        like = f"{org}/%"
        # `org` may be a full "owner/name" repo or an org/owner prefix.
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM repos WHERE full_name = ? OR full_name LIKE ?",
            (org, like),
        ).fetchone()["n"]
        for tbl, col in (("known_blobs", "repo"), ("findings", "repo"), ("repos", "full_name")):
            conn.execute(f"DELETE FROM {tbl} WHERE {col} = ? OR {col} LIKE ?", (org, like))
    else:
        n = conn.execute("SELECT COUNT(*) AS n FROM repos").fetchone()["n"]
        for tbl in ("known_blobs", "findings", "repos", "scan_runs", "state"):
            conn.execute(f"DELETE FROM {tbl}")
    conn.commit()
    return n
