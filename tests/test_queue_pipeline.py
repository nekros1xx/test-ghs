"""
Tests for the producer/worker/collector pipeline and the SQLite datastore.

These do NOT require Redis or the real git_sparse Rust module — the queue hop is
tested by driving the functions directly, git_sparse is faked, and api_request is
monkeypatched. A live end-to-end run over Redis is exercised separately.
"""

import json
import sys
import types

import pytest


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    """Point the db module at a throwaway SQLite file with a clean connection."""
    from gha_vuln_scanner import db
    monkeypatch.setenv("GHASCAN_DB", str(tmp_path / "t.db"))
    import threading
    db._local = threading.local()  # drop any cached connection
    db.init_db()
    return db


# ── db.py ────────────────────────────────────────────────────────────

def test_known_hashes_roundtrip(fresh_db):
    db = fresh_db
    assert db.known_hashes_for_repo("o/r") == []
    db.upsert_blob("o/r", ".github/workflows/ci.yml", "hashA")
    db.upsert_blob("o/r", ".github/workflows/rel.yml", "hashB")
    assert set(db.known_hashes_for_repo("o/r")) == {"hashA", "hashB"}
    # upsert on same path replaces the hash (changed file)
    db.upsert_blob("o/r", ".github/workflows/ci.yml", "hashA2")
    assert set(db.known_hashes_for_repo("o/r")) == {"hashA2", "hashB"}


def test_finding_upsert_and_filter(fresh_db):
    db = fresh_db
    db.upsert_finding("acme/app", ".github/workflows/ci.yml",
                      {"severity": "HIGH", "repo": "acme/app"})
    db.upsert_finding("other/lib", ".github/workflows/x.yml",
                      {"severity": "LOW", "repo": "other/lib"})
    assert len(list(db.iter_findings(org="acme"))) == 1
    assert len(list(db.iter_findings(repo="other/lib"))) == 1
    assert len(list(db.iter_findings(severities={"HIGH"}))) == 1


def test_flush_scoped(fresh_db):
    db = fresh_db
    db.record_repo("acme/app", "acme", 10, "Organization", "org")
    db.upsert_blob("acme/app", "p", "h")
    db.record_repo("zzz/lib", "zzz", 1, "User", "user")
    assert db.flush("acme/app") == 1
    assert db.known_hashes_for_repo("acme/app") == []
    assert len(db.list_scanned()) == 1  # zzz/lib remains


# ── worker.process_repo with a fake git_sparse ───────────────────────

class _FakeFile:
    def __init__(self, name, data):
        self.name = name
        self._data = data
        self.size = len(data)

    def read(self):
        return self._data

    def close(self):
        pass


class _FakeRepo:
    def __init__(self, files):
        self._files = files
        self.seen_known = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def sparse_checkout(self, *patterns, ref="HEAD", strict=False, known_files=None):
        self.seen_known = known_files or []
        # Emulate git_sparse: never return a blob whose hash is already known.
        return [
            {"hash": h, "file": _FakeFile(name, data)}
            for (name, h, data) in self._files
            if h not in self.seen_known
        ]


def _install_fake_git_sparse(monkeypatch, files):
    captured = {}

    def repo(url, *, depth=1):
        r = _FakeRepo(files)
        captured["repo"] = r
        captured["url"] = url
        return r

    mod = types.ModuleType("git_sparse")
    mod.repo = repo
    monkeypatch.setitem(sys.modules, "git_sparse", mod)
    return captured


def test_process_repo_analyzes_and_passes_known_files(monkeypatch):
    from gha_vuln_scanner import worker
    from gha_vuln_scanner.tokens import set_tokens
    set_tokens(["ghp_fake"])

    vulnerable = (
        "on: issue_comment\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ github.event.comment.body }}\n"
    )
    files = [(".github/workflows/ci.yml", "blob1", vulnerable.encode())]
    _install_fake_git_sparse(monkeypatch, files)

    pushed = []
    monkeypatch.setattr(worker.jobs, "push_result", lambda r, **k: pushed.append(r))

    payload = {"repo": "o/r", "owner": "o", "repo_name": "r",
               "stars": 5, "known_files": ["already-known"]}
    result = worker.process_repo(payload)

    assert result["error"] is None
    assert len(result["files"]) == 1
    fi = result["files"][0]
    assert fi["path"] == ".github/workflows/ci.yml"
    assert fi["blob_hash"] == "blob1"
    assert fi["finding"] is not None
    assert fi["finding"]["severity"]  # analyze produced a verdict
    assert pushed and pushed[0] is result  # handed to collector


def test_process_repo_skips_known_blob(monkeypatch):
    from gha_vuln_scanner import worker
    from gha_vuln_scanner.tokens import set_tokens
    set_tokens(["ghp_fake"])

    files = [(".github/workflows/ci.yml", "blob1", b"on: push\njobs: {}\n")]
    _install_fake_git_sparse(monkeypatch, files)
    monkeypatch.setattr(worker.jobs, "push_result", lambda r, **k: None)

    # blob1 is already known → git_sparse returns nothing → no files processed
    result = worker.process_repo(
        {"repo": "o/r", "owner": "o", "repo_name": "r", "known_files": ["blob1"]})
    assert result["files"] == []
    assert result["error"] is None


# ── collector.handle_result → db ─────────────────────────────────────

def test_collector_persists(fresh_db):
    from gha_vuln_scanner import collector
    result = {
        "repo": "o/r",
        "error": None,
        "files": [
            {"path": ".github/workflows/ci.yml", "blob_hash": "b1",
             "finding": {"severity": "HIGH", "repo": "o/r"}},
            {"path": ".github/workflows/safe.yml", "blob_hash": "b2", "finding": None},
        ],
    }
    blobs, findings = collector.handle_result(result)
    assert (blobs, findings) == (2, 1)
    assert set(fresh_db.known_hashes_for_repo("o/r")) == {"b1", "b2"}
    assert len(list(fresh_db.iter_findings(repo="o/r"))) == 1


# ── producer resolvers with mocked api_request ───────────────────────

def test_state_cursor_roundtrip(fresh_db):
    db = fresh_db
    assert db.get_state("yolo_since", "0") == "0"
    db.set_state("yolo_since", 12345)
    assert db.get_state("yolo_since") == "12345"


def test_ui_stats_reads_findings(fresh_db):
    from gha_vuln_scanner import ui
    fresh_db.record_repo("o/r", "o", 0, "", "yolo")
    fresh_db.upsert_finding("o/r", ".github/workflows/ci.yml",
                            {"severity": "CRITICAL", "repo": "o/r"})
    stats = ui._read_stats()
    assert stats["ready"] is True
    assert stats["totals"]["findings"] == 1
    assert stats["severities"].get("CRITICAL") == 1
    assert stats["recent"][0]["repo"] == "o/r"


def test_ui_stats_hides_false_positives(fresh_db):
    from gha_vuln_scanner import ui
    fresh_db.upsert_finding("o/r", ".github/workflows/vuln.yml",
                            {"severity": "HIGH", "repo": "o/r",
                             "vulnerable_expressions": [{"line": 1, "expression": "x"}]})
    fresh_db.upsert_finding("o/r", ".github/workflows/unpinned.yml",
                            {"severity": "FALSE_POSITIVE", "repo": "o/r",
                             "unpinned_actions": ["a/b@v1"]})
    stats = ui._read_stats()
    assert stats["totals"]["findings"] == 1  # FP not counted
    assert "FALSE_POSITIVE" not in stats["severities"]
    paths = [r["path"] for r in stats["recent"]]
    assert paths == [".github/workflows/vuln.yml"]  # FP hidden from the live list


def test_ui_search_repos_paginates_and_filters(fresh_db):
    from gha_vuln_scanner import ui
    for i in range(3):
        fresh_db.record_repo(f"acme/app{i}", "acme", i, "Organization", "yolo")
    fresh_db.record_repo("other/lib", "other", 0, "User", "yolo")
    # one real finding on acme/app1 so the count column is exercised
    fresh_db.upsert_finding("acme/app1", ".github/workflows/x.yml",
                            {"severity": "HIGH", "repo": "acme/app1",
                             "vulnerable_expressions": [{"line": 1, "expression": "x"}]})
    allr = ui._search_repos("", 0, 50)
    assert allr["total"] == 4
    assert {r["full_name"] for r in allr["rows"]} == {"acme/app0", "acme/app1", "acme/app2", "other/lib"}
    assert next(r["findings"] for r in allr["rows"] if r["full_name"] == "acme/app1") == 1
    acme = ui._search_repos("acme", 0, 50)
    assert acme["total"] == 3 and all("acme/" in r["full_name"] for r in acme["rows"])
    # pagination: page size 2 → 2 pages
    p0 = ui._search_repos("", 0, 2)
    p1 = ui._search_repos("", 1, 2)
    assert len(p0["rows"]) == 2 and len(p1["rows"]) == 2


def test_ui_repo_findings_includes_false_positives(fresh_db):
    from gha_vuln_scanner import ui
    fresh_db.upsert_finding("o/r", ".github/workflows/vuln.yml",
                            {"severity": "HIGH", "repo": "o/r",
                             "vulnerable_expressions": [{"line": 1, "expression": "x"}]})
    fresh_db.upsert_finding("o/r", ".github/workflows/unpinned.yml",
                            {"severity": "FALSE_POSITIVE", "repo": "o/r",
                             "unpinned_actions": ["a/b@v1"]})
    rows = ui._repo_findings("o/r")
    assert len(rows) == 2  # drilling into a repo shows EVERYTHING incl FP
    assert rows[0]["severity"] == "HIGH"  # ordered, real first


def test_worker_db_sink_writes_directly(fresh_db, monkeypatch):
    """sink=db routes results straight into SQLite (no Redis collector)."""
    from gha_vuln_scanner import worker
    monkeypatch.setenv("GHASCAN_SINK", "db")
    # push_result must NOT be used in db-sink mode
    monkeypatch.setattr(worker.jobs, "push_result",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("used redis")))
    worker._emit({"repo": "o/r", "error": None,
                  "files": [{"path": ".github/workflows/ci.yml", "blob_hash": "h1",
                             "finding": {"severity": "HIGH", "repo": "o/r"}}]})
    assert fresh_db.known_hashes_for_repo("o/r") == ["h1"]
    assert len(list(fresh_db.iter_findings(repo="o/r"))) == 1


def test_run_yolo_enumerates_and_checkpoints(fresh_db, monkeypatch):
    """YOLO pages /repositories, skips forks, enqueues, and persists the cursor."""
    from gha_vuln_scanner import producer

    pages = [
        [{"id": 1, "full_name": "a/one", "fork": False},
         {"id": 2, "full_name": "b/two", "fork": True},   # fork → skipped
         {"id": 3, "full_name": "c/three", "fork": False}],
        [],  # end of firehose
    ]
    seq = iter(pages)
    monkeypatch.setattr("gha_vuln_scanner.scanner.api_request",
                        lambda url, *a, **k: (next(seq), 999, 0))

    enqueued = []
    monkeypatch.setattr(producer.jobs, "redis_conn", lambda *a, **k: object())
    fake_q = type("Q", (), {"count": 0})()
    monkeypatch.setattr(producer.jobs, "get_queue", lambda *a, **k: fake_q)
    monkeypatch.setattr(producer.jobs, "enqueue_repo",
                        lambda p, **k: enqueued.append(p["repo"]))

    n = producer.run_yolo(max_repos=0, page_pause=0)
    assert n == 2                      # fork dropped
    assert enqueued == ["a/one", "c/three"]
    assert fresh_db.get_state("yolo_since") == "3"   # cursor advanced past last id


def test_worker_stores_unpinned_only_finding(monkeypatch):
    """A workflow with only unpinned actions (verdict FALSE_POSITIVE) is still stored."""
    from gha_vuln_scanner import worker
    from gha_vuln_scanner.tokens import set_tokens
    set_tokens(["ghp_fake"])

    # Benign triggers/permissions but a third-party action pinned by tag → unpinned-only.
    wf = ("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: some-vendor/do-thing@v3\n")
    files = [(".github/workflows/ci.yml", "blobU", wf.encode())]
    _install_fake_git_sparse(monkeypatch, files)
    captured = []
    monkeypatch.setattr(worker.jobs, "push_result", lambda r, **k: captured.append(r))

    res = worker.process_repo({"repo": "o/r", "owner": "o", "repo_name": "r", "known_files": []})
    fi = res["files"][0]
    assert fi["finding"] is not None, "unpinned-only finding must be stored"
    assert fi["finding"]["severity"] == "FALSE_POSITIVE"
    assert fi["finding"]["unpinned_actions"]  # the signal we must not drop


def test_worker_skips_benign_workflow(monkeypatch):
    """A workflow with no signal at all stores only the blob hash, no finding."""
    from gha_vuln_scanner import worker
    from gha_vuln_scanner.tokens import set_tokens
    set_tokens(["ghp_fake"])

    wf = ("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: actions/checkout@v4\n      - run: echo hello\n")
    _install_fake_git_sparse(monkeypatch, [(".github/workflows/ci.yml", "blobB", wf.encode())])
    monkeypatch.setattr(worker.jobs, "push_result", lambda r, **k: None)
    res = worker.process_repo({"repo": "o/r", "owner": "o", "repo_name": "r", "known_files": []})
    assert res["files"][0]["finding"] is None


def test_db_signals_and_get_finding(fresh_db):
    db = fresh_db
    fd = {"severity": "FALSE_POSITIVE", "repo": "o/r",
          "file_url": "https://github.com/o/r/blob/HEAD/.github/workflows/ci.yml",
          "unpinned_actions": ["a/b@v1", "c/d@v2"],
          "vulnerable_expressions": [{"line": 5, "expression": "x"}]}
    db.upsert_finding("o/r", ".github/workflows/ci.yml", fd)
    row = db.recent_findings()[0]
    assert row["signals"] == {"expr": 1, "env": 0, "indirect": 0, "ai": 0, "unpinned": 2}
    got = db.get_finding("o/r", ".github/workflows/ci.yml")
    assert got["file_url"].endswith("ci.yml") and len(got["unpinned_actions"]) == 2
    assert db.get_finding("no/such", "x") is None


def test_ui_chat_via_claude_cli(fresh_db, monkeypatch):
    """First turn hands Claude ONLY the raw URL to fetch (no file content / findings)."""
    from gha_vuln_scanner import ui
    fresh_db.upsert_finding("o/r", ".github/workflows/ci.yml", {
        "severity": "HIGH", "repo": "o/r", "path": ".github/workflows/ci.yml",
        "file_url": "https://github.com/o/r/blob/deadbeef/.github/workflows/ci.yml",
        "workflow_content": "on: issue_comment\njobs: {}\n",
        "vulnerable_expressions": [{"line": 6, "expression": "${{ github.event.comment.body }}",
                                    "control_label": "FULL", "context": "run"}]})

    monkeypatch.setattr(ui.shutil, "which", lambda name: "/usr/bin/claude")
    seen = {}

    class _Proc:
        returncode = 0
        stdout = json.dumps({"result": "Yes, line 6 is exploitable.", "is_error": False})
        stderr = ""

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(ui.subprocess, "run", fake_run)

    out = ui.chat_reply("o/r", ".github/workflows/ci.yml",
                        "11111111-1111-4111-8111-111111111111", True, "is this exploitable?")
    assert out == "Yes, line 6 is exploitable."
    cmd = seen["cmd"]
    assert cmd[:2] == ["claude", "-p"]
    assert "--session-id" in cmd and "11111111-1111-4111-8111-111111111111" in cmd
    assert "--allowedTools" in cmd and "WebFetch" in cmd
    prompt = cmd[2]
    # pointer carries the raw fetch URL...
    assert "raw.githubusercontent.com/o/r/deadbeef/.github/workflows/ci.yml" in prompt
    # ...but NOT the file content or our findings (Claude fetches + analyzes itself)
    assert "issue_comment" not in prompt and "github.event.comment.body" not in prompt


def test_ui_chat_followup_resumes_session(fresh_db, monkeypatch):
    from gha_vuln_scanner import ui
    fresh_db.upsert_finding("o/r", ".github/workflows/ci.yml",
                            {"severity": "HIGH", "repo": "o/r", "workflow_content": "on: push\n",
                             "vulnerable_expressions": [{"line": 1, "expression": "x"}]})
    monkeypatch.setattr(ui.shutil, "which", lambda name: "/usr/bin/claude")
    seen = {}

    class _Proc:
        returncode = 0
        stdout = json.dumps({"result": "ok", "is_error": False})
        stderr = ""

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(ui.subprocess, "run", fake_run)
    ui.chat_reply("o/r", ".github/workflows/ci.yml", "22222222-2222-4222-8222-222222222222", False, "and the fix?")
    cmd = seen["cmd"]
    assert "--resume" in cmd and "22222222-2222-4222-8222-222222222222" in cmd
    assert cmd[2] == "and the fix?"  # follow-up sends only the question


def test_ui_chat_no_cli_is_graceful(fresh_db, monkeypatch):
    from gha_vuln_scanner import ui
    fresh_db.upsert_finding("o/r", ".github/workflows/ci.yml",
                            {"severity": "LOW", "repo": "o/r", "workflow_content": "on: push\n",
                             "unpinned_actions": ["a/b@v1"]})
    monkeypatch.setattr(ui.shutil, "which", lambda name: None)
    out = ui.chat_reply("o/r", ".github/workflows/ci.yml", "s", True, "hi")
    assert "Claude Code CLI not found" in out


def test_resolve_org_filters_and_builds_payloads(monkeypatch):
    from gha_vuln_scanner import producer

    page = [
        {"full_name": "acme/good", "stargazers_count": 50, "fork": False, "archived": False},
        {"full_name": "acme/forked", "stargazers_count": 99, "fork": True, "archived": False},
        {"full_name": "acme/old", "stargazers_count": 99, "fork": False, "archived": True},
        {"full_name": "acme/tiny", "stargazers_count": 1, "fork": False, "archived": False},
    ]
    calls = {"n": 0}

    def fake_api(url, *a, **k):
        calls["n"] += 1
        return (page if calls["n"] == 1 else [], 999, 0)

    monkeypatch.setattr("gha_vuln_scanner.scanner.api_request", fake_api)
    repos = producer.resolve_org("acme", max_repos=500, min_stars=10)
    names = {r["repo"] for r in repos}
    assert names == {"acme/good"}  # forked/archived/low-star dropped
    p = repos[0]
    assert p["owner"] == "acme" and p["repo_name"] == "good" and p["org_type"] == "Organization"
