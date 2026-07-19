"""
Dumb, stateless worker: "here is a repo — download it and process it."

Runs on any host. Receives a self-contained job payload (repo + known blob hashes),
uses ``git_sparse`` to read only the workflow blobs it does NOT already know about
straight into memory (nothing hits disk), runs the analysis engine, and hands the
results back to the collector via the Redis results list. It never touches the DB.

Payload (produced by ``producer``)::

    {
      "repo":       "owner/name",
      "owner":      "owner",
      "repo_name":  "name",
      "stars":      123,
      "org_name":   "owner",
      "org_type":   "Organization" | "User",
      "known_files": ["<blob sha>", ...],   # skipped by git_sparse
    }

Result (consumed by ``collector``)::

    {
      "repo": "owner/name",
      "files": [{"path": ..., "blob_hash": ..., "finding": <dict>|None}, ...],
      "error": None | "message",
    }
"""

import contextlib
import hashlib
import os

from gha_vuln_scanner import jobs
from gha_vuln_scanner.tokens import next_token

_WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")

# Detection fields (as serialized by finding_to_dict) that make a finding worth storing.
_SIGNAL_FIELDS = (
    "vulnerable_expressions", "env_injections",
    "indirect_injections", "ai_risk", "unpinned_actions",
)


def _has_signal(finding_dict: dict) -> bool:
    """True if analyze() produced any detection signal, regardless of the verdict."""
    return any(finding_dict.get(f) for f in _SIGNAL_FIELDS)


def _clone_url(owner: str, repo_name: str) -> str:
    """Authenticated HTTPS clone URL (token pattern reused from the old clone path)."""
    token = next_token()
    if token:
        return f"https://x-access-token:{token}@github.com/{owner}/{repo_name}.git"
    return f"https://github.com/{owner}/{repo_name}.git"


def _build_finding(payload: dict, path: str, content: str):
    """Construct + analyze a Finding for one workflow file. Import scanner lazily
    so a bare ``worker`` install without analysis extras still imports."""
    from gha_vuln_scanner.scanner import Finding, analyze, finding_to_dict

    repo = payload["repo"]
    ref = payload.get("ref") or "HEAD"
    f = Finding(
        repo=repo,
        path=path,
        stars=payload.get("stars", 0),
        org_name=payload.get("org_name", payload.get("owner", "")),
        org_type=payload.get("org_type", ""),
        repo_url=f"https://github.com/{repo}",
        file_url=f"https://github.com/{repo}/blob/{ref}/{path}",
        security_url=f"https://github.com/{repo}/security",
        workflow_content=content,
        content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
        query_id=payload.get("query_id", -1),
        query_name=payload.get("query_name", "queue"),
    )
    # Incremental mode processes each changed file on its own; cross-workflow
    # context is limited to what changed (documented limitation).
    f._other_workflows = {}
    f._clone_path = None
    analyze(f)
    return finding_to_dict(f)


def process_repo(payload: dict) -> dict:
    """RQ job body. Download changed workflow blobs, analyze, push results."""
    repo = payload["repo"]
    owner = payload["owner"]
    repo_name = payload["repo_name"]
    known = payload.get("known_files", []) or []
    ref = payload.get("ref")  # optional branch/tag/commit to pin the scan to

    result = {"repo": repo, "files": [], "error": None}
    try:
        import git_sparse
    except ImportError as e:  # pragma: no cover - env-dependent
        result["error"] = f"git_sparse not installed: {e}"
        jobs.push_result(result)
        return result

    url = _clone_url(owner, repo_name)
    # A pinned ref may be an arbitrary historical commit → need full history (depth=0);
    # the default HEAD scan only needs the tip (depth=1).
    depth = 0 if ref else 1
    try:
        with git_sparse.repo(url, depth=depth) as repo_handle:
            matches = repo_handle.sparse_checkout(
                *_WORKFLOW_GLOBS, known_files=known, ref=ref or "HEAD")
            for m in matches:
                blob_hash = m["hash"]
                sf = m["file"]
                path = sf.name
                try:
                    content = sf.read().decode("utf-8", errors="replace")
                finally:
                    with contextlib.suppress(Exception):
                        sf.close()
                finding = _build_finding(payload, path, content)
                # Store the finding if analyze() produced ANY detection signal —
                # not just an exploitable verdict. This keeps unpinned-only findings
                # (always classified FALSE_POSITIVE) and FALSE_POSITIVE workflows that
                # still carry env/indirect/ai signal. Benign workflows still record only
                # the blob hash so they're skipped next time.
                result["files"].append({
                    "path": path,
                    "blob_hash": blob_hash,
                    "finding": finding if _has_signal(finding) else None,
                })
    except Exception as e:  # network/git/parse failure — report, do not crash the worker
        result["error"] = f"{type(e).__name__}: {e}"

    _emit(result)
    return result


def _emit(result: dict) -> None:
    """Hand the result off according to GHASCAN_SINK.

    ``db``    — write straight into the shared SQLite (docker-compose topology, where
                the DB volume is mounted into every worker).
    ``redis`` — push onto the results list for a separate collector (distributed hosts).
    """
    sink = os.environ.get("GHASCAN_SINK", "redis").lower()
    if sink == "db":
        from gha_vuln_scanner import collector
        collector.handle_result(result)
    else:
        jobs.push_result(result)


def run_worker(url: str | None = None, burst: bool = False, sink: str = "redis") -> None:
    """Start an RQ worker consuming the ghascan queue (blocks)."""
    jobs._require_deps()
    import rq

    os.environ["GHASCAN_SINK"] = sink  # inherited by RQ's forked job process
    conn = jobs.redis_conn(url)
    queue = rq.Queue(jobs.QUEUE_NAME, connection=conn)
    worker = rq.Worker([queue], connection=conn)
    print(f"👷 ghascan worker ready on '{jobs.QUEUE_NAME}' @ {jobs.redis_url(url)} "
          f"(sink={sink})")
    worker.work(burst=burst, with_scheduler=False)
