"""
Collector: drain worker results from Redis into the central SQLite database.

Runs on the central/DB node (long-running, or briefly alongside ``enqueue``). Each
result carries the workflow files a worker actually downloaded (changed/new blobs);
for every file the collector records the blob hash — so it is skipped next time — and
upserts the finding when the analysis produced a real verdict. Idempotent.
"""

from gha_vuln_scanner import db, jobs


def handle_result(result: dict) -> tuple[int, int]:
    """Persist one worker result. Returns (blobs_recorded, findings_stored)."""
    repo = result.get("repo", "?")
    db.mark_scanned(repo)  # so the Scanned-repos view reflects actually-processed repos
    if result.get("error"):
        print(f"  ⚠  {repo}: {result['error']}")
    blobs = findings = 0
    for fi in result.get("files", []):
        path = fi["path"]
        db.upsert_blob(repo, path, fi["blob_hash"])
        blobs += 1
        finding = fi.get("finding")
        if finding:
            db.upsert_finding(repo, path, finding)
            findings += 1
            sev = finding.get("severity", "?")
            print(f"  🔎 {repo}:{path} → {sev}")
    return blobs, findings


def run_collector(url: str | None = None, once: bool = False, idle_timeout: int = 0) -> None:
    """Block on the results list and persist everything that arrives.

    ``once`` drains what is currently queued then returns. ``idle_timeout`` (seconds)
    stops after that long with no new results (0 = run forever)."""
    db.init_db()
    conn = jobs.redis_conn(url)
    print(f"📥 ghascan collector draining '{jobs.RESULTS_LIST}' @ {jobs.redis_url(url)}")
    total_blobs = total_findings = idle = 0
    poll = 5
    while True:
        result = jobs.pop_result(timeout=poll, conn=conn)
        if result is None:
            if once:
                break
            idle += poll
            if idle_timeout and idle >= idle_timeout:
                print(f"  ⏹  Idle {idle}s, stopping.")
                break
            continue
        idle = 0
        b, f = handle_result(result)
        total_blobs += b
        total_findings += f
    print(f"\n✅ Collected {total_blobs} blob(s), {total_findings} finding(s).")
