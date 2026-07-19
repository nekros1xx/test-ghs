"""
Producer: enumerate GitHub targets and enqueue one job per repo.

Runs on the central node (it reads known blob hashes from the local SQLite so each
job payload is self-contained for the dumb workers). Target resolvers cover the four
discovery sources — org, user, single repo, and code-search queries — replacing the
old inline ``scan_org`` and wiring up the previously-dead ``--user`` / ``--repo`` flags.
"""

import time
from datetime import datetime

from gha_vuln_scanner import db, jobs

_YOLO_CURSOR = "yolo_since"


def _repo_payload(full_name: str, stars: int = 0, org_type: str = "") -> dict:
    owner, _, repo_name = full_name.partition("/")
    return {
        "repo": full_name,
        "owner": owner,
        "repo_name": repo_name,
        "stars": stars,
        "org_name": owner,
        "org_type": org_type,
    }


# ── resolvers → list[payload] ────────────────────────────────────────

def _paginate_repos(base_url: str, max_repos: int, min_stars: int, org_type: str) -> list[dict]:
    """Page through a GitHub repos listing endpoint, filtering fork/archived/stars.

    max_repos <= 0 means no cap — walk every page until the whole listing is
    exhausted (the default for org/user scans: you want the entire org).
    """
    from gha_vuln_scanner.scanner import api_request

    out, page, per_page = [], 1, 100
    while max_repos <= 0 or len(out) < max_repos:
        sep = "&" if "?" in base_url else "?"
        data, _, _ = api_request(f"{base_url}{sep}per_page={per_page}&page={page}")
        if not data or not isinstance(data, list):
            break
        for r in data:
            if r.get("fork") or r.get("archived"):
                continue
            if r.get("stargazers_count", 0) < min_stars:
                continue
            out.append(_repo_payload(r["full_name"], r.get("stargazers_count", 0), org_type))
        if len(data) < per_page:
            break
        page += 1
    return out if max_repos <= 0 else out[:max_repos]


def resolve_org(org: str, max_repos: int = 0, min_stars: int = 0) -> list[dict]:
    url = f"https://api.github.com/orgs/{org}/repos?type=public&sort=stars&direction=desc"
    return _paginate_repos(url, max_repos, min_stars, "Organization")


def resolve_user(user: str, max_repos: int = 0, min_stars: int = 0) -> list[dict]:
    url = f"https://api.github.com/users/{user}/repos?type=owner&sort=updated"
    return _paginate_repos(url, max_repos, min_stars, "User")


def resolve_repo(spec: str) -> list[dict]:
    """Resolve 'owner/name' or 'owner/name@<branch|tag|commit>' to one job payload."""
    from gha_vuln_scanner.scanner import get_repo_info

    repo_spec, _, ref = spec.partition("@")
    owner, _, repo_name = repo_spec.partition("/")
    if not repo_name:
        print(f"  ⚠  --repo expects 'owner/name[@ref]', got '{spec}'")
        return []
    info = get_repo_info(owner, repo_name) or {}
    if not info:
        # A pinned commit may not resolve via the repo metadata endpoint on forks;
        # still enqueue it — the worker clones directly.
        print(f"  ⚠  Could not fetch metadata for {repo_spec}; enqueuing anyway.")
    p = _repo_payload(repo_spec, info.get("stars", 0), info.get("org_type", ""))
    if ref:
        p["ref"] = ref
    return [p]


def resolve_query(query_ids: list[int], start_page: int = 1, end_page: int = 10,
                  auto_subdivide: bool = True, limit: int = 0) -> list[dict]:
    """Use code-search discovery, collapsing candidate files to unique repos."""
    from gha_vuln_scanner.scanner import discover

    candidates = discover(query_ids, start_page, end_page, auto_subdivide, limit=limit)
    seen, payloads = set(), []
    for c in candidates:
        repo = c["repo"]
        if repo in seen:
            continue
        seen.add(repo)
        p = _repo_payload(repo)
        p["query_id"] = c.get("query_id", -1)
        p["query_name"] = c.get("query_name", "")
        payloads.append(p)
    return payloads


# ── enqueue ──────────────────────────────────────────────────────────

def run_yolo(redis_url: str | None = None, max_repos: int = 0,
             queue_high_water: int = 5000, page_pause: float = 1.0) -> int:
    """💀 YOLO: walk *every* public repo on GitHub and enqueue it.

    Pages ``GET /repositories?since=<id>`` (the firehose of all repos by ascending id),
    resuming from a cursor persisted in the DB so restarts pick up where they left off.
    Runs until ``max_repos`` are enqueued (0 = forever). Throttles when the queue backs
    up past ``queue_high_water`` so workers are never buried and memory stays bounded.
    """
    from gha_vuln_scanner.scanner import api_request

    db.init_db()
    conn = jobs.redis_conn(redis_url)
    q = jobs.get_queue(conn=conn)
    since = db.get_state(_YOLO_CURSOR, "0")
    started = datetime.now().isoformat()
    total = 0
    cap = max_repos if max_repos else "∞"
    print(f"💀 YOLO: enumerating ALL of GitHub from id>{since} (max={cap})")

    while True:
        data, remaining, reset = api_request(
            f"https://api.github.com/repositories?since={since}")
        if data is None:  # rate limited past retries — back off and retry the page
            time.sleep(30)
            continue
        if not isinstance(data, list) or not data:
            print("  ✅ Reached the end of the repository list.")
            break

        for r in data:
            since = r["id"]
            if r.get("fork"):
                continue
            full = r["full_name"]
            p = _repo_payload(full, 0, "")
            p["known_files"] = db.known_hashes_for_repo(full)
            jobs.enqueue_repo(p, conn=conn)
            db.record_repo(full, p["owner"], 0, "", "yolo")
            total += 1
            if max_repos and total >= max_repos:
                break

        db.set_state(_YOLO_CURSOR, since)
        print(f"  📤 enqueued {total} repo(s) | cursor id={since} | api left={remaining}")
        if max_repos and total >= max_repos:
            break

        # Back-pressure: let workers drain before flooding more jobs.
        while q.count > queue_high_water:
            print(f"  ⏸  queue depth {q.count} > {queue_high_water}, waiting…")
            time.sleep(5)
        time.sleep(page_pause)

    db.record_run("all-github", "yolo", total, started)
    print(f"\n💀 YOLO enqueued {total} repo(s) total.")
    return total


def enqueue_repos(repos: list[dict], source: str, target: str,
                  redis_url: str | None = None) -> int:
    """Attach known_files from the DB and push one job per repo. Returns count."""
    db.init_db()
    conn = jobs.redis_conn(redis_url)
    started = datetime.now().isoformat()
    n = 0
    for p in repos:
        p["known_files"] = db.known_hashes_for_repo(p["repo"])
        jobs.enqueue_repo(p, conn=conn)
        db.record_repo(p["repo"], p["owner"], p.get("stars", 0),
                       p.get("org_type", ""), source)
        n += 1
        print(f"  ➕ enqueued {p['repo']} "
              f"({len(p['known_files'])} known blob(s) to skip)")
    db.record_run(target, source, n, started)
    print(f"\n📤 Enqueued {n} repo job(s) for {source}:{target}")
    return n
