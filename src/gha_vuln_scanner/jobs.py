"""
Redis/Valkey + RQ wiring for the producer/worker/collector split.

Two Redis structures are used:
- an **RQ queue** (``ghascan``) that carries per-repo jobs producer → worker
- a **results list** (``ghascan:results``) that carries analysis results
  worker → collector (LPUSH on the worker, BRPOP on the collector), so distributed
  workers never need database access.

Redis and rq are optional dependencies (``pip install '.[worker]'``); importing this
module without them raises a helpful error only when a connection is actually needed.
"""

import json
import os

QUEUE_NAME = "ghascan"
RESULTS_LIST = "ghascan:results"
_DEFAULT_URL = "redis://localhost:6379/0"


def _require_deps():
    try:
        import redis  # noqa: F401
        import rq  # noqa: F401
    except ImportError as e:  # pragma: no cover - env-dependent
        raise SystemExit(
            "The job queue needs redis + rq. Install with:\n"
            "    pip install 'gha-vuln-scanner[worker]'   # workers\n"
            "    pip install 'gha-vuln-scanner[queue]'    # producer/collector"
        ) from e


def redis_url(url: str | None = None) -> str:
    """Resolve the broker URL: explicit arg > REDIS_URL env > localhost default."""
    return url or os.environ.get("REDIS_URL") or _DEFAULT_URL


def redis_conn(url: str | None = None):
    """Open a Redis/Valkey connection (Valkey is wire-compatible with redis-py)."""
    _require_deps()
    import redis
    return redis.Redis.from_url(redis_url(url))


def get_queue(url: str | None = None, conn=None):
    """Return the RQ queue used for per-repo jobs."""
    _require_deps()
    import rq
    return rq.Queue(QUEUE_NAME, connection=conn or redis_conn(url))


def enqueue_repo(payload: dict, url: str | None = None, conn=None):
    """Push one repo job. The job runs ``worker.process_repo`` on a worker host."""
    q = get_queue(url, conn)
    return q.enqueue("gha_vuln_scanner.worker.process_repo", payload,
                     job_timeout=600, result_ttl=3600)


# ── results channel (worker → collector) ─────────────────────────────

def push_result(result: dict, url: str | None = None, conn=None) -> None:
    """Worker side: hand a result dict back to the collector."""
    c = conn or redis_conn(url)
    c.lpush(RESULTS_LIST, json.dumps(result))


def pop_result(timeout: int = 5, url: str | None = None, conn=None):
    """Collector side: block up to ``timeout`` s for the next result, or None.

    A client-side socket timeout on the blocking BRPOP is treated the same as an
    empty result (nothing arrived within the window)."""
    import redis  # imported lazily; _require_deps already ran to build the conn

    c = conn or redis_conn(url)
    try:
        item = c.brpop(RESULTS_LIST, timeout=timeout)
    except redis.exceptions.TimeoutError:
        return None
    if item is None:
        return None
    _key, raw = item
    return json.loads(raw)
