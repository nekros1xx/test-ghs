# 🔒 GHA Vulnerability Scanner

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Detect expression injection, GITHUB_ENV injection, and AI prompt injection vulnerabilities in GitHub Actions workflows.**

By [Sergio Cabrera](https://www.linkedin.com/in/sergio-cabrera-878766239/)

---

## 🏗️ Architecture

ghascan runs as a **distributed producer / worker / collector** pipeline backed by a
**Redis (or Valkey) job queue** and a central **SQLite** database:

- **`ghascan enqueue`** (producer, central node) — resolves a target (org / user / single
  repo / search query) into a list of repos and pushes one job per repo onto the queue.
  For each repo it attaches the blob hashes it already knows about (`known_files`).
- **`ghascan worker`** (any number of hosts) — a *dumb* consumer: pulls a job, uses
  [`git_sparse`](https://github.com/lsproule/check_me_out) to read only the workflow blobs
  it doesn't already know **straight into memory** (nothing hits disk), analyzes them, and
  hands the results back. Workers never touch the database.
- **`ghascan collect`** (central node) — drains worker results into SQLite: records blob
  hashes (so unchanged workflows are skipped next time) and stores findings.

Because unchanged blobs are skipped at download time, **re-scanning an org only downloads
and analyzes the workflow files that changed** since the last run.

## ⚡ Install

```bash
# Producer + collector node (holds the SQLite DB, talks to Redis):
pip install 'gha-vuln-scanner[queue] @ git+https://github.com/nekros1xx/ghascan.git'

# Worker node (adds git_sparse, installed from git — it is not on PyPI):
pip install 'gha-vuln-scanner[worker] @ git+https://github.com/nekros1xx/ghascan.git'
```

> `git_sparse` (from [check_me_out](https://github.com/lsproule/check_me_out)) is a Rust
> extension. Installing the `worker` extra from git builds it from source (needs a Rust
> toolchain). To skip the build, install a **prebuilt wheel** first, then the queue extra:
>
> ```bash
> pip install git_sparse --find-links /path/to/check_me_out/dist --no-index
> pip install 'gha-vuln-scanner[queue] @ git+https://github.com/nekros1xx/ghascan.git'
> ```
>
> The wheels are `cp311-abi3` (CPython 3.11+, standard builds) — not compatible with
> free-threaded (`t`) interpreters.

Provide a token (env or `--token`, both accept a comma-separated list for higher rate
limits) and point at your broker:

```bash
export GITHUB_TOKEN="ghp_your_token_here"        # or:  ghascan ... --token ghp_...
export REDIS_URL="redis://your-redis-host:6379/0" # or:  ghascan ... --redis redis://...
```

---

## 🎯 What It Detects

| Category | Examples | Severity |
|----------|---------|----------|
| **Expression injection** | `${{ github.event.issue.title }}` in `run:` blocks | CRITICAL/HIGH |
| **GITHUB_ENV injection** | Attacker input written to `$GITHUB_ENV` | MEDIUM/HIGH |
| **Indirect injection** | Tainted step outputs used in `run:` blocks | MEDIUM |
| **AI prompt injection** | Attacker input → AI action → output in `run:` block | AI_INJECTION |
| **Unpinned actions** | Third-party actions referenced by tag instead of SHA | Info |

### False Positive Elimination

7+ elimination rules minimize noise: commented code, disabled jobs/steps, trigger unreachability, safe contexts (`env:`, `with:`), exact-match gates, boolean expressions, quoted heredocs, per-job secrets scoping.

---

## 📖 Usage

Start one or more workers and a collector, then enqueue targets from the producer.

### 1. Start workers (one or many hosts)

```bash
ghascan worker                    # long-running; add --burst to drain then exit
```

### 2. Start the collector (central / DB node)

```bash
ghascan collect                   # long-running; --once drains the current backlog
```

### 3. Enqueue targets (producer)

```bash
ghascan enqueue --org google --min-stars 100     # every repo in an org
ghascan enqueue --user torvalds                  # every repo a user owns
ghascan enqueue --repo owner/name                # a single repo
ghascan enqueue --query 6                         # repos found by query 6
ghascan enqueue --all --min-stars 1000            # repos found by all 43 patterns
ghascan enqueue --custom '"my_pattern" path:.github/workflows'
```

Re-run any `enqueue` to incrementally re-scan — unchanged workflows are skipped
automatically.

### 💀 YOLO — scan all of GitHub

```bash
ghascan enqueue --yolo                       # enumerate EVERY public repo (forever)
ghascan enqueue --yolo --max-repos 50000     # ...or stop after N
```

YOLO walks GitHub's `/repositories` firehose by ascending id, resuming from a cursor
persisted in the DB, and throttles itself when the queue backs up (`--queue-high-water`).

### Docker Compose (1 producer + 3 workers + redis + live UI)

The bundled stack runs YOLO with a shared SQLite database mounted into every container
and a live dashboard:

```bash
cat > .env <<'EOF'
GITHUB_TOKEN=ghp_your_token          # enumeration + clone auth (required for throughput)
ANTHROPIC_API_KEY=sk-ant-your_key    # enables the "chat with Claude" panel (optional)
EOF
# place a git_sparse wheel in docker/wheels/ (see Install note above)
docker compose up --build
```

Then open **http://localhost:8080** and watch findings land in real time. Workers write
straight into the shared `./data/ghascan.db` (`--sink db`); scale them with
`docker compose up --scale worker=6`. Click any finding to open a detail drawer with the
exact vulnerable expressions, injections, and unpinned actions — and chat with Claude about
that repo + workflow file (context: the stored workflow content and constructed GitHub URL).

### Live UI (standalone)

```bash
ghascan ui --port 8080      # serves the dashboard against your SQLite DB
```

### Report from the database

```bash
ghascan report --scanned                          # list scanned repos + finding counts
ghascan report --org google --html report.html    # findings for an org → HTML/PDF/JSON
ghascan report --repo owner/name -o results.json -v
```

### Offline analysis (no network / queue)

```bash
ghascan offline scan_data.json -v --verdict CRITICAL HIGH
```

### Flush stored state

```bash
ghascan flush                     # wipe everything (forces a full re-scan next time)
ghascan flush --org google        # only forget this org/owner (or owner/name repo)
```

Report output formats: `-o results.json` (JSON, with a Markdown sibling), `--html
report.html`, `--pdf report.pdf`.

---

## 🔍 43 Query Patterns

<details>
<summary>Click to expand</summary>

| # | Pattern | Target |
|---|---------|--------|
| 1-3 | PR title/body/head_ref in `run:` | `pull_request_target` |
| 4 | Comment body in `run:` | `issue_comment` |
| 5-6 | Issue title/body in `run:` | `issues` |
| 7-8 | Discussion title/body in `run:` | `discussion` |
| 9-10 | Review body/comment in `run:` | `pull_request_review` |
| 11-16 | `toJSON()` on parent objects | Various |
| 17-22 | `contains()`/`startsWith()` wrapping | Various |
| 23-24 | `format()` with attacker input | Various |
| 25-29 | Less common fields (labels, repo desc) | Various |
| 30 | `toJSON(steps)` in `run:` | Various |
| 31-35 | `github-script` + attacker input | Various |
| 36-38 | `GITHUB_ENV` injection | Various |
| 39-41 | Indirect injection via step outputs | Various |
| 42-43 | `workflow_dispatch` inputs | `workflow_dispatch` |

</details>

---

## 🏗️ Severity Levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Full control + open trigger + custom secrets + no auth |
| **HIGH** | Full control + open trigger + GITHUB_TOKEN only |
| **MEDIUM** | Auth check present, restricted trigger, or dispatch-only |
| **LOW** | Limited control (head_ref), internal triggers, or read-only perms |
| **AI_INJECTION** | AI action output (tainted) used in executable context |
| **FALSE_POSITIVE** | All expressions eliminated by analysis rules |

---

## 🛡️ Responsible Disclosure

This tool is for **defensive security research**. If you find vulnerabilities, report them responsibly via the repo's Security tab. Do not exploit them.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Sergio Cabrera** — [LinkedIn](https://www.linkedin.com/in/sergio-cabrera-878766239/) · [GitHub](https://github.com/nekros1xx)
