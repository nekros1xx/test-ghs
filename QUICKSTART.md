# ghascan — Quickstart (Docker, one command)

Run the whole scanner as a single classic-style command, with all the
producer / worker / Redis / DB plumbing hidden inside Docker.

## Requirements
- Docker + Docker Compose v2
- A GitHub Personal Access Token (one or more)

## Install (one-liner)
```bash
git clone https://github.com/nekros1xx/test-ghs.git && cd test-ghs && ./scripts/install.sh
```
This builds the image and installs a `ghascan` command into `~/.local/bin`.
> If `ghascan` isn't found afterwards, open a new shell or run
> `export PATH="$HOME/.local/bin:$PATH"`.

## Configure your token (no secrets are shipped)
The installer creates `.env` from `.env.example`. Edit it and add your token(s):
```bash
# .env
GITHUB_TOKEN=ghp_yourtoken            # comma-separate several for round-robin
CLAUDE_CODE_OAUTH_TOKEN=              # optional, only for the UI chat panel
```
`.env` is gitignored and never leaves your machine.

## Use it — one command
```bash
ghascan --org microsoft --pdf microsoft.pdf     # scan an org, write a PDF
ghascan --repo torvalds/linux --pdf linux.pdf   # a single repo
ghascan --query 1 --verdict CRITICAL HIGH       # discovery of vulnerable repos
ghascan --user someuser -o findings.json        # a user's repos, JSON out
ghascan --help
```
Under the hood each call: brings the stack up if needed, enqueues the target,
waits for the workers to finish, then writes the report. Output files land in
`./data/` inside the repo. Live dashboard: http://127.0.0.1:9191

## Shut down
```bash
docker compose down          # add -v to also clear the Redis queue
```
