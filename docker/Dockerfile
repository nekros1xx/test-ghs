# ghascan runtime image — producer, workers, and UI all run from this one image.
# Python 3.12 (standard, non-free-threaded) so the git_sparse cp311-abi3 wheel loads.
FROM python:3.12-slim

# git + certs for git_sparse's remote fetches; node + the Claude Code CLI so the UI
# service can run the chat panel (`claude -p`). Build context is the repo root.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm i -g @anthropic-ai/claude-code \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Install the package (ui = rq+redis, pdf = reportlab for `report --pdf`) + the
# prebuilt git_sparse wheel. Drop a matching wheel into docker/wheels/ to avoid a Rust build.
RUN pip install --no-cache-dir -e '.[ui,pdf]' pyyaml \
 && pip install --no-cache-dir --no-index --find-links /app/docker/wheels git_sparse

ENV GHASCAN_DB=/data/ghascan.db \
    REDIS_URL=redis://redis:6379/0 \
    PYTHONUNBUFFERED=1

# Default command is overridden per-service in docker-compose.yml.
ENTRYPOINT ["ghascan"]
CMD ["--help"]
