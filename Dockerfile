FROM ghcr.io/astral-sh/uv:0.13.1 AS uv
FROM python:3.12-slim-bookworm
COPY --from=uv /uv /usr/local/bin/uv
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 bot && useradd --uid 10001 --gid bot --no-create-home bot \
    && mkdir -p /app/data && chown bot:bot /app/data
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project && rm -rf /root/.cache/uv
COPY main.py database.py utils.py steam_login.py login_flow.py update_processor.py healthcheck.py ./
COPY protobufs/steam_auth_pb2.py protobufs/__init__.py ./protobufs/
USER bot
CMD ["/app/.venv/bin/python", "main.py"]
