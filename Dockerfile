# opnsense-guard-mcp. Default transport is stdio:
#   docker run -i --rm --env-file .env -v guard-data:/data opnsense-guard-mcp
# HTTP mode: see README ("Running in Docker").
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin guard \
    && mkdir -p /data && chown guard /data
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
ENV OPNSENSE_GUARD_DATA_DIR=/data \
    PYTHONUNBUFFERED=1
USER guard
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["opnsense-guard-mcp"]
