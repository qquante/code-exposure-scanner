FROM ghcr.io/trufflesecurity/trufflehog:3.96.0@sha256:aa821cf4ace8861c7d096d83818cdf7bb9719028a52d37a52eaad44086a52577 AS trufflehog

FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY pyproject.toml README.md ./
COPY secret_hunter ./secret_hunter
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog

RUN python -m pip install '.[postgres,service,crypto]' \
    && trufflehog --version

USER 10001:10001

FROM base AS test
USER root
COPY tests ./tests
COPY benchmarks ./benchmarks
COPY scripts ./scripts
RUN python -m pip install '.[dev,crypto]'
USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "pytest", "-q"]

FROM base AS production
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "secret_hunter.api:app", "--host", "0.0.0.0", "--port", "8000"]
