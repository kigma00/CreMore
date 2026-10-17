# The Python (Apache-2.0) platform image. One image serves both entrypoints —
# `cremore-api` and `cremore-worker` — selected by the compose service's command.
#
# Build in the -dev image (pip, compilers), run on the minimal image: no shell,
# no package manager and no OS utilities, so the runtime carries only Python and
# the platform's own dependencies. Both images are pinned by digest and move
# together; they ship the same interpreter at /usr/bin/python3.14.
FROM cgr.dev/chainguard/python:latest-dev@sha256:96cb9c155159daf6b21e70555f244081909ff161c5589112ddf308624c1a1c77 AS build

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY pyproject.toml README.md requirements.txt requirements-build.txt ./
COPY cremore ./cremore
COPY aws/backend ./aws/backend
COPY github/backend ./github/backend
COPY notion/backend ./notion/backend
COPY slack/backend ./slack/backend
COPY packages/cremore-siem-slack ./packages/cremore-siem-slack
# Every package comes from a hash-pinned lock file, the build backend included,
# so a rebuild installs the exact artifacts that were audited. The wheel is
# built in a throwaway venv; the runtime venv gets only the locked dependencies
# and the cremore wheel itself.
RUN python -m venv /tmp/build \
    && /tmp/build/bin/pip install --require-hashes -r requirements-build.txt \
    && /tmp/build/bin/pip wheel --no-deps --no-build-isolation -w /tmp/dist . \
    && /tmp/build/bin/pip wheel --no-deps --no-build-isolation -w /tmp/dist ./packages/cremore-siem-slack \
    && python -m venv /app/venv \
    && /app/venv/bin/pip install --require-hashes --only-binary :all: -r requirements.txt \
    && /app/venv/bin/pip install --no-deps /tmp/dist/*.whl \
    # Fails when pyproject.toml gained a dependency the lock file lacks.
    && /app/venv/bin/pip check \
    # The installer is not needed at run time; leaving it would ship its
    # vendored libraries in the final image.
    && /app/venv/bin/pip uninstall -y pip setuptools wheel

FROM cgr.dev/chainguard/python:latest@sha256:1961420e5f93bd056d4b0b40eca12cdf01b3ed09177aa4d6ec71fab38cbf158f

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/venv/bin:/usr/bin:/bin"

WORKDIR /app
COPY --from=build /app/venv /app/venv
# Served by the dashboard so member scanner roles deploy with the CLI, no S3 hosting.
COPY deploy/cloudformation/member-account-role.yaml /app/cloudformation/member-account-role.yaml

# The base image already runs as the unprivileged uid/gid 65532.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT []
# Default to the API; the worker service overrides `command`.
CMD ["cremore-api"]
