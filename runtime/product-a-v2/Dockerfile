# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=docker.io/library/python@sha256:edaf703dce209d774af3ff768fc92b1e3b60261e7602126276f9ceb0e3a96874
FROM --platform=linux/amd64 ${PYTHON_IMAGE}

ARG DEBIAN_SNAPSHOT=20260824T000000Z
ARG PROFILE_TASK
ARG IMAGE_LOCK_SHA256
ARG CODEX_SHA256=54818cb9fce3360cc6e44cfc5a96952cd5c1243efb43cbe488e11dda84663e08
ARG CODEX_BINARY_SHA256=56ef98ab4032d317ab26e9b5e5a175650717351edb16ed9cde0cb6d1734d62da

RUN case "${PROFILE_TASK}:${IMAGE_LOCK_SHA256}" in \
      full-starlette-websocket-denial:24052fd1f6931e31f3853079b9b391c2bf104d2ed6ec06dac2fd252fea3e34cb|\
      confirm-starlette-session-tracking:c43532687a7bf69ec02b8008e7322209dd64c6d06778e26561097bdb3ef2dddf|\
      confirm-starlette-malformed-host:adf210e6cd3cacc2ea6696fa1669ac33e6354f8240da1aecf70ee581d0b87c41) ;; \
      *) echo 'unsupported Product A profile' >&2; exit 2 ;; \
    esac

RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends \
      ca-certificates=20230311 git=1:2.39.5-0+deb12u3 tinyproxy=1.11.1-2.1+deb12u1; \
    rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:54818cb9fce3360cc6e44cfc5a96952cd5c1243efb43cbe488e11dda84663e08 \
    https://registry.npmjs.org/@openai/codex/-/codex-0.153.4-linux-x64.tgz /tmp/codex.tgz
COPY --chmod=0555 runtime/product-a-v2/probe.py /usr/lib/mdseval/probe.py
COPY --chmod=0555 tooling/taskcheck.py /usr/lib/mdseval/taskcheck.py
COPY --chmod=0444 runtime/product-a-v2/LICENSE.codex /usr/share/licenses/codex/LICENSE
COPY --chmod=0444 runtime/product-a-v2/proxy.conf /etc/tinyproxy/mdseval.conf
COPY --chmod=0444 runtime/product-a-v2/model.filter /etc/tinyproxy/model.filter
COPY tasks/${PROFILE_TASK}/image-lock.json /task/image-lock.json
COPY tasks/${PROFILE_TASK}/image/wheels/ /task/image/wheels/

RUN set -eux; \
    echo "${CODEX_SHA256}  /tmp/codex.tgz" | sha256sum -c -; \
    mkdir -p /usr/lib/codex /sealed-deps; \
    tar -xzf /tmp/codex.tgz -C /usr/lib/codex --strip-components=3 \
      package/vendor/x86_64-unknown-linux-musl; \
    echo "${CODEX_BINARY_SHA256}  /usr/lib/codex/bin/codex" | sha256sum -c -; \
    python3 /usr/lib/mdseval/probe.py install /task/image-lock.json "${IMAGE_LOCK_SHA256}"; \
    chmod -R a=rX /usr/lib/codex /usr/lib/mdseval /usr/share/licenses /sealed-deps; \
    rm -rf /tmp/codex.tgz /task /usr/local

LABEL org.opencontainers.image.source="https://github.com/b0ggs/md-eval-starlette-demo" \
      org.opencontainers.image.version="product-a-v2"
