# Arnacon SIPhon edge image.
#
# Uses standard CPython 3.14 (GIL). pyo3 in siphon-edge links this interpreter.
# Media is siphon.peer. aiortc is not installed.
#
# Build context = this repo root. The binary is siphon-edge in this repo.
# It links siphon-project/siphon-sip main (cargo git) and registers siphon.peer.
#
#   cd docker && DEPLOY_ENV=development docker compose build

# ── Builder ──────────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        xz-utils \
        git \
        ffmpeg \
        libavformat-dev \
        libavcodec-dev \
        libavdevice-dev \
        libavutil-dev \
        libswscale-dev \
        libswresample-dev \
        libavfilter-dev \
        libsrtp2-dev \
        libopus-dev \
    && rm -rf /var/lib/apt/lists/*

ENV UV_INSTALL_DIR=/usr/local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV UV_PYTHON_INSTALL_DIR=/opt/python
# Standard GIL CPython — pyo3 links this interpreter.
RUN uv python install 3.14 && \
    ln -sfn "$(uv python find 3.14)" /usr/local/bin/python3.14 && \
    ln -sfn /usr/local/bin/python3.14 /usr/local/bin/python3 && \
    ln -sfn /usr/local/bin/python3.14 /usr/local/bin/python
ENV PYO3_PYTHON=/usr/local/bin/python3.14

RUN uv pip install --system --python /usr/local/bin/python3.14 \
        --break-system-packages \
        httpx[http2] \
        redis \
        requests \
        prometheus_client \
        eth-account \
        eth-abi \
        eth-utils \
        eth-hash[pycryptodome] \
        cryptography

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# No Cargo.lock in siphon-edge, so this resolves siphon-sip branch main.
# Default 1 job so an 8G box does not OOM. On the Mac:
#   CARGO_BUILD_JOBS=8 docker compose build siphon
ARG CARGO_BUILD_JOBS=1
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
ENV CARGO_INCREMENTAL=0
COPY siphon-edge /src/siphon-edge
WORKDIR /src/siphon-edge
RUN cargo build --release --jobs ${CARGO_BUILD_JOBS}

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        iproute2 \
        ffmpeg \
        libsrtp2-1 \
        libopus0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/python /opt/python
RUN PY_BIN=$(find /opt/python -type f \( -name 'python3.14' -o -name 'python3.14*' \) -perm -u+x \
        | grep -v freethreaded | grep -v 't-linux' | head -n1) && \
    test -n "$PY_BIN" && \
    PY_PREFIX=$(dirname $(dirname "$PY_BIN")) && \
    ln -sfn "$PY_BIN" /usr/local/bin/python3.14 && \
    ln -sfn "$PY_BIN" /usr/local/bin/python3 && \
    ln -sfn "$PY_BIN" /usr/local/bin/python && \
    echo "$PY_PREFIX/lib" > /etc/ld.so.conf.d/python3.14.conf && \
    ldconfig && \
    python3 -c "import sys; print(sys.version)"

COPY --from=builder /src/siphon-edge/target/release/siphon /usr/local/bin/siphon

# Context = repo root (sibling of docker/): sip_code/ + docker/
COPY sip_code/siphon.yaml /etc/siphon/siphon.yaml
COPY sip_code/http.yaml /etc/siphon/http.yaml
COPY sip_code/siphon_app.py /etc/siphon/scripts/siphon_app.py
COPY sip_code/policy.py /etc/siphon/scripts/policy.py
COPY sip_code/client_ingress.py /etc/siphon/scripts/client_ingress.py
COPY sip_code/extension_hunt.py /etc/siphon/scripts/extension_hunt.py
COPY sip_code/webrtc_pc.py /etc/siphon/scripts/webrtc_pc.py
COPY sip_code/identity.py /etc/siphon/scripts/identity.py
COPY sip_code/logic_client.py /etc/siphon/scripts/logic_client.py
COPY sip_code/notify_push.py /etc/siphon/scripts/notify_push.py
COPY sip_code/media_worker.py /etc/siphon/scripts/media_worker.py
COPY sip_code/webrtc_pc_worker.py /etc/siphon/scripts/webrtc_pc_worker.py
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p /run/siphon /etc/siphon/scripts

# GIL CPython — do NOT set PYTHON_GIL=0 (that was for freethreaded 3.14t).
ENV PYTHONFAULTHANDLER=1
ENV SIPHON_SCRIPT_PATH=/etc/siphon/scripts/siphon_app.py

EXPOSE 5060/tcp
EXPOSE 5061/tcp
EXPOSE 8443/tcp
EXPOSE 9001/tcp

WORKDIR /etc/siphon

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["siphon", "-c", "/run/siphon/siphon.yaml"]
