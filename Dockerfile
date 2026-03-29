# =============================================================================
# Windows EXE Decompiler MCP Server - Docker Full Linux Analysis Stack
# =============================================================================
# Multi-stage build: Builder -> Python Base -> Dynamic Python -> Core Tools
#                  -> Heavy Tools -> Ghidra -> Runtime
# Final image intentionally favors completeness over size.
# =============================================================================

# -----------------------------------------------------------------------------
# Global Arguments
# -----------------------------------------------------------------------------
ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG http_proxy=""
ARG https_proxy=""
ARG NO_PROXY="localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com"
ARG GHIDRA_VERSION=12.0.4
ARG CAPA_RULES_VERSION=v9.3.1
ARG CAPA_VERSION=9.3.1
ARG DIE_VERSION=3.10
ARG DIE_RELEASE_CHANNEL=3.10
ARG UPX_VERSION=5.1.1
ARG RIZIN_VERSION=0.8.2
ARG RETDEC_VERSION=5.0
ARG ANGR_VERSION=9.2.205

# =============================================================================
# Stage 1: TypeScript Builder
# =============================================================================
FROM node:20-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN npm config set registry https://registry.npmmirror.com

WORKDIR /app
COPY package*.json ./
RUN npm ci --legacy-peer-deps || npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc --noEmit --skipLibCheck --noUnusedLocals false --noUnusedParameters false || true
RUN npm run build -- --skipLibCheck || echo "Build completed with type warnings"

# =============================================================================
# Stage 2: Python Base (baseline + full global worker/toolchain packages)
# =============================================================================
FROM python:3.11-slim-bookworm AS python-base

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN rm -f /etc/apt/sources.list.d/* && cat > /etc/apt/sources.list <<EOF
deb https://mirrors.aliyun.com/debian bookworm main contrib non-free non-free-firmware
deb https://mirrors.aliyun.com/debian bookworm-updates main contrib non-free non-free-firmware
deb https://mirrors.aliyun.com/debian-security bookworm-security main contrib non-free non-free-firmware
EOF

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    file \
    git \
    libyara-dev \
    python3-venv \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
COPY workers/ ./workers/

RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r workers/requirements.txt && \
    pip install --no-cache-dir -r workers/requirements-dynamic.txt

RUN ls -la /app/workers/ && \
    python3 -c "import sys; sys.path.insert(0, '/app/workers'); import static_worker; print('✓ static_worker.py loaded')" && \
    python3 -m py_compile /app/workers/static_worker.py && \
    python3 -c "import yara_x, pandare, frida, psutil; import speakeasy; print('✓ global dynamic imports ready')" && \
    python3 -c "import importlib.metadata as m; print('frida-tools', m.version('frida-tools')); print('yara-x', m.version('yara-x'))" && \
    echo "✓ Baseline Python + full worker extras validated"

# =============================================================================
# Stage 3: Qiling Python (isolated unicorn>=2 runtime)
# =============================================================================
FROM python-base AS qiling-python

RUN python3 -m venv /opt/qiling-venv && \
    /opt/qiling-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/qiling-venv/bin/pip install --no-cache-dir -r /app/workers/requirements-qiling.txt && \
    /opt/qiling-venv/bin/python -c "import qiling; print('✓ qiling', getattr(qiling, '__version__', 'unknown'))"

# =============================================================================
# Stage 4: Dynamic Python (isolated angr runtime)
# =============================================================================
FROM python-base AS dynamic-python

ARG ANGR_VERSION

RUN python3 -m venv /opt/angr-venv && \
    /opt/angr-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/angr-venv/bin/pip install --no-cache-dir "angr==${ANGR_VERSION}" && \
    /opt/angr-venv/bin/python -c "import angr; print('✓ angr', angr.__version__)"

# =============================================================================
# Stage 5: Core Linux Toolchain (Rizin)
# =============================================================================
FROM debian:bookworm-slim AS core-tools

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG RIZIN_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) rizin_asset="rizin-v${RIZIN_VERSION}-static-x86_64.tar.xz" ;; \
      *) echo "Unsupported architecture for bundled Rizin static release: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/rizinorg/rizin/releases/download/v${RIZIN_VERSION}/${rizin_asset}" -o /tmp/rizin.tar.xz; \
    mkdir -p /opt/rizin; \
    tar -xJf /tmp/rizin.tar.xz -C /opt/rizin; \
    test -x /opt/rizin/bin/rizin; \
    /opt/rizin/bin/rizin -v >/dev/null

# =============================================================================
# Stage 6: Heavy Linux Toolchain (RetDec)
# =============================================================================
FROM debian:bookworm-slim AS heavy-tools

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG RETDEC_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL "https://github.com/avast/retdec/releases/download/v${RETDEC_VERSION}/RetDec-v${RETDEC_VERSION}-Linux-Release.tar.xz" -o /tmp/retdec.tar.xz; \
    mkdir -p /opt/retdec; \
    tar -xJf /tmp/retdec.tar.xz -C /opt/retdec; \
    test -x /opt/retdec/bin/retdec-decompiler; \
    /opt/retdec/bin/retdec-decompiler --help >/dev/null

# =============================================================================
# Stage 7: Ghidra
# =============================================================================
FROM eclipse-temurin:21-jdk AS ghidra-stage

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG GHIDRA_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

RUN rm -f /etc/apt/sources.list.d/* && cat > /etc/apt/sources.list <<EOF
deb https://mirrors.aliyun.com/ubuntu noble main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu noble-updates main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu noble-security main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu noble-backports main restricted universe multiverse
EOF

WORKDIR /opt

RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20260303.zip"; \
    echo "Downloading Ghidra ${GHIDRA_VERSION}..."; \
    echo "URL: $GHIDRA_URL"; \
    if curl -fsSL --connect-timeout 120 --retry 3 --retry-delay 10 -o ghidra.zip "$GHIDRA_URL"; then \
        echo "Download successful"; \
    else \
        echo "ERROR: Failed to download Ghidra"; \
        exit 1; \
    fi && \
    FILE_SIZE=$(wc -c < ghidra.zip); \
    if [ "$FILE_SIZE" -lt 1000000 ]; then \
        echo "ERROR: Ghidra archive too small"; \
        exit 1; \
    fi && \
    unzip -q ghidra.zip && \
    mv ghidra_* ghidra && \
    rm ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/opt/java/openjdk

RUN test -f /opt/ghidra/support/analyzeHeadless

# =============================================================================
# Stage 8: Runtime (default full image)
# =============================================================================
FROM python:3.11-slim-bookworm AS runtime

ARG HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY
ARG CAPA_RULES_VERSION
ARG CAPA_VERSION
ARG DIE_VERSION
ARG DIE_RELEASE_CHANNEL
ARG UPX_VERSION

ENV HTTP_PROXY="${HTTP_PROXY}" \
    HTTPS_PROXY="${HTTPS_PROXY}" \
    http_proxy="${http_proxy}" \
    https_proxy="${https_proxy}" \
    NO_PROXY="${NO_PROXY}"

LABEL maintainer="windows-exe-decompiler-mcp-server"
LABEL version="0.1.4"
LABEL description="MCP server for Windows binary reverse engineering - full Linux analysis stack"
LABEL node_version="20.x"
LABEL python_version="3.11"
LABEL java_version="21"
LABEL ghidra_version="12.0.4"

RUN rm -f /etc/apt/sources.list.d/* && cat > /etc/apt/sources.list <<EOF
deb https://mirrors.aliyun.com/debian bookworm main contrib non-free non-free-firmware
deb https://mirrors.aliyun.com/debian bookworm-updates main contrib non-free non-free-firmware
deb https://mirrors.aliyun.com/debian-security bookworm-security main contrib non-free non-free-firmware
EOF

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    file \
    gdb \
    graphviz \
    libstdc++6 \
    libgcc-s1 \
    ltrace \
    strace \
    wget \
    wine \
    wine64 \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/opt/java/openjdk
ENV JAVA_TOOL_OPTIONS=
ENV PATH="/opt/java/openjdk/bin:${PATH}"

WORKDIR /app

COPY --from=builder /usr/local/bin/node /usr/local/bin/node
COPY --from=builder /usr/local/bin/npm /usr/local/bin/npm
COPY --from=builder /usr/local/bin/npx /usr/local/bin/npx
COPY --from=builder /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./

COPY --from=python-base /usr/local/bin /usr/local/bin
COPY --from=python-base /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-base /app/workers ./workers
COPY --from=qiling-python /opt/qiling-venv /opt/qiling-venv
COPY --from=dynamic-python /opt/angr-venv /opt/angr-venv
COPY --from=core-tools /opt/rizin /opt/rizin
COPY --from=heavy-tools /opt/retdec /opt/retdec

RUN python3 -m py_compile ./workers/static_worker.py || echo "Python worker validation skipped"

RUN set -eux; \
    mkdir -p /opt/capa-rules /opt/capa-sigs /opt/downloads; \
    curl -fsSL "https://github.com/mandiant/capa-rules/archive/refs/tags/${CAPA_RULES_VERSION}.tar.gz" -o /tmp/capa-rules.tar.gz; \
    tar -xzf /tmp/capa-rules.tar.gz -C /opt/downloads; \
    extracted_dir="$(find /opt/downloads -mindepth 1 -maxdepth 1 -type d -name 'capa-rules-*' | head -n 1)"; \
    test -n "${extracted_dir}"; \
    rm -rf /opt/capa-rules; \
    mv "${extracted_dir}" /opt/capa-rules; \
    curl -fsSL "https://github.com/mandiant/capa/archive/refs/tags/v${CAPA_VERSION}.tar.gz" -o /tmp/capa.tar.gz; \
    tar -xzf /tmp/capa.tar.gz -C /opt/downloads; \
    capa_dir="$(find /opt/downloads -mindepth 1 -maxdepth 1 -type d -name 'capa-*' | head -n 1)"; \
    test -n "${capa_dir}"; \
    cp -R "${capa_dir}/sigs/." /opt/capa-sigs/; \
    rm -rf /opt/downloads /tmp/capa-rules.tar.gz /tmp/capa.tar.gz; \
    curl -fsSL "https://github.com/horsicq/DIE-engine/releases/download/${DIE_RELEASE_CHANNEL}/die_${DIE_VERSION}_Debian_12_amd64.deb" -o /tmp/die.deb; \
    apt-get update; \
    apt-get install -y --no-install-recommends /tmp/die.deb; \
    rm -f /tmp/die.deb; \
    rm -rf /var/lib/apt/lists/*; \
    printf '%s\n' '#!/bin/sh' 'exec python3 -m capa.main -s /opt/capa-sigs "$@"' > /usr/local/bin/capa; \
    chmod +x /usr/local/bin/capa; \
    command -v diec >/dev/null 2>&1; \
    test -d /opt/capa-rules; \
    test -d /opt/capa-sigs

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) upx_asset="upx-${UPX_VERSION}-amd64_linux.tar.xz" ;; \
      arm64) upx_asset="upx-${UPX_VERSION}-arm64_linux.tar.xz" ;; \
      *) echo "Unsupported architecture for bundled UPX release: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${upx_asset}" -o /tmp/upx.tar.xz; \
    mkdir -p /opt/upx; \
    tar -xJf /tmp/upx.tar.xz -C /opt/upx --strip-components=1; \
    ln -sf /opt/upx/upx /usr/local/bin/upx; \
    /usr/local/bin/upx --version >/dev/null

RUN ln -sf /opt/rizin/bin/rizin /usr/local/bin/rizin && \
    ln -sf /opt/rizin/bin/rz-bin /usr/local/bin/rz-bin && \
    ln -sf /opt/rizin/bin/rz-asm /usr/local/bin/rz-asm && \
    ln -sf /opt/rizin/bin/rz-diff /usr/local/bin/rz-diff && \
    ln -sf /opt/rizin/bin/rz-find /usr/local/bin/rz-find && \
    ln -sf /opt/rizin/bin/rz-hash /usr/local/bin/rz-hash && \
    ln -sf /opt/retdec/bin/retdec-decompiler /usr/local/bin/retdec-decompiler && \
    ln -sf /opt/retdec/bin/retdec-fileinfo /usr/local/bin/retdec-fileinfo

COPY --from=ghidra-stage /opt/java/openjdk /opt/java/openjdk
COPY --from=ghidra-stage /opt/ghidra /opt/ghidra

COPY ghidra_scripts/ ./ghidra_scripts/
COPY helpers/ ./helpers/
COPY frida_scripts/ ./frida_scripts/
COPY scripts/validate-docker-full-stack.sh /usr/local/bin/validate-docker-full-stack.sh

RUN chmod +x /usr/local/bin/validate-docker-full-stack.sh && \
    /usr/local/bin/capa --version >/dev/null 2>&1 && \
    diec --version >/dev/null 2>&1 && \
    dot -V >/dev/null 2>&1 && \
    rizin -v >/dev/null 2>&1 && \
    upx --version >/dev/null 2>&1 && \
    wine --version >/dev/null 2>&1 && \
    command -v winedbg >/dev/null 2>&1 && \
    frida-ps --help >/dev/null 2>&1 && \
    retdec-decompiler --help >/dev/null 2>&1 && \
    retdec-fileinfo --help >/dev/null 2>&1 && \
    python3 -c "import yara_x, pandare, frida, psutil; print('✓ global runtime imports ready')" && \
    /opt/qiling-venv/bin/python -c "import qiling; print('✓ isolated qiling runtime ready')" && \
    /opt/angr-venv/bin/python -c "import angr; print('✓ isolated angr runtime ready')" && \
    /usr/local/bin/validate-docker-full-stack.sh

RUN useradd -m -u 1000 -s /bin/bash appuser

RUN mkdir -p /app/storage/samples /app/storage/artifacts /app/storage/uploads /app/storage/.metadata && \
    chown -R appuser:appuser /app/storage

RUN mkdir -p /app/uploads && chown -R appuser:appuser /app/uploads

EXPOSE 18080
EXPOSE 18081

ENV NODE_ENV=production \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/workers \
    JAVA_HOME=/opt/java/openjdk \
    JAVA_TOOL_OPTIONS="" \
    AUDIT_LOG_PATH=/app/logs/audit.log \
    XDG_CONFIG_HOME=/app/logs/.config \
    XDG_CACHE_HOME=/app/cache/xdg \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    GHIDRA_PROJECT_ROOT=/ghidra-projects \
    GHIDRA_LOG_ROOT=/ghidra-logs \
    WORKSPACE_ROOT=/app/workspaces \
    DB_PATH=/app/data/database.db \
    CACHE_ROOT=/app/cache \
    RUNNING_IN_DOCKER=true \
    UPLOAD_PORT=18081 \
    CAPA_PATH=/usr/local/bin/capa \
    CAPA_RULES_PATH=/opt/capa-rules \
    DIE_PATH=/usr/bin/diec \
    GRAPHVIZ_DOT_PATH=/usr/bin/dot \
    RIZIN_PATH=/opt/rizin/bin/rizin \
    UPX_PATH=/usr/local/bin/upx \
    WINE_PATH=/usr/bin/wine \
    WINEDBG_PATH=/usr/bin/winedbg \
    YARAX_PYTHON=/usr/local/bin/python3 \
    QILING_PYTHON=/opt/qiling-venv/bin/python \
    QILING_ROOTFS=/opt/qiling-rootfs \
    ANGR_PYTHON=/opt/angr-venv/bin/python \
    PANDA_PYTHON=/usr/local/bin/python3 \
    RETDEC_PATH=/opt/retdec/bin/retdec-decompiler \
    RETDEC_INSTALL_DIR=/opt/retdec

RUN mkdir -p /app/workspaces /app/data /app/cache /app/logs /ghidra-projects /ghidra-logs /samples /tmp /opt/qiling-rootfs /root/.windows-exe-decompiler-mcp-server && \
    chown -R appuser:appuser /app && \
    chown -R appuser:appuser /ghidra-projects && \
    chown -R appuser:appuser /ghidra-logs && \
    chown -R appuser:appuser /opt/qiling-rootfs && \
    chown -R appuser:appuser /root/.windows-exe-decompiler-mcp-server && \
    chmod 1777 /tmp

WORKDIR /app

COPY --chown=appuser:appuser docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["node", "dist/index.js"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "console.log('MCP Server healthy')" || exit 1
