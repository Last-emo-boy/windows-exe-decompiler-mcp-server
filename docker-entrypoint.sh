#!/bin/bash
# =============================================================================
# Docker Entrypoint Script for Rikune
# =============================================================================
# This script handles container initialization:
# 1. Validate required environment variables
# 2. Create necessary directories
# 3. Set permissions
# 4. Start MCP Server
# =============================================================================

set -e

# Disable colors for MCP stdio compatibility
RED=''
GREEN=''
YELLOW=''
NC=''

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if an environment variable is set
check_env() {
    local var_name=$1
    local var_value="${!var_name}"
    
    if [ -z "$var_value" ]; then
        log_error "Environment variable $var_name is not set"
        exit 1
    fi
    
    log_info "$var_name=$var_value"
}

check_optional_command() {
    local label=$1
    local command_name=$2
    local version_args=${3:---version}

    if command -v "$command_name" >/dev/null 2>&1; then
        local version_output
        version_output=$("$command_name" $version_args 2>&1 | head -n 1 || true)
        if [ -n "$version_output" ]; then
            log_info "$label available: $version_output"
        else
            log_info "$label available at $(command -v "$command_name")"
        fi
    else
        log_warn "$label is not available on PATH"
    fi
}

# Check if a directory exists, create if not
ensure_dir() {
    local dir_path=$1
    local owner=${2:-appuser}
    
    if [ ! -d "$dir_path" ]; then
        log_info "Creating directory: $dir_path"
        mkdir -p "$dir_path"
        chown "$owner" "$dir_path"
    fi
}

# =============================================================================
# Step 1: Validate Environment Variables
# =============================================================================

log_info "=== Validating Environment Variables ==="

check_env GHIDRA_INSTALL_DIR
check_env JAVA_HOME
check_env WORKSPACE_ROOT
check_env DB_PATH
check_env CACHE_ROOT

# Optional variables (log if set)
if [ -n "$GHIDRA_PROJECT_ROOT" ]; then
    log_info "GHIDRA_PROJECT_ROOT=$GHIDRA_PROJECT_ROOT"
fi

if [ -n "$GHIDRA_LOG_ROOT" ]; then
    log_info "GHIDRA_LOG_ROOT=$GHIDRA_LOG_ROOT"
fi

# =============================================================================
# Step 2: Verify Tool Availability
# =============================================================================

log_info "=== Verifying Tool Availability ==="

# Check Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    log_info "Node.js available: $NODE_VERSION"
else
    log_error "Node.js is not installed"
    exit 1
fi

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    log_info "Python available: $PYTHON_VERSION"
else
    log_error "Python 3 is not installed"
    exit 1
fi

# Check Java
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1)
    log_info "Java available: $JAVA_VERSION"
else
    log_error "Java is not installed"
    exit 1
fi

# Check Ghidra analyzeHeadless
if [ -f "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then
    log_info "Ghidra analyzeHeadless found at: $GHIDRA_INSTALL_DIR/support/analyzeHeadless"
else
    log_error "Ghidra analyzeHeadless not found at: $GHIDRA_INSTALL_DIR/support/analyzeHeadless"
    exit 1
fi

check_optional_command "Graphviz dot" "${GRAPHVIZ_DOT_PATH:-dot}" "-V"
check_optional_command "Rizin" "${RIZIN_PATH:-rizin}" "-v"
check_optional_command "UPX" "${UPX_PATH:-upx}" "--version"
check_optional_command "Wine" "${WINE_PATH:-wine}" "--version"
check_optional_command "RetDec" "${RETDEC_PATH:-retdec-decompiler}" "--help"

if command -v frida-ps >/dev/null 2>&1; then
    log_info "Frida CLI available: $(frida-ps --help 2>&1 | head -n 1 || true)"
else
    log_warn "Frida CLI is not available on PATH"
fi

if [ -x "${ANGR_PYTHON:-}" ]; then
    log_info "angr runtime available at ${ANGR_PYTHON}"
else
    log_warn "ANGR_PYTHON is not executable: ${ANGR_PYTHON:-unset}"
fi

if [ -x "${QILING_PYTHON:-}" ]; then
    log_info "Qiling runtime available at ${QILING_PYTHON}"
else
    log_warn "QILING_PYTHON is not executable: ${QILING_PYTHON:-unset}"
fi

if [ -x "${PANDA_PYTHON:-}" ]; then
    log_info "PANDA runtime available at ${PANDA_PYTHON}"
else
    log_warn "PANDA_PYTHON is not executable: ${PANDA_PYTHON:-unset}"
fi

# =============================================================================
# Step 3: Create Runtime Directories
# =============================================================================

log_info "=== Creating Runtime Directories ==="

# Create appuser home directory to avoid mkdir errors
if [ ! -d "/root/.rikune" ]; then
    mkdir -p /root/.rikune 2>/dev/null || true
fi

# Create directories (will be mounted as volumes or created if not mounted)
ensure_dir "$WORKSPACE_ROOT" "appuser"
ensure_dir "$(dirname $DB_PATH)" "appuser"
ensure_dir "$CACHE_ROOT" "appuser"
ensure_dir "/app/logs" "appuser"
if [ -n "$XDG_CONFIG_HOME" ]; then
    ensure_dir "$XDG_CONFIG_HOME" "appuser"
fi
if [ -n "$XDG_CACHE_HOME" ]; then
    ensure_dir "$XDG_CACHE_HOME" "appuser"
fi
ensure_dir "/ghidra-projects" "appuser"
ensure_dir "/ghidra-logs" "appuser"
ensure_dir "/samples" "appuser"
ensure_dir "${QILING_ROOTFS:-/opt/qiling-rootfs}" "appuser"
ensure_dir "/tmp" "appuser"

# Ensure database directory exists
DB_DIR=$(dirname "$DB_PATH")
if [ ! -d "$DB_DIR" ]; then
    log_info "Creating database directory: $DB_DIR"
    mkdir -p "$DB_DIR"
    chown appuser:appuser "$DB_DIR"
fi

# =============================================================================
# Step 4: Set Permissions
# =============================================================================

log_info "=== Setting Permissions ==="

# Ensure appuser owns all application directories
chown -R appuser:appuser /app 2>/dev/null || log_warn "Could not chown /app"
chown -R appuser:appuser /ghidra-projects 2>/dev/null || log_warn "Could not chown /ghidra-projects"
chown -R appuser:appuser /ghidra-logs 2>/dev/null || log_warn "Could not chown /ghidra-logs"

# Set proper permissions on tmp
chmod 1777 /tmp

# =============================================================================
# Step 5: Pre-flight Checks
# =============================================================================

log_info "=== Running Pre-flight Checks ==="

# Check if dist/index.js exists
if [ ! -f "/app/dist/index.js" ]; then
    log_error "MCP Server entry point not found: /app/dist/index.js"
    log_error "Make sure the Docker image was built correctly with 'npm run build'"
    exit 1
fi

# Check if workers/static_worker.py exists and is valid
if [ -f "/app/workers/static_worker.py" ]; then
    log_info "Validating Python worker syntax..."
    if python3 -m py_compile /app/workers/static_worker.py 2>/dev/null; then
        log_info "Python worker syntax OK"
    else
        log_warn "Python worker syntax check failed, but continuing..."
    fi
fi

# Check if node_modules exists
if [ ! -d "/app/node_modules" ]; then
    log_error "node_modules not found. Docker image build may have failed."
    exit 1
fi

# =============================================================================
# Step 6: Display Configuration Summary
# =============================================================================

log_info "=== Configuration Summary ==="
log_info "Workspace Root:    $WORKSPACE_ROOT"
log_info "Database Path:     $DB_PATH"
log_info "Cache Root:        $CACHE_ROOT"
log_info "Ghidra Install:    $GHIDRA_INSTALL_DIR"
log_info "Ghidra Projects:   ${GHIDRA_PROJECT_ROOT:-/ghidra-projects}"
log_info "Ghidra Logs:       ${GHIDRA_LOG_ROOT:-/ghidra-logs}"
log_info "Graphviz Dot:      ${GRAPHVIZ_DOT_PATH:-dot}"
log_info "Rizin:             ${RIZIN_PATH:-rizin}"
log_info "UPX:               ${UPX_PATH:-upx}"
log_info "Wine:              ${WINE_PATH:-wine}"
log_info "winedbg:           ${WINEDBG_PATH:-winedbg}"
log_info "YARA-X Python:     ${YARAX_PYTHON:-python3}"
log_info "Qiling Python:     ${QILING_PYTHON:-python3}"
log_info "Qiling RootFS:     ${QILING_ROOTFS:-/opt/qiling-rootfs}"
log_info "angr Python:       ${ANGR_PYTHON:-unset}"
log_info "PANDA Python:      ${PANDA_PYTHON:-python3}"
log_info "RetDec:            ${RETDEC_PATH:-retdec-decompiler}"
log_info "Samples Root:      /samples"
log_info ""
log_info "Security:"
log_info "  - Running as user: $(whoami)"
log_info "  - Network:         ${NETWORK_MODE:-none (default)}"
log_info "  - Root filesystem: ${READ_ONLY_MODE:-read-only (recommended)}"
log_info ""

# =============================================================================
# Step 7: Start MCP Server
# =============================================================================

log_info "=== Starting MCP Server ==="
log_info "Command: node dist/index.js"
log_info ""

# Use exec to replace this shell process with Node.js
# This ensures proper signal handling and PID 1 behavior
exec node dist/index.js
