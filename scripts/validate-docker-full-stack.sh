#!/bin/sh
set -eu

echo "[validate] core executables"
node --version >/dev/null
python3 --version >/dev/null
java -version >/dev/null 2>&1
capa --version >/dev/null 2>&1
diec --version >/dev/null 2>&1
dot -V >/dev/null 2>&1
rizin -v >/dev/null 2>&1
upx --version >/dev/null 2>&1
wine --version >/dev/null 2>&1
command -v winedbg >/dev/null 2>&1
frida-ps --help >/dev/null 2>&1
retdec-decompiler --help >/dev/null 2>&1
retdec-fileinfo --help >/dev/null 2>&1

echo "[validate] python backends"
python3 - <<'PY'
import importlib.metadata as m
import frida
import pandare
import psutil
import yara_x

print("pandare", m.version("pandare"))
print("yara-x", m.version("yara-x"))
print("frida-tools", m.version("frida-tools"))
print("psutil", psutil.__version__)
PY

/opt/qiling-venv/bin/python - <<'PY'
import qiling
print("qiling", qiling.__version__ if hasattr(qiling, "__version__") else "unknown")
PY

/opt/angr-venv/bin/python - <<'PY'
import angr
print("angr", angr.__version__)
PY

echo "[validate] full stack OK"
