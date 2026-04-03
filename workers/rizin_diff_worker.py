#!/usr/bin/env python3
"""
Rizin diff worker — compares two binaries using radiff2.
Returns function-level diff as structured JSON.
"""

import json
import subprocess
import shutil
import sys
import os


def find_radiff2() -> str | None:
    """Locate radiff2 binary."""
    # Check env override
    path = os.environ.get("RADIFF2_PATH")
    if path and os.path.isfile(path):
        return path
    # Check common locations
    found = shutil.which("radiff2")
    if found:
        return found
    # Rizin ships radiff2 alongside
    rizin_path = os.environ.get("RIZIN_PATH")
    if rizin_path:
        candidate = os.path.join(os.path.dirname(rizin_path), "radiff2")
        if os.path.isfile(candidate):
            return candidate
    return None


def run_radiff2(binary_a: str, binary_b: str, timeout: int = 120) -> dict:
    """Run radiff2 -A -j on two binaries and return parsed JSON."""
    radiff2 = find_radiff2()
    if not radiff2:
        return {"ok": False, "error": "radiff2 not found in PATH or RADIFF2_PATH"}

    if not os.path.isfile(binary_a):
        return {"ok": False, "error": f"File not found: {binary_a}"}
    if not os.path.isfile(binary_b):
        return {"ok": False, "error": f"File not found: {binary_b}"}

    try:
        result = subprocess.run(
            [radiff2, "-A", "-j", binary_a, binary_b],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"radiff2 timed out after {timeout}s"}
    except Exception as e:
        return {"ok": False, "error": f"radiff2 execution failed: {e}"}

    # radiff2 -j outputs JSON array of function matches
    stdout = result.stdout.strip()
    if not stdout:
        # radiff2 may output text on stderr with partial info
        return {
            "ok": True,
            "functions_added": [],
            "functions_removed": [],
            "functions_modified": [],
            "warnings": [f"radiff2 produced no JSON output. stderr: {result.stderr[:500]}"],
        }

    try:
        raw = json.loads(stdout)
    except json.JSONDecodeError:
        return parse_text_output(result.stdout, result.stderr)

    return classify_functions(raw)


def classify_functions(raw: list | dict) -> dict:
    """Classify radiff2 JSON output into added/removed/modified."""
    functions_added = []
    functions_removed = []
    functions_modified = []

    entries = raw if isinstance(raw, list) else raw.get("functions", raw.get("diff", []))

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = entry.get("type", entry.get("status", ""))
        similarity = entry.get("similarity", entry.get("ratio", 0.0))

        func_info = {
            "name": entry.get("name", entry.get("fcn_name", "unknown")),
            "address_a": entry.get("addr", entry.get("offset_a")),
            "address_b": entry.get("addr2", entry.get("offset_b")),
            "size_a": entry.get("size", entry.get("size_a")),
            "size_b": entry.get("size2", entry.get("size_b")),
            "similarity": similarity,
        }

        if status in ("NEW", "added"):
            functions_added.append(func_info)
        elif status in ("GONE", "removed"):
            functions_removed.append(func_info)
        else:
            if isinstance(similarity, (int, float)) and similarity < 1.0:
                functions_modified.append(func_info)

    return {
        "ok": True,
        "functions_added": functions_added,
        "functions_removed": functions_removed,
        "functions_modified": sorted(
            functions_modified, key=lambda f: f.get("similarity", 1.0)
        ),
    }


def parse_text_output(stdout: str, stderr: str) -> dict:
    """Fallback parser for non-JSON radiff2 output."""
    return {
        "ok": True,
        "functions_added": [],
        "functions_removed": [],
        "functions_modified": [],
        "raw_output": stdout[:2000],
        "warnings": ["radiff2 did not produce JSON; raw text captured"],
    }


def main():
    """CLI entry point for direct invocation."""
    if len(sys.argv) < 3:
        print(json.dumps({"ok": False, "error": "Usage: rizin_diff_worker.py <binary_a> <binary_b>"}))
        sys.exit(1)

    result = run_radiff2(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
