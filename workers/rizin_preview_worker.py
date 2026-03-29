from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Dict


def build_response(job_id: str, *, ok: bool, warnings=None, errors=None, data=None) -> Dict[str, Any]:
    return {
        "job_id": job_id,
        "ok": ok,
        "warnings": warnings or [],
        "errors": errors or [],
        "data": data,
        "artifacts": [],
        "metrics": {},
    }


def run_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    job_id = str(payload.get("job_id") or "unknown")
    backend_path = str(payload["backend_path"])
    sample_path = str(payload["sample_path"])
    command = str(payload["command"])
    timeout_ms = int(payload.get("timeout_ms") or 45000)

    try:
        result = subprocess.run(
            [backend_path, "-A", "-q0", "-c", f"{command};q", sample_path],
            capture_output=True,
            text=True,
            timeout=max(timeout_ms / 1000.0, 1.0),
            check=False,
        )
        return build_response(
            job_id,
            ok=result.returncode == 0,
            errors=(
                []
                if result.returncode == 0
                else [
                    f"Rizin exited with code {result.returncode}",
                    (result.stderr or result.stdout or "No backend output was returned.").strip(),
                ]
            ),
            data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "timed_out": False,
            },
        )
    except subprocess.TimeoutExpired as exc:
        return build_response(
            job_id,
            ok=False,
            errors=[f"Rizin timed out after {timeout_ms}ms"],
            data={
                "stdout": exc.stdout or "",
                "stderr": exc.stderr or "",
                "exit_code": 124,
                "timed_out": True,
            },
        )
    except Exception as exc:
        return build_response(job_id, ok=False, errors=[str(exc)], data=None)


def main() -> None:
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            payload = json.loads(raw_line)
            response = run_request(payload)
        except Exception as exc:
            response = build_response("unknown", ok=False, errors=[f"Unexpected error: {exc}"], data=None)
        print(json.dumps(response, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
