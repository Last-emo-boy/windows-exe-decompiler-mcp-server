"""
Static Worker - PE 瑙ｆ瀽銆佸瓧绗︿覆鎻愬彇銆乊ARA 鎵弿

瀹炵幇涓?Node.js 鐨勮繘绋嬮棿閫氫俊锛坰tdin/stdout JSON锛?
"""

from __future__ import annotations

import sys
import json
import os
import hashlib
import math
import time
import re
import shutil
import subprocess
import importlib.metadata
import traceback
import warnings
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
    YARA_IMPORT_ERROR = None
except (ImportError, FileNotFoundError, OSError):
    YARA_AVAILABLE = False
    YARA_IMPORT_ERROR = str(sys.exc_info()[1])
    yara = None  # Set to None so we can check it later

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = None


@dataclass
class SampleInfo:
    """鏍锋湰淇℃伅"""
    sample_id: str
    path: str


@dataclass
class PolicyContext:
    """绛栫暐涓婁笅鏂?"""
    allow_dynamic: bool
    allow_network: bool


@dataclass
class WorkerContext:
    """Worker 涓婁笅鏂?"""
    request_time_utc: str
    policy: PolicyContext
    versions: Dict[str, str]


@dataclass
class WorkerRequest:
    """Worker 璇锋眰鏁版嵁绫?"""
    job_id: str
    tool: str
    sample: SampleInfo
    args: Dict[str, Any]
    context: WorkerContext


@dataclass
class ArtifactRef:
    """浜х墿寮曠敤"""
    id: str
    type: str
    path: str
    sha256: str
    mime: Optional[str] = None


@dataclass
class WorkerResponse:
    """Worker 鍝嶅簲鏁版嵁绫?"""
    job_id: str
    ok: bool
    warnings: List[str]
    errors: List[str]
    data: Any
    artifacts: List[ArtifactRef]
    metrics: Dict[str, Any]


class StaticWorker:
    """鎵ц闈欐€佸垎鏋愪换鍔＄殑 Worker"""

    def __init__(self):
        """鍒濆鍖?Static Worker"""
        self.tool_handlers = {
            'pe.fingerprint': self.pe_fingerprint,
            'pe.imports.extract': self.pe_imports_extract,
            'pe.exports.extract': self.pe_exports_extract,
            'pe.structure.analyze': self.pe_structure_analyze,
            'static.capability.triage': self.static_capability_triage,
            'strings.extract': self.strings_extract,
            'strings.floss.decode': self.floss_decode,
            'yara.scan': self.yara_scan,
            'runtime.detect': self.runtime_detect,
            'packer.detect': self.packer_detect,
            'entrypoint.disasm': self.entrypoint_disasm,
            'system.health': self.system_health,
            'dynamic.dependencies': self.dynamic_dependencies,
            'sandbox.execute': self.sandbox_execute,
            # 鍏朵粬宸ュ叿澶勭悊鍣ㄥ皢鍦ㄥ悗缁换鍔′腑瀹炵幇
        }
        self._floss_cli_cache = None
        self._dependency_status_cache = None

    def _get_python_package_version(self, package_name: str) -> Optional[str]:
        """Get installed Python package version, if available."""
        try:
            return importlib.metadata.version(package_name)
        except Exception:
            return None

    def _parse_major_version(self, version: Optional[str]) -> Optional[int]:
        """Extract the major version number from a package version string."""
        if not version:
            return None
        match = re.match(r"^\s*(\d+)", str(version))
        if not match:
            return None
        try:
            return int(match.group(1))
        except Exception:
            return None

    def _probe_speakeasy_emulator(self) -> Dict[str, Any]:
        """Probe whether the FLARE Speakeasy emulator is installed and importable."""
        emulator_version = self._get_python_package_version("speakeasy-emulator")
        legacy_version = self._get_python_package_version("speakeasy")
        setuptools_version = self._get_python_package_version("setuptools")

        result: Dict[str, Any] = {
            "available": False,
            "version": emulator_version,
            "distribution": "speakeasy-emulator" if emulator_version else None,
            "legacy_distribution_version": legacy_version,
            "setuptools_version": setuptools_version,
            "module_path": None,
            "package_root": None,
            "api_available": False,
            "import_mode": None,
            "warnings": [],
            "error": None,
        }

        emulator_summary = None
        legacy_summary = None
        try:
            if emulator_version:
                emulator_summary = importlib.metadata.metadata("speakeasy-emulator").get("Summary")
        except Exception:
            emulator_summary = None
        try:
            if legacy_version:
                legacy_summary = importlib.metadata.metadata("speakeasy").get("Summary")
        except Exception:
            legacy_summary = None

        if emulator_summary:
            result["summary"] = emulator_summary
        if legacy_summary:
            result["legacy_distribution_summary"] = legacy_summary

        probe_warnings: List[str] = []
        setuptools_major = self._parse_major_version(setuptools_version)
        if setuptools_major is not None and setuptools_major >= 81:
            probe_warnings.append(
                "setuptools>=81 may break unicorn/pkg_resources imports; pin setuptools<81."
            )

        if legacy_version and legacy_summary and "metrics aggregation server" in legacy_summary.lower():
            probe_warnings.append(
                "An unrelated `speakeasy` PyPI distribution is installed (metrics server package)."
            )

        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                from speakeasy_compat import load_speakeasy_module

                speakeasy_module, compat_info = load_speakeasy_module()

            result["module_path"] = compat_info.get("module_path") or getattr(speakeasy_module, "__file__", None)
            result["package_root"] = compat_info.get("package_root")
            result["api_available"] = hasattr(speakeasy_module, "Speakeasy")
            result["import_mode"] = compat_info.get("import_mode")
            result["module_exports"] = [
                name
                for name in ["Speakeasy", "Win32Emulator", "WinKernelEmulator", "PeFile"]
                if hasattr(speakeasy_module, name)
            ]

            import_warnings = [str(item.message) for item in caught]
            probe_warnings.extend(import_warnings + list(compat_info.get("warnings", [])))

            if not result["api_available"]:
                result["error"] = "Imported `speakeasy` module does not expose the Speakeasy emulator API."
            elif emulator_version:
                result["available"] = True
            elif legacy_version and legacy_summary and "malware emulation framework" in legacy_summary.lower():
                # Defensive fallback for odd environments where the emulator may be repackaged.
                result["available"] = True
                result["distribution"] = "speakeasy"
                result["version"] = legacy_version
            else:
                result["error"] = (
                    "The `speakeasy` module imported successfully, but the `speakeasy-emulator` "
                    "distribution metadata was not found."
                )
        except Exception as exc:
            result["error"] = str(exc)

        result["warnings"] = self._dedupe_preserve(probe_warnings)[:8]
        return result

    def _discover_floss_cli(self) -> Dict[str, Any]:
        """
        Discover a compatible FLARE-FLOSS CLI and cache the result.
        Reject unrelated `floss` tools (e.g., fault-localization CLI).
        """
        if self._floss_cli_cache is not None:
            return self._floss_cli_cache

        candidates: List[List[str]] = []

        flare_floss = shutil.which("flare-floss")
        if flare_floss:
            candidates.append([flare_floss])

        floss = shutil.which("floss")
        if floss:
            candidates.append([floss])

        # Fallback when command entrypoint is missing but module exists.
        candidates.append([sys.executable, "-m", "floss.main"])

        probe_errors: List[str] = []

        for candidate in candidates:
            try:
                help_result = subprocess.run(
                    candidate + ["--help"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                help_text = f"{help_result.stdout}\n{help_result.stderr}".strip()
                help_lower = help_text.lower()

                # This is not FLARE-FLOSS; it's an unrelated package with same command name.
                if "fault localization with spectrum-based scoring" in help_lower:
                    probe_errors.append(
                        f"{' '.join(candidate)} points to incompatible `floss` package"
                    )
                    continue

                supports_json = "--json" in help_lower or " json" in help_lower
                supports_no_flags = (
                    "--no-static-strings" in help_lower
                    and "--no-stack-strings" in help_lower
                    and "--no-tight-strings" in help_lower
                    and "--no-decoded-strings" in help_lower
                )

                if not supports_json:
                    continue

                version_output = None
                for version_args in (["--version"], ["version"]):
                    try:
                        version_result = subprocess.run(
                            candidate + version_args,
                            capture_output=True,
                            text=True,
                            timeout=5,
                            check=False,
                        )
                        output = (version_result.stdout or version_result.stderr or "").strip()
                        if output:
                            version_output = output.splitlines()[0]
                            break
                    except Exception:
                        continue

                self._floss_cli_cache = {
                    "ok": True,
                    "command": candidate,
                    "json_flag": "--json",
                    "supports_no_flags": supports_no_flags,
                    "version": version_output,
                }
                return self._floss_cli_cache
            except Exception as e:
                probe_errors.append(f"{' '.join(candidate)} probe failed: {str(e)}")

        error_message = (
            "Compatible FLARE-FLOSS CLI not found. "
            "Install with `pip install flare-floss` and ensure it is first in PATH."
        )
        if probe_errors:
            error_message = f"{error_message} Details: {'; '.join(probe_errors)}"

        self._floss_cli_cache = {
            "ok": False,
            "error": error_message,
        }
        return self._floss_cli_cache

    def _resolve_capa_rules_path(self, requested_path: Optional[str] = None) -> Dict[str, Any]:
        """Resolve a capa rules directory or compiled rules file from args or environment."""
        candidates: List[tuple[str, str]] = []
        if requested_path and str(requested_path).strip():
            candidates.append((str(requested_path).strip(), "arg"))

        env_rules = os.environ.get("CAPA_RULES_PATH", "").strip()
        if env_rules:
            candidates.append((env_rules, "env"))

        seen = set()
        for candidate, source in candidates:
            normalized = os.path.abspath(candidate)
            if normalized.lower() in seen:
                continue
            seen.add(normalized.lower())
            if os.path.exists(normalized):
                return {
                    "available": True,
                    "path": normalized,
                    "source": source,
                    "kind": "directory" if os.path.isdir(normalized) else "file",
                }
            return {
                "available": False,
                "path": normalized,
                "source": source,
                "error": f"Configured capa rules path does not exist: {normalized}",
            }

        return {
            "available": False,
            "path": None,
            "source": None,
            "error": "No capa rules path configured. Set CAPA_RULES_PATH or pass rules_path.",
        }

    def _discover_capa_backend(
        self,
        requested_rules_path: Optional[str] = None,
        requested_command: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Discover a usable capa backend and the configured rules path."""
        rules_status = self._resolve_capa_rules_path(requested_rules_path)
        package_version = self._get_python_package_version("flare-capa") or self._get_python_package_version("capa")
        candidates: List[List[str]] = []

        if requested_command:
            if isinstance(requested_command, list):
                requested_items = [str(item).strip() for item in requested_command if str(item).strip()]
                if requested_items:
                    candidates.append(requested_items)
            elif str(requested_command).strip():
                candidates.append([str(requested_command).strip()])

        capa_cli = shutil.which("capa")
        if capa_cli:
            candidates.append([capa_cli])
        candidates.append([sys.executable, "-m", "capa.main"])

        probe_errors: List[str] = []
        for candidate in candidates:
            try:
                version_result = subprocess.run(
                    candidate + ["--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                output = f"{version_result.stdout}\n{version_result.stderr}".strip()
                if version_result.returncode == 0 or output:
                    version = output.splitlines()[0] if output else package_version
                    return {
                        "available": True,
                        "command": candidate,
                        "version": package_version or version,
                        "backend_version": version,
                        "rules": rules_status,
                        "error": None,
                    }
                probe_errors.append(f"{' '.join(candidate)} returned exit code {version_result.returncode}")
            except Exception as exc:
                probe_errors.append(f"{' '.join(candidate)} probe failed: {str(exc)}")

        return {
            "available": False,
            "command": None,
            "version": package_version,
            "rules": rules_status,
            "error": (
                "Compatible capa backend not found. Install with `pip install flare-capa`."
                + (f" Details: {'; '.join(probe_errors)}" if probe_errors else "")
            ),
        }

    def _probe_frida_runtime(self) -> Dict[str, Any]:
        """Probe whether the Frida runtime is installed and functional."""
        frida_version = self._get_python_package_version("frida")
        frida_tools_version = self._get_python_package_version("frida-tools")

        # Resolve Frida configuration from environment variables
        frida_path = os.environ.get("FRIDA_PATH") or os.environ.get("FRIDA_SERVER_PATH")
        frida_script_root = os.environ.get("FRIDA_SCRIPT_ROOT")

        result: Dict[str, Any] = {
            "available": False,
            "version": frida_version,
            "tools_version": frida_tools_version,
            "module_path": None,
            "api_available": False,
            "error": None,
            "warnings": [],
            "config": {
                "frida_path": frida_path,
                "frida_script_root": frida_script_root,
                "frida_server_binary": None,
            },
        }

        probe_warnings: List[str] = []

        try:
            import frida
            result["module_path"] = getattr(frida, "__file__", None)
            result["api_available"] = hasattr(frida, "spawn") and hasattr(frida, "attach")

            # Check if frida-server binary is accessible (optional)
            try:
                import subprocess
                frida_ps_result = subprocess.run(
                    ["frida-ps", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if frida_ps_result.returncode == 0:
                    result["frida_ps_available"] = True
                else:
                    probe_warnings.append("frida-ps command not available")
            except Exception:
                probe_warnings.append("frida-ps command not found in PATH")

            # Check for frida-server binary if frida_path is configured
            if frida_path and os.path.exists(frida_path):
                result["config"]["frida_server_binary"] = frida_path
                result["config"]["frida_server_exists"] = True
            elif frida_path:
                result["config"]["frida_server_exists"] = False
                probe_warnings.append(f"Configured frida_path does not exist: {frida_path}")
            else:
                # Try to find frida-server in common locations
                result["config"]["frida_server_auto_found"] = False

            if result["api_available"]:
                result["available"] = True
            else:
                result["error"] = "Frida module imported but core APIs (spawn/attach) not available"
        except ImportError as e:
            result["error"] = f"Frida not installed: {str(e)}"
        except Exception as e:
            result["error"] = f"Frida probe error: {str(e)}"

        result["warnings"] = self._dedupe_preserve(probe_warnings)[:4]
        return result

    def _get_dependency_status(self) -> Dict[str, Any]:
        """Collect runtime dependency status for diagnostics."""
        if self._dependency_status_cache is not None:
            return self._dependency_status_cache

        speakeasy_status = self._probe_speakeasy_emulator()
        capa_status = self._discover_capa_backend()
        frida_status = self._probe_frida_runtime()

        status = {
            "python": sys.version.split()[0],
            "pefile": {
                "available": PEFILE_AVAILABLE,
                "version": self._get_python_package_version("pefile"),
            },
            "lief": {
                "available": LIEF_AVAILABLE,
                "version": self._get_python_package_version("lief"),
            },
            "capa": {
                "available": bool(capa_status.get("available")),
                "version": capa_status.get("version"),
                "backend_version": capa_status.get("backend_version"),
                "command": capa_status.get("command"),
                "error": capa_status.get("error"),
                "rules": capa_status.get("rules"),
            },
            "yara_python": {
                "available": YARA_AVAILABLE,
                "version": self._get_python_package_version("yara-python"),
                "error": YARA_IMPORT_ERROR,
            },
            "capstone": {
                "available": CAPSTONE_AVAILABLE,
                "version": self._get_python_package_version("capstone"),
            },
            "dnfile": {
                "available": self._get_python_package_version("dnfile") is not None,
                "version": self._get_python_package_version("dnfile"),
            },
            "speakeasy": speakeasy_status,
            "frida": frida_status,
            "psutil": {
                "available": self._get_python_package_version("psutil") is not None,
                "version": self._get_python_package_version("psutil"),
            },
        }

        floss_probe = self._discover_floss_cli()
        status["floss_cli"] = {
            "available": floss_probe.get("ok", False),
            "command": floss_probe.get("command"),
            "json_flag": floss_probe.get("json_flag"),
            "supports_no_flags": floss_probe.get("supports_no_flags", False),
            "version": floss_probe.get("version"),
            "error": floss_probe.get("error"),
        }

        self._dependency_status_cache = status
        return status

    def system_health(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return static-worker dependency and rule-set health summary.

        Args:
            sample_path: unused
            args: optional arguments

        Returns:
            Dict: health status payload
        """
        _ = sample_path
        _ = args

        dependencies = self._get_dependency_status()
        rules_dir = os.path.join(os.path.dirname(__file__), 'yara_rules')
        rule_files = ['default.yar', 'malware_families.yar', 'packers.yar']

        yara_rules: Dict[str, Dict[str, Any]] = {}
        available_rule_count = 0

        for rule_file in rule_files:
            rule_path = os.path.join(rules_dir, rule_file)
            exists = os.path.isfile(rule_path)
            size = os.path.getsize(rule_path) if exists else 0
            if exists:
                available_rule_count += 1
            yara_rules[rule_file] = {
                'exists': exists,
                'size_bytes': size,
                'path': rule_path,
            }

        capa_rules = dependencies.get("capa", {}).get("rules", {})
        required_checks = [
            bool(dependencies.get('pefile', {}).get('available')),
            bool(dependencies.get('lief', {}).get('available')),
            bool(dependencies.get('capa', {}).get('available')),
            bool(dependencies.get('floss_cli', {}).get('available')),
            bool(dependencies.get('yara_python', {}).get('available')),
            available_rule_count >= 2,
        ]

        available_count = sum(1 for check in required_checks if check)
        status = 'healthy'
        if available_count < len(required_checks):
            status = 'degraded'
        if available_count <= 1:
            status = 'unhealthy'

        return {
            'status': status,
            'worker': {
                'python_executable': sys.executable,
                'python_version': sys.version.split()[0],
                'cwd': os.getcwd(),
            },
            'dependencies': dependencies,
            'capa_rules': capa_rules,
            'yara_rules': {
                'directory': rules_dir,
                'available_count': available_rule_count,
                'required_count': len(rule_files),
                'files': yara_rules,
            },
            'checked_at': datetime.now(timezone.utc).isoformat(),
        }

    def dynamic_dependencies(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return dynamic-analysis capability readiness based on optional Python components.
        This is a safe bootstrap endpoint and does not execute the sample.
        """
        _ = sample_path
        _ = args

        dependencies = self._get_dependency_status()
        speakeasy_comp = dependencies.get("speakeasy", {"available": False, "version": None})
        frida_comp = dependencies.get("frida", {"available": False, "version": None})
        psutil_comp = dependencies.get("psutil", {"available": False, "version": None})

        dynamic_components = {
            "speakeasy": speakeasy_comp,
            "frida": frida_comp,
            "psutil": psutil_comp,
        }

        available = [
            name for name, payload in dynamic_components.items() if bool(payload.get("available"))
        ]
        status = "bootstrap_required"
        if len(available) >= 2:
            status = "ready"
        elif len(available) == 1:
            status = "partial"

        recommendations = []
        if not speakeasy_comp.get("available"):
            recommendations.append(
                "Install FLARE Speakeasy emulator for PE user-mode emulation: pip install speakeasy-emulator"
            )
        if speakeasy_comp.get("legacy_distribution_summary") and "metrics aggregation server" in str(
            speakeasy_comp.get("legacy_distribution_summary", "")
        ).lower():
            recommendations.append(
                "Remove the unrelated `speakeasy` metrics package if present: pip uninstall speakeasy"
            )
        setuptools_version = speakeasy_comp.get("setuptools_version")
        setuptools_major = self._parse_major_version(str(setuptools_version) if setuptools_version else None)
        if setuptools_major is not None and setuptools_major >= 81:
            recommendations.append(
                "Pin setuptools below 81 for Unicorn/Speakeasy compatibility: pip install \"setuptools<81\""
            )
        if not frida_comp.get("available"):
            recommendations.append("Install frida for runtime API tracing: pip install frida")
        else:
            # Add specific recommendations if frida is partially functional
            frida_error = frida_comp.get("error")
            if frida_error and "spawn" in str(frida_error).lower():
                recommendations.append("Frida installed but core APIs are incomplete; reinstall frida-tools")
            if not frida_comp.get("frida_ps_available"):
                recommendations.append("frida-tools CLI not found; ensure frida-tools is installed and in PATH")
        if not psutil_comp.get("available"):
            recommendations.append("Install psutil for process telemetry collection: pip install psutil")

        # Add setup guidance for Frida if unavailable
        setup_actions = []
        if not frida_comp.get("available"):
            setup_actions = [
                {
                    "action_type": "pip_install",
                    "package": "frida",
                    "description": "Install Frida runtime for dynamic instrumentation",
                    "command": "pip install frida",
                },
                {
                    "action_type": "pip_install",
                    "package": "frida-tools",
                    "description": "Install Frida tools package for CLI and Python APIs",
                    "command": "pip install frida-tools",
                },
                {
                    "action_type": "verify_install",
                    "command": "python -c \"import frida; print(frida.__version__)\"",
                    "description": "Verify Frida installation",
                },
            ]

        return {
            "status": status,
            "available_components": available,
            "components": dynamic_components,
            "recommendations": recommendations,
            "setup_actions": setup_actions if not frida_comp.get("available") else [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def _dedupe_preserve(self, values: List[str]) -> List[str]:
        """Deduplicate a list while preserving order."""
        seen = set()
        output: List[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            output.append(value)
        return output

    def _extract_quick_string_entries(
        self,
        data: bytes,
        min_len: int = 5,
        max_items: int = 2500,
    ) -> List[Dict[str, Any]]:
        """Extract lightweight ASCII/UTF-16LE strings with offsets for memory-guided analysis."""
        extracted: List[Dict[str, Any]] = []
        if not data:
            return extracted

        ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
        unicode_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len)

        for match in ascii_pattern.finditer(data):
            if len(extracted) >= max_items:
                break
            try:
                decoded = match.group(0).decode('utf-8', errors='ignore').strip()
            except Exception:
                decoded = ''
            if decoded:
                extracted.append(
                    {
                        "offset": int(match.start()),
                        "string": decoded,
                        "encoding": "ascii",
                    }
                )

        if len(extracted) < max_items:
            for match in unicode_pattern.finditer(data):
                if len(extracted) >= max_items:
                    break
                try:
                    decoded = match.group(0).decode('utf-16le', errors='ignore').strip()
                except Exception:
                    decoded = ''
                if decoded:
                    extracted.append(
                        {
                            "offset": int(match.start()),
                            "string": decoded,
                            "encoding": "utf-16le",
                        }
                    )

        deduped: Dict[str, Dict[str, Any]] = {}
        for item in extracted:
            key = item.get("string", "")
            if key not in deduped or item.get("offset", 0) < deduped[key].get("offset", 0):
                deduped[key] = item

        return sorted(deduped.values(), key=lambda item: (item.get("offset", 0), item.get("string", "")))

    def _extract_quick_strings(
        self,
        data: bytes,
        min_len: int = 5,
        max_items: int = 2500,
    ) -> List[str]:
        """Extract lightweight ASCII/UTF-16LE strings for behavior simulation."""
        return [
            str(item.get("string", ""))
            for item in self._extract_quick_string_entries(
                data,
                min_len=min_len,
                max_items=max_items,
            )
        ]

    def _extract_api_tokens_from_strings(self, values: List[str]) -> List[str]:
        """Recover Win32/NT API-like tokens from free-form strings."""
        if not values:
            return []

        api_pattern = re.compile(
            r'\b('
            r'GetProcAddress|LoadLibrary(?:Ex)?[AW]?|GetModuleHandle[AW]?|'
            r'OpenProcess|ReadProcessMemory|WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|'
            r'SetThreadContext|ResumeThread|CreateProcess[AW]?|CreateFile[AW]?|ReadFile|WriteFile|'
            r'DeleteFile[AW]?|MoveFile(?:Ex)?[AW]?|CopyFile(?:Ex)?[AW]?|FindFirstFile[AW]?|FindNextFile[AW]?|'
            r'Reg(?:Open|Create|Set|Query|Delete)Key(?:Ex)?[AW]?|Reg(?:Set|Query)Value(?:Ex)?[AW]?|'
            r'NtQueryInformationProcess|NtQuerySystemInformation|IsDebuggerPresent|CheckRemoteDebuggerPresent|'
            r'InternetOpen[AW]?|InternetConnect[AW]?|HttpSendRequest[AW]?|URLDownloadToFile[AW]?|'
            r'WinHttp[A-Za-z0-9_]*|connect|send|recv'
            r')\b',
            re.IGNORECASE,
        )

        matches: List[str] = []
        for value in values:
            for hit in api_pattern.findall(value or ''):
                if hit:
                    matches.append(hit)
        return self._dedupe_preserve(matches)

    def _build_api_resolution_trace(
        self,
        import_hints: List[str],
        string_entries: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Combine import evidence and string evidence into API-resolution observations."""
        api_map: Dict[str, Dict[str, Any]] = {}

        for hint in import_hints:
            api_name = hint.split('!')[-1].strip()
            if not api_name:
                continue
            key = api_name.lower()
            payload = api_map.setdefault(
                key,
                {
                    "api": api_name,
                    "import_sources": [],
                    "string_sources": [],
                },
            )
            payload["import_sources"].append(hint)

        for entry in string_entries:
            value = str(entry.get("string", ""))
            offset = int(entry.get("offset", 0))
            for api_name in self._extract_api_tokens_from_strings([value]):
                key = api_name.lower()
                payload = api_map.setdefault(
                    key,
                    {
                        "api": api_name,
                        "import_sources": [],
                        "string_sources": [],
                    },
                )
                payload["string_sources"].append(f"string@0x{offset:x}:{api_name}")

        results: List[Dict[str, Any]] = []
        for payload in api_map.values():
            import_sources = self._dedupe_preserve(payload.get("import_sources", []))
            string_sources = self._dedupe_preserve(payload.get("string_sources", []))
            api_name = payload.get("api", "unknown")
            api_lower = api_name.lower()

            if import_sources and string_sources:
                provenance = "hybrid_import_string"
                confidence = 0.86
            elif string_sources:
                provenance = "string_reference"
                confidence = 0.68
            else:
                provenance = "import_table"
                confidence = 0.62

            if api_lower in {"getprocaddress", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}:
                confidence = min(0.92, confidence + 0.08)
            elif api_lower.startswith("ntquery"):
                confidence = min(0.9, confidence + 0.05)
            elif any(marker in api_lower for marker in [
                "writeprocessmemory",
                "readprocessmemory",
                "openprocess",
                "setthreadcontext",
                "resumethread",
                "createremotethread",
                "virtualallocex",
                "createprocess",
                "regopenkey",
                "regsetvalue",
                "regqueryvalue",
                "createfile",
                "readfile",
                "writefile",
                "internetopen",
                "internetconnect",
                "httpsendrequest",
                "urldownloadtofile",
            ]):
                confidence = min(0.9, confidence + 0.1)
            elif api_lower.startswith("__") or api_lower.startswith("_") or api_lower in {"memset", "memcmp", "strlen"}:
                confidence = max(0.35, confidence - 0.12)

            results.append(
                {
                    "api": api_name,
                    "provenance": provenance,
                    "confidence": round(confidence, 2),
                    "sources": (import_sources + string_sources)[:8],
                }
            )

        results.sort(key=lambda item: (-float(item.get("confidence", 0.0)), str(item.get("api", "")).lower()))
        return results[:40]

    def _build_memory_regions(
        self,
        string_entries: List[Dict[str, Any]],
        import_hints: List[str],
        api_resolution: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Infer likely runtime memory/configuration regions from raw-image string neighborhoods."""
        windows = self._build_context_windows(
            string_entries,
            context_window_bytes=192,
            max_context_windows=10,
        )
        import_api_names = self._dedupe_preserve([hint.split('!')[-1] for hint in import_hints if '!' in hint])
        regions: List[Dict[str, Any]] = []

        for window in windows:
            window_strings = [str(item.get("string", "")) for item in window.get("strings", [])]
            merged = " ".join(window_strings).lower()
            categories = set(window.get("categories", []))
            api_tokens = self._extract_api_tokens_from_strings(window_strings)
            has_packer_terms = bool(re.search(r'packer|protector|upx|vmprotect|themida|entry point in non-first section|entropy', merged))
            region_type = "string_cluster"
            purpose = "Likely operator-facing help, configuration, or status buffer."
            source = "string_window"
            confidence = 0.55

            if re.search(r'writeprocessmemory|readprocessmemory|openprocess|setthreadcontext|resumethread|createprocess', merged):
                region_type = "process_operation_plan"
                purpose = "Likely remote-process access, memory-write, or execution-transfer buffer."
                confidence = 0.84
                source = "hybrid" if import_api_names else "string_window"
            elif re.search(r'getprocaddress|loadlibrary|getmodulehandle', merged):
                region_type = "api_resolution_table"
                purpose = "Likely dynamic API-resolution table assembled before sensitive actions."
                confidence = 0.8
                source = "hybrid" if import_api_names else "string_window"
            elif re.search(r'ntquerysysteminformation|kernel_code_integrity|codeintegrity|testsign', merged):
                region_type = "code_integrity_probe"
                purpose = "Likely environment or code-integrity probe state."
                confidence = 0.82
                source = "hybrid"
            elif has_packer_terms:
                region_type = "packer_signature_block"
                purpose = "Likely PE/packer signature set or section-analysis workspace."
                confidence = 0.8
            elif 'registry' in categories:
                region_type = "registry_config"
                purpose = "Likely registry-backed configuration or persistence buffer."
                confidence = 0.76
            elif 'command' in categories:
                region_type = "command_buffer"
                purpose = "Likely command-line, child-process, or operator task buffer."
                confidence = 0.74
            elif 'url' in categories or 'network' in categories:
                region_type = "network_config"
                purpose = "Likely endpoint, transport, or request configuration block."
                confidence = 0.72
            elif 'ipc' in categories:
                region_type = "ipc_channel"
                purpose = "Likely named-pipe or IPC coordination buffer."
                confidence = 0.68

            indicators = self._dedupe_preserve(
                window_strings
                + api_tokens
            )[:6]

            if (
                region_type == "string_cluster"
                and not categories
                and not api_tokens
                and not has_packer_terms
            ):
                continue

            regions.append(
                {
                    "region_type": region_type,
                    "purpose": purpose,
                    "source": source,
                    "confidence": round(min(0.95, confidence + min(float(window.get("score", 0.0)) / 200.0, 0.08)), 2),
                    "start_offset": int(window.get("start_offset", 0)),
                    "end_offset": int(window.get("end_offset", 0)),
                    "indicators": indicators,
                }
                )

        if not any(item.get("region_type") == "api_resolution_table" for item in regions):
            dynamic_apis = [
                item for item in api_resolution
                if any(marker in str(item.get("api", "")).lower() for marker in ["getprocaddress", "loadlibrary", "getmodulehandle"])
            ]
            if dynamic_apis:
                regions.append(
                    {
                        "region_type": "api_resolution_table",
                        "purpose": "Likely dynamic API-resolution table assembled before higher-risk activity.",
                        "source": "hybrid" if any(item.get("provenance") == "hybrid_import_string" for item in dynamic_apis) else "api_trace",
                        "confidence": round(max(float(item.get("confidence", 0.75)) for item in dynamic_apis), 2),
                        "indicators": self._dedupe_preserve(
                            [item.get("api", "") for item in dynamic_apis] + dynamic_apis[0].get("sources", [])
                        )[:6],
                    }
                )

        if not any(item.get("region_type") == "process_operation_plan" for item in regions):
            process_apis = [
                item for item in api_resolution
                if any(marker in str(item.get("api", "")).lower() for marker in [
                    "openprocess",
                    "readprocessmemory",
                    "writeprocessmemory",
                    "setthreadcontext",
                    "resumethread",
                    "createprocess",
                    "createremotethread",
                    "virtualallocex",
                ])
            ]
            if process_apis:
                regions.append(
                    {
                        "region_type": "process_operation_plan",
                        "purpose": "Likely process targeting, remote-memory, or execution-transfer workspace.",
                        "source": "hybrid" if any(item.get("provenance") == "hybrid_import_string" for item in process_apis) else "api_trace",
                        "confidence": round(max(float(item.get("confidence", 0.78)) for item in process_apis), 2),
                        "indicators": self._dedupe_preserve(
                            [item.get("api", "") for item in process_apis] + process_apis[0].get("sources", [])
                        )[:6],
                    }
                )

        if not any(item.get("region_type") == "code_integrity_probe" for item in regions):
            code_integrity_apis = [
                item for item in api_resolution
                if str(item.get("api", "")).lower().startswith("ntquerysysteminformation")
            ]
            if code_integrity_apis:
                regions.append(
                    {
                        "region_type": "code_integrity_probe",
                        "purpose": "Likely environment or code-integrity inspection state derived from NT query APIs.",
                        "source": "api_trace",
                        "confidence": round(max(float(item.get("confidence", 0.8)) for item in code_integrity_apis), 2),
                        "indicators": self._dedupe_preserve(
                            [item.get("api", "") for item in code_integrity_apis] + code_integrity_apis[0].get("sources", [])
                        )[:6],
                    }
                )

        if not regions and api_resolution:
            for item in api_resolution[:4]:
                regions.append(
                    {
                        "region_type": "api_resolution_table",
                        "purpose": "Likely API resolution state inferred from import/string evidence.",
                        "source": "hybrid" if item.get("provenance") == "hybrid_import_string" else "api_trace",
                        "confidence": float(item.get("confidence", 0.6)),
                        "indicators": list(item.get("sources", []))[:4],
                    }
                )

        regions.sort(key=lambda item: (-float(item.get("confidence", 0.0)), int(item.get("start_offset", 0))))
        return regions[:12]

    def _build_execution_hypotheses(
        self,
        capabilities: Dict[str, int],
        api_resolution: List[Dict[str, Any]],
        memory_regions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Summarize likely execution stages supported by memory-guided evidence."""
        hypotheses: List[Dict[str, Any]] = []

        def add_hypothesis(stage: str, description: str, source: str, confidence: float, indicators: List[str]) -> None:
            if not indicators:
                return
            hypotheses.append(
                {
                    "stage": stage,
                    "description": description,
                    "source": source,
                    "confidence": round(min(0.95, confidence), 2),
                    "indicators": self._dedupe_preserve(indicators)[:6],
                }
            )

        api_lookup = {str(item.get("api", "")).lower(): item for item in api_resolution}
        region_lookup = {str(item.get("region_type", "")): item for item in memory_regions}

        loader_indicators = [
            item.get("api", "")
            for item in api_resolution
            if str(item.get("api", "")).lower() in {"getprocaddress", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getmodulehandlea", "getmodulehandlew"}
        ]
        if loader_indicators:
            add_hypothesis(
                "resolve_dynamic_apis",
                "Resolve Windows APIs at runtime before enabling higher-risk capabilities.",
                "hybrid" if any(item.get("provenance") == "hybrid_import_string" for item in api_resolution if item.get("api", "") in loader_indicators) else "string",
                0.82,
                loader_indicators,
            )

        process_indicators = [
            item.get("api", "")
            for item in api_resolution
            if any(marker in str(item.get("api", "")).lower() for marker in ["openprocess", "readprocessmemory", "writeprocessmemory", "setthreadcontext", "resumethread", "createprocess", "createremotethread", "virtualallocex"])
        ]
        if capabilities.get("process_injection", 0) > 0 or "process_operation_plan" in region_lookup:
            add_hypothesis(
                "prepare_remote_process_access",
                "Acquire process/thread handles, memory-write primitives, or launch context before acting on a target process.",
                "hybrid" if process_indicators else "region",
                0.84,
                process_indicators + region_lookup.get("process_operation_plan", {}).get("indicators", []),
            )

        if capabilities.get("registry_modification", 0) > 0 or "registry_config" in region_lookup:
            add_hypothesis(
                "stage_registry_state",
                "Load or update registry-backed configuration or persistence state.",
                "hybrid" if capabilities.get("registry_modification", 0) > 0 else "region",
                0.74,
                region_lookup.get("registry_config", {}).get("indicators", []),
            )

        if capabilities.get("command_execution", 0) > 0 or "command_buffer" in region_lookup:
            add_hypothesis(
                "launch_operator_command",
                "Prepare a child-process or operator command buffer before execution.",
                "hybrid" if capabilities.get("command_execution", 0) > 0 else "region",
                0.73,
                region_lookup.get("command_buffer", {}).get("indicators", []),
            )

        if "code_integrity_probe" in region_lookup or "ntquerysysteminformation" in api_lookup:
            add_hypothesis(
                "check_execution_environment",
                "Query code-integrity or anti-analysis state before continuing.",
                "hybrid" if "ntquerysysteminformation" in api_lookup else "region",
                0.81,
                region_lookup.get("code_integrity_probe", {}).get("indicators", [])
                + [api_lookup.get("ntquerysysteminformation", {}).get("api", "")],
            )

        if "packer_signature_block" in region_lookup:
            add_hypothesis(
                "scan_pe_layout",
                "Inspect PE sections, signatures, or entrypoint layout to classify packers/protectors.",
                "region",
                0.79,
                region_lookup.get("packer_signature_block", {}).get("indicators", []),
            )

        hypotheses.sort(key=lambda item: (-float(item.get("confidence", 0.0)), str(item.get("stage", ""))))
        return hypotheses[:8]

    def _collect_import_api_hints(self, sample_path: str) -> List[str]:
        """Collect imported APIs as behavior simulation hints."""
        hints: List[str] = []
        if not PEFILE_AVAILABLE:
            return hints

        pe = None
        try:
            pe = pefile.PE(sample_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            )
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return hints

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = (
                    entry.dll.decode('utf-8', errors='ignore')
                    if entry.dll
                    else 'unknown'
                )
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', errors='ignore')
                        hints.append(f"{dll_name}!{api_name}")
        except Exception:
            return hints
        finally:
            try:
                if pe is not None:
                    pe.close()
            except Exception:
                pass

        return self._dedupe_preserve(hints)

    def _classify_api_signal(self, api_name: str, runtime: bool = False) -> Optional[Dict[str, Any]]:
        """Classify an API name into a behavioral category/capability bucket."""
        normalized = str(api_name).split('!')[-1].split('.')[-1].lower()
        if not normalized:
            return None

        process_markers = [
            "writeprocessmemory",
            "readprocessmemory",
            "openprocess",
            "setthreadcontext",
            "resumethread",
            "createremotethread",
            "virtualallocex",
        ]
        command_markers = ["createprocess", "shellexecute", "winexec"]
        network_markers = ["internetopen", "internetconnect", "httpsendrequest", "urldownloadtofile", "wsasocket", "connect", "send", "recv"]
        registry_markers = ["regsetvalue", "regcreatekey", "regopenkey", "regqueryvalue", "regdeletekey"]
        credential_markers = ["lsa", "cred", "sam"]
        loader_markers = ["getprocaddress", "loadlibrary", "getmodulehandle"]
        defense_markers = ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "ntquerysysteminformation"]

        if any(marker in normalized for marker in process_markers):
            return {
                "category": "process_injection",
                "capability": "process_injection",
                "confidence": 0.9 if runtime else 0.72,
            }
        if any(marker in normalized for marker in command_markers):
            return {
                "category": "command_execution",
                "capability": "command_execution",
                "confidence": 0.86 if runtime else 0.72,
            }
        if any(marker in normalized for marker in network_markers):
            return {
                "category": "network_communication",
                "capability": "network_communication",
                "confidence": 0.85 if runtime else 0.7,
            }
        if any(marker in normalized for marker in registry_markers):
            return {
                "category": "registry_modification",
                "capability": "registry_modification",
                "confidence": 0.82 if runtime else 0.66,
            }
        if any(marker in normalized for marker in credential_markers):
            return {
                "category": "credential_access",
                "capability": "credential_access",
                "confidence": 0.8 if runtime else 0.64,
            }
        if any(marker in normalized for marker in loader_markers):
            return {
                "category": "dynamic_resolution",
                "capability": None,
                "confidence": 0.93 if runtime else 0.74,
            }
        if any(marker in normalized for marker in defense_markers):
            return {
                "category": "defense_evasion",
                "capability": "defense_evasion",
                "confidence": 0.88 if runtime else 0.66,
            }

        return None

    def _record_api_observation(
        self,
        api_label: str,
        source_event_type: str,
        capabilities: Dict[str, int],
        iocs: Dict[str, List[str]],
        timeline: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register an API hint/trace into IOC, capability, and timeline buckets."""
        classification = self._classify_api_signal(api_label, runtime=source_event_type == "api_call")
        if classification is None:
            if source_event_type == "api_call":
                timeline.append(
                    {
                        "event_type": "api_call",
                        "category": "runtime_api",
                        "indicator": str(api_label),
                        "confidence": 0.74,
                    }
                )
            return

        capability = classification.get("capability")
        if capability:
            capabilities[capability] += 1
            iocs["suspicious_apis"].append(str(api_label))

        event_type = "api_call" if source_event_type == "api_call" else "api_hint"
        indicator = str(api_label)
        if metadata and metadata.get("pc"):
            indicator = f"{api_label} @ {metadata.get('pc')}"

        timeline.append(
            {
                "event_type": event_type,
                "category": str(classification.get("category", "runtime_api")),
                "indicator": indicator,
                "confidence": float(classification.get("confidence", 0.7)),
            }
        )

    def _scan_text_indicators(
        self,
        text_entries: List[str],
        iocs: Dict[str, List[str]],
        capabilities: Dict[str, int],
        timeline: List[Dict[str, Any]],
        event_type: str = "string_indicator",
        confidence_bias: float = 0.0,
    ) -> None:
        """Scan strings/arguments for IOC and behavior tokens."""
        url_regex = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
        ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        reg_regex = re.compile(r'HKEY_[A-Z_]+\\[^\s]+', re.IGNORECASE)
        pipe_regex = re.compile(r'\\\\\.\\pipe\\[^\s]+|\\\\pipe\\[^\s]+', re.IGNORECASE)
        command_regex = re.compile(
            r'cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe',
            re.IGNORECASE,
        )
        evade_regex = re.compile(
            r'vmprotect|themida|upx|anti[-_]?debug|isdebuggerpresent|kernel_code_integrity|testsign',
            re.IGNORECASE,
        )

        for entry in text_entries:
            value = str(entry).strip()
            if not value:
                continue

            for hit in url_regex.findall(value):
                iocs['urls'].append(hit)
                capabilities['network_communication'] += 1
                timeline.append(
                    {
                        'event_type': event_type,
                        'category': 'network_communication',
                        'indicator': hit,
                        'confidence': round(min(0.98, 0.69 + confidence_bias), 2),
                    }
                )

            for hit in ip_regex.findall(value):
                iocs['ip_addresses'].append(hit)
                capabilities['network_communication'] += 1

            for hit in reg_regex.findall(value):
                iocs['registry_keys'].append(hit)
                capabilities['registry_modification'] += 1
                timeline.append(
                    {
                        'event_type': event_type,
                        'category': 'registry_modification',
                        'indicator': hit,
                        'confidence': round(min(0.98, 0.64 + confidence_bias), 2),
                    }
                )

            for hit in pipe_regex.findall(value):
                iocs['pipes'].append(hit)
                capabilities['ipc_activity'] += 1
                timeline.append(
                    {
                        'event_type': event_type,
                        'category': 'ipc_activity',
                        'indicator': hit,
                        'confidence': round(min(0.98, 0.61 + confidence_bias), 2),
                    }
                )

            if command_regex.search(value):
                iocs['commands'].append(value)
                capabilities['command_execution'] += 1
                timeline.append(
                    {
                        'event_type': event_type,
                        'category': 'command_execution',
                        'indicator': value[:140],
                        'confidence': round(min(0.98, 0.65 + confidence_bias), 2),
                    }
                )

            if evade_regex.search(value):
                capabilities['defense_evasion'] += 1

    def _flatten_speakeasy_strings(self, value: Any, max_items: int = 1600) -> List[str]:
        """Flatten nested Speakeasy report string buckets into a simple string list."""
        flattened: List[str] = []

        def visit(node: Any) -> None:
            if len(flattened) >= max_items:
                return
            if isinstance(node, str):
                text = node.strip()
                if len(text) >= 5 and any(ch.isalnum() for ch in text):
                    flattened.append(text)
                return
            if isinstance(node, dict):
                for child in node.values():
                    visit(child)
                    if len(flattened) >= max_items:
                        break
                return
            if isinstance(node, (list, tuple, set)):
                for child in node:
                    visit(child)
                    if len(flattened) >= max_items:
                        break

        visit(value)
        return self._dedupe_preserve(flattened)[:max_items]

    def _build_runtime_string_entries(
        self,
        strings: List[str],
        start_offset: int,
    ) -> List[Dict[str, Any]]:
        """Convert runtime strings into synthetic offset-backed entries for context windowing."""
        entries: List[Dict[str, Any]] = []
        offset = max(0, start_offset)
        for value in strings:
            if len(entries) >= 800:
                break
            entries.append(
                {
                    "string": value,
                    "offset": offset,
                    "encoding": "runtime",
                }
            )
            offset += max(32, min(len(value) + 8, 128))
        return entries

    def _extract_speakeasy_api_calls(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract runtime API calls from a Speakeasy JSON report."""
        observed: List[Dict[str, Any]] = []
        entry_points = report.get("entry_points", [])
        if not isinstance(entry_points, list):
            return observed

        for index, entry in enumerate(entry_points):
            if not isinstance(entry, dict):
                continue
            apis = entry.get("apis", [])
            if not isinstance(apis, list):
                continue
            for api in apis:
                if not isinstance(api, dict):
                    continue
                api_name = str(api.get("api_name", "")).strip()
                if not api_name:
                    continue
                observed.append(
                    {
                        "api_name": api_name,
                        "args": [str(item) for item in list(api.get("args", []))[:8]],
                        "ret_val": api.get("ret_val"),
                        "pc": api.get("pc"),
                        "entry_point_index": index,
                        "entry_point_type": entry.get("ep_type"),
                    }
                )

        return observed[:600]

    def _merge_api_resolution_entries(
        self,
        baseline: List[Dict[str, Any]],
        runtime_entries: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Merge baseline import/string API resolution with runtime trace evidence."""
        priority = {
            "runtime_loader_trace": 4,
            "runtime_api_trace": 3,
            "hybrid_import_string": 2,
            "string_reference": 1,
            "import_table": 0,
        }
        merged: Dict[str, Dict[str, Any]] = {}

        for item in baseline + runtime_entries:
            api_name = str(item.get("api", "")).strip()
            if not api_name:
                continue
            key = api_name.lower()
            existing = merged.get(key)
            sources = self._dedupe_preserve(list(item.get("sources", [])))
            if existing is None:
                merged[key] = {
                    "api": api_name,
                    "provenance": item.get("provenance", "import_table"),
                    "confidence": float(item.get("confidence", 0.6)),
                    "sources": sources[:8],
                }
                continue

            existing["sources"] = self._dedupe_preserve(list(existing.get("sources", [])) + sources)[:8]
            existing["confidence"] = round(max(float(existing.get("confidence", 0.0)), float(item.get("confidence", 0.0))), 2)
            existing_priority = priority.get(str(existing.get("provenance", "")), -1)
            item_priority = priority.get(str(item.get("provenance", "")), -1)
            if item_priority >= existing_priority:
                existing["provenance"] = item.get("provenance", existing.get("provenance"))
                existing["api"] = api_name

        output = list(merged.values())
        output.sort(key=lambda item: (-float(item.get("confidence", 0.0)), str(item.get("api", "")).lower()))
        return output[:60]

    def _run_speakeasy_report(self, sample_path: str, timeout_sec: int) -> Dict[str, Any]:
        """Run Speakeasy in a subprocess and return the parsed JSON report."""
        speakeasy_probe = self._probe_speakeasy_emulator()
        if not speakeasy_probe.get("available"):
            raise RuntimeError(
                speakeasy_probe.get("error")
                or "Speakeasy emulator is not available in the current Python environment."
            )

        worker_dir = os.path.dirname(os.path.abspath(__file__))
        helper_code = """
import json
import os
import sys
import traceback
import warnings

payload = {
    "ok": False,
    "warnings": [],
}

try:
    worker_dir = __WORKER_DIR__
    if worker_dir and worker_dir not in sys.path:
        sys.path.insert(0, worker_dir)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        from speakeasy_compat import load_speakeasy_module

        speakeasy, compat_info = load_speakeasy_module()

    payload["warnings"] = [str(item.message) for item in caught]
    if not hasattr(speakeasy, "Speakeasy"):
        raise RuntimeError("Imported `speakeasy` module does not expose Speakeasy emulator API")

    sample_path = sys.argv[1]
    se = speakeasy.Speakeasy()
    module = se.load_module(sample_path)
    se.run_module(module, all_entrypoints=False, emulate_children=False)
    report_raw = se.get_json_report()
    report = json.loads(report_raw) if isinstance(report_raw, str) else report_raw

    payload["ok"] = True
    payload["module_type"] = type(module).__name__
    payload["module_path"] = compat_info.get("module_path") or getattr(speakeasy, "__file__", None)
    payload["package_root"] = compat_info.get("package_root")
    payload["import_mode"] = compat_info.get("import_mode")
    payload["warnings"].extend(list(compat_info.get("warnings", [])))
    payload["report"] = report
except Exception as exc:
    payload["error"] = str(exc)
    payload["traceback"] = traceback.format_exc(limit=10)

print(json.dumps(payload))
""".replace("__WORKER_DIR__", json.dumps(worker_dir))

        try:
            result = subprocess.run(
                [sys.executable, "-c", helper_code, sample_path],
                capture_output=True,
                text=True,
                timeout=max(10, int(timeout_sec)),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Speakeasy execution timed out after {max(10, int(timeout_sec))}s"
            ) from exc

        stdout = str(result.stdout or "").strip()
        stderr = str(result.stderr or "").strip()
        if result.returncode != 0:
            raise RuntimeError(
                f"Speakeasy subprocess exited with code {result.returncode}: {stderr or stdout or 'no output'}"
            )
        if not stdout:
            raise RuntimeError(
                f"Speakeasy subprocess returned no JSON output. stderr={stderr or 'none'}"
            )

        try:
            payload = json.loads(stdout.splitlines()[-1])
        except Exception as exc:
            raise RuntimeError(
                f"Failed to parse Speakeasy JSON output: {str(exc)}"
            ) from exc

        if not payload.get("ok"):
            raise RuntimeError(
                payload.get("error")
                or f"Speakeasy execution failed. stderr={stderr or 'none'}"
            )

        payload["warnings"] = self._dedupe_preserve(
            list(payload.get("warnings", []))
            + ([stderr] if stderr else [])
        )[:8]
        return payload

    def _execute_speakeasy_mode(
        self,
        sample_path: str,
        timeout_sec: int,
        network_policy: str,
        max_scan_bytes: int,
        sample_data: bytes,
        quick_string_entries: List[Dict[str, Any]],
        import_hints: List[str],
        inherited_warnings: List[str],
    ) -> Dict[str, Any]:
        """Execute user-mode emulation via Speakeasy and convert it into sandbox.execute payload."""
        speakeasy_payload = self._run_speakeasy_report(sample_path, timeout_sec)
        report = speakeasy_payload.get("report", {})
        runtime_api_calls = self._extract_speakeasy_api_calls(report)
        runtime_strings = self._flatten_speakeasy_strings(report.get("strings", {}))
        synthetic_base = max([int(item.get("offset", 0)) for item in quick_string_entries] + [0]) + 0x1000
        runtime_string_entries = self._build_runtime_string_entries(runtime_strings, synthetic_base)
        combined_string_entries = quick_string_entries + runtime_string_entries
        combined_strings = self._dedupe_preserve(
            [str(item.get("string", "")) for item in combined_string_entries if item.get("string")]
        )[:2500]

        iocs: Dict[str, List[str]] = {
            'urls': [],
            'ip_addresses': [],
            'registry_keys': [],
            'commands': [],
            'pipes': [],
            'suspicious_apis': [],
        }
        timeline: List[Dict[str, Any]] = []
        capabilities: Dict[str, int] = {
            'process_injection': 0,
            'command_execution': 0,
            'network_communication': 0,
            'registry_modification': 0,
            'ipc_activity': 0,
            'credential_access': 0,
            'defense_evasion': 0,
        }

        for api in import_hints:
            self._record_api_observation(api, "api_hint", capabilities, iocs, timeline)

        runtime_api_resolution: List[Dict[str, Any]] = []
        for call in runtime_api_calls:
            api_label = str(call.get("api_name", ""))
            self._record_api_observation(api_label, "api_call", capabilities, iocs, timeline, metadata=call)

            short_name = api_label.split('!')[-1].split('.')[-1]
            normalized = short_name.lower()
            if short_name:
                provenance = "runtime_loader_trace" if any(
                    marker in normalized for marker in ["getprocaddress", "loadlibrary", "getmodulehandle"]
                ) else "runtime_api_trace"
                confidence = 0.94 if provenance == "runtime_loader_trace" else 0.86
                if self._classify_api_signal(short_name, runtime=True):
                    confidence = min(0.97, confidence + 0.06)

                sources = []
                if call.get("pc"):
                    sources.append(f"pc:{call.get('pc')}")
                if call.get("entry_point_type"):
                    sources.append(f"entry:{call.get('entry_point_type')}#{call.get('entry_point_index')}")
                for arg in list(call.get("args", []))[:4]:
                    sources.append(f"arg:{str(arg)[:80]}")

                runtime_api_resolution.append(
                    {
                        "api": short_name,
                        "provenance": provenance,
                        "confidence": round(confidence, 2),
                        "sources": self._dedupe_preserve(sources)[:8],
                    }
                )

            self._scan_text_indicators(
                [str(arg) for arg in list(call.get("args", []))[:8]],
                iocs,
                capabilities,
                timeline,
                event_type="runtime_argument",
                confidence_bias=0.08,
            )

        self._scan_text_indicators(
            combined_strings,
            iocs,
            capabilities,
            timeline,
            event_type="runtime_string",
            confidence_bias=0.1,
        )

        baseline_api_resolution = self._build_api_resolution_trace(import_hints, combined_string_entries)
        api_resolution = self._merge_api_resolution_entries(baseline_api_resolution, runtime_api_resolution)
        memory_regions = self._build_memory_regions(combined_string_entries, import_hints, api_resolution)
        execution_hypotheses = self._build_execution_hypotheses(
            capabilities,
            api_resolution,
            memory_regions,
        )

        for region in memory_regions[:8]:
            timeline.append(
                {
                    'event_type': 'memory_region',
                    'category': str(region.get('region_type', 'memory_region')),
                    'indicator': (region.get('indicators') or [region.get('purpose', 'runtime region')])[0],
                    'confidence': float(region.get('confidence', 0.65)),
                }
            )

        for hypothesis in execution_hypotheses[:6]:
            timeline.append(
                {
                    'event_type': 'execution_stage',
                    'category': str(hypothesis.get('stage', 'execution_stage')),
                    'indicator': str(hypothesis.get('description', 'runtime execution hypothesis')),
                    'confidence': float(hypothesis.get('confidence', 0.7)),
                }
            )

        for key in list(iocs.keys()):
            iocs[key] = self._dedupe_preserve(iocs[key])[:120]

        capability_weights = {
            'process_injection': 42,
            'command_execution': 18,
            'network_communication': 20,
            'registry_modification': 16,
            'ipc_activity': 10,
            'credential_access': 18,
            'defense_evasion': 16,
        }

        score = 0
        for cap_name, cap_count in capabilities.items():
            if cap_count <= 0:
                continue
            score += min(capability_weights.get(cap_name, 8), cap_count * 8)

        if capabilities['process_injection'] > 0 and capabilities['network_communication'] > 0:
            score += 10
        if capabilities['command_execution'] > 0 and capabilities['network_communication'] > 0:
            score += 8
        score += min(18, len(runtime_api_calls) // 8 + len(execution_hypotheses) * 2 + len(memory_regions))
        score = max(0, min(score, 100))

        confidence = min(
            0.99,
            0.45
            + 0.06 * sum(1 for count in capabilities.values() if count > 0)
            + 0.004 * len(timeline)
            + 0.01 * min(len(runtime_api_calls), 20),
        )
        confidence = round(confidence, 2)

        if score >= 75:
            risk_level = 'high'
            classification = 'runtime_confirmed_malicious_behavior'
        elif score >= 40:
            risk_level = 'medium'
            classification = 'runtime_confirmed_suspicious_behavior'
        elif score > 0:
            risk_level = 'low'
            classification = 'runtime_observed_low_signal_behavior'
        else:
            risk_level = 'clean'
            classification = 'runtime_no_meaningful_behavior_observed'

        active_capabilities = [
            {
                'name': name,
                'evidence_count': count,
                'confidence': round(min(0.97, 0.5 + 0.08 * min(count, 4)), 2),
            }
            for name, count in capabilities.items()
            if count > 0
        ]
        active_capabilities = sorted(
            active_capabilities,
            key=lambda item: (item.get('evidence_count', 0), item.get('confidence', 0)),
            reverse=True,
        )

        inherited = self._dedupe_preserve(
            list(inherited_warnings or [])
            + list(speakeasy_payload.get("warnings", []))
        )[:12]

        return {
            'run_id': f"emu-{int(time.time() * 1000)}",
            'status': 'completed',
            'mode': 'speakeasy',
            'backend': 'speakeasy-emulator',
            'simulated': False,
            'timeout_sec': timeout_sec,
            'event_count': len(timeline),
            'timeline': timeline[:240],
            'iocs': iocs,
            'capabilities': active_capabilities,
            'memory_regions': memory_regions,
            'api_resolution': api_resolution,
            'execution_hypotheses': execution_hypotheses,
            'risk': {
                'score': score,
                'level': risk_level,
                'confidence': confidence,
            },
            'environment': {
                'network_policy': network_policy,
                'executed': True,
                'isolation': 'user_mode_emulation',
            },
            'evidence': {
                'import_hints': import_hints[:80],
                'strings_scanned': len(combined_strings),
                'string_samples': combined_strings[:40],
                'string_windows': self._build_context_windows(
                    combined_string_entries,
                    context_window_bytes=192,
                    max_context_windows=8,
                ),
                'api_resolution': api_resolution,
                'memory_regions': memory_regions,
                'runtime_api_calls': runtime_api_calls[:120],
                'speakeasy_report': {
                    'entry_point_count': len(report.get('entry_points', [])) if isinstance(report.get('entry_points', []), list) else 0,
                    'emu_version': report.get('emu_version'),
                    'report_version': report.get('report_version'),
                    'module_type': speakeasy_payload.get('module_type'),
                    'module_path': speakeasy_payload.get('module_path'),
                    'package_root': speakeasy_payload.get('package_root'),
                    'import_mode': speakeasy_payload.get('import_mode'),
                },
            },
            'inference': {
                'classification': classification,
                'summary': (
                    f"Speakeasy user-mode emulation observed {len(runtime_api_calls)} API call(s), "
                    f"recovered {len(active_capabilities)} capability cluster(s), and inferred "
                    f"{len(execution_hypotheses)} execution stage(s); risk={risk_level} "
                    f"(score={score}, confidence={confidence})."
                ),
            },
            'warnings': inherited,
            'metrics': {
                'elapsed_ms': 0,
                'scanned_bytes': len(sample_data),
                'max_scan_bytes': max_scan_bytes,
                'string_count': len(combined_strings),
                'import_hint_count': len(import_hints),
                'runtime_api_call_count': len(runtime_api_calls),
                'api_resolution_count': len(api_resolution),
                'memory_region_count': len(memory_regions),
                'execution_hypothesis_count': len(execution_hypotheses),
            },
        }

    def sandbox_execute(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Safe dynamic-analysis entrypoint (simulation-first).

        This endpoint does not execute the sample process directly; it derives
        behavior hypotheses from imports/strings and emits timeline-style events
        for downstream correlation.
        """
        start_time = time.time()
        mode = str(args.get('mode', 'safe_simulation')).lower()
        timeout_sec = int(args.get('timeout_sec', 20))
        network_policy = str(args.get('network', 'disabled')).lower()
        max_scan_bytes = int(args.get('max_scan_bytes', 5 * 1024 * 1024))

        if not os.path.isfile(sample_path):
            raise Exception(f"Sample file not found: {sample_path}")

        warnings: List[str] = []
        supported_modes = {'safe_simulation', 'memory_guided', 'speakeasy', 'live_local'}
        if mode not in supported_modes:
            warnings.append(f"Unsupported mode '{mode}', falling back to safe_simulation.")
            mode = 'safe_simulation'

        if mode == 'live_local':
            warnings.append(
                "Mode 'live_local' is not enabled in this build; executed with safe_simulation backend."
            )
            mode = 'safe_simulation'

        try:
            with open(sample_path, 'rb') as f:
                sample_data = f.read(max_scan_bytes)
        except Exception as e:
            raise Exception(f"Failed to read sample for simulation: {str(e)}")

        if len(sample_data) >= max_scan_bytes:
            warnings.append(
                f"Behavior simulation scanned first {max_scan_bytes} bytes only; indicators may be partial."
            )

        quick_string_entries = self._extract_quick_string_entries(sample_data)
        quick_strings = [str(item.get("string", "")) for item in quick_string_entries]
        import_hints = self._collect_import_api_hints(sample_path)
        api_resolution = self._build_api_resolution_trace(import_hints, quick_string_entries)

        if mode == 'speakeasy':
            try:
                speakeasy_result = self._execute_speakeasy_mode(
                    sample_path,
                    timeout_sec,
                    network_policy,
                    max_scan_bytes,
                    sample_data,
                    quick_string_entries,
                    import_hints,
                    warnings,
                )
                speakeasy_result.setdefault('metrics', {})
                speakeasy_result['metrics']['elapsed_ms'] = int((time.time() - start_time) * 1000)
                return speakeasy_result
            except Exception as e:
                warnings.append(
                    f"Speakeasy mode failed ({str(e)}); falling back to safe_simulation backend."
                )
                mode = 'safe_simulation'

        memory_regions: List[Dict[str, Any]] = []
        execution_hypotheses: List[Dict[str, Any]] = []

        iocs: Dict[str, List[str]] = {
            'urls': [],
            'ip_addresses': [],
            'registry_keys': [],
            'commands': [],
            'pipes': [],
            'suspicious_apis': [],
        }
        timeline: List[Dict[str, Any]] = []
        capabilities: Dict[str, int] = {
            'process_injection': 0,
            'command_execution': 0,
            'network_communication': 0,
            'registry_modification': 0,
            'ipc_activity': 0,
            'credential_access': 0,
            'defense_evasion': 0,
        }

        for api in import_hints:
            self._record_api_observation(api, "api_hint", capabilities, iocs, timeline)

        self._scan_text_indicators(quick_strings, iocs, capabilities, timeline)

        for key in list(iocs.keys()):
            iocs[key] = self._dedupe_preserve(iocs[key])[:80]

        if mode == 'memory_guided':
            warnings.append(
                'memory_guided mode does not spawn the sample; memory regions are inferred from image-backed strings and import evidence.'
            )
            memory_regions = self._build_memory_regions(quick_string_entries, import_hints, api_resolution)
            execution_hypotheses = self._build_execution_hypotheses(
                capabilities,
                api_resolution,
                memory_regions,
            )

            for region in memory_regions[:8]:
                timeline.append(
                    {
                        'event_type': 'memory_region',
                        'category': str(region.get('region_type', 'memory_region')),
                        'indicator': (region.get('indicators') or [region.get('purpose', 'memory-guided region')])[0],
                        'confidence': float(region.get('confidence', 0.6)),
                    }
                )

            for hypothesis in execution_hypotheses[:6]:
                timeline.append(
                    {
                        'event_type': 'execution_stage',
                        'category': str(hypothesis.get('stage', 'execution_stage')),
                        'indicator': str(hypothesis.get('description', 'memory-guided execution hypothesis')),
                        'confidence': float(hypothesis.get('confidence', 0.6)),
                    }
                )

        capability_weights = {
            'process_injection': 42,
            'command_execution': 18,
            'network_communication': 20,
            'registry_modification': 16,
            'ipc_activity': 10,
            'credential_access': 18,
            'defense_evasion': 16,
        }

        score = 0
        for cap_name, cap_count in capabilities.items():
            if cap_count <= 0:
                continue
            score += min(capability_weights.get(cap_name, 8), cap_count * 8)

        if capabilities['process_injection'] > 0 and capabilities['network_communication'] > 0:
            score += 10
        if capabilities['command_execution'] > 0 and capabilities['network_communication'] > 0:
            score += 8
        if mode == 'memory_guided':
            score += min(12, len(memory_regions) * 2 + len(execution_hypotheses))

        score = max(0, min(score, 100))
        confidence = min(0.95, 0.30 + 0.05 * sum(1 for count in capabilities.values() if count > 0) + 0.005 * len(timeline))
        if mode == 'memory_guided':
            confidence = min(0.98, confidence + 0.08 + 0.01 * min(len(api_resolution), 5))
        confidence = round(confidence, 2)

        if score >= 70:
            risk_level = 'high'
            classification = 'likely_malicious_behavior'
        elif score >= 35:
            risk_level = 'medium'
            classification = 'suspicious_behavior'
        elif score > 0:
            risk_level = 'low'
            classification = 'weak_behavioral_signal'
        else:
            risk_level = 'clean'
            classification = 'no_meaningful_behavioral_signal'

        active_capabilities = [
            {
                'name': name,
                'evidence_count': count,
                'confidence': round(min(0.95, 0.45 + 0.08 * min(count, 4)), 2),
            }
            for name, count in capabilities.items()
            if count > 0
        ]
        active_capabilities = sorted(
            active_capabilities,
            key=lambda item: (item.get('evidence_count', 0), item.get('confidence', 0)),
            reverse=True,
        )

        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            'run_id': f"sim-{int(time.time() * 1000)}",
            'status': 'completed',
            'mode': mode,
            'backend': 'static-memory-guided' if mode == 'memory_guided' else 'static-simulation',
            'simulated': True,
            'timeout_sec': timeout_sec,
            'event_count': len(timeline),
            'timeline': timeline[:200],
            'iocs': iocs,
            'capabilities': active_capabilities,
            'memory_regions': memory_regions,
            'api_resolution': api_resolution,
            'execution_hypotheses': execution_hypotheses,
            'risk': {
                'score': score,
                'level': risk_level,
                'confidence': confidence,
            },
            'environment': {
                'network_policy': network_policy,
                'executed': False,
                'isolation': 'image_memory_guided' if mode == 'memory_guided' else 'process_not_spawned',
            },
            'evidence': {
                'import_hints': import_hints[:80],
                'strings_scanned': len(quick_strings),
                'string_samples': quick_strings[:40],
                'string_windows': self._build_context_windows(
                    quick_string_entries,
                    context_window_bytes=192,
                    max_context_windows=8,
                ),
                'api_resolution': api_resolution,
                'memory_regions': memory_regions,
            },
            'inference': {
                'classification': classification,
                'summary': (
                    f"Simulation inferred {len(active_capabilities)} capability cluster(s)"
                    f"{'; memory-guided staging recovered ' + str(len(execution_hypotheses)) + ' execution hypothesis(es)' if mode == 'memory_guided' else ''}; "
                    f"risk={risk_level} (score={score}, confidence={confidence})."
                ),
            },
            'warnings': warnings,
            'metrics': {
                'elapsed_ms': elapsed_ms,
                'scanned_bytes': len(sample_data),
                'max_scan_bytes': max_scan_bytes,
                'string_count': len(quick_strings),
                'import_hint_count': len(import_hints),
                'api_resolution_count': len(api_resolution),
                'memory_region_count': len(memory_regions),
                'execution_hypothesis_count': len(execution_hypotheses),
            },
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """
        璁＄畻鏁版嵁鐨勭喌鍊?
        
        Args:
            data: 瀛楄妭鏁版嵁
            
        Returns:
            float: 鐔靛€?(0-8)
        """
        if not data:
            return 0.0
        
        # 缁熻瀛楄妭棰戠巼
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # 璁＄畻鐔?
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy

    def _pe_fingerprint_pefile(self, sample_path: str, fast: bool) -> Dict[str, Any]:
        """
        浣跨敤 pefile 鎻愬彇 PE 鎸囩汗
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            fast: 鏄惁浣跨敤蹇€熸ā寮?
            
        Returns:
            Dict: PE 鎸囩汗淇℃伅
        """
        pe = pefile.PE(sample_path)
        
        # 鍩虹淇℃伅
        result = {
            "machine": pe.FILE_HEADER.Machine,
            "machine_name": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "Unknown"),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "subsystem_name": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "timestamp_iso": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc).isoformat() if pe.FILE_HEADER.TimeDateStamp > 0 else None,
            "imphash": pe.get_imphash() if hasattr(pe, 'get_imphash') else None,
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
        }
        
        # 瀹屾暣妯″紡锛氭彁鍙栬妭鍖虹喌鍊煎拰绛惧悕淇℃伅
        if not fast:
            # 鑺傚尯鐔靛€?
            sections = []
            for section in pe.sections:
                section_data = section.get_data()
                entropy = self._calculate_entropy(section_data)
                sections.append({
                    "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(entropy, 2),
                    "characteristics": section.Characteristics
                })
            result["sections"] = sections
            
            # 鏁板瓧绛惧悕淇℃伅
            signature_info = None
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                try:
                    signature_info = {
                        "present": True,
                        "address": pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress,
                        "size": pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
                    }
                except:
                    signature_info = {"present": False}
            else:
                signature_info = {"present": False}
            
            result["signature"] = signature_info
        
        pe.close()
        return result

    def _pe_fingerprint_lief(self, sample_path: str, fast: bool) -> Dict[str, Any]:
        """
        浣跨敤 LIEF 鎻愬彇 PE 鎸囩汗锛堝鐢ㄨВ鏋愬櫒锛?
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            fast: 鏄惁浣跨敤蹇€熸ā寮?
            
        Returns:
            Dict: PE 鎸囩汗淇℃伅
        """
        binary = lief.parse(sample_path)
        
        if not binary or not isinstance(binary, lief.PE.Binary):
            raise ValueError("Not a valid PE file")
        
        # 鍩虹淇℃伅
        result = {
            "machine": binary.header.machine.value,
            "machine_name": str(binary.header.machine),
            "subsystem": binary.optional_header.subsystem.value,
            "subsystem_name": str(binary.optional_header.subsystem),
            "timestamp": binary.header.time_date_stamps,
            "timestamp_iso": datetime.fromtimestamp(binary.header.time_date_stamps, tz=timezone.utc).isoformat() if binary.header.time_date_stamps > 0 else None,
            "imphash": None,  # LIEF 涓嶇洿鎺ユ敮鎸?imphash
            "entry_point": binary.optional_header.addressof_entrypoint,
            "image_base": binary.optional_header.imagebase,
        }
        
        # 瀹屾暣妯″紡锛氭彁鍙栬妭鍖虹喌鍊?
        if not fast:
            sections = []
            for section in binary.sections:
                section_data = bytes(section.content)
                entropy = self._calculate_entropy(section_data)
                sections.append({
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "virtual_size": section.virtual_size,
                    "raw_size": section.size,
                    "entropy": round(entropy, 2),
                    "characteristics": section.characteristics
                })
            result["sections"] = sections
            
            # 鏁板瓧绛惧悕淇℃伅
            signature_info = {"present": binary.has_signature}
            if binary.has_signature:
                try:
                    signature_info["verified"] = binary.verify_signature()
                except:
                    signature_info["verified"] = False
            
            result["signature"] = signature_info
        
        return result


    def _classify_capa_group(self, namespace: Optional[str], rule_name: str) -> str:
        lowered = f"{namespace or ''} {rule_name}".lower()
        if 'service' in lowered or 'persistence' in lowered:
            return 'service_and_persistence'
        if 'http' in lowered or 'network' in lowered or 'socket' in lowered:
            return 'network_communication'
        if 'registry' in lowered:
            return 'registry_modification'
        if 'credential' in lowered or 'password' in lowered or 'token' in lowered:
            return 'credential_access'
        if 'process' in lowered or 'inject' in lowered or 'remote thread' in lowered:
            return 'process_manipulation'
        if 'file' in lowered or 'filesystem' in lowered or 'resource' in lowered:
            return 'file_and_resource_access'
        if 'crypto' in lowered or 'encrypt' in lowered or 'decrypt' in lowered:
            return 'cryptography'
        if 'debugger' in lowered or 'anti-analysis' in lowered or 'evasion' in lowered:
            return 'defense_evasion'
        if 'execute' in lowered or 'command' in lowered or 'shell' in lowered:
            return 'command_execution'
        if 'com' in lowered or 'class factory' in lowered or 'dll' in lowered:
            return 'component_activation'
        return 'general_capability'

    def _collect_capa_evidence_strings(self, value: Any, max_items: int = 8) -> List[str]:
        evidence: List[str] = []

        def visit(node: Any) -> None:
            if len(evidence) >= max_items:
                return
            if isinstance(node, dict):
                for key, item in node.items():
                    if len(evidence) >= max_items:
                        return
                    if isinstance(item, (dict, list)):
                        visit(item)
                        continue
                    if isinstance(item, (str, int, float)):
                        text = str(item).strip()
                        if not text or len(text) > 160:
                            continue
                        lowered_key = str(key).lower()
                        if lowered_key in {'success', 'node', 'type'}:
                            continue
                        if re.fullmatch(r'0x[0-9a-f]+', text.lower()) or re.search(r'[A-Za-z]', text):
                            evidence.append(text)
            elif isinstance(node, list):
                for item in node:
                    visit(item)
                    if len(evidence) >= max_items:
                        return
            elif isinstance(node, str):
                text = node.strip()
                if text and len(text) <= 160 and re.search(r'[A-Za-z]', text):
                    evidence.append(text)

        visit(value)
        return self._dedupe_preserve(evidence)[:max_items]

    def pe_fingerprint(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        鎻愬彇 PE 鏂囦欢鎸囩汗淇℃伅
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            args: 鍙傛暟瀛楀吀锛屽寘鍚?fast (bool) 鍙傛暟
            
        Returns:
            Dict: PE 鎸囩汗淇℃伅
            
        Raises:
            Exception: 瑙ｆ瀽澶辫触鏃舵姏鍑哄紓甯?
        """
        fast = args.get("fast", False)
        
        # 灏濊瘯浣跨敤 pefile
        if PEFILE_AVAILABLE:
            try:
                return self._pe_fingerprint_pefile(sample_path, fast)
            except Exception as e:
                # pefile 澶辫触锛屽皾璇?LIEF
                if LIEF_AVAILABLE:
                    try:
                        result = self._pe_fingerprint_lief(sample_path, fast)
                        result["_parser"] = "lief"
                        result["_pefile_error"] = str(e)
                        return result
                    except Exception as lief_error:
                        raise Exception(f"Both parsers failed. pefile: {str(e)}, lief: {str(lief_error)}")
                else:
                    raise Exception(f"pefile failed and LIEF not available: {str(e)}")
        
        # 濡傛灉 pefile 涓嶅彲鐢紝鐩存帴浣跨敤 LIEF
        elif LIEF_AVAILABLE:
            try:
                result = self._pe_fingerprint_lief(sample_path, fast)
                result["_parser"] = "lief"
                return result
            except Exception as e:
                raise Exception(f"LIEF parser failed: {str(e)}")
        
        else:
            raise Exception("No PE parser available (neither pefile nor LIEF)")

    def _pe_imports_extract_pefile(self, sample_path: str, group_by_dll: bool) -> Dict[str, Any]:
        """
        浣跨敤 pefile 鎻愬彇瀵煎叆琛?
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            group_by_dll: 鏄惁鎸?DLL 鍒嗙粍
            
        Returns:
            Dict: 瀵煎叆琛ㄤ俊鎭?
        """
        pe = pefile.PE(sample_path)
        
        imports = {}
        delayed_imports = {}
        
        # 鎻愬彇鏅€氬鍏ヨ〃
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore') if isinstance(entry.dll, bytes) else entry.dll
                
                if group_by_dll:
                    imports[dll_name] = []
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore') if isinstance(imp.name, bytes) else imp.name
                        else:
                            func_name = f"Ordinal_{imp.ordinal}"
                        imports[dll_name].append(func_name)
                else:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore') if isinstance(imp.name, bytes) else imp.name
                        else:
                            func_name = f"Ordinal_{imp.ordinal}"
                        
                        if dll_name not in imports:
                            imports[dll_name] = []
                        imports[dll_name].append(func_name)
        
        # 鎻愬彇寤惰繜鍔犺浇瀵煎叆琛?
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore') if isinstance(entry.dll, bytes) else entry.dll
                
                delayed_imports[dll_name] = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore') if isinstance(imp.name, bytes) else imp.name
                    else:
                        func_name = f"Ordinal_{imp.ordinal}"
                    delayed_imports[dll_name].append(func_name)
        
        pe.close()
        
        result = {
            "imports": imports,
            "delayed_imports": delayed_imports,
            "total_dlls": len(imports),
            "total_delayed_dlls": len(delayed_imports),
            "total_functions": sum(len(funcs) for funcs in imports.values()),
            "total_delayed_functions": sum(len(funcs) for funcs in delayed_imports.values())
        }
        
        return result

    def _pe_imports_extract_lief(self, sample_path: str, group_by_dll: bool) -> Dict[str, Any]:
        """
        浣跨敤 LIEF 鎻愬彇瀵煎叆琛紙澶囩敤瑙ｆ瀽鍣級
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            group_by_dll: 鏄惁鎸?DLL 鍒嗙粍
            
        Returns:
            Dict: 瀵煎叆琛ㄤ俊鎭?
        """
        binary = lief.parse(sample_path)
        
        if not binary or not isinstance(binary, lief.PE.Binary):
            raise ValueError("Not a valid PE file")
        
        imports = {}
        delayed_imports = {}
        
        # 鎻愬彇鏅€氬鍏ヨ〃
        for imp in binary.imports:
            dll_name = imp.name
            
            if group_by_dll:
                imports[dll_name] = []
                for entry in imp.entries:
                    if entry.is_ordinal:
                        func_name = f"Ordinal_{entry.ordinal}"
                    else:
                        func_name = entry.name
                    imports[dll_name].append(func_name)
            else:
                for entry in imp.entries:
                    if entry.is_ordinal:
                        func_name = f"Ordinal_{entry.ordinal}"
                    else:
                        func_name = entry.name
                    
                    if dll_name not in imports:
                        imports[dll_name] = []
                    imports[dll_name].append(func_name)
        
        # LIEF 涔熸敮鎸佸欢杩熷姞杞藉鍏?
        if hasattr(binary, 'delay_imports'):
            for imp in binary.delay_imports:
                dll_name = imp.name
                delayed_imports[dll_name] = []
                
                for entry in imp.entries:
                    if entry.is_ordinal:
                        func_name = f"Ordinal_{entry.ordinal}"
                    else:
                        func_name = entry.name
                    delayed_imports[dll_name].append(func_name)
        
        result = {
            "imports": imports,
            "delayed_imports": delayed_imports,
            "total_dlls": len(imports),
            "total_delayed_dlls": len(delayed_imports),
            "total_functions": sum(len(funcs) for funcs in imports.values()),
            "total_delayed_functions": sum(len(funcs) for funcs in delayed_imports.values())
        }
        
        return result

    def pe_imports_extract(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        鎻愬彇 PE 鏂囦欢鐨勫鍏ヨ〃
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            args: 鍙傛暟瀛楀吀锛屽寘鍚?group_by_dll (bool) 鍙傛暟
            
        Returns:
            Dict: 瀵煎叆琛ㄤ俊鎭紝鍖呭惈鏅€氬鍏ュ拰寤惰繜鍔犺浇瀵煎叆
            
        Raises:
            Exception: 瑙ｆ瀽澶辫触鏃舵姏鍑哄紓甯?
        """
        group_by_dll = args.get("group_by_dll", True)
        
        # 灏濊瘯浣跨敤 pefile
        if PEFILE_AVAILABLE:
            try:
                return self._pe_imports_extract_pefile(sample_path, group_by_dll)
            except Exception as e:
                # pefile 澶辫触锛屽皾璇?LIEF
                if LIEF_AVAILABLE:
                    try:
                        result = self._pe_imports_extract_lief(sample_path, group_by_dll)
                        result["_parser"] = "lief"
                        result["_pefile_error"] = str(e)
                        return result
                    except Exception as lief_error:
                        raise Exception(f"Both parsers failed. pefile: {str(e)}, lief: {str(lief_error)}")
                else:
                    raise Exception(f"pefile failed and LIEF not available: {str(e)}")
        
        # 濡傛灉 pefile 涓嶅彲鐢紝鐩存帴浣跨敤 LIEF
        elif LIEF_AVAILABLE:
            try:
                result = self._pe_imports_extract_lief(sample_path, group_by_dll)
                result["_parser"] = "lief"
                return result
            except Exception as e:
                raise Exception(f"LIEF parser failed: {str(e)}")
        
        else:
            raise Exception("No PE parser available (neither pefile nor LIEF)")

    def _pe_exports_extract_pefile(self, sample_path: str) -> Dict[str, Any]:
        """
        浣跨敤 pefile 鎻愬彇瀵煎嚭琛?
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            
        Returns:
            Dict: 瀵煎嚭琛ㄤ俊鎭?
        """
        pe = pefile.PE(sample_path)
        
        exports = []
        forwarders = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    "ordinal": exp.ordinal,
                    "address": exp.address,
                    "name": None
                }
                
                # 鎻愬彇鍑芥暟鍚?
                if exp.name:
                    export_info["name"] = exp.name.decode('utf-8', errors='ignore') if isinstance(exp.name, bytes) else exp.name
                
                # 妫€鏌ユ槸鍚︽槸杞彂鍣紙forwarder锛?
                if exp.forwarder:
                    forwarder_name = exp.forwarder.decode('utf-8', errors='ignore') if isinstance(exp.forwarder, bytes) else exp.forwarder
                    export_info["forwarder"] = forwarder_name
                    forwarders.append(export_info)
                else:
                    exports.append(export_info)
        
        pe.close()
        
        result = {
            "exports": exports,
            "forwarders": forwarders,
            "total_exports": len(exports),
            "total_forwarders": len(forwarders)
        }
        
        return result

    def _pe_exports_extract_lief(self, sample_path: str) -> Dict[str, Any]:
        """
        浣跨敤 LIEF 鎻愬彇瀵煎嚭琛紙澶囩敤瑙ｆ瀽鍣級
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            
        Returns:
            Dict: 瀵煎嚭琛ㄤ俊鎭?
        """
        binary = lief.parse(sample_path)
        
        if not binary or not isinstance(binary, lief.PE.Binary):
            raise ValueError("Not a valid PE file")
        
        exports = []
        forwarders = []
        
        if binary.has_exports:
            export_dir = binary.get_export()
            
            for entry in export_dir.entries:
                export_info = {
                    "ordinal": entry.ordinal,
                    "address": entry.address,
                    "name": entry.name if entry.name else None
                }
                
                # LIEF 閫氳繃妫€鏌?is_extern 鏉ュ垽鏂槸鍚︽槸杞彂鍣?
                if entry.is_extern:
                    # 杞彂鍣ㄧ殑鍦板潃鎸囧悜鍙︿竴涓?DLL 鐨勫嚱鏁?
                    export_info["forwarder"] = entry.name  # LIEF 涓浆鍙戝櫒淇℃伅瀛樺偍鍦?name 涓?
                    forwarders.append(export_info)
                else:
                    exports.append(export_info)
        
        result = {
            "exports": exports,
            "forwarders": forwarders,
            "total_exports": len(exports),
            "total_forwarders": len(forwarders)
        }
        
        return result

    def pe_exports_extract(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        鎻愬彇 PE 鏂囦欢鐨勫鍑鸿〃
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            args: 鍙傛暟瀛楀吀锛堝綋鍓嶆湭浣跨敤锛?
            
        Returns:
            Dict: 瀵煎嚭琛ㄤ俊鎭紝鍖呭惈瀵煎嚭鍑芥暟鍜岃浆鍙戝櫒
            
        Raises:
            Exception: 瑙ｆ瀽澶辫触鏃舵姏鍑哄紓甯?
        """
        # 灏濊瘯浣跨敤 pefile
        if PEFILE_AVAILABLE:
            try:
                return self._pe_exports_extract_pefile(sample_path)
            except Exception as e:
                # pefile 澶辫触锛屽皾璇?LIEF
                if LIEF_AVAILABLE:
                    try:
                        result = self._pe_exports_extract_lief(sample_path)
                        result["_parser"] = "lief"
                        result["_pefile_error"] = str(e)
                        return result
                    except Exception as lief_error:
                        raise Exception(f"Both parsers failed. pefile: {str(e)}, lief: {str(lief_error)}")
                else:
                    raise Exception(f"pefile failed and LIEF not available: {str(e)}")
        
        # 濡傛灉 pefile 涓嶅彲鐢紝鐩存帴浣跨敤 LIEF
        elif LIEF_AVAILABLE:
            try:
                result = self._pe_exports_extract_lief(sample_path)
                result["_parser"] = "lief"
                return result
            except Exception as e:
                raise Exception(f"LIEF parser failed: {str(e)}")
        
        else:
            raise Exception("No PE parser available (neither pefile nor LIEF)")


    def strings_extract(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        鎻愬彇鏂囦欢涓殑鍙瀛楃涓诧紙ASCII 鍜?Unicode锛?
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            args: 鍙傛暟瀛楀吀
                - min_len: 鏈€灏忓瓧绗︿覆闀垮害锛堥粯璁わ細4锛?
                - encoding: 缂栫爜绫诲瀷 ('ascii', 'unicode', 'all'锛岄粯璁わ細'all')
            
        Returns:
            Dict: 瀛楃涓插垪琛ㄥ強鍏跺亸绉婚噺
                {
                    "strings": [
                        {"offset": int, "string": str, "encoding": str},
                        ...
                    ],
                    "count": int,
                    "min_len": int,
                    "encoding_filter": str
                }
            
        Raises:
            Exception: 鏂囦欢璇诲彇澶辫触鏃舵姏鍑哄紓甯?
        """
        min_len = args.get('min_len', 4)
        encoding_filter = args.get('encoding', 'all')
        max_strings = args.get('max_strings', 500)
        max_string_length = args.get('max_string_length', 512)
        context_window_bytes = args.get('context_window_bytes', 1024)
        max_context_windows = args.get('max_context_windows', 12)
        category_filter = args.get('category_filter', 'all')
        scan_mode = args.get('scan_mode', 'full')
        max_scan_bytes = args.get('max_scan_bytes')
        
        # 楠岃瘉鍙傛暟
        if min_len < 1:
            raise ValueError("min_len must be at least 1")
        
        if encoding_filter not in ['ascii', 'unicode', 'all']:
            raise ValueError(f"Invalid encoding: {encoding_filter}. Must be 'ascii', 'unicode', or 'all'")

        if scan_mode not in ['preview', 'full']:
            raise ValueError("scan_mode must be 'preview' or 'full'")

        if max_strings is None:
            max_strings = 500
        if not isinstance(max_strings, int) or max_strings < 1:
            raise ValueError("max_strings must be a positive integer")

        if max_string_length is None:
            max_string_length = 512
        if not isinstance(max_string_length, int) or max_string_length < 16:
            raise ValueError("max_string_length must be an integer >= 16")

        if context_window_bytes is None:
            context_window_bytes = 1024
        if not isinstance(context_window_bytes, int) or context_window_bytes < 32:
            raise ValueError("context_window_bytes must be an integer >= 32")

        if max_context_windows is None:
            max_context_windows = 12
        if not isinstance(max_context_windows, int) or max_context_windows < 1:
            raise ValueError("max_context_windows must be a positive integer")

        if max_scan_bytes is not None:
            if not isinstance(max_scan_bytes, int) or max_scan_bytes < 65536:
                raise ValueError("max_scan_bytes must be an integer >= 65536")

        valid_category_filters = [
            'all',
            'ioc',
            'url',
            'network',
            'ipc',
            'command',
            'registry',
            'file_path',
            'suspicious_api',
        ]
        if category_filter not in valid_category_filters:
            raise ValueError(
                f"Invalid category_filter: {category_filter}. Must be one of {valid_category_filters}"
            )
        
        # 璇诲彇鏂囦欢鍐呭
        try:
            with open(sample_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            raise Exception(f"Failed to read file: {str(e)}")
        
        segment_specs = self._build_string_scan_segments(data, scan_mode, max_scan_bytes)
        scan_bytes = sum(len(segment_data) for _, segment_data in segment_specs)
        strings_list = []

        for base_offset, segment_data in segment_specs:
            # 鎻愬彇 ASCII 瀛楃涓?
            if encoding_filter in ['ascii', 'all']:
                ascii_strings = self._extract_ascii_strings(segment_data, min_len)
                strings_list.extend(self._offset_extracted_strings(ascii_strings, base_offset))
            
            # 鎻愬彇 Unicode (UTF-16LE) 瀛楃涓?
            if encoding_filter in ['unicode', 'all']:
                unicode_strings = self._extract_unicode_strings(segment_data, min_len)
                strings_list.extend(self._offset_extracted_strings(unicode_strings, base_offset))
            
            # 濡傛灉 encoding='all'锛屽皾璇曞叾浠栫紪鐮?
            if encoding_filter == 'all':
                # 鎻愬彇 UTF-8 瀛楃涓?
                utf8_strings = self._extract_utf8_strings(segment_data, min_len)
                strings_list.extend(self._offset_extracted_strings(utf8_strings, base_offset))
                
                # 鎻愬彇 GBK 瀛楃涓诧紙涓枃缂栫爜锛?
                gbk_strings = self._extract_gbk_strings(segment_data, min_len)
                strings_list.extend(self._offset_extracted_strings(gbk_strings, base_offset))
        
        # 鎸夊亸绉婚噺鎺掑簭骞跺幓閲?
        all_strings = self._deduplicate_strings(strings_list)
        normalized_strings = self._normalize_extracted_strings(
            all_strings,
            min_len=min_len,
            max_string_length=max_string_length
        )
        deduped_by_content = self._deduplicate_by_content(normalized_strings)
        filtered_strings = self._filter_strings_by_category(deduped_by_content, category_filter)
        prioritized = self._prioritize_strings(filtered_strings)
        truncated = len(prioritized) > max_strings
        selected_strings = prioritized[:max_strings]
        # Keep backward-compatible output order by file offset.
        returned_strings = sorted(selected_strings, key=lambda item: item.get("offset", 0))
        summary = self._build_strings_summary(
            prioritized,
            context_window_bytes=context_window_bytes,
            max_context_windows=max_context_windows
        )

        return {
            "strings": returned_strings,
            "count": len(returned_strings),
            "total_count": len(filtered_strings),
            "pre_filter_count": len(deduped_by_content),
            "truncated": truncated,
            "max_strings": max_strings,
            "max_string_length": max_string_length,
            "context_window_bytes": context_window_bytes,
            "max_context_windows": max_context_windows,
            "min_len": min_len,
            "encoding_filter": encoding_filter,
            "category_filter": category_filter,
            "scan_mode": scan_mode,
            "scan_bytes": scan_bytes,
            "sampled": scan_bytes < len(data),
            "summary": summary
        }

    def _offset_extracted_strings(self, strings: List[Dict[str, Any]], base_offset: int) -> List[Dict[str, Any]]:
        """
        Apply segment base offsets so preview scanning can sample file regions
        while still reporting original file offsets.
        """
        if base_offset <= 0:
            return strings
        adjusted = []
        for item in strings:
            cloned = dict(item)
            cloned["offset"] = int(cloned.get("offset", 0)) + base_offset
            adjusted.append(cloned)
        return adjusted

    def _build_string_scan_segments(
        self,
        data: bytes,
        scan_mode: str,
        max_scan_bytes: Optional[int]
    ) -> List[Tuple[int, bytes]]:
        """
        Build bounded scan segments for preview mode so string extraction does
        not always read and regex-scan the full sample before truncation.
        """
        total_size = len(data)
        if scan_mode != 'preview':
            return [(0, data)]
        if max_scan_bytes is None:
            max_scan_bytes = 1024 * 1024
        if total_size <= max_scan_bytes:
            return [(0, data)]

        budget = max(65536, min(max_scan_bytes, total_size))
        if budget <= 256 * 1024:
            return [(0, data[:budget])]

        head_size = max(65536, budget // 3)
        tail_size = max(65536, budget // 3)
        middle_size = max(65536, budget - head_size - tail_size)

        if head_size + middle_size + tail_size >= total_size:
            return [(0, data)]

        middle_start = max(head_size, (total_size // 2) - (middle_size // 2))
        tail_start = max(middle_start + middle_size, total_size - tail_size)

        segments = [
            (0, head_size),
            (middle_start, middle_start + middle_size),
            (tail_start, total_size),
        ]

        merged_segments = []
        for start, end in segments:
            start = max(0, min(start, total_size))
            end = max(start, min(end, total_size))
            if not merged_segments:
                merged_segments.append([start, end])
                continue
            prev_start, prev_end = merged_segments[-1]
            if start <= prev_end:
                merged_segments[-1][1] = max(prev_end, end)
            else:
                merged_segments.append([start, end])

        return [(start, data[start:end]) for start, end in merged_segments if end > start]
    
    def _extract_ascii_strings(self, data: bytes, min_len: int) -> List[Dict[str, Any]]:
        """
        鎻愬彇 ASCII 瀛楃涓?
        
        Args:
            data: 鏂囦欢鏁版嵁
            min_len: 鏈€灏忓瓧绗︿覆闀垮害
            
        Returns:
            List[Dict]: ASCII 瀛楃涓插垪琛?
        """
        import re
        
        strings = []
        # ASCII 鍙墦鍗板瓧绗﹁寖鍥达細0x20-0x7E
        pattern = b'[\x20-\x7E]{' + str(min_len).encode() + b',}'
        
        for match in re.finditer(pattern, data):
            offset = match.start()
            string_bytes = match.group()
            try:
                string_value = string_bytes.decode('ascii')
                strings.append({
                    "offset": offset,
                    "string": string_value,
                    "encoding": "ascii"
                })
            except UnicodeDecodeError:
                # 璺宠繃鏃犳硶瑙ｇ爜鐨勫瓧绗︿覆
                continue
        
        return strings
    
    def _extract_unicode_strings(self, data: bytes, min_len: int) -> List[Dict[str, Any]]:
        """
        鎻愬彇 Unicode (UTF-16LE) 瀛楃涓?
        
        Args:
            data: 鏂囦欢鏁版嵁
            min_len: 鏈€灏忓瓧绗︿覆闀垮害
            
        Returns:
            List[Dict]: Unicode 瀛楃涓插垪琛?
        """
        import re
        
        strings = []
        # UTF-16LE 妯″紡锛氬彲鎵撳嵃瀛楃鍚庤窡 \x00
        # 鍖归厤鑷冲皯 min_len 涓瓧绗?
        pattern = b'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + b',}'
        
        for match in re.finditer(pattern, data):
            offset = match.start()
            string_bytes = match.group()
            try:
                string_value = string_bytes.decode('utf-16le')
                strings.append({
                    "offset": offset,
                    "string": string_value,
                    "encoding": "utf-16le"
                })
            except UnicodeDecodeError:
                # 璺宠繃鏃犳硶瑙ｇ爜鐨勫瓧绗︿覆
                continue
        
        return strings
    
    def _extract_utf8_strings(self, data: bytes, min_len: int) -> List[Dict[str, Any]]:
        """
        鎻愬彇 UTF-8 瀛楃涓?
        
        Args:
            data: 鏂囦欢鏁版嵁
            min_len: 鏈€灏忓瓧绗︿覆闀垮害
            
        Returns:
            List[Dict]: UTF-8 瀛楃涓插垪琛?
        """
        strings = []
        current_string = bytearray()
        start_offset = 0
        
        i = 0
        while i < len(data):
            byte = data[i]
            
            # 灏濊瘯瑙ｆ瀽 UTF-8 瀛楃
            if byte < 0x80:  # ASCII 鑼冨洿
                if 0x20 <= byte <= 0x7E:  # 鍙墦鍗?ASCII
                    if not current_string:
                        start_offset = i
                    current_string.append(byte)
                else:
                    # 闈炲彲鎵撳嵃瀛楃锛岀粨鏉熷綋鍓嶅瓧绗︿覆
                    if len(current_string) >= min_len:
                        try:
                            string_value = current_string.decode('utf-8')
                            strings.append({
                                "offset": start_offset,
                                "string": string_value,
                                "encoding": "utf-8"
                            })
                        except UnicodeDecodeError:
                            pass
                    current_string = bytearray()
                i += 1
            elif byte >= 0xC0:  # 澶氬瓧鑺?UTF-8 搴忓垪寮€濮?
                # 纭畾瀛楄妭鏁?
                if byte < 0xE0:
                    char_len = 2
                elif byte < 0xF0:
                    char_len = 3
                elif byte < 0xF8:
                    char_len = 4
                else:
                    # 鏃犳晥鐨?UTF-8 璧峰瀛楄妭
                    if len(current_string) >= min_len:
                        try:
                            string_value = current_string.decode('utf-8')
                            strings.append({
                                "offset": start_offset,
                                "string": string_value,
                                "encoding": "utf-8"
                            })
                        except UnicodeDecodeError:
                            pass
                    current_string = bytearray()
                    i += 1
                    continue
                
                # 妫€鏌ユ槸鍚︽湁瓒冲鐨勫瓧鑺?
                if i + char_len <= len(data):
                    char_bytes = data[i:i+char_len]
                    try:
                        # 楠岃瘉鏄惁涓烘湁鏁堢殑 UTF-8
                        char_bytes.decode('utf-8')
                        if not current_string:
                            start_offset = i
                        current_string.extend(char_bytes)
                        i += char_len
                    except UnicodeDecodeError:
                        # 鏃犳晥鐨?UTF-8 搴忓垪
                        if len(current_string) >= min_len:
                            try:
                                string_value = current_string.decode('utf-8')
                                strings.append({
                                    "offset": start_offset,
                                    "string": string_value,
                                    "encoding": "utf-8"
                                })
                            except UnicodeDecodeError:
                                pass
                        current_string = bytearray()
                        i += 1
                else:
                    # 鏂囦欢缁撴潫
                    break
            else:
                # 鏃犳晥鐨?UTF-8 瀛楄妭
                if len(current_string) >= min_len:
                    try:
                        string_value = current_string.decode('utf-8')
                        strings.append({
                            "offset": start_offset,
                            "string": string_value,
                            "encoding": "utf-8"
                        })
                    except UnicodeDecodeError:
                        pass
                current_string = bytearray()
                i += 1
        
        # 澶勭悊鏈€鍚庝竴涓瓧绗︿覆
        if len(current_string) >= min_len:
            try:
                string_value = current_string.decode('utf-8')
                strings.append({
                    "offset": start_offset,
                    "string": string_value,
                    "encoding": "utf-8"
                })
            except UnicodeDecodeError:
                pass
        
        return strings
    
    def _extract_gbk_strings(self, data: bytes, min_len: int) -> List[Dict[str, Any]]:
        """
        鎻愬彇 GBK 缂栫爜瀛楃涓诧紙涓枃锛?
        
        Args:
            data: 鏂囦欢鏁版嵁
            min_len: 鏈€灏忓瓧绗︿覆闀垮害
            
        Returns:
            List[Dict]: GBK 瀛楃涓插垪琛?
        """
        strings = []
        current_string = bytearray()
        start_offset = 0
        
        i = 0
        while i < len(data):
            byte = data[i]
            
            # ASCII 鑼冨洿
            if byte < 0x80:
                if 0x20 <= byte <= 0x7E:  # 鍙墦鍗?ASCII
                    if not current_string:
                        start_offset = i
                    current_string.append(byte)
                else:
                    # 闈炲彲鎵撳嵃瀛楃锛岀粨鏉熷綋鍓嶅瓧绗︿覆
                    if len(current_string) >= min_len:
                        try:
                            string_value = current_string.decode('gbk')
                            strings.append({
                                "offset": start_offset,
                                "string": string_value,
                                "encoding": "gbk"
                            })
                        except (UnicodeDecodeError, LookupError):
                            pass
                    current_string = bytearray()
                i += 1
            elif 0x81 <= byte <= 0xFE:  # GBK 鍙屽瓧鑺傚瓧绗︾涓€瀛楄妭
                if i + 1 < len(data):
                    second_byte = data[i + 1]
                    if 0x40 <= second_byte <= 0xFE and second_byte != 0x7F:
                        # 鏈夋晥鐨?GBK 鍙屽瓧鑺傚瓧绗?
                        if not current_string:
                            start_offset = i
                        current_string.extend([byte, second_byte])
                        i += 2
                    else:
                        # 鏃犳晥鐨?GBK 搴忓垪
                        if len(current_string) >= min_len:
                            try:
                                string_value = current_string.decode('gbk')
                                strings.append({
                                    "offset": start_offset,
                                    "string": string_value,
                                    "encoding": "gbk"
                                })
                            except (UnicodeDecodeError, LookupError):
                                pass
                        current_string = bytearray()
                        i += 1
                else:
                    # 鏂囦欢缁撴潫
                    break
            else:
                # 鏃犳晥鐨?GBK 瀛楄妭
                if len(current_string) >= min_len:
                    try:
                        string_value = current_string.decode('gbk')
                        strings.append({
                            "offset": start_offset,
                            "string": string_value,
                            "encoding": "gbk"
                        })
                    except (UnicodeDecodeError, LookupError):
                        pass
                current_string = bytearray()
                i += 1
        
        # 澶勭悊鏈€鍚庝竴涓瓧绗︿覆
        if len(current_string) >= min_len:
            try:
                string_value = current_string.decode('gbk')
                strings.append({
                    "offset": start_offset,
                    "string": string_value,
                    "encoding": "gbk"
                })
            except (UnicodeDecodeError, LookupError):
                pass
        
        return strings
    
    def _deduplicate_strings(self, strings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        鍘婚噸瀛楃涓插垪琛紙淇濈暀鍋忕Щ閲忔渶灏忕殑锛?
        
        Args:
            strings_list: 瀛楃涓插垪琛?
            
        Returns:
            List[Dict]: 鍘婚噸鍚庣殑瀛楃涓插垪琛紝鎸夊亸绉婚噺鎺掑簭
        """
        # 浣跨敤瀛楀吀鍘婚噸锛岄敭涓?(offset, string)锛屼繚鐣欑涓€娆″嚭鐜扮殑缂栫爜
        seen = {}
        for item in strings_list:
            key = (item["offset"], item["string"])
            if key not in seen:
                seen[key] = item
        
        # 鎸夊亸绉婚噺鎺掑簭
        result = sorted(seen.values(), key=lambda x: x["offset"])
        return result

    def _split_long_string(
        self,
        value: str,
        max_string_length: int,
        min_len: int
    ) -> List[str]:
        """
        Split long noisy strings into useful segments while preserving IOC-like tokens.
        """
        if len(value) <= max_string_length:
            return [value]

        # First pass: split by common separators observed in concatenated blobs.
        raw_segments = re.split(r'[|;,]|\s{2,}', value)
        cleaned_segments = []
        for segment in raw_segments:
            segment = segment.strip()
            if len(segment) >= min_len:
                cleaned_segments.append(segment)

        if cleaned_segments:
            return cleaned_segments[:50]

        # Fallback: hard chunking for separator-free blobs.
        chunks = []
        for index in range(0, len(value), max_string_length):
            chunk = value[index:index + max_string_length].strip()
            if len(chunk) >= min_len:
                chunks.append(chunk)
            if len(chunks) >= 20:
                break
        return chunks if chunks else [value[:max_string_length]]

    def _normalize_extracted_strings(
        self,
        strings_list: List[Dict[str, Any]],
        min_len: int,
        max_string_length: int
    ) -> List[Dict[str, Any]]:
        """
        Normalize and segment noisy strings; enforce max length without dropping IOC hints.
        """
        normalized = []
        for item in strings_list:
            value = str(item.get("string", "")).strip()
            if len(value) < min_len:
                continue

            base_offset = int(item.get("offset", 0))
            encoding = item.get("encoding", "unknown")
            segments = self._split_long_string(value, max_string_length, min_len)

            for idx, segment in enumerate(segments):
                normalized.append({
                    "offset": base_offset + idx,
                    "string": segment[:max_string_length],
                    "encoding": encoding,
                })

        return normalized

    def _deduplicate_by_content(self, strings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove near-duplicate noise by keeping earliest offset for same normalized content.
        """
        seen = {}
        for item in strings_list:
            normalized_key = item.get("string", "").strip().lower()
            if not normalized_key:
                continue
            if normalized_key not in seen:
                seen[normalized_key] = item
            elif item.get("offset", 0) < seen[normalized_key].get("offset", 0):
                seen[normalized_key] = item

        return sorted(seen.values(), key=lambda x: x.get("offset", 0))

    def _filter_strings_by_category(
        self,
        strings_list: List[Dict[str, Any]],
        category_filter: str
    ) -> List[Dict[str, Any]]:
        if category_filter == 'all':
            return strings_list

        if category_filter == 'ioc':
            ioc_categories = {"url", "network", "ipc", "command", "registry", "file_path", "suspicious_api"}
            filtered = []
            for item in strings_list:
                categories = set(self._classify_string_entry(item.get("string", "")))
                if categories.intersection(ioc_categories):
                    filtered.append(item)
            return filtered

        filtered = []
        for item in strings_list:
            categories = self._classify_string_entry(item.get("string", ""))
            if category_filter in categories:
                filtered.append(item)
        return filtered

    def _classify_string_entry(self, value: str) -> List[str]:
        """Classify string into behavior-related categories."""
        categories: List[str] = []
        lower = value.lower()

        if re.search(r'https?://[^\s]+', value, re.IGNORECASE):
            categories.append("url")
        if re.search(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', value):
            categories.append("network")
        if re.search(r'\\\\\.\\|\\\\pipe\\|namedpipe', lower):
            categories.append("ipc")
        if re.search(r'hkey_(local_machine|current_user|classes_root|users|current_config)\\', lower):
            categories.append("registry")
        if re.search(r'[a-zA-Z]:\\[^\\s]+', value):
            categories.append("file_path")
        if re.search(r'\b(cmd|powershell|wscript|cscript|rundll32|regsvr32)\.exe\b', lower):
            categories.append("command")
        if re.search(r'\b(createprocess\w*|writeprocessmemory|createremotethread|virtualalloc\w*|loadlibrary\w*|getprocaddress)\b', lower):
            categories.append("suspicious_api")

        return categories

    def _score_string_entry(self, item: Dict[str, Any]) -> float:
        """Score string relevance for reverse-engineering triage."""
        value = item.get("string", "")
        categories = self._classify_string_entry(value)

        score = float(len(categories) * 10)
        if "suspicious_api" in categories:
            score += 8.0
        if "command" in categories:
            score += 6.0
        if "url" in categories or "network" in categories:
            score += 5.0

        # Prefer medium-length strings over very short/noisy blobs.
        score += min(len(value) / 40.0, 5.0)
        return score

    def _prioritize_strings(self, strings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize high-value strings first to reduce truncation impact.
        """
        return sorted(
            strings_list,
            key=lambda item: (-self._score_string_entry(item), item.get("offset", 0))
        )

    def _build_context_windows(
        self,
        strings_list: List[Dict[str, Any]],
        context_window_bytes: int,
        max_context_windows: int
    ) -> List[Dict[str, Any]]:
        """
        Regroup nearby strings into offset-neighborhood windows so long help text
        and operator UX strings remain interpretable as a single context block.
        """
        if not strings_list:
            return []

        ordered = sorted(strings_list, key=lambda item: item.get("offset", 0))
        grouped: List[List[Dict[str, Any]]] = []
        current_group: List[Dict[str, Any]] = []
        last_offset: Optional[int] = None

        for item in ordered:
            offset = int(item.get("offset", 0))
            if not current_group:
                current_group = [item]
                last_offset = offset
                continue

            if last_offset is not None and offset - last_offset <= context_window_bytes:
                current_group.append(item)
            else:
                grouped.append(current_group)
                current_group = [item]
            last_offset = offset

        if current_group:
            grouped.append(current_group)

        windows: List[Dict[str, Any]] = []
        for group in grouped:
            categories = sorted(
                {
                    category
                    for entry in group
                    for category in self._classify_string_entry(entry.get("string", ""))
                }
            )
            score = round(sum(self._score_string_entry(entry) for entry in group), 2)
            start_offset = int(group[0].get("offset", 0))
            last_entry = group[-1]
            last_string = str(last_entry.get("string", ""))
            end_offset = int(last_entry.get("offset", 0)) + len(last_string)
            windows.append({
                "start_offset": start_offset,
                "end_offset": end_offset,
                "score": score,
                "categories": categories,
                "strings": [
                    {
                        "offset": int(entry.get("offset", 0)),
                        "string": entry.get("string", ""),
                        "encoding": entry.get("encoding", "unknown"),
                        "categories": self._classify_string_entry(entry.get("string", "")),
                    }
                    for entry in group[:20]
                ],
            })

        windows.sort(key=lambda item: (-float(item.get("score", 0.0)), int(item.get("start_offset", 0))))
        return windows[:max_context_windows]

    def _build_strings_summary(
        self,
        strings_list: List[Dict[str, Any]],
        context_window_bytes: int,
        max_context_windows: int
    ) -> Dict[str, Any]:
        """
        Build behavior-oriented summary clusters for large string outputs.
        """
        cluster_keys = [
            "url",
            "network",
            "ipc",
            "command",
            "registry",
            "file_path",
            "suspicious_api",
        ]
        cluster_counts = {key: 0 for key in cluster_keys}
        clusters: Dict[str, List[str]] = {key: [] for key in cluster_keys}
        top_high_value: List[Dict[str, Any]] = []

        for item in strings_list:
            value = item.get("string", "")
            categories = self._classify_string_entry(value)
            if not categories:
                continue

            for category in categories:
                cluster_counts[category] += 1
                if len(clusters[category]) < 20 and value not in clusters[category]:
                    clusters[category].append(value)

            if len(top_high_value) < 20:
                top_high_value.append({
                    "offset": item.get("offset", 0),
                    "string": value,
                    "encoding": item.get("encoding", "unknown"),
                    "categories": categories,
                })

        return {
            "cluster_counts": cluster_counts,
            "clusters": clusters,
            "top_high_value": top_high_value,
            "context_windows": self._build_context_windows(
                strings_list,
                context_window_bytes=context_window_bytes,
                max_context_windows=max_context_windows
            ),
        }


    def floss_decode(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        浣跨敤 FLOSS 宸ュ叿瑙ｇ爜娣锋穯瀛楃涓?
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            args: 鍙傛暟瀛楀吀
                - timeout: 瓒呮椂鏃堕棿锛堢锛岄粯璁わ細60锛?
                - modes: 瑙ｇ爜妯″紡鍒楄〃 (['static', 'stack', 'tight', 'decoded']锛岄粯璁わ細['decoded'])
            
        Returns:
            Dict: 瑙ｇ爜鍚庣殑瀛楃涓插垪琛?
                {
                    "decoded_strings": [
                        {
                            "string": str,
                            "offset": int,
                            "type": str,  # 'static', 'stack', 'tight', 'decoded'
                            "decoding_method": str  # 瑙ｇ爜鏂规硶锛堝鏋滈€傜敤锛?
                        },
                        ...
                    ],
                    "count": int,
                    "timeout_occurred": bool,
                    "partial_results": bool
                }
            
        Raises:
            Exception: FLOSS 鎵ц澶辫触鏃舵姏鍑哄紓甯?
        """
        timeout = args.get('timeout', 60)
        modes = args.get('modes', ['decoded'])
        
        # 楠岃瘉鍙傛暟
        if timeout < 1:
            raise ValueError("timeout must be at least 1 second")
        
        valid_modes = ['static', 'stack', 'tight', 'decoded']
        for mode in modes:
            if mode not in valid_modes:
                raise ValueError(f"Invalid mode: {mode}. Must be one of {valid_modes}")

        # Locate FLOSS CLI without extra probe calls on the hot path.
        floss_cli = shutil.which("flare-floss") or shutil.which("floss")
        if not floss_cli:
            raise Exception(
                "FLOSS tool not found. Install FLARE-FLOSS (`pip install flare-floss`) and ensure it is in PATH."
            )
        
        # Build FLARE-FLOSS command
        command = [floss_cli, "--json", sample_path]
        
        timeout_occurred = False
        partial_results = False
        decoded_strings = []
        
        try:
            # 鎵ц FLOSS 鍛戒护锛岃缃秴鏃?
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False  # 涓嶈嚜鍔ㄦ姏鍑哄紓甯革紝鎵嬪姩妫€鏌ヨ繑鍥炵爜
            )
            
            # 妫€鏌ヨ繑鍥炵爜
            if result.returncode != 0:
                # FLOSS 鍙兘杩斿洖闈為浂閫€鍑虹爜浣嗕粛鏈夐儴鍒嗙粨鏋?
                if result.stdout:
                    partial_results = True
                else:
                    error_output = (result.stderr or "").strip()
                    detector_text = f"{result.stdout}\n{result.stderr}".lower()
                    if (
                        "fault localization with spectrum-based scoring" in detector_text
                        or (
                            "--json" in detector_text
                            and ("unrecognized arguments" in detector_text or "no such option" in detector_text)
                        )
                    ):
                        raise Exception(
                            "Incompatible `floss` CLI detected. Install FLARE-FLOSS (`pip install flare-floss`) and ensure it appears first in PATH."
                        )
                    raise Exception(f"FLOSS failed with exit code {result.returncode}: {error_output}")
            
            # 瑙ｆ瀽 JSON 杈撳嚭
            if result.stdout:
                try:
                    floss_output = json.loads(result.stdout)
                    decoded_strings = self._parse_floss_output(floss_output, modes)
                except json.JSONDecodeError as e:
                    raise Exception(f"Failed to parse FLOSS JSON output: {str(e)}")
            
        except subprocess.TimeoutExpired:
            # 瓒呮椂锛屽皾璇曡幏鍙栭儴鍒嗙粨鏋?
            timeout_occurred = True
            partial_results = True
            
            # 娉ㄦ剰锛歴ubprocess.TimeoutExpired 涓嶅寘鍚?stdout/stderr
            # 鎴戜滑闇€瑕佷娇鐢?Popen 鏉ヨ幏鍙栭儴鍒嗚緭鍑?
            # 閲嶆柊鎵ц浠ヨ幏鍙栭儴鍒嗙粨鏋?
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # 绛夊緟瓒呮椂
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    # 缁堟杩涚▼
                    process.kill()
                    stdout, stderr = process.communicate()
                    
                    # 灏濊瘯瑙ｆ瀽閮ㄥ垎杈撳嚭
                    if stdout:
                        try:
                            floss_output = json.loads(stdout)
                            decoded_strings = self._parse_floss_output(floss_output, modes)
                        except json.JSONDecodeError:
                            # 鏃犳硶瑙ｆ瀽閮ㄥ垎杈撳嚭
                            pass
            except Exception:
                # 鏃犳硶鑾峰彇閮ㄥ垎缁撴灉
                pass
        
        return {
            "decoded_strings": decoded_strings,
            "count": len(decoded_strings),
            "timeout_occurred": timeout_occurred,
            "partial_results": partial_results,
            "tooling": {
                "floss_command": command,
                "floss_version": self._get_python_package_version("flare-floss"),
            }
        }
    
    def _parse_floss_output(self, floss_output: Dict[str, Any], modes: List[str]) -> List[Dict[str, Any]]:
        """
        瑙ｆ瀽 FLOSS JSON 杈撳嚭
        
        Args:
            floss_output: FLOSS JSON 杈撳嚭
            modes: 璇锋眰鐨勮В鐮佹ā寮?
            
        Returns:
            List[Dict]: 瑙ｇ爜鍚庣殑瀛楃涓插垪琛?
        """
        decoded_strings = []
        
        # FLOSS JSON 杈撳嚭缁撴瀯锛?
        # {
        #   "strings": {
        #     "static_strings": [...],
        #     "stack_strings": [...],
        #     "tight_strings": [...],
        #     "decoded_strings": [...]
        #   }
        # }
        
        strings_data = floss_output.get('strings', {})
        
        # 鎻愬彇闈欐€佸瓧绗︿覆
        if 'static' in modes and 'static_strings' in strings_data:
            for item in strings_data['static_strings']:
                decoded_strings.append({
                    "string": item.get('string', ''),
                    "offset": item.get('offset', 0),
                    "type": "static",
                    "decoding_method": None
                })
        
        # 鎻愬彇鏍堝瓧绗︿覆
        if 'stack' in modes and 'stack_strings' in strings_data:
            for item in strings_data['stack_strings']:
                decoded_strings.append({
                    "string": item.get('string', ''),
                    "offset": item.get('offset', 0),
                    "type": "stack",
                    "decoding_method": item.get('function', 'stack_analysis')
                })
        
        # 鎻愬彇 tight 瀛楃涓?
        if 'tight' in modes and 'tight_strings' in strings_data:
            for item in strings_data['tight_strings']:
                decoded_strings.append({
                    "string": item.get('string', ''),
                    "offset": item.get('offset', 0),
                    "type": "tight",
                    "decoding_method": item.get('function', 'tight_analysis')
                })
        
        # 鎻愬彇瑙ｇ爜瀛楃涓?
        if 'decoded' in modes and 'decoded_strings' in strings_data:
            for item in strings_data['decoded_strings']:
                decoded_strings.append({
                    "string": item.get('string', ''),
                    "offset": item.get('offset', 0),
                    "type": "decoded",
                    "decoding_method": item.get('decoding_routine', 'unknown')
                })
        
        return decoded_strings

    def _collect_import_evidence(self, sample_path: str) -> Dict[str, List[str]]:
        """
        Collect imported DLL/API names as static evidence anchors for YARA match confidence.
        """
        dlls = set()
        apis = set()

        if PEFILE_AVAILABLE:
            pe = None
            try:
                pe = pefile.PE(sample_path, fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
                )
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        if dll_name:
                            dlls.add(dll_name)
                        for imp in entry.imports:
                            if imp.name:
                                api_name = imp.name.decode('utf-8', errors='ignore').lower()
                                if api_name:
                                    apis.add(api_name)
            except Exception:
                pass
            finally:
                try:
                    if pe is not None:
                        pe.close()
                except Exception:
                    pass

        if (not dlls and not apis) and LIEF_AVAILABLE:
            try:
                binary = lief.parse(sample_path)
                if binary is not None:
                    for imported_lib in binary.imports:
                        dll_name = (imported_lib.name or '').lower()
                        if dll_name:
                            dlls.add(dll_name)
                        for entry in imported_lib.entries:
                            api_name = (entry.name or '').lower()
                            if api_name:
                                apis.add(api_name)
            except Exception:
                pass

        return {
            "dlls": sorted(dlls),
            "apis": sorted(apis),
        }

    def _build_binary_layout(self, sample_path: str) -> Dict[str, Any]:
        """
        Build lightweight PE layout metadata for offset->section/function mapping.
        """
        layout: Dict[str, Any] = {
            "sections": [],
            "entry_point": {
                "offset": None,
                "rva": None,
                "va": None,
            },
            "parser": None,
        }

        if PEFILE_AVAILABLE:
            pe = None
            try:
                pe = pefile.PE(sample_path, fast_load=True)
                entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                image_base = int(pe.OPTIONAL_HEADER.ImageBase)
                layout["entry_point"] = {
                    "offset": int(pe.get_offset_from_rva(entry_rva)),
                    "rva": entry_rva,
                    "va": image_base + entry_rva,
                }
                for section in pe.sections:
                    raw_start = int(section.PointerToRawData)
                    raw_size = int(section.SizeOfRawData)
                    raw_end = raw_start + max(0, raw_size)
                    va_start = int(section.VirtualAddress)
                    va_size = max(int(section.Misc_VirtualSize), raw_size)
                    va_end = va_start + max(0, va_size)
                    section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                    layout["sections"].append(
                        {
                            "name": section_name or "unknown",
                            "raw_start": raw_start,
                            "raw_end": raw_end,
                            "va_start": va_start,
                            "va_end": va_end,
                        }
                    )
                layout["parser"] = "pefile"
                return layout
            except Exception:
                pass
            finally:
                try:
                    if pe is not None:
                        pe.close()
                except Exception:
                    pass

        if LIEF_AVAILABLE:
            try:
                binary = lief.parse(sample_path)
                if binary is not None and isinstance(binary, lief.PE.Binary):
                    entry_rva = int(binary.optional_header.addressof_entrypoint)
                    image_base = int(binary.optional_header.imagebase)
                    entry_offset = None
                    for section in binary.sections:
                        raw_start = int(getattr(section, "offset", 0))
                        raw_size = int(section.size)
                        raw_end = raw_start + max(0, raw_size)
                        va_start = int(section.virtual_address)
                        va_size = max(int(section.virtual_size), raw_size)
                        va_end = va_start + max(0, va_size)
                        section_name = section.name or "unknown"
                        layout["sections"].append(
                            {
                                "name": section_name,
                                "raw_start": raw_start,
                                "raw_end": raw_end,
                                "va_start": va_start,
                                "va_end": va_end,
                            }
                        )
                        if va_start <= entry_rva < va_end:
                            entry_offset = raw_start + (entry_rva - va_start)

                    layout["entry_point"] = {
                        "offset": entry_offset,
                        "rva": entry_rva,
                        "va": image_base + entry_rva,
                    }
                    layout["parser"] = "lief"
            except Exception:
                pass

        return layout

    def _map_offset_context(self, layout: Dict[str, Any], offset: int) -> Dict[str, Any]:
        """
        Map raw file offset to section and lightweight function hint.
        """
        mapped = {
            "section": None,
            "offset_in_section": None,
            "rva": None,
            "function_hint": None,
            "distance_to_entrypoint": None,
        }

        for section in layout.get("sections", []):
            raw_start = int(section.get("raw_start", 0))
            raw_end = int(section.get("raw_end", 0))
            if raw_start <= offset < raw_end:
                mapped["section"] = section.get("name")
                mapped["offset_in_section"] = offset - raw_start
                va_start = int(section.get("va_start", 0))
                mapped["rva"] = va_start + (offset - raw_start)
                break

        entry_offset = layout.get("entry_point", {}).get("offset")
        entry_rva = layout.get("entry_point", {}).get("rva")
        if isinstance(entry_offset, int):
            distance = abs(offset - entry_offset)
            mapped["distance_to_entrypoint"] = distance
            if distance <= 0x400:
                mapped["function_hint"] = {
                    "name": "entrypoint",
                    "address": f"0x{int(entry_rva or 0):08x}",
                    "proximity": "near" if distance <= 0x120 else "window",
                }

        return mapped

    def _collect_location_evidence(self, string_hits: List[Dict[str, Any]]) -> Dict[str, Any]:
        section_hits = []
        near_entrypoint_hits = 0
        for entry in string_hits:
            location = entry.get("location", {}) or {}
            section_name = location.get("section")
            if section_name:
                section_hits.append(str(section_name))
            distance = location.get("distance_to_entrypoint")
            if isinstance(distance, int) and distance <= 0x400:
                near_entrypoint_hits += 1

        unique_sections = sorted(set(section_hits))
        return {
            "section_hits": unique_sections[:20],
            "near_entrypoint_hits": near_entrypoint_hits,
        }

    def _evaluate_yara_match_confidence(
        self,
        match_data: Dict[str, Any],
        import_evidence: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        Correlate YARA string hits with import evidence to reduce false positives.
        String-only matches without import/API support are downgraded.
        """
        import_dlls = import_evidence.get("dlls", [])
        import_apis = import_evidence.get("apis", [])

        strings_blob = " ".join(
            f"{entry.get('identifier', '')} {entry.get('matched_data', '')}"
            for entry in match_data.get("strings", [])
        ).lower()

        dll_hits = []
        for dll in import_dlls:
            dll_stem = dll.rsplit('.', 1)[0]
            if dll in strings_blob or (dll_stem and dll_stem in strings_blob):
                dll_hits.append(dll)

        api_hits = []
        for api in import_apis:
            if api in strings_blob:
                api_hits.append(api)

        # Normalize to unique short evidence lists.
        dll_hits = sorted(set(dll_hits))[:20]
        api_hits = sorted(set(api_hits))[:30]
        location_evidence = self._collect_location_evidence(match_data.get("strings", []))
        section_hits = location_evidence.get("section_hits", [])
        near_entrypoint_hits = int(location_evidence.get("near_entrypoint_hits", 0))

        tags = [str(tag).lower() for tag in match_data.get("tags", [])]
        rule_name = str(match_data.get("rule", "")).lower()
        has_packer_tag = "packer" in tags
        has_string_hits = len(match_data.get("strings", [])) > 0

        score = 0.25
        reason = "No corroborating static evidence."
        if has_string_hits:
            score = 0.35
            reason = "Matched rule strings only."
        if has_packer_tag:
            score = max(score, 0.55)
            reason = "Packer-tagged rule match."
        if near_entrypoint_hits > 0 and has_string_hits:
            score = max(score, 0.48)
            reason = "String hits are close to entrypoint region."
        if dll_hits:
            score = max(score, 0.62)
            reason = "Matched imported DLL evidence."
        if api_hits:
            score = max(score, 0.82)
            reason = "Matched imported API evidence."
        if dll_hits and api_hits:
            score = max(score, 0.9)
            reason = "Matched both imported DLL and API evidence."

        # Explicit downgrade path requested by user: string-only without import/call evidence.
        has_strong_location_hint = near_entrypoint_hits > 0
        if (
            has_string_hits
            and not dll_hits
            and not api_hits
            and not has_packer_tag
            and not has_strong_location_hint
        ):
            score = min(score, 0.35)
            reason = "String pattern matched without import/call evidence."

        if rule_name == "generic_trojan":
            if has_string_hits and not api_hits and not dll_hits:
                score = min(score, 0.28)
                reason = "Generic_Trojan matched strings only without import/API corroboration."
            elif not api_hits:
                score = min(score, 0.45)
                reason = "Generic_Trojan lacks imported API corroboration."

        if score >= 0.75:
            level = "high"
        elif score >= 0.5:
            level = "medium"
        else:
            level = "low"

        string_only = bool(
            has_string_hits
            and not dll_hits
            and not api_hits
            and not has_strong_location_hint
        )
        inference_class = "supported_signal"
        if string_only:
            inference_class = "weak_signal"
        elif level == "high":
            inference_class = "high_confidence_signal"

        return {
            "confidence": {
                "level": level,
                "score": round(float(score), 2),
                "reason": reason,
            },
            "evidence": {
                "import_dll_hits": dll_hits,
                "import_api_hits": api_hits,
                "section_hits": section_hits,
                "near_entrypoint_hits": near_entrypoint_hits,
                "string_only": string_only,
            },
            "inference": {
                "classification": inference_class,
                "summary": reason,
            },
        }


    def yara_scan(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        浣跨敤 YARA 瑙勫垯鎵弿鏍锋湰
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            args: 鍙傛暟瀛楀吀
                - rule_set: 瑙勫垯闆嗗悕绉帮紙濡?malware_families, packers锛?
                - timeout_ms: 瓒呮椂鏃堕棿锛堟绉掞級锛岄粯璁?30000
                
        Returns:
            Dict: 鎵弿缁撴灉
                - matches: 鍖归厤鐨勮鍒欏垪琛?
                - ruleset_version: 瑙勫垯闆嗙増鏈?
                - timed_out: 鏄惁瓒呮椂
                
        Raises:
            RuntimeError: YARA 涓嶅彲鐢ㄦ垨瑙勫垯闆嗕笉瀛樺湪
        """
        if not YARA_AVAILABLE:
            import_error = f" Import error: {YARA_IMPORT_ERROR}" if YARA_IMPORT_ERROR else ""
            raise RuntimeError(
                "YARA is not available. Install/repair `yara-python` and its native runtime."
                + import_error
            )
        
        # 鑾峰彇鍙傛暟
        rule_set = args.get('rule_set', 'default')
        timeout_ms = args.get('timeout_ms', 30000)
        rule_tier = str(args.get('rule_tier', 'production') or 'production').strip().lower()
        if rule_tier not in {'production', 'experimental', 'test', 'all'}:
            rule_tier = 'production'
        
        # 杞崲瓒呮椂鏃堕棿涓虹
        timeout_sec = timeout_ms / 1000.0
        
        # 鏋勫缓瑙勫垯闆嗚矾寰?
        # 瑙勫垯闆嗗簲璇ュ瓨鍌ㄥ湪 workers/yara_rules/ 鐩綍涓?
        import os
        rules_dir = os.path.join(os.path.dirname(__file__), 'yara_rules')
        quality_notes: List[str] = []

        if str(rule_set).strip().lower() == 'default':
            if rule_tier == 'test':
                selected_sets = ['default']
            elif rule_tier == 'all':
                selected_sets = ['malware_families', 'packers', 'default']
            elif rule_tier == 'experimental':
                selected_sets = ['malware_families', 'packers']
                quality_notes.append(
                    'No dedicated experimental ruleset found; using production sets.'
                )
            else:
                # production default: avoid weak test rules such as PE_File/Test_Rule.
                selected_sets = ['malware_families', 'packers']
                quality_notes.append(
                    'Production tier enabled: weak test rules (PE_File/Test_Rule) excluded.'
                )
        else:
            selected_sets = [str(rule_set).strip()]

        rule_files = [os.path.join(rules_dir, f'{name}.yar') for name in selected_sets]
        missing_files = [rule_file for rule_file in rule_files if not os.path.exists(rule_file)]
        if missing_files:
            raise RuntimeError(
                f"Rule set files not found: {', '.join(missing_files)}"
            )
        
        # 鍔犺浇瑙勫垯闆?
        try:
            if len(rule_files) == 1:
                rules = yara.compile(filepath=rule_files[0])
            else:
                filepaths = {
                    os.path.splitext(os.path.basename(item))[0]: item
                    for item in rule_files
                }
                rules = yara.compile(filepaths=filepaths)
        except yara.SyntaxError as e:
            raise RuntimeError(f"YARA rule syntax error: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Failed to compile YARA rules: {str(e)}")
        
        # 鎵弿鏍锋湰
        matches = []
        timed_out = False
        import_evidence = self._collect_import_evidence(sample_path)
        binary_layout = self._build_binary_layout(sample_path)
        confidence_summary = {"high": 0, "medium": 0, "low": 0}
        
        try:
            # 鎵ц鎵弿锛岃缃秴鏃?
            yara_matches = rules.match(sample_path, timeout=int(timeout_sec))
            
            # 瑙ｆ瀽鍖归厤缁撴灉
            for match in yara_matches:
                match_data = {
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": []
                }
                
                # 鎻愬彇鍖归厤鐨勫瓧绗︿覆
                for string_match in match.strings:
                    for instance in string_match.instances:
                        offset_value = int(instance.offset)
                        location = self._map_offset_context(binary_layout, offset_value)
                        match_data["strings"].append({
                            "identifier": string_match.identifier,
                            "offset": offset_value,
                            "matched_data": instance.matched_data.decode('utf-8', errors='replace') if isinstance(instance.matched_data, bytes) else str(instance.matched_data),
                            "location": location,
                        })

                confidence_result = self._evaluate_yara_match_confidence(match_data, import_evidence)
                match_data["confidence"] = confidence_result["confidence"]
                match_data["evidence"] = confidence_result["evidence"]
                match_data["inference"] = confidence_result["inference"]
                confidence_level = match_data["confidence"].get("level", "low")
                if confidence_level in confidence_summary:
                    confidence_summary[confidence_level] += 1

                matches.append(match_data)
                
        except yara.TimeoutError:
            # 瓒呮椂锛岃繑鍥炲凡鍖归厤鐨勮鍒?
            timed_out = True
        except Exception as e:
            raise RuntimeError(f"YARA scan failed: {str(e)}")
        
        # 鑾峰彇瑙勫垯闆嗙増鏈紙浠庤鍒欐枃浠剁殑鍏冩暟鎹垨鏂囦欢淇敼鏃堕棿锛?
        ruleset_version = (
            self._get_ruleset_version(rule_files[0])
            if len(rule_files) == 1
            else self._get_ruleset_version_multi(rule_files)
        )
        
        return {
            "matches": matches,
            "ruleset_version": ruleset_version,
            "timed_out": timed_out,
            "rule_set": rule_set,
            "rule_tier": rule_tier,
            "rule_files": [os.path.basename(item) for item in rule_files],
            "confidence_summary": confidence_summary,
            "import_evidence": {
                "dll_count": len(import_evidence.get("dlls", [])),
                "api_count": len(import_evidence.get("apis", [])),
            },
            "offset_mapping": {
                "parser": binary_layout.get("parser"),
                "sections_count": len(binary_layout.get("sections", [])),
                "entry_point": binary_layout.get("entry_point", {}),
            },
            "tooling": {
                "yara_python_version": self._get_python_package_version("yara-python"),
            },
            "quality_notes": quality_notes,
        }
    
    
    def _get_ruleset_version(self, rule_file: str) -> str:
        """
        鑾峰彇瑙勫垯闆嗙増鏈?
        
        Args:
            rule_file: 瑙勫垯鏂囦欢璺緞
            
        Returns:
            str: 瑙勫垯闆嗙増鏈紙浣跨敤鏂囦欢淇敼鏃堕棿鐨勫搱甯岋級
        """
        import os
        
        # 浣跨敤鏂囦欢淇敼鏃堕棿浣滀负鐗堟湰鏍囪瘑
        mtime = os.path.getmtime(rule_file)
        
        # 璁＄畻鐗堟湰鍝堝笇
        version_str = f"{rule_file}:{mtime}"
        version_hash = hashlib.sha256(version_str.encode()).hexdigest()[:16]
        
        return version_hash

    def _get_ruleset_version_multi(self, rule_files: List[str]) -> str:
        """
        Build combined version hash for merged multi-file rulesets.
        """
        version_items = []
        for rule_file in sorted(rule_files):
            try:
                mtime = os.path.getmtime(rule_file)
            except Exception:
                mtime = 0
            version_items.append(f"{rule_file}:{mtime}")
        joined = "|".join(version_items)
        return hashlib.sha256(joined.encode()).hexdigest()[:16]


    def runtime_detect(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        妫€娴?PE 鏂囦欢鐨勮繍琛屾椂绫诲瀷
        
        鏍规嵁闇€姹?6.1-6.5 瀹炵幇锛?
        - 妫€鏌ュ鍏ヨ〃涓殑杩愯鏃?DLL
        - 瑙ｆ瀽 .NET CLR 澶撮儴
        - 璇嗗埆 C++ 杩愯鏃剁増鏈?
        - 杩斿洖缃俊搴﹀垎鏁?
        
        Args:
            sample_path: 鏍锋湰鏂囦欢璺緞
            args: 鍙傛暟瀛楀吀锛堝綋鍓嶆湭浣跨敤锛?
            
        Returns:
            Dict[str, Any]: 杩愯鏃舵娴嬬粨鏋?
                {
                    "is_dotnet": bool,
                    "dotnet_version": str | None,
                    "target_framework": str | None,
                    "suspected": List[Dict[str, Any]],  # [{"runtime": str, "confidence": float, "evidence": List[str]}]
                    "import_dlls": List[str]
                }
        """
        result = {
            "is_dotnet": False,
            "dotnet_version": None,
            "target_framework": None,
            "suspected": [],
            "import_dlls": []
        }
        
        try:
            # 棣栧厛灏濊瘯浣跨敤 pefile 瑙ｆ瀽
            pe = pefile.PE(sample_path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
            ])
            
            # 鎻愬彇瀵煎叆鐨?DLL 鍒楄〃
            import_dlls = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    import_dlls.append(dll_name)
            
            result["import_dlls"] = import_dlls
            
            # 妫€娴?.NET 杩愯鏃?
            dotnet_info = self._detect_dotnet_runtime(pe, import_dlls)
            if dotnet_info:
                result["is_dotnet"] = True
                result["dotnet_version"] = dotnet_info.get("version")
                result["target_framework"] = dotnet_info.get("target_framework")
                result["suspected"].append({
                    "runtime": ".NET",
                    "confidence": dotnet_info.get("confidence", 0.9),
                    "evidence": dotnet_info.get("evidence", [])
                })
            
            # 妫€娴?C++ 杩愯鏃?
            cpp_info = self._detect_cpp_runtime(import_dlls)
            if cpp_info:
                result["suspected"].append({
                    "runtime": cpp_info["runtime"],
                    "confidence": cpp_info["confidence"],
                    "evidence": cpp_info["evidence"]
                })
            
            # 妫€娴嬪叾浠栬繍琛屾椂
            other_runtimes = self._detect_other_runtimes(import_dlls)
            result["suspected"].extend(other_runtimes)

            # Rust detection from binary markers (symbols/paths/toolchain breadcrumbs)
            rust_info = self._detect_rust_runtime(sample_path)
            if rust_info:
                result["suspected"].append(rust_info)
            
            pe.close()
            
        except Exception as e:
            # 濡傛灉 pefile 澶辫触锛屽皾璇曚娇鐢?LIEF
            try:
                binary = lief.parse(sample_path)
                if binary is None:
                    raise ValueError("LIEF failed to parse PE file")
                
                # 鎻愬彇瀵煎叆鐨?DLL 鍒楄〃
                import_dlls = []
                for imported_lib in binary.imports:
                    dll_name = imported_lib.name.lower()
                    import_dlls.append(dll_name)
                
                result["import_dlls"] = import_dlls
                
                # 妫€娴?.NET 杩愯鏃讹紙LIEF 鏂瑰紡锛?
                dotnet_info = self._detect_dotnet_runtime_lief(binary, import_dlls)
                if dotnet_info:
                    result["is_dotnet"] = True
                    result["dotnet_version"] = dotnet_info.get("version")
                    result["target_framework"] = dotnet_info.get("target_framework")
                    result["suspected"].append({
                        "runtime": ".NET",
                        "confidence": dotnet_info.get("confidence", 0.9),
                        "evidence": dotnet_info.get("evidence", [])
                    })
                
                # 妫€娴?C++ 杩愯鏃?
                cpp_info = self._detect_cpp_runtime(import_dlls)
                if cpp_info:
                    result["suspected"].append({
                        "runtime": cpp_info["runtime"],
                        "confidence": cpp_info["confidence"],
                        "evidence": cpp_info["evidence"]
                    })
                
                # 妫€娴嬪叾浠栬繍琛屾椂
                other_runtimes = self._detect_other_runtimes(import_dlls)
                result["suspected"].extend(other_runtimes)

                # Rust detection from binary markers (symbols/paths/toolchain breadcrumbs)
                rust_info = self._detect_rust_runtime(sample_path)
                if rust_info:
                    result["suspected"].append(rust_info)
                
            except Exception as lief_error:
                # 涓や釜瑙ｆ瀽鍣ㄩ兘澶辫触
                raise ValueError(f"Failed to parse PE file with both pefile and LIEF: {str(e)}, {str(lief_error)}")

        self._augment_rust_msvc_fusion(result["suspected"])

        # Sort by confidence so mixed-toolchain samples don't get pinned to the first detector hit.
        result["suspected"] = sorted(
            result["suspected"],
            key=lambda item: item.get("confidence", 0.0),
            reverse=True
        )
        result["tooling"] = self._get_dependency_status()

        return result


    def _safe_resource_name(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)

    def _extract_pe_resources_pefile(self, pe: Any) -> Dict[str, Any]:
        result = {
            "present": False,
            "type_count": 0,
            "entry_count": 0,
            "types": [],
            "entries": [],
        }

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return result

        type_names: List[str] = []
        entries: List[Dict[str, Any]] = []

        try:
            for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = self._safe_resource_name(getattr(type_entry, "name", None))
                if not type_name:
                    type_id = getattr(getattr(type_entry, "struct", None), "Id", None)
                    type_name = pefile.RESOURCE_TYPE.get(type_id, str(type_id))
                type_names.append(type_name)
                if not hasattr(type_entry, "directory"):
                    continue
                for name_entry in type_entry.directory.entries:
                    entry_name = self._safe_resource_name(getattr(name_entry, "name", None))
                    if not entry_name:
                        entry_name = str(getattr(getattr(name_entry, "struct", None), "Id", "unnamed"))
                    if not hasattr(name_entry, "directory"):
                        continue
                    for lang_entry in name_entry.directory.entries:
                        data_entry = getattr(lang_entry, "data", None)
                        size = None
                        if getattr(data_entry, "struct", None) is not None:
                            size = getattr(data_entry.struct, "Size", None)
                        elif data_entry is not None:
                            size = getattr(data_entry, "Size", None)
                        entries.append(
                            {
                                "type": type_name,
                                "name": entry_name,
                                "lang": getattr(data_entry, "lang", None),
                                "sublang": getattr(data_entry, "sublang", None),
                                "size": size,
                            }
                        )
        except Exception:
            pass

        result["present"] = len(type_names) > 0
        result["type_count"] = len(set(type_names))
        result["entry_count"] = len(entries)
        result["types"] = sorted(set(type_names))
        result["entries"] = entries[:128]
        return result

    def _extract_overlay_pefile(self, pe: Any, sample_path: str) -> Dict[str, Any]:
        offset = None
        size = 0
        try:
            offset = pe.get_overlay_data_start_offset()
            if offset is not None:
                size = max(0, os.path.getsize(sample_path) - int(offset))
        except Exception:
            offset = None
            size = 0
        return {
            "present": offset is not None and size > 0,
            "offset": int(offset) if offset is not None else None,
            "size": int(size),
        }

    def _pe_structure_pefile(self, sample_path: str) -> Dict[str, Any]:
        pe = pefile.PE(sample_path)
        fingerprint = self._pe_fingerprint_pefile(sample_path, False)
        imports = self._pe_imports_extract_pefile(sample_path, True)
        exports = self._pe_exports_extract_pefile(sample_path)
        resources = self._extract_pe_resources_pefile(pe)
        overlay = self._extract_overlay_pefile(pe, sample_path)
        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        entry_section = None
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00') or 'unknown'
            raw_offset = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
            virtual_address = int(section.VirtualAddress)
            virtual_size = int(section.Misc_VirtualSize)
            section_info = {
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "entropy": round(self._calculate_entropy(section.get_data()), 2),
                "characteristics": int(section.Characteristics),
            }
            sections.append(section_info)
            if virtual_address <= entry_rva < (virtual_address + max(virtual_size, raw_size)):
                entry_section = name

        pe.close()
        return {
            "headers": fingerprint,
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "resources": resources,
            "overlay": overlay,
            "entry_point": {
                "rva": entry_rva,
                "va": image_base + entry_rva,
                "section": entry_section,
            },
        }

    def _extract_pe_resources_lief(self, binary: Any) -> Dict[str, Any]:
        result = {
            "present": False,
            "type_count": 0,
            "entry_count": 0,
            "types": [],
            "entries": [],
        }
        try:
            if not getattr(binary, "has_resources", False):
                return result

            manager = getattr(binary, "resources_manager", None)
            types = []
            if manager is not None:
                for attr_name in ("types_available", "types"):
                    values = getattr(manager, attr_name, [])
                    if values:
                        types.extend(self._safe_resource_name(item) for item in values)
            result["present"] = True
            result["types"] = [item for item in types if item]
            result["type_count"] = len(result["types"])
            result["entry_count"] = len(result["types"])
        except Exception:
            pass
        return result

    def _extract_overlay_lief(self, binary: Any) -> Dict[str, Any]:
        try:
            overlay = bytes(getattr(binary, "overlay", b"") or b"")
            return {
                "present": len(overlay) > 0,
                "offset": None,
                "size": len(overlay),
            }
        except Exception:
            return {
                "present": False,
                "offset": None,
                "size": 0,
            }

    def _pe_structure_lief(self, sample_path: str) -> Dict[str, Any]:
        binary = lief.parse(sample_path)
        if not binary or not isinstance(binary, lief.PE.Binary):
            raise ValueError("Not a valid PE file")

        fingerprint = self._pe_fingerprint_lief(sample_path, False)
        imports = self._pe_imports_extract_lief(sample_path, True)
        exports = self._pe_exports_extract_lief(sample_path)
        resources = self._extract_pe_resources_lief(binary)
        overlay = self._extract_overlay_lief(binary)
        entry_rva = int(binary.optional_header.addressof_entrypoint)
        image_base = int(binary.optional_header.imagebase)
        entry_section = None
        sections = []
        for section in binary.sections:
            name = section.name or "unknown"
            raw_offset = int(getattr(section, "offset", 0))
            raw_size = int(section.size)
            virtual_address = int(section.virtual_address)
            virtual_size = int(section.virtual_size)
            characteristics = getattr(section, "characteristics", 0)
            characteristics_value = int(getattr(characteristics, "value", characteristics))
            sections.append(
                {
                    "name": name,
                    "virtual_address": virtual_address,
                    "virtual_size": virtual_size,
                    "raw_offset": raw_offset,
                    "raw_size": raw_size,
                    "entropy": round(self._calculate_entropy(bytes(section.content)), 2),
                    "characteristics": characteristics_value,
                }
            )
            if virtual_address <= entry_rva < (virtual_address + max(virtual_size, raw_size)):
                entry_section = name

        return {
            "headers": fingerprint,
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "resources": resources,
            "overlay": overlay,
            "entry_point": {
                "rva": entry_rva,
                "va": image_base + entry_rva,
                "section": entry_section,
            },
        }

    def pe_structure_analyze(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Return merged PE structure analysis using pefile and LIEF when available."""
        warnings: List[str] = []
        backend_details: Dict[str, Any] = {}

        if PEFILE_AVAILABLE:
            try:
                backend_details["pefile"] = self._pe_structure_pefile(sample_path)
            except Exception as exc:
                warnings.append(f"pefile parsing failed: {str(exc)}")
        else:
            warnings.append("pefile unavailable")

        if LIEF_AVAILABLE:
            try:
                backend_details["lief"] = self._pe_structure_lief(sample_path)
            except Exception as exc:
                warnings.append(f"LIEF parsing failed: {str(exc)}")
        else:
            warnings.append("LIEF unavailable")

        primary = backend_details.get("pefile") or backend_details.get("lief")
        if primary is None:
            raise Exception("No PE parser available for structure analysis.")

        imports = primary.get("imports", {})
        exports = primary.get("exports", {})
        resources = primary.get("resources", {})
        overlay = primary.get("overlay", {})
        sections = primary.get("sections", [])
        headers = primary.get("headers", {})
        entry_point = primary.get("entry_point", {})

        return {
            "status": "ready",
            "summary": {
                "section_count": len(sections),
                "import_dll_count": int(imports.get("total_dlls", 0)),
                "import_function_count": int(imports.get("total_functions", 0)),
                "export_count": int(exports.get("total_exports", 0)),
                "forwarder_count": int(exports.get("total_forwarders", 0)),
                "resource_count": int(resources.get("entry_count", 0)),
                "overlay_present": bool(overlay.get("present")),
                "parser_preference": "pefile" if "pefile" in backend_details else "lief",
            },
            "headers": headers,
            "entry_point": entry_point,
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "resources": resources,
            "overlay": overlay,
            "backend_details": backend_details,
            "warnings": warnings,
        }

    def _classify_capability_group(self, namespace: str, name: str) -> str:
        combined = f"{namespace} {name}".lower()
        if "service" in combined:
            return "service_installation"
        if any(item in combined for item in ["http", "socket", "dns", "network", "c2"]):
            return "network_communication"
        if any(item in combined for item in ["inject", "process", "thread", "remote"]):
            return "process_manipulation"
        if any(item in combined for item in ["registry", "autorun"]):
            return "registry_persistence"
        if any(item in combined for item in ["file", "write", "read", "create directory", "delete"]):
            return "filesystem"
        if any(item in combined for item in ["crypto", "encrypt", "decrypt", "hash"]):
            return "cryptography"
        if any(item in combined for item in ["persistence", "startup", "scheduled task"]):
            return "persistence"
        if any(item in combined for item in ["execute", "spawn", "shell", "command"]):
            return "execution"
        return "general"

    def _normalize_capa_capabilities(self, raw_report: Dict[str, Any]) -> Dict[str, Any]:
        rules_block = raw_report.get("rules", {})
        if not isinstance(rules_block, dict):
            rules_block = {}

        capabilities: List[Dict[str, Any]] = []
        namespaces = set()
        groups: Dict[str, int] = {}

        for rule_id, rule_data in rules_block.items():
            if not isinstance(rule_data, dict):
                continue

            meta = rule_data.get("meta", {}) if isinstance(rule_data.get("meta"), dict) else {}
            name = str(meta.get("name") or rule_id)
            namespace = str(meta.get("namespace") or "").strip()
            scopes_value = meta.get("scopes")
            scopes: List[str] = []
            if isinstance(scopes_value, list):
                scopes = [str(item) for item in scopes_value if str(item).strip()]
            elif isinstance(scopes_value, str) and scopes_value.strip():
                scopes = [scopes_value.strip()]

            matches = rule_data.get("matches")
            if isinstance(matches, dict):
                match_count = len(matches)
            elif isinstance(matches, list):
                match_count = len(matches)
            else:
                match_count = 0

            group = self._classify_capability_group(namespace, name)
            groups[group] = groups.get(group, 0) + 1
            if namespace:
                namespaces.add(namespace)

            confidence = round(
                min(0.96, 0.52 + 0.08 * min(match_count, 4) + (0.04 if namespace else 0.0)),
                2,
            )
            capabilities.append(
                {
                    "rule_id": str(rule_id),
                    "name": name,
                    "namespace": namespace or None,
                    "scopes": scopes,
                    "group": group,
                    "confidence": confidence,
                    "match_count": match_count,
                    "evidence_summary": (
                        f"namespace={namespace or 'none'}, matches={match_count}, scopes={','.join(scopes) or 'unknown'}"
                    ),
                }
            )

        capabilities = sorted(
            capabilities,
            key=lambda item: (item.get("confidence", 0.0), item.get("match_count", 0), item.get("name", "")),
            reverse=True,
        )

        return {
            "capabilities": capabilities,
            "behavior_namespaces": sorted(namespaces),
            "capability_groups": groups,
        }

    def static_capability_triage(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run capa against the executable and normalize behavior capabilities."""
        rules_path = args.get("rules_path")
        timeout = int(args.get("timeout", 120))
        backend = self._discover_capa_backend(str(rules_path) if rules_path else None)

        if not backend.get("available"):
            return {
                "status": "setup_required",
                "backend": backend,
                "capabilities": [],
                "behavior_namespaces": [],
                "capability_groups": {},
                "raw_backend": None,
                "warnings": [backend.get("error") or "capa backend unavailable"],
            }

        if not (backend.get("rules") or {}).get("available"):
            return {
                "status": "setup_required",
                "backend": backend,
                "capabilities": [],
                "behavior_namespaces": [],
                "capability_groups": {},
                "raw_backend": None,
                "warnings": [backend.get("rules", {}).get("error") or "capa rules unavailable"],
            }

        command = list(backend["command"])
        command.extend(["--json"])
        rules_info = backend.get("rules", {})
        if rules_info.get("path"):
            command.extend(["-r", str(rules_info.get("path"))])
        command.append(sample_path)

        capa_result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(5, timeout),
            check=False,
        )
        combined_output = f"{capa_result.stdout}\n{capa_result.stderr}".strip()
        if capa_result.returncode != 0:
            raise Exception(
                f"capa execution failed with exit code {capa_result.returncode}: {combined_output}"
            )

        raw_report = json.loads(capa_result.stdout)
        normalized = self._normalize_capa_capabilities(raw_report)
        return {
            "status": "ready",
            "backend": backend,
            "capability_count": len(normalized["capabilities"]),
            "behavior_namespaces": normalized["behavior_namespaces"],
            "capability_groups": normalized["capability_groups"],
            "capabilities": normalized["capabilities"],
            "summary": (
                f"Recovered {len(normalized['capabilities'])} capa capability rule(s) across "
                f"{len(normalized['behavior_namespaces'])} namespace(s)."
            ),
            "raw_backend": raw_report,
            "warnings": [],
        }


    def _augment_rust_msvc_fusion(self, suspected: List[Dict[str, Any]]) -> None:
        """
        Promote mixed Rust + MSVC samples to an explicit fused label.
        This avoids over-biasing to plain C++ runtime when Rust markers are strong.
        """
        rust_entry: Optional[Dict[str, Any]] = None
        msvc_entry: Optional[Dict[str, Any]] = None

        for entry in suspected:
            runtime_name = str(entry.get("runtime", "")).lower()
            if rust_entry is None and runtime_name.startswith("rust"):
                rust_entry = entry
            if msvc_entry is None and ("msvc" in runtime_name or "c++ runtime" in runtime_name):
                msvc_entry = entry

        if rust_entry is None or msvc_entry is None:
            return

        rust_conf = float(rust_entry.get("confidence", 0.0))
        msvc_conf = float(msvc_entry.get("confidence", 0.0))
        fused_conf = round(min(0.98, max(rust_conf, msvc_conf) + 0.08), 2)

        rust_evidence = list(rust_entry.get("evidence", []))
        msvc_evidence = [item for item in list(msvc_entry.get("evidence", [])) if "msvc" in str(item).lower()]
        merged_evidence = rust_evidence + msvc_evidence + [
            "Rust markers co-exist with MSVC runtime imports"
        ]
        deduped_evidence = []
        seen = set()
        for item in merged_evidence:
            normalized = str(item).strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped_evidence.append(normalized)

        suspected.append({
            "runtime": "Rust (MSVC toolchain)",
            "confidence": fused_conf,
            "evidence": deduped_evidence[:10],
        })

        rust_entry["confidence"] = round(max(rust_conf, fused_conf - 0.02), 2)
    
    
    def _detect_dotnet_runtime(self, pe: pefile.PE, import_dlls: List[str]) -> Optional[Dict[str, Any]]:
        """
        妫€娴?.NET 杩愯鏃讹紙浣跨敤 pefile锛?
        
        Args:
            pe: pefile.PE 瀵硅薄
            import_dlls: 瀵煎叆鐨?DLL 鍒楄〃
            
        Returns:
            Optional[Dict[str, Any]]: .NET 杩愯鏃朵俊鎭紝濡傛灉涓嶆槸 .NET 鍒欒繑鍥?None
        """
        evidence = []
        
        # 妫€鏌ユ槸鍚﹀鍏?mscoree.dll
        has_mscoree = any('mscoree.dll' in dll for dll in import_dlls)
        if has_mscoree:
            evidence.append("Imports mscoree.dll")
        
        # 妫€鏌?COM Descriptor (CLR Header)
        if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            evidence.append("Has COM Descriptor (CLR Header)")
            
            try:
                com_descriptor = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
                
                # 鎻愬彇 CLR 鐗堟湰淇℃伅
                clr_version = None
                target_framework = None
                
                # CLR 澶撮儴鍖呭惈杩愯鏃剁増鏈俊鎭?
                if hasattr(com_descriptor, 'struct'):
                    major_version = getattr(com_descriptor.struct, 'MajorRuntimeVersion', None)
                    minor_version = getattr(com_descriptor.struct, 'MinorRuntimeVersion', None)
                    
                    if major_version is not None and minor_version is not None:
                        clr_version = f"{major_version}.{minor_version}"
                        evidence.append(f"CLR Runtime Version: {clr_version}")
                        
                        # 鏍规嵁 CLR 鐗堟湰鎺ㄦ柇鐩爣妗嗘灦
                        if major_version == 2 and minor_version == 5:
                            target_framework = ".NET Framework 2.0-3.5"
                        elif major_version == 2 and minor_version == 0:
                            target_framework = ".NET Framework 2.0"
                        elif major_version == 4 and minor_version == 0:
                            target_framework = ".NET Framework 4.0+"
                
                return {
                    "version": clr_version,
                    "target_framework": target_framework,
                    "confidence": 1.0,
                    "evidence": evidence
                }
                
            except Exception as e:
                # CLR 澶撮儴瑙ｆ瀽澶辫触锛屼絾浠嶇劧鍙兘鏄?.NET
                pass
        
        # 濡傛灉鍙湁 mscoree.dll 瀵煎叆锛岀疆淇″害杈冧綆
        if has_mscoree:
            return {
                "version": None,
                "target_framework": None,
                "confidence": 0.8,
                "evidence": evidence
            }
        
        return None
    
    
    def _detect_dotnet_runtime_lief(self, binary: lief.Binary, import_dlls: List[str]) -> Optional[Dict[str, Any]]:
        """
        妫€娴?.NET 杩愯鏃讹紙浣跨敤 LIEF锛?
        
        Args:
            binary: LIEF Binary 瀵硅薄
            import_dlls: 瀵煎叆鐨?DLL 鍒楄〃
            
        Returns:
            Optional[Dict[str, Any]]: .NET 杩愯鏃朵俊鎭紝濡傛灉涓嶆槸 .NET 鍒欒繑鍥?None
        """
        evidence = []
        
        # 妫€鏌ユ槸鍚﹀鍏?mscoree.dll
        has_mscoree = any('mscoree.dll' in dll for dll in import_dlls)
        if has_mscoree:
            evidence.append("Imports mscoree.dll")
        
        # LIEF 鍙互妫€鏌?data directories
        try:
            # 妫€鏌ユ槸鍚︽湁 CLR 澶撮儴锛圕OM Descriptor锛?
            if hasattr(binary, 'data_directories'):
                for directory in binary.data_directories:
                    if directory.type == lief.PE.DATA_DIRECTORY.COM_DESCRIPTOR:
                        if directory.size > 0:
                            evidence.append("Has COM Descriptor (CLR Header)")
                            
                            return {
                                "version": None,
                                "target_framework": None,
                                "confidence": 0.95,
                                "evidence": evidence
                            }
        except Exception:
            pass
        
        # 濡傛灉鍙湁 mscoree.dll 瀵煎叆锛岀疆淇″害杈冧綆
        if has_mscoree:
            return {
                "version": None,
                "target_framework": None,
                "confidence": 0.8,
                "evidence": evidence
            }
        
        return None

    def _detect_rust_runtime(self, sample_path: str) -> Optional[Dict[str, Any]]:
        """
        Detect Rust native binaries by string/symbol breadcrumbs.
        This complements import-based heuristics, which are weak for statically linked Rust.
        """
        marker_map = {
            b"rust_panic": "Contains rust_panic symbol",
            b"core::panicking": "Contains Rust core::panicking path",
            b"alloc::": "Contains Rust alloc namespace markers",
            b"cargo\\registry\\src": "Contains Cargo registry source path",
            b"\\src\\main.rs": "Contains Rust source path marker",
            b"\\src\\lib.rs": "Contains Rust library source marker",
            b"rustc": "Contains rustc toolchain marker",
            b"panic_fmt": "Contains panic formatting symbol",
            b"tokio::": "Contains tokio async runtime marker",
            b"tokio-runtime-worker": "Contains tokio runtime worker marker",
            b"goblin::": "Contains goblin binary parsing crate marker",
            b"iced_x86": "Contains iced-x86 disassembly crate marker",
            b"rust_eh_personality": "Contains Rust exception personality symbol",
            b"_rnv": "Contains Rust demangle marker (_R* symbols)",
        }

        try:
            with open(sample_path, "rb") as f:
                data = f.read()
        except Exception:
            return None

        data_lower = data.lower()
        evidence: List[str] = []
        for marker, description in marker_map.items():
            if marker in data_lower:
                evidence.append(description)

        if not evidence:
            return None

        confidence = 0.55 + min(0.35, 0.07 * len(evidence))
        if any("cargo" in item.lower() for item in evidence):
            confidence = min(confidence + 0.05, 0.95)
        if any("tokio" in item.lower() for item in evidence):
            confidence = min(confidence + 0.06, 0.96)
        if any("goblin" in item.lower() for item in evidence):
            confidence = min(confidence + 0.04, 0.96)
        if any("iced-x86" in item.lower() for item in evidence):
            confidence = min(confidence + 0.04, 0.96)

        return {
            "runtime": "Rust (native)",
            "confidence": round(confidence, 2),
            "evidence": evidence[:8],
            "semantic_hints": [
                hint
                for hint in ["tokio", "goblin", "iced-x86"]
                if any(hint in item.lower() for item in evidence)
            ],
        }
    
    
    def _detect_cpp_runtime(self, import_dlls: List[str]) -> Optional[Dict[str, Any]]:
        """
        妫€娴?C++ 杩愯鏃剁増鏈?
        
        Args:
            import_dlls: 瀵煎叆鐨?DLL 鍒楄〃
            
        Returns:
            Optional[Dict[str, Any]]: C++ 杩愯鏃朵俊鎭紝濡傛灉鏈娴嬪埌鍒欒繑鍥?None
        """
        evidence = []
        msvc_version = None
        confidence = 0.0
        
        # MSVC 杩愯鏃?DLL 妯″紡
        # msvcp140.dll -> Visual Studio 2015-2022 (MSVC 14.x)
        # msvcp120.dll -> Visual Studio 2013 (MSVC 12.0)
        # msvcp110.dll -> Visual Studio 2012 (MSVC 11.0)
        # msvcp100.dll -> Visual Studio 2010 (MSVC 10.0)
        # msvcp90.dll -> Visual Studio 2008 (MSVC 9.0)
        # msvcp80.dll -> Visual Studio 2005 (MSVC 8.0)
        # msvcp71.dll -> Visual Studio 2003 (MSVC 7.1)
        # msvcp70.dll -> Visual Studio 2002 (MSVC 7.0)
        # msvcp60.dll -> Visual Studio 6.0 (MSVC 6.0)
        
        msvc_mapping = {
            'msvcp140.dll': ('Visual Studio 2015-2022', 'MSVC 14.x', 0.9),
            'vcruntime140.dll': ('Visual Studio 2015-2022', 'MSVC 14.x', 0.9),
            'msvcp140_1.dll': ('Visual Studio 2019-2022', 'MSVC 14.2+', 0.95),
            'msvcp140_2.dll': ('Visual Studio 2019-2022', 'MSVC 14.2+', 0.95),
            'msvcp120.dll': ('Visual Studio 2013', 'MSVC 12.0', 0.95),
            'msvcr120.dll': ('Visual Studio 2013', 'MSVC 12.0', 0.95),
            'msvcp110.dll': ('Visual Studio 2012', 'MSVC 11.0', 0.95),
            'msvcr110.dll': ('Visual Studio 2012', 'MSVC 11.0', 0.95),
            'msvcp100.dll': ('Visual Studio 2010', 'MSVC 10.0', 0.95),
            'msvcr100.dll': ('Visual Studio 2010', 'MSVC 10.0', 0.95),
            'msvcp90.dll': ('Visual Studio 2008', 'MSVC 9.0', 0.95),
            'msvcr90.dll': ('Visual Studio 2008', 'MSVC 9.0', 0.95),
            'msvcp80.dll': ('Visual Studio 2005', 'MSVC 8.0', 0.95),
            'msvcr80.dll': ('Visual Studio 2005', 'MSVC 8.0', 0.95),
            'msvcp71.dll': ('Visual Studio 2003', 'MSVC 7.1', 0.95),
            'msvcr71.dll': ('Visual Studio 2003', 'MSVC 7.1', 0.95),
            'msvcp70.dll': ('Visual Studio 2002', 'MSVC 7.0', 0.95),
            'msvcr70.dll': ('Visual Studio 2002', 'MSVC 7.0', 0.95),
            'msvcp60.dll': ('Visual Studio 6.0', 'MSVC 6.0', 0.95),
            'msvcrt.dll': ('Windows System CRT', 'System CRT', 0.7),  # 绯荤粺 CRT锛岀疆淇″害杈冧綆
        }
        
        # 妫€鏌ュ鍏ョ殑 DLL
        for dll in import_dlls:
            dll_lower = dll.lower()
            if dll_lower in msvc_mapping:
                vs_version, msvc_ver, conf = msvc_mapping[dll_lower]
                evidence.append(f"Imports {dll} ({vs_version})")
                if conf > confidence:
                    confidence = conf
                    msvc_version = msvc_ver
        
        if msvc_version:
            return {
                "runtime": f"C++ Runtime ({msvc_version})",
                "confidence": confidence,
                "evidence": evidence
            }
        
        return None
    
    
    def _detect_other_runtimes(self, import_dlls: List[str]) -> List[Dict[str, Any]]:
        """
        妫€娴嬪叾浠栬繍琛屾椂锛堝 Go, Rust, Python 绛夛級
        
        Args:
            import_dlls: 瀵煎叆鐨?DLL 鍒楄〃
            
        Returns:
            List[Dict[str, Any]]: 鍏朵粬杩愯鏃朵俊鎭垪琛?
        """
        runtimes = []
        
        # Python 杩愯鏃?
        python_dlls = [dll for dll in import_dlls if 'python' in dll.lower()]
        if python_dlls:
            evidence = [f"Imports {dll}" for dll in python_dlls]
            # 灏濊瘯鎻愬彇 Python 鐗堟湰
            version = None
            for dll in python_dlls:
                # 渚嬪: python39.dll -> Python 3.9
                import re
                match = re.search(r'python(\d)(\d+)', dll.lower())
                if match:
                    major, minor = match.groups()
                    version = f"Python {major}.{minor}"
                    break
            
            runtimes.append({
                "runtime": version if version else "Python Runtime",
                "confidence": 0.9,
                "evidence": evidence
            })
        
        # Go 杩愯鏃讹紙Go 绋嬪簭閫氬父闈欐€侀摼鎺ワ紝浣嗗彲鑳芥湁鐗瑰畾瀵煎叆锛?
        # Go 绋嬪簭鐨勭壒寰侊細杈冨皯鐨勫鍏ワ紝閫氬父鍙湁 kernel32.dll, ntdll.dll 绛夌郴缁?DLL
        if len(import_dlls) <= 5:
            system_dlls = ['kernel32.dll', 'ntdll.dll', 'advapi32.dll', 'ws2_32.dll']
            if all(dll.lower() in system_dlls for dll in import_dlls):
                runtimes.append({
                    "runtime": "Possibly Go Runtime (static linking)",
                    "confidence": 0.5,
                    "evidence": ["Minimal imports (typical of Go binaries)"]
                })
        
        # Rust 杩愯鏃讹紙绫讳技 Go锛岄€氬父闈欐€侀摼鎺ワ級
        # Rust 鐨勭壒寰佷笌 Go 绫讳技锛屼絾杩欓噷鎴戜滑涓嶅仛鍖哄垎锛屽洜涓哄緢闅句粎浠庡鍏ヨ〃鍒ゆ柇
        
        # Delphi/Borland 杩愯鏃?
        delphi_dlls = [dll for dll in import_dlls if any(x in dll.lower() for x in ['borland', 'cc3250']) or dll.lower().startswith('rtl')]
        if delphi_dlls:
            evidence = [f"Imports {dll}" for dll in delphi_dlls]
            runtimes.append({
                "runtime": "Delphi/Borland Runtime",
                "confidence": 0.85,
                "evidence": evidence
            })
        
        # Visual Basic 杩愯鏃?
        vb_dlls = [dll for dll in import_dlls if 'msvbvm' in dll.lower()]
        if vb_dlls:
            evidence = [f"Imports {dll}" for dll in vb_dlls]
            # 鎻愬彇 VB 鐗堟湰
            version = None
            for dll in vb_dlls:
                # 渚嬪: msvbvm60.dll -> Visual Basic 6.0
                import re
                match = re.search(r'msvbvm(\d+)', dll.lower())
                if match:
                    ver = match.group(1)
                    version = f"Visual Basic {ver[0]}.{ver[1:]}" if len(ver) > 1 else f"Visual Basic {ver}"
                    break
            
            runtimes.append({
                "runtime": version if version else "Visual Basic Runtime",
                "confidence": 0.95,
                "evidence": evidence
            })
        
        return runtimes
    def _resolve_capstone_profile(self, machine: int) -> Optional[Dict[str, Any]]:
        """
        Resolve capstone arch/mode from PE machine type.
        Currently supports x86/x64.
        """
        if not CAPSTONE_AVAILABLE:
            return None

        if machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
            return {
                "arch": capstone.CS_ARCH_X86,
                "mode": capstone.CS_MODE_32,
                "name": "x86",
            }

        if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return {
                "arch": capstone.CS_ARCH_X86,
                "mode": capstone.CS_MODE_64,
                "name": "x86_64",
            }

        return None

    def entrypoint_disasm(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Secondary disassembly fallback around PE entrypoint.
        Uses pefile/lief for entrypoint mapping and capstone (if available) for instruction decode.
        """
        start_time = time.time()
        max_instructions = int(args.get("max_instructions", 120))
        max_bytes = int(args.get("max_bytes", 1024))
        target_address_raw = args.get("target_address")
        target_symbol = str(args.get("target_symbol", "") or "").strip()
        max_instructions = max(16, min(max_instructions, 400))
        max_bytes = max(128, min(max_bytes, 8192))

        warnings: List[str] = []
        parser = "unknown"
        machine = 0
        image_base = 0
        entry_rva = 0
        entry_va = 0
        entry_section = "unknown"
        entry_offset = 0
        read_size = max_bytes
        requested_va: Optional[int] = None
        requested_rva: Optional[int] = None
        resolved_from = "entrypoint"
        target_section = "unknown"
        target_offset = 0
        target_rva = 0
        target_va = 0

        if target_address_raw is not None:
            try:
                if isinstance(target_address_raw, (int, float)):
                    requested_va = int(target_address_raw)
                else:
                    normalized = str(target_address_raw).strip().lower().replace("`", "")
                    if normalized.startswith("0x"):
                        requested_va = int(normalized, 16)
                    else:
                        requested_va = int(normalized, 10)
            except Exception:
                warnings.append(f"Invalid target_address '{target_address_raw}', using entrypoint fallback.")
                requested_va = None

        if PEFILE_AVAILABLE:
            pe = pefile.PE(sample_path)
            parser = "pefile"
            machine = int(pe.FILE_HEADER.Machine)
            image_base = int(pe.OPTIONAL_HEADER.ImageBase)
            entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            entry_va = image_base + entry_rva
            entry_offset = int(pe.get_offset_from_rva(entry_rva))
            section_layout = []

            for section in pe.sections:
                section_start = int(section.VirtualAddress)
                section_size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
                section_end = section_start + section_size
                raw_start = int(section.PointerToRawData)
                raw_size = int(section.SizeOfRawData)
                raw_end = raw_start + max(0, raw_size)
                section_name = (
                    section.Name.decode("utf-8", errors="ignore").rstrip("\x00") or "unknown"
                )
                section_layout.append(
                    {
                        "name": section_name,
                        "va_start": section_start,
                        "va_end": section_end,
                        "raw_start": raw_start,
                        "raw_end": raw_end,
                    }
                )
                if section_start <= entry_rva < section_end:
                    entry_section = section_name
                    offset_in_section = entry_rva - section_start
                    section_remaining = max(0, section_size - offset_in_section)
                    if section_remaining > 0:
                        read_size = min(max_bytes, section_remaining)
                    break

            target_rva = entry_rva
            target_va = entry_va
            target_section = entry_section
            target_offset = entry_offset

            if requested_va is not None:
                guessed_rva = requested_va - image_base if requested_va >= image_base else requested_va
                section_match = None
                for section in section_layout:
                    if section["va_start"] <= guessed_rva < section["va_end"]:
                        section_match = section
                        break

                if section_match is None:
                    warnings.append(
                        f"Requested address 0x{requested_va:08x} is outside mapped PE sections; "
                        "falling back to entrypoint."
                    )
                else:
                    requested_rva = guessed_rva
                    target_rva = guessed_rva
                    target_va = image_base + target_rva
                    target_section = str(section_match["name"])
                    target_offset = int(section_match["raw_start"]) + (target_rva - int(section_match["va_start"]))
                    section_remaining = max(0, int(section_match["raw_end"]) - target_offset)
                    if section_remaining > 0:
                        read_size = min(max_bytes, section_remaining)
                    resolved_from = "requested_address"

            pe.close()
        elif LIEF_AVAILABLE:
            binary = lief.parse(sample_path)
            if not binary or not isinstance(binary, lief.PE.Binary):
                raise Exception("Failed to parse sample as PE via LIEF")

            parser = "lief"
            machine = int(getattr(binary.header.machine, "value", int(binary.header.machine)))
            image_base = int(binary.optional_header.imagebase)
            entry_rva = int(binary.optional_header.addressof_entrypoint)
            entry_va = image_base + entry_rva

            section_match = None
            section_layout = []
            for section in binary.sections:
                section_start = int(section.virtual_address)
                section_size = max(int(section.virtual_size), int(section.size))
                section_end = section_start + section_size
                raw_start = int(getattr(section, "offset", 0))
                raw_size = int(section.size)
                raw_end = raw_start + max(0, raw_size)
                section_layout.append(
                    {
                        "name": section.name or "unknown",
                        "va_start": section_start,
                        "va_end": section_end,
                        "raw_start": raw_start,
                        "raw_end": raw_end,
                    }
                )
                if section_start <= entry_rva < section_end:
                    section_match = section
                    break

            if section_match is not None:
                entry_section = section_match.name or "unknown"
                offset_in_section = entry_rva - int(section_match.virtual_address)
                section_offset = int(getattr(section_match, "offset", 0))
                entry_offset = section_offset + max(0, offset_in_section)
                section_remaining = max(0, int(section_match.size) - max(0, offset_in_section))
                if section_remaining > 0:
                    read_size = min(max_bytes, section_remaining)
            else:
                entry_offset = max(0, entry_rva)

            target_rva = entry_rva
            target_va = entry_va
            target_section = entry_section
            target_offset = entry_offset

            if requested_va is not None:
                guessed_rva = requested_va - image_base if requested_va >= image_base else requested_va
                layout_match = None
                for section in section_layout:
                    if section["va_start"] <= guessed_rva < section["va_end"]:
                        layout_match = section
                        break

                if layout_match is None:
                    warnings.append(
                        f"Requested address 0x{requested_va:08x} is outside mapped PE sections; "
                        "falling back to entrypoint."
                    )
                else:
                    requested_rva = guessed_rva
                    target_rva = guessed_rva
                    target_va = image_base + target_rva
                    target_section = str(layout_match["name"])
                    target_offset = int(layout_match["raw_start"]) + (
                        target_rva - int(layout_match["va_start"])
                    )
                    section_remaining = max(0, int(layout_match["raw_end"]) - target_offset)
                    if section_remaining > 0:
                        read_size = min(max_bytes, section_remaining)
                    resolved_from = "requested_address"
        else:
            raise Exception("No PE parser available (neither pefile nor LIEF)")

        with open(sample_path, "rb") as f:
            f.seek(target_offset)
            code_bytes = f.read(read_size)

        if len(code_bytes) == 0:
            raise Exception("No bytes available at requested window for fallback disassembly")

        backend = "hexdump"
        arch_name = "unknown"
        instructions: List[Dict[str, Any]] = []
        assembly_lines: List[str] = []

        capstone_profile = self._resolve_capstone_profile(machine)
        if capstone_profile:
            try:
                md = capstone.Cs(capstone_profile["arch"], capstone_profile["mode"])
                md.detail = False
                arch_name = capstone_profile["name"]
                for instruction in md.disasm(code_bytes, target_va):
                    if len(instructions) >= max_instructions:
                        break
                    line = f"0x{instruction.address:08x}: {instruction.mnemonic} {instruction.op_str}".rstrip()
                    assembly_lines.append(line)
                    instructions.append(
                        {
                            "address": f"0x{instruction.address:08x}",
                            "mnemonic": instruction.mnemonic,
                            "op_str": instruction.op_str,
                            "bytes": instruction.bytes.hex(),
                        }
                    )
                if instructions:
                    backend = "capstone"
            except Exception as e:
                warnings.append(f"Capstone decode failed: {str(e)}")

        if backend != "capstone":
            arch_name = "raw-bytes"
            max_lines = min(max_instructions, math.ceil(len(code_bytes) / 16))
            for line_idx in range(max_lines):
                start = line_idx * 16
                chunk = code_bytes[start : start + 16]
                if not chunk:
                    break
                address = target_va + start
                hex_part = " ".join(f"{value:02x}" for value in chunk)
                ascii_part = "".join(chr(value) if 32 <= value <= 126 else "." for value in chunk)
                assembly_lines.append(f"0x{address:08x}: {hex_part:<47} ; {ascii_part}")

        function_name = "entrypoint_fallback"
        if resolved_from == "requested_address":
            function_name = "requested_address_fallback"
        if target_symbol:
            function_name = f"{target_symbol}_fallback"

        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "result": {
                "function": function_name,
                "address": f"0x{target_va:08x}",
                "entry_point_rva": f"0x{entry_rva:08x}",
                "entry_section": target_section,
                "architecture": arch_name,
                "backend": backend,
                "parser": parser,
                "instruction_count": len(instructions) if backend == "capstone" else len(assembly_lines),
                "assembly": "\n".join(assembly_lines),
                "instructions": instructions,
                "bytes_window": len(code_bytes),
                "requested_address": f"0x{requested_va:08x}" if requested_va is not None else None,
                "requested_rva": f"0x{requested_rva:08x}" if requested_rva is not None else None,
                "resolved_from": resolved_from,
            },
            "warnings": warnings,
            "metrics": {
                "elapsed_ms": elapsed_ms,
                "backend": backend,
                "parser": parser,
                "capstone_available": CAPSTONE_AVAILABLE,
            },
        }

    def packer_detect(self, sample_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Multi-signal packer detection with fused evidence scoring.
        Reduces false positives from string-only YARA matches by correlating:
        - YARA (rule + confidence evidence)
        - section entropy profile
        - OEP / entrypoint section anomalies
        - import sparsity + suspicious section names
        """
        start_time = time.time()
        engines = args.get('engines', ['yara', 'entropy', 'entrypoint'])
        if isinstance(engines, str):
            engines = [engines]
        engines = [str(engine).lower() for engine in engines]
        allowed_engines = {'yara', 'entropy', 'entrypoint'}
        engines = [engine for engine in engines if engine in allowed_engines]
        if not engines:
            engines = ['yara', 'entropy', 'entrypoint']

        result = {
            'packed': False,
            'confidence': 0.0,
            'detections': [],
            'methods': [],
            'confidence_breakdown': {},
            'feature_fusion': {},
            'evidence': {},
            'inference': {},
        }

        warnings = []
        high_entropy_sections: List[Dict[str, Any]] = []
        suspicious_section_names: List[str] = []
        entry_section: Optional[str] = None
        entrypoint_in_high_entropy = False
        import_dll_count: Optional[int] = None
        import_api_count: Optional[int] = None
        import_sparsity = False
        parser_used: Optional[str] = None

        try:
            suspicious_name_markers = (
                '.upx',
                'upx0',
                'upx1',
                '.aspack',
                '.packed',
                'vmp',
                'themida',
                'petite',
            )

            # Shared feature extraction phase (single PE parse pass).
            if PEFILE_AVAILABLE:
                pe = None
                try:
                    pe = pefile.PE(sample_path, fast_load=True)
                    parser_used = 'pefile'
                    entry_point = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

                    pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
                    )
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        import_dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
                        import_api_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                    else:
                        import_dll_count = 0
                        import_api_count = 0

                    import_sparsity = bool(
                        (import_dll_count is not None and import_dll_count <= 3)
                        or (import_api_count is not None and import_api_count <= 18)
                    )

                    entry_section_entropy = None
                    for section in pe.sections:
                        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                        section_data = section.get_data()
                        entropy = self._calculate_entropy(section_data) if len(section_data) > 0 else 0.0

                        if entropy > 7.0:
                            high_entropy_sections.append(
                                {
                                    'name': section_name,
                                    'entropy': round(entropy, 2),
                                    'size': len(section_data),
                                }
                            )

                        normalized_name = section_name.lower()
                        if any(marker in normalized_name for marker in suspicious_name_markers):
                            suspicious_section_names.append(section_name)

                        section_start = int(section.VirtualAddress)
                        section_end = section_start + max(
                            int(section.Misc_VirtualSize), int(section.SizeOfRawData)
                        )
                        if section_start <= entry_point < section_end:
                            entry_section = section_name
                            entry_section_entropy = entropy

                    entrypoint_in_high_entropy = bool(
                        entry_section_entropy is not None and entry_section_entropy > 7.0
                    )
                except Exception as e:
                    warnings.append(f"Shared PE feature extraction failed: {str(e)}")
                finally:
                    try:
                        if pe is not None:
                            pe.close()
                    except Exception:
                        pass

            # 1. YARA 瑙勫垯鍖归厤
            if 'yara' in engines:
                try:
                    yara_result = self.yara_scan(sample_path, {'rule_set': 'packers'})
                    if yara_result.get('matches'):
                        for match in yara_result['matches']:
                            confidence_info = match.get('confidence', {}) or {}
                            evidence_info = match.get('evidence', {}) or {}
                            confidence_score = float(confidence_info.get('score', 0.35))
                            confidence_level = str(confidence_info.get('level', 'low')).lower()
                            string_only = bool(evidence_info.get('string_only', False))

                            if string_only and confidence_level == 'low':
                                confidence_score = min(confidence_score, 0.35)

                            detection = {
                                'method': 'yara',
                                'name': match['rule'].replace('_Packer', ''),
                                'confidence': round(max(0.0, min(confidence_score, 1.0)), 2),
                                'details': {
                                    'rule': match['rule'],
                                    'tags': match.get('tags', []),
                                    'meta': match.get('meta', {}),
                                    'confidence': confidence_info,
                                    'evidence': evidence_info,
                                    'inference': match.get('inference', {}),
                                }
                            }
                            result['detections'].append(detection)
                            result['methods'].append('yara')
                except Exception as e:
                    warnings.append(f"YARA scan failed: {str(e)}")

            # 2. 鑺傚尯鐔靛€煎垎鏋?
            if 'entropy' in engines:
                try:
                    if high_entropy_sections:
                        max_entropy = max(section.get('entropy', 7.0) for section in high_entropy_sections)
                        entropy_confidence = min(0.82, 0.55 + max(0.0, (max_entropy - 7.0) * 0.11))
                        detection = {
                            'method': 'entropy',
                            'name': 'High Entropy',
                            'confidence': round(entropy_confidence, 2),
                            'details': {
                                'high_entropy_sections': high_entropy_sections,
                                'description': 'Sections with abnormally high entropy (> 7.0) detected'
                            }
                        }
                        result['detections'].append(detection)
                        result['methods'].append('entropy')
                except Exception as e:
                    warnings.append(f"Entropy analysis failed: {str(e)}")

            # 3. 鍏ュ彛鐐逛綅缃鏌?
            if 'entrypoint' in engines:
                try:
                    # 姝ｅ父鎯呭喌涓嬶紝鍏ュ彛鐐瑰簲璇ュ湪 .text 鎴?CODE 鑺傚尯
                    standard_sections = ['.text', 'CODE', '.code', 'text']
                    is_suspicious = entry_section and entry_section not in standard_sections

                    if is_suspicious or entrypoint_in_high_entropy:
                        entry_confidence = 0.65
                        if entrypoint_in_high_entropy:
                            entry_confidence = 0.78
                        detection = {
                            'method': 'entrypoint',
                            'name': 'Suspicious Entry Point',
                            'confidence': round(entry_confidence, 2),
                            'details': {
                                'entry_section': entry_section,
                                'entrypoint_in_high_entropy': entrypoint_in_high_entropy,
                                'description': (
                                    f'Entry point is in non-standard section: {entry_section}'
                                    if is_suspicious
                                    else 'Entry point located in high-entropy section'
                                ),
                            }
                        }
                        result['detections'].append(detection)
                        result['methods'].append('entrypoint')
                except Exception as e:
                    warnings.append(f"Entry point analysis failed: {str(e)}")

            # 璁＄畻鎬讳綋缃俊搴?
            method_scores = {'yara': 0.0, 'entropy': 0.0, 'entrypoint': 0.0}
            for detection in result['detections']:
                method = str(detection.get('method', ''))
                confidence = float(detection.get('confidence', 0.0))
                if method in method_scores:
                    method_scores[method] = max(method_scores[method], confidence)

            suspicious_section_names = sorted(set(suspicious_section_names))
            feature_score = 0.0
            if suspicious_section_names:
                feature_score += 0.28
            if entrypoint_in_high_entropy:
                feature_score += 0.26
            if len(high_entropy_sections) >= 2:
                feature_score += 0.14
            if import_sparsity:
                feature_score += 0.16
            if import_sparsity and (
                method_scores['entropy'] >= 0.55 or method_scores['entrypoint'] >= 0.60
            ):
                feature_score += 0.10
            feature_score = min(feature_score, 1.0)

            weighted_score = (
                0.40 * method_scores['yara']
                + 0.25 * method_scores['entropy']
                + 0.20 * method_scores['entrypoint']
                + 0.15 * feature_score
            )

            no_detector_hits = len(result['detections']) == 0
            has_meaningful_feature_anomaly = bool(
                suspicious_section_names
                or entrypoint_in_high_entropy
                or len(high_entropy_sections) >= 2
                or any(float(section.get('entropy', 0.0)) >= 7.6 for section in high_entropy_sections)
            )
            if no_detector_hits and not has_meaningful_feature_anomaly:
                # Import sparsity alone is a weak heuristic and should not elevate clean binaries.
                weighted_score = 0.0

            corroborated_methods = [score for score in method_scores.values() if score >= 0.55]
            if len(corroborated_methods) >= 2:
                weighted_score += 0.08
            if len(corroborated_methods) == 3:
                weighted_score += 0.05

            yara_string_only = any(
                bool((detection.get('details', {}) or {}).get('evidence', {}).get('string_only', False))
                for detection in result['detections']
                if str(detection.get('method', '')) == 'yara'
            )
            weak_non_yara = (
                method_scores['entropy'] < 0.55
                and method_scores['entrypoint'] < 0.60
                and feature_score < 0.45
            )
            if yara_string_only and weak_non_yara:
                weighted_score = min(weighted_score, 0.42)

            result['confidence'] = round(min(weighted_score, 1.0), 2)
            result['confidence_breakdown'] = {
                **method_scores,
                'feature_fusion': round(feature_score, 2),
            }

            has_strong_non_yara = (
                method_scores['entropy'] >= 0.62
                or method_scores['entrypoint'] >= 0.68
                or feature_score >= 0.62
            )
            has_high_yara = method_scores['yara'] >= 0.80 and not yara_string_only
            result['packed'] = bool(
                has_strong_non_yara
                or has_high_yara
                or result['confidence'] >= 0.58
            )

            if not result['packed'] and method_scores['yara'] > 0:
                warnings.append(
                    'Packer YARA hits were downgraded due to weak corroborating evidence (imports/API/entropy/entrypoint/features).'
                )

            result['feature_fusion'] = {
                'parser': parser_used,
                'suspicious_section_names': suspicious_section_names,
                'high_entropy_sections': high_entropy_sections,
                'entrypoint_section': entry_section,
                'entrypoint_in_high_entropy': entrypoint_in_high_entropy,
                'import_dll_count': import_dll_count,
                'import_api_count': import_api_count,
                'import_sparsity': import_sparsity,
            }
            result['evidence'] = {
                'detections': result['detections'],
                'feature_fusion': result['feature_fusion'],
            }
            result['inference'] = {
                'classification': 'likely_packed' if result['packed'] else 'uncertain_or_not_packed',
                'reason': (
                    'Multiple corroborated signals suggest packing/obfuscation.'
                    if result['packed']
                    else 'Signals are weak or string-only; packing inference downgraded.'
                ),
            }

            # 鍘婚噸 methods
            result['methods'] = sorted(set(result['methods']))

        except Exception as e:
            raise Exception(f"Packer detection failed: {str(e)}")

        elapsed_ms = int((time.time() - start_time) * 1000)

        return {
            'result': result,
            'warnings': warnings,
            'metrics': {
                'elapsed_ms': elapsed_ms,
                'engines_used': engines
            }
        }


    def execute(self, request: WorkerRequest) -> WorkerResponse:
        """
        鎵ц闈欐€佸垎鏋愪换鍔?
        
        Args:
            request: Worker 璇锋眰瀵硅薄
            
        Returns:
            WorkerResponse: Worker 鍝嶅簲瀵硅薄
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # 鏌ユ壘宸ュ叿澶勭悊鍣?
            handler = self.tool_handlers.get(request.tool)
            
            if handler is None:
                return WorkerResponse(
                    job_id=request.job_id,
                    ok=False,
                    warnings=[],
                    errors=[f"Unknown tool: {request.tool}"],
                    data=None,
                    artifacts=[],
                    metrics={}
                )
            
            # 鎵ц宸ュ叿澶勭悊鍣?
            result = handler(request.sample.path, request.args)
            
            # 璁＄畻鎵ц鏃堕棿
            elapsed_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            return WorkerResponse(
                job_id=request.job_id,
                ok=True,
                warnings=[],
                errors=[],
                data=result,
                artifacts=[],
                metrics={
                    "elapsed_ms": elapsed_ms,
                    "tool": request.tool
                }
            )
            
        except Exception as e:
            elapsed_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            return WorkerResponse(
                job_id=request.job_id,
                ok=False,
                warnings=[],
                errors=[str(e)],
                data=None,
                artifacts=[],
                metrics={
                    "elapsed_ms": elapsed_ms,
                    "tool": request.tool
                }
            )


def parse_request(request_dict: Dict[str, Any]) -> WorkerRequest:
    """
    瑙ｆ瀽璇锋眰瀛楀吀涓?WorkerRequest 瀵硅薄
    
    Args:
        request_dict: 璇锋眰瀛楀吀
        
    Returns:
        WorkerRequest: 瑙ｆ瀽鍚庣殑璇锋眰瀵硅薄
    """
    sample_dict = request_dict["sample"]
    context_dict = request_dict["context"]
    policy_dict = context_dict["policy"]
    
    sample = SampleInfo(
        sample_id=sample_dict["sample_id"],
        path=sample_dict["path"]
    )
    
    policy = PolicyContext(
        allow_dynamic=policy_dict["allow_dynamic"],
        allow_network=policy_dict["allow_network"]
    )
    
    context = WorkerContext(
        request_time_utc=context_dict["request_time_utc"],
        policy=policy,
        versions=context_dict["versions"]
    )
    
    return WorkerRequest(
        job_id=request_dict["job_id"],
        tool=request_dict["tool"],
        sample=sample,
        args=request_dict["args"],
        context=context
    )


def response_to_dict(response: WorkerResponse) -> Dict[str, Any]:
    """
    灏?WorkerResponse 瀵硅薄杞崲涓哄瓧鍏?
    
    Args:
        response: Worker 鍝嶅簲瀵硅薄
        
    Returns:
        Dict: 鍝嶅簲瀛楀吀
    """
    return {
        "job_id": response.job_id,
        "ok": response.ok,
        "warnings": response.warnings,
        "errors": response.errors,
        "data": response.data,
        "artifacts": [asdict(artifact) for artifact in response.artifacts],
        "metrics": response.metrics
    }


def main():
    """
    涓诲嚱鏁?- 瀹炵幇涓?Node.js 鐨勮繘绋嬮棿閫氫俊锛坰tdin/stdout JSON锛?
    
    閫氫俊鍗忚锛?
    1. 浠?stdin 璇诲彇涓€琛?JSON 璇锋眰
    2. 瑙ｆ瀽璇锋眰骞舵墽琛屽垎鏋?
    3. 灏嗗搷搴斾互 JSON 鏍煎紡鍐欏叆 stdout
    4. 寰幆澶勭悊鐩村埌 stdin 鍏抽棴
    """
    worker = StaticWorker()
    
    # 浠?stdin 璇诲彇璇锋眰
    for line in sys.stdin:
        try:
            # 瑙ｆ瀽 JSON 璇锋眰
            request_dict = json.loads(line.strip())
            
            # 瑙ｆ瀽涓?WorkerRequest 瀵硅薄
            request = parse_request(request_dict)
            
            # 鎵ц鍒嗘瀽
            response = worker.execute(request)
            
            # 杞崲涓哄瓧鍏?
            response_dict = response_to_dict(response)
            
            # 杈撳嚭 JSON 鍝嶅簲鍒?stdout
            print(json.dumps(response_dict), flush=True)
            
        except json.JSONDecodeError as e:
            # JSON 瑙ｆ瀽閿欒
            error_response = {
                "job_id": "unknown",
                "ok": False,
                "warnings": [],
                "errors": [f"JSON decode error: {str(e)}"],
                "data": None,
                "artifacts": [],
                "metrics": {}
            }
            print(json.dumps(error_response), flush=True)
            
        except KeyError as e:
            # 缂哄皯蹇呴渶瀛楁
            error_response = {
                "job_id": request_dict.get("job_id", "unknown"),
                "ok": False,
                "warnings": [],
                "errors": [f"Missing required field: {str(e)}"],
                "data": None,
                "artifacts": [],
                "metrics": {}
            }
            print(json.dumps(error_response), flush=True)
            
        except Exception as e:
            # 鍏朵粬閿欒
            error_response = {
                "job_id": request_dict.get("job_id", "unknown") if 'request_dict' in locals() else "unknown",
                "ok": False,
                "warnings": [],
                "errors": [f"Unexpected error: {str(e)}"],
                "data": None,
                "artifacts": [],
                "metrics": {}
            }
            print(json.dumps(error_response), flush=True)


if __name__ == "__main__":
    main()

