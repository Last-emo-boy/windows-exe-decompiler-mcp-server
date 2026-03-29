import { z } from 'zod'
import type { WorkerResult } from './types.js'

export const SetupActionSchema = z.object({
  id: z.string(),
  required: z.boolean(),
  kind: z.enum(['pip_install', 'install_package', 'set_env', 'provide_path', 'verify_install']),
  title: z.string(),
  summary: z.string(),
  command: z.string().nullable().optional(),
  env_var: z.string().nullable().optional(),
  value_hint: z.string().nullable().optional(),
  examples: z.array(z.string()).default([]),
  applies_to: z.array(z.string()).default([]),
})

export const RequiredUserInputSchema = z.object({
  key: z.string(),
  label: z.string(),
  summary: z.string(),
  required: z.boolean(),
  env_vars: z.array(z.string()).default([]),
  examples: z.array(z.string()).default([]),
})

export type SetupAction = z.infer<typeof SetupActionSchema>
export type RequiredUserInput = z.infer<typeof RequiredUserInputSchema>

const WINDOWS_GHIDRA_EXAMPLES = [
  'C:\\Users\\<user>\\Downloads\\ghidra_12.0.4_PUBLIC',
  'D:\\tools\\ghidra_12.0.4_PUBLIC',
]

const WINDOWS_JAVA_EXAMPLES = [
  'C:\\Program Files\\Eclipse Adoptium\\jdk-21',
  'C:\\Program Files\\Java\\jdk-21',
]

const WINDOWS_CAPA_RULES_EXAMPLES = [
  'C:\\tools\\capa-rules',
  'D:\\analysis\\capa-rules',
]

const WINDOWS_DIE_EXAMPLES = [
  'C:\\tools\\die\\diec.exe',
  'D:\\tools\\Detect It Easy\\diec.exe',
]

const WINDOWS_FRIDA_EXAMPLES = [
  'pip install frida',
  'pip install frida-tools',
]

const LINUX_QILING_ROOTFS_EXAMPLES = [
  '/opt/qiling-rootfs/windows_x86_64',
  '/mnt/qiling-rootfs',
]

const LINUX_RETDEC_EXAMPLES = [
  '/opt/retdec/bin/retdec-decompiler',
  '/usr/local/bin/retdec-decompiler',
]

export function mergeSetupActions(...groups: SetupAction[][]): SetupAction[] {
  const merged = new Map<string, SetupAction>()
  for (const group of groups) {
    for (const action of group) {
      merged.set(action.id, action)
    }
  }
  return [...merged.values()]
}

export function mergeRequiredUserInputs(...groups: RequiredUserInput[][]): RequiredUserInput[] {
  const merged = new Map<string, RequiredUserInput>()
  for (const group of groups) {
    for (const input of group) {
      merged.set(input.key, input)
    }
  }
  return [...merged.values()]
}

export function buildBaselinePythonSetupActions(): SetupAction[] {
  return [
    {
      id: 'install_python_requirements',
      required: true,
      kind: 'pip_install',
      title: 'Install baseline Python dependencies',
      summary:
        'Install the baseline static-analysis Python packages before using worker-backed analysis tools.',
      command: 'python -m pip install -r requirements.txt',
      examples: ['python -m pip install -r requirements.txt'],
      applies_to: ['system.health', 'dynamic.dependencies', 'static-analysis'],
    },
  ]
}

export function buildStaticAnalysisRequiredUserInputs(): RequiredUserInput[] {
  return [
    {
      key: 'capa_rules_path',
      label: 'capa rules directory',
      summary:
        'Provide the absolute path to a downloaded capa rules directory so static capability triage can run.',
      required: false,
      env_vars: ['CAPA_RULES_PATH'],
      examples: WINDOWS_CAPA_RULES_EXAMPLES,
    },
    {
      key: 'die_path',
      label: 'Detect It Easy CLI path',
      summary:
        'Provide the absolute path to the Detect It Easy CLI executable (diec) for compiler and protector attribution.',
      required: false,
      env_vars: ['DIE_PATH'],
      examples: WINDOWS_DIE_EXAMPLES,
    },
  ]
}

export function buildStaticAnalysisSetupActions(): SetupAction[] {
  return [
    {
      id: 'install_static_python_requirements',
      required: true,
      kind: 'pip_install',
      title: 'Install static-analysis Python dependencies',
      summary:
        'Install the core Python packages used by PE parsing and capability triage, including pefile, LIEF, and flare-capa.',
      command: 'python -m pip install -r requirements.txt',
      examples: ['python -m pip install -r requirements.txt'],
      applies_to: ['system.health', 'system.setup.guide', 'static.capability.triage', 'pe.structure.analyze'],
    },
    {
      id: 'install_capa',
      required: false,
      kind: 'pip_install',
      title: 'Install capa',
      summary:
        'Install FLARE capa so the server can recognize executable behavior capabilities from rules.',
      command: 'python -m pip install flare-capa',
      examples: ['python -m pip install flare-capa'],
      applies_to: ['static.capability.triage', 'system.health'],
    },
    {
      id: 'install_pefile',
      required: false,
      kind: 'pip_install',
      title: 'Install pefile',
      summary: 'Install pefile for lightweight PE header, section, import, export, and resource parsing.',
      command: 'python -m pip install pefile',
      examples: ['python -m pip install pefile'],
      applies_to: ['pe.structure.analyze', 'system.health'],
    },
    {
      id: 'install_lief',
      required: false,
      kind: 'pip_install',
      title: 'Install LIEF',
      summary:
        'Install LIEF for richer normalized PE parsing and rebuild-oriented metadata extraction.',
      command: 'python -m pip install lief',
      examples: ['python -m pip install lief'],
      applies_to: ['pe.structure.analyze', 'system.health'],
    },
    {
      id: 'set_capa_rules_path',
      required: false,
      kind: 'set_env',
      title: 'Set CAPA_RULES_PATH',
      summary:
        'Set CAPA_RULES_PATH to the extracted capa rules directory when the rules are not installed in a default location.',
      env_var: 'CAPA_RULES_PATH',
      value_hint: 'Absolute path to a capa rules directory',
      examples: WINDOWS_CAPA_RULES_EXAMPLES.map((example) => `$env:CAPA_RULES_PATH = "${example}"`),
      applies_to: ['static.capability.triage', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'provide_capa_rules_path',
      required: false,
      kind: 'provide_path',
      title: 'Provide capa rules directory',
      summary:
        'Download and extract the official capa rules repository, then provide the absolute directory path to the server.',
      value_hint: 'Absolute path to a capa rules directory',
      examples: WINDOWS_CAPA_RULES_EXAMPLES,
      applies_to: ['static.capability.triage', 'system.health'],
    },
    {
      id: 'set_die_path',
      required: false,
      kind: 'set_env',
      title: 'Set DIE_PATH',
      summary:
        'Set DIE_PATH to the Detect It Easy CLI executable (diec.exe) when it is not already available in PATH.',
      env_var: 'DIE_PATH',
      value_hint: 'Absolute path to diec.exe',
      examples: WINDOWS_DIE_EXAMPLES.map((example) => `$env:DIE_PATH = "${example}"`),
      applies_to: ['compiler.packer.detect', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'provide_die_path',
      required: false,
      kind: 'provide_path',
      title: 'Provide Detect It Easy CLI path',
      summary:
        'Provide the absolute path to Detect It Easy CLI (diec.exe) so compiler, packer, and protector attribution can run.',
      value_hint: 'Absolute path to diec.exe',
      examples: WINDOWS_DIE_EXAMPLES,
      applies_to: ['compiler.packer.detect', 'system.health'],
    },
    {
      id: 'verify_die_install',
      required: false,
      kind: 'verify_install',
      title: 'Verify Detect It Easy installation',
      summary:
        'Confirm that diec.exe can be launched directly and is either configured explicitly or available on PATH.',
      command: 'diec.exe --version',
      examples: ['diec.exe --version'],
      applies_to: ['compiler.packer.detect', 'system.health'],
    },
  ]
}

export function buildCoreLinuxToolchainSetupActions(): SetupAction[] {
  return [
    {
      id: 'install_graphviz_package',
      required: false,
      kind: 'install_package',
      title: 'Install Graphviz',
      summary:
        'Install Graphviz so CFG and call-graph exports can render SVG or PNG artifacts from DOT input.',
      command: 'apt-get update && apt-get install -y graphviz',
      examples: ['apt-get update && apt-get install -y graphviz', 'brew install graphviz'],
      applies_to: ['code.function.cfg', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'install_rizin_package',
      required: false,
      kind: 'install_package',
      title: 'Install Rizin',
      summary:
        'Install Rizin for lightweight disassembly, Xref, graph, and fallback binary-inspection workflows.',
      command:
        'curl -fsSL https://github.com/rizinorg/rizin/releases/download/v0.8.2/rizin-v0.8.2-static-x86_64.tar.xz | tar -xJf - -C /opt/rizin --strip-components=1',
      examples: [
        'curl -fsSL https://github.com/rizinorg/rizin/releases/download/v0.8.2/rizin-v0.8.2-static-x86_64.tar.xz | tar -xJf - -C /opt/rizin --strip-components=1',
      ],
      applies_to: ['system.health', 'system.setup.guide'],
    },
    {
      id: 'install_yarax_package',
      required: false,
      kind: 'pip_install',
      title: 'Install YARA-X',
      summary:
        'Install YARA-X alongside legacy YARA so future scans can use the newer engine without removing yara-python.',
      command: 'python -m pip install yara-x',
      examples: ['python -m pip install yara-x'],
      applies_to: ['yara.scan', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'install_upx_package',
      required: false,
      kind: 'install_package',
      title: 'Install UPX',
      summary: 'Install UPX for common packed-sample inspection and unpack-helper workflows.',
      command:
        'curl -fsSL https://github.com/upx/upx/releases/download/v5.1.1/upx-5.1.1-amd64_linux.tar.xz | tar -xJf - -C /opt/upx --strip-components=1',
      examples: [
        'curl -fsSL https://github.com/upx/upx/releases/download/v5.1.1/upx-5.1.1-amd64_linux.tar.xz | tar -xJf - -C /opt/upx --strip-components=1',
      ],
      applies_to: ['packer.detect', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'install_wine_package',
      required: false,
      kind: 'install_package',
      title: 'Install Wine and winedbg',
      summary:
        'Install Wine plus winedbg for Linux-hosted Windows user-mode execution and debugger-style troubleshooting.',
      command: 'apt-get update && apt-get install -y wine wine64',
      examples: ['apt-get update && apt-get install -y wine wine64'],
      applies_to: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'install_frida_tools_cli',
      required: false,
      kind: 'pip_install',
      title: 'Install Frida CLI tools',
      summary: 'Install frida-tools so frida-ps, frida-trace, and other CLI helpers are available on PATH.',
      command: 'python -m pip install frida-tools',
      examples: ['python -m pip install frida-tools'],
      applies_to: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
    },
  ]
}

export function buildDynamicDependencySetupActions(): SetupAction[] {
  return [
    {
      id: 'install_dynamic_requirements',
      required: false,
      kind: 'pip_install',
      title: 'Install dynamic-analysis extras',
      summary:
        'Install the optional dynamic-analysis package set used by Speakeasy, Frida, and process telemetry probes.',
      command: 'python -m pip install -r workers/requirements-dynamic.txt',
      examples: ['python -m pip install -r workers/requirements-dynamic.txt'],
      applies_to: ['dynamic.dependencies', 'sandbox.execute'],
    },
    {
      id: 'install_speakeasy_emulator',
      required: false,
      kind: 'pip_install',
      title: 'Install Speakeasy emulator',
      summary: 'Install FLARE Speakeasy for user-mode PE emulation.',
      command: 'python -m pip install speakeasy-emulator',
      examples: ['python -m pip install speakeasy-emulator'],
      applies_to: ['dynamic.dependencies', 'sandbox.execute'],
    },
    {
      id: 'install_frida',
      required: false,
      kind: 'pip_install',
      title: 'Install Frida runtime tracing',
      summary: 'Install Frida when you need live instrumentation or API tracing support.',
      command: 'python -m pip install frida',
      examples: ['python -m pip install frida'],
      applies_to: ['dynamic.dependencies', 'frida.runtime.instrument'],
    },
    {
      id: 'install_frida_tools',
      required: false,
      kind: 'pip_install',
      title: 'Install Frida tools',
      summary: 'Install frida-tools for CLI support and script compilation.',
      command: 'python -m pip install frida-tools',
      examples: ['python -m pip install frida-tools'],
      applies_to: ['dynamic.dependencies', 'frida.script.inject'],
    },
    {
      id: 'install_psutil',
      required: false,
      kind: 'pip_install',
      title: 'Install psutil process telemetry',
      summary: 'Install psutil for process metadata and lightweight telemetry probes.',
      command: 'python -m pip install psutil',
      examples: ['python -m pip install psutil'],
      applies_to: ['dynamic.dependencies'],
    },
    {
      id: 'install_qiling_runtime',
      required: false,
      kind: 'pip_install',
      title: 'Install Qiling',
      summary:
        'Install Qiling for Windows API emulation, hookable user-mode execution, and automated dynamic analysis workflows.',
      command: 'python -m pip install qiling',
      examples: ['python -m pip install qiling'],
      applies_to: ['dynamic.dependencies', 'sandbox.execute', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'set_qiling_rootfs',
      required: false,
      kind: 'set_env',
      title: 'Set QILING_ROOTFS',
      summary:
        'Set QILING_ROOTFS to a mounted Windows rootfs directory. Qiling does not ship Windows DLLs or registry hives for you.',
      env_var: 'QILING_ROOTFS',
      value_hint: 'Absolute path to a mounted Qiling Windows rootfs directory',
      examples: LINUX_QILING_ROOTFS_EXAMPLES.map((example) => `export QILING_ROOTFS="${example}"`),
      applies_to: ['dynamic.dependencies', 'sandbox.execute', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'install_angr_runtime',
      required: false,
      kind: 'pip_install',
      title: 'Install angr',
      summary:
        'Install angr, ideally in an isolated Python environment, for symbolic execution, CFG recovery, and path exploration.',
      command: 'python -m venv /opt/angr-venv && /opt/angr-venv/bin/pip install angr',
      examples: ['python -m venv /opt/angr-venv && /opt/angr-venv/bin/pip install angr'],
      applies_to: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'set_angr_python',
      required: false,
      kind: 'set_env',
      title: 'Set ANGR_PYTHON',
      summary:
        'Point ANGR_PYTHON at the isolated Python interpreter used to import angr so future advanced-analysis tools can invoke it consistently.',
      env_var: 'ANGR_PYTHON',
      value_hint: 'Absolute path to the Python interpreter with angr installed',
      examples: ['export ANGR_PYTHON="/opt/angr-venv/bin/python"'],
      applies_to: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'install_panda_runtime',
      required: false,
      kind: 'pip_install',
      title: 'Install PANDA Python bindings',
      summary:
        'Install pandare so record/replay-oriented PANDA workflows are available to helper tooling and future integrations.',
      command: 'python -m pip install pandare',
      examples: ['python -m pip install pandare'],
      applies_to: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
    },
    {
      id: 'set_panda_python',
      required: false,
      kind: 'set_env',
      title: 'Set PANDA_PYTHON',
      summary:
        'Optionally point PANDA_PYTHON at the interpreter that has pandare installed when it differs from the server default Python.',
      env_var: 'PANDA_PYTHON',
      value_hint: 'Absolute path to the Python interpreter with pandare installed',
      examples: ['export PANDA_PYTHON="/usr/local/bin/python3"'],
      applies_to: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
    },
  ]
}

export function buildDynamicDependencyRequiredUserInputs(): RequiredUserInput[] {
  return [
    {
      key: 'qiling_rootfs_path',
      label: 'Qiling rootfs directory',
      summary:
        'Provide a mounted Windows rootfs directory for Qiling. This should contain the Windows DLL and registry snapshot expected by the emulated sample.',
      required: false,
      env_vars: ['QILING_ROOTFS'],
      examples: LINUX_QILING_ROOTFS_EXAMPLES,
    },
  ]
}

export function buildFridaRequiredUserInputs(): RequiredUserInput[] {
  return [
    {
      key: 'frida_path',
      label: 'Frida server binary path',
      summary:
        'Optional: Provide the absolute path to the Frida server binary (frida-server) for advanced configurations. Usually not required as pip install handles this automatically.',
      required: false,
      env_vars: ['FRIDA_PATH'],
      examples: WINDOWS_FRIDA_EXAMPLES,
    },
    {
      key: 'frida_script_root',
      label: 'Frida scripts directory',
      summary:
        'Optional: Provide the absolute path to a directory containing custom Frida scripts for reuse across analysis sessions.',
      required: false,
      env_vars: ['FRIDA_SCRIPT_ROOT'],
      examples: ['C:\\tools\\frida-scripts', 'D:\\analysis\\frida-scripts'],
    },
  ]
}

export function buildFridaSetupActions(): SetupAction[] {
  return [
    {
      id: 'install_frida_runtime',
      required: false,
      kind: 'pip_install',
      title: 'Install Frida runtime',
      summary:
        'Install the Frida runtime for dynamic instrumentation. This provides the core functionality for process instrumentation and API tracing.',
      command: 'python -m pip install frida',
      examples: ['python -m pip install frida'],
      applies_to: ['frida.runtime.instrument', 'system.health'],
    },
    {
      id: 'install_frida_tools_package',
      required: false,
      kind: 'pip_install',
      title: 'Install Frida tools package',
      summary:
        'Install frida-tools for additional CLI utilities and script compilation support.',
      command: 'python -m pip install frida-tools',
      examples: ['python -m pip install frida-tools'],
      applies_to: ['frida.script.inject', 'system.health'],
    },
    {
      id: 'verify_frida_install',
      required: false,
      kind: 'verify_install',
      title: 'Verify Frida installation',
      summary:
        'Confirm that Frida can be imported in Python and the frida-server binary is accessible.',
      command: 'python -c "import frida; print(frida.__version__)"',
      examples: ['python -c "import frida; print(frida.__version__)"', 'frida-ps --help'],
      applies_to: ['frida.runtime.instrument', 'system.health'],
    },
    {
      id: 'set_frida_script_root',
      required: false,
      kind: 'set_env',
      title: 'Set FRIDA_SCRIPT_ROOT',
      summary:
        'Optionally set FRIDA_SCRIPT_ROOT to a directory containing custom Frida scripts for reuse.',
      env_var: 'FRIDA_SCRIPT_ROOT',
      value_hint: 'Absolute path to a directory containing Frida scripts',
      examples: WINDOWS_FRIDA_EXAMPLES.map(() => `$env:FRIDA_SCRIPT_ROOT = "C:\\tools\\frida-scripts"`),
      applies_to: ['frida.script.inject', 'system.health'],
    },
  ]
}

export function buildHeavyBackendSetupActions(): SetupAction[] {
  return [
    {
      id: 'install_retdec_backend',
      required: false,
      kind: 'install_package',
      title: 'Install RetDec',
      summary:
        'Install the RetDec release bundle when you want an additional heavy decompiler/fileinfo backend beyond Ghidra and compiler/packer triage.',
      command:
        'curl -fsSL https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz | tar -xJf - -C /opt/retdec --strip-components=1',
      examples: [
        'curl -fsSL https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz | tar -xJf - -C /opt/retdec --strip-components=1',
      ],
      applies_to: ['system.health', 'system.setup.guide'],
    },
    {
      id: 'set_retdec_path',
      required: false,
      kind: 'set_env',
      title: 'Set RETDEC_PATH',
      summary:
        'Set RETDEC_PATH to the retdec-decompiler executable when it is installed outside the default PATH layout.',
      env_var: 'RETDEC_PATH',
      value_hint: 'Absolute path to retdec-decompiler',
      examples: LINUX_RETDEC_EXAMPLES.map((example) => `export RETDEC_PATH="${example}"`),
      applies_to: ['system.health', 'system.setup.guide'],
    },
    {
      id: 'verify_retdec_install',
      required: false,
      kind: 'verify_install',
      title: 'Verify RetDec installation',
      summary:
        'Confirm that retdec-decompiler and retdec-fileinfo launch successfully before using them in artifact-first workflows.',
      command: 'retdec-decompiler --help && retdec-fileinfo --help',
      examples: ['retdec-decompiler --help', 'retdec-fileinfo --help'],
      applies_to: ['system.health', 'system.setup.guide'],
    },
  ]
}

export function buildJavaRequiredUserInputs(): RequiredUserInput[] {
  return [
    {
      key: 'java_home',
      label: 'Java 21+ install root',
      summary:
        'Provide the absolute path to a Java 21 or newer installation root so Ghidra can launch reliably.',
      required: true,
      env_vars: ['JAVA_HOME'],
      examples: WINDOWS_JAVA_EXAMPLES,
    },
  ]
}

export function buildJavaSetupActions(): SetupAction[] {
  return [
    {
      id: 'install_java_21',
      required: true,
      kind: 'provide_path',
      title: 'Install Java 21 or newer',
      summary:
        'Install a Java 21+ runtime or JDK before using Ghidra 12.x features that depend on a supported JVM.',
      value_hint: 'Path to the Java 21+ installation root',
      examples: WINDOWS_JAVA_EXAMPLES,
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
    {
      id: 'set_java_home',
      required: true,
      kind: 'set_env',
      title: 'Set JAVA_HOME',
      summary:
        'Set JAVA_HOME to the Java 21+ installation root so Ghidra launchers can resolve the correct JVM.',
      env_var: 'JAVA_HOME',
      value_hint: 'Absolute path to the Java 21+ installation root',
      examples: WINDOWS_JAVA_EXAMPLES.map((example) => `$env:JAVA_HOME = "${example}"`),
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
    {
      id: 'verify_java_version',
      required: true,
      kind: 'verify_install',
      title: 'Verify Java runtime version',
      summary:
        'Confirm that java -version resolves to Java 21 or newer before retrying Ghidra analysis.',
      command: 'java -version',
      examples: ['java -version'],
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
  ]
}

export function buildPyGhidraSetupActions(): SetupAction[] {
  return [
    {
      id: 'install_pyghidra',
      required: false,
      kind: 'pip_install',
      title: 'Install PyGhidra',
      summary:
        'Install PyGhidra in the active Python environment to improve Ghidra post-script compatibility.',
      command: 'python -m pip install pyghidra',
      examples: ['python -m pip install pyghidra'],
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
  ]
}

export function buildGhidraRequiredUserInputs(): RequiredUserInput[] {
  return [
    {
      key: 'ghidra_install_dir',
      label: 'Ghidra install root',
      summary:
        'Provide the absolute path to the Ghidra installation root. This is the directory that contains support\\analyzeHeadless.bat.',
      required: true,
      env_vars: ['GHIDRA_PATH', 'GHIDRA_INSTALL_DIR'],
      examples: WINDOWS_GHIDRA_EXAMPLES,
    },
    {
      key: 'ghidra_project_root',
      label: 'Ghidra project root',
      summary:
        'Optional writable directory where Ghidra projects should be created and reused. If omitted, the server uses its default user-level project root.',
      required: false,
      env_vars: ['GHIDRA_PROJECT_ROOT'],
      examples: ['C:\\Temp\\GhidraProjects', 'D:\\Analysis\\GhidraProjects'],
    },
  ]
}

export function buildGhidraSetupActions(): SetupAction[] {
  return [
    {
      id: 'set_ghidra_path',
      required: true,
      kind: 'set_env',
      title: 'Set GHIDRA_PATH',
      summary:
        'Set GHIDRA_PATH to the Ghidra installation root so the server can find support\\analyzeHeadless.bat.',
      env_var: 'GHIDRA_PATH',
      value_hint: 'Absolute path to the Ghidra installation root directory',
      examples: WINDOWS_GHIDRA_EXAMPLES.map((example) => `$env:GHIDRA_PATH = "${example}"`),
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
    {
      id: 'set_ghidra_install_dir',
      required: false,
      kind: 'set_env',
      title: 'Set GHIDRA_INSTALL_DIR',
      summary:
        'As an alternative to GHIDRA_PATH, set GHIDRA_INSTALL_DIR to the same Ghidra installation root.',
      env_var: 'GHIDRA_INSTALL_DIR',
      value_hint: 'Absolute path to the Ghidra installation root directory',
      examples: WINDOWS_GHIDRA_EXAMPLES.map((example) => `$env:GHIDRA_INSTALL_DIR = "${example}"`),
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
    {
      id: 'verify_ghidra_install_layout',
      required: true,
      kind: 'verify_install',
      title: 'Verify Ghidra install layout',
      summary:
        'Confirm the configured directory contains support\\analyzeHeadless.bat. Do not point GHIDRA_PATH at the support subdirectory itself.',
      examples: WINDOWS_GHIDRA_EXAMPLES.map((example) => `${example}\\support\\analyzeHeadless.bat`),
      applies_to: ['ghidra.health', 'ghidra.analyze'],
    },
    {
      id: 'set_ghidra_project_root',
      required: false,
      kind: 'set_env',
      title: 'Set GHIDRA_PROJECT_ROOT',
      summary:
        'Optionally set GHIDRA_PROJECT_ROOT to a stable writable directory where Ghidra projects and reuse state should be stored.',
      env_var: 'GHIDRA_PROJECT_ROOT',
      value_hint: 'Absolute path to a writable Ghidra project root directory',
      examples: [
        '$env:GHIDRA_PROJECT_ROOT = "C:\\Temp\\GhidraProjects"',
        '$env:GHIDRA_PROJECT_ROOT = "D:\\Analysis\\GhidraProjects"',
      ],
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
    {
      id: 'set_ghidra_log_root',
      required: false,
      kind: 'set_env',
      title: 'Set GHIDRA_LOG_ROOT',
      summary:
        'Optionally set GHIDRA_LOG_ROOT to control where analyzeHeadless command logs are persisted for troubleshooting.',
      env_var: 'GHIDRA_LOG_ROOT',
      value_hint: 'Absolute path to a writable Ghidra log directory',
      examples: [
        '$env:GHIDRA_LOG_ROOT = "C:\\Temp\\GhidraLogs"',
        '$env:GHIDRA_LOG_ROOT = "D:\\Analysis\\GhidraLogs"',
      ],
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
  ]
}

export function buildAllSetupActions(includeOptional = true): SetupAction[] {
  return mergeSetupActions(
    buildBaselinePythonSetupActions(),
    buildStaticAnalysisSetupActions(),
    includeOptional ? buildCoreLinuxToolchainSetupActions() : [],
    buildDynamicDependencySetupActions(),
    buildJavaSetupActions(),
    buildGhidraSetupActions(),
    includeOptional ? buildHeavyBackendSetupActions() : [],
    includeOptional ? buildPyGhidraSetupActions() : [],
    includeOptional ? buildFridaSetupActions() : []
  )
}

function inferSetupGuidanceFromMessages(messages: string[]) {
  const combined = messages.join('\n')
  let setupActions: SetupAction[] = []
  let requiredUserInputs: RequiredUserInput[] = []

  if (/ghidra|analyzeheadless|project_.*ghidra|support\\analyzeHeadless/i.test(combined)) {
    setupActions = mergeSetupActions(setupActions, buildGhidraSetupActions())
    requiredUserInputs = mergeRequiredUserInputs(requiredUserInputs, buildGhidraRequiredUserInputs())
  }
  if (/JAVA_HOME|UnsupportedClassVersionError|class file version|java runtime|java version|java 21/i.test(combined)) {
    setupActions = mergeSetupActions(setupActions, buildJavaSetupActions())
    requiredUserInputs = mergeRequiredUserInputs(requiredUserInputs, buildJavaRequiredUserInputs())
  }
  if (/pyghidra/i.test(combined)) {
    setupActions = mergeSetupActions(setupActions, buildPyGhidraSetupActions())
  }
  if (
    /python worker|module not found|modulenotfounderror|no module named|yara-python|yara-x|flare-floss|flare-capa|capa rules|pefile|lief|detect it easy|diec|speakeasy|frida|psutil|qiling|angr|pandare|panda|retdec|rizin|graphviz|upx|wine|winedbg|pip install/i.test(
      combined
    )
  ) {
    setupActions = mergeSetupActions(
      setupActions,
      buildBaselinePythonSetupActions(),
      buildStaticAnalysisSetupActions()
    )
    requiredUserInputs = mergeRequiredUserInputs(
      requiredUserInputs,
      buildStaticAnalysisRequiredUserInputs()
    )
    if (/graphviz|rizin|yara-x|upx|wine|winedbg/i.test(combined)) {
      setupActions = mergeSetupActions(setupActions, buildCoreLinuxToolchainSetupActions())
    }
    if (/speakeasy|frida|psutil|qiling|angr|pandare|panda|wine|winedbg/i.test(combined)) {
      setupActions = mergeSetupActions(setupActions, buildDynamicDependencySetupActions())
      requiredUserInputs = mergeRequiredUserInputs(requiredUserInputs, buildDynamicDependencyRequiredUserInputs())
    }
    if (/frida/i.test(combined)) {
      setupActions = mergeSetupActions(setupActions, buildFridaSetupActions())
      requiredUserInputs = mergeRequiredUserInputs(requiredUserInputs, buildFridaRequiredUserInputs())
    }
    if (/retdec/i.test(combined)) {
      setupActions = mergeSetupActions(setupActions, buildHeavyBackendSetupActions())
    }
  }

  return {
    setupActions,
    requiredUserInputs,
  }
}

export { inferSetupGuidanceFromMessages }

export function collectSetupGuidanceFromWorkerResult(result?: WorkerResult | null) {
  if (!result) {
    return {
      setupActions: [] as SetupAction[],
      requiredUserInputs: [] as RequiredUserInput[],
    }
  }

  const data = result.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  const setupActions = Array.isArray(data.setup_actions)
    ? data.setup_actions.filter(Boolean).map((item) => SetupActionSchema.parse(item))
    : []
  const requiredUserInputs = Array.isArray(data.required_user_inputs)
    ? data.required_user_inputs.filter(Boolean).map((item) => RequiredUserInputSchema.parse(item))
    : []

  const inferred = inferSetupGuidanceFromMessages([
    ...(result.errors || []),
    ...(result.warnings || []),
  ])

  return {
    setupActions: mergeSetupActions(setupActions, inferred.setupActions),
    requiredUserInputs: mergeRequiredUserInputs(requiredUserInputs, inferred.requiredUserInputs),
  }
}
