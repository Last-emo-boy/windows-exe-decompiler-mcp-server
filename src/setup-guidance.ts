import { z } from 'zod'
import type { WorkerResult } from './types.js'

export const SetupActionSchema = z.object({
  id: z.string(),
  required: z.boolean(),
  kind: z.enum(['pip_install', 'set_env', 'provide_path', 'verify_install']),
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
      applies_to: ['dynamic.dependencies'],
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
      examples: WINDOWS_GHIDRA_EXAMPLES.map(
        (example) => `$env:GHIDRA_PATH = "${example}"`
      ),
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
      examples: WINDOWS_GHIDRA_EXAMPLES.map(
        (example) => `$env:GHIDRA_INSTALL_DIR = "${example}"`
      ),
      applies_to: ['ghidra.health', 'ghidra.analyze', 'system.health'],
    },
    {
      id: 'verify_ghidra_install_layout',
      required: true,
      kind: 'verify_install',
      title: 'Verify Ghidra install layout',
      summary:
        'Confirm the configured directory contains support\\analyzeHeadless.bat. Do not point GHIDRA_PATH at the support subdirectory itself.',
      examples: WINDOWS_GHIDRA_EXAMPLES.map(
        (example) => `${example}\\support\\analyzeHeadless.bat`
      ),
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
    buildDynamicDependencySetupActions(),
    buildJavaSetupActions(),
    buildGhidraSetupActions(),
    includeOptional ? buildPyGhidraSetupActions() : []
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
    /python worker|module not found|modulenotfounderror|no module named|yara-python|flare-floss|speakeasy|frida|psutil|pip install/i.test(
      combined
    )
  ) {
    setupActions = mergeSetupActions(setupActions, buildBaselinePythonSetupActions())
    if (/speakeasy|frida|psutil/i.test(combined)) {
      setupActions = mergeSetupActions(setupActions, buildDynamicDependencySetupActions())
    }
  }

  return {
    setupActions,
    requiredUserInputs,
  }
}

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
