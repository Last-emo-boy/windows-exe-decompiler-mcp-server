import fs from 'fs'
import path from 'path'
import { execFileSync } from 'child_process'
import { config, type Config } from './config.js'

export type ExecutableSource = 'config' | 'env' | 'path' | 'none'

export interface ExternalExecutableResolution {
  available: boolean
  source: ExecutableSource
  path: string | null
  version: string | null
  checked_candidates: string[]
  error: string | null
}

export interface CapaRulesResolution {
  available: boolean
  source: 'config' | 'env' | 'none'
  path: string | null
  error: string | null
}

export interface ToolchainBackendResolution {
  capa_cli: ExternalExecutableResolution
  capa_rules: CapaRulesResolution
  die: ExternalExecutableResolution
  graphviz: ExternalExecutableResolution
  rizin: ExternalExecutableResolution
  upx: ExternalExecutableResolution
  wine: ExternalExecutableResolution
  winedbg: ExternalExecutableResolution
  frida_cli: ExternalExecutableResolution
  yara_x: ExternalExecutableResolution
  qiling: ExternalExecutableResolution
  angr: ExternalExecutableResolution
  panda: ExternalExecutableResolution
  retdec: ExternalExecutableResolution
}

export type StaticBackendResolution = ToolchainBackendResolution

function pathExists(targetPath: string | null | undefined): targetPath is string {
  if (!targetPath || targetPath.trim().length === 0) {
    return false
  }
  try {
    fs.accessSync(targetPath, fs.constants.F_OK)
    return true
  } catch {
    return false
  }
}

function isExecutableFile(targetPath: string | null | undefined): targetPath is string {
  if (!pathExists(targetPath)) {
    return false
  }

  try {
    const stats = fs.statSync(targetPath)
    return stats.isFile()
  } catch {
    return false
  }
}

function uniquePreserve(values: string[]): string[] {
  const seen = new Set<string>()
  const output: string[] = []
  for (const value of values) {
    const normalized = value.trim()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    output.push(normalized)
  }
  return output
}

function splitPathEntries(rawPath: string | undefined): string[] {
  return (rawPath || '')
    .split(path.delimiter)
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
}

function expandExecutableCandidates(baseName: string): string[] {
  const candidates = [baseName]
  if (process.platform === 'win32') {
    const lower = baseName.toLowerCase()
    if (!lower.endsWith('.exe') && !lower.endsWith('.bat') && !lower.endsWith('.cmd')) {
      candidates.push(`${baseName}.exe`, `${baseName}.bat`, `${baseName}.cmd`)
    }
  }
  return candidates
}

function findOnPath(candidateNames: string[]): string | null {
  const entries = splitPathEntries(process.env.PATH)
  for (const entry of entries) {
    for (const candidateName of candidateNames) {
      for (const expanded of expandExecutableCandidates(candidateName)) {
        const absolutePath = path.join(entry, expanded)
        if (isExecutableFile(absolutePath)) {
          return absolutePath
        }
      }
    }
  }
  return null
}

function probeVersion(binaryPath: string, versionArgSets: string[][]): string | null {
  for (const args of versionArgSets) {
    try {
      const output = execFileSync(binaryPath, args, {
        encoding: 'utf8',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      const line = output.split(/\r?\n/).map((item) => item.trim()).find((item) => item.length > 0)
      if (line) {
        return line
      }
    } catch (error) {
      const stderr = (error as { stderr?: string | Buffer | null }).stderr
      const stdout = (error as { stdout?: string | Buffer | null }).stdout
      const combined = [stdout, stderr]
        .map((item) => (typeof item === 'string' ? item : Buffer.isBuffer(item) ? item.toString('utf8') : ''))
        .join('\n')
      const line = combined
        .split(/\r?\n/)
        .map((item) => item.trim())
        .find((item) => item.length > 0)
      if (line) {
        return line
      }
    }
  }
  return null
}

function resolveExecutable(options: {
  configuredPath?: string | null
  envPath?: string | null
  pathCandidates: string[]
  versionArgSets: string[][]
}): ExternalExecutableResolution {
  const checkedCandidates: string[] = []
  const configuredPath = options.configuredPath?.trim()
  if (configuredPath) {
    checkedCandidates.push(configuredPath)
    if (isExecutableFile(configuredPath)) {
      return {
        available: true,
        source: 'config',
        path: configuredPath,
        version: probeVersion(configuredPath, options.versionArgSets),
        checked_candidates: checkedCandidates,
        error: null,
      }
    }
    return {
      available: false,
      source: 'config',
      path: configuredPath,
      version: null,
      checked_candidates: checkedCandidates,
      error: 'Configured path does not exist or is not an executable file.',
    }
  }

  const envPath = options.envPath?.trim()
  if (envPath) {
    checkedCandidates.push(envPath)
    if (isExecutableFile(envPath)) {
      return {
        available: true,
        source: 'env',
        path: envPath,
        version: probeVersion(envPath, options.versionArgSets),
        checked_candidates: checkedCandidates,
        error: null,
      }
    }
    return {
      available: false,
      source: 'env',
      path: envPath,
      version: null,
      checked_candidates: checkedCandidates,
      error: 'Environment-provided path does not exist or is not an executable file.',
    }
  }

  const discovered = findOnPath(options.pathCandidates)
  checkedCandidates.push(...options.pathCandidates)
  if (discovered) {
    return {
      available: true,
      source: 'path',
      path: discovered,
      version: probeVersion(discovered, options.versionArgSets),
      checked_candidates: uniquePreserve(checkedCandidates),
      error: null,
    }
  }

  return {
    available: false,
    source: 'none',
    path: null,
    version: null,
    checked_candidates: uniquePreserve(checkedCandidates),
    error: 'Executable was not found in config, environment variables, or PATH.',
  }
}

function probePythonModule(options: {
  pythonPath: string
  moduleNames: string[]
  distributionNames?: string[]
}): { available: boolean; version: string | null; error: string | null } {
  const distributions = options.distributionNames && options.distributionNames.length > 0
    ? options.distributionNames
    : options.moduleNames

  const script = `
import importlib, importlib.metadata, json, sys
module_names = ${JSON.stringify(options.moduleNames)}
distribution_names = ${JSON.stringify(distributions)}
loaded = None
version = None
errors = []
for name in module_names:
    try:
        module = importlib.import_module(name)
        loaded = name
        version = getattr(module, "__version__", None)
        break
    except Exception as exc:
        errors.append(f"{name}: {exc}")
if version is None:
    for name in distribution_names:
        try:
            version = importlib.metadata.version(name)
            break
        except Exception:
            pass
print(json.dumps({"loaded": loaded, "version": version, "errors": errors}))
sys.exit(0 if loaded else 1)
`.trim()

  try {
    const output = execFileSync(options.pythonPath, ['-c', script], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const parsed = JSON.parse(output.trim())
    return {
      available: true,
      version: parsed.version || null,
      error: null,
    }
  } catch (error) {
    const stdout = (error as { stdout?: string | Buffer | null }).stdout
    const stderr = (error as { stderr?: string | Buffer | null }).stderr
    const combined = [stdout, stderr]
      .map((item) => (typeof item === 'string' ? item : Buffer.isBuffer(item) ? item.toString('utf8') : ''))
      .join('\n')
      .trim()
    const line = combined.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).pop()
    if (line) {
      try {
        const parsed = JSON.parse(line)
        const errorText = Array.isArray(parsed.errors) ? parsed.errors.join('; ') : 'Module import failed'
        return {
          available: false,
          version: parsed.version || null,
          error: errorText || 'Module import failed',
        }
      } catch {
        // Fall through to generic message.
      }
    }
    return {
      available: false,
      version: null,
      error: combined || 'Module import failed',
    }
  }
}

function resolvePythonModuleBackend(options: {
  configuredPythonPath?: string | null
  envPythonPath?: string | null
  pathCandidates?: string[]
  moduleNames: string[]
  distributionNames?: string[]
}): ExternalExecutableResolution {
  const checkedCandidates: string[] = []
  const candidates = options.pathCandidates && options.pathCandidates.length > 0 ? options.pathCandidates : ['python3', 'python']

  const configuredPath = options.configuredPythonPath?.trim()
  if (configuredPath) {
    checkedCandidates.push(configuredPath)
    if (!isExecutableFile(configuredPath)) {
      return {
        available: false,
        source: 'config',
        path: configuredPath,
        version: null,
        checked_candidates: checkedCandidates,
        error: 'Configured interpreter path does not exist or is not executable.',
      }
    }
    const probe = probePythonModule({
      pythonPath: configuredPath,
      moduleNames: options.moduleNames,
      distributionNames: options.distributionNames,
    })
    return {
      available: probe.available,
      source: 'config',
      path: configuredPath,
      version: probe.version,
      checked_candidates: checkedCandidates,
      error: probe.error,
    }
  }

  const envPath = options.envPythonPath?.trim()
  if (envPath) {
    checkedCandidates.push(envPath)
    if (!isExecutableFile(envPath)) {
      return {
        available: false,
        source: 'env',
        path: envPath,
        version: null,
        checked_candidates: checkedCandidates,
        error: 'Environment-provided interpreter path does not exist or is not executable.',
      }
    }
    const probe = probePythonModule({
      pythonPath: envPath,
      moduleNames: options.moduleNames,
      distributionNames: options.distributionNames,
    })
    return {
      available: probe.available,
      source: 'env',
      path: envPath,
      version: probe.version,
      checked_candidates: checkedCandidates,
      error: probe.error,
    }
  }

  const discovered = findOnPath(candidates)
  checkedCandidates.push(...candidates)
  if (discovered) {
    const probe = probePythonModule({
      pythonPath: discovered,
      moduleNames: options.moduleNames,
      distributionNames: options.distributionNames,
    })
    return {
      available: probe.available,
      source: 'path',
      path: discovered,
      version: probe.version,
      checked_candidates: uniquePreserve(checkedCandidates),
      error: probe.error,
    }
  }

  return {
    available: false,
    source: 'none',
    path: null,
    version: null,
    checked_candidates: uniquePreserve(checkedCandidates),
    error: 'Python interpreter for module probe was not found in config, environment variables, or PATH.',
  }
}

export function resolveCapaRulesPath(currentConfig: Config = config): CapaRulesResolution {
  const configuredPath = currentConfig.workers.static.capaRulesPath?.trim()
  if (configuredPath) {
    if (pathExists(configuredPath)) {
      return {
        available: true,
        source: 'config',
        path: configuredPath,
        error: null,
      }
    }
    return {
      available: false,
      source: 'config',
      path: configuredPath,
      error: 'Configured capa rules path does not exist.',
    }
  }

  const envPath = process.env.CAPA_RULES_PATH?.trim()
  if (envPath) {
    if (pathExists(envPath)) {
      return {
        available: true,
        source: 'env',
        path: envPath,
        error: null,
      }
    }
    return {
      available: false,
      source: 'env',
      path: envPath,
      error: 'Environment-provided capa rules path does not exist.',
    }
  }

  return {
    available: false,
    source: 'none',
    path: null,
    error: 'No capa rules path was configured.',
  }
}

export function resolveCapaCli(currentConfig: Config = config): ExternalExecutableResolution {
  return resolveExecutable({
    configuredPath: currentConfig.workers.static.capaPath,
    envPath: process.env.CAPA_PATH,
    pathCandidates: ['capa'],
    versionArgSets: [['--version'], ['-v']],
  })
}

export function resolveDieCli(currentConfig: Config = config): ExternalExecutableResolution {
  return resolveExecutable({
    configuredPath: currentConfig.workers.static.diePath,
    envPath: process.env.DIE_PATH,
    pathCandidates: ['diec', 'die'],
    versionArgSets: [['--version'], ['-v'], ['-h']],
  })
}

export function resolveAnalysisBackends(currentConfig: Config = config): ToolchainBackendResolution {
  return {
    capa_cli: resolveCapaCli(currentConfig),
    capa_rules: resolveCapaRulesPath(currentConfig),
    die: resolveDieCli(currentConfig),
    graphviz: resolveExecutable({
      configuredPath: currentConfig.workers.static.graphvizDotPath,
      envPath: process.env.GRAPHVIZ_DOT_PATH,
      pathCandidates: ['dot'],
      versionArgSets: [['-V']],
    }),
    rizin: resolveExecutable({
      configuredPath: currentConfig.workers.static.rizinPath,
      envPath: process.env.RIZIN_PATH,
      pathCandidates: ['rizin', 'rz-bin'],
      versionArgSets: [['-v']],
    }),
    upx: resolveExecutable({
      configuredPath: currentConfig.workers.static.upxPath,
      envPath: process.env.UPX_PATH,
      pathCandidates: ['upx'],
      versionArgSets: [['--version'], ['-V']],
    }),
    wine: resolveExecutable({
      configuredPath: currentConfig.workers.sandbox.winePath,
      envPath: process.env.WINE_PATH,
      pathCandidates: ['wine'],
      versionArgSets: [['--version']],
    }),
    winedbg: resolveExecutable({
      configuredPath: currentConfig.workers.sandbox.winedbgPath,
      envPath: process.env.WINEDBG_PATH,
      pathCandidates: ['winedbg'],
      versionArgSets: [['--version'], ['--help']],
    }),
    frida_cli: resolveExecutable({
      pathCandidates: ['frida-ps', 'frida-trace'],
      versionArgSets: [['--version'], ['--help']],
    }),
    yara_x: resolvePythonModuleBackend({
      configuredPythonPath: currentConfig.workers.static.yaraXPythonPath,
      envPythonPath: process.env.YARAX_PYTHON,
      moduleNames: ['yara_x'],
      distributionNames: ['yara-x'],
    }),
    qiling: resolvePythonModuleBackend({
      configuredPythonPath: currentConfig.workers.sandbox.qilingPythonPath,
      envPythonPath: process.env.QILING_PYTHON,
      moduleNames: ['qiling'],
      distributionNames: ['qiling'],
    }),
    angr: resolvePythonModuleBackend({
      configuredPythonPath: currentConfig.workers.sandbox.angrPythonPath,
      envPythonPath: process.env.ANGR_PYTHON,
      moduleNames: ['angr'],
      distributionNames: ['angr'],
    }),
    panda: resolvePythonModuleBackend({
      configuredPythonPath: currentConfig.workers.sandbox.pandaPythonPath,
      envPythonPath: process.env.PANDA_PYTHON,
      moduleNames: ['pandare'],
      distributionNames: ['pandare'],
    }),
    retdec: resolveExecutable({
      configuredPath: currentConfig.workers.static.retdecPath,
      envPath: process.env.RETDEC_PATH,
      pathCandidates: ['retdec-decompiler'],
      versionArgSets: [['--version'], ['--help']],
    }),
  }
}

export function resolveStaticBackends(currentConfig: Config = config): StaticBackendResolution {
  return resolveAnalysisBackends(currentConfig)
}
