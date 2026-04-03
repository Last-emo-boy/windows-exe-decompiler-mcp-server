/**
 * Configuration validation & startup diagnostics
 * Validates config, checks tool availability, and reports issues.
 */

import fs from 'fs'
import path from 'path'
import { execFileSync } from 'child_process'
import type { Config } from './config.js'
import { logger } from './logger.js'

export interface DiagnosticItem {
  category: string
  key: string
  status: 'ok' | 'warn' | 'error'
  message: string
  value?: unknown
}

export interface ValidationReport {
  valid: boolean
  timestamp: string
  diagnostics: DiagnosticItem[]
  summary: { ok: number; warn: number; error: number }
}

function checkPathExists(label: string, p: string | undefined): DiagnosticItem {
  if (!p) {
    return { category: 'path', key: label, status: 'warn', message: `${label} not configured` }
  }
  if (fs.existsSync(p)) {
    return { category: 'path', key: label, status: 'ok', message: `${label} exists`, value: p }
  }
  return { category: 'path', key: label, status: 'error', message: `${label} not found at ${p}`, value: p }
}

function checkExecutable(label: string, p: string | undefined): DiagnosticItem {
  if (!p) {
    return { category: 'tool', key: label, status: 'warn', message: `${label} not configured` }
  }
  try {
    execFileSync(p, ['--version'], { timeout: 5000, stdio: 'pipe' })
    return { category: 'tool', key: label, status: 'ok', message: `${label} reachable`, value: p }
  } catch {
    return { category: 'tool', key: label, status: 'warn', message: `${label} configured but not executable`, value: p }
  }
}

function checkDirectory(label: string, p: string): DiagnosticItem {
  try {
    if (!fs.existsSync(p)) {
      fs.mkdirSync(p, { recursive: true })
      return { category: 'dir', key: label, status: 'ok', message: `${label} created`, value: p }
    }
    fs.accessSync(p, fs.constants.W_OK)
    return { category: 'dir', key: label, status: 'ok', message: `${label} writable`, value: p }
  } catch {
    return { category: 'dir', key: label, status: 'error', message: `${label} not writable`, value: p }
  }
}

export function validateConfig(config: Config): ValidationReport {
  const diagnostics: DiagnosticItem[] = []

  // Core directories
  diagnostics.push(checkDirectory('workspace_root', config.workspace.root))
  diagnostics.push(checkDirectory('cache_root', config.cache.root))
  diagnostics.push(checkDirectory('database_dir', path.dirname(config.database.path)))

  // Ghidra
  if (config.workers.ghidra.enabled) {
    diagnostics.push(checkPathExists('ghidra_path', config.workers.ghidra.path))
    diagnostics.push(checkDirectory('ghidra_project_root', config.workers.ghidra.projectRoot))
    diagnostics.push(checkDirectory('ghidra_log_root', config.workers.ghidra.logRoot))
  } else {
    diagnostics.push({ category: 'worker', key: 'ghidra', status: 'warn', message: 'Ghidra worker disabled' })
  }

  // Static analysis tools
  if (config.workers.static.enabled) {
    diagnostics.push(checkExecutable('python', config.workers.static.pythonPath))
    diagnostics.push(checkPathExists('capa', config.workers.static.capaPath))
    diagnostics.push(checkPathExists('die', config.workers.static.diePath))
    diagnostics.push(checkPathExists('rizin', config.workers.static.rizinPath))
    diagnostics.push(checkPathExists('retdec', config.workers.static.retdecPath))
    diagnostics.push(checkPathExists('jadx', config.workers.static.jadxPath))
  }

  // .NET worker
  if (config.workers.dotnet.enabled) {
    diagnostics.push(checkPathExists('ilspy', config.workers.dotnet.ilspyPath))
  }

  // Sandbox
  if (config.workers.sandbox.enabled) {
    diagnostics.push(checkPathExists('wine', config.workers.sandbox.winePath))
    diagnostics.push(checkPathExists('qiling_python', config.workers.sandbox.qilingPythonPath))
  }

  // Frida
  if (config.workers.frida.enabled) {
    diagnostics.push(checkPathExists('frida', config.workers.frida.path))
  }

  // API
  if (config.api.enabled) {
    diagnostics.push({ category: 'api', key: 'port', status: 'ok', message: `API port ${config.api.port}`, value: config.api.port })
    if (!config.api.apiKey) {
      diagnostics.push({ category: 'api', key: 'api_key', status: 'warn', message: 'No API key set — auto-generated at runtime' })
    }
  }

  // Database
  diagnostics.push({
    category: 'database',
    key: 'type',
    status: 'ok',
    message: `Database type: ${config.database.type}`,
    value: config.database.type,
  })

  const summary = {
    ok: diagnostics.filter(d => d.status === 'ok').length,
    warn: diagnostics.filter(d => d.status === 'warn').length,
    error: diagnostics.filter(d => d.status === 'error').length,
  }

  const report: ValidationReport = {
    valid: summary.error === 0,
    timestamp: new Date().toISOString(),
    diagnostics,
    summary,
  }

  // Log summary
  if (summary.error > 0) {
    logger.warn({ summary }, 'Configuration validation found errors')
  } else {
    logger.info({ summary }, 'Configuration validation passed')
  }

  return report
}
