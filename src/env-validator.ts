/**
 * Environment validation for MCP Server
 * Validates that required dependencies and paths exist
 */

import fs from 'fs'
import path from 'path'
import { safeCommandExists, safeGetCommandVersion } from './safe-command.js'
import type { Config } from './config.js'

export interface ValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
}

/**
 * Check if a file or directory exists
 */
function pathExists(path: string): boolean {
  try {
    fs.accessSync(path, fs.constants.F_OK)
    return true
  } catch {
    return false
  }
}

/**
 * Check if a command is available in PATH
 */
function commandExists(command: string): boolean {
  return safeCommandExists(command)
}

/**
 * Validate Node.js version
 */
function validateNodeVersion(): { valid: boolean; error?: string } {
  const version = process.version
  const major = parseInt(version.slice(1).split('.')[0], 10)
  
  if (major < 18) {
    return {
      valid: false,
      error: `Node.js version ${version} is not supported. Minimum required version is 18.0.0`,
    }
  }
  
  return { valid: true }
}

/**
 * Validate workspace directory
 */
function validateWorkspace(workspaceRoot: string): { valid: boolean; error?: string; warning?: string } {
  if (!pathExists(workspaceRoot)) {
    try {
      fs.mkdirSync(workspaceRoot, { recursive: true })
      return { valid: true, warning: `Created workspace directory: ${workspaceRoot}` }
    } catch (error) {
      return {
        valid: false,
        error: `Failed to create workspace directory ${workspaceRoot}: ${(error as Error).message}`,
      }
    }
  }

  // Check if directory is writable
  try {
    fs.accessSync(workspaceRoot, fs.constants.W_OK)
    return { valid: true }
  } catch {
    return {
      valid: false,
      error: `Workspace directory ${workspaceRoot} is not writable`,
    }
  }
}

/**
 * Validate database configuration
 */
function validateDatabase(dbConfig: Config['database']): { valid: boolean; error?: string; warning?: string } {
  if (dbConfig.type === 'sqlite') {
    if (dbConfig.path) {
      const dir = path.dirname(dbConfig.path)
      if (dir && dir !== '.' && !pathExists(dir)) {
        try {
          fs.mkdirSync(dir, { recursive: true })
          return { valid: true, warning: `Created database directory: ${dir}` }
        } catch (error) {
          return {
            valid: false,
            error: `Failed to create database directory ${dir}: ${(error as Error).message}`,
          }
        }
      }
    }
    return { valid: true }
  }

  if (dbConfig.type === 'postgresql') {
    if (!dbConfig.host || !dbConfig.database) {
      return {
        valid: false,
        error: 'PostgreSQL configuration requires host and database name',
      }
    }
    return { valid: true }
  }

  return { valid: true }
}

/**
 * Validate Ghidra worker configuration
 */
function validateGhidraWorker(ghidraConfig: Config['workers']['ghidra']): {
  valid: boolean
  error?: string
  warning?: string
} {
  if (!ghidraConfig.enabled) {
    return { valid: true }
  }

  if (!ghidraConfig.path) {
    return {
      valid: false,
      error: 'Ghidra worker is enabled but GHIDRA_PATH is not configured',
    }
  }

  if (!pathExists(ghidraConfig.path)) {
    return {
      valid: false,
      error: `Ghidra path does not exist: ${ghidraConfig.path}`,
    }
  }

  // Check for analyzeHeadless script
  const analyzeHeadless = `${ghidraConfig.path}/support/analyzeHeadless`
  if (!pathExists(analyzeHeadless) && !pathExists(`${analyzeHeadless}.bat`)) {
    return {
      valid: false,
      error: `Ghidra analyzeHeadless script not found at ${analyzeHeadless}`,
    }
  }

  return { valid: true }
}

/**
 * Validate Python worker configuration
 */
function validatePythonWorker(staticConfig: Config['workers']['static']): {
  valid: boolean
  error?: string
  warning?: string
} {
  if (!staticConfig.enabled) {
    return { valid: true }
  }

  const pythonCmd = staticConfig.pythonPath || 'python3'
  
  if (!commandExists(pythonCmd)) {
    return {
      valid: false,
      error: `Python command not found: ${pythonCmd}`,
    }
  }

  // Check Python version
  try {
    const version = safeGetCommandVersion(pythonCmd, '--version') || ''
    const match = version.match(/Python (\d+)\.(\d+)/)
    if (match) {
      const major = parseInt(match[1], 10)
      const minor = parseInt(match[2], 10)
      if (major < 3 || (major === 3 && minor < 9)) {
        return {
          valid: false,
          error: `Python version ${version.trim()} is not supported. Minimum required version is 3.9`,
        }
      }
    }
  } catch (error) {
    return {
      valid: false,
      error: `Failed to check Python version: ${(error as Error).message}`,
    }
  }

  return { valid: true }
}

/**
 * Validate .NET worker configuration
 */
function validateDotNetWorker(dotnetConfig: Config['workers']['dotnet']): {
  valid: boolean
  error?: string
  warning?: string
} {
  if (!dotnetConfig.enabled) {
    return { valid: true }
  }

  if (!dotnetConfig.ilspyPath) {
    return {
      valid: false,
      error: '.NET worker is enabled but ilspyPath is not configured',
    }
  }

  if (!pathExists(dotnetConfig.ilspyPath)) {
    return {
      valid: false,
      error: `ILSpy path does not exist: ${dotnetConfig.ilspyPath}`,
    }
  }

  return { valid: true }
}

/**
 * Validate the entire environment based on configuration
 */
export function validateEnvironment(config: Config): ValidationResult {
  const errors: string[] = []
  const warnings: string[] = []

  // Validate Node.js version
  const nodeValidation = validateNodeVersion()
  if (!nodeValidation.valid && nodeValidation.error) {
    errors.push(nodeValidation.error)
  }

  // Validate workspace
  const workspaceValidation = validateWorkspace(config.workspace.root)
  if (!workspaceValidation.valid && workspaceValidation.error) {
    errors.push(workspaceValidation.error)
  }
  if (workspaceValidation.warning) {
    warnings.push(workspaceValidation.warning)
  }

  // Validate database
  const dbValidation = validateDatabase(config.database)
  if (!dbValidation.valid && dbValidation.error) {
    errors.push(dbValidation.error)
  }
  if (dbValidation.warning) {
    warnings.push(dbValidation.warning)
  }

  // Validate workers
  const ghidraValidation = validateGhidraWorker(config.workers.ghidra)
  if (!ghidraValidation.valid && ghidraValidation.error) {
    errors.push(ghidraValidation.error)
  }
  if (ghidraValidation.warning) {
    warnings.push(ghidraValidation.warning)
  }

  const pythonValidation = validatePythonWorker(config.workers.static)
  if (!pythonValidation.valid && pythonValidation.error) {
    errors.push(pythonValidation.error)
  }
  if (pythonValidation.warning) {
    warnings.push(pythonValidation.warning)
  }

  const dotnetValidation = validateDotNetWorker(config.workers.dotnet)
  if (!dotnetValidation.valid && dotnetValidation.error) {
    errors.push(dotnetValidation.error)
  }
  if (dotnetValidation.warning) {
    warnings.push(dotnetValidation.warning)
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  }
}
