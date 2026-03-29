/**
 * Configuration management for MCP Server
 * Handles loading and validating configuration from files and environment variables
 */

import { z } from 'zod'
import fs from 'fs'
import os from 'os'
import path from 'path'

export const APP_CONFIG_DIRNAME = '.windows-exe-decompiler-mcp-server'

export function getDefaultAppRoot(): string {
  return path.join(os.homedir(), APP_CONFIG_DIRNAME)
}

export function getDefaultWorkspaceRoot(): string {
  return path.join(getDefaultAppRoot(), 'workspaces')
}

export function getDefaultConfigPath(): string {
  return path.join(getDefaultAppRoot(), 'config.json')
}

export function getDefaultDatabasePath(): string {
  return path.join(getDefaultAppRoot(), 'data', 'database.db')
}

export function getDefaultCacheRoot(): string {
  return path.join(getDefaultAppRoot(), 'cache')
}

export function getDefaultAuditLogPath(): string {
  return path.join(getDefaultAppRoot(), 'audit.log')
}

export function getDefaultGhidraBaseRoot(): string {
  if (process.platform === 'win32') {
    const programData = process.env.ProgramData || process.env.PROGRAMDATA
    if (programData && programData.trim().length > 0) {
      return path.join(programData, APP_CONFIG_DIRNAME)
    }
    return path.join('C:\\', 'ProgramData', APP_CONFIG_DIRNAME)
  }

  return getDefaultAppRoot()
}

export function getDefaultGhidraProjectRoot(): string {
  return path.join(getDefaultGhidraBaseRoot(), 'ghidra-projects')
}

export function getDefaultGhidraLogRoot(): string {
  return path.join(getDefaultGhidraBaseRoot(), 'ghidra-logs')
}

// Configuration schema using Zod
export const ConfigSchema = z.object({
  server: z.object({
    port: z.number().int().min(1).max(65535).default(3000),
    host: z.string().default('localhost'),
  }).default({}),
  database: z.object({
    type: z.enum(['sqlite', 'postgresql']).default('sqlite'),
    path: z.string().default(getDefaultDatabasePath()),
    host: z.string().optional(),
    port: z.number().int().optional(),
    database: z.string().optional(),
    user: z.string().optional(),
    password: z.string().optional(),
  }).default({}),
  workspace: z.object({
    root: z.string().default(getDefaultWorkspaceRoot()),
    maxSampleSize: z.number().int().min(1).default(500 * 1024 * 1024), // 500MB
  }).default({}),
  workers: z.object({
    ghidra: z.object({
      enabled: z.boolean().default(false),
      path: z.string().optional(),
      projectRoot: z.string().default(getDefaultGhidraProjectRoot()),
      logRoot: z.string().default(getDefaultGhidraLogRoot()),
      cleanupAfterAnalysis: z.boolean().default(false),
      logRetentionDays: z.number().int().min(1).default(30),
      minJavaVersion: z.number().int().min(8).default(21),
      maxConcurrent: z.number().int().min(1).max(16).default(4),
      timeout: z.number().int().min(1).default(300),
    }).default({}),
    static: z.object({
      enabled: z.boolean().default(true),
      pythonPath: z.string().optional(),
      capaPath: z.string().optional(),
      capaRulesPath: z.string().optional(),
      diePath: z.string().optional(),
      graphvizDotPath: z.string().optional(),
      rizinPath: z.string().optional(),
      upxPath: z.string().optional(),
      retdecPath: z.string().optional(),
      yaraXPythonPath: z.string().optional(),
      dieTimeout: z.number().int().min(1).default(30),
      timeout: z.number().int().min(1).default(60),
    }).default({}),
    dotnet: z.object({
      enabled: z.boolean().default(false),
      ilspyPath: z.string().optional(),
      timeout: z.number().int().min(1).default(60),
    }).default({}),
    sandbox: z.object({
      enabled: z.boolean().default(false),
      winePath: z.string().optional(),
      winedbgPath: z.string().optional(),
      qilingPythonPath: z.string().optional(),
      qilingRootfsPath: z.string().optional(),
      angrPythonPath: z.string().optional(),
      pandaPythonPath: z.string().optional(),
      timeout: z.number().int().min(1).default(120),
    }).default({}),
    frida: z.object({
      enabled: z.boolean().default(false),
      path: z.string().optional(),
      scriptRoot: z.string().optional(),
      timeout: z.number().int().min(1).default(30),
    }).default({}),
  }).default({}),
  cache: z.object({
    enabled: z.boolean().default(true),
    root: z.string().default(getDefaultCacheRoot()),
    ttl: z.number().int().min(0).default(30 * 24 * 60 * 60), // 30 days
  }).default({}),
  logging: z.object({
    level: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
    pretty: z.boolean().default(false),
    auditPath: z.string().default(getDefaultAuditLogPath()),
  }).default({}),
  api: z.object({
    enabled: z.boolean().default(true),  // Default: enabled
    port: z.number().int().min(1).max(65535).default(18080),
    apiKey: z.string().optional(),  // Auto-generated if not set
    maxFileSize: z.number().int().min(1).default(500 * 1024 * 1024), // 500MB
    storageRoot: z.string().default('/app/storage'),
    retentionDays: z.number().int().min(1).default(30),
  }).default({
    enabled: true,
    port: 18080,
    maxFileSize: 500 * 1024 * 1024,
    storageRoot: '/app/storage',
    retentionDays: 30,
  }),
})

export type Config = z.infer<typeof ConfigSchema>

/**
 * Load configuration from a JSON file
 */
export function loadConfigFromFile(filePath: string): Partial<Config> {
  try {
    const content = fs.readFileSync(filePath, 'utf-8')
    return JSON.parse(content)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return {}
    }
    throw new Error(`Failed to load config from ${filePath}: ${(error as Error).message}`)
  }
}

/**
 * Load configuration from environment variables
 */
export function loadConfigFromEnv(): Record<string, any> {
  const config: Record<string, any> = {}

  // Server configuration
  if (process.env.SERVER_PORT) {
    if (!config.server) config.server = {}
    config.server.port = parseInt(process.env.SERVER_PORT, 10)
  }
  if (process.env.SERVER_HOST) {
    if (!config.server) config.server = {}
    config.server.host = process.env.SERVER_HOST
  }

  // Database configuration
  if (process.env.DB_TYPE) {
    if (!config.database) config.database = {}
    config.database.type = process.env.DB_TYPE
  }
  if (process.env.DB_PATH) {
    if (!config.database) config.database = {}
    config.database.path = process.env.DB_PATH
  }
  if (process.env.DB_HOST) {
    if (!config.database) config.database = {}
    config.database.host = process.env.DB_HOST
  }
  if (process.env.DB_PORT) {
    if (!config.database) config.database = {}
    config.database.port = parseInt(process.env.DB_PORT, 10)
  }

  // Workspace configuration
  if (process.env.WORKSPACE_ROOT) {
    if (!config.workspace) config.workspace = {}
    config.workspace.root = process.env.WORKSPACE_ROOT
  }
  if (process.env.CACHE_ROOT) {
    if (!config.cache) config.cache = {}
    config.cache.root = process.env.CACHE_ROOT
  }
  if (process.env.MAX_SAMPLE_SIZE) {
    if (!config.workspace) config.workspace = {}
    config.workspace.maxSampleSize = parseInt(process.env.MAX_SAMPLE_SIZE, 10)
  }

  // Worker configuration
  if (process.env.GHIDRA_PATH || process.env.GHIDRA_INSTALL_DIR) {
    if (!config.workers) config.workers = {}
    if (!config.workers.ghidra) config.workers.ghidra = {}
    config.workers.ghidra.path = process.env.GHIDRA_PATH || process.env.GHIDRA_INSTALL_DIR
    config.workers.ghidra.enabled = true
  }
  if (process.env.GHIDRA_PROJECT_ROOT) {
    if (!config.workers) config.workers = {}
    if (!config.workers.ghidra) config.workers.ghidra = {}
    config.workers.ghidra.projectRoot = process.env.GHIDRA_PROJECT_ROOT
  }
  if (process.env.GHIDRA_LOG_ROOT) {
    if (!config.workers) config.workers = {}
    if (!config.workers.ghidra) config.workers.ghidra = {}
    config.workers.ghidra.logRoot = process.env.GHIDRA_LOG_ROOT
  }
  if (process.env.GHIDRA_CLEANUP_AFTER_ANALYSIS) {
    if (!config.workers) config.workers = {}
    if (!config.workers.ghidra) config.workers.ghidra = {}
    config.workers.ghidra.cleanupAfterAnalysis =
      /^(1|true|yes|on)$/i.test(process.env.GHIDRA_CLEANUP_AFTER_ANALYSIS)
  }
  if (process.env.GHIDRA_LOG_RETENTION_DAYS) {
    if (!config.workers) config.workers = {}
    if (!config.workers.ghidra) config.workers.ghidra = {}
    config.workers.ghidra.logRetentionDays = parseInt(process.env.GHIDRA_LOG_RETENTION_DAYS, 10)
  }
  if (process.env.GHIDRA_MIN_JAVA_VERSION) {
    if (!config.workers) config.workers = {}
    if (!config.workers.ghidra) config.workers.ghidra = {}
    config.workers.ghidra.minJavaVersion = parseInt(process.env.GHIDRA_MIN_JAVA_VERSION, 10)
  }
  if (process.env.PYTHON_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.pythonPath = process.env.PYTHON_PATH
  }
  if (process.env.CAPA_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.capaPath = process.env.CAPA_PATH
  }
  if (process.env.CAPA_RULES_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.capaRulesPath = process.env.CAPA_RULES_PATH
  }
  if (process.env.DIE_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.diePath = process.env.DIE_PATH
  }
  if (process.env.GRAPHVIZ_DOT_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.graphvizDotPath = process.env.GRAPHVIZ_DOT_PATH
  }
  if (process.env.RIZIN_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.rizinPath = process.env.RIZIN_PATH
  }
  if (process.env.UPX_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.upxPath = process.env.UPX_PATH
  }
  if (process.env.RETDEC_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.retdecPath = process.env.RETDEC_PATH
  }
  if (process.env.YARAX_PYTHON) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.yaraXPythonPath = process.env.YARAX_PYTHON
  }
  if (process.env.DIE_TIMEOUT) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.dieTimeout = parseInt(process.env.DIE_TIMEOUT, 10)
  }
  if (process.env.WINE_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.sandbox) config.workers.sandbox = {}
    config.workers.sandbox.winePath = process.env.WINE_PATH
  }
  if (process.env.WINEDBG_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.sandbox) config.workers.sandbox = {}
    config.workers.sandbox.winedbgPath = process.env.WINEDBG_PATH
  }
  if (process.env.QILING_PYTHON) {
    if (!config.workers) config.workers = {}
    if (!config.workers.sandbox) config.workers.sandbox = {}
    config.workers.sandbox.qilingPythonPath = process.env.QILING_PYTHON
  }
  if (process.env.QILING_ROOTFS) {
    if (!config.workers) config.workers = {}
    if (!config.workers.sandbox) config.workers.sandbox = {}
    config.workers.sandbox.qilingRootfsPath = process.env.QILING_ROOTFS
  }
  if (process.env.ANGR_PYTHON) {
    if (!config.workers) config.workers = {}
    if (!config.workers.sandbox) config.workers.sandbox = {}
    config.workers.sandbox.angrPythonPath = process.env.ANGR_PYTHON
  }
  if (process.env.PANDA_PYTHON) {
    if (!config.workers) config.workers = {}
    if (!config.workers.sandbox) config.workers.sandbox = {}
    config.workers.sandbox.pandaPythonPath = process.env.PANDA_PYTHON
  }
  if (process.env.FRIDA_PATH || process.env.FRIDA_SERVER_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.frida) config.workers.frida = {}
    config.workers.frida.path = process.env.FRIDA_PATH || process.env.FRIDA_SERVER_PATH
    config.workers.frida.enabled = true
  }
  if (process.env.FRIDA_SCRIPT_ROOT) {
    if (!config.workers) config.workers = {}
    if (!config.workers.frida) config.workers.frida = {}
    config.workers.frida.scriptRoot = process.env.FRIDA_SCRIPT_ROOT
  }
  if (process.env.FRIDA_TIMEOUT) {
    if (!config.workers) config.workers = {}
    if (!config.workers.frida) config.workers.frida = {}
    config.workers.frida.timeout = parseInt(process.env.FRIDA_TIMEOUT, 10)
  }

  // Logging configuration
  if (process.env.LOG_LEVEL) {
    if (!config.logging) config.logging = {}
    config.logging.level = process.env.LOG_LEVEL
  }
  if (process.env.AUDIT_LOG_PATH) {
    if (!config.logging) config.logging = {}
    config.logging.auditPath = process.env.AUDIT_LOG_PATH
  }

  // API configuration
  if (process.env.API_ENABLED) {
    if (!config.api) config.api = {}
    config.api.enabled = process.env.API_ENABLED === 'true' || process.env.API_ENABLED === '1'
  }
  if (process.env.API_PORT) {
    if (!config.api) config.api = {}
    config.api.port = parseInt(process.env.API_PORT, 10)
  }
  if (process.env.API_KEY) {
    if (!config.api) config.api = {}
    config.api.apiKey = process.env.API_KEY
  }
  if (process.env.API_MAX_FILE_SIZE) {
    if (!config.api) config.api = {}
    config.api.maxFileSize = parseInt(process.env.API_MAX_FILE_SIZE, 10)
  }
  if (process.env.API_STORAGE_ROOT) {
    if (!config.api) config.api = {}
    config.api.storageRoot = process.env.API_STORAGE_ROOT
  }
  if (process.env.API_RETENTION_DAYS) {
    if (!config.api) config.api = {}
    config.api.retentionDays = parseInt(process.env.API_RETENTION_DAYS, 10)
  }

  return config
}

/**
 * Deep merge helper function
 */
function deepMerge(target: any, source: any): any {
  const output = { ...target }
  
  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach(key => {
      if (isObject(source[key])) {
        if (!(key in target)) {
          output[key] = source[key]
        } else {
          output[key] = deepMerge(target[key], source[key])
        }
      } else {
        output[key] = source[key]
      }
    })
  }
  
  return output
}

function isObject(item: any): boolean {
  return item && typeof item === 'object' && !Array.isArray(item)
}

/**
 * Merge multiple configuration sources with priority: env > file > defaults
 */
export function mergeConfigs(...configs: any[]): any {
  return configs.reduce((acc, config) => deepMerge(acc, config), {})
}

/**
 * Load and validate configuration from all sources
 */
export function loadConfig(configPath?: string): Config {
  const resolvedConfigPath = configPath || process.env.CONFIG_PATH || getDefaultConfigPath()
  const fileConfig = loadConfigFromFile(resolvedConfigPath)
  const envConfig = loadConfigFromEnv()
  const mergedConfig = mergeConfigs(fileConfig, envConfig)

  const result = ConfigSchema.safeParse(mergedConfig)
  if (!result.success) {
    throw new Error(`Configuration validation failed: ${result.error.message}`)
  }

  return result.data
}

/**
 * Default configuration instance
 * Loads configuration from environment variables and default config file
 */
export const config = loadConfig()
