/**
 * Unit tests for configuration loading
 * **Validates: Requirements 31.3**
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import {
  loadConfigFromFile,
  loadConfigFromEnv,
  mergeConfigs,
  loadConfig,
  ConfigSchema,
  getDefaultConfigPath,
  getDefaultDatabasePath,
  getDefaultCacheRoot,
  getDefaultWorkspaceRoot,
  getDefaultAuditLogPath,
} from '../../src/config.js'

describe('Configuration Loading', () => {
  const testConfigDir = path.join(process.cwd(), 'test-configs')
  const testConfigPath = path.join(testConfigDir, 'test-config.json')
  const isolatedDefaultConfigPath = path.join(testConfigDir, 'isolated-default-config.json')

  beforeEach(() => {
    // Create test config directory
    if (!fs.existsSync(testConfigDir)) {
      fs.mkdirSync(testConfigDir, { recursive: true })
    }
    process.env.CONFIG_PATH = isolatedDefaultConfigPath
  })

  afterEach(() => {
    // Clean up test files
    if (fs.existsSync(testConfigPath)) {
      fs.unlinkSync(testConfigPath)
    }
    if (fs.existsSync(isolatedDefaultConfigPath)) {
      fs.unlinkSync(isolatedDefaultConfigPath)
    }
    if (fs.existsSync(testConfigDir)) {
      fs.rmdirSync(testConfigDir)
    }

    // Clean up environment variables
    delete process.env.SERVER_PORT
    delete process.env.SERVER_HOST
    delete process.env.DB_TYPE
    delete process.env.DB_PATH
    delete process.env.WORKSPACE_ROOT
    delete process.env.CACHE_ROOT
    delete process.env.CONFIG_PATH
    delete process.env.GHIDRA_PATH
    delete process.env.LOG_LEVEL
    delete process.env.AUDIT_LOG_PATH
  })

  describe('loadConfigFromFile', () => {
    test('should load valid configuration from JSON file', () => {
      const config = {
        server: { port: 8080, host: '0.0.0.0' },
        database: { type: 'sqlite', path: './data/db.sqlite' },
      }
      fs.writeFileSync(testConfigPath, JSON.stringify(config))

      const result = loadConfigFromFile(testConfigPath)

      expect(result).toEqual(config)
    })

    test('should return empty object if file does not exist', () => {
      const result = loadConfigFromFile('./non-existent-config.json')

      expect(result).toEqual({})
    })

    test('should throw error for invalid JSON', () => {
      fs.writeFileSync(testConfigPath, 'invalid json {')

      expect(() => loadConfigFromFile(testConfigPath)).toThrow(/Failed to load config/)
    })

    test('should handle empty JSON file', () => {
      fs.writeFileSync(testConfigPath, '{}')

      const result = loadConfigFromFile(testConfigPath)

      expect(result).toEqual({})
    })
  })

  describe('loadConfigFromEnv', () => {
    test('should load server configuration from environment variables', () => {
      process.env.SERVER_PORT = '9000'
      process.env.SERVER_HOST = 'example.com'

      const result = loadConfigFromEnv()

      expect(result.server?.port).toBe(9000)
      expect(result.server?.host).toBe('example.com')
    })

    test('should load database configuration from environment variables', () => {
      process.env.DB_TYPE = 'postgresql'
      process.env.DB_HOST = 'localhost'
      process.env.DB_PORT = '5432'

      const result = loadConfigFromEnv()

      expect(result.database?.type).toBe('postgresql')
      expect(result.database?.host).toBe('localhost')
      expect(result.database?.port).toBe(5432)
    })

    test('should load workspace configuration from environment variables', () => {
      process.env.WORKSPACE_ROOT = '/custom/workspace'
      process.env.CACHE_ROOT = '/custom/cache'
      process.env.MAX_SAMPLE_SIZE = '1048576'
      process.env.AUDIT_LOG_PATH = '/custom/audit.log'

      const result = loadConfigFromEnv()

      expect(result.workspace?.root).toBe('/custom/workspace')
      expect(result.workspace?.maxSampleSize).toBe(1048576)
      expect(result.cache?.root).toBe('/custom/cache')
      expect(result.logging?.auditPath).toBe('/custom/audit.log')
    })

    test('should enable Ghidra worker when GHIDRA_PATH is set', () => {
      process.env.GHIDRA_PATH = '/opt/ghidra'

      const result = loadConfigFromEnv()

      expect(result.workers?.ghidra?.path).toBe('/opt/ghidra')
      expect(result.workers?.ghidra?.enabled).toBe(true)
    })

    test('should load logging configuration from environment variables', () => {
      process.env.LOG_LEVEL = 'debug'

      const result = loadConfigFromEnv()

      expect(result.logging?.level).toBe('debug')
    })

    test('should return empty object when no environment variables are set', () => {
      // Clean up all relevant environment variables
      delete process.env.SERVER_PORT
      delete process.env.SERVER_HOST
      delete process.env.DB_TYPE
      delete process.env.DB_PATH
      delete process.env.DB_HOST
      delete process.env.DB_PORT
      delete process.env.WORKSPACE_ROOT
      delete process.env.CACHE_ROOT
      delete process.env.MAX_SAMPLE_SIZE
      delete process.env.GHIDRA_PATH
      delete process.env.PYTHON_PATH
      delete process.env.LOG_LEVEL
      delete process.env.AUDIT_LOG_PATH

      const result = loadConfigFromEnv()

      expect(result).toEqual({})
    })
  })

  describe('mergeConfigs', () => {
    test('should merge multiple configurations with later configs taking priority', () => {
      const config1 = { server: { port: 3000, host: 'host1' } }
      const config2 = { server: { port: 8080, host: 'localhost' } }
      const config3 = { server: { port: 9000, host: 'host3' } }

      const result = mergeConfigs(config1, config2, config3)

      expect(result.server?.port).toBe(9000)
      expect(result.server?.host).toBe('host3')
    })

    test('should deep merge nested worker configurations', () => {
      const config1 = {
        workers: {
          ghidra: { enabled: false, maxConcurrent: 2, timeout: 300 },
          static: { enabled: true },
          dotnet: { enabled: false },
        },
      }
      const config2 = {
        workers: {
          ghidra: { enabled: true, path: '/opt/ghidra', maxConcurrent: 2, timeout: 300 },
          static: { enabled: true },
          dotnet: { enabled: false },
        },
      }

      const result = mergeConfigs(config1, config2)

      expect(result.workers?.ghidra?.enabled).toBe(true)
      expect(result.workers?.ghidra?.path).toBe('/opt/ghidra')
      expect(result.workers?.ghidra?.maxConcurrent).toBe(2)
      expect(result.workers?.static?.enabled).toBe(true)
    })

    test('should handle empty configurations', () => {
      const result = mergeConfigs({}, {}, {})

      expect(result).toEqual({})
    })
  })

  describe('loadConfig', () => {
    test('should load and validate configuration with defaults', () => {
      const config = loadConfig()

      expect(config.server.port).toBe(3000)
      expect(config.server.host).toBe('localhost')
      expect(config.database.type).toBe('sqlite')
      expect(config.database.path).toBe(getDefaultDatabasePath())
      expect(config.workspace.root).toBe(getDefaultWorkspaceRoot())
      expect(config.workers.static.enabled).toBe(true)
      expect(config.cache.enabled).toBe(true)
      expect(config.cache.root).toBe(getDefaultCacheRoot())
      expect(config.logging.auditPath).toBe(getDefaultAuditLogPath())
    })

    test('should load default user config path when no explicit config path is provided', () => {
      const defaultConfigPath = getDefaultConfigPath()
      const defaultConfigDir = path.dirname(defaultConfigPath)
      const backupPath = fs.existsSync(defaultConfigPath) ? `${defaultConfigPath}.bak-test` : null

      try {
        delete process.env.CONFIG_PATH
        if (backupPath) {
          fs.copyFileSync(defaultConfigPath, backupPath)
        }
        fs.mkdirSync(defaultConfigDir, { recursive: true })
        fs.writeFileSync(defaultConfigPath, JSON.stringify({
          workspace: { root: '/persisted/workspace' },
        }))

        const config = loadConfig()
        expect(config.workspace.root).toBe('/persisted/workspace')
      } finally {
        if (fs.existsSync(defaultConfigPath)) {
          fs.unlinkSync(defaultConfigPath)
        }
        if (backupPath && fs.existsSync(backupPath)) {
          fs.copyFileSync(backupPath, defaultConfigPath)
          fs.unlinkSync(backupPath)
        }
      }
    })

    test('should merge file and environment configurations', () => {
      const fileConfig = {
        server: { port: 8080 },
        database: { type: 'sqlite' as const, path: './db.sqlite' },
      }
      fs.writeFileSync(testConfigPath, JSON.stringify(fileConfig))
      process.env.SERVER_HOST = 'custom.host'
      process.env.LOG_LEVEL = 'debug'

      const config = loadConfig(testConfigPath)

      expect(config.server.port).toBe(8080)
      expect(config.server.host).toBe('custom.host')
      expect(config.logging.level).toBe('debug')
    })

    test('should throw error for invalid configuration', () => {
      const invalidConfig = {
        server: { port: -1 }, // Invalid port
      }
      fs.writeFileSync(testConfigPath, JSON.stringify(invalidConfig))

      expect(() => loadConfig(testConfigPath)).toThrow(/Configuration validation failed/)
    })

    test('should validate port range', () => {
      const invalidConfig = {
        server: { port: 70000 }, // Port out of range
      }
      fs.writeFileSync(testConfigPath, JSON.stringify(invalidConfig))

      expect(() => loadConfig(testConfigPath)).toThrow(/Configuration validation failed/)
    })

    test('should validate database type enum', () => {
      const invalidConfig = {
        database: { type: 'mysql' }, // Invalid database type
      }
      fs.writeFileSync(testConfigPath, JSON.stringify(invalidConfig))

      expect(() => loadConfig(testConfigPath)).toThrow(/Configuration validation failed/)
    })

    test('should validate Ghidra maxConcurrent range', () => {
      const invalidConfig = {
        workers: {
          ghidra: { maxConcurrent: 20 }, // Exceeds max of 16
        },
      }
      fs.writeFileSync(testConfigPath, JSON.stringify(invalidConfig))

      expect(() => loadConfig(testConfigPath)).toThrow(/Configuration validation failed/)
    })

    test('should apply default values for missing fields', () => {
      const minimalConfig = {
        server: { port: 8080 },
      }
      fs.writeFileSync(testConfigPath, JSON.stringify(minimalConfig))

      const config = loadConfig(testConfigPath)

      expect(config.server.host).toBe('localhost')
      expect(config.database.type).toBe('sqlite')
      expect(config.workspace.maxSampleSize).toBe(500 * 1024 * 1024)
      expect(config.workers.ghidra.maxConcurrent).toBe(4)
      expect(config.database.path).toBe(getDefaultDatabasePath())
      expect(config.cache.root).toBe(getDefaultCacheRoot())
      expect(config.cache.ttl).toBe(30 * 24 * 60 * 60)
      expect(config.logging.auditPath).toBe(getDefaultAuditLogPath())
    })
  })

  describe('ConfigSchema validation', () => {
    test('should accept valid complete configuration', () => {
      const validConfig = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' as const, path: getDefaultDatabasePath() },
        workspace: { root: getDefaultWorkspaceRoot(), maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: true, path: '/opt/ghidra', maxConcurrent: 4, timeout: 300 },
          static: { enabled: true, pythonPath: 'python3' },
          dotnet: { enabled: false },
        },
        cache: { enabled: true, root: getDefaultCacheRoot(), ttl: 2592000 },
        logging: { level: 'info' as const, pretty: false, auditPath: getDefaultAuditLogPath() },
      }

      const result = ConfigSchema.safeParse(validConfig)

      expect(result.success).toBe(true)
    })

    test('should reject invalid log level', () => {
      const invalidConfig = {
        logging: { level: 'invalid' },
      }

      const result = ConfigSchema.safeParse(invalidConfig)

      expect(result.success).toBe(false)
    })

    test('should accept PostgreSQL configuration', () => {
      const pgConfig = {
        database: {
          type: 'postgresql' as const,
          host: 'localhost',
          port: 5432,
          database: 'mcp_server',
          user: 'admin',
          password: 'secret',
        },
      }

      const result = ConfigSchema.safeParse(pgConfig)

      expect(result.success).toBe(true)
    })
  })
})
