/**
 * Unit tests for system.health tool
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createSystemHealthHandler, SystemHealthInputSchema } from '../../src/tools/system-health.js'
import type { GhidraHealthStatus } from '../../src/ghidra-config.js'

type StaticWorkerHealthData = {
  status?: string
  worker?: Record<string, unknown>
  dependencies?: Record<string, unknown>
  yara_rules?: Record<string, unknown>
  checked_at?: string
}

function buildGhidraStatus(ok: boolean): GhidraHealthStatus {
  return {
    ok,
    checked_at: new Date().toISOString(),
    install_dir: ok ? 'C:\\ghidra' : '',
    analyze_headless_path: ok ? 'C:\\ghidra\\support\\analyzeHeadless.bat' : '',
    scripts_dir: path.join(process.cwd(), 'ghidra_scripts'),
    project_root: path.join(process.cwd(), 'ghidra-projects'),
    log_root: path.join(process.cwd(), 'ghidra-logs'),
    version: ok ? '11.2' : undefined,
    checks: {
      install_dir_exists: ok,
      analyze_headless_exists: ok,
      scripts_dir_exists: true,
      launch_ok: ok,
      pyghidra_available: ok,
      java_available: ok,
      java_version_ok: ok,
    },
    pyghidra_probe: {
      command: process.platform === 'win32' ? 'python' : 'python3',
      available: ok,
      version: ok ? '1.0.0' : undefined,
      error: ok ? undefined : 'pyghidra missing',
    },
    java_probe: {
      command: 'java',
      available: ok,
      source: ok ? 'PATH' : 'none',
      version: ok ? 'openjdk version "21.0.2"' : undefined,
      major_version: ok ? 21 : undefined,
      version_ok: ok,
      error: ok ? undefined : 'java missing',
    },
    errors: ok ? [] : ['install dir not found'],
    warnings: [],
  }
}

describe('system.health tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string
  let cacheManager: CacheManager

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-system-health')
    testDbPath = path.join(process.cwd(), 'test-system-health.db')
    testCachePath = path.join(process.cwd(), 'test-cache-system-health')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  test('should apply input defaults', () => {
    const parsed = SystemHealthInputSchema.parse({})
    expect(parsed.timeout_ms).toBe(10000)
    expect(parsed.include_ghidra).toBe(true)
    expect(parsed.include_static_worker).toBe(true)
    expect(parsed.include_cache_probe).toBe(true)
  })

  test('should return healthy when all checks are healthy', async () => {
    const handler = createSystemHealthHandler(workspaceManager, database, {
      checkGhidra: () => buildGhidraStatus(true),
      cacheManager,
      probeStaticWorker: async (): Promise<StaticWorkerHealthData> => ({
        status: 'healthy',
        worker: { python_version: '3.11.9' },
        dependencies: {
          pefile: { available: true },
          yara_python: { available: true },
          floss_cli: { available: true },
        },
      }),
    })

    const result = await handler({})
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.overall_status).toBe('healthy')
    expect(data.components.workspace.status).toBe('healthy')
    expect(data.components.database.status).toBe('healthy')
    expect(data.components.ghidra.status).toBe('healthy')
    expect(data.components.static_worker.status).toBe('healthy')
    expect(data.components.cache.status).toBe('healthy')
    expect(data.cache_observability.key).toContain('health_cache_probe_')
    expect(data.cache_observability.hit_at).toBeTruthy()
  })

  test('should return degraded when optional component fails', async () => {
    const handler = createSystemHealthHandler(workspaceManager, database, {
      checkGhidra: () => buildGhidraStatus(false),
      cacheManager,
      probeStaticWorker: async (): Promise<StaticWorkerHealthData> => ({
        status: 'healthy',
      }),
    })

    const result = await handler({})
    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.overall_status).toBe('degraded')
    expect(data.components.ghidra.status).toBe('degraded')
    expect(Array.isArray(data.recommendations)).toBe(true)
    expect(data.recommendations.length).toBeGreaterThan(0)
    expect(data.setup_actions.map((item: any) => item.id)).toContain('set_java_home')
    expect(data.setup_actions.map((item: any) => item.id)).toContain('set_ghidra_path')
    expect(data.required_user_inputs.map((item: any) => item.key)).toContain('java_home')
    expect(data.required_user_inputs.map((item: any) => item.key)).toContain('ghidra_install_dir')
  })

  test('should return unhealthy when essential component fails', async () => {
    const handler = createSystemHealthHandler(workspaceManager, database)

    database.close()
    const result = await handler({
      include_ghidra: false,
      include_static_worker: false,
    })

    expect(result.ok).toBe(false)
    const data = result.data as any
    expect(data.overall_status).toBe('unhealthy')
    expect(data.components.database.status).toBe('unhealthy')
  })

  test('should mark static_worker as degraded when probe throws', async () => {
    const handler = createSystemHealthHandler(workspaceManager, database, {
      checkGhidra: () => buildGhidraStatus(true),
      cacheManager,
      probeStaticWorker: async () => {
        throw new Error('python missing')
      },
    })

    const result = await handler({
      include_ghidra: false,
      include_static_worker: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.overall_status).toBe('degraded')
    expect(data.components.static_worker.status).toBe('degraded')
    expect(data.components.ghidra.status).toBe('skipped')
    expect(data.setup_actions.map((item: any) => item.id)).toContain('install_python_requirements')
  })

  test('should report cache sample-state consistency when sample_id is provided', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'a'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const handler = createSystemHealthHandler(workspaceManager, database, {
      cacheManager,
      checkGhidra: () => buildGhidraStatus(true),
      probeStaticWorker: async (): Promise<StaticWorkerHealthData> => ({ status: 'healthy' }),
    })

    const result = await handler({
      sample_id: sampleId,
      include_ghidra: false,
      include_static_worker: false,
      include_cache_probe: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.components.cache.status).toBe('healthy')
    expect(data.cache_observability.sample_sha256).toBe('a'.repeat(64))
    expect(data.cache_observability.sample_state_consistent).toBe(true)
  })
})
