import { describe, expect, test, jest } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import {
  RuntimeWorkerPool,
  buildStaticWorkerCompatibilityKey,
  buildRizinPreviewCompatibilityKey,
} from '../../src/runtime-worker-pool.js'

describe('runtime worker pool', () => {
  test('builds deterministic compatibility keys and separates incompatible requests', () => {
    const staticPreviewA = buildStaticWorkerCompatibilityKey({
      tool: 'strings.extract',
      context: { versions: { tool_version: '1.0.0' } },
      args: { scan_mode: 'preview' },
    })
    const staticPreviewB = buildStaticWorkerCompatibilityKey({
      tool: 'strings.extract',
      context: { versions: { tool_version: '1.0.0' } },
      args: { scan_mode: 'preview' },
    })
    const staticFull = buildStaticWorkerCompatibilityKey({
      tool: 'strings.extract',
      context: { versions: { tool_version: '1.0.0' } },
      args: { scan_mode: 'full' },
    })
    const rizinInfo = buildRizinPreviewCompatibilityKey({
      backendPath: '/tool/rizin',
      backendVersion: '0.8.2',
      operation: 'info',
    })
    const rizinFunctions = buildRizinPreviewCompatibilityKey({
      backendPath: '/tool/rizin',
      backendVersion: '0.8.2',
      operation: 'functions',
    })

    expect(staticPreviewA).toBe(staticPreviewB)
    expect(staticPreviewA).not.toBe(staticFull)
    expect(rizinInfo).not.toBe(rizinFunctions)
  })

  test('reuses only healthy compatible idle workers and evicts stale ones with persisted telemetry', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-worker-pool-'))
    const database = new DatabaseManager(path.join(tempDir, 'test.db'))
    const pool = new RuntimeWorkerPool() as any

    try {
      const nowIso = new Date().toISOString()
      const kill = jest.fn()
      const staleKill = jest.fn()
      const unhealthyKill = jest.fn()

      pool.workers.set('worker-compatible', {
        id: 'worker-compatible',
        family: 'static_python.preview',
        compatibilityKey: 'compat-a',
        deploymentKey: 'deploy-a',
        child: { kill } as any,
        busy: false,
        unhealthy: false,
        createdAt: nowIso,
        lastUsedAt: nowIso,
        stdoutBuffer: '',
      })
      pool.workers.set('worker-stale', {
        id: 'worker-stale',
        family: 'static_python.preview',
        compatibilityKey: 'compat-a',
        deploymentKey: 'deploy-a',
        child: { kill: staleKill } as any,
        busy: false,
        unhealthy: false,
        createdAt: nowIso,
        lastUsedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
        stdoutBuffer: '',
      })
      pool.workers.set('worker-unhealthy', {
        id: 'worker-unhealthy',
        family: 'static_python.preview',
        compatibilityKey: 'compat-a',
        deploymentKey: 'deploy-a',
        child: { kill: unhealthyKill } as any,
        busy: false,
        unhealthy: true,
        createdAt: nowIso,
        lastUsedAt: nowIso,
        stdoutBuffer: '',
      })

      const matched = pool.findIdleWorker('static_python.preview', 'compat-a', 'deploy-a')
      expect(matched?.id).toBe('worker-compatible')

      pool.evictIdleWorkers(database, 60_000)
      expect(pool.workers.has('worker-compatible')).toBe(true)
      expect(pool.workers.has('worker-stale')).toBe(false)
      expect(pool.workers.has('worker-unhealthy')).toBe(false)
      expect(staleKill).toHaveBeenCalled()
      expect(unhealthyKill).toHaveBeenCalled()

      const familyStates = database.findRuntimeWorkerFamilyStates('static_python.preview')
      expect(familyStates.length).toBeGreaterThan(0)
      expect(familyStates[0]?.eviction_count).toBeGreaterThanOrEqual(1)
    } finally {
      database.close()
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  test('marks unhealthy disposal in family telemetry', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-worker-pool-'))
    const database = new DatabaseManager(path.join(tempDir, 'test.db'))
    const pool = new RuntimeWorkerPool() as any

    try {
      const worker = {
        id: 'worker-failed',
        family: 'rizin.preview',
        compatibilityKey: 'compat-rizin',
        deploymentKey: 'deploy-rizin',
        child: { kill: jest.fn() } as any,
        busy: false,
        unhealthy: true,
        createdAt: new Date().toISOString(),
        lastUsedAt: new Date().toISOString(),
        stdoutBuffer: '',
      }

      pool.workers.set(worker.id, worker)
      pool.disposeWorker(worker, database, true)

      const familyStates = database.findRuntimeWorkerFamilyStates('rizin.preview')
      expect(familyStates.length).toBeGreaterThan(0)
      expect(familyStates[0]?.last_error).toBe('worker_marked_unhealthy')
      expect(familyStates[0]?.eviction_count).toBeGreaterThanOrEqual(1)
    } finally {
      database.close()
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })
})
