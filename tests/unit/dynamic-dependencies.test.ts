import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createDynamicDependenciesHandler } from '../../src/tools/dynamic-dependencies.js'

describe('dynamic.dependencies tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'dynamic-dependencies-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should report speakeasy emulator metadata and actionable recommendations', async () => {
    const handler = createDynamicDependenciesHandler(workspaceManager, database)
    const result = await handler({})

    expect(result.ok).toBe(true)
    const data = result.data as {
      status: string
      components: {
        speakeasy?: {
          available?: boolean
          distribution?: string | null
          version?: string | null
          api_available?: boolean
          warnings?: string[]
          legacy_distribution_summary?: string
        }
      }
      recommendations: string[]
      setup_actions: Array<{ id: string; kind: string; command?: string | null }>
      required_user_inputs: Array<unknown>
    }

    expect(['ready', 'partial', 'bootstrap_required']).toContain(data.status)
    expect(Array.isArray(data.recommendations)).toBe(true)
    expect(Array.isArray(data.setup_actions)).toBe(true)
    expect(Array.isArray(data.required_user_inputs)).toBe(true)

    const speakeasy = data.components.speakeasy || {}
    if (speakeasy.available) {
      expect(speakeasy.distribution).toBe('speakeasy-emulator')
      expect(typeof speakeasy.version).toBe('string')
      expect(speakeasy.api_available).toBe(true)
      expect(data.recommendations.join(' ')).not.toContain('pip install speakeasy ')
      expect(data.recommendations.join(' ')).not.toContain('pip install speakeasy\n')
    } else {
      expect(data.recommendations.join(' ')).toContain('speakeasy-emulator')
    }

    if ((speakeasy.legacy_distribution_summary || '').toLowerCase().includes('metrics aggregation server')) {
      expect(data.recommendations.join(' ')).toContain('pip uninstall speakeasy')
    }
  })

  test('should degrade to bootstrap_required when the worker probe fails', async () => {
    const handler = createDynamicDependenciesHandler(workspaceManager, database, {
      callWorker: async () => {
        throw new Error('Python worker exited with code 1')
      },
    })

    const result = await handler({})

    expect(result.ok).toBe(true)
    const data = result.data as {
      status: string
      components: {
        worker?: {
          available?: boolean
          error?: string
        }
      }
      recommendations: string[]
      setup_actions: Array<{ id: string; command?: string | null }>
    }

    expect(data.status).toBe('bootstrap_required')
    expect(data.components.worker?.available).toBe(false)
    expect(data.components.worker?.error).toContain('Python worker exited with code 1')
    expect(data.recommendations.join(' ')).toContain('pip install -r requirements.txt')
    expect(data.setup_actions.map((item) => item.id)).toContain('install_python_requirements')
    expect(data.setup_actions.map((item) => item.id)).toContain('install_speakeasy_emulator')
  })
})
