/**
 * Unit tests for core/tool-executor.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { z } from 'zod'
import pino from 'pino'
import { createHash } from 'crypto'
import { MCPRegistry } from '../../../src/core/mcp-registry.js'
import { ToolExecutor } from '../../../src/core/tool-executor.js'
import { getToolSurfaceManager } from '../../../src/core/tool-surface-manager.js'
import type { WorkerResult } from '../../../src/types.js'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

describe('ToolExecutor', () => {
  let registry: MCPRegistry
  let executor: ToolExecutor

  beforeEach(() => {
    registry = new MCPRegistry(logger)
    executor = new ToolExecutor(logger)
    resetSurfaceForTest()
  })

  function makeToolDef(name: string, schema: z.ZodTypeAny = z.object({})) {
    return {
      name,
      canonicalName: name,
      description: `Tool ${name}`,
      inputSchema: schema,
    } as any
  }

  test('should execute tool and return WorkerResult as ToolResult', async () => {
    const handler = async (): Promise<WorkerResult> => ({ ok: true, data: { result: 42 } })
    registry.registerTool(makeToolDef('test.tool', z.object({ input: z.string() })), handler)

    const result = await executor.executeTool('test_tool', { input: 'hello' }, { registry, logger })

    expect(result.isError).toBe(false)
    const text = (result.content[0] as any).text
    expect(JSON.parse(text)).toMatchObject({ ok: true, data: { result: 42 } })
  })

  test('should validate args and throw structured error on bad input', async () => {
    registry.registerTool(makeToolDef('test.tool', z.object({ count: z.number() })), async () => ({
      ok: true,
    }))

    await expect(
      executor.executeTool(
        'test_tool',
        { count: 'not-a-number' },
        { registry, logger }
      )
    ).rejects.toThrow(/Invalid arguments/)
  })

  test.each(['worker', 'tool'] as const)('preserves hash-bound artifact content in %s responses', async (kind) => {
    const original = JSON.stringify({ program_name: 'sample.bin', program_path: '/tmp/sample.bin',
      literal_tool_name: 'artifact.read', unicode: '函数' }, null, 2)
    const sha256 = createHash('sha256').update(original).digest('hex')
    const payload = { ok: true, data: { content: original, artifact: { id: 'artifact-one', sha256 },
      message: 'Next use artifact.read', path: '/tmp/sample.bin' } }
    registry.registerTool(makeToolDef('artifact.read'), async () => kind === 'worker' ? payload : {
      content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], structuredContent: payload,
    })
    const result = await executor.executeTool('artifact_read', {}, { registry, logger })
    for (const actual of [result.structuredContent, JSON.parse((result.content[0] as any).text)] as any[]) {
      expect(actual.data.content).toBe(original)
      expect(createHash('sha256').update(actual.data.content).digest('hex')).toBe(sha256)
      expect(actual.data.path).toBe('/tmp/sample.bin')
      expect(actual.data.message).toBe('Next use artifact_read')
    }
  })

  test('should return error when tool not found', async () => {
    await expect(
      executor.executeTool('missing_tool', {}, { registry, logger })
    ).rejects.toThrow(/Tool not found/)
  })

  test('should fire plugin before/after hooks', async () => {
    const beforeHook = jest.fn().mockResolvedValue(undefined)
    const afterHook = jest.fn().mockResolvedValue(undefined)
    const pluginRuntime = {
      fireHook: jest.fn().mockImplementation((phase) => {
        if (phase === 'before') return beforeHook()
        if (phase === 'after') return afterHook()
      }),
    }

    registry.registerTool(makeToolDef('test.tool'), async () => ({ ok: true }))
    await executor.executeTool('test_tool', {}, { registry, pluginRuntime, logger })

    expect(pluginRuntime.fireHook).toHaveBeenCalledWith('before', 'test.tool', expect.anything())
    expect(pluginRuntime.fireHook).toHaveBeenCalledWith(
      'after',
      'test.tool',
      expect.anything(),
      expect.objectContaining({ elapsedMs: expect.any(Number) })
    )
  })

  test('should fire error hook on handler failure', async () => {
    const pluginRuntime = { fireHook: jest.fn().mockResolvedValue(undefined) }
    registry.registerTool(makeToolDef('test.tool'), async () => {
      throw new Error('handler boom')
    })

    const result = await executor.executeTool('test_tool', {}, { registry, pluginRuntime, logger })

    expect(result.isError).toBe(true)
    expect(pluginRuntime.fireHook).toHaveBeenCalledWith(
      'error',
      'test_tool',
      expect.anything(),
      expect.objectContaining({ error: expect.any(Error) })
    )
  })

  test('should pass through ToolResult directly', async () => {
    registry.registerTool(
      makeToolDef('test.tool'),
      async () =>
        ({
          content: [{ type: 'text', text: 'hello' }],
          isError: false,
        }) as any
    )

    const result = await executor.executeTool('test_tool', {}, { registry, logger })
    expect(result.content[0]).toMatchObject({ type: 'text', text: 'hello' })
  })

  test('should expand progressive surface from ToolResult structuredContent', async () => {
    const surface = getToolSurfaceManager()
    surface.registerGatewayCoreTools(['test.tool'])
    surface.registerCoreTools(['workflow.analyze.start'])

    registry.registerTool(
      makeToolDef('test.tool'),
      async () =>
        ({
          content: [{ type: 'text', text: 'ready' }],
          structuredContent: {
            data: { recommended_next_tools: ['workflow.analyze.start'] },
          },
          isError: false,
        }) as any
    )

    expect(surface.isToolVisible('workflow.analyze.start')).toBe(false)

    const result = await executor.executeTool('test_tool', {}, { registry, logger })

    expect(result.isError).toBe(false)
    expect(surface.isToolVisible('workflow.analyze.start')).toBe(true)
  })

  test('should block registered tools hidden by the progressive surface', async () => {
    registry.registerTool(makeToolDef('workflow.analyze.start'), async () => ({ ok: true }))
    getToolSurfaceManager().registerCoreTools(['workflow.analyze.start'])
    getToolSurfaceManager().registerGatewayCoreTools(['tools.discover'])

    await expect(
      executor.executeTool('workflow_analyze_start', {}, { registry, logger })
    ).rejects.toThrow(/Use workflow\.search query="workflow\.analyze\.start"/)
  })

  test('holds and fences the declared shared sample set across handler execution', async () => {
    const events: string[] = []
    const lease = {
      heartbeat: jest.fn(() => events.push('heartbeat')),
      assertOwned: jest.fn(() => events.push('assert')),
      release: jest.fn(() => events.push('release')),
    }
    const sampleOperationGate = {
      sharedLeaseTtlMs: 30_000,
      resolveSampleReferences: jest.fn(() => new Set([`sha256:${'a'.repeat(64)}`])),
      acquireShared: jest.fn(() => lease),
    }
    registry.registerTool(
      {
        ...makeToolDef('sample.reader', z.object({ sample_id: z.string() })),
        sampleReferences: { direct: ['sample_id'] },
      },
      async () => {
        events.push('handler')
        return { ok: true }
      }
    )

    await executor.executeTool(
      'sample_reader',
      { sample_id: `sha256:${'a'.repeat(64)}` },
      { registry, logger, sampleOperationGate: sampleOperationGate as any }
    )

    expect(sampleOperationGate.resolveSampleReferences).toHaveBeenCalledWith(
      { sample_id: `sha256:${'a'.repeat(64)}` },
      { direct: ['sample_id'] }
    )
    expect(sampleOperationGate.acquireShared).toHaveBeenCalledTimes(1)
    expect(events).toEqual(['assert', 'handler', 'assert', 'release'])
  })

  test('resolves exclusive-managed references without acquiring a deadlocking shared lease', async () => {
    const handler = jest.fn(async () => ({ content: [], structuredContent: { ok: true } }))
    const sampleOperationGate = {
      resolveSampleReferences: jest.fn(() => new Set([`sha256:${'b'.repeat(64)}`])),
      acquireShared: jest.fn(() => {
        throw new Error('must not acquire shared lease')
      }),
    }
    registry.registerTool(
      {
        ...makeToolDef('sample.delete', z.object({ sample_id: z.string() })),
        sampleReferences: { direct: ['sample_id'] },
        sampleLeaseMode: 'exclusive-managed',
      },
      handler as any
    )

    const response = await executor.executeTool(
      'sample_delete',
      { sample_id: `sha256:${'b'.repeat(64)}` },
      { registry, logger, sampleOperationGate: sampleOperationGate as any }
    )

    expect(response.structuredContent).toEqual({ ok: true })
    expect(sampleOperationGate.resolveSampleReferences).toHaveBeenCalledTimes(1)
    expect(sampleOperationGate.acquireShared).not.toHaveBeenCalled()
    expect(handler).toHaveBeenCalledTimes(1)
  })

  test.each([
    'workflow.triage',
    'workflow.analyze.start',
    'workflow.analyze.status',
    'workflow.analyze.promote',
    'workflow.analyze.auto',
    'workflow.reconstruct',
    'workflow.deep_static',
    'workflow.function_index.recover',
    'workflow.semantic_name_review',
    'workflow.function_explanation_review',
    'workflow.module_reconstruction_review',
    'ghidra.analyze',
    'strings.extract',
    'strings.floss.decode',
    'binary.role.profile',
    'analysis.context.link',
    'crypto.identify',
    'attack.map',
  ])('fails closed before handler/queue/database mutation for static direct call %s', async (name) => {
    const previousProfile = process.env.RIKUNE_DOCKER_PROFILE
    const enqueue = jest.fn()
    const databaseWrite = jest.fn()
    const handler = jest.fn(async () => {
      enqueue()
      databaseWrite()
      return { ok: true }
    })
    registry.registerTool(makeToolDef(name), handler)
    process.env.RIKUNE_DOCKER_PROFILE = 'static'

    try {
      const result = await executor.executeTool(name.replaceAll('.', '_'), {}, { registry, logger })
      expect(result.isError).toBe(true)
      expect((result.content[0] as any).text).toContain('E_STATIC_PROFILE_CONTRACT')
      expect(handler).not.toHaveBeenCalled()
      expect(enqueue).not.toHaveBeenCalled()
      expect(databaseWrite).not.toHaveBeenCalled()
    } finally {
      if (previousProfile === undefined) delete process.env.RIKUNE_DOCKER_PROFILE
      else process.env.RIKUNE_DOCKER_PROFILE = previousProfile
    }
  })
})
