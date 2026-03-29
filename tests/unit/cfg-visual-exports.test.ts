import { describe, expect, test } from '@jest/globals'
import type { Function as DatabaseFunction } from '../../src/database.js'
import type { ControlFlowGraph } from '../../src/decompiler-worker.js'
import {
  buildCFGExport,
  buildCFGSummary,
  buildLocalCallGraphExport,
  buildLocalCallGraphPreview,
} from '../../src/cfg-visual-exports.js'

const sampleCFG: ControlFlowGraph = {
  function: 'FUN_140001000',
  address: '0x140001000',
  nodes: [
    {
      id: 'block_0',
      address: '0x140001000',
      instructions: ['push rbp', 'mov rbp, rsp', 'cmp rcx, 0'],
      type: 'entry',
    },
    {
      id: 'block_1',
      address: '0x140001020',
      instructions: ['jne 0x140001040', 'call WriteProcessMemory'],
      type: 'call',
    },
    {
      id: 'block_2',
      address: '0x140001040',
      instructions: ['xor eax, eax', 'ret'],
      type: 'exit',
    },
  ],
  edges: [
    { from: 'block_0', to: 'block_1', type: 'fallthrough' },
    { from: 'block_1', to: 'block_2', type: 'jump' },
  ],
}

describe('cfg visual exports helpers', () => {
  test('should build deterministic CFG dot and mermaid exports with bounded previews', () => {
    const dotExport = buildCFGExport(sampleCFG, 'dot', 400, 8, 8)
    const mermaidExport = buildCFGExport(sampleCFG, 'mermaid', 400, 8, 8)
    const jsonExport = buildCFGExport(sampleCFG, 'json', 400, 2, 1)
    const summary = buildCFGSummary(sampleCFG)

    expect(summary.node_count).toBe(3)
    expect(summary.edge_count).toBe(2)
    expect(summary.block_type_counts.entry).toBe(1)
    expect(dotExport.text).toContain('digraph "FUN_140001000"')
    expect(dotExport.text).toContain('"block_1" -> "block_2"')
    expect(dotExport.preview.inline_text).toContain('WriteProcessMemory')
    expect(mermaidExport.text).toContain('flowchart TD')
    expect(mermaidExport.text).toContain('0x140001020')
    expect(jsonExport.preview.truncated).toBe(true)
    expect((jsonExport.preview.inline_json as any).nodes).toHaveLength(2)
    expect((jsonExport.preview.inline_json as any).edges).toHaveLength(1)
    expect(jsonExport.preview.omitted_nodes).toBe(1)
    expect(jsonExport.preview.omitted_edges).toBe(1)
  })

  test('should build bounded local call-relationship exports in multiple formats', () => {
    const functions: DatabaseFunction[] = [
      {
        sample_id: 'sha256:' + 'a'.repeat(64),
        address: '0x140001000',
        name: 'FUN_140001000',
        size: 32,
        score: 0,
        tags: '[]',
        summary: null,
        caller_count: 1,
        callee_count: 2,
        is_entry_point: 1,
        is_exported: 0,
        callees: JSON.stringify(['FUN_140002000', 'Sleep']),
      },
      {
        sample_id: 'sha256:' + 'a'.repeat(64),
        address: '0x140000900',
        name: 'caller_fn',
        size: 24,
        score: 0,
        tags: '[]',
        summary: null,
        caller_count: 0,
        callee_count: 1,
        is_entry_point: 0,
        is_exported: 0,
        callees: JSON.stringify(['FUN_140001000']),
      },
      {
        sample_id: 'sha256:' + 'a'.repeat(64),
        address: '0x140002000',
        name: 'FUN_140002000',
        size: 40,
        score: 0,
        tags: '[]',
        summary: null,
        caller_count: 1,
        callee_count: 0,
        is_entry_point: 0,
        is_exported: 0,
        callees: JSON.stringify([]),
      },
    ]

    const localGraph = buildLocalCallGraphPreview(functions, sampleCFG, 1, 4)
    const dotExport = buildLocalCallGraphExport(localGraph, 'dot', 400)
    const jsonExport = buildLocalCallGraphExport(localGraph, 'json', 400)

    expect(localGraph.bounded).toBe(true)
    expect(localGraph.depth).toBe(1)
    expect(localGraph.note).toContain('not a whole-program call graph')
    expect(localGraph.nodes.some((node) => node.role === 'caller')).toBe(true)
    expect(localGraph.nodes.some((node) => node.role === 'callee')).toBe(true)
    expect(localGraph.nodes.some((node) => node.role === 'external')).toBe(true)
    expect(dotExport.text).toContain('digraph "FUN_140001000_calls"')
    expect(dotExport.preview.inline_text).toContain('caller_fn')
    expect((jsonExport.preview.inline_json as any).root.name).toBe('FUN_140001000')
    expect((jsonExport.preview.inline_json as any).nodes.length).toBeGreaterThanOrEqual(3)
  })
})
