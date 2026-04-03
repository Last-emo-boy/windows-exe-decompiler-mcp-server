/**
 * Unit tests for KB bulk import and sharing
 */

import { exportToJsonl, type KbExportEntry } from '../../src/kb/kb-export.js'

// Minimal DatabaseManager mock for KB tests
function createMockDb(functionKbRows: Record<string, unknown>[] = [], sampleKbRows: Record<string, unknown>[] = []) {
  return {
    querySql: jest.fn().mockImplementation((sql: string) => {
      if (sql.includes('function_kb')) return functionKbRows
      if (sql.includes('sample_kb')) return sampleKbRows
      return []
    }),
  } as any
}

describe('kb-export', () => {
  it('exports empty JSONL for empty database', () => {
    const db = createMockDb()
    const result = exportToJsonl(db)
    expect(result).toBe('')
  })

  it('exports function_kb entries as JSONL', () => {
    const entries = [
      { id: 1, semantics_name: 'CreateFileA', semantics_confidence: 0.9 },
      { id: 2, semantics_name: 'VirtualAlloc', semantics_confidence: 0.8 },
    ]
    const db = createMockDb(entries)
    const result = exportToJsonl(db)
    const lines = result.trim().split('\n').filter(Boolean)
    expect(lines.length).toBeGreaterThanOrEqual(2)
    for (const line of lines) {
      const parsed = JSON.parse(line)
      expect(parsed.type).toBeDefined()
      expect(parsed.data).toBeDefined()
    }
  })

  it('exports sample_kb entries as JSONL', () => {
    const entries = [
      { id: 1, sample_id: 'sha256:abc', evidence_family: 'emotet' },
    ]
    const db = createMockDb([], entries)
    const result = exportToJsonl(db, { entryType: 'sample_kb' })
    const lines = result.trim().split('\n').filter(Boolean)
    expect(lines.length).toBe(1)
    const parsed = JSON.parse(lines[0])
    expect(parsed.type).toBe('sample_kb')
  })

  it('exports all types when entryType is all', () => {
    const funcKb = [{ id: 1, semantics_name: 'A' }]
    const sampKb = [{ id: 1, sample_id: 'sha256:x' }]
    const db = createMockDb(funcKb, sampKb)
    const result = exportToJsonl(db, { entryType: 'all' })
    const lines = result.trim().split('\n').filter(Boolean)
    expect(lines.length).toBe(2)
    const types = lines.map(l => JSON.parse(l).type)
    expect(types).toContain('function_kb')
    expect(types).toContain('sample_kb')
  })
})

describe('capa-import', () => {
  it('module loads successfully', async () => {
    const mod = await import('../../src/kb/capa-import.js')
    expect(typeof mod.parseCapaRules).toBe('function')
  })
})

describe('misp-import', () => {
  it('module loads successfully', async () => {
    const mod = await import('../../src/kb/misp-import.js')
    expect(typeof mod.parseMispEvents).toBe('function')
  })
})
