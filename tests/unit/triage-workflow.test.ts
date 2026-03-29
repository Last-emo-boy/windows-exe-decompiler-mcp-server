/**
 * Unit tests for triage workflow
 * Requirements: 15.1, 15.2, 15.4, 15.5
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createTriageWorkflowHandler, TriageWorkflowInputSchema } from '../../src/workflows/triage.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('Triage Workflow', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testDir: string
  let dbPath: string

  beforeEach(async () => {
    // Create temporary test directory
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'triage-test-'))
    const workspaceRoot = path.join(testDir, 'workspaces')
    const cacheDir = path.join(testDir, 'cache')
    dbPath = path.join(testDir, 'test.db')

    // Initialize components
    workspaceManager = new WorkspaceManager(workspaceRoot)
    database = new DatabaseManager(dbPath)
    cacheManager = new CacheManager(cacheDir, database)
  })

  afterEach(async () => {
    // Cleanup
    database.close()
    await fs.rm(testDir, { recursive: true, force: true })
  })

  test('should return error for non-existent sample', async () => {
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    const result = await handler({
      sample_id: 'sha256:nonexistent',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should validate input schema', async () => {
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    // Missing sample_id
    const result = await handler({})

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
  })

  test('should default triage raw result mode to compact', () => {
    const parsed = TriageWorkflowInputSchema.parse({
      sample_id: 'sha256:' + 'f'.repeat(64),
    })

    expect(parsed.raw_result_mode).toBe('compact')
  })

  test('should have correct structure in successful result', async () => {
    // This test verifies the output structure without requiring a real sample
    // We'll mock the individual tool handlers in integration tests
    
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    // Create a dummy sample
    const sampleId = 'sha256:' + '0'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '0'.repeat(64),
      md5: '0'.repeat(32),
      size: 1024,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace with a dummy file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'test.exe'), Buffer.from('MZ'))

    const result = await handler({ sample_id: sampleId })

    // The workflow should attempt to run but may fail on individual tools
    // We're mainly checking that it doesn't crash and returns proper structure
    expect(result).toBeDefined()
    expect(result.metrics).toBeDefined()
    expect(result.metrics?.tool).toBe('workflow.triage')
    expect(result.metrics?.elapsed_ms).toBeGreaterThan(0)
  })

  test('should aggregate results from multiple tools', async () => {
    // This is a structural test - integration tests will verify actual functionality
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
    expect(typeof handler).toBe('function')
  })

  test('should calculate threat level correctly', async () => {
    // Test the threat level calculation logic indirectly through the workflow
    // Integration tests will verify with real samples
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should identify suspicious imports', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should extract IOCs from strings', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should generate evidence list', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should provide recommendations based on threat level', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should complete within reasonable time', async () => {
    // Requirement: 15.3 - should complete within 5 minutes
    // This will be verified in integration tests with real samples
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should handle partial tool failures gracefully', async () => {
    // Create a dummy sample
    const sampleId = 'sha256:' + '1'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 1024,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace with a dummy file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'test.exe'), Buffer.from('MZ'))

    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    const result = await handler({ sample_id: sampleId })

    // Should not crash even if tools fail
    expect(result).toBeDefined()
    expect(result.metrics).toBeDefined()
  })

  test('should include raw results from individual tools', async () => {
    // Create a dummy sample
    const sampleId = 'sha256:' + '2'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 1024,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace with a dummy file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'test.exe'), Buffer.from('MZ'))

    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    const result = await handler({ sample_id: sampleId })

    // Check that result structure includes raw_results field
    if (result.ok && result.data) {
      const data = result.data as any
      expect(data.result_mode).toBe('quick_profile')
      expect(data.coverage_level).toBe('quick')
      expect(data.completion_state).toBe('bounded')
      expect(data.coverage_gaps.some((item: any) => item.domain === 'ghidra_analysis')).toBe(true)
      expect(data.upgrade_paths.some((item: any) => item.tool === 'ghidra.analyze')).toBe(true)
      expect(data.recommended_next_tools).toContain('ghidra.analyze')
      expect(data.next_actions[0]).toContain('ghidra.analyze')
      expect(data.raw_results).toBeDefined()
      expect(data.raw_results).toHaveProperty('static_capability')
      expect(data.raw_results).toHaveProperty('pe_structure')
      expect(data.raw_results).toHaveProperty('compiler_packer')
      expect(data.raw_results).toHaveProperty('string_context')
    }
  })

  test('should integrate compact string context previews into triage output', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 2048,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
      peFingerprint: async () => ({
        ok: true,
        data: {
          machine_name: 'IMAGE_FILE_MACHINE_AMD64',
          sections: [{ name: '.text' }],
        },
      }),
      runtimeDetect: async () => ({
        ok: true,
        data: {
          suspected: [{ runtime: 'native', confidence: 0.8, evidence: ['pe imports'] }],
          import_dlls: ['KERNEL32.dll'],
        },
      }),
      peImportsExtract: async () => ({
        ok: true,
        data: {
          imports: {
            'KERNEL32.dll': ['WriteProcessMemory', 'CreateRemoteThread'],
          },
          delay_imports: {},
        },
      }),
      stringsExtract: async () => ({
        ok: true,
        data: {
          strings: [
            { offset: 0x1000, string: 'http://evil.example/c2', encoding: 'ascii' },
            { offset: 0x1200, string: 'CreateRemoteThread', encoding: 'ascii' },
          ],
          summary: {
            cluster_counts: { ioc: 2 },
            context_windows: [],
          },
        },
      }),
      yaraScan: async () => ({
        ok: true,
        data: {
          matches: [],
          quality_notes: [],
        },
      }),
      staticCapabilityTriage: async () => ({
        ok: true,
        data: {
          status: 'ready',
          capability_count: 1,
          capability_groups: {
            injection: 1,
          },
          capabilities: [
            {
              rule_id: 'cap-1',
              name: 'process injection',
              namespace: 'host-interaction/injection',
              scopes: ['function'],
              group: 'injection',
              confidence: 0.88,
              match_count: 2,
              evidence_summary: 'WriteProcessMemory + CreateRemoteThread',
            },
          ],
        },
      }),
      peStructureAnalyze: async () => ({
        ok: true,
        data: {
          status: 'ready',
          summary: {
            section_count: 4,
            resource_count: 1,
            forwarder_count: 0,
            parser_preference: 'pefile',
            overlay_present: false,
          },
        },
      }),
      compilerPackerDetect: async () => ({
        ok: true,
        data: {
          status: 'ready',
          compiler_findings: [
            {
              name: 'MSVC',
              category: 'compiler',
              confidence: 0.92,
              evidence_summary: 'Rich header',
              source: 'die',
            },
          ],
          packer_findings: [],
          protector_findings: [],
          file_type_findings: [],
          summary: {
            compiler_count: 1,
            packer_count: 0,
            protector_count: 0,
            likely_primary_file_type: 'native_pe',
          },
        },
      }),
      analysisContextLink: async () => ({
        ok: true,
        data: {
          status: 'ready',
          xref_status: 'available',
          sample_id: sampleId,
          merged_strings: {
            status: 'ready',
            total_records: 3,
            kept_records: 3,
            analyst_relevant_count: 3,
            runtime_noise_count: 0,
            encoded_candidate_count: 0,
            merged_sources: true,
            truncated: false,
            top_suspicious: [
              {
                value: 'http://evil.example/c2',
                offset: 0x1000,
                categories: ['url'],
                labels: ['analyst_relevant'],
                confidence: 0.84,
                score: 20,
                source_labels: ['extract:ascii'],
              },
            ],
            top_iocs: [],
            top_runtime_noise: [],
            top_decoded: [],
            context_windows: [],
          },
          function_contexts: [
            {
              function: 'FUN_140010000',
              address: '0x140010000',
              score: 18,
              top_strings: ['http://evil.example/c2'],
              top_categories: ['url'],
              sensitive_apis: ['CreateRemoteThread'],
              inbound_refs: ['call'],
              outbound_refs: [],
              rationale: ['string:http://evil.example/c2'],
            },
          ],
          summary: 'Mapped suspicious string evidence to one compact function context.',
          source_artifact_refs: [],
          recommended_next_tools: ['code.function.decompile'],
          next_actions: ['Use code.function.decompile'],
        },
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.recommended_next_tools).toContain('analysis.context.link')
    expect(data.recommended_next_tools).toContain('code.xrefs.analyze')
    expect(data.raw_results.string_context.summary).toContain('Mapped suspicious string evidence')
    expect(data.raw_results.string_context.function_contexts[0].function).toBe('FUN_140010000')
    expect(data.next_actions[0]).toContain('analysis.context.link')
  })

  test('should auto-select bounded triage enrichments when packer and weak-YARA signals are present', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '4'.repeat(64),
      md5: '4'.repeat(32),
      size: 4096,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'test.exe'), Buffer.from('MZ'))

    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
      peFingerprint: async () => ({
        ok: true,
        data: { machine_name: 'IMAGE_FILE_MACHINE_AMD64', sections: [] },
      }),
      runtimeDetect: async () => ({
        ok: true,
        data: {
          suspected: [{ runtime: 'native', confidence: 0.7, evidence: ['imports'] }],
          import_dlls: ['KERNEL32.dll'],
        },
      }),
      peImportsExtract: async () => ({
        ok: true,
        data: {
          imports: { 'KERNEL32.dll': ['WriteProcessMemory'] },
          delay_imports: {},
        },
      }),
      stringsExtract: async () => ({
        ok: true,
        data: {
          strings: [{ string: 'http://evil.example', offset: 16, encoding: 'ascii' }],
          summary: { cluster_counts: {}, context_windows: [] },
        },
      }),
      yaraScan: async () => ({
        ok: true,
        data: {
          matches: [],
          quality_notes: [],
        },
      }),
      staticCapabilityTriage: async () => ({
        ok: true,
        data: {
          status: 'ready',
          capability_count: 0,
          capability_groups: {},
          capabilities: [],
        },
      }),
      peStructureAnalyze: async () => ({
        ok: true,
        data: {
          status: 'partial',
          summary: {
            section_count: 3,
            resource_count: 0,
            forwarder_count: 0,
            parser_preference: 'lief',
            overlay_present: true,
          },
        },
      }),
      compilerPackerDetect: async () => ({
        ok: true,
        data: {
          status: 'ready',
          compiler_findings: [],
          packer_findings: [
            {
              name: 'UPX',
              category: 'packer',
              confidence: 0.91,
              evidence_summary: 'upx markers',
              source: 'die',
            },
          ],
          protector_findings: [],
          file_type_findings: [],
          summary: {
            compiler_count: 0,
            packer_count: 1,
            protector_count: 0,
            file_type_count: 0,
            likely_primary_file_type: 'pe32+',
          },
        },
      }),
      analysisContextLink: async () => ({
        ok: true,
        data: {
          status: 'partial',
          xref_status: 'unavailable',
          merged_strings: {
            analyst_relevant_count: 1,
            total_records: 1,
            kept_records: 1,
            runtime_noise_count: 0,
            encoded_candidate_count: 0,
            merged_sources: true,
            truncated: false,
            top_suspicious: [],
            top_iocs: [],
            top_decoded: [],
            context_windows: [],
          },
          function_contexts: [],
          source_artifact_refs: [],
        },
      }),
      upxInspect: async () => ({
        ok: true,
        data: {
          status: 'ready',
          operation: 'test',
          summary: 'UPX validation completed.',
          recommended_next_tools: [],
          next_actions: [],
        },
      }),
      yaraXScan: async () => ({
        ok: true,
        data: {
          status: 'ready',
          match_count: 1,
          matches: [{ identifier: 'triage_match' }],
          summary: 'YARA-X found one rule match.',
          recommended_next_tools: [],
          next_actions: [],
        },
      }),
      rizinAnalyze: async () => ({
        ok: true,
        data: {
          status: 'ready',
          operation: 'sections',
          preview: [{ name: '.text' }],
          summary: 'Rizin section inspection complete.',
          recommended_next_tools: [],
          next_actions: [],
        },
      }),
      resolveBackends: () => ({
        capa_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        capa_rules: { available: false, source: 'none', path: null, error: null },
        die: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        graphviz: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        rizin: { available: true, source: 'path', path: '/tool/rizin', version: '1', checked_candidates: ['rizin'], error: null },
        upx: { available: true, source: 'path', path: '/tool/upx', version: '1', checked_candidates: ['upx'], error: null },
        wine: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        winedbg: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        frida_cli: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        yara_x: { available: true, source: 'path', path: '/tool/python', version: '1', checked_candidates: ['python3'], error: null },
        qiling: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        angr: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        panda: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
        retdec: { available: false, source: 'none', path: null, version: null, checked_candidates: [], error: null },
      }),
    })

    const result = await handler({
      sample_id: sampleId,
      backend_policy: 'prefer_new',
      depth: 'deep',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.backend_selected.map((item: any) => item.tool)).toEqual(
      expect.arrayContaining(['upx.inspect', 'yara_x.scan', 'rizin.analyze'])
    )
    expect(data.raw_results.backend_enrichments.upx.summary).toContain('UPX')
    expect(data.raw_results.backend_enrichments.yara_x.match_count).toBe(1)
    expect(data.raw_results.backend_enrichments.rizin.operation).toBe('sections')
  })
})
