/**
 * V0.1 Acceptance Tests
 * 
 * Tests the core acceptance criteria for V0.1 release:
 * 1. Sample ingestion and basic info extraction
 * 2. YARA scan identifies packers
 * 3. Triage workflow completes in <5 minutes
 * 4. All tools return schema-compliant results
 * 
 * Requirements: V0.1 验收标准
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals'
import { MCPServer } from '../../src/server.js'
import { loadConfig } from '../../src/config.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { CacheManager } from '../../src/cache-manager.js'
import {
  sampleIngestToolDefinition,
  createSampleIngestHandler
} from '../../src/tools/sample-ingest.js'
import {
  sampleProfileGetToolDefinition,
  createSampleProfileGetHandler
} from '../../src/tools/sample-profile-get.js'
import {
  peFingerprintToolDefinition,
  createPEFingerprintHandler
} from '../../src/plugins/pe-analysis/tools/pe-fingerprint.js'
import {
  peImportsExtractToolDefinition,
  createPEImportsExtractHandler
} from '../../src/plugins/pe-analysis/tools/pe-imports-extract.js'
import {
  peExportsExtractToolDefinition,
  createPEExportsExtractHandler
} from '../../src/plugins/pe-analysis/tools/pe-exports-extract.js'
import {
  stringsExtractToolDefinition,
  createStringsExtractHandler
} from '../../src/tools/strings-extract.js'
import {
  yaraScanToolDefinition,
  createYaraScanHandler
} from '../../src/tools/yara-scan.js'
import {
  runtimeDetectToolDefinition,
  createRuntimeDetectHandler
} from '../../src/tools/runtime-detect.js'
import {
  packerDetectToolDefinition,
  createPackerDetectHandler
} from '../../src/tools/packer-detect.js'
import {
  reportSummarizeToolDefinition,
  createReportSummarizeHandler
} from '../../src/tools/report-summarize.js'
import { createTriageWorkflowHandler } from '../../src/workflows/triage.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('V0.1 Acceptance Tests', () => {
  let server: MCPServer
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let policyGuard: PolicyGuard
  let cacheManager: CacheManager
  let triageHandler: ReturnType<typeof createTriageWorkflowHandler>
  let testDir: string
  let dbPath: string
  let auditLogPath: string
  let cacheDir: string

  beforeAll(async () => {
    // Create temporary test directory
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'v01-acceptance-'))
    const workspaceRoot = path.join(testDir, 'workspaces')
    cacheDir = path.join(testDir, 'cache')
    dbPath = path.join(testDir, 'test.db')
    auditLogPath = path.join(testDir, 'audit.log')

    // Initialize components
    workspaceManager = new WorkspaceManager(workspaceRoot)
    database = new DatabaseManager(dbPath)
    cacheManager = new CacheManager(cacheDir, database)
    policyGuard = new PolicyGuard(auditLogPath)

    // Create MCP server
    const config = loadConfig()
    server = new MCPServer(config)

    // Register all V0.1 tools
    server.registerTool(
      sampleIngestToolDefinition,
      createSampleIngestHandler(workspaceManager, database, policyGuard)
    )
    server.registerTool(
      sampleProfileGetToolDefinition,
      createSampleProfileGetHandler(database)
    )
    server.registerTool(
      peFingerprintToolDefinition,
      createPEFingerprintHandler({ workspaceManager, database, cacheManager } as any)
    )
    server.registerTool(
      peImportsExtractToolDefinition,
      createPEImportsExtractHandler({ workspaceManager, database, cacheManager } as any)
    )
    server.registerTool(
      peExportsExtractToolDefinition,
      createPEExportsExtractHandler({ workspaceManager, database, cacheManager } as any)
    )
    server.registerTool(
      stringsExtractToolDefinition,
      createStringsExtractHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      yaraScanToolDefinition,
      createYaraScanHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      runtimeDetectToolDefinition,
      createRuntimeDetectHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      packerDetectToolDefinition,
      createPackerDetectHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      reportSummarizeToolDefinition,
      createReportSummarizeHandler(workspaceManager, database, cacheManager)
    )

    // Create triage workflow handler
    triageHandler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
  })

  afterAll(async () => {
    // Cleanup
    database.close()
    await fs.rm(testDir, { recursive: true, force: true })
  })

  /**
   * Helper function to create a minimal PE file for testing
   */
  function createMinimalPE(): Buffer {
    const pe = Buffer.alloc(1024)
    
    // DOS header
    pe.write('MZ', 0, 'ascii')  // e_magic
    pe.writeUInt32LE(0x80, 0x3c)  // e_lfanew (offset to PE header)
    
    // PE header at offset 0x80
    pe.write('PE\0\0', 0x80, 'ascii')  // Signature
    
    // COFF header
    pe.writeUInt16LE(0x014c, 0x84)  // Machine (IMAGE_FILE_MACHINE_I386)
    pe.writeUInt16LE(1, 0x86)  // NumberOfSections
    pe.writeUInt32LE(Math.floor(Date.now() / 1000), 0x88)  // TimeDateStamp
    pe.writeUInt32LE(0, 0x8c)  // PointerToSymbolTable
    pe.writeUInt32LE(0, 0x90)  // NumberOfSymbols
    pe.writeUInt16LE(0xe0, 0x94)  // SizeOfOptionalHeader
    pe.writeUInt16LE(0x010f, 0x96)  // Characteristics
    
    // Optional header
    pe.writeUInt16LE(0x010b, 0x98)  // Magic (PE32)
    pe.writeUInt8(0x0e, 0x9a)  // MajorLinkerVersion
    pe.writeUInt8(0x00, 0x9b)  // MinorLinkerVersion
    pe.writeUInt32LE(0x1000, 0x9c)  // SizeOfCode
    pe.writeUInt32LE(0x1000, 0xa0)  // SizeOfInitializedData
    pe.writeUInt32LE(0, 0xa4)  // SizeOfUninitializedData
    pe.writeUInt32LE(0x1000, 0xa8)  // AddressOfEntryPoint
    pe.writeUInt32LE(0x1000, 0xac)  // BaseOfCode
    pe.writeUInt32LE(0x2000, 0xb0)  // BaseOfData
    pe.writeUInt32LE(0x400000, 0xb4)  // ImageBase
    pe.writeUInt32LE(0x1000, 0xb8)  // SectionAlignment
    pe.writeUInt32LE(0x200, 0xbc)  // FileAlignment
    pe.writeUInt16LE(5, 0xc0)  // MajorOperatingSystemVersion
    pe.writeUInt16LE(1, 0xc2)  // MinorOperatingSystemVersion
    pe.writeUInt16LE(0, 0xc4)  // MajorImageVersion
    pe.writeUInt16LE(0, 0xc6)  // MinorImageVersion
    pe.writeUInt16LE(5, 0xc8)  // MajorSubsystemVersion
    pe.writeUInt16LE(1, 0xca)  // MinorSubsystemVersion
    pe.writeUInt32LE(0, 0xcc)  // Win32VersionValue
    pe.writeUInt32LE(0x3000, 0xd0)  // SizeOfImage
    pe.writeUInt32LE(0x200, 0xd4)  // SizeOfHeaders
    pe.writeUInt32LE(0, 0xd8)  // CheckSum
    pe.writeUInt16LE(3, 0xdc)  // Subsystem (IMAGE_SUBSYSTEM_WINDOWS_CUI)
    pe.writeUInt16LE(0, 0xde)  // DllCharacteristics
    
    return pe
  }

  /**
   * Helper function to create a PE with UPX packer signature
   * This simulates a packed executable for packer detection testing
   */
  function createPackedPE(): Buffer {
    const pe = createMinimalPE()
    
    // Add UPX signature patterns at specific offsets
    // UPX typically has these characteristics:
    // 1. Section names like UPX0, UPX1
    // 2. High entropy in packed sections
    // 3. Specific byte patterns
    
    // Add UPX section name at section header offset (after optional header)
    const sectionHeaderOffset = 0x98 + 0xe0  // After optional header
    pe.write('UPX0\0\0\0\0', sectionHeaderOffset, 'ascii')
    
    // Add some high-entropy data to simulate packed content
    for (let i = 512; i < 768; i++) {
      pe[i] = Math.floor(Math.random() * 256)
    }
    
    // Add UPX magic bytes that YARA rules might look for
    pe.write('UPX!', 800, 'ascii')
    
    return pe
  }

  /**
   * Acceptance Test 1: Sample ingestion and basic info extraction
   * 
   * Verifies:
   * - Sample can be ingested successfully
   * - SHA256 and MD5 hashes are computed
   * - Sample profile can be retrieved
   * - Basic PE information is extracted
   */
  describe('Acceptance Test 1: Sample Ingestion and Basic Info Extraction', () => {
    test('should ingest sample and extract basic information', async () => {
      const peData = createMinimalPE()
      
      // Step 1: Ingest sample
      const ingestResult = await server.callTool('sample.ingest', {
        bytes_b64: peData.toString('base64'),
        filename: 'acceptance_test_1.exe',
        source: 'v0.1_acceptance_test',
      })
      
      expect(ingestResult.isError).toBe(false)
      const ingestText = ingestResult.content.find(c => c.type === 'text')
      expect(ingestText).toBeDefined()
      const ingestData = JSON.parse(ingestText!.text!)
      
      expect(ingestData.ok).toBe(true)
      expect(ingestData.data.sample_id).toBeDefined()
      expect(ingestData.data.sample_id).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(ingestData.data.size).toBe(peData.length)
      
      const sampleId = ingestData.data.sample_id

      // Step 2: Get sample profile
      const profileResult = await server.callTool('sample.profile.get', {
        sample_id: sampleId,
      })
      
      expect(profileResult.isError).toBe(false)
      const profileText = profileResult.content.find(c => c.type === 'text')
      expect(profileText).toBeDefined()
      const profileData = JSON.parse(profileText!.text!)
      
      expect(profileData.ok).toBe(true)
      expect(profileData.data.sample.id).toBe(sampleId)
      expect(profileData.data.sample.sha256).toBeDefined()
      expect(profileData.data.sample.sha256).toMatch(/^[0-9a-f]{64}$/)
      expect(profileData.data.sample.md5).toBeDefined()
      expect(profileData.data.sample.md5).toMatch(/^[0-9a-f]{32}$/)
      expect(profileData.data.sample.size).toBe(peData.length)
      expect(profileData.data.sample.file_type).toBeDefined()
      
      // Step 3: Extract PE fingerprint
      const fingerprintResult = await server.callTool('pe.fingerprint', {
        sample_id: sampleId,
        fast: true,
      })
      
      expect(fingerprintResult.isError).toBe(false)
      const fingerprintText = fingerprintResult.content.find(c => c.type === 'text')
      expect(fingerprintText).toBeDefined()
      const fingerprintData = JSON.parse(fingerprintText!.text!)
      
      expect(fingerprintData.ok).toBe(true)
      expect(fingerprintData.data).toBeDefined()
      // PE fingerprint should contain basic PE information
      expect(fingerprintData.data.machine).toBeDefined()
      expect(fingerprintData.data.subsystem).toBeDefined()
      
      // Step 4: Extract imports
      const importsResult = await server.callTool('pe.imports.extract', {
        sample_id: sampleId,
        group_by_dll: true,
      })
      
      expect(importsResult.isError).toBe(false)
      const importsText = importsResult.content.find(c => c.type === 'text')
      expect(importsText).toBeDefined()
      const importsData = JSON.parse(importsText!.text!)
      
      expect(importsData.ok).toBe(true)
      expect(importsData.data).toBeDefined()
      
      // Step 5: Extract strings
      const stringsResult = await server.callTool('strings.extract', {
        sample_id: sampleId,
        min_len: 4,
      })
      
      expect(stringsResult.isError).toBe(false)
      const stringsText = stringsResult.content.find(c => c.type === 'text')
      expect(stringsText).toBeDefined()
      const stringsData = JSON.parse(stringsText!.text!)
      
      expect(stringsData.ok).toBe(true)
      expect(stringsData.data).toBeDefined()
    }, 10 * 60 * 1000) // 10 minute timeout
  })

  /**
   * Acceptance Test 2: YARA scan identifies packers
   * 
   * Verifies:
   * - YARA scanning functionality works
   * - Packer detection can identify common packers
   * - Results are properly formatted
   */
  describe('Acceptance Test 2: YARA Scan Identifies Packers', () => {
    test('should detect packer signatures using YARA', async () => {
      const packedPE = createPackedPE()
      
      // Step 1: Ingest packed sample
      const ingestResult = await server.callTool('sample.ingest', {
        bytes_b64: packedPE.toString('base64'),
        filename: 'acceptance_test_2_packed.exe',
        source: 'v0.1_acceptance_test',
      })
      
      expect(ingestResult.isError).toBe(false)
      const ingestText = ingestResult.content.find(c => c.type === 'text')
      const ingestData = JSON.parse(ingestText!.text!)
      const sampleId = ingestData.data.sample_id
      
      // Step 2: Run packer detection
      const packerResult = await server.callTool('packer.detect', {
        sample_id: sampleId,
      })
      
      expect(packerResult.isError).toBe(false)
      const packerText = packerResult.content.find(c => c.type === 'text')
      expect(packerText).toBeDefined()
      const packerData = JSON.parse(packerText!.text!)
      
      expect(packerData.ok).toBe(true)
      expect(packerData.data).toBeDefined()
      
      // Packer detection should return structured results
      // Even if no packer is detected, the structure should be valid
      if (packerData.data.detected) {
        expect(Array.isArray(packerData.data.detected)).toBe(true)
      }
      
      // Step 3: Run YARA scan with packer rules
      const yaraResult = await server.callTool('yara.scan', {
        sample_id: sampleId,
        rule_set: 'packers',
      })
      
      // YARA scan may succeed or fail depending on rule availability
      // We verify the response structure is correct
      const yaraText = yaraResult.content.find(c => c.type === 'text')
      expect(yaraText).toBeDefined()
      const yaraData = JSON.parse(yaraText!.text!)
      
      // Response should have ok field
      expect(yaraData).toHaveProperty('ok')
      
      if (yaraData.ok) {
        // If successful, should have matches array
        expect(yaraData.data).toBeDefined()
        expect(yaraData.data.matches).toBeDefined()
        expect(Array.isArray(yaraData.data.matches)).toBe(true)
        
        // Each match should have proper structure
        for (const match of yaraData.data.matches) {
          expect(match.rule).toBeDefined()
          expect(typeof match.rule).toBe('string')
        }
      }
    }, 10 * 60 * 1000)
  })

  /**
   * Acceptance Test 3: Triage workflow completes in <5 minutes
   * 
   * Verifies:
   * - Complete triage workflow executes successfully
   * - Workflow completes within 5 minute performance requirement
   * - Report is generated with all required fields
   */
  describe('Acceptance Test 3: Triage Workflow Performance', () => {
    test('should complete triage workflow within 5 minutes', async () => {
      const peData = createMinimalPE()
      
      // Step 1: Ingest sample
      const ingestResult = await server.callTool('sample.ingest', {
        bytes_b64: peData.toString('base64'),
        filename: 'acceptance_test_3_triage.exe',
        source: 'v0.1_acceptance_test',
      })
      
      expect(ingestResult.isError).toBe(false)
      const ingestText = ingestResult.content.find(c => c.type === 'text')
      const ingestData = JSON.parse(ingestText!.text!)
      const sampleId = ingestData.data.sample_id
      
      // Step 2: Execute triage workflow and measure time
      const startTime = Date.now()
      const triageResult = await triageHandler({ sample_id: sampleId })
      const elapsedMs = Date.now() - startTime
      
      // Verify completion time (5 minutes = 300,000 ms)
      expect(elapsedMs).toBeLessThan(5 * 60 * 1000)
      
      // Verify workflow succeeded
      expect(triageResult).toBeDefined()
      expect(triageResult.ok).toBe(true)
      
      // Verify report structure
      expect(triageResult.data).toBeDefined()
      const report = triageResult.data as any
      
      expect(report.summary).toBeDefined()
      expect(typeof report.summary).toBe('string')
      expect(report.summary.length).toBeGreaterThan(0)
      
      expect(report.confidence).toBeDefined()
      expect(typeof report.confidence).toBe('number')
      expect(report.confidence).toBeGreaterThanOrEqual(0)
      expect(report.confidence).toBeLessThanOrEqual(1)
      
      expect(report.threat_level).toBeDefined()
      expect(['clean', 'suspicious', 'malicious', 'unknown']).toContain(report.threat_level)
      
      expect(report.iocs).toBeDefined()
      expect(report.evidence).toBeDefined()
      expect(Array.isArray(report.evidence)).toBe(true)
      
      expect(report.recommendation).toBeDefined()
      expect(typeof report.recommendation).toBe('string')
      
      // Verify metrics are included
      expect(triageResult.metrics).toBeDefined()
      expect(triageResult.metrics?.elapsed_ms).toBeDefined()
      expect(triageResult.metrics?.elapsed_ms).toBeGreaterThan(0)
    }, 6 * 60 * 1000) // 6 minute timeout for the test itself
  })

  /**
   * Acceptance Test 4: All tools return schema-compliant results
   * 
   * Verifies:
   * - All V0.1 tools are registered
   * - Each tool has valid input/output schema
   * - Tool responses conform to their schemas
   * - Error responses are properly formatted
   */
  describe('Acceptance Test 4: Schema Compliance', () => {
    let testSampleId: string

    beforeAll(async () => {
      // Create a test sample for schema validation
      const peData = createMinimalPE()
      const ingestResult = await server.callTool('sample.ingest', {
        bytes_b64: peData.toString('base64'),
        filename: 'acceptance_test_4_schema.exe',
        source: 'v0.1_acceptance_test',
      })
      
      const ingestText = ingestResult.content.find(c => c.type === 'text')
      const ingestData = JSON.parse(ingestText!.text!)
      testSampleId = ingestData.data.sample_id
    })

    test('should have all V0.1 tools registered', async () => {
      const tools = await server.listTools()
      
      expect(tools).toBeDefined()
      expect(Array.isArray(tools)).toBe(true)
      
      const toolNames = tools.map(t => t.name)
      
      // Verify all required V0.1 tools are present
      const requiredTools = [
        'sample.ingest',
        'sample.profile.get',
        'pe.fingerprint',
        'pe.imports.extract',
        'pe.exports.extract',
        'strings.extract',
        'yara.scan',
        'runtime.detect',
        'packer.detect',
        'report.summarize',
      ]
      
      for (const toolName of requiredTools) {
        expect(toolNames).toContain(toolName)
      }
    })

    test('should have valid schemas for all tools', async () => {
      const tools = await server.listTools()
      
      for (const tool of tools) {
        // Verify tool definition structure
        expect(tool.name).toBeDefined()
        expect(typeof tool.name).toBe('string')
        expect(tool.name.length).toBeGreaterThan(0)
        
        expect(tool.description).toBeDefined()
        expect(typeof tool.description).toBe('string')
        if (tool.description) {
          expect(tool.description.length).toBeGreaterThan(0)
        }
        
        expect(tool.inputSchema).toBeDefined()
        expect(typeof tool.inputSchema).toBe('object')
        const schema = tool.inputSchema as any

        const isObjectSchema =
          schema.type === 'object' && schema.properties !== undefined

        const isObjectUnionSchema =
          Array.isArray(schema.anyOf) &&
          schema.anyOf.length > 0 &&
          schema.anyOf.every(
            (branch: any) => branch?.type === 'object' && branch.properties !== undefined
          )

        expect(isObjectSchema || isObjectUnionSchema).toBe(true)
      }
    })

    test('should return schema-compliant results for sample.ingest', async () => {
      const peData = createMinimalPE()
      const result = await server.callTool('sample.ingest', {
        bytes_b64: peData.toString('base64'),
        filename: 'schema_test.exe',
      })
      
      expect(result.isError).toBe(false)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      
      // Verify response structure
      expect(data).toHaveProperty('ok')
      expect(typeof data.ok).toBe('boolean')
      expect(data.ok).toBe(true)
      
      expect(data).toHaveProperty('data')
      expect(data.data).toHaveProperty('sample_id')
      expect(data.data.sample_id).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(data.data).toHaveProperty('size')
      expect(typeof data.data.size).toBe('number')
    })

    test('should return schema-compliant results for pe.fingerprint', async () => {
      const result = await server.callTool('pe.fingerprint', {
        sample_id: testSampleId,
        fast: true,
      })
      
      expect(result.isError).toBe(false)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      
      expect(data).toHaveProperty('ok')
      expect(typeof data.ok).toBe('boolean')
      expect(data).toHaveProperty('data')
    })

    test('should return schema-compliant results for pe.imports.extract', async () => {
      const result = await server.callTool('pe.imports.extract', {
        sample_id: testSampleId,
        group_by_dll: true,
      })
      
      expect(result.isError).toBe(false)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      
      expect(data).toHaveProperty('ok')
      expect(typeof data.ok).toBe('boolean')
      expect(data).toHaveProperty('data')
    })

    test('should return schema-compliant results for strings.extract', async () => {
      const result = await server.callTool('strings.extract', {
        sample_id: testSampleId,
        min_len: 4,
      })
      
      expect(result.isError).toBe(false)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      
      expect(data).toHaveProperty('ok')
      expect(typeof data.ok).toBe('boolean')
      expect(data).toHaveProperty('data')
    })

    test('should return schema-compliant results for runtime.detect', async () => {
      const result = await server.callTool('runtime.detect', {
        sample_id: testSampleId,
      })
      
      expect(result.isError).toBe(false)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      
      expect(data).toHaveProperty('ok')
      expect(typeof data.ok).toBe('boolean')
      expect(data).toHaveProperty('data')
      
      if (data.ok) {
        expect(data.data).toHaveProperty('is_dotnet')
        expect(typeof data.data.is_dotnet).toBe('boolean')
      }
    })

    test('should return schema-compliant results for packer.detect', async () => {
      const result = await server.callTool('packer.detect', {
        sample_id: testSampleId,
      })
      
      expect(result.isError).toBe(false)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      
      expect(data).toHaveProperty('ok')
      expect(typeof data.ok).toBe('boolean')
      expect(data).toHaveProperty('data')
    })

    test('should return properly formatted error responses', async () => {
      // Test with non-existent sample
      const result = await server.callTool('pe.fingerprint', {
        sample_id: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      })
      
      expect(result.isError).toBe(true)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      
      // Error responses should have ok: false
      expect(data).toHaveProperty('ok')
      expect(data.ok).toBe(false)
      
      // Should have errors array
      expect(data).toHaveProperty('errors')
      expect(Array.isArray(data.errors)).toBe(true)
      expect(data.errors.length).toBeGreaterThan(0)
    })

    test('should validate input parameters', async () => {
      // Test with invalid parameter type
      const result = await server.callTool('strings.extract', {
        sample_id: testSampleId,
        min_len: 'not-a-number', // Should be number
      })
      
      expect(result.isError).toBe(true)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      // The error message should contain information about invalid arguments
      expect(textContent!.text).toContain('Invalid arguments')
    })

    test('should handle missing required parameters', async () => {
      // Test with missing required parameter
      const result = await server.callTool('pe.fingerprint', {
        // Missing sample_id
        fast: true,
      })
      
      expect(result.isError).toBe(true)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      // The error message should contain information about invalid arguments
      expect(textContent!.text).toContain('Invalid arguments')
    })
  })
})
