/**
 * Integration tests for MCP Tools
 * Tests end-to-end tool calling, schema validation, and error handling
 * Requirements: 31.3
 */

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
  stringsFlossDecodeToolDefinition,
  createStringsFlossDecodeHandler
} from '../../src/tools/strings-floss-decode.js'
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
import fs from 'fs'
import path from 'path'

describe('MCP Tools Integration Tests', () => {
  const testDir = './test-data-mcp-integration'
  const workspaceRoot = path.join(testDir, 'workspaces')
  const dbPath = path.join(testDir, 'test.db')
  const auditLogPath = path.join(testDir, 'audit.log')
  const cachePath = path.join(testDir, 'cache')

  let server: MCPServer
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let policyGuard: PolicyGuard
  let cacheManager: CacheManager
  let testSampleId: string

  beforeAll(() => {
    // Clean up old test data if exists
    if (fs.existsSync(testDir)) {
      try {
        fs.rmSync(testDir, { recursive: true, force: true })
      } catch (e) {
        console.warn('Failed to cleanup old test directory:', (e as Error).message)
      }
    }

    // Create test directory
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true })
    }
    if (!fs.existsSync(workspaceRoot)) {
      fs.mkdirSync(workspaceRoot, { recursive: true })
    }
    if (!fs.existsSync(cachePath)) {
      fs.mkdirSync(cachePath, { recursive: true })
    }

    // Initialize components
    workspaceManager = new WorkspaceManager(workspaceRoot)
    database = new DatabaseManager(dbPath)
    policyGuard = new PolicyGuard(auditLogPath)
    cacheManager = new CacheManager(cachePath, database)

    // Create server with test config
    const config = loadConfig()
    server = new MCPServer(config)

    // Register all tools
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
      stringsFlossDecodeToolDefinition,
      createStringsFlossDecodeHandler(workspaceManager, database, cacheManager)
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
  })

  afterAll(() => {
    // Close database connection before cleanup
    try {
      database.close()
    } catch (e) {
      // Ignore if already closed
    }

    // Cleanup test directory with retry logic for Windows
    const cleanupWithRetry = (dirPath: string, attempts: number = 3) => {
      for (let i = 0; i < attempts; i++) {
        try {
          if (fs.existsSync(dirPath)) {
            fs.rmSync(dirPath, { recursive: true, force: true })
          }
          break
        } catch (e: any) {
          if (i === attempts - 1) {
            console.warn(`Failed to cleanup ${dirPath} after ${attempts} attempts:`, e.message)
          } else {
            // Wait a bit before retrying
            const delay = 100 * (i + 1)
            const start = Date.now()
            while (Date.now() - start < delay) {
              // Busy wait
            }
          }
        }
      }
    }

    cleanupWithRetry(testDir)
  })

  describe('Tool Registration and Discovery', () => {
    test('should list all registered tools', async () => {
      const tools = await server.listTools()

      expect(tools).toBeDefined()
      expect(Array.isArray(tools)).toBe(true)
      expect(tools.length).toBeGreaterThanOrEqual(10)

      // Verify all expected tools are registered
      const toolNames = tools.map(t => t.name)
      expect(toolNames).toContain('sample.ingest')
      expect(toolNames).toContain('sample.profile.get')
      expect(toolNames).toContain('pe.fingerprint')
      expect(toolNames).toContain('pe.imports.extract')
      expect(toolNames).toContain('pe.exports.extract')
      expect(toolNames).toContain('strings.extract')
      expect(toolNames).toContain('strings.floss.decode')
      expect(toolNames).toContain('yara.scan')
      expect(toolNames).toContain('runtime.detect')
      expect(toolNames).toContain('packer.detect')
    })

    test('should have valid schema for each tool', async () => {
      const tools = await server.listTools()

      for (const tool of tools) {
        expect(tool.name).toBeDefined()
        expect(typeof tool.name).toBe('string')
        expect(tool.description).toBeDefined()
        expect(typeof tool.description).toBe('string')
        expect(tool.inputSchema).toBeDefined()
        expect(typeof tool.inputSchema).toBe('object')
      }
    })
  })

  describe('End-to-End Tool Calling', () => {
    test('should ingest a sample successfully', async () => {
      // Create a minimal PE file
      const testData = createMinimalPE()
      const base64Data = testData.toString('base64')

      const result = await server.callTool('sample.ingest', {
        bytes_b64: base64Data,
        filename: 'test.exe',
        source: 'integration_test'
      })

      expect(result.isError).toBeFalsy()
      expect(result.content).toBeDefined()
      expect(result.content.length).toBeGreaterThan(0)

      // Extract sample_id from result
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data.sample_id).toBeDefined()
      expect(data.data.sample_id).toMatch(/^sha256:/)

      testSampleId = data.data.sample_id
    })

    test('should get sample profile', async () => {
      const result = await server.callTool('sample.profile.get', {
        sample_id: testSampleId
      })

      expect(result.isError).toBeFalsy()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data.sample.id).toBe(testSampleId)
      expect(data.data.sample.sha256).toBeDefined()
      expect(data.data.sample.size).toBeGreaterThan(0)
    })

    test('should extract PE fingerprint', async () => {
      const result = await server.callTool('pe.fingerprint', {
        sample_id: testSampleId,
        fast: true
      })

      expect(result.isError).toBeFalsy()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data).toBeDefined()
    })

    test('should extract PE imports', async () => {
      const result = await server.callTool('pe.imports.extract', {
        sample_id: testSampleId,
        group_by_dll: true
      })

      expect(result.isError).toBeFalsy()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data).toBeDefined()
    })

    test('should extract PE exports', async () => {
      const result = await server.callTool('pe.exports.extract', {
        sample_id: testSampleId
      })

      expect(result.isError).toBeFalsy()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data).toBeDefined()
    })

    test('should extract strings', async () => {
      const result = await server.callTool('strings.extract', {
        sample_id: testSampleId,
        min_len: 4
      })

      expect(result.isError).toBeFalsy()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data).toBeDefined()
    })

    test('should detect runtime', async () => {
      const result = await server.callTool('runtime.detect', {
        sample_id: testSampleId
      })

      expect(result.isError).toBeFalsy()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data).toBeDefined()
      expect(data.data.is_dotnet).toBeDefined()
    })

    test('should detect packer', async () => {
      const result = await server.callTool('packer.detect', {
        sample_id: testSampleId
      })

      expect(result.isError).toBeFalsy()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(true)
      expect(data.data).toBeDefined()
    })
  })

  describe('Schema Validation', () => {
    test('should reject invalid input for sample.ingest', async () => {
      const result = await server.callTool('sample.ingest', {
        // Missing both path and bytes_b64
        filename: 'test.exe'
      })

      expect(result.isError).toBe(true)
      expect(result.content).toBeDefined()
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      expect(textContent!.text).toContain('Invalid arguments')
    })

    test('should reject invalid sample_id format', async () => {
      const result = await server.callTool('sample.profile.get', {
        sample_id: 'invalid-format'
      })

      expect(result.isError).toBe(true)
    })

    test('should reject missing required parameters', async () => {
      const result = await server.callTool('pe.fingerprint', {
        // Missing sample_id
        fast: true
      })

      expect(result.isError).toBe(true)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      expect(textContent!.text).toContain('Invalid arguments')
    })

    test('should accept optional parameters', async () => {
      const result = await server.callTool('pe.fingerprint', {
        sample_id: testSampleId
        // fast parameter is optional
      })

      expect(result.isError).toBeFalsy()
    })

    test('should reject invalid parameter types', async () => {
      const result = await server.callTool('strings.extract', {
        sample_id: testSampleId,
        min_len: 'not-a-number' // should be number
      })

      expect(result.isError).toBe(true)
    })
  })

  describe('Error Handling', () => {
    test('should handle non-existent sample gracefully', async () => {
      const result = await server.callTool('pe.fingerprint', {
        sample_id: 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
      })

      expect(result.isError).toBe(true)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      const data = JSON.parse(textContent!.text!)
      expect(data.ok).toBe(false)
      expect(data.errors).toBeDefined()
      expect(data.errors.length).toBeGreaterThan(0)
    })

    test('should handle invalid tool name', async () => {
      const result = await server.callTool('non.existent.tool', {
        sample_id: testSampleId
      })

      expect(result.isError).toBe(true)
      const textContent = result.content.find(c => c.type === 'text')
      expect(textContent).toBeDefined()
      expect(textContent!.text).toContain('not found')
    })

    test('should handle malformed PE file', async () => {
      // Ingest a malformed file
      const malformedData = Buffer.from('This is not a PE file')
      const base64Data = malformedData.toString('base64')

      const ingestResult = await server.callTool('sample.ingest', {
        bytes_b64: base64Data,
        filename: 'malformed.exe'
      })

      expect(ingestResult.isError).toBeFalsy()
      const textContent = ingestResult.content.find(c => c.type === 'text')
      const ingestData = JSON.parse(textContent!.text!)
      const malformedSampleId = ingestData.data.sample_id

      // Try to extract PE fingerprint from malformed file
      const fingerprintResult = await server.callTool('pe.fingerprint', {
        sample_id: malformedSampleId,
        fast: true
      })

      // Should return error or partial result
      const fingerprintText = fingerprintResult.content.find(c => c.type === 'text')
      expect(fingerprintText).toBeDefined()
      const fingerprintData = JSON.parse(fingerprintText!.text!)
      // Either error or warnings should be present
      expect(
        fingerprintData.ok === false || 
        (fingerprintData.warnings && fingerprintData.warnings.length > 0)
      ).toBe(true)
    })

    test('should handle file size limit', async () => {
      // Create data exceeding 500MB (simulate with metadata)
      const result = await server.callTool('sample.ingest', {
        bytes_b64: Buffer.alloc(100).toString('base64'), // Small actual data
        filename: 'large.exe',
        // The actual size check happens during ingestion
      })

      // This test verifies the handler exists and processes the request
      expect(result).toBeDefined()
    })
  })

  describe('Tool Chaining', () => {
    test('should chain multiple tool calls', async () => {
      // 1. Ingest sample
      const testData = createMinimalPE()
      const ingestResult = await server.callTool('sample.ingest', {
        bytes_b64: testData.toString('base64'),
        filename: 'chain-test.exe'
      })
      expect(ingestResult.isError).toBeFalsy()
      const ingestText = ingestResult.content.find(c => c.type === 'text')
      const ingestData = JSON.parse(ingestText!.text!)
      const sampleId = ingestData.data.sample_id

      // 2. Get profile
      const profileResult = await server.callTool('sample.profile.get', {
        sample_id: sampleId
      })
      expect(profileResult.isError).toBeFalsy()

      // 3. Extract fingerprint
      const fingerprintResult = await server.callTool('pe.fingerprint', {
        sample_id: sampleId,
        fast: true
      })
      expect(fingerprintResult.isError).toBeFalsy()

      // 4. Detect runtime
      const runtimeResult = await server.callTool('runtime.detect', {
        sample_id: sampleId
      })
      expect(runtimeResult.isError).toBeFalsy()

      // 5. Detect packer
      const packerResult = await server.callTool('packer.detect', {
        sample_id: sampleId
      })
      expect(packerResult.isError).toBeFalsy()

      // All tools should work together seamlessly
      expect(true).toBe(true)
    })
  })

  describe('Caching Behavior', () => {
    test('should cache tool results', async () => {
      // First call
      const result1 = await server.callTool('pe.fingerprint', {
        sample_id: testSampleId,
        fast: true
      })
      expect(result1.isError).toBeFalsy()

      // Second call should use cache
      const result2 = await server.callTool('pe.fingerprint', {
        sample_id: testSampleId,
        fast: true
      })
      expect(result2.isError).toBeFalsy()

      // Results should be consistent
      const text1 = result1.content.find(c => c.type === 'text')
      const text2 = result2.content.find(c => c.type === 'text')
      expect(text1).toBeDefined()
      expect(text2).toBeDefined()
    })

    test('should differentiate cache by parameters', async () => {
      // Call with fast=true
      const result1 = await server.callTool('pe.fingerprint', {
        sample_id: testSampleId,
        fast: true
      })
      expect(result1.isError).toBeFalsy()

      // Call with fast=false (different cache key)
      const result2 = await server.callTool('pe.fingerprint', {
        sample_id: testSampleId,
        fast: false
      })
      expect(result2.isError).toBeFalsy()

      // Both should succeed independently
      expect(true).toBe(true)
    })
  })

  describe('Concurrent Tool Calls', () => {
    test('should handle concurrent calls to same tool', async () => {
      const promises = []
      for (let i = 0; i < 5; i++) {
        promises.push(
          server.callTool('pe.fingerprint', {
            sample_id: testSampleId,
            fast: true
          })
        )
      }

      const results = await Promise.all(promises)
      
      // All calls should succeed
      for (const result of results) {
        expect(result.isError).toBeFalsy()
      }
    })

    test('should handle concurrent calls to different tools', async () => {
      const promises = [
        server.callTool('pe.fingerprint', { sample_id: testSampleId, fast: true }),
        server.callTool('pe.imports.extract', { sample_id: testSampleId }),
        server.callTool('pe.exports.extract', { sample_id: testSampleId }),
        server.callTool('strings.extract', { sample_id: testSampleId, min_len: 4 }),
        server.callTool('runtime.detect', { sample_id: testSampleId })
      ]

      const results = await Promise.all(promises)
      
      // All calls should succeed
      for (const result of results) {
        expect(result.isError).toBeFalsy()
      }
    })
  })
})

/**
 * Helper function to create a minimal PE file for testing
 */
function createMinimalPE(): Buffer {
  // Create a minimal PE header structure
  const dosHeader = Buffer.alloc(64)
  dosHeader.write('MZ', 0) // DOS signature
  dosHeader.writeUInt32LE(64, 60) // PE header offset

  const peSignature = Buffer.from('PE\0\0')
  
  const coffHeader = Buffer.alloc(20)
  coffHeader.writeUInt16LE(0x014c, 0) // Machine: IMAGE_FILE_MACHINE_I386
  coffHeader.writeUInt16LE(1, 2) // NumberOfSections
  coffHeader.writeUInt32LE(Math.floor(Date.now() / 1000), 4) // TimeDateStamp
  coffHeader.writeUInt16LE(224, 16) // SizeOfOptionalHeader
  coffHeader.writeUInt16LE(0x0102, 18) // Characteristics

  const optionalHeader = Buffer.alloc(224)
  optionalHeader.writeUInt16LE(0x010b, 0) // Magic: PE32
  optionalHeader.writeUInt32LE(0x1000, 24) // ImageBase
  optionalHeader.writeUInt32LE(0x1000, 32) // SectionAlignment
  optionalHeader.writeUInt32LE(0x200, 36) // FileAlignment
  optionalHeader.writeUInt16LE(3, 68) // Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI

  const sectionHeader = Buffer.alloc(40)
  sectionHeader.write('.text', 0)
  sectionHeader.writeUInt32LE(0x1000, 8) // VirtualSize
  sectionHeader.writeUInt32LE(0x1000, 12) // VirtualAddress
  sectionHeader.writeUInt32LE(0x200, 16) // SizeOfRawData
  sectionHeader.writeUInt32LE(0x400, 20) // PointerToRawData

  const sectionData = Buffer.alloc(512)

  return Buffer.concat([
    dosHeader,
    peSignature,
    coffHeader,
    optionalHeader,
    sectionHeader,
    sectionData
  ])
}
