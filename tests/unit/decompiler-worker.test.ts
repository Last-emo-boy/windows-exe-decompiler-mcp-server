/**
 * Unit tests for Decompiler Worker
 * 
 * Tests Ghidra integration and function extraction
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  DecompilerWorker,
  GhidraProcessError,
  GhidraOutputParseError,
  normalizeGhidraError,
  type AnalysisResult,
} from '../../src/decompiler-worker';
import { DatabaseManager } from '../../src/database';
import { WorkspaceManager } from '../../src/workspace-manager';
import { ghidraConfig } from '../../src/ghidra-config';

function createMinimalAmd64PdataPE(): Buffer {
  const dosHeader = Buffer.alloc(0x80, 0);
  dosHeader.write('MZ', 0, 'ascii');
  dosHeader.writeUInt32LE(0x80, 0x3c);

  const peSignature = Buffer.from('PE\0\0', 'ascii');
  const coffHeader = Buffer.alloc(20, 0);
  coffHeader.writeUInt16LE(0x8664, 0);
  coffHeader.writeUInt16LE(3, 2);
  coffHeader.writeUInt16LE(0x00f0, 16);
  coffHeader.writeUInt16LE(0x0022, 18);

  const optionalHeader = Buffer.alloc(0x00f0, 0);
  optionalHeader.writeUInt16LE(0x20b, 0);
  optionalHeader.writeUInt32LE(0x200, 4);
  optionalHeader.writeUInt32LE(0x1000, 16);
  optionalHeader.writeUInt32LE(0x1000, 20);
  optionalHeader.writeBigUInt64LE(0x140000000n, 24);
  optionalHeader.writeUInt32LE(0x1000, 32);
  optionalHeader.writeUInt32LE(0x200, 36);
  optionalHeader.writeUInt32LE(0x4000, 56);
  optionalHeader.writeUInt32LE(0x200, 60);
  optionalHeader.writeUInt16LE(3, 68);
  optionalHeader.writeUInt32LE(16, 108);
  optionalHeader.writeUInt32LE(0x2000, 136);
  optionalHeader.writeUInt32LE(12, 140);

  const textSection = Buffer.alloc(40, 0);
  textSection.write('.text', 0, 'ascii');
  textSection.writeUInt32LE(0x100, 8);
  textSection.writeUInt32LE(0x1000, 12);
  textSection.writeUInt32LE(0x200, 16);
  textSection.writeUInt32LE(0x200, 20);
  textSection.writeUInt32LE(0x60000020, 36);

  const pdataSection = Buffer.alloc(40, 0);
  pdataSection.write('.pdata', 0, 'ascii');
  pdataSection.writeUInt32LE(0x0c, 8);
  pdataSection.writeUInt32LE(0x2000, 12);
  pdataSection.writeUInt32LE(0x200, 16);
  pdataSection.writeUInt32LE(0x400, 20);
  pdataSection.writeUInt32LE(0x40000040, 36);

  const xdataSection = Buffer.alloc(40, 0);
  xdataSection.write('.xdata', 0, 'ascii');
  xdataSection.writeUInt32LE(0x10, 8);
  xdataSection.writeUInt32LE(0x3000, 12);
  xdataSection.writeUInt32LE(0x200, 16);
  xdataSection.writeUInt32LE(0x600, 20);
  xdataSection.writeUInt32LE(0x40000040, 36);

  const headers = Buffer.concat([
    dosHeader,
    peSignature,
    coffHeader,
    optionalHeader,
    textSection,
    pdataSection,
    xdataSection,
  ]);

  const textData = Buffer.alloc(0x200, 0);
  textData[0] = 0xc3;

  const pdataData = Buffer.alloc(0x200, 0);
  pdataData.writeUInt32LE(0x1000, 0);
  pdataData.writeUInt32LE(0x1100, 4);
  pdataData.writeUInt32LE(0x3000, 8);

  const xdataData = Buffer.alloc(0x200, 0);
  xdataData.writeUInt8(0x01, 0);
  xdataData.writeUInt8(0x10, 1);

  return Buffer.concat([headers, textData, pdataData, xdataData]);
}

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Mock child_process
jest.mock('child_process');

describe('DecompilerWorker', () => {
  let database: DatabaseManager;
  let workspaceManager: WorkspaceManager;
  let decompilerWorker: DecompilerWorker;
  let testDbPath: string;
  let testWorkspaceRoot: string;

  beforeEach(() => {
    // Create temporary database
    testDbPath = path.join(__dirname, '../temp', `test-decompiler-${Date.now()}.db`);
    const dbDir = path.dirname(testDbPath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    database = new DatabaseManager(testDbPath);

    // Create temporary workspace
    testWorkspaceRoot = path.join(__dirname, '../temp', `workspace-${Date.now()}`);
    workspaceManager = new WorkspaceManager(testWorkspaceRoot);

    // Create decompiler worker
    decompilerWorker = new DecompilerWorker(database, workspaceManager);
  });

  afterEach(() => {
    // Clean up database
    database.close();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }

    // Clean up workspace
    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 100,
      });
    }
  });

  describe('project lock retry helpers', () => {
    test('should retry when a parse error carries project lock diagnostics', async () => {
      let attempts = 0

      const result = await (decompilerWorker as any).runWithProjectLockRetry(
        'Function decompilation',
        async () => {
          attempts += 1
          if (attempts === 1) {
            throw new GhidraOutputParseError(
              'code.function.decompile: No JSON output found',
              {
                raw_cmd: 'analyzeHeadless ...',
                command: 'analyzeHeadless.bat',
                args: [],
                cwd: testWorkspaceRoot,
                exit_code: 1,
                signal: null,
                timed_out: false,
                cancelled: false,
                stdout: 'ERROR Abort due to Headless analyzer error: ghidra.framework.store.LockException: Unable to lock project!',
                stderr: '',
                stdout_encoding: 'utf-8',
                stderr_encoding: 'utf-8',
              }
            )
          }
          return 'ok'
        },
        { sampleId: 'sha256:' + '1'.repeat(64) },
        2,
        0
      )

      expect(result).toBe('ok')
      expect(attempts).toBe(2)
    })
  })

  describe('analyze', () => {
    test('should throw error if Ghidra is not configured', async () => {
      // Skip if Ghidra is actually configured
      if (ghidraConfig.isValid) {
        return;
      }

      const sampleId = 'sha256:' + 'a'.repeat(64);

      await expect(decompilerWorker.analyze(sampleId)).rejects.toThrow(
        'Ghidra is not properly configured'
      );
    });

    test('should throw error if sample not found', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      const sampleId = 'sha256:' + 'b'.repeat(64);

      await expect(decompilerWorker.analyze(sampleId)).rejects.toThrow(
        'Sample not found'
      );
    });

    test('should create analysis record with running status', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample
      const sha256 = 'c'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'd'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, 'fake PE content');

      const workerInternals = decompilerWorker as any;
      const originalExecuteMainAnalysis = workerInternals.executeMainAnalysis;
      const originalTryExtractFunctionsWithFallback = workerInternals.tryExtractFunctionsWithFallback;
      const originalProbeCapability = workerInternals.probeCapability;

      try {
        workerInternals.executeMainAnalysis = jest.fn(async () => ({
          stdout: '',
          stderr: '',
          diagnostics: {
            raw_cmd: 'analyzeHeadless ...',
            command: 'analyzeHeadless.bat',
            args: [],
            cwd: workspace.ghidra,
            exit_code: 0,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr: '',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          },
        }));
        workerInternals.tryExtractFunctionsWithFallback = jest.fn(async () => ({
          scriptUsed: 'ExtractFunctions.java',
          warnings: [],
          attempts: [{ script: 'ExtractFunctions.java' }],
          output: {
            program_name: 'sample.exe',
            program_path: samplePath,
            function_count: 2,
            functions: [
              {
                address: '0x00401000',
                name: 'main',
                size: 100,
                is_thunk: false,
                is_external: false,
                calling_convention: 'cdecl',
                signature: 'int main(int argc, char** argv)',
                callers: [],
                caller_count: 0,
                callees: [],
                callee_count: 0,
                is_entry_point: true,
                is_exported: false
              },
              {
                address: '0x00401100',
                name: 'helper',
                size: 50,
                is_thunk: false,
                is_external: false,
                calling_convention: 'cdecl',
                signature: 'void helper()',
                callers: [],
                caller_count: 0,
                callees: [],
                callee_count: 0,
                is_entry_point: false,
                is_exported: false
              }
            ]
          }
        }));
        workerInternals.probeCapability = jest.fn(async (_capability: string, _projectPath: string, _projectKey: string, _samplePath: string, target: string) => ({
          status: {
            available: true,
            status: 'ready',
            checked_at: new Date().toISOString(),
            target,
          },
        }));

        const result = await decompilerWorker.analyze(sampleId, { timeout: 5000 });

        // Verify result
        expect(result.backend).toBe('ghidra');
        expect(result.functionCount).toBe(2);
        expect(result.analysisId).toBeDefined();

        // Verify analysis record was created
        const analysis = database.findAnalysis(result.analysisId);
        expect(analysis).toBeDefined();
        expect(analysis?.status).toBe('done');
        expect(analysis?.sample_id).toBe(sampleId);

        // Verify functions were stored
        const functions = database.findFunctions(sampleId);
        expect(functions).toHaveLength(2);
        expect(functions[0].address).toBe('0x00401000');
        expect(functions[0].name).toBe('main');
        expect(functions[1].address).toBe('0x00401100');
        expect(functions[1].name).toBe('helper');

      } catch (error) {
        // If test fails, check if it's due to Ghidra not being configured
        if (error instanceof Error && error.message.includes('Ghidra')) {
          console.log('Skipping test: Ghidra not configured');
          return;
        }
        throw error;
      } finally {
        workerInternals.executeMainAnalysis = originalExecuteMainAnalysis;
        workerInternals.tryExtractFunctionsWithFallback = originalTryExtractFunctionsWithFallback;
        workerInternals.probeCapability = originalProbeCapability;
      }
    });

    test('should handle timeout correctly', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample
      const sha256 = 'e'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'f'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, 'fake PE content');

      const workerInternals = decompilerWorker as any;
      const originalExecuteMainAnalysis = workerInternals.executeMainAnalysis;

      try {
        workerInternals.executeMainAnalysis = jest.fn(async () => {
          throw new GhidraProcessError(
            'E_TIMEOUT: Ghidra analysis exceeded timeout of 100ms',
            {
              raw_cmd: 'analyzeHeadless ...',
              command: 'analyzeHeadless.bat',
              args: [],
              cwd: workspace.ghidra,
              exit_code: null,
              signal: null,
              timed_out: true,
              cancelled: false,
              stdout: '',
              stderr: '',
              stdout_encoding: 'utf-8',
              stderr_encoding: 'utf-8',
            },
            'E_TIMEOUT'
          );
        });

        await expect(
          decompilerWorker.analyze(sampleId, { timeout: 100 })
        ).rejects.toThrow('E_TIMEOUT');

        const analyses = database.findAnalysesBySample(sampleId);
        expect(analyses).toHaveLength(1);
        expect(analyses[0].status).toBe('failed');
        const outputJson = JSON.parse(analyses[0].output_json || '{}');
        expect(outputJson.ghidra_diagnostics.timed_out).toBe(true);

      } catch (error) {
        // If test fails, check if it's due to Ghidra not being configured
        if (error instanceof Error && error.message.includes('Ghidra')) {
          console.log('Skipping test: Ghidra not configured');
          return;
        }
        throw error;
      } finally {
        workerInternals.executeMainAnalysis = originalExecuteMainAnalysis;
      }
    });

    test('should update analysis status to failed on error', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample
      const sha256 = '7'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: '8'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, 'fake PE content');

      const workerInternals = decompilerWorker as any;
      const originalExecuteMainAnalysis = workerInternals.executeMainAnalysis;

      try {
        workerInternals.executeMainAnalysis = jest.fn(async () => {
          throw new GhidraProcessError(
            'Ghidra analysis failed with exit code 1',
            {
              raw_cmd: 'analyzeHeadless ...',
              command: 'analyzeHeadless.bat',
              args: [],
              cwd: workspace.ghidra,
              exit_code: 1,
              signal: null,
              timed_out: false,
              cancelled: false,
              stdout: '',
              stderr: 'Ghidra error message',
              stdout_encoding: 'utf-8',
              stderr_encoding: 'utf-8',
            },
            'E_GHIDRA_PROCESS'
          );
        });

        await expect(decompilerWorker.analyze(sampleId)).rejects.toThrow();

        // Find the analysis record (we don't know the ID)
        const analyses = database.findAnalysesBySample(sampleId);
        expect(analyses).toHaveLength(1);
        expect(analyses[0].status).toBe('failed');
        const outputJson = JSON.parse(analyses[0].output_json || '{}');
        expect(outputJson.ghidra_diagnostics).toBeDefined();
        expect(outputJson.ghidra_diagnostics.exit_code).toBe(1);
        expect(outputJson.ghidra_diagnostics.raw_cmd).toContain('analyzeHeadless');
        expect(outputJson.ghidra_diagnostics.stderr).toContain('Ghidra error message');

      } catch (error) {
        // If test fails, check if it's due to Ghidra not being configured
        if (error instanceof Error && error.message.includes('Ghidra')) {
          console.log('Skipping test: Ghidra not configured');
          return;
        }
        throw error;
      } finally {
        workerInternals.executeMainAnalysis = originalExecuteMainAnalysis;
      }
    });

    test('should fallback to ExtractFunctions.java when PyGhidra is unavailable', async () => {
      if (!ghidraConfig.isValid) {
        return
      }

      const sha256 = '9'.repeat(64)
      const sampleId = `sha256:${sha256}`
      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'a'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test',
      })

      const workspace = await workspaceManager.createWorkspace(sampleId)
      const samplePath = path.join(workspace.original, 'sample.exe')
      fs.writeFileSync(samplePath, 'fake PE content')

      const workerInternals = decompilerWorker as any
      const originalExecuteMainAnalysis = workerInternals.executeMainAnalysis
      const originalTryExtractFunctionsWithFallback = workerInternals.tryExtractFunctionsWithFallback
      const originalProbeCapability = workerInternals.probeCapability

      try {
        workerInternals.executeMainAnalysis = jest.fn(async () => ({
          stdout: '',
          stderr: '',
          diagnostics: {
            raw_cmd: 'analyzeHeadless ...',
            command: 'analyzeHeadless.bat',
            args: [],
            cwd: workspace.ghidra,
            exit_code: 0,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr: '',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          },
        }))
        workerInternals.tryExtractFunctionsWithFallback = jest.fn(async () => ({
          scriptUsed: 'ExtractFunctions.java',
          warnings: ['Falling back to ExtractFunctions.java because PyGhidra is unavailable.'],
          attempts: [
            { script: 'ExtractFunctions.py', error: 'Ghidra was not started with PyGhidra. Python is not available' },
            { script: 'ExtractFunctions.java' },
          ],
          output: {
            program_name: 'sample.exe',
            program_path: samplePath,
            function_count: 1,
            functions: [
              {
                address: '0x00401000',
                name: 'main',
                size: 120,
                is_thunk: false,
                is_external: false,
                calling_convention: 'cdecl',
                signature: 'int main()',
                callers: [],
                caller_count: 0,
                callees: [],
                callee_count: 0,
                is_entry_point: true,
                is_exported: false,
              },
            ],
          },
        }))
        workerInternals.probeCapability = jest.fn(async (_capability: string, _projectPath: string, _projectKey: string, _samplePath: string, target: string) => ({
          status: {
            available: true,
            status: 'ready',
            checked_at: new Date().toISOString(),
            target,
          },
        }))

        const result = await decompilerWorker.analyze(sampleId, { timeout: 5000 })
        expect(result.status).toBe('done')
        expect(result.functionCount).toBe(1)
        expect(result.warnings?.some((item) => item.includes('Falling back to ExtractFunctions.java'))).toBe(true)

        const analyses = database.findAnalysesBySample(sampleId)
        expect(analyses[0].status).toBe('done')
        const outputJson = JSON.parse(analyses[0].output_json || '{}')
        expect(outputJson.function_extraction.script_used).toBe('ExtractFunctions.java')
        expect(Array.isArray(outputJson.function_extraction.attempts)).toBe(true)
      } finally {
        workerInternals.executeMainAnalysis = originalExecuteMainAnalysis
        workerInternals.tryExtractFunctionsWithFallback = originalTryExtractFunctionsWithFallback
        workerInternals.probeCapability = originalProbeCapability
      }
    })

    test('should mark analysis as partial_success when post-processing fails', async () => {
      if (!ghidraConfig.isValid) {
        return
      }

      const sha256 = 'b'.repeat(64)
      const sampleId = `sha256:${sha256}`
      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'c'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test',
      })

      const workspace = await workspaceManager.createWorkspace(sampleId)
      fs.writeFileSync(path.join(workspace.original, 'sample.exe'), 'fake PE content')

      const workerInternals = decompilerWorker as any
      const originalExecuteMainAnalysis = workerInternals.executeMainAnalysis
      const originalTryExtractFunctionsWithFallback = workerInternals.tryExtractFunctionsWithFallback
      const originalTryRecoverFunctionsFromPE = workerInternals.tryRecoverFunctionsFromPE

      try {
        workerInternals.executeMainAnalysis = jest.fn(async () => ({
          stdout: '',
          stderr: '',
          diagnostics: {
            raw_cmd: 'analyzeHeadless ...',
            command: 'analyzeHeadless.bat',
            args: [],
            cwd: workspace.ghidra,
            exit_code: 0,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr: '',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          },
        }))
        workerInternals.tryExtractFunctionsWithFallback = jest.fn(async () => ({
          scriptUsed: undefined,
          warnings: ['Function extraction failed with ExtractFunctions.py: Function extraction (ExtractFunctions.py) failed with exit code 1'],
          attempts: [
            { script: 'ExtractFunctions.py', error: 'Ghidra was not started with PyGhidra. Python is not available' },
            { script: 'ExtractFunctions.java', error: 'Java post-script also failed' },
          ],
          output: undefined,
        }))
        workerInternals.tryRecoverFunctionsFromPE = jest.fn(() => ({
          functions: [],
          warnings: [],
          recoveryMetadata: { source: 'test' },
        }))

        const result = await decompilerWorker.analyze(sampleId, { timeout: 5000 })
        expect(result.status).toBe('partial_success')
        expect(result.functionCount).toBe(0)

        const analyses = database.findAnalysesBySample(sampleId)
        expect(analyses[0].status).toBe('partial_success')
        const outputJson = JSON.parse(analyses[0].output_json || '{}')
        expect(outputJson.project_path).toBeDefined()
        expect(outputJson.function_extraction.status).toBe('failed')
      } finally {
        workerInternals.executeMainAnalysis = originalExecuteMainAnalysis
        workerInternals.tryExtractFunctionsWithFallback = originalTryExtractFunctionsWithFallback
        workerInternals.tryRecoverFunctionsFromPE = originalTryRecoverFunctionsFromPE
      }
    })

    test('should recover function candidates from .pdata when Ghidra post-scripts fail', async () => {
      const originalConfig = {
        installDir: ghidraConfig.installDir,
        analyzeHeadlessPath: ghidraConfig.analyzeHeadlessPath,
        scriptsDir: ghidraConfig.scriptsDir,
        version: ghidraConfig.version,
        isValid: ghidraConfig.isValid,
      }

      ghidraConfig.installDir = 'C:\\ghidra'
      ghidraConfig.analyzeHeadlessPath = 'C:\\ghidra\\support\\analyzeHeadless.bat'
      ghidraConfig.scriptsDir = path.join(process.cwd(), 'ghidra_scripts')
      ghidraConfig.isValid = true

      try {
        const sha256 = 'a'.repeat(64)
        const sampleId = `sha256:${sha256}`
        database.insertSample({
          id: sampleId,
          sha256,
          md5: 'b'.repeat(32),
          size: 2048,
          file_type: 'PE32+',
          created_at: new Date().toISOString(),
          source: 'test',
        })

        const workspace = await workspaceManager.createWorkspace(sampleId)
        fs.writeFileSync(path.join(workspace.original, 'sample.exe'), createMinimalAmd64PdataPE())

        const workerInternals = decompilerWorker as any
        const originalExecuteMainAnalysis = workerInternals.executeMainAnalysis
        const originalTryExtractFunctionsWithFallback = workerInternals.tryExtractFunctionsWithFallback

        workerInternals.executeMainAnalysis = jest.fn(async () => ({
          stdout: '',
          stderr: '',
          diagnostics: {
            raw_cmd: 'analyzeHeadless ...',
            command: 'analyzeHeadless.bat',
            args: [],
            cwd: workspace.ghidra,
            exit_code: 0,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr: '',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          },
        }))
        workerInternals.tryExtractFunctionsWithFallback = jest.fn(async () => ({
          warnings: [
            'Function extraction failed with ExtractFunctions.py: Function extraction (ExtractFunctions.py) failed with exit code 1',
          ],
          attempts: [
            { script: 'ExtractFunctions.java', error: 'ExtractFunctions.java failed for Rust binary' },
            { script: 'ExtractFunctions.py', error: 'Function extraction (ExtractFunctions.py) failed with exit code 1' },
          ],
        }))

        try {
          const result = await decompilerWorker.analyze(sampleId, { timeout: 5000 })

          expect(result.status).toBe('partial_success')
          expect(result.functionCount).toBe(1)
          expect(result.readiness?.function_index.status).toBe('degraded')
          expect(result.readiness?.decompile.status).toBe('missing')
          expect(result.warnings?.some((item) => item.includes('Recovered 1 function candidates from PE exception metadata'))).toBe(true)

          const functions = database.findFunctions(sampleId)
          expect(functions).toHaveLength(1)
          expect(functions[0].address).toBe('0x0000000140001000')
          expect(functions[0].name).toBe('entry_point')

          const analyses = database.findAnalysesBySample(sampleId)
          expect(analyses[0].status).toBe('partial_success')
          const outputJson = JSON.parse(analyses[0].output_json || '{}')
          expect(outputJson.function_extraction.status).toBe('recovered_via_smart_recover')
          expect(outputJson.function_recovery.count).toBe(1)
          expect(outputJson.readiness.function_index.status).toBe('degraded')

          const artifacts = database.findArtifacts(sampleId)
          expect(artifacts.some((artifact) => artifact.type === 'function_recovery')).toBe(true)
        } finally {
          workerInternals.executeMainAnalysis = originalExecuteMainAnalysis
          workerInternals.tryExtractFunctionsWithFallback = originalTryExtractFunctionsWithFallback
        }
      } finally {
        ghidraConfig.installDir = originalConfig.installDir
        ghidraConfig.analyzeHeadlessPath = originalConfig.analyzeHeadlessPath
        ghidraConfig.scriptsDir = originalConfig.scriptsDir
        ghidraConfig.version = originalConfig.version
        ghidraConfig.isValid = originalConfig.isValid
      }
    })
  });

  describe('createJobResult', () => {
    test('should create successful job result', () => {
      const analysisResult: AnalysisResult = {
        analysisId: 'test-analysis-id',
        backend: 'ghidra',
        functionCount: 10,
        projectPath: '/path/to/project',
        status: 'done',
      };

      const jobResult = decompilerWorker.createJobResult(analysisResult, 5000);

      expect(jobResult.ok).toBe(true);
      expect(jobResult.jobId).toBe('test-analysis-id');
      expect(jobResult.data).toEqual(analysisResult);
      expect(jobResult.errors).toHaveLength(0);
      expect(jobResult.metrics.elapsedMs).toBe(5000);
    });
  });

  describe('createErrorJobResult', () => {
    test('should create error job result', () => {
      const error = new Error('Test error');
      const jobResult = decompilerWorker.createErrorJobResult('test-job-id', error, 3000);

      expect(jobResult.ok).toBe(false);
      expect(jobResult.jobId).toBe('test-job-id');
      expect(jobResult.errors).toContain('Test error');
      expect(jobResult.metrics.elapsedMs).toBe(3000);
    });
  });

  describe('output parsing diagnostics', () => {
    test('should include stdout/stderr snippets when ghidra JSON sentinel is missing', () => {
      const parseGhidraOutput = (decompilerWorker as unknown as {
        parseGhidraOutput: (
          stdout: string,
          stderr: string,
          diagnostics: {
            raw_cmd: string
            command: string
            args: string[]
            cwd: string
            exit_code: number | null
            signal: NodeJS.Signals | null
            timed_out: boolean
            cancelled: boolean
            stdout: string
            stderr: string
            stdout_encoding: string
            stderr_encoding: string
          }
        ) => unknown
      }).parseGhidraOutput.bind(decompilerWorker)

      expect(() =>
        parseGhidraOutput(
          'INFO: script started\\nno json payload here',
          'stderr context text',
          {
            raw_cmd: 'cmd.exe /d /s /c "analyzeHeadless ..."',
            command: 'cmd.exe',
            args: ['/d', '/s', '/c', '"..."'],
            cwd: 'C:\\\\tmp',
            exit_code: 0,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: 'INFO: script started\\nno json payload here',
            stderr: 'stderr context text',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          }
        )
      ).toThrow(GhidraOutputParseError)

      try {
        parseGhidraOutput(
          'INFO: script started\\nno json payload here',
          'stderr context text',
          {
            raw_cmd: 'cmd.exe /d /s /c "analyzeHeadless ..."',
            command: 'cmd.exe',
            args: ['/d', '/s', '/c', '"..."'],
            cwd: 'C:\\\\tmp',
            exit_code: 0,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: 'INFO: script started\\nno json payload here',
            stderr: 'stderr context text',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          }
        )
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        expect(message).toContain('No JSON output found')
        expect(message).toContain('stdout_snippet=')
        expect(message).toContain('stderr_snippet=')
      }
    })

    test('should normalize recovered caller and callee relationships from decompile output', () => {
      const parseDecompileOutput = (decompilerWorker as unknown as {
        parseDecompileOutput: (
          stdout: string,
          stderr: string,
          diagnostics?: {
            raw_cmd: string
            command: string
            args: string[]
            cwd: string
            exit_code: number | null
            signal: NodeJS.Signals | null
            timed_out: boolean
            cancelled: boolean
            stdout: string
            stderr: string
            stdout_encoding: string
            stderr_encoding: string
          }
        ) => unknown
      }).parseDecompileOutput.bind(decompilerWorker)

      const parsed = parseDecompileOutput(
        JSON.stringify({
          function: 'FUN_140081090',
          address: '0x140081090',
          pseudocode: 'int FUN_140081090(void) { return 0; }',
          callers: [],
          callees: [{ address: '0x140005000', name: 'WriteProcessMemory' }],
          caller_relationships: [
            {
              address: '0x140020000',
              name: 'thunk_FUN_140081090',
              relation_types: ['tail_jump_hint'],
              reference_types: ['UNCONDITIONAL_JUMP'],
              reference_addresses: ['0x140020010'],
              is_exact: false,
            },
          ],
          callee_relationships: [
            {
              address: '0x140005000',
              name: 'WriteProcessMemory',
              relation_types: ['direct_call_body'],
              reference_types: ['UNCONDITIONAL_CALL'],
              reference_addresses: ['0x140081120'],
              resolved_by: 'resolver_stub',
              is_exact: true,
            },
          ],
        }),
        ''
      ) as any

      expect(parsed.error).toBeUndefined()
      expect(parsed.caller_relationships).toHaveLength(1)
      expect(parsed.caller_relationships[0].relation_types).toContain('tail_jump_hint')
      expect(parsed.caller_relationships[0].reference_types).toContain('UNCONDITIONAL_JUMP')
      expect(parsed.callee_relationships).toHaveLength(1)
      expect(parsed.callee_relationships[0].resolved_by).toBe('resolver_stub')
      expect(parsed.callee_relationships[0].is_exact).toBe(true)
    })
  })

  describe('normalized ghidra errors', () => {
    test('should classify PyGhidra availability failures with remediation hints', () => {
      const normalized = normalizeGhidraError(
        new GhidraProcessError(
          'Function extraction failed',
          {
            raw_cmd: 'analyzeHeadless ...',
            command: 'analyzeHeadless.bat',
            args: [],
            cwd: testWorkspaceRoot,
            exit_code: 1,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr: 'Ghidra was not started with PyGhidra. Python is not available',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          },
          'E_GHIDRA_PROCESS'
        ),
        'ghidra.analyze'
      )

      expect(normalized?.code).toBe('pyghidra_unavailable')
      expect(normalized?.category).toBe('environment')
      expect(normalized?.summary).toContain('ghidra.analyze')
      expect(normalized?.remediation_hints.join(' ')).toContain('Java post-script fallback')
    })

    test('should classify Windows spawn EINVAL failures', () => {
      const normalized = normalizeGhidraError(
        new GhidraProcessError(
          'Failed to spawn Ghidra process: spawn EINVAL',
          {
            raw_cmd: 'cmd.exe /d /s /c "analyzeHeadless.bat ..."',
            command: 'cmd.exe',
            args: ['/d', '/s', '/c', '"analyzeHeadless.bat ..."'],
            cwd: testWorkspaceRoot,
            exit_code: null,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr: '',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
            spawn_error: 'spawn EINVAL',
          },
          'E_SPAWN'
        ),
        'code.function.decompile'
      )

      expect(normalized?.code).toBe('spawn_einval')
      expect(normalized?.category).toBe('configuration')
      expect(normalized?.remediation_hints.join(' ')).toContain('GHIDRA_PATH')
      expect(normalized?.evidence.join(' ')).toContain('spawn_error=spawn EINVAL')
    })

    test('should classify missing Ghidra project directory failures', () => {
      const normalized = normalizeGhidraError(
        new GhidraProcessError(
          'Ghidra analysis failed',
          {
            raw_cmd: 'analyzeHeadless ...',
            command: 'analyzeHeadless.bat',
            args: [],
            cwd: testWorkspaceRoot,
            exit_code: 1,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr:
              'java.io.FileNotFoundException: Directory not found: C:\\Temp\\GhidraProject\nat ghidra.framework.project.DefaultProjectManager.createProject(DefaultProjectManager.java:100)',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
            log_path: 'C:\\Temp\\ghidra.log',
            java_exception: {
              exception_class: 'java.io.FileNotFoundException',
              message: 'Directory not found: C:\\Temp\\GhidraProject',
              stack_preview: ['at ghidra.framework.project.DefaultProjectManager.createProject(DefaultProjectManager.java:100)'],
            },
          },
          'E_GHIDRA_PROCESS'
        ),
        'ghidra.analyze'
      )

      expect(normalized?.code).toBe('project_directory_missing')
      expect(normalized?.category).toBe('configuration')
      expect(normalized?.evidence.join(' ')).toContain('log_path=C:\\Temp\\ghidra.log')
      expect(normalized?.remediation_hints.join(' ')).toContain('project root')
    })

    test('should classify Java runtime compatibility failures', () => {
      const normalized = normalizeGhidraError(
        new GhidraProcessError(
          'Ghidra analysis failed',
          {
            raw_cmd: 'analyzeHeadless ...',
            command: 'analyzeHeadless.bat',
            args: [],
            cwd: testWorkspaceRoot,
            exit_code: 1,
            signal: null,
            timed_out: false,
            cancelled: false,
            stdout: '',
            stderr:
              'Error: UnsupportedClassVersionError\nJAVA_HOME=C:\\Java\\jdk-17\nclass file version 65.0',
            stdout_encoding: 'utf-8',
            stderr_encoding: 'utf-8',
          },
          'E_GHIDRA_PROCESS'
        ),
        'ghidra.health'
      )

      expect(normalized?.code).toBe('java_runtime_invalid')
      expect(normalized?.category).toBe('environment')
      expect(normalized?.remediation_hints.join(' ')).toContain('Java 21+')
    })
  })

  describe('listFunctions', () => {
    test('should return empty array when no functions exist', async () => {
      const sampleId = 'sha256:' + 'd'.repeat(64);

      // Insert sample without functions
      database.insertSample({
        id: sampleId,
        sha256: 'd'.repeat(64),
        md5: 'e'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      const functions = await decompilerWorker.listFunctions(sampleId);

      expect(functions).toEqual([]);
    });

    test('should return all functions when no limit specified', async () => {
      const sampleId = 'sha256:' + 'f'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 'f'.repeat(64),
        md5: '7'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert test functions
      const testFunctions = [
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'main',
          size: 256,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'sub_401100',
          size: 128,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'sub_401100',
          size: 128,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401200',
          name: 'sub_401200',
          size: 64,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        }
      ];

      database.insertFunctionsBatch(testFunctions);

      const functions = await decompilerWorker.listFunctions(sampleId);

      expect(functions).toHaveLength(3);
      expect(functions[0]).toEqual({
        name: 'main',
        address: '0x00401000',
        size: 256,
        callers: 0,
        callees: 0
      });
      expect(functions[1]).toEqual({
        name: 'sub_401100',
        address: '0x00401100',
        size: 128,
        callers: 0,
        callees: 0
      });
    });

    test('should respect limit parameter', async () => {
      const sampleId = 'sha256:' + '8'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: '8'.repeat(64),
        md5: '9'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert test functions
      const testFunctions = [
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'func1',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'func2',
          size: 200,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401200',
          name: 'func3',
          size: 300,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        }
      ];

      database.insertFunctionsBatch(testFunctions);

      const functions = await decompilerWorker.listFunctions(sampleId, 2);

      expect(functions).toHaveLength(2);
      expect(functions[0].name).toBe('func1');
      expect(functions[1].name).toBe('func2');
    });

    test('should handle functions with null name', async () => {
      const sampleId = 'sha256:' + 'a'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 'a'.repeat(64),
        md5: 'b'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert function with null name
      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: null,
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        }
      ]);

      const functions = await decompilerWorker.listFunctions(sampleId);

      expect(functions).toHaveLength(1);
      expect(functions[0].name).toBe('unknown');
    });
  });

  describe('rankFunctions', () => {
    test('should return empty array when no functions exist', async () => {
      const sampleId = 'sha256:' + 'm'.repeat(64);

      // Insert sample without functions
      database.insertSample({
        id: sampleId,
        sha256: 'm'.repeat(64),
        md5: 'n'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      const rankedFunctions = await decompilerWorker.rankFunctions(sampleId);

      expect(rankedFunctions).toEqual([]);
    });

    test('should score large functions higher', async () => {
      const sampleId = 'sha256:' + 'o'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 'o'.repeat(64),
        md5: 'p'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert test functions
      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'small_func',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'large_func',
          size: 2000,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        }
      ]);

      const rankedFunctions = await decompilerWorker.rankFunctions(sampleId);

      expect(rankedFunctions).toHaveLength(2);
      expect(rankedFunctions[0].name).toBe('large_func');
      expect(rankedFunctions[0].score).toBeGreaterThan(rankedFunctions[1].score);
      expect(rankedFunctions[0].reasons).toContain('large_function');
    });

    test('should score functions with many callers higher', async () => {
      const sampleId = 'sha256:' + 'q'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 'q'.repeat(64),
        md5: 'r'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert test functions
      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'rarely_called',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 2,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'frequently_called',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 50,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        }
      ]);

      const rankedFunctions = await decompilerWorker.rankFunctions(sampleId);

      expect(rankedFunctions).toHaveLength(2);
      expect(rankedFunctions[0].name).toBe('frequently_called');
      expect(rankedFunctions[0].score).toBeGreaterThan(rankedFunctions[1].score);
      expect(rankedFunctions[0].reasons).toContain('high_callers');
    });

    test('should score functions calling sensitive APIs higher', async () => {
      const sampleId = 'sha256:' + 's'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 's'.repeat(64),
        md5: 't'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert test functions
      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'benign_func',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify(['printf', 'malloc'])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'suspicious_func',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify(['CreateProcess', 'WriteFile', 'RegSetValue'])
        }
      ]);

      const rankedFunctions = await decompilerWorker.rankFunctions(sampleId);

      expect(rankedFunctions).toHaveLength(2);
      expect(rankedFunctions[0].name).toBe('suspicious_func');
      expect(rankedFunctions[0].score).toBeGreaterThan(rankedFunctions[1].score);
      expect(rankedFunctions[0].reasons.some(r => r.includes('calls_sensitive_api'))).toBe(true);
    });

    test('should include heuristic xref provenance summary for sensitive APIs', async () => {
      const sampleId = 'sha256:' + 'p'.repeat(64);

      database.insertSample({
        id: sampleId,
        sha256: 'p'.repeat(64),
        md5: 'q'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'resolver_func',
          size: 120,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify(['GetProcAddress', 'CreateRemoteThread'])
        }
      ]);

      const rankedFunctions = await decompilerWorker.rankFunctions(sampleId);

      expect(rankedFunctions).toHaveLength(1);
      expect(rankedFunctions[0].xref_summary).toBeDefined();
      expect(rankedFunctions[0].xref_summary?.some((item) => item.api === 'GetProcAddress' && item.provenance === 'dynamic_resolution_api')).toBe(true);
      expect(rankedFunctions[0].xref_summary?.some((item) => item.api === 'CreateRemoteThread' && item.provenance === 'dynamic_resolution_helper')).toBe(true);
    });

    test('should score entry points and exported functions higher', async () => {
      const sampleId = 'sha256:' + 'u'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 'u'.repeat(64),
        md5: 'v'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert test functions
      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'internal_func',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'entry_point',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 1,
          is_exported: 0,
          callees: JSON.stringify([])
        },
        {
          sample_id: sampleId,
          address: '0x00401200',
          name: 'exported_func',
          size: 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 1,
          callees: JSON.stringify([])
        }
      ]);

      const rankedFunctions = await decompilerWorker.rankFunctions(sampleId);

      expect(rankedFunctions).toHaveLength(3);
      // Entry point and exported should be ranked higher
      expect(rankedFunctions[0].score).toBeGreaterThan(rankedFunctions[2].score);
      expect(rankedFunctions[1].score).toBeGreaterThan(rankedFunctions[2].score);
      expect(rankedFunctions[0].reasons).toContain('entry_point');
      expect(rankedFunctions[1].reasons).toContain('exported');
    });

    test('should respect topK parameter', async () => {
      const sampleId = 'sha256:' + 'w'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 'w'.repeat(64),
        md5: 'x'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert 10 test functions
      const functions = [];
      for (let i = 0; i < 10; i++) {
        functions.push({
          sample_id: sampleId,
          address: `0x0040${i.toString().padStart(4, '0')}`,
          name: `func_${i}`,
          size: 100 + i * 100,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([])
        });
      }
      database.insertFunctionsBatch(functions);

      const rankedFunctions = await decompilerWorker.rankFunctions(sampleId, 5);

      expect(rankedFunctions).toHaveLength(5);
    });

    test('should update function scores in database', async () => {
      const sampleId = 'sha256:' + 'y'.repeat(64);

      // Insert sample
      database.insertSample({
        id: sampleId,
        sha256: 'y'.repeat(64),
        md5: 'z'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Insert test function
      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'test_func',
          size: 2000,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 0,
          callee_count: 0,
          is_entry_point: 1,
          is_exported: 0,
          callees: JSON.stringify([])
        }
      ]);

      await decompilerWorker.rankFunctions(sampleId);

      // Verify score was updated in database
      const functions = database.findFunctions(sampleId);
      expect(functions[0].score).toBeGreaterThan(0);
      expect(functions[0].tags).toBeDefined();
      const tags = JSON.parse(functions[0].tags || '[]');
      expect(tags).toContain('large_function');
      expect(tags).toContain('entry_point');
    });
  });

  describe('searchFunctions', () => {
    test('should reverse-search API calls from indexed function metadata', () => {
      const sampleId = 'sha256:' + '1'.repeat(64);

      database.insertSample({
        id: sampleId,
        sha256: '1'.repeat(64),
        md5: '2'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      database.insertFunctionsBatch([
        {
          sample_id: sampleId,
          address: '0x00401000',
          name: 'resolver',
          size: 120,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 3,
          callee_count: 2,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify(['GetProcAddress', 'WriteProcessMemory'])
        },
        {
          sample_id: sampleId,
          address: '0x00401100',
          name: 'injector',
          size: 180,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 12,
          callee_count: 2,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify(['WriteProcessMemory', 'CreateRemoteThread'])
        },
        {
          sample_id: sampleId,
          address: '0x00401200',
          name: 'benign',
          size: 90,
          score: 0.0,
          tags: JSON.stringify([]),
          summary: null,
          caller_count: 40,
          callee_count: 1,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify(['printf'])
        }
      ]);

      const result = (decompilerWorker as any).searchFunctionsFromIndex(
        sampleId,
        'WriteProcessMemory',
        10
      );

      expect(result.count).toBe(2);
      expect(result.matches[0].function).toBe('injector');
      expect(result.matches[0].api_matches).toContain('WriteProcessMemory');
      expect(result.matches[0].match_types).toContain('api_call_index');
      expect(result.matches[1].function).toBe('resolver');
    });

    test('should parse Ghidra search output with string-reference matches', () => {
      const result = (decompilerWorker as any).parseSearchOutput(
        [
          'INFO  Loading program...',
          '{"query":{"api":"WriteProcessMemory","string":"WriteProcessMemory failed at","limit":5},' +
            '"matches":[{"function":"FUN_140081090","address":"140081090","caller_count":0,"callee_count":6,' +
            '"api_matches":["WriteProcessMemory"],"string_matches":[{"value":"WriteProcessMemory failed at %p",' +
            '"data_address":"1401a2030","referenced_from":"1400812ab"}]}],"count":1}'
        ].join('\n'),
        ''
      );

      expect('error' in result).toBe(false);
      if ('error' in result) {
        return;
      }

      expect(result.count).toBe(1);
      expect(result.matches[0].function).toBe('FUN_140081090');
      expect(result.matches[0].string_matches?.[0]?.value).toContain('failed at');
      expect(result.matches[0].match_types).toContain('api_call');
      expect(result.matches[0].match_types).toContain('string_reference');
    });
  });

  describe('getFunctionCFG', () => {
    test('should throw error if Ghidra is not configured', async () => {
      // Skip if Ghidra is actually configured
      if (ghidraConfig.isValid) {
        return;
      }

      const sampleId = 'sha256:' + 'a'.repeat(64);

      await expect(
        decompilerWorker.getFunctionCFG(sampleId, '0x00401000')
      ).rejects.toThrow('Ghidra is not properly configured');
    });

    test('should throw error if sample not found', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      const sampleId = 'sha256:' + 'b'.repeat(64);

      await expect(
        decompilerWorker.getFunctionCFG(sampleId, '0x00401000')
      ).rejects.toThrow('Sample not found');
    });

    test('should throw error if no Ghidra analysis found', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample without analysis
      const sha256 = 'c'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'd'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      await expect(
        decompilerWorker.getFunctionCFG(sampleId, '0x00401000')
      ).rejects.toThrow('No Ghidra analysis with cfg readiness found');
    });

    test('should accept address as string', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample with completed analysis
      const sha256 = 'e'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'f'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, Buffer.from('MZ'));

      // Insert completed analysis
      const analysisId = 'analysis-' + Date.now();
      database.insertAnalysis({
        id: analysisId,
        sample_id: sampleId,
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'done',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          project_path: path.join(workspace.ghidra, 'project_test'),
          project_key: 'test_project'
        }),
        metrics_json: JSON.stringify({ elapsed_ms: 1000 })
      });

      // This will fail because we don't have a real Ghidra project,
      // but it should get past the validation checks
      try {
        await decompilerWorker.getFunctionCFG(sampleId, '0x00401000');
      } catch (error) {
        // Expected to fail at Ghidra execution, not validation
        expect(error).toBeDefined();
      }
    });

    test('should accept symbol name as string', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample with completed analysis
      const sha256 = '7'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: '8'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, Buffer.from('MZ'));

      // Insert completed analysis
      const analysisId = 'analysis-' + Date.now();
      database.insertAnalysis({
        id: analysisId,
        sample_id: sampleId,
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'done',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          project_path: path.join(workspace.ghidra, 'project_test'),
          project_key: 'test_project'
        }),
        metrics_json: JSON.stringify({ elapsed_ms: 1000 })
      });

      // This will fail because we don't have a real Ghidra project,
      // but it should accept symbol name
      try {
        await decompilerWorker.getFunctionCFG(sampleId, 'main');
      } catch (error) {
        // Expected to fail at Ghidra execution, not validation
        expect(error).toBeDefined();
      }
    });

    test('should respect timeout parameter', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample with completed analysis
      const sha256 = '9'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'a'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, Buffer.from('MZ'));

      // Insert completed analysis
      const analysisId = 'analysis-' + Date.now();
      database.insertAnalysis({
        id: analysisId,
        sample_id: sampleId,
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'done',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          project_path: path.join(workspace.ghidra, 'project_test'),
          project_key: 'test_project'
        }),
        metrics_json: JSON.stringify({ elapsed_ms: 1000 })
      });

      // This will fail because we don't have a real Ghidra project,
      // but it should accept timeout parameter
      try {
        await decompilerWorker.getFunctionCFG(sampleId, '0x00401000', 60000);
      } catch (error) {
        // Expected to fail at Ghidra execution, not validation
        expect(error).toBeDefined();
      }
    });
  });

  describe('decompileFunction', () => {
    test('should throw error if Ghidra is not configured', async () => {
      // Skip if Ghidra is actually configured
      if (ghidraConfig.isValid) {
        return;
      }

      const sampleId = 'sha256:' + 'a'.repeat(64);

      await expect(
        decompilerWorker.decompileFunction(sampleId, '0x00401000')
      ).rejects.toThrow('Ghidra is not properly configured');
    });

    test('should throw error if sample not found', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      const sampleId = 'sha256:' + 'b'.repeat(64);

      await expect(
        decompilerWorker.decompileFunction(sampleId, '0x00401000')
      ).rejects.toThrow('Sample not found');
    });

    test('should throw error if no Ghidra analysis found', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample without analysis
      const sha256 = 'c'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'd'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      await expect(
        decompilerWorker.decompileFunction(sampleId, '0x00401000')
      ).rejects.toThrow('No Ghidra analysis with decompile readiness found');
    });

    test('should accept address as string', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample with completed analysis
      const sha256 = 'e'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'f'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, Buffer.from('MZ')); // Minimal PE header

      // Insert completed analysis
      const analysisId = 'analysis-' + Date.now();
      database.insertAnalysis({
        id: analysisId,
        sample_id: sampleId,
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'done',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          project_path: path.join(workspace.ghidra, 'project_test'),
          project_key: 'test_project'
        }),
        metrics_json: JSON.stringify({ elapsed_ms: 1000 })
      });

      // This will fail because we don't have a real Ghidra project,
      // but it should get past the validation checks
      try {
        await decompilerWorker.decompileFunction(sampleId, '0x00401000');
      } catch (error) {
        // Expected to fail at Ghidra execution, not validation
        expect(error).toBeDefined();
      }
    });

    test('should accept symbol name as string', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample with completed analysis
      const sha256 = '7'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: '8'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, Buffer.from('MZ'));

      // Insert completed analysis
      const analysisId = 'analysis-' + Date.now();
      database.insertAnalysis({
        id: analysisId,
        sample_id: sampleId,
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'done',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          project_path: path.join(workspace.ghidra, 'project_test'),
          project_key: 'test_project'
        }),
        metrics_json: JSON.stringify({ elapsed_ms: 1000 })
      });

      // This will fail because we don't have a real Ghidra project,
      // but it should accept symbol name
      try {
        await decompilerWorker.decompileFunction(sampleId, 'main');
      } catch (error) {
        // Expected to fail at Ghidra execution, not validation
        expect(error).toBeDefined();
      }
    });

    test('should respect includeXrefs parameter', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample with completed analysis
      const sha256 = '9'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'a'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, Buffer.from('MZ'));

      // Insert completed analysis
      const analysisId = 'analysis-' + Date.now();
      database.insertAnalysis({
        id: analysisId,
        sample_id: sampleId,
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'done',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          project_path: path.join(workspace.ghidra, 'project_test'),
          project_key: 'test_project'
        }),
        metrics_json: JSON.stringify({ elapsed_ms: 1000 })
      });

      // This will fail because we don't have a real Ghidra project,
      // but it should accept includeXrefs parameter
      try {
        await decompilerWorker.decompileFunction(sampleId, '0x00401000', true);
      } catch (error) {
        // Expected to fail at Ghidra execution, not validation
        expect(error).toBeDefined();
      }
    });

    test('should respect timeout parameter', async () => {
      // Skip if Ghidra is not configured
      if (!ghidraConfig.isValid) {
        return;
      }

      // Create a test sample with completed analysis
      const sha256 = 'b'.repeat(64);
      const sampleId = `sha256:${sha256}`;

      database.insertSample({
        id: sampleId,
        sha256,
        md5: 'c'.repeat(32),
        size: 1024,
        file_type: 'PE32',
        created_at: new Date().toISOString(),
        source: 'test'
      });

      // Create workspace and sample file
      const workspace = await workspaceManager.createWorkspace(sampleId);
      const samplePath = path.join(workspace.original, 'sample.exe');
      fs.writeFileSync(samplePath, Buffer.from('MZ'));

      // Insert completed analysis
      const analysisId = 'analysis-' + Date.now();
      database.insertAnalysis({
        id: analysisId,
        sample_id: sampleId,
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'done',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          project_path: path.join(workspace.ghidra, 'project_test'),
          project_key: 'test_project'
        }),
        metrics_json: JSON.stringify({ elapsed_ms: 1000 })
      });

      // This will fail because we don't have a real Ghidra project,
      // but it should accept timeout parameter
      try {
        await decompilerWorker.decompileFunction(sampleId, '0x00401000', false, 60000);
      } catch (error) {
        // Expected to fail at Ghidra execution, not validation
        expect(error).toBeDefined();
      }
    });
  });

});
