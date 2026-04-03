/**
 * Generate missing unit test files for tools.
 * Run: node scripts/gen-missing-tests.mjs
 */
import fs from 'fs'
import path from 'path'

// Tools that follow createXxxHandler pattern (with sample_id input)
const STANDARD_TOOLS = [
  { file: 'analysis-template', handler: 'createAnalysisTemplateHandler', schema: 'AnalysisTemplateInputSchema' },
  { file: 'apk-packer-detect', handler: 'createApkPackerDetectHandler', schema: 'ApkPackerDetectInputSchema' },
  { file: 'artifact-download', handler: 'createArtifactDownloadHandler', schema: 'ArtifactDownloadInputSchema' },
  { file: 'behavior-timeline', handler: 'createBehaviorTimelineHandler', schema: 'BehaviorTimelineInputSchema' },
  { file: 'binary-diff-summary', handler: 'createBinaryDiffSummaryHandler', schema: 'BinaryDiffSummaryInputSchema' },
  { file: 'c2-extract', handler: 'createC2ExtractHandler', schema: 'C2ExtractInputSchema' },
  { file: 'call-graph-cross-module', handler: 'createCallGraphCrossModuleHandler', schema: 'CallGraphCrossModuleInputSchema' },
  { file: 'code-function-cfg', handler: 'createCodeFunctionCFGHandler', schema: 'codeFunctionCFGInputSchema' },
  { file: 'code-function-decompile', handler: 'createCodeFunctionDecompileHandler', schema: 'codeFunctionDecompileInputSchema' },
  { file: 'code-function-disassemble', handler: 'createCodeFunctionDisassembleHandler', schema: 'codeFunctionDisassembleInputSchema' },
  { file: 'code-function-explain-apply', handler: 'createCodeFunctionExplainApplyHandler', schema: 'codeFunctionExplainApplyInputSchema' },
  { file: 'code-function-rename-apply', handler: 'createCodeFunctionRenameApplyHandler', schema: 'codeFunctionRenameApplyInputSchema' },
  { file: 'code-function-rename-prepare', handler: 'createCodeFunctionRenamePrepareHandler', schema: 'codeFunctionRenamePrepareInputSchema' },
  { file: 'code-functions-list', handler: 'createCodeFunctionsListHandler', schema: 'codeFunctionsListInputSchema' },
  { file: 'code-functions-rank', handler: 'createCodeFunctionsRankHandler', schema: 'codeFunctionsRankInputSchema' },
  { file: 'code-functions-search', handler: 'createCodeFunctionsSearchHandler', schema: 'codeFunctionsSearchInputSchema' },
  { file: 'code-module-review-apply', handler: 'createCodeModuleReviewApplyHandler', schema: 'codeModuleReviewApplyInputSchema' },
  { file: 'code-module-review-prepare', handler: 'createCodeModuleReviewPrepareHandler', schema: 'codeModuleReviewPrepareInputSchema' },
  { file: 'compiler-packer-detect', handler: 'createCompilerPackerDetectHandler', schema: 'compilerPackerDetectInputSchema' },
  { file: 'constraint-extract', handler: 'createConstraintExtractHandler', schema: 'constraintExtractInputSchema' },
  { file: 'crackme-locate-validation', handler: 'createCrackmeLocateValidationHandler', schema: 'CrackmeLocateValidationInputSchema' },
  { file: 'cross-binary-compare', handler: 'createCrossBinaryCompareHandler', schema: 'CrossBinaryCompareInputSchema' },
  { file: 'data-flow-map', handler: 'createDataFlowMapHandler', schema: 'DataFlowMapInputSchema' },
  { file: 'debug-session-breakpoint', handler: 'createDebugSessionBreakpointHandler', schema: 'DebugSessionBreakpointInputSchema' },
  { file: 'debug-session-continue', handler: 'createDebugSessionContinueHandler', schema: 'DebugSessionContinueInputSchema' },
  { file: 'debug-session-end', handler: 'createDebugSessionEndHandler', schema: 'DebugSessionEndInputSchema' },
  { file: 'debug-session-inspect', handler: 'createDebugSessionInspectHandler', schema: 'DebugSessionInspectInputSchema' },
  { file: 'debug-session-start', handler: 'createDebugSessionStartHandler', schema: 'DebugSessionStartInputSchema' },
  { file: 'debug-session-step', handler: 'createDebugSessionStepHandler', schema: 'DebugSessionStepInputSchema' },
  { file: 'dex-classes-list', handler: 'createDexClassesListHandler', schema: 'DexClassesListInputSchema' },
  { file: 'dex-decompile', handler: 'createDexDecompileHandler', schema: 'DexDecompileInputSchema' },
  { file: 'dll-dependency-tree', handler: 'createDllDependencyTreeHandler', schema: 'DllDependencyTreeInputSchema' },
  { file: 'dynamic-auto-hook', handler: 'createDynamicAutoHookHandler', schema: 'DynamicAutoHookInputSchema' },
  { file: 'dynamic-memory-dump', handler: 'createDynamicMemoryDumpHandler', schema: 'DynamicMemoryDumpInputSchema' },
  { file: 'dynamic-trace-attribute', handler: 'createDynamicTraceAttributeHandler', schema: 'DynamicTraceAttributeInputSchema' },
  { file: 'elf-exports-extract', handler: 'createElfExportsExtractHandler', schema: 'ElfExportsExtractInputSchema' },
  { file: 'elf-imports-extract', handler: 'createElfImportsExtractHandler', schema: 'ElfImportsExtractInputSchema' },
  { file: 'elf-structure-analyze', handler: 'createElfStructureAnalyzeHandler', schema: 'ElfStructureAnalyzeInputSchema' },
  { file: 'kb-export', handler: 'createKbExportHandler', schema: 'KbExportInputSchema' },
  { file: 'kb-function-match', handler: 'createKbFunctionMatchHandler', schema: 'KbFunctionMatchInputSchema' },
  { file: 'kb-import-bulk', handler: 'createKbImportBulkHandler', schema: 'KbImportBulkInputSchema' },
  { file: 'kb-import', handler: 'createKbImportHandler', schema: 'KbImportInputSchema' },
  { file: 'kb-stats', handler: 'createKbStatsHandler', schema: 'KbStatsInputSchema' },
  { file: 'keygen-synthesize', handler: 'createKeygenSynthesizeHandler', schema: 'keygenSynthesizeInputSchema' },
  { file: 'keygen-verify', handler: 'createKeygenVerifyHandler', schema: 'KeygenVerifyInputSchema' },
  { file: 'macho-structure-analyze', handler: 'createMachoStructureAnalyzeHandler', schema: 'MachoStructureAnalyzeInputSchema' },
  { file: 'malware-classify', handler: 'createMalwareClassifyHandler', schema: 'MalwareClassifyInputSchema' },
  { file: 'mba-simplify', handler: 'createMbaSimplifyHandler', schema: 'mbaSimplifyInputSchema' },
  { file: 'pe-structure-analyze', handler: 'createPEStructureAnalyzeHandler', schema: 'peStructureAnalyzeInputSchema' },
  { file: 'report-html-generate', handler: 'createReportHtmlGenerateHandler', schema: 'ReportHtmlGenerateInputSchema' },
  { file: 'sandbox-report', handler: 'createSandboxReportHandler', schema: 'SandboxReportInputSchema' },
  { file: 'setup-remediate', handler: 'createSetupRemediateHandler', schema: 'SetupRemediateInputSchema' },
  { file: 'smt-solve', handler: 'createSmtSolveHandler', schema: 'smtSolveInputSchema' },
  { file: 'static-capability-triage', handler: 'createStaticCapabilityTriageHandler', schema: 'staticCapabilityTriageInputSchema' },
  { file: 'task-cancel', handler: 'createTaskCancelHandler', schema: 'taskCancelInputSchema' },
  { file: 'task-status', handler: 'createTaskStatusHandler', schema: 'taskStatusInputSchema' },
  { file: 'task-sweep', handler: 'createTaskSweepHandler', schema: 'taskSweepInputSchema' },
  { file: 'vm-detect', handler: 'createVmDetectHandler', schema: 'vmDetectInputSchema' },
  { file: 'vm-disasm-build', handler: 'createVmDisasmBuildHandler', schema: 'vmDisasmBuildInputSchema' },
  { file: 'vm-emulate', handler: 'createVmEmulateHandler', schema: 'vmEmulateInputSchema' },
  { file: 'vm-opcode-extract', handler: 'createVmOpcodeExtractHandler', schema: 'vmOpcodeExtractInputSchema' },
  { file: 'vm-pattern-analyze', handler: 'createVmPatternAnalyzeHandler', schema: 'vmPatternAnalyzeInputSchema' },
  { file: 'vuln-pattern-scan', handler: 'createVulnPatternScanHandler', schema: 'VulnPatternScanInputSchema' },
  { file: 'vuln-pattern-summary', handler: 'createVulnPatternSummaryHandler', schema: 'VulnPatternSummaryInputSchema' },
]

// Utility tools (no createXxxHandler / no sample_id)
const UTILITY_TOOLS = [
  { file: 'cache-observability', exports: ['lookupCachedResult', 'formatCacheWarning'] },
  { file: 'entrypoint-fallback-disasm', exports: ['runEntrypointFallbackDisasm'] },
  { file: 'rust-demangle', exports: ['demangleRustSymbol', 'normalizeRustName', 'boundedPreview', 'normalizeSymbolList'] },
  { file: 'static-worker-client', exports: ['buildStaticWorkerRequest', 'callStaticWorker'] },
]

// Check which tools use sample_id vs other primary keys
function needsSampleIdCheck(toolFile) {
  const src = fs.readFileSync(path.join('src', 'tools', `${toolFile}.ts`), 'utf8')
  // Check if schema has sample_id
  if (src.includes("sample_id:") || src.includes("sample_id'")) return 'sample_id'
  // Some tools use task_id, session_id, etc.
  if (src.includes("task_id:") || src.includes("task_id'")) return 'task_id'
  if (src.includes("session_id:") || src.includes("session_id'")) return 'session_id'
  return 'sample_id' // default assumption
}

// Check handler dependencies
function getHandlerDeps(toolFile) {
  const src = fs.readFileSync(path.join('src', 'tools', `${toolFile}.ts`), 'utf8')
  const match = src.match(/export function (create\w+)\(([^)]+)\)/)
  if (!match) return ['workspaceManager', 'database', 'cacheManager']
  const params = match[2]
  const deps = []
  if (params.includes('WorkspaceManager') || params.includes('workspace')) deps.push('workspaceManager')
  if (params.includes('DatabaseManager') || params.includes('database')) deps.push('database')
  if (params.includes('CacheManager') || params.includes('cache')) deps.push('cacheManager')
  if (params.includes('Config') || params.includes('config')) deps.push('config')
  if (params.includes('JobQueue') || params.includes('jobQueue')) deps.push('jobQueue')
  if (params.includes('WorkerPool') || params.includes('workerPool')) deps.push('workerPool')
  if (params.includes('DebugSessionManager') || params.includes('debugManager')) deps.push('debugManager')
  if (params.includes('KnowledgeBaseManager') || params.includes('kbManager')) deps.push('kbManager')
  return deps.length ? deps : ['workspaceManager', 'database', 'cacheManager']
}

function toDotName(kebab) {
  return kebab.replace(/-/g, '.')
}

function generateStandardTest(tool) {
  const { file, handler, schema } = tool
  const primaryKey = needsSampleIdCheck(file)
  const deps = getHandlerDeps(file)
  const dotName = toDotName(file)

  // Build mock setup based on deps
  const mockDeclarations = []
  const mockSetup = []
  const mockImports = []
  const handlerArgs = []

  if (deps.includes('workspaceManager')) {
    mockImports.push("import type { WorkspaceManager } from '../../src/workspace-manager.js'")
    mockDeclarations.push('let mockWorkspaceManager: jest.Mocked<WorkspaceManager>')
    mockSetup.push(`    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>`)
    handlerArgs.push('mockWorkspaceManager')
  }
  if (deps.includes('database')) {
    mockImports.push("import type { DatabaseManager } from '../../src/database.js'")
    mockDeclarations.push('let mockDatabase: jest.Mocked<DatabaseManager>')
    mockSetup.push(`    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>`)
    handlerArgs.push('mockDatabase')
  }
  if (deps.includes('cacheManager')) {
    mockImports.push("import type { CacheManager } from '../../src/cache-manager.js'")
    mockDeclarations.push('let mockCacheManager: jest.Mocked<CacheManager>')
    mockSetup.push(`    mockCacheManager = {
      getCachedResult: jest.fn(),
      setCachedResult: jest.fn(),
    } as unknown as jest.Mocked<CacheManager>`)
    handlerArgs.push('mockCacheManager')
  }
  if (deps.includes('config')) {
    mockImports.push("import type { Config } from '../../src/config.js'")
    mockDeclarations.push('let mockConfig: jest.Mocked<Config>')
    mockSetup.push(`    mockConfig = {} as unknown as jest.Mocked<Config>`)
    handlerArgs.push('mockConfig')
  }
  if (deps.includes('jobQueue')) {
    mockImports.push("import type { JobQueue } from '../../src/job-queue.js'")
    mockDeclarations.push('let mockJobQueue: jest.Mocked<JobQueue>')
    mockSetup.push(`    mockJobQueue = {
      enqueue: jest.fn(),
      getStatus: jest.fn(),
    } as unknown as jest.Mocked<JobQueue>`)
    handlerArgs.push('mockJobQueue')
  }
  if (deps.includes('workerPool')) {
    mockImports.push("import type { WorkerPool } from '../../src/worker-pool.js'")
    mockDeclarations.push('let mockWorkerPool: jest.Mocked<WorkerPool>')
    mockSetup.push(`    mockWorkerPool = {} as unknown as jest.Mocked<WorkerPool>`)
    handlerArgs.push('mockWorkerPool')
  }
  if (deps.includes('debugManager')) {
    mockImports.push("import type { DebugSessionManager } from '../../src/debug-session-manager.js'")
    mockDeclarations.push('let mockDebugManager: jest.Mocked<DebugSessionManager>')
    mockSetup.push(`    mockDebugManager = {
      getSession: jest.fn(),
      createSession: jest.fn(),
    } as unknown as jest.Mocked<DebugSessionManager>`)
    handlerArgs.push('mockDebugManager')
  }
  if (deps.includes('kbManager')) {
    mockImports.push("import type { KnowledgeBaseManager } from '../../src/knowledge-base-manager.js'")
    mockDeclarations.push('let mockKbManager: jest.Mocked<KnowledgeBaseManager>')
    mockSetup.push(`    mockKbManager = {
      search: jest.fn(),
      importEntry: jest.fn(),
      getStats: jest.fn(),
    } as unknown as jest.Mocked<KnowledgeBaseManager>`)
    handlerArgs.push('mockKbManager')
  }

  // Build primary key test samples
  let inputValid, inputMissing, notFoundCheck
  if (primaryKey === 'task_id') {
    inputValid = "{ task_id: 'task-abc123' }"
    inputMissing = '{}'
    notFoundCheck = `expect(result.ok).toBe(false)`
  } else if (primaryKey === 'session_id') {
    inputValid = "{ session_id: 'sess-abc123' }"
    inputMissing = '{}'
    notFoundCheck = `expect(result.ok).toBe(false)`
  } else {
    inputValid = "{ sample_id: 'sha256:abc123def456' }"
    inputMissing = '{}'
    notFoundCheck = `expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)`
  }

  // Generate findSample mock only if db dep and sample_id primary key
  const sampleNotFoundSetup = (deps.includes('database') && primaryKey === 'sample_id')
    ? '\n      mockDatabase.findSample.mockReturnValue(undefined)\n'
    : ''

  return `/**
 * Unit tests for ${dotName} tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { ${handler}, ${schema} } from '../../src/tools/${file}.js'
${mockImports.join('\n')}

describe('${dotName} tool', () => {
${mockDeclarations.map(d => '  ' + d).join('\n')}

  beforeEach(() => {
${mockSetup.join('\n\n')}
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = ${schema}.safeParse(${inputValid})
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = ${schema}.safeParse(${inputMissing})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = ${schema}.safeParse({ ${primaryKey}: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = ${handler}(${handlerArgs.join(', ')})
${sampleNotFoundSetup}
      const result = await handler(${inputValid})

      ${notFoundCheck}
    })
  })
})
`
}

function generateUtilityTest(tool) {
  const { file, exports: exps } = tool
  const dotName = toDotName(file)
  const imports = exps.map(e => e).join(', ')

  return `/**
 * Unit tests for ${dotName} utility
 */

import { describe, test, expect } from '@jest/globals'
import { ${imports} } from '../../src/tools/${file}.js'

describe('${dotName} utility', () => {
${exps.map(exp => `  describe('${exp}', () => {
    test('should be a function', () => {
      expect(typeof ${exp}).toBe('function')
    })
  })
`).join('\n')}})
`
}

// Generate all test files
const outDir = path.join('tests', 'unit')
let created = 0
let skipped = 0

for (const tool of STANDARD_TOOLS) {
  const outPath = path.join(outDir, `${tool.file}.test.ts`)
  if (fs.existsSync(outPath)) {
    skipped++
    continue
  }
  const content = generateStandardTest(tool)
  fs.writeFileSync(outPath, content, 'utf8')
  created++
}

for (const tool of UTILITY_TOOLS) {
  const outPath = path.join(outDir, `${tool.file}.test.ts`)
  if (fs.existsSync(outPath)) {
    skipped++
    continue
  }
  const content = generateUtilityTest(tool)
  fs.writeFileSync(outPath, content, 'utf8')
  created++
}

console.log(`✓ Created: ${created} test files, Skipped: ${skipped} (already exist)`)
