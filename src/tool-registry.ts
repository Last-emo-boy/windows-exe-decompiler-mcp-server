/**
 * Centralised tool / prompt / resource registry.
 *
 * Every MCP tool, prompt, and resource is imported here and wired to its handler factory.
 * `index.ts` calls `registerAllTools(server, deps)` once during bootstrap �?
 * keeping the entry-point lean and all registration logic in one place.
 */

import fs from 'fs/promises'
import path from 'path'
import { fileURLToPath } from 'url'
import type { MCPServer } from './server.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import type { PolicyGuard } from './policy-guard.js'
import type { CacheManager } from './cache-manager.js'
import type { JobQueue } from './job-queue.js'
import type { StorageManager } from './storage/storage-manager.js'
import type { Config } from './config.js'

// ─── Dependency bag passed to every handler factory ────────────────────────
export interface ToolDeps {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  policyGuard: PolicyGuard
  cacheManager: CacheManager
  jobQueue: JobQueue
  storageManager: StorageManager
  config: Config
  server: MCPServer
}

// ─── Prompts ───────────────────────────────────────────────────────────────
import {
  semanticNameReviewPromptDefinition,
  createSemanticNameReviewPromptHandler,
} from './prompts/semantic-name-review.js'
import {
  functionExplanationReviewPromptDefinition,
  createFunctionExplanationReviewPromptHandler,
} from './prompts/function-explanation-review.js'
import {
  moduleReconstructionReviewPromptDefinition,
  createModuleReconstructionReviewPromptHandler,
} from './prompts/module-reconstruction-review.js'

// ─── Core tools ────────────────────────────────────────────────────────────
import { sampleIngestToolDefinition, createSampleIngestHandler } from './tools/sample-ingest.js'
import { sampleRequestUploadToolDefinition, createSampleRequestUploadHandler } from './tools/sample-request-upload.js'
import { sampleProfileGetToolDefinition, createSampleProfileGetHandler } from './tools/sample-profile-get.js'
import { artifactReadToolDefinition, createArtifactReadHandler } from './tools/artifact-read.js'
import { artifactsListToolDefinition, createArtifactsListHandler } from './tools/artifacts-list.js'
import { artifactsDiffToolDefinition, createArtifactsDiffHandler } from './tools/artifacts-diff.js'
import { artifactDownloadToolDefinition, createArtifactDownloadHandler } from './tools/artifact-download.js'

// ─── LLM ───────────────────────────────────────────────────────────────────
import { llmAnalyzeToolDefinition, createLlmAnalyzeHandler } from './llm/llm-analyze.js'

// ─── PE analysis ───────────────────────────────────────────────────────────

// ─── Strings ───────────────────────────────────────────────────────────────
import { stringsExtractToolDefinition, createStringsExtractHandler } from './tools/strings-extract.js'
import { stringsFlossDecodeToolDefinition, createStringsFlossDecodeHandler } from './tools/strings-floss-decode.js'

// ─── Static analysis ──────────────────────────────────────────────────────
import { analysisContextLinkToolDefinition, createAnalysisContextLinkHandler } from './tools/analysis-context-link.js'
import { yaraScanToolDefinition, createYaraScanHandler } from './tools/yara-scan.js'
import { runtimeDetectToolDefinition, createRuntimeDetectHandler } from './tools/runtime-detect.js'
import { dotNetMetadataExtractToolDefinition, createDotNetMetadataExtractHandler } from './tools/dotnet-metadata-extract.js'
import { dotNetTypesListToolDefinition, createDotNetTypesListHandler } from './tools/dotnet-types-list.js'
import { packerDetectToolDefinition, createPackerDetectHandler } from './tools/packer-detect.js'
import { staticCapabilityTriageToolDefinition, createStaticCapabilityTriageHandler } from './tools/static-capability-triage.js'
import { compilerPackerDetectToolDefinition, createCompilerPackerDetectHandler } from './tools/compiler-packer-detect.js'
import { binaryRoleProfileToolDefinition, createBinaryRoleProfileHandler } from './tools/binary-role-profile.js'
import { cryptoIdentifyToolDefinition, createCryptoIdentifyHandler } from './tools/crypto-identify.js'
import { breakpointSmartToolDefinition, createBreakpointSmartHandler } from './tools/breakpoint-smart.js'
import { traceConditionToolDefinition, createTraceConditionHandler } from './tools/trace-condition.js'
import { dllExportProfileToolDefinition, createDllExportProfileHandler } from './tools/dll-export-profile.js'
import { comRoleProfileToolDefinition, createComRoleProfileHandler } from './tools/com-role-profile.js'
import { rustBinaryAnalyzeToolDefinition, createRustBinaryAnalyzeHandler } from './tools/rust-binary-analyze.js'

// ─── Workflows ─────────────────────────────────────────────────────────────
import { triageWorkflowToolDefinition, createTriageWorkflowHandler } from './workflows/triage.js'
import { analyzeAutoWorkflowToolDefinition, createAnalyzeAutoWorkflowHandler } from './workflows/analyze-auto.js'
import {
  analyzeWorkflowPromoteToolDefinition,
  analyzeWorkflowStartToolDefinition,
  analyzeWorkflowStatusToolDefinition,
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
  createAnalyzeWorkflowStatusHandler,
} from './workflows/analyze-pipeline.js'
import { reconstructWorkflowToolDefinition, createReconstructWorkflowHandler } from './workflows/reconstruct.js'
import { deepStaticWorkflowToolDefinition, createDeepStaticWorkflowHandler } from './workflows/deep-static.js'
import { functionIndexRecoverWorkflowToolDefinition, createFunctionIndexRecoverWorkflowHandler } from './workflows/function-index-recover.js'
import { semanticNameReviewWorkflowToolDefinition, createSemanticNameReviewWorkflowHandler } from './workflows/semantic-name-review.js'
import { functionExplanationReviewWorkflowToolDefinition, createFunctionExplanationReviewWorkflowHandler } from './workflows/function-explanation-review.js'
import { moduleReconstructionReviewWorkflowToolDefinition, createModuleReconstructionReviewWorkflowHandler } from './workflows/module-reconstruction-review.js'

// ─── Reports ───────────────────────────────────────────────────────────────
import { reportSummarizeToolDefinition, createReportSummarizeHandler } from './tools/report-summarize.js'
import { reportGenerateToolDefinition, createReportGenerateHandler } from './tools/report-generate.js'
import { workflowSummarizeToolDefinition, createWorkflowSummarizeHandler } from './workflows/summarize.js'

// ─── Ghidra / task management ──────────────────────────────────────────────
import { systemHealthToolDefinition, createSystemHealthHandler } from './tools/system-health.js'
import { systemSetupGuideToolDefinition, createSystemSetupGuideHandler } from './tools/system-setup-guide.js'
import { setupRemediateToolDefinition, createSetupRemediateHandler } from './tools/setup-remediate.js'
import { taskStatusToolDefinition, createTaskStatusHandler } from './tools/task-status.js'
import { taskCancelToolDefinition, createTaskCancelHandler } from './tools/task-cancel.js'
import { taskSweepToolDefinition, createTaskSweepHandler } from './tools/task-sweep.js'

// ─── Dynamic analysis ─────────────────────────────────────────────────────
import { dynamicDependenciesToolDefinition, createDynamicDependenciesHandler } from './tools/dynamic-dependencies.js'
import { dynamicTraceImportToolDefinition, createDynamicTraceImportHandler } from './tools/dynamic-trace-import.js'
import { dynamicMemoryImportToolDefinition, createDynamicMemoryImportHandler } from './tools/dynamic-memory-import.js'
import { sandboxExecuteToolDefinition, createSandboxExecuteHandler } from './tools/sandbox-execute.js'

// ─── Docker backend tools ──────────────────────────────────────────────────
import {
  angrAnalyzeToolDefinition, createAngrAnalyzeHandler,
  graphvizRenderToolDefinition, createGraphvizRenderHandler,
  pandaInspectToolDefinition, createPandaInspectHandler,
  qilingInspectToolDefinition, createQilingInspectHandler,
  retdecDecompileToolDefinition, createRetDecDecompileHandler,
  rizinAnalyzeToolDefinition, createRizinAnalyzeHandler,
  upxInspectToolDefinition, createUPXInspectHandler,
  wineRunToolDefinition, createWineRunHandler,
  yaraXScanToolDefinition, createYaraXScanHandler,
} from './tools/docker-backend-tools.js'

// ─── Threat intel & reporting ─────────────────────────────────────────────
import { toolHelpToolDefinition, createToolHelpHandler } from './tools/tool-help.js'

// ─── Code analysis ─────────────────────────────────────────────────────────
import { codeFunctionsListToolDefinition, createCodeFunctionsListHandler } from './tools/code-functions-list.js'
import { codeFunctionsRankToolDefinition, createCodeFunctionsRankHandler } from './tools/code-functions-rank.js'
import { codeFunctionsSmartRecoverToolDefinition, createCodeFunctionsSmartRecoverHandler } from './tools/code-functions-smart-recover.js'
import { codeFunctionsDefineToolDefinition, createCodeFunctionsDefineHandler } from './tools/code-functions-define.js'
import { codeFunctionsSearchToolDefinition, createCodeFunctionsSearchHandler } from './tools/code-functions-search.js'
import { codeXrefsAnalyzeToolDefinition, createCodeXrefsAnalyzeHandler } from './tools/code-xrefs-analyze.js'
import { codeFunctionDecompileToolDefinition, createCodeFunctionDecompileHandler } from './tools/code-function-decompile.js'
import { codeFunctionDisassembleToolDefinition, createCodeFunctionDisassembleHandler } from './tools/code-function-disassemble.js'
import { codeFunctionCFGToolDefinition, createCodeFunctionCFGHandler } from './tools/code-function-cfg.js'
import { codeFunctionsReconstructToolDefinition, createCodeFunctionsReconstructHandler } from './tools/code-functions-reconstruct.js'
import { codeFunctionRenamePrepareToolDefinition, createCodeFunctionRenamePrepareHandler } from './tools/code-function-rename-prepare.js'
import { codeFunctionExplainPrepareToolDefinition, createCodeFunctionExplainPrepareHandler } from './tools/code-function-explain-prepare.js'
import { codeFunctionExplainApplyToolDefinition, createCodeFunctionExplainApplyHandler } from './tools/code-function-explain-apply.js'
import { codeFunctionRenameApplyToolDefinition, createCodeFunctionRenameApplyHandler } from './tools/code-function-rename-apply.js'
import { codeReconstructExportToolDefinition, createCodeReconstructExportHandler } from './tools/code-reconstruct-export.js'
import { dotNetReconstructExportToolDefinition, createDotNetReconstructExportHandler } from './tools/dotnet-reconstruct-export.js'
import { codeReconstructPlanToolDefinition, createCodeReconstructPlanHandler } from './tools/code-reconstruct-plan.js'
import { codeModuleReviewPrepareToolDefinition, createCodeModuleReviewPrepareHandler } from './tools/code-module-review-prepare.js'
import { codeModuleReviewApplyToolDefinition, createCodeModuleReviewApplyHandler } from './tools/code-module-review-apply.js'

// ─── Unpacking / diffing / YARA ────────────────────────────────────────────
import { unpackAutoToolDefinition, createUnpackAutoHandler } from './tools/unpack-auto.js'
import { binaryDiffToolDefinition, createBinaryDiffHandler } from './tools/binary-diff.js'
import { binaryDiffSummaryToolDefinition, createBinaryDiffSummaryHandler } from './tools/binary-diff-summary.js'
import { yaraGenerateToolDefinition, createYaraGenerateHandler } from './tools/yara-generate.js'
import { yaraGenerateBatchToolDefinition, createYaraGenerateBatchHandler } from './tools/yara-generate-batch.js'

// ─── Vulnerability scanning ────────────────────────────────────────────────

// ─── Knowledge base ────────────────────────────────────────────────────────
import { kbImportBulkToolDefinition, createKbImportBulkHandler } from './tools/kb-import-bulk.js'
import { kbExportToolDefinition, createKbExportHandler } from './tools/kb-export.js'
import { kbImportToolDefinition, createKbImportHandler } from './tools/kb-import.js'
import { kbStatsToolDefinition, createKbStatsHandler } from './tools/kb-stats.js'

// ─── ELF / Mach-O ─────────────────────────────────────────────────────────
import { elfStructureAnalyzeToolDefinition, createElfStructureAnalyzeHandler } from './tools/elf-structure-analyze.js'
import { machoStructureAnalyzeToolDefinition, createMachoStructureAnalyzeHandler } from './tools/macho-structure-analyze.js'
import { elfImportsExtractToolDefinition, createElfImportsExtractHandler } from './tools/elf-imports-extract.js'
import { elfExportsExtractToolDefinition, createElfExportsExtractHandler } from './tools/elf-exports-extract.js'

// ─── Debug sessions ────────────────────────────────────────────────────────

// ─── VM / constraint solving ──────────────────────────────────────────────
import { vmDetectToolDefinition, createVmDetectHandler } from './tools/vm-detect.js'
import { vmPatternAnalyzeToolDefinition, createVmPatternAnalyzeHandler } from './tools/vm-pattern-analyze.js'
import { vmOpcodeExtractToolDefinition, createVmOpcodeExtractHandler } from './tools/vm-opcode-extract.js'
import { vmDisasmBuildToolDefinition, createVmDisasmBuildHandler } from './tools/vm-disasm-build.js'
import { vmEmulateToolDefinition, createVmEmulateHandler } from './tools/vm-emulate.js'
import { vmSemanticDiffToolDefinition, createVmSemanticDiffHandler } from './tools/vm-semantic-diff.js'
import { constraintExtractToolDefinition, createConstraintExtractHandler } from './tools/constraint-extract.js'
import { smtSolveToolDefinition, createSmtSolveHandler } from './tools/smt-solve.js'
import { keygenSynthesizeToolDefinition, createKeygenSynthesizeHandler } from './tools/keygen-synthesize.js'
import { mbaSimplifyToolDefinition, createMbaSimplifyHandler } from './tools/mba-simplify.js'

// ─── v2.0 �?Plugin-managed tools ─────────────────────────────────────────
// Android, CrackMe, Dynamic, Malware, Frida, Ghidra, Cross-module, Visualization, KB
// Imports are handled inside each plugin's register() function; see src/plugins.ts.
import { loadPlugins, getPluginManager } from './plugins.js'

// ── Plugin utility imports (injected into plugin deps) ────────────────────
import { resolvePrimarySamplePath } from './sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from './static-analysis-artifacts.js'
import { resolvePackagePath } from './runtime-paths.js'
import { generateCacheKey } from './cache-manager.js'
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from './decompiler-worker.js'
import {
  findBestGhidraAnalysis,
  getGhidraReadiness,
  parseGhidraAnalysisMetadata,
} from './ghidra-analysis-status.js'
import { PollingGuidanceSchema, buildPollingGuidance } from './polling-guidance.js'
import { SetupActionSchema, RequiredUserInputSchema } from './setup-guidance.js'
import { logger as serverLogger } from './logger.js'

// ─── Plugin introspection tools ───────────────────────────────────────────
import {
  pluginListToolDefinition, createPluginListHandler,
  pluginEnableToolDefinition, createPluginEnableHandler,
  pluginDisableToolDefinition, createPluginDisableHandler,
} from './tools/plugin-list.js'

// ─── System diagnostics tools ─────────────────────────────────────────────
import {
  configValidateToolDefinition, createConfigValidateHandler,
} from './tools/config-validate.js'

// ─── SBOM generation ─────────────────────────────────────────────────────
import {
  sbomGenerateToolDefinition, createSbomGenerateHandler,
} from './tools/sbom-generate.js'

// ─── Batch analysis ──────────────────────────────────────────────────────
import {
  batchSubmitToolDefinition, createBatchSubmitHandler,
  batchStatusToolDefinition, createBatchStatusHandler,
  batchResultsToolDefinition, createBatchResultsHandler,
} from './tools/batch-analysis.js'

// ─── Async wrapper ─────────────────────────────────────────────────────────
import { createAsyncToolWrapper, LONG_RUNNING_TOOLS } from './async-tool-wrapper.js'

// ============================================================================
// Registration
// ============================================================================

export async function registerAllTools(server: MCPServer, deps: ToolDeps): Promise<void> {
  const {
    workspaceManager, database, policyGuard,
    cacheManager, jobQueue, storageManager, config,
  } = deps

  // ── Prompts ────────────────────────────────────────────────────────────
  server.registerPrompt(semanticNameReviewPromptDefinition, createSemanticNameReviewPromptHandler())
  server.registerPrompt(functionExplanationReviewPromptDefinition, createFunctionExplanationReviewPromptHandler())
  server.registerPrompt(moduleReconstructionReviewPromptDefinition, createModuleReconstructionReviewPromptHandler())

  // ── Core ───────────────────────────────────────────────────────────────
  server.registerTool(sampleIngestToolDefinition, createSampleIngestHandler(workspaceManager, database, policyGuard))
  server.registerTool(sampleRequestUploadToolDefinition, createSampleRequestUploadHandler(database, { apiPort: config.api.port }))
  server.registerTool(sampleProfileGetToolDefinition, createSampleProfileGetHandler(database, workspaceManager))
  server.registerTool(artifactReadToolDefinition, createArtifactReadHandler(workspaceManager, database))
  server.registerTool(artifactsListToolDefinition, createArtifactsListHandler(workspaceManager, database))
  server.registerTool(artifactsDiffToolDefinition, createArtifactsDiffHandler(workspaceManager, database))
  server.registerTool(artifactDownloadToolDefinition, createArtifactDownloadHandler(database, { storageManager, workspaceManager }))

  // ── LLM ────────────────────────────────────────────────────────────────
  server.registerTool(llmAnalyzeToolDefinition, createLlmAnalyzeHandler(server))

  // ── PE analysis ────────────────────────────────────────────────────────

  // ── Strings ────────────────────────────────────────────────────────────
  server.registerTool(stringsExtractToolDefinition, createStringsExtractHandler(workspaceManager, database, cacheManager, jobQueue))
  server.registerTool(stringsFlossDecodeToolDefinition, createStringsFlossDecodeHandler(workspaceManager, database, cacheManager, jobQueue))

  // ── Static analysis ────────────────────────────────────────────────────
  server.registerTool(analysisContextLinkToolDefinition, createAnalysisContextLinkHandler(workspaceManager, database, cacheManager, {}, jobQueue))
  server.registerTool(yaraScanToolDefinition, createYaraScanHandler(workspaceManager, database, cacheManager))
  server.registerTool(runtimeDetectToolDefinition, createRuntimeDetectHandler(workspaceManager, database, cacheManager))
  server.registerTool(dotNetMetadataExtractToolDefinition, createDotNetMetadataExtractHandler(workspaceManager, database, cacheManager))
  server.registerTool(dotNetTypesListToolDefinition, createDotNetTypesListHandler(workspaceManager, database, cacheManager))
  server.registerTool(packerDetectToolDefinition, createPackerDetectHandler(workspaceManager, database, cacheManager))
  server.registerTool(staticCapabilityTriageToolDefinition, createStaticCapabilityTriageHandler(workspaceManager, database))
  server.registerTool(compilerPackerDetectToolDefinition, createCompilerPackerDetectHandler(workspaceManager, database))
  server.registerTool(binaryRoleProfileToolDefinition, createBinaryRoleProfileHandler(workspaceManager, database, cacheManager, undefined, jobQueue))
  server.registerTool(cryptoIdentifyToolDefinition, createCryptoIdentifyHandler(workspaceManager, database, cacheManager, {}, jobQueue))
  server.registerTool(breakpointSmartToolDefinition, createBreakpointSmartHandler(workspaceManager, database, cacheManager))
  server.registerTool(traceConditionToolDefinition, createTraceConditionHandler(workspaceManager, database, cacheManager))
  server.registerTool(dllExportProfileToolDefinition, createDllExportProfileHandler(workspaceManager, database, cacheManager))
  server.registerTool(comRoleProfileToolDefinition, createComRoleProfileHandler(workspaceManager, database, cacheManager))
  server.registerTool(rustBinaryAnalyzeToolDefinition, createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager))

  // ── Workflows ──────────────────────────────────────────────────────────
  server.registerTool(triageWorkflowToolDefinition, createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
    analyzeStart: createAnalyzeWorkflowStartHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue),
  }))
  server.registerTool(analyzeWorkflowStartToolDefinition, createAnalyzeWorkflowStartHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(analyzeWorkflowStatusToolDefinition, createAnalyzeWorkflowStatusHandler(database, {}, jobQueue))
  server.registerTool(analyzeWorkflowPromoteToolDefinition, createAnalyzeWorkflowPromoteHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(analyzeAutoWorkflowToolDefinition, createAnalyzeAutoWorkflowHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(reconstructWorkflowToolDefinition, createReconstructWorkflowHandler(workspaceManager, database, cacheManager, undefined, jobQueue))
  server.registerTool(deepStaticWorkflowToolDefinition, createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager, jobQueue))
  server.registerTool(functionIndexRecoverWorkflowToolDefinition, createFunctionIndexRecoverWorkflowHandler(workspaceManager, database, cacheManager))
  server.registerTool(semanticNameReviewWorkflowToolDefinition, createSemanticNameReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))
  server.registerTool(functionExplanationReviewWorkflowToolDefinition, createFunctionExplanationReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))
  server.registerTool(moduleReconstructionReviewWorkflowToolDefinition, createModuleReconstructionReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))

  // ── Reports ────────────────────────────────────────────────────────────
  server.registerTool(reportSummarizeToolDefinition, createReportSummarizeHandler(workspaceManager, database, cacheManager))
  server.registerTool(workflowSummarizeToolDefinition, createWorkflowSummarizeHandler(workspaceManager, database, cacheManager, server))
  server.registerTool(reportGenerateToolDefinition, createReportGenerateHandler(workspaceManager, database, cacheManager))

  // ── Task management ─────────────────────────────────────────────────────
  // (Ghidra tools are now registered via the ghidra plugin)
  server.registerTool(taskStatusToolDefinition, createTaskStatusHandler(jobQueue, database))
  server.registerTool(taskCancelToolDefinition, createTaskCancelHandler(jobQueue))
  server.registerTool(taskSweepToolDefinition, createTaskSweepHandler(jobQueue, database))

  // ── System health & setup ──────────────────────────────────────────────
  const systemHealthHandler = createSystemHealthHandler(workspaceManager, database, { cacheManager })
  const systemSetupGuideHandler = createSystemSetupGuideHandler()
  server.registerTool(systemHealthToolDefinition, systemHealthHandler)
  server.registerTool(systemSetupGuideToolDefinition, systemSetupGuideHandler)
  server.registerTool(setupRemediateToolDefinition, createSetupRemediateHandler(workspaceManager, database, cacheManager, {
    healthHandler: systemHealthHandler,
    setupGuideHandler: systemSetupGuideHandler,
  }))

  // ── Dynamic analysis ───────────────────────────────────────────────────
  server.registerTool(dynamicDependenciesToolDefinition, createDynamicDependenciesHandler(workspaceManager, database))
  server.registerTool(dynamicTraceImportToolDefinition, createDynamicTraceImportHandler(workspaceManager, database))
  server.registerTool(dynamicMemoryImportToolDefinition, createDynamicMemoryImportHandler(workspaceManager, database))
  server.registerTool(sandboxExecuteToolDefinition, createSandboxExecuteHandler(workspaceManager, database, policyGuard))

  // ── Docker backend tools ───────────────────────────────────────────────
  server.registerTool(graphvizRenderToolDefinition, createGraphvizRenderHandler(workspaceManager, database))
  server.registerTool(rizinAnalyzeToolDefinition, createRizinAnalyzeHandler(workspaceManager, database))
  server.registerTool(yaraXScanToolDefinition, createYaraXScanHandler(workspaceManager, database))
  server.registerTool(upxInspectToolDefinition, createUPXInspectHandler(workspaceManager, database))
  server.registerTool(retdecDecompileToolDefinition, createRetDecDecompileHandler(workspaceManager, database))
  server.registerTool(angrAnalyzeToolDefinition, createAngrAnalyzeHandler(workspaceManager, database))
  server.registerTool(qilingInspectToolDefinition, createQilingInspectHandler(workspaceManager, database))
  server.registerTool(pandaInspectToolDefinition, createPandaInspectHandler(workspaceManager, database))
  server.registerTool(wineRunToolDefinition, createWineRunHandler(workspaceManager, database))

  // ── Threat intel & reporting ───────────────────────────────────────────
  server.registerTool(toolHelpToolDefinition, createToolHelpHandler(() => server.getToolDefinitions()))

  // ── Code analysis ──────────────────────────────────────────────────────
  server.registerTool(codeFunctionsListToolDefinition, createCodeFunctionsListHandler(workspaceManager, database))
  server.registerTool(codeFunctionsRankToolDefinition, createCodeFunctionsRankHandler(workspaceManager, database))
  server.registerTool(codeFunctionsSmartRecoverToolDefinition, createCodeFunctionsSmartRecoverHandler(workspaceManager, database, cacheManager))
  server.registerTool(codeFunctionsDefineToolDefinition, createCodeFunctionsDefineHandler(workspaceManager, database))
  server.registerTool(codeFunctionsSearchToolDefinition, createCodeFunctionsSearchHandler(workspaceManager, database))
  server.registerTool(codeXrefsAnalyzeToolDefinition, createCodeXrefsAnalyzeHandler(workspaceManager, database, cacheManager))
  server.registerTool(codeFunctionDecompileToolDefinition, createCodeFunctionDecompileHandler(workspaceManager, database))
  server.registerTool(codeFunctionDisassembleToolDefinition, createCodeFunctionDisassembleHandler(workspaceManager, database))
  server.registerTool(codeFunctionCFGToolDefinition, createCodeFunctionCFGHandler(workspaceManager, database))
  server.registerTool(codeFunctionsReconstructToolDefinition, createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager))
  server.registerTool(codeFunctionRenamePrepareToolDefinition, createCodeFunctionRenamePrepareHandler(workspaceManager, database, cacheManager))
  server.registerTool(codeFunctionExplainPrepareToolDefinition, createCodeFunctionExplainPrepareHandler(workspaceManager, database, cacheManager))
  server.registerTool(codeFunctionExplainApplyToolDefinition, createCodeFunctionExplainApplyHandler(workspaceManager, database))
  server.registerTool(codeModuleReviewPrepareToolDefinition, createCodeModuleReviewPrepareHandler(workspaceManager, database, cacheManager))
  server.registerTool(codeModuleReviewApplyToolDefinition, createCodeModuleReviewApplyHandler(workspaceManager, database))
  server.registerTool(codeFunctionRenameApplyToolDefinition, createCodeFunctionRenameApplyHandler(workspaceManager, database))
  server.registerTool(codeReconstructExportToolDefinition, createCodeReconstructExportHandler(workspaceManager, database, cacheManager))
  server.registerTool(dotNetReconstructExportToolDefinition, createDotNetReconstructExportHandler(workspaceManager, database, cacheManager))
  server.registerTool(codeReconstructPlanToolDefinition, createCodeReconstructPlanHandler(workspaceManager, database, cacheManager))

  // ── Unpacking / diffing / YARA ─────────────────────────────────────────
  server.registerTool(unpackAutoToolDefinition, createUnpackAutoHandler(workspaceManager, database))
  server.registerTool(binaryDiffToolDefinition, createBinaryDiffHandler(workspaceManager, database))
  server.registerTool(binaryDiffSummaryToolDefinition, createBinaryDiffSummaryHandler(workspaceManager, database))
  server.registerTool(yaraGenerateToolDefinition, createYaraGenerateHandler(workspaceManager, database))
  server.registerTool(yaraGenerateBatchToolDefinition, createYaraGenerateBatchHandler(workspaceManager, database))

  // ── Vulnerability scanning ─────────────────────────────────────────────

  // ── Knowledge base ─────────────────────────────────────────────────────
  server.registerTool(kbImportBulkToolDefinition, createKbImportBulkHandler(workspaceManager, database))
  server.registerTool(kbExportToolDefinition, createKbExportHandler(workspaceManager, database))
  server.registerTool(kbImportToolDefinition, createKbImportHandler(workspaceManager, database))
  server.registerTool(kbStatsToolDefinition, createKbStatsHandler(workspaceManager, database))

  // ── ELF / Mach-O ──────────────────────────────────────────────────────
  server.registerTool(elfStructureAnalyzeToolDefinition, createElfStructureAnalyzeHandler(workspaceManager, database))
  server.registerTool(machoStructureAnalyzeToolDefinition, createMachoStructureAnalyzeHandler(workspaceManager, database))
  server.registerTool(elfImportsExtractToolDefinition, createElfImportsExtractHandler(workspaceManager, database))
  server.registerTool(elfExportsExtractToolDefinition, createElfExportsExtractHandler(workspaceManager, database))

  // ── Debug sessions ─────────────────────────────────────────────────────

  // ── VM / constraint solving ────────────────────────────────────────────
  server.registerTool(vmDetectToolDefinition, createVmDetectHandler(workspaceManager, database))
  server.registerTool(vmPatternAnalyzeToolDefinition, createVmPatternAnalyzeHandler(workspaceManager, database))
  server.registerTool(vmOpcodeExtractToolDefinition, createVmOpcodeExtractHandler(workspaceManager, database))
  server.registerTool(vmDisasmBuildToolDefinition, createVmDisasmBuildHandler(workspaceManager, database))
  server.registerTool(vmEmulateToolDefinition, createVmEmulateHandler(workspaceManager, database))
  server.registerTool(vmSemanticDiffToolDefinition, createVmSemanticDiffHandler(workspaceManager, database))
  server.registerTool(constraintExtractToolDefinition, createConstraintExtractHandler(workspaceManager, database))
  server.registerTool(smtSolveToolDefinition, createSmtSolveHandler(workspaceManager, database))
  server.registerTool(keygenSynthesizeToolDefinition, createKeygenSynthesizeHandler(workspaceManager, database))
  server.registerTool(mbaSimplifyToolDefinition, createMbaSimplifyHandler(workspaceManager, database))

  // ── v2.0 �?Plugin-managed tools ─────────────────────────────────────────
  // Android, CrackMe, Dynamic, Malware, Frida, Ghidra, Cross-module,
  // Visualization, and KB tools are all loaded via the plugin system.
  // Enabled/disabled via PLUGINS env var (default: all enabled).
  // ── v2.0 �?Plugin-managed tools ─────────────────────────────────────────
  // All plugin tools are auto-discovered from src/plugins/<id>/index.ts
  // Plugin deps include utility functions so plugins have zero server imports.
  const pluginDeps = {
    ...deps,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
    resolvePackagePath,
    generateCacheKey,
    DecompilerWorker,
    getGhidraDiagnostics,
    normalizeGhidraError,
    findBestGhidraAnalysis,
    getGhidraReadiness,
    parseGhidraAnalysisMetadata,
    buildPollingGuidance,
    PollingGuidanceSchema,
    SetupActionSchema,
    RequiredUserInputSchema,
    logger: serverLogger,
  }
  await loadPlugins(server, pluginDeps as any)

  // Wire PluginManager into server for lifecycle hooks
  server.setPluginManager(getPluginManager())

  // ── Plugin introspection tools ─────────────────────────────────────────
  server.registerTool(pluginListToolDefinition, createPluginListHandler(server))
  server.registerTool(pluginEnableToolDefinition, createPluginEnableHandler(server))
  server.registerTool(pluginDisableToolDefinition, createPluginDisableHandler(server))

  // ── System diagnostics tools ───────────────────────────────────────────
  server.registerTool(configValidateToolDefinition, createConfigValidateHandler(server))

  // ── SBOM generation ────────────────────────────────────────────────────
  server.registerTool(sbomGenerateToolDefinition, createSbomGenerateHandler(workspaceManager, database))

  // ── Batch analysis ─────────────────────────────────────────────────────
  server.registerTool(batchSubmitToolDefinition, createBatchSubmitHandler(server, database))
  server.registerTool(batchStatusToolDefinition, createBatchStatusHandler())
  server.registerTool(batchResultsToolDefinition, createBatchResultsHandler())

  // ══════════════════════════════════════════════════════════════════════════
  // MCP Resources �?read-only content exposed to clients
  // ══════════════════════════════════════════════════════════════════════════
  registerScriptResources(server)
}

// ============================================================================
// Script Resources �?expose Frida / Ghidra scripts as readable MCP resources
// ============================================================================

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = path.resolve(__dirname, '..')

interface ScriptEntry {
  uri: string
  name: string
  description: string
  mimeType: string
  filePath: string
}

const FRIDA_SCRIPTS: ScriptEntry[] = [
  { uri: 'script://frida/anti_debug_bypass', name: 'Frida: Anti-Debug Bypass', description: 'Bypass common anti-debugging techniques', mimeType: 'application/javascript', filePath: 'frida_scripts/anti_debug_bypass.js' },
  { uri: 'script://frida/api_trace', name: 'Frida: API Trace', description: 'Trace Windows API calls at runtime', mimeType: 'application/javascript', filePath: 'frida_scripts/api_trace.js' },
  { uri: 'script://frida/crypto_finder', name: 'Frida: Crypto Finder', description: 'Detect cryptographic operations at runtime', mimeType: 'application/javascript', filePath: 'frida_scripts/crypto_finder.js' },
  { uri: 'script://frida/file_registry_monitor', name: 'Frida: File/Registry Monitor', description: 'Monitor file and registry access', mimeType: 'application/javascript', filePath: 'frida_scripts/file_registry_monitor.js' },
  { uri: 'script://frida/string_decoder', name: 'Frida: String Decoder', description: 'Decode obfuscated strings at runtime', mimeType: 'application/javascript', filePath: 'frida_scripts/string_decoder.js' },
  { uri: 'script://frida/android_crypto_trace', name: 'Frida: Android Crypto Trace', description: 'Trace Android crypto API calls', mimeType: 'application/javascript', filePath: 'frida_scripts/android_crypto_trace.js' },
  { uri: 'script://frida/android_root_bypass', name: 'Frida: Android Root Bypass', description: 'Bypass Android root detection', mimeType: 'application/javascript', filePath: 'frida_scripts/android_root_bypass.js' },
  { uri: 'script://frida/android_ssl_bypass', name: 'Frida: Android SSL Bypass', description: 'Bypass Android SSL pinning', mimeType: 'application/javascript', filePath: 'frida_scripts/android_ssl_bypass.js' },
]

const GHIDRA_SCRIPTS: ScriptEntry[] = [
  { uri: 'script://ghidra/AnalyzeCrossReferences', name: 'Ghidra: Analyze Cross References', description: 'Extract cross-reference data from Ghidra project', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/AnalyzeCrossReferences.java' },
  { uri: 'script://ghidra/DecompileFunction', name: 'Ghidra: Decompile Function (Java)', description: 'Decompile specific function via Ghidra headless', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/DecompileFunction.java' },
  { uri: 'script://ghidra/ExtractCFG', name: 'Ghidra: Extract CFG (Java)', description: 'Extract control flow graph from Ghidra', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/ExtractCFG.java' },
  { uri: 'script://ghidra/ExtractFunctions', name: 'Ghidra: Extract Functions (Java)', description: 'List all functions from Ghidra project', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/ExtractFunctions.java' },
  { uri: 'script://ghidra/SearchFunctionReferences', name: 'Ghidra: Search Function References', description: 'Search for function references in Ghidra', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/SearchFunctionReferences.java' },
  { uri: 'script://ghidra/DecompileFunction_py', name: 'Ghidra: Decompile Function (Python)', description: 'Decompile function via Ghidra Python', mimeType: 'text/x-python', filePath: 'ghidra_scripts/DecompileFunction.py' },
  { uri: 'script://ghidra/ExtractCFG_py', name: 'Ghidra: Extract CFG (Python)', description: 'Extract CFG via Ghidra Python', mimeType: 'text/x-python', filePath: 'ghidra_scripts/ExtractCFG.py' },
  { uri: 'script://ghidra/ExtractFunctions_py', name: 'Ghidra: Extract Functions (Python)', description: 'List functions via Ghidra Python', mimeType: 'text/x-python', filePath: 'ghidra_scripts/ExtractFunctions.py' },
]

function registerScriptResources(server: MCPServer): void {
  for (const entry of [...FRIDA_SCRIPTS, ...GHIDRA_SCRIPTS]) {
    const absPath = path.join(PROJECT_ROOT, entry.filePath)
    server.registerResource(
      { uri: entry.uri, name: entry.name, description: entry.description, mimeType: entry.mimeType },
      async () => {
        const text = await fs.readFile(absPath, 'utf8')
        return { uri: entry.uri, mimeType: entry.mimeType, text }
      },
    )
  }
}
