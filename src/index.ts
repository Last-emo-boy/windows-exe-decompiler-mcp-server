/**
 * Windows EXE Decompiler MCP Server
 * Entry point
 */

import { MCPServer } from './server.js'
import { loadConfig } from './config.js'
import { WorkspaceManager } from './workspace-manager.js'
import { DatabaseManager } from './database.js'
import { PolicyGuard } from './policy-guard.js'
import { CacheManager } from './cache-manager.js'
import { JobQueue } from './job-queue.js'
import { AnalysisTaskRunner } from './analysis-task-runner.js'
import { 
  sampleIngestToolDefinition, 
  createSampleIngestHandler 
} from './tools/sample-ingest.js'
import {
  sampleProfileGetToolDefinition,
  createSampleProfileGetHandler
} from './tools/sample-profile-get.js'
import {
  artifactReadToolDefinition,
  createArtifactReadHandler
} from './tools/artifact-read.js'
import {
  artifactsListToolDefinition,
  createArtifactsListHandler
} from './tools/artifacts-list.js'
import {
  artifactsDiffToolDefinition,
  createArtifactsDiffHandler
} from './tools/artifacts-diff.js'
import {
  peFingerprintToolDefinition,
  createPEFingerprintHandler
} from './tools/pe-fingerprint.js'
import {
  peImportsExtractToolDefinition,
  createPEImportsExtractHandler
} from './tools/pe-imports-extract.js'
import {
  peExportsExtractToolDefinition,
  createPEExportsExtractHandler
} from './tools/pe-exports-extract.js'
import {
  pePdataExtractToolDefinition,
  createPEPdataExtractHandler,
} from './tools/pe-pdata-extract.js'
import {
  peSymbolsRecoverToolDefinition,
  createPESymbolsRecoverHandler,
} from './tools/pe-symbols-recover.js'
import {
  stringsExtractToolDefinition,
  createStringsExtractHandler
} from './tools/strings-extract.js'
import {
  stringsFlossDecodeToolDefinition,
  createStringsFlossDecodeHandler
} from './tools/strings-floss-decode.js'
import {
  yaraScanToolDefinition,
  createYaraScanHandler
} from './tools/yara-scan.js'
import {
  runtimeDetectToolDefinition,
  createRuntimeDetectHandler
} from './tools/runtime-detect.js'
import {
  dotNetMetadataExtractToolDefinition,
  createDotNetMetadataExtractHandler
} from './tools/dotnet-metadata-extract.js'
import {
  dotNetTypesListToolDefinition,
  createDotNetTypesListHandler
} from './tools/dotnet-types-list.js'
import {
  packerDetectToolDefinition,
  createPackerDetectHandler
} from './tools/packer-detect.js'
import {
  binaryRoleProfileToolDefinition,
  createBinaryRoleProfileHandler,
} from './tools/binary-role-profile.js'
import {
  dllExportProfileToolDefinition,
  createDllExportProfileHandler,
} from './tools/dll-export-profile.js'
import {
  comRoleProfileToolDefinition,
  createComRoleProfileHandler,
} from './tools/com-role-profile.js'
import {
  rustBinaryAnalyzeToolDefinition,
  createRustBinaryAnalyzeHandler,
} from './tools/rust-binary-analyze.js'
import {
  triageWorkflowToolDefinition,
  createTriageWorkflowHandler
} from './workflows/triage.js'
import {
  reconstructWorkflowToolDefinition,
  createReconstructWorkflowHandler
} from './workflows/reconstruct.js'
import {
  deepStaticWorkflowToolDefinition,
  createDeepStaticWorkflowHandler
} from './workflows/deep-static.js'
import {
  functionIndexRecoverWorkflowToolDefinition,
  createFunctionIndexRecoverWorkflowHandler,
} from './workflows/function-index-recover.js'
import {
  semanticNameReviewWorkflowToolDefinition,
  createSemanticNameReviewWorkflowHandler,
} from './workflows/semantic-name-review.js'
import {
  functionExplanationReviewWorkflowToolDefinition,
  createFunctionExplanationReviewWorkflowHandler,
} from './workflows/function-explanation-review.js'
import {
  reportSummarizeToolDefinition,
  createReportSummarizeHandler
} from './tools/report-summarize.js'
import {
  reportGenerateToolDefinition,
  createReportGenerateHandler
} from './tools/report-generate.js'
import {
  toolHelpToolDefinition,
  createToolHelpHandler
} from './tools/tool-help.js'
import {
  ghidraAnalyzeToolDefinition,
  createGhidraAnalyzeHandler
} from './tools/ghidra-analyze.js'
import {
  ghidraHealthToolDefinition,
  createGhidraHealthHandler
} from './tools/ghidra-health.js'
import {
  systemHealthToolDefinition,
  createSystemHealthHandler
} from './tools/system-health.js'
import {
  systemSetupGuideToolDefinition,
  createSystemSetupGuideHandler,
} from './tools/system-setup-guide.js'
import {
  dynamicDependenciesToolDefinition,
  createDynamicDependenciesHandler
} from './tools/dynamic-dependencies.js'
import {
  dynamicTraceImportToolDefinition,
  createDynamicTraceImportHandler
} from './tools/dynamic-trace-import.js'
import {
  dynamicMemoryImportToolDefinition,
  createDynamicMemoryImportHandler
} from './tools/dynamic-memory-import.js'
import {
  sandboxExecuteToolDefinition,
  createSandboxExecuteHandler
} from './tools/sandbox-execute.js'
import {
  attackMapToolDefinition,
  createAttackMapHandler
} from './tools/attack-map.js'
import {
  iocExportToolDefinition,
  createIOCExportHandler
} from './tools/ioc-export.js'
import {
  taskStatusToolDefinition,
  createTaskStatusHandler
} from './tools/task-status.js'
import {
  taskCancelToolDefinition,
  createTaskCancelHandler
} from './tools/task-cancel.js'
import {
  taskSweepToolDefinition,
  createTaskSweepHandler
} from './tools/task-sweep.js'
import {
  codeFunctionsListToolDefinition,
  createCodeFunctionsListHandler
} from './tools/code-functions-list.js'
import {
  codeFunctionsRankToolDefinition,
  createCodeFunctionsRankHandler
} from './tools/code-functions-rank.js'
import {
  codeFunctionsSmartRecoverToolDefinition,
  createCodeFunctionsSmartRecoverHandler,
} from './tools/code-functions-smart-recover.js'
import {
  codeFunctionsDefineToolDefinition,
  createCodeFunctionsDefineHandler,
} from './tools/code-functions-define.js'
import {
  codeFunctionsSearchToolDefinition,
  createCodeFunctionsSearchHandler
} from './tools/code-functions-search.js'
import {
  codeFunctionDecompileToolDefinition,
  createCodeFunctionDecompileHandler
} from './tools/code-function-decompile.js'
import {
  codeFunctionDisassembleToolDefinition,
  createCodeFunctionDisassembleHandler
} from './tools/code-function-disassemble.js'
import {
  codeFunctionCFGToolDefinition,
  createCodeFunctionCFGHandler
} from './tools/code-function-cfg.js'
import {
  codeFunctionsReconstructToolDefinition,
  createCodeFunctionsReconstructHandler
} from './tools/code-functions-reconstruct.js'
import {
  codeFunctionRenamePrepareToolDefinition,
  createCodeFunctionRenamePrepareHandler,
} from './tools/code-function-rename-prepare.js'
import {
  codeFunctionExplainPrepareToolDefinition,
  createCodeFunctionExplainPrepareHandler,
} from './tools/code-function-explain-prepare.js'
import {
  codeFunctionExplainApplyToolDefinition,
  createCodeFunctionExplainApplyHandler,
} from './tools/code-function-explain-apply.js'
import {
  codeFunctionExplainReviewToolDefinition,
  createCodeFunctionExplainReviewHandler,
} from './tools/code-function-explain-review.js'
import {
  codeFunctionRenameApplyToolDefinition,
  createCodeFunctionRenameApplyHandler,
} from './tools/code-function-rename-apply.js'
import {
  codeFunctionRenameReviewToolDefinition,
  createCodeFunctionRenameReviewHandler,
} from './tools/code-function-rename-review.js'
import {
  codeReconstructExportToolDefinition,
  createCodeReconstructExportHandler
} from './tools/code-reconstruct-export.js'
import {
  dotNetReconstructExportToolDefinition,
  createDotNetReconstructExportHandler
} from './tools/dotnet-reconstruct-export.js'
import {
  codeReconstructPlanToolDefinition,
  createCodeReconstructPlanHandler
} from './tools/code-reconstruct-plan.js'
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
import {
  codeModuleReviewPrepareToolDefinition,
  createCodeModuleReviewPrepareHandler,
} from './tools/code-module-review-prepare.js'
import {
  codeModuleReviewApplyToolDefinition,
  createCodeModuleReviewApplyHandler,
} from './tools/code-module-review-apply.js'
import {
  codeModuleReviewToolDefinition,
  createCodeModuleReviewHandler,
} from './tools/code-module-review.js'
import {
  moduleReconstructionReviewWorkflowToolDefinition,
  createModuleReconstructionReviewWorkflowHandler,
} from './workflows/module-reconstruction-review.js'

// Export public API
export { MCPServer } from './server.js'
export { loadConfig } from './config.js'
export { WorkspaceManager } from './workspace-manager.js'
export * from './types.js'

async function main() {
  try {
    // Load configuration
    const configPath = process.env.CONFIG_PATH
    const config = loadConfig(configPath)

    // Initialize components
    const workspaceManager = new WorkspaceManager(config.workspace.root)
    const database = new DatabaseManager(config.database.path)
    const policyGuard = new PolicyGuard(config.logging.auditPath)
    const cacheManager = new CacheManager(config.cache.root, database)
    const jobQueue = new JobQueue()
    const analysisTaskRunner = new AnalysisTaskRunner(jobQueue, database, workspaceManager, cacheManager)
    analysisTaskRunner.start()

    // Create and start MCP server
    const server = new MCPServer(config)

    // Register tools
    server.registerPrompt(
      semanticNameReviewPromptDefinition,
      createSemanticNameReviewPromptHandler()
    )
    server.registerPrompt(
      functionExplanationReviewPromptDefinition,
      createFunctionExplanationReviewPromptHandler()
    )
    server.registerPrompt(
      moduleReconstructionReviewPromptDefinition,
      createModuleReconstructionReviewPromptHandler()
    )

    // Task 8.1: sample.ingest tool
    server.registerTool(
      sampleIngestToolDefinition,
      createSampleIngestHandler(workspaceManager, database, policyGuard)
    )

    // Task 8.2: sample.profile.get tool
    server.registerTool(
      sampleProfileGetToolDefinition,
      createSampleProfileGetHandler(database, workspaceManager)
    )

    // Task 18.15: artifact.read tool - Read manifest/gaps and other artifacts via MCP
    server.registerTool(
      artifactReadToolDefinition,
      createArtifactReadHandler(workspaceManager, database)
    )

    // Task 18.18: artifacts.list tool - Enumerate artifact inventory with existence metadata
    server.registerTool(
      artifactsListToolDefinition,
      createArtifactsListHandler(workspaceManager, database)
    )

    server.registerTool(
      artifactsDiffToolDefinition,
      createArtifactsDiffHandler(workspaceManager, database)
    )

    // Task 8.3: pe.fingerprint tool
    server.registerTool(
      peFingerprintToolDefinition,
      createPEFingerprintHandler(workspaceManager, database, cacheManager)
    )

    // Task 8.4: pe.imports.extract tool
    server.registerTool(
      peImportsExtractToolDefinition,
      createPEImportsExtractHandler(workspaceManager, database, cacheManager)
    )

    // Task 8.5: pe.exports.extract tool
    server.registerTool(
      peExportsExtractToolDefinition,
      createPEExportsExtractHandler(workspaceManager, database, cacheManager)
    )

    server.registerTool(
      pePdataExtractToolDefinition,
      createPEPdataExtractHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      peSymbolsRecoverToolDefinition,
      createPESymbolsRecoverHandler(workspaceManager, database, cacheManager)
    )

    // Task 8.6: strings.extract tool
    server.registerTool(
      stringsExtractToolDefinition,
      createStringsExtractHandler(workspaceManager, database, cacheManager)
    )

    // Task 8.7: strings.floss.decode tool
    server.registerTool(
      stringsFlossDecodeToolDefinition,
      createStringsFlossDecodeHandler(workspaceManager, database, cacheManager)
    )

    // Task 8.8: yara.scan tool
    server.registerTool(
      yaraScanToolDefinition,
      createYaraScanHandler(workspaceManager, database, cacheManager)
    )

    // Task 8.9: runtime.detect tool
    server.registerTool(
      runtimeDetectToolDefinition,
      createRuntimeDetectHandler(workspaceManager, database, cacheManager)
    )

    server.registerTool(
      dotNetMetadataExtractToolDefinition,
      createDotNetMetadataExtractHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      dotNetTypesListToolDefinition,
      createDotNetTypesListHandler(workspaceManager, database, cacheManager)
    )

    // Task 8.10: packer.detect tool
    server.registerTool(
      packerDetectToolDefinition,
      createPackerDetectHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      binaryRoleProfileToolDefinition,
      createBinaryRoleProfileHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      dllExportProfileToolDefinition,
      createDllExportProfileHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      comRoleProfileToolDefinition,
      createComRoleProfileHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      rustBinaryAnalyzeToolDefinition,
      createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager)
    )

    // Task 9.1: workflow.triage - Quick triage workflow
    server.registerTool(
      triageWorkflowToolDefinition,
      createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    )

    // Task 40.5.1: workflow.reconstruct - End-to-end source reconstruction workflow
    server.registerTool(
      reconstructWorkflowToolDefinition,
      createReconstructWorkflowHandler(workspaceManager, database, cacheManager, undefined, jobQueue)
    )

    // Task 16.x: workflow.deep_static - Comprehensive long-running static analysis
    server.registerTool(
      deepStaticWorkflowToolDefinition,
      createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager, jobQueue)
    )
    server.registerTool(
      functionIndexRecoverWorkflowToolDefinition,
      createFunctionIndexRecoverWorkflowHandler(workspaceManager, database, cacheManager)
    )

    server.registerTool(
      semanticNameReviewWorkflowToolDefinition,
      createSemanticNameReviewWorkflowHandler(
        workspaceManager,
        database,
        cacheManager,
        server,
        undefined,
        jobQueue
      )
    )
    server.registerTool(
      functionExplanationReviewWorkflowToolDefinition,
      createFunctionExplanationReviewWorkflowHandler(
        workspaceManager,
        database,
        cacheManager,
        server,
        undefined,
        jobQueue
      )
    )
    server.registerTool(
      moduleReconstructionReviewWorkflowToolDefinition,
      createModuleReconstructionReviewWorkflowHandler(
        workspaceManager,
        database,
        cacheManager,
        server,
        undefined,
        jobQueue
      )
    )

    // Task 9.2: report.summarize - Generate quick triage report
    server.registerTool(
      reportSummarizeToolDefinition,
      createReportSummarizeHandler(workspaceManager, database, cacheManager)
    )

    // Task 24.x: report.generate - Generate stored multi-stage analysis report artifact
    server.registerTool(
      reportGenerateToolDefinition,
      createReportGenerateHandler(workspaceManager, database, cacheManager)
    )

    // Task 15.1: ghidra.analyze - Analyze binary with Ghidra
    server.registerTool(
      ghidraAnalyzeToolDefinition,
      createGhidraAnalyzeHandler(workspaceManager, database, jobQueue)
    )

    // Task execution controls: query/cancel/sweep analysis jobs
    server.registerTool(
      taskStatusToolDefinition,
      createTaskStatusHandler(jobQueue)
    )
    server.registerTool(
      taskCancelToolDefinition,
      createTaskCancelHandler(jobQueue)
    )
    server.registerTool(
      taskSweepToolDefinition,
      createTaskSweepHandler(jobQueue, database)
    )

    // Task 15.1.1: ghidra.health - Validate Ghidra execution environment
    server.registerTool(
      ghidraHealthToolDefinition,
      createGhidraHealthHandler(workspaceManager, database)
    )

    // Task 40.5.2: system.health - Aggregated HA readiness health check
    server.registerTool(
      systemHealthToolDefinition,
      createSystemHealthHandler(workspaceManager, database, { cacheManager })
    )
    server.registerTool(
      systemSetupGuideToolDefinition,
      createSystemSetupGuideHandler()
    )

    // Task 18.22: dynamic.dependencies - probe dynamic-analysis component readiness
    server.registerTool(
      dynamicDependenciesToolDefinition,
      createDynamicDependenciesHandler(workspaceManager, database)
    )

    // Runtime evidence import: normalize external traces / memory summaries into MCP artifacts
    server.registerTool(
      dynamicTraceImportToolDefinition,
      createDynamicTraceImportHandler(workspaceManager, database)
    )

    // Memory snapshot ingest: normalize minidump / process-memory captures into runtime artifacts
    server.registerTool(
      dynamicMemoryImportToolDefinition,
      createDynamicMemoryImportHandler(workspaceManager, database)
    )

    // Task 31.2 (bootstrap): sandbox.execute - safe simulation-first dynamic analysis
    server.registerTool(
      sandboxExecuteToolDefinition,
      createSandboxExecuteHandler(workspaceManager, database, policyGuard)
    )

    // P1 enhancement: ATT&CK mapping from correlated static indicators
    server.registerTool(
      attackMapToolDefinition,
      createAttackMapHandler(workspaceManager, database, cacheManager)
    )

    // P2 productization: IOC export (JSON/CSV/STIX) for SOC/IR pipelines
    server.registerTool(
      iocExportToolDefinition,
      createIOCExportHandler(workspaceManager, database, cacheManager)
    )

    // Tool metadata help: query normalized schema/help for registered MCP tools
    server.registerTool(
      toolHelpToolDefinition,
      createToolHelpHandler(() => server.getToolDefinitions())
    )

    // Task 15.2: code.functions.list - List extracted functions
    server.registerTool(
      codeFunctionsListToolDefinition,
      createCodeFunctionsListHandler(workspaceManager, database)
    )

    // Task 15.3: code.functions.rank - Rank functions by interest
    server.registerTool(
      codeFunctionsRankToolDefinition,
      createCodeFunctionsRankHandler(workspaceManager, database)
    )

    server.registerTool(
      codeFunctionsSmartRecoverToolDefinition,
      createCodeFunctionsSmartRecoverHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      codeFunctionsDefineToolDefinition,
      createCodeFunctionsDefineHandler(workspaceManager, database)
    )

    server.registerTool(
      codeFunctionsSearchToolDefinition,
      createCodeFunctionsSearchHandler(workspaceManager, database)
    )

    // Task 15.4: code.function.decompile - Decompile specific function
    server.registerTool(
      codeFunctionDecompileToolDefinition,
      createCodeFunctionDecompileHandler(workspaceManager, database)
    )

    // Task 15.5: code.function.disassemble - Get assembly code
    server.registerTool(
      codeFunctionDisassembleToolDefinition,
      createCodeFunctionDisassembleHandler(workspaceManager, database)
    )

    // Task 15.6: code.function.cfg - Extract control flow graph
    server.registerTool(
      codeFunctionCFGToolDefinition,
      createCodeFunctionCFGHandler(workspaceManager, database)
    )

    // Task 40.2: code.functions.reconstruct - Function-level semantic reconstruction
    server.registerTool(
      codeFunctionsReconstructToolDefinition,
      createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager)
    )

    // External semantic naming workflow: prepare structured evidence for any MCP-capable LLM
    server.registerTool(
      codeFunctionRenamePrepareToolDefinition,
      createCodeFunctionRenamePrepareHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      codeFunctionExplainPrepareToolDefinition,
      createCodeFunctionExplainPrepareHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      codeFunctionExplainApplyToolDefinition,
      createCodeFunctionExplainApplyHandler(workspaceManager, database)
    )
    server.registerTool(
      codeModuleReviewPrepareToolDefinition,
      createCodeModuleReviewPrepareHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      codeModuleReviewApplyToolDefinition,
      createCodeModuleReviewApplyHandler(workspaceManager, database)
    )
    server.registerTool(
      codeModuleReviewToolDefinition,
      createCodeModuleReviewHandler(workspaceManager, database, cacheManager, server)
    )
    server.registerTool(
      codeFunctionExplainReviewToolDefinition,
      createCodeFunctionExplainReviewHandler(workspaceManager, database, cacheManager, server)
    )
    server.registerTool(
      codeFunctionRenameApplyToolDefinition,
      createCodeFunctionRenameApplyHandler(workspaceManager, database)
    )
    server.registerTool(
      codeFunctionRenameReviewToolDefinition,
      createCodeFunctionRenameReviewHandler(workspaceManager, database, cacheManager, server)
    )

    // Task 40.3: code.reconstruct.export - Module regrouping and skeleton export
    server.registerTool(
      codeReconstructExportToolDefinition,
      createCodeReconstructExportHandler(workspaceManager, database, cacheManager)
    )

    // Task 40.4.1: dotnet.reconstruct.export - .NET skeleton reconstruction baseline
    server.registerTool(
      dotNetReconstructExportToolDefinition,
      createDotNetReconstructExportHandler(workspaceManager, database, cacheManager)
    )

    // Task 40.1: code.reconstruct.plan - Source reconstruction planning
    server.registerTool(
      codeReconstructPlanToolDefinition,
      createCodeReconstructPlanHandler(workspaceManager, database, cacheManager)
    )

    // Start server
    await server.start()

    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      server.getLogger().info('Received SIGINT, shutting down gracefully')
      analysisTaskRunner.stop()
      await server.stop()
      process.exit(0)
    })

    process.on('SIGTERM', async () => {
      server.getLogger().info('Received SIGTERM, shutting down gracefully')
      analysisTaskRunner.stop()
      await server.stop()
      process.exit(0)
    })
  } catch (error) {
    console.error('Failed to start MCP Server:', error)
    process.exit(1)
  }
}

main()
