/**
 * Binary Analysis MCP Server
 * Universal reverse-engineering tool surface for PE, ELF, Mach-O, APK/DEX,
 * .NET, and more 鈥?exposed as reusable MCP tools for any tool-calling LLM.
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
import { StorageManager } from './storage/storage-manager.js'
import { registerAllTools } from './tool-registry.js'

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
    const storageManager = new StorageManager({
      root: config.api.storageRoot,
      maxFileSize: config.api.maxFileSize,
      retentionDays: config.api.retentionDays,
    })
    await storageManager.initialize()
    const jobQueue = new JobQueue(database)
    const analysisTaskRunner = new AnalysisTaskRunner(jobQueue, database, workspaceManager, cacheManager, policyGuard)
    analysisTaskRunner.start()

    // Create and start MCP server
    const server = new MCPServer(config, {
      workspaceManager,
      database,
      policyGuard,
      storageManager,
    })

    // Register all tools & prompts via the centralised registry
    await registerAllTools(server, {
      workspaceManager,
      database,
      policyGuard,
      cacheManager,
      jobQueue,
      storageManager,
      config,
      server,
    })

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
    process.stderr.write(`Failed to start MCP Server: ${error}\n`)
    process.exit(1)
  }
}

main()
