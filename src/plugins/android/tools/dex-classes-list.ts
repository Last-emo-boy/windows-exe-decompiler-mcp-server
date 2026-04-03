/**
 * dex.classes.list MCP tool — list classes from DEX / APK files.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'dex.classes.list'

export const DexClassesListInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
})

export const dexClassesListToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'List all class names defined in DEX bytecode. Works on standalone .dex or .apk (parses all embedded classes.dex files).',
  inputSchema: DexClassesListInputSchema,
}

async function callApkWorker(request: Record<string, unknown>, pythonCmd: string, workerPath: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('close', (code) => {
      if (code !== 0) { reject(new Error(`Worker exited ${code}: ${stderr}`)); return }
      try { resolve(JSON.parse(stdout.trim())) }
      catch (e) { reject(new Error(`Parse: ${(e as Error).message}`)) }
    })
    proc.on('error', (e) => reject(new Error(`Spawn: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createDexClassesListHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, config, resolvePrimarySamplePath, resolvePackagePath } = deps
  const pythonCmd = config.workers.static.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')
  const workerPath = resolvePackagePath('workers', 'apk_dex_worker.py')
  return async (args: z.infer<typeof DexClassesListInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)
      const result = await callApkWorker({ action: 'list_dex_classes', file_path: samplePath }, pythonCmd, workerPath)

      return {
        ok: true,
        data: result,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
