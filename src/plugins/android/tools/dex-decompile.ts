/**
 * dex.decompile MCP tool — decompile DEX/APK via jadx, with optional class filter.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'dex.decompile'

export const DexDecompileInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  class_filter: z.string().optional().describe('Substring filter for class names (e.g. "com.example.Main")'),
})

export const DexDecompileOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const dexDecompileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile DEX bytecode to Java source using jadx. Supports APK files (auto-extracts DEX) and standalone .dex files. Optional class_filter to narrow output.',
  inputSchema: DexDecompileInputSchema,
  outputSchema: DexDecompileOutputSchema,
}

async function callApkWorker(request: Record<string, unknown>, pythonCmd: string, workerPath: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })

    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`APK worker exited with code ${code}: ${stderr}`))
        return
      }
      try { resolve(JSON.parse(stdout.trim())) }
      catch (e) { reject(new Error(`Parse error: ${(e as Error).message}`)) }
    })
    proc.on('error', (e) => reject(new Error(`Spawn error: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createDexDecompileHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, config, resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath } = deps
  const pythonCmd = config.workers.static.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')
  const workerPath = resolvePackagePath('workers', 'apk_dex_worker.py')
  return async (args: z.infer<typeof DexDecompileInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)
      const result = await callApkWorker({
        action: 'decompile_dex',
        file_path: samplePath,
        class_filter: args.class_filter ?? null,
      }, pythonCmd, workerPath)

      if (!result.ok) {
        return { ok: false, errors: [String(result.error || 'DEX decompilation failed')] }
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id,
          'dex_decompilation', 'dex-decompile', result
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: result,
        artifacts,
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
