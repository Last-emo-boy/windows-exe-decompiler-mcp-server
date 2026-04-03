/**
 * apk.structure.analyze MCP tool — analyze APK structure, manifest, DEX files,
 * native libraries, and packer indicators.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'apk.structure.analyze'

export const ApkStructureAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
})

export const ApkStructureAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const apkStructureAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze APK structure: AndroidManifest.xml, DEX files, native libraries (.so), signing info, and packer/hardening indicators (360, Bangbang, Legu, etc.).',
  inputSchema: ApkStructureAnalyzeInputSchema,
  outputSchema: ApkStructureAnalyzeOutputSchema,
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
      try {
        resolve(JSON.parse(stdout.trim()))
      } catch (e) {
        reject(new Error(`Failed to parse APK worker response: ${(e as Error).message}`))
      }
    })

    proc.on('error', (e) => reject(new Error(`Failed to spawn APK worker: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createApkStructureAnalyzeHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, config, resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath } = deps
  const pythonCmd = config.workers.static.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')
  const workerPath = resolvePackagePath('workers', 'apk_dex_worker.py')
  return async (args: z.infer<typeof ApkStructureAnalyzeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)
      const result = await callApkWorker({ action: 'parse_apk', file_path: samplePath }, pythonCmd, workerPath)

      if (!result.ok) {
        return { ok: false, errors: [String(result.error || 'APK parsing failed')] }
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id,
          'apk_structure', 'apk-structure', result
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
