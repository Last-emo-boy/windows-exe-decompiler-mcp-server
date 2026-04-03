/**
 * apk.packer.detect MCP tool — detect Android packer/hardening solutions.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'apk.packer.detect'

export const ApkPackerDetectInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
})

export const apkPackerDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Detect Android packer/hardening solutions (360, Bangbang, Legu, iJiaMi, Ali, DexProtector, etc.) by checking native library signatures and DEX structure anomalies.',
  inputSchema: ApkPackerDetectInputSchema,
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

export function createApkPackerDetectHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, config, resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath } = deps
  const pythonCmd = config.workers.static.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')
  const workerPath = resolvePackagePath('workers', 'apk_dex_worker.py')
  return async (args: z.infer<typeof ApkPackerDetectInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)
      const result = await callApkWorker({ action: 'detect_packer', file_path: samplePath }, pythonCmd, workerPath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id,
          'apk_packer_detection', 'apk-packer-detect', result
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
