/**
 * keygen.verify MCP tool — verify a synthesized keygen by running it in
 * Speakeasy/Qiling emulation and checking if the target validation passes.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'keygen.verify'

export const KeygenVerifyInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  serial: z.string().describe('Serial/key to verify against the validation function'),
  username: z.string().optional().describe('Username if the CrackMe requires one'),
  validation_address: z.string().optional().describe('Address of validation function (hex). Auto-detected if omitted.'),
  emulation_backend: z.enum(['speakeasy', 'qiling']).optional().default('speakeasy'),
  timeout_sec: z.number().int().min(5).max(120).optional().default(30),
})

export const keygenVerifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Verify a keygen-produced serial by emulating the target binary validation function. ' +
    'Feeds the serial (and optional username) into the binary via emulation and checks if the success path is taken.',
  inputSchema: KeygenVerifyInputSchema,
}

async function callVerifyWorker(request: Record<string, unknown>, pythonCmd: string, resolvePackagePath: (...segments: string[]) => string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'keygen_verify_worker.py')
    const proc = spawn(pythonCmd, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: ((request.timeout_sec as number) ?? 30) * 1000 + 10000,
    })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Worker exited ${code}: ${stderr.slice(0, 500)}`))
        return
      }
      try { resolve(JSON.parse(stdout.trim())) }
      catch (e) { reject(new Error(`Parse: ${(e as Error).message}`)) }
    })
    proc.on('error', (e) => reject(new Error(`Spawn: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createKeygenVerifyHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, config, policyGuard, resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath } = deps

  const pythonCmd = config?.workers?.sandbox?.qilingPythonPath || config?.workers?.static?.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')
  return async (args: z.infer<typeof KeygenVerifyInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const policyDecision = await policyGuard.checkPermission(
        { type: 'dynamic_execution', tool: TOOL_NAME, args: { backend: args.emulation_backend } },
        { sampleId: args.sample_id, timestamp: new Date().toISOString() }
      )
      await policyGuard.auditLog({
        timestamp: new Date().toISOString(), operation: TOOL_NAME,
        sampleId: args.sample_id, decision: policyDecision.allowed ? 'allow' : 'deny',
        reason: policyDecision.reason,
      })
      if (!policyDecision.allowed) {
        return { ok: false, errors: [policyDecision.reason || 'Keygen verification denied by policy guard.'], metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME } }
      }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      // Look for crackme locate results to auto-detect validation address
      let validationAddr = args.validation_address ?? null
      if (!validationAddr) {
        const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
        if (Array.isArray(evidence)) {
          for (const entry of evidence) {
            if (entry.evidence_family === 'crackme_validation_candidates') {
              try {
                const data = typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
                const candidates = data?.candidates ?? data?.data?.candidates ?? []
                if (candidates.length > 0) {
                  validationAddr = candidates[0].address
                }
              } catch { /* */ }
            }
          }
        }
      }

      const result = await callVerifyWorker({
        action: 'verify',
        file_path: samplePath,
        serial: args.serial,
        username: args.username ?? null,
        validation_address: validationAddr,
        backend: args.emulation_backend,
        timeout_sec: args.timeout_sec,
      }, pythonCmd, resolvePackagePath!)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'keygen_verification', 'keygen-verify', result
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: Boolean(result.ok),
        data: result,
        errors: result.ok ? undefined : [String(result.error ?? 'Verification failed')],
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
