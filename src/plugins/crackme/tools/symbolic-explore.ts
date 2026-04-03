/**
 * symbolic.explore MCP tool — angr-based symbolic execution for CrackMe solving.
 * Explores paths to find/avoid target addresses, recovers concrete inputs.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'symbolic.explore'

export const SymbolicExploreInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  find_addresses: z.array(z.string()).min(1).describe('Target addresses to reach (hex, e.g. ["0x401234"])'),
  avoid_addresses: z.array(z.string()).optional().default([]).describe('Addresses to avoid (hex)'),
  start_address: z.string().optional().describe('Custom start address instead of entry point (hex)'),
  input_length: z.number().int().min(1).max(256).optional().default(32).describe('Symbolic input length in bytes'),
  timeout_sec: z.number().int().min(5).max(600).optional().default(60).describe('Exploration timeout in seconds'),
  stdin_mode: z.boolean().optional().default(true).describe('Use symbolic stdin as input'),
  argv_mode: z.boolean().optional().default(false).describe('Use symbolic argv[1] as input'),
})

export const symbolicExploreToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run angr symbolic execution to find inputs reaching target addresses (CrackMe solving). ' +
    'Specify find_addresses (success path) and avoid_addresses (failure path). ' +
    'Returns concrete input values that satisfy path constraints.',
  inputSchema: SymbolicExploreInputSchema,
}

async function callWorker(request: Record<string, unknown>, pythonCmd: string, resolvePackagePath: (...segments: string[]) => string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'symbolic_explorer_worker.py')
    const proc = spawn(pythonCmd, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: ((request.timeout_sec as number) ?? 60) * 1000 + 10000,
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

export function createSymbolicExploreHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, config, policyGuard, resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath } = deps

  const pythonCmd = config?.workers?.sandbox?.angrPythonPath || (process.platform === 'win32' ? 'python' : 'python3')
  return async (args: z.infer<typeof SymbolicExploreInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const policyDecision = await policyGuard.checkPermission(
        { type: 'dynamic_execution', tool: TOOL_NAME, args: { find_addresses: args.find_addresses } },
        { sampleId: args.sample_id, timestamp: new Date().toISOString() }
      )
      await policyGuard.auditLog({
        timestamp: new Date().toISOString(), operation: TOOL_NAME,
        sampleId: args.sample_id, decision: policyDecision.allowed ? 'allow' : 'deny',
        reason: policyDecision.reason,
      })
      if (!policyDecision.allowed) {
        return { ok: false, errors: [policyDecision.reason || 'Symbolic execution denied by policy guard.'], metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME } }
      }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)
      const result = await callWorker({
        action: 'explore',
        file_path: samplePath,
        find_addresses: args.find_addresses,
        avoid_addresses: args.avoid_addresses,
        start_address: args.start_address ?? null,
        input_length: args.input_length,
        timeout_sec: args.timeout_sec,
        stdin_mode: args.stdin_mode,
        argv_mode: args.argv_mode,
      }, pythonCmd, resolvePackagePath!)

      const artifacts: ArtifactRef[] = []
      if (result.ok) {
        try {
          const artRef = await persistStaticAnalysisJsonArtifact!(
            workspaceManager, database, args.sample_id,
            'symbolic_exploration', 'symbolic-explore', result
          )
          if (artRef) artifacts.push(artRef)
        } catch { /* non-fatal */ }
      }

      return {
        ok: Boolean(result.ok),
        data: result,
        errors: result.ok ? undefined : [String(result.error ?? 'Symbolic exploration failed')],
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
