/**
 * smt.solve MCP tool — solve extracted constraints using Z3 via Python worker.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { spawn } from 'child_process'
import path from 'path'

const TOOL_NAME = 'smt.solve'

export const smtSolveInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  z3_script: z.string().optional().describe('Custom Z3 Python script to execute (overrides auto-extracted constraints)'),
  timeout_ms: z.number().int().min(1000).max(300000).optional().default(30000).describe('Solver timeout in milliseconds'),
})

export const smtSolveOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const smtSolveToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Solve constraints using Z3 SMT solver. Uses previously extracted constraints or a custom Z3 script. Returns satisfiability result and variable solutions.',
  inputSchema: smtSolveInputSchema,
  outputSchema: smtSolveOutputSchema,
}

function invokeWorker(
  request: Record<string, unknown>
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = path.resolve(
      import.meta.dirname ?? '.',
      '../../workers/constraint_solver_worker.py'
    )

    const proc = spawn('python', [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    proc.stdout.on('data', (data: Buffer) => { stdout += data.toString() })
    proc.stderr.on('data', (data: Buffer) => { stderr += data.toString() })

    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Worker exited with code ${code}: ${stderr}`))
        return
      }
      try {
        const lines = stdout.trim().split('\n')
        const lastLine = lines[lines.length - 1]
        resolve(JSON.parse(lastLine))
      } catch (e) {
        reject(new Error(`Failed to parse worker output: ${stdout}`))
      }
    })

    proc.on('error', reject)

    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createSmtSolveHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = smtSolveInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // If custom Z3 script provided, use check_sat command
    if (input.z3_script) {
      try {
        const response = await invokeWorker({
          job_id: `smt-${input.sample_id}`,
          tool: 'check_sat',
          params: {
            script: input.z3_script,
            timeout_ms: input.timeout_ms,
          },
        })

        const artifacts: ArtifactRef[] = []
        try {
          const ref = await persistStaticAnalysisJsonArtifact(
            workspaceManager, database, input.sample_id,
            'smt_solution', 'z3_result', response
          )
          artifacts.push(ref)
        } catch {
          warnings.push('Failed to persist SMT solution artifact')
        }

        return {
          ok: (response as Record<string, unknown>).ok as boolean ?? true,
          data: response,
          warnings: warnings.length > 0 ? warnings : undefined,
          artifacts,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      } catch (e) {
        return { ok: false, errors: [`Z3 worker error: ${e}`] }
      }
    }

    // Load constraints from previous analysis
    const evidence = database.findAnalysisEvidenceBySample(input.sample_id)
    let constraintData: Record<string, unknown> | null = null

    if (Array.isArray(evidence)) {
      for (const entry of evidence) {
        if (entry.evidence_family === 'constraint_extraction') {
          const data = typeof entry.result_json === 'string'
            ? JSON.parse(entry.result_json)
            : entry.result_json
          if (data) {
            constraintData = data as Record<string, unknown>
            break
          }
        }
      }
    }

    if (!constraintData) {
      return {
        ok: false,
        errors: ['No constraints found. Run constraint.extract first or provide z3_script.'],
      }
    }

    // Use the Z3 script from constraint extraction
    const z3Script = constraintData.z3_script as string
    if (!z3Script) {
      return {
        ok: false,
        errors: ['Constraint data has no Z3 script. Re-run constraint.extract.'],
      }
    }

    try {
      const response = await invokeWorker({
        job_id: `smt-${input.sample_id}`,
        tool: 'check_sat',
        params: {
          script: z3Script,
          timeout_ms: input.timeout_ms,
        },
      })

      const artifacts: ArtifactRef[] = []
      try {
        const ref = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id,
          'smt_solution', 'z3_result', response
        )
        artifacts.push(ref)
      } catch {
        warnings.push('Failed to persist SMT solution artifact')
      }

      return {
        ok: (response as Record<string, unknown>).ok as boolean ?? true,
        data: response,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (e) {
      return { ok: false, errors: [`Z3 worker error: ${e}`] }
    }
  }
}
