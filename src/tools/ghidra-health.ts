/**
 * ghidra.health MCP Tool
 *
 * Performs both environment validation and an optional downstream live probe
 * against a real analyzed sample/project to verify end-to-end usability.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager, Analysis } from '../database.js'
import {
  checkGhidraHealth,
  type GhidraHealthStatus,
} from '../ghidra-config.js'
import {
  findBestGhidraAnalysis,
  getGhidraReadiness,
  parseGhidraAnalysisMetadata,
} from '../ghidra-analysis-status.js'
import { DecompilerWorker } from '../decompiler-worker.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  buildJavaRequiredUserInputs,
  buildJavaSetupActions,
  buildGhidraRequiredUserInputs,
  buildGhidraSetupActions,
  buildPyGhidraSetupActions,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'

export const ghidraHealthInputSchema = z.object({
  timeout_ms: z
    .number()
    .int()
    .min(1000)
    .max(60000)
    .optional()
    .default(8000)
    .describe('Timeout for launch probe and downstream live probes in milliseconds'),
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample ID to use for the end-to-end downstream probe'),
  include_end_to_end: z
    .boolean()
    .optional()
    .default(true)
    .describe('Attempt decompile/CFG live probes against a reusable analyzed sample'),
  stale_running_ms: z
    .number()
    .int()
    .min(1000)
    .nullable()
    .optional()
    .describe('Optional stale-analysis reap threshold in milliseconds. Omit or null to disable auto-reaping.'),
})

export type GhidraHealthInput = z.infer<typeof ghidraHealthInputSchema>

export const ghidraHealthOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      environment: z.any(),
      downstream: z.record(z.any()).optional(),
      reaped_persisted_analysis_ids: z.array(z.string()),
      reaped_persisted_analysis_count: z.number().int().nonnegative(),
      setup_actions: z.array(SetupActionSchema),
      required_user_inputs: z.array(RequiredUserInputSchema),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
})

export const ghidraHealthToolDefinition: ToolDefinition = {
  name: 'ghidra.health',
  description:
    'Run a Ghidra environment health check plus optional end-to-end downstream probes using a real analyzed sample/project.',
  inputSchema: ghidraHealthInputSchema,
  outputSchema: ghidraHealthOutputSchema,
}

interface GhidraHealthDependencies {
  checkGhidra?: (timeoutMs: number) => GhidraHealthStatus
  decompilerWorker?: Pick<DecompilerWorker, 'decompileFunction' | 'getFunctionCFG'>
}

function jsonResult(payload: unknown, isError: boolean): ToolResult {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2),
      },
    ],
    isError,
  }
}

function normalizeProbeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function selectProbeAnalysis(
  database?: DatabaseManager,
  sampleId?: string
): { sampleId: string; analysis: Analysis } | null {
  if (!database) {
    return null
  }

  if (sampleId) {
    const selected = findBestGhidraAnalysis(database.findAnalysesBySample(sampleId), 'function_index')
    return selected ? { sampleId, analysis: selected } : null
  }

  for (const sample of database.findRecentSamples(50)) {
    const selected = findBestGhidraAnalysis(database.findAnalysesBySample(sample.id), 'function_index')
    if (selected) {
      return { sampleId: sample.id, analysis: selected }
    }
  }

  return null
}

function selectProbeTarget(database: DatabaseManager, sampleId: string, analysis: Analysis): string | undefined {
  const readiness = getGhidraReadiness(analysis)
  const metadata = parseGhidraAnalysisMetadata(analysis.output_json)
  return (
    readiness.decompile.target ||
    readiness.cfg.target ||
    metadata.end_to_end_probe?.target ||
    database.findFunctions(sampleId).find((func) => typeof func.address === 'string' && func.address.length > 0)
      ?.address
  )
}

export function createGhidraHealthHandler(
  workspaceManager?: WorkspaceManager,
  database?: DatabaseManager,
  dependencies?: GhidraHealthDependencies
): ToolHandler {
  const runHealthCheck = dependencies?.checkGhidra || checkGhidraHealth
  const decompilerWorker =
    dependencies?.decompilerWorker ||
    (workspaceManager && database ? new DecompilerWorker(database, workspaceManager) : undefined)

  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = ghidraHealthInputSchema.parse(args)
      const result = runHealthCheck(input.timeout_ms)
      const warnings = [...result.warnings]
      const errors = [...result.errors]
      let setupActions = [] as z.infer<typeof SetupActionSchema>[]
      let requiredUserInputs = [] as z.infer<typeof RequiredUserInputSchema>[]

      if (!result.ok) {
        setupActions = mergeSetupActions(setupActions, buildJavaSetupActions(), buildGhidraSetupActions())
        requiredUserInputs = mergeRequiredUserInputs(
          requiredUserInputs,
          buildJavaRequiredUserInputs(),
          buildGhidraRequiredUserInputs()
        )
      }
      if (result.checks?.java_available === false || result.checks?.java_version_ok === false) {
        setupActions = mergeSetupActions(setupActions, buildJavaSetupActions())
        requiredUserInputs = mergeRequiredUserInputs(
          requiredUserInputs,
          buildJavaRequiredUserInputs()
        )
      }
      if (result.checks?.pyghidra_available === false) {
        setupActions = mergeSetupActions(setupActions, buildPyGhidraSetupActions())
      }

      let reapedAnalyses: string[] = []
      if (database && typeof input.stale_running_ms === 'number') {
        reapedAnalyses = database
          .reapStaleAnalyses(input.stale_running_ms, input.sample_id)
          .map((analysis) => analysis.id)
        if (reapedAnalyses.length > 0) {
          warnings.push(
            `Reaped ${reapedAnalyses.length} stale persisted running analysis record(s) before probing downstream capabilities.`
          )
        }
      }

      const probeSelection = selectProbeAnalysis(database, input.sample_id)
      let downstream: Record<string, unknown> | undefined
      let downstreamOk = true

      if (input.include_end_to_end) {
        if (!database || !workspaceManager || !decompilerWorker) {
          warnings.push(
            'End-to-end probe skipped because workspace/database dependencies are unavailable in this handler.'
          )
          downstream = {
            attempted: false,
            available: false,
            reason: 'missing_handler_dependencies',
          }
        } else if (input.sample_id && !probeSelection) {
          downstream = {
            attempted: false,
            available: false,
            sample_id: input.sample_id,
            reason: 'no_reusable_ghidra_analysis_for_sample',
          }
          warnings.push(
            `No reusable Ghidra analysis with function-index readiness was found for sample ${input.sample_id}.`
          )
        } else if (!probeSelection) {
          downstream = {
            attempted: false,
            available: false,
            reason: 'no_recent_analyzed_sample_available',
          }
          warnings.push(
            'No recent analyzed sample was available for an end-to-end downstream probe. Environment-only status may overstate readiness.'
          )
        } else {
          const readiness = getGhidraReadiness(probeSelection.analysis)
          const metadata = parseGhidraAnalysisMetadata(probeSelection.analysis.output_json)
          const target = selectProbeTarget(database, probeSelection.sampleId, probeSelection.analysis)

          downstream = {
            attempted: true,
            available: true,
            sample_id: probeSelection.sampleId,
            analysis_id: probeSelection.analysis.id,
            analysis_status: probeSelection.analysis.status,
            probe_target: target || null,
            persisted_capabilities: readiness,
            persisted_probe: metadata.end_to_end_probe || null,
          }

          if (!target) {
            downstreamOk = false
            warnings.push(
              `No probe target function could be selected for sample ${probeSelection.sampleId}; downstream verification is incomplete.`
            )
            downstream.live_probe = {
              decompile: { ok: false, error: 'No probe target function available' },
              cfg: { ok: false, error: 'No probe target function available' },
            }
          } else {
            type LiveProbeItem = {
              ok: boolean
              error?: string
              pseudocode_length?: number
              callers?: number
              callees?: number
              node_count?: number
              edge_count?: number
            }
            const liveProbe = {
              decompile: { ok: false, error: undefined } as LiveProbeItem,
              cfg: { ok: false, error: undefined } as LiveProbeItem,
            }

            try {
              const decompiled = await decompilerWorker.decompileFunction(
                probeSelection.sampleId,
                target,
                false,
                input.timeout_ms
              )
              liveProbe.decompile = {
                ok: true,
                pseudocode_length: decompiled.pseudocode.length,
                callers: decompiled.callers.length,
                callees: decompiled.callees.length,
              }
            } catch (error) {
              downstreamOk = false
              liveProbe.decompile = {
                ok: false,
                error: normalizeProbeError(error),
              }
            }

            try {
              const cfg = await decompilerWorker.getFunctionCFG(
                probeSelection.sampleId,
                target,
                input.timeout_ms
              )
              liveProbe.cfg = {
                ok: true,
                node_count: cfg.nodes.length,
                edge_count: cfg.edges.length,
              }
            } catch (error) {
              downstreamOk = false
              liveProbe.cfg = {
                ok: false,
                error: normalizeProbeError(error),
              }
            }

            downstream.live_probe = liveProbe
          }
        }
      }

      const ok = result.ok && (!input.include_end_to_end || downstreamOk)

      return jsonResult(
        {
          ok,
          data: {
            environment: result,
            downstream,
            reaped_persisted_analysis_ids: reapedAnalyses,
            reaped_persisted_analysis_count: reapedAnalyses.length,
            setup_actions: setupActions,
            required_user_inputs: requiredUserInputs,
          },
          errors: errors.length > 0 ? errors : undefined,
          warnings: warnings.length > 0 ? warnings : undefined,
        },
        !ok
      )
    } catch (error) {
      return jsonResult(
        {
          ok: false,
          errors: [normalizeProbeError(error)],
        },
        true
      )
    }
  }
}
