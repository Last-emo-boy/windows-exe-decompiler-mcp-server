/**
 * debug.session.start MCP tool â€?start interactive GDB debug session.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult , PluginToolDeps} from '../../sdk.js'
import { resolvePrimarySamplePath } from '../../../sample-workspace.js'
import { detectFormat } from '../../../format-detect.js'
import { getDebugSessionManager } from '../../../debug/debug-session-state.js'

const TOOL_NAME = 'debug.session.start'

export const DebugSessionStartInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  gdb_path: z.string().optional().describe('Custom GDB path (default: gdb)'),
})

export const DebugSessionStartOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const debugSessionStartToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Start an interactive GDB debug session for a sample. Supports ELF (direct GDB) and PE (via wine+GDB). Returns a session_id for subsequent debug commands.',
  inputSchema: DebugSessionStartInputSchema,
  outputSchema: DebugSessionStartOutputSchema,
}

export function createDebugSessionStartHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: z.infer<typeof DebugSessionStartInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)
      const format = detectFormat(samplePath)

      const useWine = format === 'PE'
      const mgr = getDebugSessionManager()

      const session = await mgr.createSession(
        args.sample_id,
        samplePath,
        args.gdb_path,
        useWine
      )

      return {
        ok: true,
        data: {
          session_id: session.id,
          sample_id: args.sample_id,
          binary_format: format,
          use_wine: useWine,
          active_sessions: mgr.activeCount,
        },
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
