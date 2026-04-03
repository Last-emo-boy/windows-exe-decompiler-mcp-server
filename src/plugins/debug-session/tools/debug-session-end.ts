/**
 * debug.session.end MCP tool â€?end a debug session, persist trace artifact.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef , PluginToolDeps} from '../../sdk.js'
import { persistStaticAnalysisJsonArtifact } from '../../../static-analysis-artifacts.js'
import { getDebugSessionManager } from '../../../debug/debug-session-state.js'

const TOOL_NAME = 'debug.session.end'

export const DebugSessionEndInputSchema = z.object({
  session_id: z.string().describe('Debug session ID to end'),
})

export const DebugSessionEndOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const debugSessionEndToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'End a debug session: kill GDB, persist session trace as an artifact (breakpoint hits, register snapshots, history).',
  inputSchema: DebugSessionEndInputSchema,
  outputSchema: DebugSessionEndOutputSchema,
}

export function createDebugSessionEndHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: z.infer<typeof DebugSessionEndInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const mgr = getDebugSessionManager()
      const session = mgr.getSession(args.session_id)
      if (!session) {
        return { ok: false, errors: [`Session not found: ${args.session_id}`] }
      }

      const sampleId = session.sampleId
      const history = await mgr.endSession(args.session_id)

      const traceData = {
        session_id: args.session_id,
        sample_id: sampleId,
        history,
        ended_at: new Date().toISOString(),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          sampleId,
          'debug_session_trace',
          'debug-trace',
          traceData
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        // non-fatal
      }

      return {
        ok: true,
        data: {
          session_id: args.session_id,
          history_entries: history.length,
          remaining_sessions: mgr.activeCount,
        },
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
