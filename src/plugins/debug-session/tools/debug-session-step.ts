/**
 * debug.session.step MCP tool â€?single-step execution.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult , PluginToolDeps} from '../../sdk.js'
import { getDebugSessionManager } from '../../../debug/debug-session-state.js'
import type { MiResponse } from '../../../debug/gdb-mi-client.js'

const TOOL_NAME = 'debug.session.step'

export const DebugSessionStepInputSchema = z.object({
  session_id: z.string().describe('Debug session ID'),
  mode: z
    .enum(['instruction', 'over'])
    .optional()
    .default('instruction')
    .describe('Step mode: instruction (into) or over (step over calls)'),
})

export const DebugSessionStepOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const debugSessionStepToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Single-step execution in a debug session. Supports instruction-level stepping (into) and step-over mode.',
  inputSchema: DebugSessionStepInputSchema,
  outputSchema: DebugSessionStepOutputSchema,
}

export function createDebugSessionStepHandler(deps: PluginToolDeps) {
  return async (args: z.infer<typeof DebugSessionStepInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const mgr = getDebugSessionManager()
      const session = mgr.getSession(args.session_id)
      if (!session) {
        return { ok: false, errors: [`Session not found: ${args.session_id}`] }
      }
      mgr.touch(args.session_id)

      const cmd = args.mode === 'over' ? '-exec-next-instruction' : '-exec-step-instruction'
      await session.gdb.command(cmd)

      // Wait for stopped event
      const stopEvent = await new Promise<MiResponse>((resolve, reject) => {
        const timer = setTimeout(() => {
          session.gdb.removeAllListeners('exec')
          reject(new Error('Step timed out after 10s'))
        }, 10000)

        const handler = (resp: MiResponse) => {
          if (resp.class_ === 'stopped') {
            clearTimeout(timer)
            session.gdb.removeListener('exec', handler)
            resolve(resp)
          }
        }
        session.gdb.on('exec', handler)
      })

      // Get register values
      let registers: Record<string, unknown> = {}
      try {
        const regResp = await session.gdb.command('-data-list-register-values x')
        registers = regResp.payload
      } catch {
        // non-fatal
      }

      const detail = {
        stop_reason: String(stopEvent.payload.reason || 'end-stepping-range'),
        frame: stopEvent.payload.frame || {},
        registers,
      }

      session.history.push({
        timestamp: new Date().toISOString(),
        action: `step_${args.mode}`,
        detail,
      })

      return {
        ok: true,
        data: detail,
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
