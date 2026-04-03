/**
 * debug.session.continue MCP tool â€?continue execution until breakpoint or signal.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult , PluginToolDeps} from '../../sdk.js'
import { getDebugSessionManager } from '../../../debug/debug-session-state.js'
import type { MiResponse } from '../../../debug/gdb-mi-client.js'

const TOOL_NAME = 'debug.session.continue'

export const DebugSessionContinueInputSchema = z.object({
  session_id: z.string().describe('Debug session ID'),
  timeout_ms: z
    .number()
    .int()
    .min(1000)
    .max(120000)
    .optional()
    .default(30000)
    .describe('Maximum time to wait for stop event (ms)'),
})

export const DebugSessionContinueOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const debugSessionContinueToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Continue execution in a debug session. Blocks until a breakpoint is hit, a signal is received, or timeout.',
  inputSchema: DebugSessionContinueInputSchema,
  outputSchema: DebugSessionContinueOutputSchema,
}

export function createDebugSessionContinueHandler(deps: PluginToolDeps) {
  return async (args: z.infer<typeof DebugSessionContinueInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const mgr = getDebugSessionManager()
      const session = mgr.getSession(args.session_id)
      if (!session) {
        return { ok: false, errors: [`Session not found: ${args.session_id}`] }
      }
      mgr.touch(args.session_id)

      // Send continue command
      await session.gdb.command('-exec-continue')

      // Wait for stop event
      const stopEvent = await new Promise<MiResponse>((resolve, reject) => {
        const timer = setTimeout(() => {
          session.gdb.removeAllListeners('exec')
          reject(new Error(`Timeout waiting for stop event after ${args.timeout_ms}ms`))
        }, args.timeout_ms)

        const handler = (resp: MiResponse) => {
          if (resp.class_ === 'stopped') {
            clearTimeout(timer)
            session.gdb.removeListener('exec', handler)
            resolve(resp)
          }
        }
        session.gdb.on('exec', handler)
      })

      const stopReason = String(stopEvent.payload.reason || 'unknown')
      const detail: Record<string, unknown> = {
        stop_reason: stopReason,
        payload: stopEvent.payload,
      }

      session.history.push({
        timestamp: new Date().toISOString(),
        action: 'continue_stopped',
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
