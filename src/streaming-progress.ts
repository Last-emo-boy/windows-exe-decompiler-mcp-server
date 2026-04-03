/**
 * Streaming progress support for long-running MCP tools.
 *
 * Provides a `ProgressReporter` that tools can use to send incremental
 * progress updates to the MCP client while a tool call is in flight.
 *
 * Usage in a tool handler:
 *   const progress = server.createProgressReporter(progressToken)
 *   await progress.report(0.25, 'Phase 1 of 4: PE header analysis')
 *   // ... do work ...
 *   await progress.report(0.5, 'Phase 2 of 4: Import resolution')
 */

import type { Server } from '@modelcontextprotocol/sdk/server/index.js'

export interface ProgressReporter {
  /** Report progress (0..1) with an optional human-readable message. */
  report(progress: number, message?: string): Promise<void>
}

/**
 * Create a ProgressReporter bound to a specific progress token.
 * If `progressToken` is undefined the reporter is a no-op (client didn't request progress).
 */
export function createProgressReporter(
  server: Server,
  progressToken: string | number | undefined,
): ProgressReporter {
  if (progressToken === undefined) {
    return { report: async () => {} }
  }
  let total = 1
  return {
    async report(progress: number, message?: string) {
      try {
        await server.notification({
          method: 'notifications/progress',
          params: {
            progressToken,
            progress: Math.max(0, Math.min(1, progress)),
            total,
            ...(message ? { message } : {}),
          },
        } as any)
      } catch {
        // Client may not support progress; swallow errors.
      }
    },
  }
}
