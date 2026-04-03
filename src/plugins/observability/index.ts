/**
 * Observability Plugin — demonstrates the hook system.
 *
 * Tracks tool invocation metrics (call counts, latencies, errors)
 * via onBeforeToolCall / onAfterToolCall / onToolError hooks.
 * Exposes a diagnostic tool `observability.metrics` to query stats.
 */

import type {
  Plugin,
  PluginServerInterface,
  PluginToolDeps,
  PluginContext,
  ToolDefinition,
  PluginHooks,
} from '../sdk.js'
import { z } from 'zod'

// ── In-memory metrics store ───────────────────────────────────────────────

interface ToolMetrics {
  calls: number
  errors: number
  totalMs: number
  minMs: number
  maxMs: number
  lastCalledAt: string | null
  lastError: string | null
}

const metricsStore = new Map<string, ToolMetrics>()

function getOrCreate(toolName: string): ToolMetrics {
  let m = metricsStore.get(toolName)
  if (!m) {
    m = { calls: 0, errors: 0, totalMs: 0, minMs: Infinity, maxMs: 0, lastCalledAt: null, lastError: null }
    metricsStore.set(toolName, m)
  }
  return m
}

// ── Hook implementations ──────────────────────────────────────────────────

const hooks: PluginHooks = {
  onBeforeToolCall(toolName: string, _args: Record<string, unknown>) {
    const m = getOrCreate(toolName)
    m.calls++
    m.lastCalledAt = new Date().toISOString()
  },

  onAfterToolCall(toolName: string, _args: Record<string, unknown>, elapsedMs: number) {
    const m = getOrCreate(toolName)
    m.totalMs += elapsedMs
    if (elapsedMs < m.minMs) m.minMs = elapsedMs
    if (elapsedMs > m.maxMs) m.maxMs = elapsedMs
  },

  onToolError(toolName: string, error: unknown) {
    const m = getOrCreate(toolName)
    m.errors++
    m.lastError = error instanceof Error ? error.message : String(error)
  },
}

// ── Metrics query tool ────────────────────────────────────────────────────

const metricsInputSchema = z.object({
  tool_name: z.string().optional().describe('Filter metrics to a specific tool name'),
  top_n: z.number().int().min(1).max(100).default(20).describe('Return top N tools by call count'),
  sort_by: z.enum(['calls', 'errors', 'avg_ms', 'max_ms']).default('calls').describe('Sort key'),
})

const metricsToolDefinition: ToolDefinition = {
  name: 'observability.metrics',
  description: 'Query tool invocation metrics — call counts, latencies, error rates. Powered by the plugin hook system.',
  inputSchema: metricsInputSchema,
}

function createMetricsHandler() {
  return async (args: unknown) => {
    const input = metricsInputSchema.parse(args)

    if (input.tool_name) {
      const m = metricsStore.get(input.tool_name)
      if (!m) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ ok: true, data: null, message: `No metrics recorded for '${input.tool_name}'` }) }],
        }
      }
      const avgMs = m.calls > 0 ? Math.round(m.totalMs / m.calls) : 0
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            data: {
              tool: input.tool_name,
              calls: m.calls,
              errors: m.errors,
              error_rate: m.calls > 0 ? +(m.errors / m.calls).toFixed(4) : 0,
              avg_ms: avgMs,
              min_ms: m.minMs === Infinity ? 0 : m.minMs,
              max_ms: m.maxMs,
              last_called_at: m.lastCalledAt,
              last_error: m.lastError,
            },
          }),
        }],
      }
    }

    // Aggregate all tools
    const entries = [...metricsStore.entries()].map(([name, m]) => ({
      tool: name,
      calls: m.calls,
      errors: m.errors,
      error_rate: m.calls > 0 ? +(m.errors / m.calls).toFixed(4) : 0,
      avg_ms: m.calls > 0 ? Math.round(m.totalMs / m.calls) : 0,
      min_ms: m.minMs === Infinity ? 0 : m.minMs,
      max_ms: m.maxMs,
      last_called_at: m.lastCalledAt,
    }))

    const sortFn: Record<string, (a: typeof entries[0], b: typeof entries[0]) => number> = {
      calls:  (a, b) => b.calls - a.calls,
      errors: (a, b) => b.errors - a.errors,
      avg_ms: (a, b) => b.avg_ms - a.avg_ms,
      max_ms: (a, b) => b.max_ms - a.max_ms,
    }
    entries.sort(sortFn[input.sort_by] || sortFn.calls)
    const top = entries.slice(0, input.top_n)

    const totalCalls = entries.reduce((s, e) => s + e.calls, 0)
    const totalErrors = entries.reduce((s, e) => s + e.errors, 0)

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          ok: true,
          data: {
            summary: {
              total_tools_tracked: entries.length,
              total_calls: totalCalls,
              total_errors: totalErrors,
              global_error_rate: totalCalls > 0 ? +(totalErrors / totalCalls).toFixed(4) : 0,
            },
            tools: top,
          },
        }),
      }],
    }
  }
}

// ── Plugin definition ─────────────────────────────────────────────────────

const plugin: Plugin = {
  id: 'observability',
  name: 'Observability',
  description: 'Tool invocation metrics and monitoring via lifecycle hooks',
  version: '1.0.0',
  hooks,
  globalHooks: true,

  register(server: PluginServerInterface, _deps: PluginToolDeps, ctx?: PluginContext) {
    server.registerTool(metricsToolDefinition, createMetricsHandler())
    ctx?.logger.info('Observability plugin loaded — tracking tool metrics')
    return ['observability.metrics']
  },

  teardown() {
    metricsStore.clear()
  },
}

export default plugin
