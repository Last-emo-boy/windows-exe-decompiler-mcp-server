/**
 * MCP tool: system.config.validate
 * Validates the current configuration and returns a diagnostic report.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolResult } from '../types.js'
import type { MCPServer } from '../server.js'
import { validateConfig } from '../config-validator.js'
import { config } from '../config.js'

const inputSchema = z.object({
  category: z.string().optional().describe('Filter diagnostics by category (path, tool, dir, worker, api, database)'),
  status: z.enum(['ok', 'warn', 'error']).optional().describe('Filter diagnostics by status'),
})

export const configValidateToolDefinition: ToolDefinition = {
  name: 'system.config.validate',
  description: 'Validate the current server configuration and run startup diagnostics. Returns a report of all config checks including tool availability, directory permissions, and worker status.',
  inputSchema: inputSchema as any,
}

export function createConfigValidateHandler(_server: MCPServer) {
  return async (args: z.infer<typeof inputSchema>): Promise<ToolResult> => {
    const report = validateConfig(config)

    let filtered = report.diagnostics
    if (args.category) {
      filtered = filtered.filter(d => d.category === args.category)
    }
    if (args.status) {
      filtered = filtered.filter(d => d.status === args.status)
    }

    const result = {
      valid: report.valid,
      timestamp: report.timestamp,
      summary: report.summary,
      diagnostics: filtered,
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      structuredContent: result,
    }
  }
}
