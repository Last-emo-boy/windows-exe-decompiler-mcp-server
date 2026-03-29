/**
 * Health Check Route
 * GET /api/v1/health
 */

import type { ServerResponse } from 'http'

export interface HealthResponse {
  status: string
  uptime: number
  timestamp: string
  version?: string
}

/**
 * Handle health check
 * GET /api/v1/health
 */
export async function handleHealthCheck(
  res: ServerResponse,
  version?: string
): Promise<void> {
  const health: HealthResponse = {
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: version || '1.0.0-beta.1',
  }

  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(health))
}
