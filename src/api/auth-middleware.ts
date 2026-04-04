/**
 * API Key Authentication Middleware
 * Simple token-based authentication for file upload API
 */

import type { IncomingHttpHeaders } from 'http'
import { logger } from '../logger.js'

export interface AuthConfig {
  apiKey?: string
  enabled: boolean
}

export class AuthMiddleware {
  private config: AuthConfig

  constructor(config: AuthConfig) {
    this.config = config
  }

  isEnabled(): boolean {
    return this.config.enabled
  }

  /**
   * Validate API Key from request headers
   */
  validateApiKey(headers: IncomingHttpHeaders): boolean {
    if (!this.config.enabled) {
      return true
    }

    const apiKey = headers['x-api-key'] as string

    if (!apiKey) {
      logger.warn('Missing API key')
      return false
    }

    if (!this.config.apiKey) {
      logger.warn('No API key configured')
      return false
    }

    const isValid = apiKey === this.config.apiKey

    if (!isValid) {
      logger.warn('Invalid API key provided')
    }

    return isValid
  }

  /**
   * Get authentication error response
   */
  getAuthError(hasApiKey: boolean): { status: number; body: string } {
    if (!hasApiKey) {
      return {
        status: 401,
        body: JSON.stringify({
          error: 'Unauthorized',
          message: 'Missing X-API-Key header',
        }),
      }
    }

    return {
      status: 403,
      body: JSON.stringify({
        error: 'Forbidden',
        message: 'Invalid API key',
      }),
    }
  }
}

/**
 * Generate random API key
 */
export async function generateApiKey(): Promise<string> {
  const crypto = await import('crypto')
  return crypto.randomBytes(32).toString('hex')
}
