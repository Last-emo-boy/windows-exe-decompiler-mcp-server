/**
 * HTTP API Rate Limiter — sliding-window token bucket
 * Provides per-IP and global rate limiting for the HTTP file server.
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { logger } from '../logger.js'

export interface RateLimitConfig {
  /** Max requests per window per IP */
  maxRequestsPerWindow: number
  /** Window size in milliseconds */
  windowMs: number
  /** Global max requests per window (0 = unlimited) */
  globalMaxPerWindow: number
}

interface BucketEntry {
  tokens: number
  lastRefill: number
}

const DEFAULT_CONFIG: RateLimitConfig = {
  maxRequestsPerWindow: 100,
  windowMs: 60_000,
  globalMaxPerWindow: 1000,
}

export class RateLimiter {
  private readonly config: RateLimitConfig
  private readonly buckets = new Map<string, BucketEntry>()
  private globalEntry: BucketEntry
  private cleanupTimer?: NodeJS.Timeout

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.globalEntry = { tokens: this.config.globalMaxPerWindow, lastRefill: Date.now() }

    // Periodic cleanup of stale buckets
    this.cleanupTimer = setInterval(() => this.cleanup(), this.config.windowMs * 2)
    if (this.cleanupTimer.unref) this.cleanupTimer.unref()
  }

  /**
   * Check if request is allowed. Returns true if allowed, false if rate-limited.
   */
  check(req: IncomingMessage, res: ServerResponse): boolean {
    const ip = this.extractIp(req)
    const now = Date.now()

    // Refill per-IP bucket
    let bucket = this.buckets.get(ip)
    if (!bucket) {
      bucket = { tokens: this.config.maxRequestsPerWindow, lastRefill: now }
      this.buckets.set(ip, bucket)
    } else {
      const elapsed = now - bucket.lastRefill
      if (elapsed >= this.config.windowMs) {
        bucket.tokens = this.config.maxRequestsPerWindow
        bucket.lastRefill = now
      }
    }

    // Refill global bucket
    if (this.config.globalMaxPerWindow > 0) {
      const elapsed = now - this.globalEntry.lastRefill
      if (elapsed >= this.config.windowMs) {
        this.globalEntry.tokens = this.config.globalMaxPerWindow
        this.globalEntry.lastRefill = now
      }
    }

    // Check per-IP limit
    if (bucket.tokens <= 0) {
      this.reject(res, ip, 'per-ip')
      return false
    }

    // Check global limit
    if (this.config.globalMaxPerWindow > 0 && this.globalEntry.tokens <= 0) {
      this.reject(res, ip, 'global')
      return false
    }

    // Consume token
    bucket.tokens--
    if (this.config.globalMaxPerWindow > 0) this.globalEntry.tokens--

    // Add rate limit headers
    res.setHeader('X-RateLimit-Limit', this.config.maxRequestsPerWindow)
    res.setHeader('X-RateLimit-Remaining', Math.max(0, bucket.tokens))
    res.setHeader('X-RateLimit-Reset', Math.ceil((bucket.lastRefill + this.config.windowMs) / 1000))

    return true
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = undefined
    }
    this.buckets.clear()
  }

  private reject(res: ServerResponse, ip: string, scope: string): void {
    logger.warn({ ip, scope }, 'Rate limit exceeded')
    const retryAfter = Math.ceil(this.config.windowMs / 1000)
    res.setHeader('Retry-After', retryAfter)
    res.setHeader('X-RateLimit-Limit', this.config.maxRequestsPerWindow)
    res.setHeader('X-RateLimit-Remaining', 0)
    res.writeHead(429, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      error: 'Too Many Requests',
      message: `Rate limit exceeded (${scope}). Retry after ${retryAfter}s.`,
    }))
  }

  private extractIp(req: IncomingMessage): string {
    const forwarded = req.headers['x-forwarded-for']
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0].trim()
    }
    return req.socket?.remoteAddress || '0.0.0.0'
  }

  private cleanup(): void {
    const now = Date.now()
    for (const [ip, bucket] of this.buckets) {
      if (now - bucket.lastRefill > this.config.windowMs * 2) {
        this.buckets.delete(ip)
      }
    }
  }
}
