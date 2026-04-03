/**
 * Error recovery & retry utility
 * Exponential backoff with jitter for external tool calls.
 */

import { logger } from './logger.js'

export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries: number
  /** Initial delay in ms (default: 500) */
  initialDelayMs: number
  /** Maximum delay in ms (default: 30000) */
  maxDelayMs: number
  /** Backoff multiplier (default: 2) */
  backoffMultiplier: number
  /** Jitter factor 0-1 (default: 0.1) */
  jitter: number
  /** Predicate to decide if error is retryable (default: always true) */
  retryable?: (error: unknown) => boolean
  /** Label for logging */
  label?: string
}

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  initialDelayMs: 500,
  maxDelayMs: 30_000,
  backoffMultiplier: 2,
  jitter: 0.1,
}

export class RetryError extends Error {
  public readonly attempts: number
  public readonly lastError: unknown

  constructor(message: string, attempts: number, lastError: unknown) {
    super(message)
    this.name = 'RetryError'
    this.attempts = attempts
    this.lastError = lastError
  }
}

/**
 * Execute a function with exponential backoff retry.
 */
export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  opts: Partial<RetryOptions> = {}
): Promise<T> {
  const config = { ...DEFAULT_OPTIONS, ...opts }
  let lastError: unknown

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn(attempt)
    } catch (err) {
      lastError = err

      if (attempt >= config.maxRetries) break

      // Check if retryable
      if (config.retryable && !config.retryable(err)) {
        throw err
      }

      // Calculate delay with exponential backoff + jitter
      const baseDelay = config.initialDelayMs * Math.pow(config.backoffMultiplier, attempt)
      const jitterRange = baseDelay * config.jitter
      const jitterOffset = (Math.random() * 2 - 1) * jitterRange
      const delay = Math.min(baseDelay + jitterOffset, config.maxDelayMs)

      logger.debug({
        label: config.label,
        attempt: attempt + 1,
        maxRetries: config.maxRetries,
        delayMs: Math.round(delay),
        error: err instanceof Error ? err.message : String(err),
      }, 'Retrying after error')

      await sleep(delay)
    }
  }

  const label = config.label || 'operation'
  throw new RetryError(
    `${label} failed after ${config.maxRetries + 1} attempts: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
    config.maxRetries + 1,
    lastError
  )
}

/**
 * Create a retry-wrapped version of a function.
 */
export function retryable<T>(
  fn: (...args: any[]) => Promise<T>,
  opts: Partial<RetryOptions> = {}
): (...args: any[]) => Promise<T> {
  return (...args: any[]): Promise<T> => withRetry(() => fn(...args), opts)
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
