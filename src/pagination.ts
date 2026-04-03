/**
 * Reusable pagination helper for MCP tool results.
 * Tools that return lists can use paginate() to apply offset/limit slicing.
 */

import { z } from 'zod'

export const paginationSchema = {
  offset: z.number().int().min(0).optional().default(0).describe('Number of items to skip (default: 0)'),
  limit: z.number().int().min(1).max(1000).optional().default(100).describe('Max items to return (default: 100, max: 1000)'),
}

export interface PaginatedResult<T> {
  items: T[]
  total: number
  offset: number
  limit: number
  hasMore: boolean
}

/**
 * Apply pagination to an array of items.
 */
export function paginate<T>(
  items: T[],
  offset = 0,
  limit = 100
): PaginatedResult<T> {
  const safeOffset = Math.max(0, offset)
  const safeLimit = Math.max(1, Math.min(1000, limit))
  const sliced = items.slice(safeOffset, safeOffset + safeLimit)

  return {
    items: sliced,
    total: items.length,
    offset: safeOffset,
    limit: safeLimit,
    hasMore: safeOffset + safeLimit < items.length,
  }
}
