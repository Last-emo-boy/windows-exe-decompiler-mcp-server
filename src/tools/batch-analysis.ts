/**
 * MCP tools for batch/corpus analysis mode.
 *
 * Provides:
 *  - batch.submit  — submit a set of samples for parallel analysis
 *  - batch.status  — check progress of a batch job
 *  - batch.results — retrieve results once complete
 */

import { z } from 'zod'
import crypto from 'crypto'
import type { ToolDefinition, ToolResult } from '../types.js'
import type { MCPServer } from '../server.js'
import type { DatabaseManager } from '../database.js'
import { logger } from '../logger.js'

// ══════════════════════════════════════════════════════════════════════════
// In-memory batch state
// ══════════════════════════════════════════════════════════════════════════

export interface BatchJob {
  id: string
  sampleIds: string[]
  toolPipeline: string[]
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: { completed: number; total: number; errors: string[] }
  results: Map<string, unknown>
  createdAt: string
  updatedAt: string
}

const batches = new Map<string, BatchJob>()

// ══════════════════════════════════════════════════════════════════════════
// batch.submit
// ══════════════════════════════════════════════════════════════════════════

const submitSchema = z.object({
  sample_ids: z.array(z.string()).min(1).max(500).describe('List of sample IDs to process'),
  tool_pipeline: z.array(z.string()).min(1).describe('Ordered list of tool names to run on each sample'),
  concurrency: z.number().int().min(1).max(16).optional().default(4).describe('Max concurrent analyses'),
})

export const batchSubmitToolDefinition: ToolDefinition = {
  name: 'batch.submit',
  description: 'Submit a batch of samples for parallel analysis through a tool pipeline. Returns a batch ID for tracking.',
  inputSchema: submitSchema as any,
}

export function createBatchSubmitHandler(server: MCPServer, database: DatabaseManager) {
  return async (args: z.infer<typeof submitSchema>): Promise<ToolResult> => {
    const batchId = crypto.randomUUID()
    const now = new Date().toISOString()

    const job: BatchJob = {
      id: batchId,
      sampleIds: args.sample_ids,
      toolPipeline: args.tool_pipeline,
      status: 'pending',
      progress: { completed: 0, total: args.sample_ids.length * args.tool_pipeline.length, errors: [] },
      results: new Map(),
      createdAt: now,
      updatedAt: now,
    }

    batches.set(batchId, job)

    // Start processing asynchronously
    void processBatch(job, server, args.concurrency).catch(err => {
      logger.error({ err, batchId }, 'Batch processing failed')
      job.status = 'failed'
      job.updatedAt = new Date().toISOString()
    })

    const result = {
      batch_id: batchId,
      sample_count: args.sample_ids.length,
      pipeline: args.tool_pipeline,
      status: 'pending',
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      structuredContent: result,
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════
// batch.status
// ══════════════════════════════════════════════════════════════════════════

const statusSchema = z.object({
  batch_id: z.string().describe('Batch ID returned from batch.submit'),
})

export const batchStatusToolDefinition: ToolDefinition = {
  name: 'batch.status',
  description: 'Check the progress of a batch analysis job.',
  inputSchema: statusSchema as any,
}

export function createBatchStatusHandler() {
  return async (args: z.infer<typeof statusSchema>): Promise<ToolResult> => {
    const job = batches.get(args.batch_id)

    if (!job) {
      return {
        content: [{ type: 'text', text: `Batch '${args.batch_id}' not found` }],
        isError: true,
      }
    }

    const result = {
      batch_id: job.id,
      status: job.status,
      progress: {
        completed: job.progress.completed,
        total: job.progress.total,
        percent: job.progress.total > 0 ? Math.round(job.progress.completed / job.progress.total * 100) : 0,
        error_count: job.progress.errors.length,
      },
      created_at: job.createdAt,
      updated_at: job.updatedAt,
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      structuredContent: result,
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════
// batch.results
// ══════════════════════════════════════════════════════════════════════════

const resultsSchema = z.object({
  batch_id: z.string().describe('Batch ID'),
  sample_id: z.string().optional().describe('Filter results by a specific sample ID'),
})

export const batchResultsToolDefinition: ToolDefinition = {
  name: 'batch.results',
  description: 'Retrieve results of a completed batch analysis job.',
  inputSchema: resultsSchema as any,
}

export function createBatchResultsHandler() {
  return async (args: z.infer<typeof resultsSchema>): Promise<ToolResult> => {
    const job = batches.get(args.batch_id)

    if (!job) {
      return {
        content: [{ type: 'text', text: `Batch '${args.batch_id}' not found` }],
        isError: true,
      }
    }

    let entries = Array.from(job.results.entries()).map(([key, value]) => ({
      key,
      ...value as Record<string, unknown>,
    }))

    if (args.sample_id) {
      entries = entries.filter(e => e.key.startsWith(args.sample_id!))
    }

    const result = {
      batch_id: job.id,
      status: job.status,
      total_results: entries.length,
      errors: job.progress.errors,
      results: entries,
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      structuredContent: result,
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Background processor
// ══════════════════════════════════════════════════════════════════════════

async function processBatch(job: BatchJob, server: MCPServer, concurrency: number): Promise<void> {
  job.status = 'running'
  job.updatedAt = new Date().toISOString()

  // Build work items: [sampleId, toolName]
  const workItems: Array<[string, string]> = []
  for (const sampleId of job.sampleIds) {
    for (const tool of job.toolPipeline) {
      workItems.push([sampleId, tool])
    }
  }

  // Process with concurrency limit
  let idx = 0
  const workers: Promise<void>[] = []

  for (let w = 0; w < Math.min(concurrency, workItems.length); w++) {
    workers.push((async () => {
      while (idx < workItems.length) {
        const myIdx = idx++
        if (myIdx >= workItems.length) break
        const [sampleId, tool] = workItems[myIdx]

        try {
          // Call the tool through the server's callTool interface
          const result = await (server as any).callToolInternal?.(tool, { sample_id: sampleId })
          job.results.set(`${sampleId}:${tool}`, { ok: true, data: result ?? null })
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          job.results.set(`${sampleId}:${tool}`, { ok: false, error: msg })
          job.progress.errors.push(`${sampleId}:${tool}: ${msg}`)
        }

        job.progress.completed++
        job.updatedAt = new Date().toISOString()
      }
    })())
  }

  await Promise.all(workers)

  job.status = job.progress.errors.length === 0 ? 'completed' : 'completed'
  job.updatedAt = new Date().toISOString()

  logger.info({
    batchId: job.id,
    completed: job.progress.completed,
    errors: job.progress.errors.length,
  }, 'Batch processing complete')
}
