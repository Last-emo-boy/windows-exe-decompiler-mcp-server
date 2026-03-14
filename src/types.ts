/**
 * Type definitions for the MCP Server
 */

import { z } from 'zod'

// ============================================================================
// MCP Protocol Types
// ============================================================================

/**
 * JSON Schema type for tool input/output validation
 */
export type JSONSchema = z.ZodTypeAny

/**
 * Tool definition following MCP protocol
 */
export interface ToolDefinition {
  name: string
  description: string
  inputSchema: JSONSchema
  outputSchema?: JSONSchema
}

/**
 * Prompt argument definition following MCP protocol
 */
export interface PromptArgumentDefinition {
  name: string
  description?: string
  required?: boolean
}

/**
 * Prompt definition following MCP protocol
 */
export interface PromptDefinition {
  name: string
  title?: string
  description?: string
  arguments?: PromptArgumentDefinition[]
}

/**
 * Prompt arguments (generic string map)
 */
export type PromptArgs = Record<string, string>

/**
 * Prompt message content
 */
export interface PromptMessageContent {
  type: 'text'
  text: string
}

/**
 * Prompt message item
 */
export interface PromptMessage {
  role: 'user' | 'assistant'
  content: PromptMessageContent
}

/**
 * Prompt handler result
 */
export interface PromptResult {
  description?: string
  messages: PromptMessage[]
}

/**
 * Content types for MCP responses
 */
export type ContentType = 'text' | 'resource' | 'structuredContent'

/**
 * Resource content structure
 */
export interface ResourceContent {
  uri: string
  mimeType?: string
  text?: string
}

/**
 * Structured content with schema
 */
export interface StructuredContent {
  type: string
  data: unknown
  schema?: JSONSchema
}

/**
 * Content item in tool result
 */
export interface Content {
  type: ContentType
  text?: string
  resource?: ResourceContent
  structuredContent?: StructuredContent
}

/**
 * Tool execution result
 */
export interface ToolResult {
  content: Content[]
  isError?: boolean
}

/**
 * Tool arguments (generic)
 */
export type ToolArgs = Record<string, unknown>

/**
 * Tool handler function type
 */
export type ToolHandler = (args: unknown) => Promise<ToolResult>

/**
 * Worker result from analysis workers
 */
export interface WorkerResult {
  ok: boolean
  data?: unknown
  errors?: string[]
  warnings?: string[]
  setup_actions?: unknown[]
  required_user_inputs?: unknown[]
  artifacts?: ArtifactRef[]
  metrics?: Record<string, unknown>
}

// ============================================================================
// Domain Types
// ============================================================================

export interface SampleInfo {
  sampleId: string
  sha256: string
  md5: string
  size: number
  path: string
}

export interface WorkspacePath {
  root: string
  original: string
  cache: string
  ghidra: string
  reports: string
}

export interface ArtifactRef {
  id: string
  type: string
  path: string
  sha256: string
  mime?: string
}

// ============================================================================
// Cache Types
// ============================================================================

/**
 * Parameters for cache key generation
 * Requirements: 20.1, 20.2
 */
export interface CacheKeyParams {
  sampleSha256: string
  toolName: string
  toolVersion: string
  args: Record<string, unknown>
  rulesetVersion?: string
}

/**
 * Cached result structure
 * Requirements: 20.3, 20.4, 20.5
 */
export interface CachedResult {
  key: string
  data: unknown
  createdAt: string
  expiresAt?: string
  sampleSha256?: string
}

// ============================================================================
// Error Handling Types
// ============================================================================

/**
 * Error categories for classification
 * Requirements: 22.1, 22.2, 22.3
 */
export enum ErrorCategory {
  // Retryable errors
  TIMEOUT = 'E_TIMEOUT',
  RESOURCE_EXHAUSTED = 'E_RESOURCE_EXHAUSTED',
  WORKER_UNAVAILABLE = 'E_WORKER_UNAVAILABLE',

  // Non-retryable errors
  INVALID_INPUT = 'E_INVALID_INPUT',
  PARSE_ERROR = 'E_PARSE_PE',
  POLICY_DENIED = 'E_POLICY_DENY',
  NOT_FOUND = 'E_NOT_FOUND',

  // Partial failures
  PARTIAL_SUCCESS = 'E_PARTIAL_SUCCESS',

  // Unknown errors
  UNKNOWN = 'E_UNKNOWN'
}

/**
 * Context for error handling
 * Requirements: 22.4
 */
export interface ErrorContext {
  tool: string
  sampleId: string
  attempt: number
  maxRetries: number
}

/**
 * Result of error handling
 * Requirements: 22.4, 22.5, 22.6
 */
export interface ErrorResult {
  shouldRetry: boolean
  backoffMs?: number
  fallbackAction?: string
}

// ============================================================================
// Job Queue Types
// ============================================================================

/**
 * Job priority levels (higher number = higher priority)
 * Requirements: 21.2
 */
export enum JobPriority {
  LOW = 1,
  NORMAL = 5,
  HIGH = 10,
  CRITICAL = 20
}

/**
 * Job execution status
 * Requirements: 21.1, 21.2
 */
export type JobStatusType = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'

/**
 * Retry policy for failed jobs
 * Requirements: 21.5
 */
export interface RetryPolicy {
  maxRetries: number
  backoffMs: number
  retryableErrors: string[]
}

/**
 * Job definition
 * Requirements: 21.1
 */
export interface Job {
  id: string
  type: 'static' | 'decompile' | 'dotnet' | 'sandbox'
  tool: string
  sampleId: string
  args: Record<string, unknown>
  priority: number
  timeout: number
  retryPolicy: RetryPolicy
  createdAt: string
  attempts: number
}

/**
 * Job status information
 * Requirements: 21.1, 21.2
 */
export interface JobStatus {
  id: string
  status: JobStatusType
  progress?: number
  startedAt?: string
  finishedAt?: string
  error?: string
}

/**
 * Job execution metrics
 * Requirements: 30.1, 30.2
 */
export interface JobMetrics {
  elapsedMs: number
  peakRssMb: number
  cpuPercent?: number
}

/**
 * Job execution result
 * Requirements: 21.4
 */
export interface JobResult {
  jobId: string
  ok: boolean
  data?: unknown
  errors: string[]
  warnings: string[]
  artifacts: ArtifactRef[]
  metrics: JobMetrics
}
