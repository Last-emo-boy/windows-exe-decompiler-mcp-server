/**
 * code.functions.reconstruct tool implementation
 * Function-level semantic reconstruction by combining decompile + CFG + assembly evidence.
 */

import { z } from 'zod'
import fs from 'fs'
import path from 'path'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import {
  DecompilerWorker,
  type RankedFunction,
  type DecompiledFunction,
  type ControlFlowGraph,
  type FunctionXrefSummary,
  type FunctionRelationship,
} from '../decompiler-worker.js'
import { findBestGhidraAnalysis } from '../ghidra-analysis-status.js'
import { ghidraConfig } from '../ghidra-config.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { runEntrypointFallbackDisasm, type EntrypointFallbackPayload } from './entrypoint-fallback-disasm.js'
import { loadDynamicTraceEvidence, type DynamicTraceSummary } from '../dynamic-trace.js'
import { createStringsExtractHandler } from './strings-extract.js'
import {
  correlateFunctionWithRuntimeEvidence,
  extractSensitiveApisFromReasons,
} from '../runtime-correlation.js'
import {
  findSemanticNameSuggestion,
  loadSemanticNameSuggestionIndex,
  type LoadedSemanticNameSuggestion,
  type SemanticNameSuggestionIndex,
  SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE,
} from '../semantic-name-suggestion-artifacts.js'
import {
  ConfidenceSemanticsSchema,
  buildNamingConfidenceSemantics,
  buildReconstructionConfidenceSemantics,
  buildRuntimeConfidenceSemantics,
} from '../confidence-semantics.js'
import {
  AnalysisProvenanceSchema,
  buildRuntimeArtifactProvenance,
  buildSemanticArtifactProvenance,
} from '../analysis-provenance.js'

const TOOL_NAME = 'code.functions.reconstruct'
const TOOL_VERSION = '0.2.14'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

export const CodeFunctionsReconstructInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  address: z.string().optional().describe('Specific function address (hex)'),
  symbol: z.string().optional().describe('Specific function symbol'),
  topk: z
    .number()
    .int()
    .min(1)
    .max(20)
    .default(3)
    .describe('When address/symbol not provided, reconstruct top-K ranked functions'),
  include_xrefs: z
    .boolean()
    .default(false)
    .describe('Include xrefs when calling function decompile'),
  max_pseudocode_lines: z
    .number()
    .int()
    .min(20)
    .max(300)
    .default(120)
    .describe('Maximum pseudocode lines in source-like snippet'),
  max_assembly_lines: z
    .number()
    .int()
    .min(10)
    .max(240)
    .default(80)
    .describe('Maximum assembly lines in assembly excerpt'),
  timeout: z
    .number()
    .int()
    .min(5)
    .max(300)
    .default(30)
    .describe('Per-function timeout in seconds'),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Runtime evidence scope: all artifacts, only the latest artifact window, or a specific session selector'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Semantic review artifact scope: all artifacts, only the latest semantic artifact window, or a specific semantic review session'),
  semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional semantic review session selector used when semantic_scope=session or to narrow all/latest results'),
})
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })

export type CodeFunctionsReconstructInput = z.infer<typeof CodeFunctionsReconstructInputSchema>

const FunctionXrefSignalSchema = z.object({
  api: z.string(),
  provenance: z.enum([
    'static_named_call',
    'dynamic_resolution_api',
    'dynamic_resolution_helper',
    'global_string_hint',
    'unknown',
  ]),
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
})

const FunctionRelationshipEntrySchema = z.object({
  target: z.string(),
  relation_types: z.array(z.string()),
  reference_types: z.array(z.string()),
  resolved_by: z.string().nullable(),
  is_exact: z.boolean().nullable(),
})

const FunctionRuntimeContextSchema = z
  .object({
    corroborated_apis: z.array(z.string()),
    corroborated_stages: z.array(z.string()),
    notes: z.array(z.string()),
    confidence: z.number().min(0).max(1),
    executed: z.boolean().optional(),
    evidence_sources: z.array(z.string()).optional(),
    source_names: z.array(z.string()).optional(),
    artifact_count: z.number().int().nonnegative().optional(),
    executed_artifact_count: z.number().int().nonnegative().optional(),
    matched_memory_regions: z.array(z.string()).optional(),
    matched_protections: z.array(z.string()).optional(),
    matched_address_ranges: z.array(z.string()).optional(),
    matched_region_owners: z.array(z.string()).optional(),
    matched_observed_modules: z.array(z.string()).optional(),
    matched_segment_names: z.array(z.string()).optional(),
    suggested_modules: z.array(z.string()).optional(),
    matched_by: z.array(z.string()).optional(),
    provenance_layers: z.array(z.string()).optional(),
    latest_artifact_at: z.string().nullable().optional(),
    scope_note: z.string().optional(),
  })
  .nullable()
  .optional()

const FunctionCFGShapeSchema = z.object({
  node_count: z.number().int().nonnegative(),
  edge_count: z.number().int().nonnegative(),
  has_loop: z.boolean(),
  has_branching: z.boolean(),
  block_types: z.array(z.string()),
  entry_block_type: z.string().nullable(),
})

const FunctionParameterRoleSchema = z.object({
  slot: z.string(),
  role: z.string(),
  inferred_type: z.string(),
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
})

const FunctionReturnRoleSchema = z.object({
  role: z.string(),
  inferred_type: z.string(),
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
})

const FunctionStateRoleSchema = z.object({
  state_key: z.string(),
  role: z.string(),
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
})

const FunctionStructFieldSchema = z.object({
  name: z.string(),
  inferred_type: z.string(),
  source_slot: z.string().nullable().optional(),
})

const FunctionStructInferenceSchema = z.object({
  semantic_name: z.string(),
  rewrite_type_name: z.string().nullable().optional(),
  kind: z.enum(['request', 'result', 'context', 'table', 'session']),
  confidence: z.number().min(0).max(1),
  fields: z.array(FunctionStructFieldSchema),
  evidence: z.array(z.string()),
})

const FunctionSemanticEvidenceSchema = z.object({
  semantic_summary: z.string(),
  xref_signals: z.array(FunctionXrefSignalSchema),
  call_relationships: z.object({
    callers: z.array(FunctionRelationshipEntrySchema),
    callees: z.array(FunctionRelationshipEntrySchema),
  }),
  runtime_context: FunctionRuntimeContextSchema,
  string_hints: z.array(z.string()),
  pseudocode_excerpt: z.string(),
  cfg_shape: FunctionCFGShapeSchema,
  parameter_roles: z.array(FunctionParameterRoleSchema),
  return_role: FunctionReturnRoleSchema.nullable().optional(),
  state_roles: z.array(FunctionStateRoleSchema),
  struct_inference: z.array(FunctionStructInferenceSchema),
})

const FunctionNameResolutionSchema = z.object({
  rule_based_name: z.string().nullable(),
  llm_suggested_name: z.string().nullable(),
  llm_confidence: z.number().min(0).max(1).nullable(),
  llm_why: z.string().nullable(),
  required_assumptions: z.array(z.string()),
  evidence_used: z.array(z.string()),
  validated_name: z.string().nullable(),
  resolution_source: z.enum(['rule', 'llm', 'hybrid', 'unresolved']),
  unresolved_semantic_name: z.boolean(),
})

const ReconstructedFunctionSchema = z.object({
  target: z.string(),
  function: z.string(),
  address: z.string(),
  rank_score: z.number().nullable(),
  rank_reasons: z.array(z.string()),
  suggested_name: z.string().nullable().optional(),
  suggested_role: z.string().nullable().optional(),
  rename_confidence: z.number().min(0).max(1).nullable().optional(),
  rename_evidence: z.array(z.string()).optional(),
  semantic_summary: z.string(),
  xref_signals: z.array(FunctionXrefSignalSchema),
  call_context: z.object({
    callers: z.array(z.string()),
    callees: z.array(z.string()),
  }),
  call_relationships: z.object({
    callers: z.array(FunctionRelationshipEntrySchema),
    callees: z.array(FunctionRelationshipEntrySchema),
  }),
  runtime_context: FunctionRuntimeContextSchema,
  parameter_roles: z.array(FunctionParameterRoleSchema).optional(),
  return_role: FunctionReturnRoleSchema.nullable().optional(),
  state_roles: z.array(FunctionStateRoleSchema).optional(),
  struct_inference: z.array(FunctionStructInferenceSchema).optional(),
  semantic_evidence: FunctionSemanticEvidenceSchema.optional(),
  name_resolution: FunctionNameResolutionSchema.optional(),
  confidence_profile: ConfidenceSemanticsSchema.optional(),
  runtime_confidence_profile: ConfidenceSemanticsSchema.nullable().optional(),
  naming_confidence_profile: ConfidenceSemanticsSchema.optional(),
  confidence: z.number().min(0).max(1),
  confidence_breakdown: z.object({
    decompile: z.number().min(0).max(1),
    cfg: z.number().min(0).max(1),
    assembly: z.number().min(0).max(1),
    context: z.number().min(0).max(1),
  }),
  gaps: z.array(z.string()),
  evidence: z.object({
    pseudocode_lines: z.number().int().nonnegative(),
    cfg_nodes: z.number().int().nonnegative(),
    cfg_edges: z.number().int().nonnegative(),
    instruction_count: z.number().int().nonnegative(),
    caller_count: z.number().int().nonnegative(),
    callee_count: z.number().int().nonnegative(),
  }),
  behavior_tags: z.array(z.string()),
  source_like_snippet: z.string(),
  assembly_excerpt: z.string(),
})
type ReconstructedFunction = z.infer<typeof ReconstructedFunctionSchema>
type FunctionXrefSignal = z.infer<typeof FunctionXrefSignalSchema>
type FunctionRelationshipEntry = z.infer<typeof FunctionRelationshipEntrySchema>
type FunctionRuntimeContext = z.infer<typeof FunctionRuntimeContextSchema>
type FunctionCFGShape = z.infer<typeof FunctionCFGShapeSchema>
type FunctionParameterRole = z.infer<typeof FunctionParameterRoleSchema>
type FunctionReturnRole = z.infer<typeof FunctionReturnRoleSchema>
type FunctionStateRole = z.infer<typeof FunctionStateRoleSchema>
type FunctionStructInference = z.infer<typeof FunctionStructInferenceSchema>
type FunctionNameResolution = z.infer<typeof FunctionNameResolutionSchema>

export const CodeFunctionsReconstructOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      mode: z.enum(['single', 'topk']),
      requested_count: z.number().int().nonnegative(),
      reconstructed_count: z.number().int().nonnegative(),
      overall_confidence: z.number().min(0).max(1),
      provenance: AnalysisProvenanceSchema,
      confidence_map: z.array(
        z.object({
          function: z.string(),
          address: z.string(),
          confidence: z.number().min(0).max(1),
          gaps: z.array(z.string()),
        })
      ),
      functions: z.array(ReconstructedFunctionSchema),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      cached: z.boolean().optional(),
      cache_key: z.string().optional(),
      cache_tier: z.string().optional(),
      cache_created_at: z.string().optional(),
      cache_expires_at: z.string().optional(),
      cache_hit_at: z.string().optional(),
    })
    .optional(),
})

export type CodeFunctionsReconstructOutput = z.infer<typeof CodeFunctionsReconstructOutputSchema>

export const codeFunctionsReconstructToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Reconstruct function-level semantics by combining decompile, CFG, and assembly evidence with confidence and unresolved gaps.',
  inputSchema: CodeFunctionsReconstructInputSchema,
  outputSchema: CodeFunctionsReconstructOutputSchema,
}

interface FunctionTarget {
  target: string
  rankScore: number | null
  rankReasons: string[]
  xrefSummary?: FunctionXrefSummary[]
}

interface ConfidenceBreakdown {
  decompile: number
  cfg: number
  assembly: number
  context: number
}

interface CodeFunctionsReconstructDependencies {
  rankFunctions?: (sampleId: string, topK: number) => Promise<RankedFunction[]>
  decompileFunction?: (
    sampleId: string,
    addressOrSymbol: string,
    includeXrefs: boolean,
    timeoutMs: number
  ) => Promise<DecompiledFunction>
  getFunctionCFG?: (
    sampleId: string,
    addressOrSymbol: string,
    timeoutMs: number
  ) => Promise<ControlFlowGraph>
  runtimeEvidenceLoader?: (
    sampleId: string,
    options?: { evidenceScope?: 'all' | 'latest' | 'session'; sessionTag?: string }
  ) => Promise<DynamicTraceSummary | null>
  stringEvidenceLoader?: (sampleId: string) => Promise<SampleStringEvidence | null>
  semanticNameSuggester?: (
    evidencePack: SemanticEvidencePack
  ) => Promise<ConstrainedSemanticNameSuggestion | null>
  externalSemanticSuggestionLoader?: (
    sampleId: string,
    options?: { scope?: 'all' | 'latest' | 'session'; sessionTag?: string }
  ) => Promise<SemanticNameSuggestionIndex | null>
}

interface SampleStringValue {
  offset: number
  string: string
  encoding?: string
  categories?: string[]
}

interface SampleStringContextWindow {
  start_offset: number
  end_offset: number
  score: number
  categories: string[]
  strings: SampleStringValue[]
}

interface SampleStringEvidence {
  top_high_value: SampleStringValue[]
  context_windows: SampleStringContextWindow[]
}

interface SemanticEvidencePack {
  function_name: string
  address: string
  semantic_summary: string
  xref_signals: FunctionXrefSignal[]
  call_relationships: RelationshipContext
  runtime_context: FunctionRuntimeContext | undefined
  string_hints: string[]
  pseudocode_excerpt: string
  cfg_shape: FunctionCFGShape
  parameter_roles: FunctionParameterRole[]
  return_role?: FunctionReturnRole | null
  state_roles: FunctionStateRole[]
  struct_inference: FunctionStructInference[]
}

interface ConstrainedSemanticNameSuggestion {
  candidate_name: string
  confidence: number
  why: string
  required_assumptions: string[]
  evidence_used: string[]
}

const SENSITIVE_API_SUMMARY_PATTERNS = [
  'WriteProcessMemory',
  'ReadProcessMemory',
  'CreateRemoteThread',
  'SetThreadContext',
  'ResumeThread',
  'OpenProcess',
  'CreateProcessA',
  'CreateProcessW',
  'WinExec',
  'ShellExecuteA',
  'ShellExecuteW',
  'VirtualAllocEx',
  'VirtualAlloc',
  'GetProcAddress',
  'LoadLibraryA',
  'LoadLibraryW',
  'LoadLibraryExA',
  'LoadLibraryExW',
  'InternetOpenA',
  'InternetOpenW',
  'InternetConnectA',
  'InternetConnectW',
  'HttpSendRequestA',
  'HttpSendRequestW',
  'RegOpenKeyExA',
  'RegOpenKeyExW',
  'RegSetValueExA',
  'RegSetValueExW',
  'CreateFileA',
  'CreateFileW',
  'WriteFile',
  'ReadFile',
  'DeleteFileA',
  'DeleteFileW',
  'BCryptEncrypt',
  'BCryptDecrypt',
  'IsDebuggerPresent',
  'CheckRemoteDebuggerPresent',
  'NtQueryInformationProcess',
  'NtQuerySystemInformation',
]

const KNOWN_LIBRARY_SYMBOL_NAMES = new Set([
  'memcpy',
  'memcmp',
  'memset',
  'strlen',
  'strcmp',
  'strncmp',
  'strcpy',
  'strncpy',
  'strcat',
  'strncat',
  'malloc',
  'calloc',
  'realloc',
  'free',
  'qsort',
  'bsearch',
])

const LINKED_SUGGESTION_PRIORITY_PREFIXES = [
  'resolve_',
  'prepare_',
  'transfer_',
  'query_',
  'scan_',
  'dispatch_',
  'read_',
  'write_',
  'inspect_',
  'collect_',
  'build_',
  'finalize_',
] as const

type RelationshipSummaryEntry = FunctionRelationshipEntry
type RelationshipContext = {
  callers: RelationshipSummaryEntry[]
  callees: RelationshipSummaryEntry[]
}

interface RenameSuggestion {
  suggested_name: string | null
  suggested_role: string | null
  rename_confidence: number
  rename_evidence: string[]
}

interface SnippetBodyShape {
  pseudocode: string
  is_void_return_stub: boolean
  constant_return: number | null
  has_trap_tail: boolean
}

const SEMANTIC_STOPWORDS = new Set([
  'this',
  'that',
  'with',
  'from',
  'into',
  'then',
  'void',
  'code',
  'true',
  'false',
  'return',
  'call',
  'calls',
  'function',
  'likely',
  'after',
  'before',
  'using',
  'through',
  'stage',
])

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.length > 0)))
}

function uniqBy<T>(items: T[], keyFn: (item: T) => string): T[] {
  const seen = new Set<string>()
  const output: T[] = []
  for (const item of items) {
    const key = keyFn(item)
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    output.push(item)
  }
  return output
}

function buildNamedAddressLabel(item: { address: string; name: string }): string {
  if (item.name && item.address) {
    return `${item.name}@${item.address}`
  }
  return item.name || item.address || 'unknown'
}

function buildRelationshipTargetLabel(relationship: FunctionRelationship): string {
  if (relationship.name && relationship.address) {
    return `${relationship.name}@${relationship.address}`
  }
  return relationship.name || relationship.address || 'unknown'
}

function buildRelationshipSummaryEntry(
  relationship: FunctionRelationship
): RelationshipSummaryEntry {
  return {
    target: buildRelationshipTargetLabel(relationship),
    relation_types: dedupe(relationship.relation_types || []).slice(0, 4),
    reference_types: dedupe(relationship.reference_types || []).slice(0, 4),
    resolved_by: relationship.resolved_by || null,
    is_exact: typeof relationship.is_exact === 'boolean' ? relationship.is_exact : null,
  }
}

function buildRelationshipContext(
  decompiled: DecompiledFunction | undefined
): RelationshipContext {
  const buildEntries = (
    relationships: FunctionRelationship[] | undefined,
    directEntries: Array<{ address: string; name: string }>,
    limit: number
  ): RelationshipSummaryEntry[] => {
    const relationshipEntries = (relationships || []).map((relationship) =>
      buildRelationshipSummaryEntry(relationship)
    )
    const coveredTargets = new Set(relationshipEntries.map((item) => item.target))
    const entries: RelationshipSummaryEntry[] = [
      ...relationshipEntries,
      ...directEntries.map((item) => ({
        target: buildNamedAddressLabel(item),
        relation_types: [],
        reference_types: [],
        resolved_by: null,
        is_exact: true,
      })),
    ].filter((item) => !coveredTargets.has(item.target) || item.relation_types.length > 0)

    return uniqBy(
      entries.filter((item) => item.target.length > 0),
      (item) =>
        `${item.target}|${item.relation_types.join(',')}|${item.reference_types.join(',')}|${item.resolved_by || ''}|${item.is_exact === null ? 'unknown' : item.is_exact ? 'exact' : 'heuristic'}`
    ).slice(0, limit)
  }

  return {
    callers: buildEntries(decompiled?.caller_relationships, decompiled?.callers || [], 6),
    callees: buildEntries(decompiled?.callee_relationships, decompiled?.callees || [], 8),
  }
}

function formatRelationshipEntry(entry: RelationshipSummaryEntry): string {
  const details = dedupe([
    ...(entry.relation_types || []),
    ...(entry.reference_types || []),
    entry.resolved_by ? `resolved_by=${entry.resolved_by}` : '',
    entry.is_exact === false ? 'heuristic' : '',
  ]).filter((item) => item.length > 0)

  if (details.length === 0) {
    return entry.target
  }
  return `${entry.target} [${details.join('; ')}]`
}

function summarizeRelationshipInsights(relationships: RelationshipContext): string | null {
  const insights = [
    ...relationships.callers
      .filter(
        (item) =>
          item.relation_types.length > 0 || item.reference_types.length > 0 || item.resolved_by
      )
      .slice(0, 1)
      .map((item) => `caller ${formatRelationshipEntry(item)}`),
    ...relationships.callees
      .filter(
        (item) =>
          item.relation_types.length > 0 || item.reference_types.length > 0 || item.resolved_by
      )
      .slice(0, 2)
      .map((item) => `callee ${formatRelationshipEntry(item)}`),
  ].slice(0, 2)

  if (insights.length === 0) {
    return null
  }

  return `relationship recovery links this routine to ${insights.join(' and ')}`
}

function parsePseudocodeLines(pseudocode: string | undefined): string[] {
  if (!pseudocode) {
    return []
  }
  return pseudocode
    .split(/\r?\n/)
    .map((line) => line.replace(/\s+$/g, ''))
    .filter((line) => line.length > 0)
}

function extractAssemblyFromCFG(
  cfg: ControlFlowGraph | undefined,
  maxLines: number
): { excerpt: string; instructionCount: number } {
  if (!cfg || cfg.nodes.length === 0) {
    return {
      excerpt: '; assembly unavailable (missing CFG)',
      instructionCount: 0,
    }
  }

  const lines: string[] = []
  let instructionCount = 0

  for (const node of cfg.nodes) {
    lines.push(`; block ${node.id} (${node.type}) @ ${node.address}`)
    for (const instruction of node.instructions) {
      instructionCount += 1
      if (lines.length < maxLines) {
        lines.push(instruction)
      }
    }
    if (lines.length < maxLines) {
      lines.push('')
    }
    if (lines.length >= maxLines) {
      break
    }
  }

  if (instructionCount > 0 && lines.length >= maxLines) {
    lines[lines.length - 1] = '; ...truncated'
  }

  return {
    excerpt: lines.join('\n'),
    instructionCount,
  }
}

function collectGaps(
  pseudocodeLines: string[],
  cfg: ControlFlowGraph | undefined,
  decompiled: DecompiledFunction | undefined,
  maxPseudocodeLines: number
): string[] {
  const gaps: string[] = []
  const pseudocode = pseudocodeLines.join('\n')
  const callerCount = Math.max(
    decompiled?.callers.length || 0,
    decompiled?.caller_relationships?.length || 0
  )
  const calleeCount = Math.max(
    decompiled?.callees.length || 0,
    decompiled?.callee_relationships?.length || 0
  )

  if (!decompiled || pseudocodeLines.length === 0) {
    gaps.push('missing_pseudocode')
  }

  if (!cfg || cfg.nodes.length === 0) {
    gaps.push('missing_cfg')
  } else if (cfg.nodes.length <= 1) {
    gaps.push('limited_control_flow_visibility')
  }

  if (decompiled && callerCount === 0 && calleeCount === 0) {
    gaps.push('limited_call_context')
  }

  if (pseudocodeLines.length > maxPseudocodeLines) {
    gaps.push('snippet_truncated')
  }

  if (/\bDAT_[0-9a-f]+\b/i.test(pseudocode) || /\bundefined\d*\b/i.test(pseudocode)) {
    gaps.push('unresolved_data_symbols')
  }

  if (/\bFUN_[0-9a-f]+\b/i.test(pseudocode)) {
    gaps.push('unresolved_function_symbols')
  }

  if (!decompiled && !cfg) {
    gaps.push('missing_all_primary_evidence')
  }

  return dedupe(gaps)
}

function inferBehaviorTags(decompiled: DecompiledFunction | undefined, assembly: string): string[] {
  const relationshipCorpus = [
    ...(decompiled?.callers || []).map((item) => item.name),
    ...(decompiled?.callees || []).map((item) => item.name),
    ...(decompiled?.caller_relationships || []).flatMap((item) => [item.name, item.resolved_by]),
    ...(decompiled?.callee_relationships || []).flatMap((item) => [item.name, item.resolved_by]),
  ]
    .filter((item): item is string => typeof item === 'string' && item.length > 0)
    .join('\n')
  const corpus = `${decompiled?.pseudocode || ''}\n${assembly}\n${relationshipCorpus}`
  const checks: Array<{ tag: string; regex: RegExp }> = [
    {
      tag: 'process_injection',
      regex: /\b(WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|NtWriteVirtualMemory)\b/i,
    },
    { tag: 'process_spawn', regex: /\b(CreateProcess(?:A|W)?|WinExec|ShellExecute(?:A|W)?)\b/i },
    {
      tag: 'networking',
      regex: /\b(InternetOpen(?:A|W)?|InternetConnect(?:A|W)?|HttpSendRequest(?:A|W)?|WinHttp\w*|socket|connect|WSAStartup|send|recv|bind|listen|accept)\b/i,
    },
    { tag: 'file_io', regex: /\b(CreateFile(?:A|W)?|WriteFile|ReadFile|DeleteFile)\b/i },
    { tag: 'registry', regex: /\b(RegSetValue|RegSetValueEx|RegOpenKey|RegCreateKey)\b/i },
    { tag: 'crypto', regex: /\b(CryptAcquire|CryptEncrypt|CryptDecrypt|BCrypt)\b/i },
    {
      tag: 'anti_debug',
      regex: /\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\b/i,
    },
    {
      tag: 'service_control',
      regex: /\b(CreateService(?:A|W)?|StartService(?:A|W)?|OpenSCManager(?:A|W)?|ControlService|RegisterServiceCtrlHandler(?:A|W)?)\b/i,
    },
    {
      tag: 'com_activation',
      regex: /\b(CoCreateInstance|QueryInterface|RegisterClassObject|DllGetClassObject|IID_|CLSID_)\b/i,
    },
    {
      tag: 'dll_lifecycle',
      regex: /\b(DllMain|DllRegisterServer|DllUnregisterServer|DllInstall|DLL_PROCESS_ATTACH|DLL_THREAD_ATTACH)\b/i,
    },
    {
      tag: 'export_dispatch',
      regex: /\b(export|ordinal|forwarder|DllGetClassObject|DllCanUnloadNow)\b/i,
    },
    {
      tag: 'plugin_callback',
      regex: /\b(callback|plugin|host interface|event sink|notification handler)\b/i,
    },
  ]

  return checks.filter((item) => item.regex.test(corpus)).map((item) => item.tag)
}

function buildCallContext(decompiled: DecompiledFunction | undefined): {
  callers: string[]
  callees: string[]
} {
  const relationships = buildRelationshipContext(decompiled)
  const callerRelationshipTargets = new Set(relationships.callers.map((item) => item.target))
  const calleeRelationshipTargets = new Set(relationships.callees.map((item) => item.target))
  const callers = dedupe([
    ...(decompiled?.callers || [])
      .map((item) => buildNamedAddressLabel(item))
      .filter((item) => !callerRelationshipTargets.has(item)),
    ...relationships.callers.map((item) => formatRelationshipEntry(item)),
  ]).slice(0, 6)
  const callees = dedupe([
    ...(decompiled?.callees || [])
      .map((item) => buildNamedAddressLabel(item))
      .filter((item) => !calleeRelationshipTargets.has(item)),
    ...relationships.callees.map((item) => formatRelationshipEntry(item)),
  ]).slice(0, 8)

  return { callers, callees }
}

function normalizeCalleeApiCandidate(raw: string | undefined): string | null {
  if (!raw) {
    return null
  }

  const candidate = raw.trim()
  if (candidate.length < 3) {
    return null
  }
  if (/^(FUN|LAB|DAT|UNK|sub)_[0-9a-f]+$/i.test(candidate)) {
    return null
  }
  if (/^0x[0-9a-f]+$/i.test(candidate)) {
    return null
  }
  if (!/[A-Za-z]/.test(candidate)) {
    return null
  }
  return candidate
}

function inferRelationshipProvenance(
  relationship: FunctionRelationship,
  api: string
): FunctionXrefSummary['provenance'] {
  const relationCorpus = [
    api,
    ...(relationship.relation_types || []),
    ...(relationship.reference_types || []),
    relationship.resolved_by || '',
  ]
    .join(' ')
    .toLowerCase()

  if (
    /^GetProcAddress$/i.test(api) ||
    /^LoadLibrary/i.test(api) ||
    relationCorpus.includes('dynamic') ||
    relationCorpus.includes('getprocaddress') ||
    relationCorpus.includes('loadlibrary')
  ) {
    return /^GetProcAddress$/i.test(api) || /^LoadLibrary/i.test(api)
      ? 'dynamic_resolution_api'
      : 'dynamic_resolution_helper'
  }

  if (
    relationCorpus.includes('string') ||
    (relationCorpus.includes('data') && relationCorpus.includes('body_reference_hint'))
  ) {
    return 'global_string_hint'
  }

  if (
    relationCorpus.includes('direct_call') ||
    relationCorpus.includes('tail_jump_hint') ||
    relationCorpus.includes('call')
  ) {
    return 'static_named_call'
  }

  return 'unknown'
}

function buildRelationshipEvidence(relationship: FunctionRelationship): string[] {
  return dedupe([
    ...(relationship.relation_types || []).map((item) => `relation:${item}`),
    ...(relationship.reference_types || []).map((item) => `reference:${item}`),
    ...(relationship.reference_addresses || []).slice(0, 2).map((item) => `ref_addr:${item}`),
    relationship.resolved_by ? `resolved_by:${relationship.resolved_by}` : '',
    typeof relationship.is_exact === 'boolean'
      ? `is_exact:${relationship.is_exact ? 'true' : 'false'}`
      : '',
  ])
}

function collectXrefSignals(
  target: FunctionTarget,
  decompiled: DecompiledFunction | undefined,
  assemblyExcerpt: string
): FunctionXrefSummary[] {
  const signals: FunctionXrefSummary[] = []
  const pushSignal = (signal: FunctionXrefSummary) => {
    signals.push({
      api: signal.api,
      provenance: signal.provenance,
      confidence: clamp(signal.confidence, 0, 1),
      evidence: dedupe(signal.evidence),
    })
  }

  for (const signal of target.xrefSummary || []) {
    pushSignal(signal)
  }

  for (const reason of target.rankReasons) {
    const match = /^calls_sensitive_api:(.+)$/i.exec(reason)
    if (!match) {
      continue
    }
    pushSignal({
      api: match[1],
      provenance: 'static_named_call',
      confidence: 0.6,
      evidence: [`rank_reason:${match[1]}`],
    })
  }

  for (const callee of decompiled?.callees || []) {
    const api = normalizeCalleeApiCandidate(callee.name)
    if (!api) {
      continue
    }
    pushSignal({
      api,
      provenance: 'static_named_call',
      confidence: 0.55,
      evidence: [`callee:${api}`],
    })
  }

  for (const relationship of decompiled?.callee_relationships || []) {
    const api =
      normalizeCalleeApiCandidate(relationship.name) ||
      normalizeCalleeApiCandidate(relationship.resolved_by)
    if (!api) {
      continue
    }
    const provenance = inferRelationshipProvenance(relationship, api)
    const confidenceByProvenance: Record<FunctionXrefSummary['provenance'], number> = {
      static_named_call: 0.63,
      dynamic_resolution_api: 0.76,
      dynamic_resolution_helper: 0.68,
      global_string_hint: 0.46,
      unknown: 0.4,
    }
    pushSignal({
      api,
      provenance,
      confidence: confidenceByProvenance[provenance],
      evidence: buildRelationshipEvidence(relationship),
    })
  }

  const textCorpus = `${decompiled?.pseudocode || ''}\n${assemblyExcerpt}`
  for (const api of SENSITIVE_API_SUMMARY_PATTERNS) {
    const matcher = new RegExp(`\\b${api.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}\\b`, 'i')
    if (!matcher.test(textCorpus)) {
      continue
    }
    const provenance: FunctionXrefSummary['provenance'] =
      /^GetProcAddress$|^LoadLibrary/i.test(api) ? 'dynamic_resolution_api' : 'static_named_call'
    pushSignal({
      api,
      provenance,
      confidence: provenance === 'dynamic_resolution_api' ? 0.72 : 0.58,
      evidence: [`text_match:${api}`],
    })
  }

  return uniqBy(signals, (item) => `${item.api.toLowerCase()}|${item.provenance}`)
    .sort((a, b) => b.confidence - a.confidence || a.api.localeCompare(b.api))
    .slice(0, 8)
}

function describeBehaviorTag(tag: string): string {
  const mapping: Record<string, string> = {
    process_injection: 'remote process injection',
    process_spawn: 'process creation or command execution',
    networking: 'network communication',
    file_io: 'file system operations',
    registry: 'registry access',
    crypto: 'cryptographic processing',
    anti_debug: 'anti-analysis checks',
    service_control: 'service control logic',
    com_activation: 'COM activation or interface brokering',
    dll_lifecycle: 'DLL entrypoint or registration handling',
    export_dispatch: 'DLL export dispatch or host-facing command routing',
    plugin_callback: 'plugin or callback-driven host integration',
  }
  return mapping[tag] || tag.replace(/_/g, ' ')
}

function buildRenameSuggestion(
  functionName: string,
  behaviorTags: string[],
  xrefSignals: FunctionXrefSummary[],
  callContext: { callers: string[]; callees: string[] },
  relationshipContext: RelationshipContext,
  gaps: string[],
  rankReasons: string[],
  semanticSummary: string,
  additionalEvidenceText: string,
  runtimeContext?: {
    corroborated_apis: string[]
    corroborated_stages: string[]
    notes: string[]
    confidence: number
    executed?: boolean
  }
): RenameSuggestion {
  const normalizedFunctionName = functionName.trim().toLowerCase()
  if (KNOWN_LIBRARY_SYMBOL_NAMES.has(normalizedFunctionName)) {
    return {
      suggested_name: null,
      suggested_role: null,
      rename_confidence: 0,
      rename_evidence: [],
    }
  }

  const apiSet = new Set(
    xrefSignals.map((item) => item.api.toLowerCase()).filter((item) => item.length > 0)
  )
  const stageSet = new Set(
    (runtimeContext?.corroborated_stages || []).map((item) => item.toLowerCase())
  )
  const tagSet = new Set(behaviorTags.map((item) => item.toLowerCase()))
  const textCorpus = [
    functionName,
    semanticSummary,
    additionalEvidenceText,
    ...rankReasons,
    ...callContext.callers,
    ...callContext.callees,
    ...relationshipContext.callers.map((item) => item.target),
    ...relationshipContext.callees.map((item) => item.target),
    ...relationshipContext.callers.flatMap((item) => item.relation_types || []),
    ...relationshipContext.callees.flatMap((item) => item.relation_types || []),
    ...gaps,
    ...(runtimeContext?.notes || []),
  ]
    .join('\n')
    .toLowerCase()

  const evidence: string[] = []
  const hasApi = (...apis: string[]) =>
    apis.some((api) => apiSet.has(api.toLowerCase()))
  const hasStage = (...stages: string[]) =>
    stages.some((stage) => stageSet.has(stage.toLowerCase()))
  const hasTag = (...tags: string[]) => tags.some((tag) => tagSet.has(tag.toLowerCase()))
  const textHas = (pattern: RegExp) => pattern.test(textCorpus)
  const callerCount = callContext.callers.length
  const calleeCount = callContext.callees.length
  const hasTailJumpHint =
    functionName.toLowerCase().startsWith('thunk_') ||
    textHas(/\btail_jump_hint\b|\bunconditional_jump\b|\bthunk_fun_\b/i)

  const finalize = (
    suggestedName: string,
    suggestedRole: string,
    baseConfidence: number,
    matchedEvidence: string[]
  ): RenameSuggestion => ({
    suggested_name: suggestedName,
    suggested_role: suggestedRole,
    rename_confidence: clamp(
      baseConfidence +
        (runtimeContext?.executed ? 0.06 : 0) +
        Math.min((matchedEvidence.length - 1) * 0.03, 0.12),
      0.35,
      0.98
    ),
    rename_evidence: dedupe(matchedEvidence).slice(0, 6),
  })

  if (hasTailJumpHint && calleeCount >= 1) {
    if (functionName.toLowerCase().startsWith('thunk_')) {
      evidence.push('name:thunk')
    }
    if (textHas(/\btail_jump_hint\b/i)) {
      evidence.push('relation:tail_jump_hint')
    }
    if (calleeCount === 1) {
      evidence.push('callee_count:1')
    }
    return finalize(
      'tailcall_dispatch_thunk',
      'Thin forwarding thunk that jumps into a resolved callee or dispatch target.',
      0.72,
      evidence
    )
  }

  if (hasApi('ReadProcessMemory') || hasStage('read_remote_memory')) {
    evidence.push('api:ReadProcessMemory')
    if (hasStage('prepare_remote_process_access')) {
      evidence.push('stage:prepare_remote_process_access')
    }
    return finalize(
      'read_remote_memory',
      'Reads remote process memory after preparing a target process handle.',
      0.82,
      evidence
    )
  }

  if (hasApi('WriteProcessMemory')) {
    evidence.push('api:WriteProcessMemory')
    if (hasApi('VirtualAllocEx')) {
      evidence.push('api:VirtualAllocEx')
    }
    if (hasStage('prepare_remote_process_access')) {
      evidence.push('stage:prepare_remote_process_access')
    }
    return finalize(
      'write_remote_memory',
      'Writes payload or control data into a remote process address space.',
      0.86,
      evidence
    )
  }

  if (
    hasApi('SetThreadContext', 'ResumeThread', 'CreateRemoteThread') ||
    hasStage('transfer_remote_execution', 'resume_remote_thread')
  ) {
    if (hasApi('SetThreadContext')) {
      evidence.push('api:SetThreadContext')
    }
    if (hasApi('ResumeThread')) {
      evidence.push('api:ResumeThread')
    }
    if (hasApi('CreateRemoteThread')) {
      evidence.push('api:CreateRemoteThread')
    }
    if (hasStage('transfer_remote_execution')) {
      evidence.push('stage:transfer_remote_execution')
    }
    return finalize(
      'transfer_remote_execution',
      'Transfers execution into a prepared remote process or thread context.',
      0.84,
      evidence
    )
  }

  if (
    hasApi('GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW') ||
    hasStage('resolve_dynamic_apis')
  ) {
    if (hasApi('GetProcAddress')) {
      evidence.push('api:GetProcAddress')
    }
    if (
      hasApi('LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW')
    ) {
      evidence.push('api:LoadLibrary*')
    }
    if (hasStage('resolve_dynamic_apis')) {
      evidence.push('stage:resolve_dynamic_apis')
    }
    return finalize(
      'resolve_dynamic_apis',
      'Builds or refreshes runtime API resolver state before later actions.',
      0.8,
      evidence
    )
  }

  if (
    hasApi('OpenProcess', 'CreateProcessA', 'CreateProcessW') ||
    hasStage('prepare_remote_process_access', 'spawn_remote_target') ||
    (hasTag('process_spawn', 'process_injection') && textHas(/\b(openprocess|createprocess|remote process)\b/i))
  ) {
    if (hasApi('OpenProcess')) {
      evidence.push('api:OpenProcess')
    }
    if (hasApi('CreateProcessA', 'CreateProcessW')) {
      evidence.push('api:CreateProcess*')
    }
    if (hasStage('prepare_remote_process_access')) {
      evidence.push('stage:prepare_remote_process_access')
    }
    return finalize(
      'prepare_remote_process_access',
      'Prepares a target process, launch context, or access token for later memory operations.',
      0.78,
      evidence
    )
  }

  if (
    hasApi('NtQueryInformationProcess') ||
    hasStage('inspect_process_context') ||
    textHas(/\bpeb|remote process snapshot|process information\b/i)
  ) {
    evidence.push('api:NtQueryInformationProcess')
    return finalize(
      'query_remote_process_snapshot',
      'Collects remote process state such as handles, PEB-adjacent metadata, or integrity flags.',
      0.77,
      evidence
    )
  }

  if (
    hasApi('NtQuerySystemInformation') ||
    textHas(/\bcode integrity|kernel_code_integrity_status_raw\b/i)
  ) {
    if (hasApi('NtQuerySystemInformation')) {
      evidence.push('api:NtQuerySystemInformation')
    }
    if (textHas(/\bcode integrity|kernel_code_integrity_status_raw\b/i)) {
      evidence.push('text:code_integrity')
    }
    return finalize(
      'query_code_integrity_state',
      'Queries system-level integrity or anti-analysis state before operator actions.',
      0.79,
      evidence
    )
  }

  if (
    textHas(/\bpacker|protector|vmprotect|themida|upx|entry point in non-first section\b/i)
  ) {
    evidence.push('text:packer_detection')
    return finalize(
      'scan_packer_signatures',
      'Scans PE layout and signature indicators for common packers or protectors.',
      0.83,
      evidence
    )
  }

  if (
    hasApi('CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 'DeleteFileA', 'DeleteFileW') ||
    hasTag('file_io')
  ) {
    if (hasApi('CreateFileA', 'CreateFileW')) {
      evidence.push('api:CreateFile*')
    }
    if (hasApi('ReadFile', 'WriteFile', 'DeleteFileA', 'DeleteFileW')) {
      evidence.push('api:file_io')
    }
    return finalize(
      'dispatch_file_operations',
      'Coordinates file-system access such as opening, reading, writing, or deleting files.',
      0.73,
      evidence
    )
  }

  if (
    rankReasons.includes('high_callers') &&
    callerCount >= 4 &&
    calleeCount >= 2 &&
    gaps.includes('unresolved_function_symbols')
  ) {
    evidence.push('rank_reason:high_callers')
    evidence.push(`caller_count:${callerCount}`)
    evidence.push(`callee_count:${calleeCount}`)
    evidence.push('gap:unresolved_function_symbols')
    return finalize(
      'dispatch_shared_routine',
      'Shared high-fan-in dispatcher that fans out into several subordinate routines.',
      0.66,
      evidence
    )
  }

  if (textHas(/\bdispatch|table|capability\b/i) || rankReasons.includes('entry_point')) {
    if (textHas(/\bdispatch\b/i)) {
      evidence.push('text:dispatch')
    }
    if (textHas(/\bcapability\b/i)) {
      evidence.push('text:capability')
    }
    if (rankReasons.includes('entry_point')) {
      evidence.push('rank_reason:entry_point')
    }
    return finalize(
      'dispatch_module_capabilities',
      'Acts as a dispatcher that routes execution into subordinate capability handlers.',
      0.62,
      evidence
    )
  }

  return {
    suggested_name: null,
    suggested_role: null,
    rename_confidence: 0,
    rename_evidence: [],
  }
}

function withSuggestedNameHeader(
  sourceLikeSnippet: string,
  suggestion: RenameSuggestion | null | undefined
): string {
  const baseLines = sourceLikeSnippet
    .split(/\r?\n/)
    .filter((line) => !line.startsWith('// suggested_name='))

  if (!suggestion?.suggested_name) {
    return baseLines.join('\n')
  }

  return [
    `// suggested_name=${suggestion.suggested_name} role=${suggestion.suggested_role || 'unknown'} rename_confidence=${suggestion.rename_confidence.toFixed(2)} evidence=${suggestion.rename_evidence.join(', ') || 'none'}`,
    ...baseLines,
  ].join('\n')
}

function extractSnippetBodyShape(sourceLikeSnippet: string): SnippetBodyShape {
  const pseudocode = sourceLikeSnippet
    .split(/\r?\n/)
    .filter((line) => !line.startsWith('//'))
    .join('\n')
    .trim()

  const compact = pseudocode.replace(/\s+/g, ' ').trim()
  const constantReturnMatch = compact.match(/\breturn\s+(-?\d+)\s*;/)
  const constantReturn = constantReturnMatch ? Number(constantReturnMatch[1]) : null

  return {
    pseudocode,
    is_void_return_stub: /\{\s*return;\s*\}\s*$/i.test(compact),
    constant_return: Number.isFinite(constantReturn) ? constantReturn : null,
    has_trap_tail:
      /\bswi\s*\(\s*3\s*\)|\b(__debugbreak|debugbreak|trap|abort|unreachable)\b/i.test(compact),
  }
}

function normalizeSemanticHint(value: string, maxLength = 120): string {
  return value.replace(/\s+/g, ' ').trim().slice(0, maxLength)
}

function tokenizeSemanticText(value: string): string[] {
  return dedupe(
    value
      .toLowerCase()
      .split(/[^a-z0-9_]+/)
      .map((token) => token.trim())
      .filter((token) => token.length >= 4 && !SEMANTIC_STOPWORDS.has(token))
  )
}

function buildCFGShape(cfg?: ControlFlowGraph): SemanticEvidencePack['cfg_shape'] {
  const blockTypes = dedupe((cfg?.nodes || []).map((node) => node.type))
  const entryBlockType = cfg?.nodes.find((node) => node.type === 'entry')?.type || cfg?.nodes[0]?.type || null
  const loopEdges = (cfg?.edges || []).filter((edge) => edge.from === edge.to)
  const outgoingCount = new Map<string, number>()
  for (const edge of cfg?.edges || []) {
    outgoingCount.set(edge.from, (outgoingCount.get(edge.from) || 0) + 1)
  }
  return {
    node_count: cfg?.nodes.length || 0,
    edge_count: cfg?.edges.length || 0,
    has_loop: loopEdges.length > 0,
    has_branching: Array.from(outgoingCount.values()).some((count) => count > 1),
    block_types: blockTypes,
    entry_block_type: entryBlockType,
  }
}

function buildPseudocodeExcerpt(sourceLikeSnippet: string, maxLines = 10): string {
  const lines = sourceLikeSnippet
    .split(/\r?\n/)
    .filter((line) => !line.startsWith('//'))
    .slice(0, maxLines)
  return lines.join('\n').trim()
}

function buildFunctionStringHints(
  sampleStrings: SampleStringEvidence | null,
  functionName: string,
  behaviorTags: string[],
  xrefSignals: FunctionXrefSummary[],
  runtimeContext: ReturnType<typeof correlateFunctionWithRuntimeEvidence> | undefined,
  semanticSummary: string,
  sourceLikeSnippet: string
): string[] {
  if (!sampleStrings) {
    return []
  }

  const keywords = new Set([
    ...tokenizeSemanticText(functionName),
    ...behaviorTags.map((tag) => tag.toLowerCase()),
    ...xrefSignals.flatMap((item) => tokenizeSemanticText(item.api)),
    ...(runtimeContext?.corroborated_stages || []).map((item) => item.toLowerCase()),
    ...(runtimeContext?.corroborated_apis || []).flatMap((item) => tokenizeSemanticText(item)),
    ...tokenizeSemanticText(semanticSummary),
  ])
  const evidenceCorpus = `${semanticSummary}\n${sourceLikeSnippet}`.toLowerCase()
  const scoredHints: Array<{ hint: string; score: number }> = []

  const consider = (rawValue: string, baseScore: number) => {
    const hint = normalizeSemanticHint(rawValue)
    if (!hint) {
      return
    }
    const lowered = hint.toLowerCase()
    let score = baseScore
    for (const keyword of keywords) {
      if (lowered.includes(keyword)) {
        score += 2
      }
    }
    if (xrefSignals.some((item) => lowered.includes(item.api.toLowerCase()))) {
      score += 3
    }
    if ((runtimeContext?.corroborated_stages || []).some((item) => lowered.includes(item.toLowerCase()))) {
      score += 3
    }
    if ((runtimeContext?.corroborated_apis || []).some((item) => lowered.includes(item.toLowerCase()))) {
      score += 2
    }
    if (evidenceCorpus.includes(lowered)) {
      score += 1
    }
    if (/(packer|protector|entry point|section|vmprotect|themida|upx|readprocessmemory|writeprocessmemory|getprocaddress|loadlibrary)/i.test(hint)) {
      score += 2
    }
    scoredHints.push({ hint, score })
  }

  for (const item of sampleStrings.top_high_value || []) {
    consider(item.string, 3)
  }
  for (const window of sampleStrings.context_windows || []) {
    for (const item of window.strings || []) {
      consider(item.string, 1 + Math.min(window.score, 6))
    }
  }

  return scoredHints
    .sort((a, b) => b.score - a.score || a.hint.localeCompare(b.hint))
    .map((item) => item.hint)
    .filter((value, index, all) => all.indexOf(value) === index)
    .slice(0, 6)
}

function inferParameterRoles(
  behaviorTags: string[],
  xrefSignals: FunctionXrefSummary[],
  runtimeContext: ReturnType<typeof correlateFunctionWithRuntimeEvidence> | undefined,
  stringHints: string[],
  semanticSummary: string,
  sourceLikeSnippet: string
): z.infer<typeof FunctionParameterRoleSchema>[] {
  const roles: z.infer<typeof FunctionParameterRoleSchema>[] = []
  const corpus = [
    semanticSummary,
    sourceLikeSnippet,
    ...stringHints,
    ...xrefSignals.map((item) => `${item.api} ${item.provenance}`),
    ...(runtimeContext?.corroborated_apis || []),
    ...(runtimeContext?.corroborated_stages || []),
    ...behaviorTags,
  ]
    .join('\n')
    .toLowerCase()

  const addRole = (
    slot: string,
    role: string,
    inferredType: string,
    confidence: number,
    evidence: string[]
  ) => {
    if (roles.some((item) => item.slot === slot && item.role === role)) {
      return
    }
    roles.push({
      slot,
      role,
      inferred_type: inferredType,
      confidence: clamp(confidence, 0, 1),
      evidence: dedupe(evidence),
    })
  }

  const hasProcessOps =
    behaviorTags.some((tag) => ['process_injection', 'process_spawn', 'anti_debug'].includes(tag)) ||
    /(writeprocessmemory|readprocessmemory|openprocess|createremotethread|setthreadcontext|resumethread|createprocessw|createprocessa)/i.test(
      corpus
    ) ||
    (runtimeContext?.corroborated_stages || []).includes('prepare_remote_process_access')

  const hasDynamicResolver =
    /getprocaddress|loadlibrary|resolve_dynamic_apis|dynamic api/i.test(corpus)

  const hasFileOps =
    behaviorTags.includes('file_io') ||
    /(createfile|readfile|writefile|deletefile|copyfile|findfirstfile|findnextfile)/i.test(corpus) ||
    (runtimeContext?.corroborated_stages || []).includes('file_operations')

  const hasRegistryOps =
    behaviorTags.includes('registry') ||
    /(regopenkey|regsetvalue|regqueryvalue|registry_operations)/i.test(corpus)

  const hasPackerScan =
    behaviorTags.includes('packer_detection') ||
    /(packer|protector|entry point in non-first section|vmprotect|themida|upx)/i.test(corpus)

  const hasNetworkOps =
    behaviorTags.includes('networking') ||
    /(internetopen|internetconnect|httpsendrequest|winhttp|socket|connect|send|recv|bind|listen|accept|wsastartup|urlmon|webrequest)/i.test(
      corpus
    )

  const hasServiceOps =
    behaviorTags.includes('service_control') ||
    /(createservice|startservice|openscmanager|controlservice|registerservicectrlhandler|service_main|service control)/i.test(
      corpus
    )

  const hasComOps =
    behaviorTags.includes('com_activation') ||
    /(cocreateinstance|queryinterface|registerclassobject|dllgetclassobject|clsid_|iid_|class factory|com activation)/i.test(
      corpus
    )

  const hasDllEntry =
    behaviorTags.includes('dll_lifecycle') ||
    /(dllmain|dllregisterserver|dllunregisterserver|dllinstall|dllcanunloadnow|dll_process_attach|dll_thread_attach|reason code)/i.test(
      corpus
    )

  const hasExportDispatch =
    behaviorTags.includes('export_dispatch') ||
    /(export|ordinal|forwarder|dispatch exported|host-facing command|dllgetclassobject|dllcanunloadnow)/i.test(
      corpus
    )

  const hasCliHints =
    /(usage:|--help|\/\?|command|subcommand|detect|scan|dump|inject)/i.test(corpus)

  if (hasProcessOps) {
    addRole('string_arg_0', 'target_process_selector', 'const char *', 0.78, [
      'behavior:process_injection_or_spawn',
      'runtime_stage:prepare_remote_process_access',
    ])
    addRole('string_arg_1', 'launch_command_line', 'const char *', 0.67, [
      'api:CreateProcessW/CreateProcessA',
      'summary:spawn_or_remote_execution_context',
    ])
    addRole('pointer_arg_0', 'payload_buffer', 'void *', 0.73, [
      'api:WriteProcessMemory/ReadProcessMemory',
      'summary:remote_memory_transfer',
    ])
    addRole('handle_arg_0', 'process_handle', 'HANDLE', 0.82, [
      'api:OpenProcess',
      'runtime_stage:prepare_remote_process_access',
    ])
    addRole('handle_arg_1', 'thread_handle', 'HANDLE', 0.71, [
      'api:ResumeThread/SetThreadContext/CreateRemoteThread',
      'summary:execution_transfer',
    ])
    addRole('scalar_arg_0', 'operation_mode_flags', 'uint64_t', 0.55, [
      'summary:mode_flags',
    ])
  }

  if (hasDynamicResolver) {
    addRole('string_arg_0', hasProcessOps ? 'target_process_selector' : 'module_name_hint', 'const char *', hasProcessOps ? 0.78 : 0.76, [
      'api:GetProcAddress/LoadLibrary*',
    ])
    addRole('string_arg_1', 'api_name_hint', 'const char *', 0.74, [
      'api:GetProcAddress',
      'summary:dynamic_resolution',
    ])
    addRole('handle_arg_0', hasProcessOps ? 'process_handle' : 'module_handle_hint', hasProcessOps ? 'HANDLE' : 'HMODULE', hasProcessOps ? 0.82 : 0.58, [
      'api:LoadLibrary*/GetProcAddress',
    ])
  }

  if (hasFileOps) {
    addRole('string_arg_0', 'primary_path', 'const char *', 0.77, [
      'api:CreateFile*/DeleteFile*/CopyFile*',
    ])
    addRole('string_arg_1', 'secondary_path_or_pattern', 'const char *', 0.61, [
      'api:CopyFile*/FindFirstFile*',
    ])
    addRole('pointer_arg_0', 'buffer_view', 'void *', 0.66, [
      'api:ReadFile/WriteFile',
    ])
    addRole('handle_arg_0', 'file_handle', 'HANDLE', 0.74, [
      'api:CreateFile*/ReadFile/WriteFile',
    ])
    addRole('scalar_arg_0', 'file_operation_flags', 'uint64_t', 0.52, [
      'summary:file_operation_mode',
    ])
  }

  if (hasRegistryOps) {
    addRole('string_arg_0', 'registry_path', 'const char *', 0.75, [
      'api:RegOpenKey*/RegCreateKey*',
    ])
    addRole('string_arg_1', 'registry_value_name', 'const char *', 0.63, [
      'api:RegSetValue*/RegQueryValue*',
    ])
    addRole('pointer_arg_0', 'registry_value_buffer', 'void *', 0.59, [
      'api:RegSetValue*/RegQueryValue*',
    ])
    addRole('handle_arg_0', 'registry_key_handle', 'HKEY', 0.72, [
      'api:RegOpenKey*/RegCreateKey*',
    ])
  }

  if (hasNetworkOps) {
    addRole('string_arg_0', 'remote_host_or_url', 'const char *', 0.78, [
      'api:InternetConnect*/WinHttp*/socket/connect',
    ])
    addRole('string_arg_1', 'request_path_or_header', 'const char *', 0.63, [
      'api:HttpSendRequest*/send',
    ])
    addRole('pointer_arg_0', 'network_buffer', 'void *', 0.69, [
      'api:send/recv/HttpSendRequest*',
    ])
    addRole('handle_arg_0', 'socket_or_request_handle', 'uintptr_t', 0.76, [
      'api:InternetOpen*/InternetConnect*/socket',
    ])
    addRole('scalar_arg_0', 'network_option_flags', 'uint64_t', 0.57, [
      'summary:network_configuration_or_mode',
    ])
  }

  if (hasServiceOps) {
    addRole('string_arg_0', 'service_name', 'const char *', 0.77, [
      'api:CreateService*/OpenService*',
    ])
    addRole('string_arg_1', 'service_display_name_or_command', 'const char *', 0.62, [
      'api:CreateService*/StartService*',
    ])
    addRole('handle_arg_0', 'service_manager_or_service_handle', 'SC_HANDLE', 0.73, [
      'api:OpenSCManager/CreateService/OpenService',
    ])
    addRole('scalar_arg_0', 'service_control_code', 'uint32_t', 0.58, [
      'api:ControlService/RegisterServiceCtrlHandler',
    ])
  }

  if (hasComOps) {
    addRole('string_arg_0', 'class_or_interface_identifier', 'const char *', 0.64, [
      'api:CoCreateInstance/QueryInterface',
    ])
    addRole('pointer_arg_0', 'interface_or_object_pointer', 'void **', 0.71, [
      'api:QueryInterface/DllGetClassObject',
    ])
    addRole('scalar_arg_0', 'class_context_flags', 'uint32_t', 0.56, [
      'api:CoCreateInstance',
    ])
  }

  if (hasDllEntry) {
    addRole('handle_arg_0', 'module_instance', 'HMODULE', 0.79, [
      'summary:dll_entrypoint_or_registration',
    ])
    addRole('scalar_arg_0', 'dll_reason_code', 'uint32_t', 0.74, [
      'summary:dll_process_or_thread_attach',
    ])
    addRole('pointer_arg_0', 'reserved_context', 'void *', 0.61, [
      'summary:dll_reserved_context',
    ])
  }

  if (hasExportDispatch) {
    addRole('string_arg_0', 'exported_command_name_or_dispatch_key', 'const char *', 0.6, [
      'summary:export_dispatch_or_forwarder_selection',
    ])
    addRole('pointer_arg_0', 'export_argument_block', 'void *', 0.57, [
      'summary:export_dispatch_argument_block',
    ])
    addRole('scalar_arg_0', 'ordinal_or_dispatch_flags', 'uint32_t', 0.55, [
      'summary:export_ordinal_or_dispatch_mode',
    ])
  }

  if (hasPackerScan) {
    addRole('pointer_arg_0', hasFileOps ? 'buffer_view' : 'image_view', 'void *', hasFileOps ? 0.66 : 0.81, [
      'summary:packer_or_pe_layout_scan',
    ])
    addRole('string_arg_0', hasCliHints ? 'command_hint' : 'section_name_hint', 'const char *', 0.56, [
      'strings:packer/protector/help_text',
    ])
    addRole('scalar_arg_0', 'scan_mode_flags', 'uint64_t', 0.58, [
      'summary:heuristic_scan_mode',
    ])
  }

  if (hasCliHints) {
    addRole('string_arg_0', 'command_verb_or_primary_text', 'const char *', 0.54, [
      'strings:cli_or_help_text',
    ])
  }

  return roles
}

function inferStateRoles(
  behaviorTags: string[],
  xrefSignals: FunctionXrefSummary[],
  runtimeContext: ReturnType<typeof correlateFunctionWithRuntimeEvidence> | undefined,
  stringHints: string[],
  semanticSummary: string,
  sourceLikeSnippet: string
): z.infer<typeof FunctionStateRoleSchema>[] {
  const roles: z.infer<typeof FunctionStateRoleSchema>[] = []
  const corpus = [
    semanticSummary,
    sourceLikeSnippet,
    ...stringHints,
    ...xrefSignals.map((item) => item.api),
    ...(runtimeContext?.corroborated_stages || []),
    ...(runtimeContext?.corroborated_apis || []),
    ...behaviorTags,
  ]
    .join('\n')
    .toLowerCase()

  const addRole = (stateKey: string, role: string, confidence: number, evidence: string[]) => {
    if (roles.some((item) => item.state_key === stateKey)) {
      return
    }
    roles.push({
      state_key: stateKey,
      role,
      confidence: clamp(confidence, 0, 1),
      evidence: dedupe(evidence),
    })
  }

  if (/getprocaddress|loadlibrary|resolve_dynamic_apis/i.test(corpus)) {
    addRole('dynamic_api_table', 'Caches dynamically resolved imports or late-bound API pointers.', 0.84, [
      'api:GetProcAddress/LoadLibrary*',
    ])
  }
  if (/createfile|readfile|writefile|deletefile|copyfile|file_operations/i.test(corpus)) {
    addRole('file_api_table', 'Tracks file-system capability pointers or file-operation state.', 0.74, [
      'api:CreateFile*/ReadFile/WriteFile',
    ])
  }
  if (/regopenkey|regsetvalue|regqueryvalue|registry_operations/i.test(corpus)) {
    addRole('registry_api_table', 'Tracks registry capability pointers or key/value update state.', 0.74, [
      'api:RegOpenKey*/RegSetValue*',
    ])
  }
  if (/ntqueryinformationprocess|ntquerysysteminformation|isdebuggerpresent|code integrity|anti_analysis_checks/i.test(corpus)) {
    addRole('process_probe', 'Accumulates anti-analysis probes and remote-process environment observations.', 0.79, [
      'api:NtQueryInformationProcess/NtQuerySystemInformation',
    ])
  }
  if (/writeprocessmemory|readprocessmemory|setthreadcontext|resumethread|createprocess/i.test(corpus)) {
    addRole('execution_transfer_result', 'Stores the currently selected process-transfer stage and observed status.', 0.77, [
      'api:WriteProcessMemory/SetThreadContext/ResumeThread/CreateProcess*',
    ])
  }
  if (/packer|protector|upx|themida|vmprotect|entry point in non-first section/i.test(corpus)) {
    addRole('packer_heuristics', 'Accumulates packer heuristics, matched signatures, and section-layout findings.', 0.83, [
      'strings:packer/protector',
    ])
  }
  if (/usage:|--help|command|subcommand|detect|scan|dump|inject/i.test(corpus)) {
    addRole('cli_model', 'Captures recovered command verbs, help banners, and command summaries.', 0.63, [
      'strings:cli_or_help_text',
    ])
  }
  if (/dispatch|capability/i.test(corpus)) {
    addRole('dispatch_plan', 'Stores intermediate routing decisions between capability-specific handlers.', 0.61, [
      'summary:dispatch_or_capability_routing',
    ])
  }
  if (/internetopen|internetconnect|httpsendrequest|winhttp|socket|connect|send|recv|bind|listen|accept|networking/i.test(corpus)) {
    addRole('network_session', 'Tracks socket or HTTP request state, buffers, and remote endpoint intent.', 0.76, [
      'api:InternetConnect*/HttpSendRequest*/socket',
    ])
  }
  if (/createservice|startservice|openscmanager|controlservice|registerservicectrlhandler|service_main/i.test(corpus)) {
    addRole('service_control_state', 'Tracks service manager handles, lifecycle commands, and SCM-facing status.', 0.75, [
      'api:CreateService/OpenSCManager/ControlService',
    ])
  }
  if (/cocreateinstance|queryinterface|registerclassobject|dllgetclassobject|clsid_|iid_|class factory/i.test(corpus)) {
    addRole('com_class_factory', 'Tracks COM class/object activation flow and interface handoff state.', 0.73, [
      'api:CoCreateInstance/QueryInterface/DllGetClassObject',
    ])
  }
  if (/dllmain|dllregisterserver|dllunregisterserver|dllinstall|dllcanunloadnow|dll_process_attach|dll_thread_attach/i.test(corpus)) {
    addRole('dll_entry_state', 'Tracks DLL entrypoint reasons, registration lifecycle, or attach/detach state.', 0.72, [
      'summary:dll_lifecycle',
    ])
  }
  if (/export|ordinal|forwarder|dispatch exported|host-facing command|dllgetclassobject|dllcanunloadnow/i.test(corpus)) {
    addRole('export_dispatch_table', 'Tracks export ordinals, forwarders, and host-facing dispatch routing.', 0.67, [
      'summary:export_dispatch',
    ])
  }

  return roles
}

function inferStructInference(
  parameterRoles: z.infer<typeof FunctionParameterRoleSchema>[],
  stateRoles: z.infer<typeof FunctionStateRoleSchema>[]
): z.infer<typeof FunctionStructInferenceSchema>[] {
  const structs: z.infer<typeof FunctionStructInferenceSchema>[] = []
  const hasState = (stateKey: string) => stateRoles.some((item) => item.state_key === stateKey)
  const hasRole = (slot: string, role: string) =>
    parameterRoles.some((item) => item.slot === slot && item.role === role)

  const addStruct = (value: z.infer<typeof FunctionStructInferenceSchema>) => {
    if (structs.some((item) => item.semantic_name === value.semantic_name)) {
      return
    }
    structs.push(value)
  }

  if (
    hasRole('string_arg_0', 'target_process_selector') ||
    hasRole('pointer_arg_0', 'payload_buffer') ||
    hasRole('handle_arg_0', 'process_handle')
  ) {
    addStruct({
      semantic_name: 'remote_process_request',
      rewrite_type_name: 'AkRemoteProcessRequest',
      kind: 'request',
      confidence: 0.82,
      fields: [
        { name: 'target_selector', inferred_type: 'const char *', source_slot: 'string_arg_0' },
        { name: 'launch_command_line', inferred_type: 'const char *', source_slot: 'string_arg_1' },
        { name: 'payload_view', inferred_type: 'void *', source_slot: 'pointer_arg_0' },
        { name: 'process_handle', inferred_type: 'HANDLE', source_slot: 'handle_arg_0' },
        { name: 'thread_handle', inferred_type: 'HANDLE', source_slot: 'handle_arg_1' },
        { name: 'mode_flags', inferred_type: 'uint64_t', source_slot: 'scalar_arg_0' },
      ],
      evidence: ['parameter_roles:target_process_selector/payload_buffer/process_handle'],
    })
  }

  if (hasState('execution_transfer_result')) {
    addStruct({
      semantic_name: 'execution_transfer_result',
      rewrite_type_name: 'AkExecutionTransferResult',
      kind: 'result',
      confidence: 0.78,
      fields: [
        { name: 'status_code', inferred_type: 'int' },
        { name: 'stage_name', inferred_type: 'const char *' },
        { name: 'detail', inferred_type: 'const char *' },
        { name: 'transfer_mode', inferred_type: 'const char *' },
        { name: 'observed_value', inferred_type: 'uint64_t' },
      ],
      evidence: ['state_roles:execution_transfer_result'],
    })
  }

  if (hasState('dispatch_plan')) {
    addStruct({
      semantic_name: 'capability_dispatch_plan',
      rewrite_type_name: 'AkCapabilityDispatchPlan',
      kind: 'session',
      confidence: 0.66,
      fields: [
        { name: 'request', inferred_type: 'dispatch_request' },
        { name: 'result', inferred_type: 'dispatch_result' },
      ],
      evidence: ['state_roles:dispatch_plan'],
    })
  }

  if (
    hasRole('pointer_arg_0', 'image_view') ||
    hasRole('string_arg_0', 'section_name_hint') ||
    hasState('packer_heuristics')
  ) {
    addStruct({
      semantic_name: 'packer_scan_session',
      rewrite_type_name: 'AkPackerScanSession',
      kind: 'session',
      confidence: 0.79,
      fields: [
        { name: 'request', inferred_type: 'packer_scan_request' },
        { name: 'result', inferred_type: 'packer_scan_result' },
      ],
      evidence: ['parameter_roles:image_view/section_name_hint', 'state_roles:packer_heuristics'],
    })
  }

  if (hasState('dynamic_api_table')) {
    addStruct({
      semantic_name: 'api_resolution_table',
      rewrite_type_name: 'AkResolvedApiTable',
      kind: 'table',
      confidence: 0.77,
      fields: [
        { name: 'ready', inferred_type: 'int' },
        { name: 'role', inferred_type: 'const char *' },
        { name: 'apis', inferred_type: 'const char *[8]' },
        { name: 'api_count', inferred_type: 'int' },
      ],
      evidence: ['state_roles:dynamic_api_table'],
    })
  }

  if (
    hasRole('string_arg_0', 'remote_host_or_url') ||
    hasRole('pointer_arg_0', 'network_buffer') ||
    hasState('network_session')
  ) {
    addStruct({
      semantic_name: 'network_request_context',
      rewrite_type_name: 'AkNetworkRequestContext',
      kind: 'request',
      confidence: 0.75,
      fields: [
        { name: 'remote_host_or_url', inferred_type: 'const char *', source_slot: 'string_arg_0' },
        { name: 'request_path_or_header', inferred_type: 'const char *', source_slot: 'string_arg_1' },
        { name: 'buffer_view', inferred_type: 'void *', source_slot: 'pointer_arg_0' },
        { name: 'request_handle', inferred_type: 'uintptr_t', source_slot: 'handle_arg_0' },
        { name: 'option_flags', inferred_type: 'uint64_t', source_slot: 'scalar_arg_0' },
      ],
      evidence: ['parameter_roles:remote_host_or_url/network_buffer', 'state_roles:network_session'],
    })
  }

  if (
    hasRole('string_arg_0', 'service_name') ||
    hasRole('handle_arg_0', 'service_manager_or_service_handle') ||
    hasState('service_control_state')
  ) {
    addStruct({
      semantic_name: 'service_control_context',
      rewrite_type_name: 'AkServiceControlContext',
      kind: 'context',
      confidence: 0.74,
      fields: [
        { name: 'service_name', inferred_type: 'const char *', source_slot: 'string_arg_0' },
        {
          name: 'display_name_or_command',
          inferred_type: 'const char *',
          source_slot: 'string_arg_1',
        },
        {
          name: 'service_handle',
          inferred_type: 'SC_HANDLE',
          source_slot: 'handle_arg_0',
        },
        { name: 'control_code', inferred_type: 'uint32_t', source_slot: 'scalar_arg_0' },
      ],
      evidence: ['parameter_roles:service_name/service_manager_or_service_handle', 'state_roles:service_control_state'],
    })
  }

  if (
    hasRole('string_arg_0', 'class_or_interface_identifier') ||
    hasRole('pointer_arg_0', 'interface_or_object_pointer') ||
    hasState('com_class_factory')
  ) {
    addStruct({
      semantic_name: 'com_activation_context',
      rewrite_type_name: 'AkComActivationContext',
      kind: 'context',
      confidence: 0.72,
      fields: [
        {
          name: 'class_or_interface_id',
          inferred_type: 'const char *',
          source_slot: 'string_arg_0',
        },
        {
          name: 'object_pointer',
          inferred_type: 'void **',
          source_slot: 'pointer_arg_0',
        },
        { name: 'class_context', inferred_type: 'uint32_t', source_slot: 'scalar_arg_0' },
      ],
      evidence: ['parameter_roles:class_or_interface_identifier/interface_or_object_pointer', 'state_roles:com_class_factory'],
    })
  }

  if (
    hasRole('handle_arg_0', 'module_instance') ||
    hasRole('scalar_arg_0', 'dll_reason_code') ||
    hasState('dll_entry_state')
  ) {
    addStruct({
      semantic_name: 'dll_entry_context',
      rewrite_type_name: 'AkDllEntryContext',
      kind: 'context',
      confidence: 0.74,
      fields: [
        { name: 'module_instance', inferred_type: 'HMODULE', source_slot: 'handle_arg_0' },
        { name: 'reason_code', inferred_type: 'uint32_t', source_slot: 'scalar_arg_0' },
        { name: 'reserved_context', inferred_type: 'void *', source_slot: 'pointer_arg_0' },
      ],
      evidence: ['parameter_roles:module_instance/dll_reason_code', 'state_roles:dll_entry_state'],
    })
  }

  if (
    hasRole('string_arg_0', 'exported_command_name_or_dispatch_key') ||
    hasRole('pointer_arg_0', 'export_argument_block') ||
    hasState('export_dispatch_table')
  ) {
    addStruct({
      semantic_name: 'export_dispatch_table',
      rewrite_type_name: 'AkExportDispatchTable',
      kind: 'table',
      confidence: 0.68,
      fields: [
        {
          name: 'dispatch_key',
          inferred_type: 'const char *',
          source_slot: 'string_arg_0',
        },
        { name: 'argument_block', inferred_type: 'void *', source_slot: 'pointer_arg_0' },
        { name: 'ordinal_or_flags', inferred_type: 'uint32_t', source_slot: 'scalar_arg_0' },
      ],
      evidence: ['parameter_roles:exported_command_name_or_dispatch_key/export_argument_block', 'state_roles:export_dispatch_table'],
    })
  }

  if (stateRoles.length > 0) {
    const runtimeFields = [
      hasState('dynamic_api_table')
        ? { name: 'dynamic_apis', inferred_type: 'api_resolution_table' }
        : null,
      hasState('file_api_table') ? { name: 'file_apis', inferred_type: 'api_resolution_table' } : null,
      hasState('registry_api_table')
        ? { name: 'registry_apis', inferred_type: 'api_resolution_table' }
        : null,
      hasState('process_probe') ? { name: 'process_probe', inferred_type: 'process_probe_state' } : null,
      hasState('network_session')
        ? { name: 'network_session', inferred_type: 'network_request_context' }
        : null,
      hasState('service_control_state')
        ? { name: 'service_control', inferred_type: 'service_control_context' }
        : null,
      hasState('com_class_factory')
        ? { name: 'com_activation', inferred_type: 'com_activation_context' }
        : null,
      hasState('dll_entry_state') ? { name: 'dll_entry', inferred_type: 'dll_entry_context' } : null,
      hasState('export_dispatch_table')
        ? { name: 'exports', inferred_type: 'export_dispatch_table' }
        : null,
      hasState('packer_heuristics')
        ? { name: 'packer_heuristics', inferred_type: 'packer_heuristics' }
        : null,
      hasState('cli_model') ? { name: 'cli', inferred_type: 'cli_model' } : null,
    ].filter((item): item is { name: string; inferred_type: string } => Boolean(item))

    addStruct({
      semantic_name: 'runtime_context',
      rewrite_type_name: 'AkRuntimeContext',
      kind: 'context',
      confidence: clamp(0.55 + stateRoles.length * 0.05, 0.55, 0.88),
      fields: runtimeFields,
      evidence: stateRoles.map((item) => `state_roles:${item.state_key}`),
    })
  }

  return structs
}

function inferReturnRole(
  behaviorTags: string[],
  xrefSignals: FunctionXrefSummary[],
  runtimeContext: ReturnType<typeof correlateFunctionWithRuntimeEvidence> | undefined,
  stringHints: string[],
  semanticSummary: string,
  sourceLikeSnippet: string
): z.infer<typeof FunctionReturnRoleSchema> | null {
  const corpus = [
    semanticSummary,
    sourceLikeSnippet,
    ...stringHints,
    ...xrefSignals.map((item) => `${item.api} ${item.provenance}`),
    ...(runtimeContext?.corroborated_apis || []),
    ...(runtimeContext?.corroborated_stages || []),
    ...behaviorTags,
  ]
    .join('\n')
    .toLowerCase()

  const buildRole = (
    role: string,
    inferredType: string,
    confidence: number,
    evidence: string[]
  ): z.infer<typeof FunctionReturnRoleSchema> => ({
    role,
    inferred_type: inferredType,
    confidence: clamp(confidence, 0, 1),
    evidence: dedupe(evidence),
  })

  if (/\b(getprocaddress|loadlibrary|loadlibraryex|resolved api|dynamic api)\b/i.test(corpus)) {
    return buildRole('resolved_symbol_pointer', 'void *', 0.78, [
      'api:GetProcAddress/LoadLibrary*',
      'summary:dynamic_resolution',
    ])
  }
  if (/\b(writeprocessmemory|readprocessmemory|setthreadcontext|resumethread|createremotethread|virtualallocex|createprocess[a-z]*)\b/i.test(corpus)) {
    return buildRole('execution_transfer_status', 'int', 0.74, [
      'api:WriteProcessMemory/SetThreadContext/ResumeThread/CreateProcess*',
      'runtime_stage:prepare_remote_process_access',
    ])
  }
  if (/\b(createfile[a-z]*|readfile|writefile|deletefile[a-z]*|copyfile[a-z]*|findfirstfile[a-z]*|findnextfile[a-z]*)\b/i.test(corpus)) {
    return buildRole('io_status_or_bytes', 'int', 0.69, ['api:CreateFile*/ReadFile/WriteFile'])
  }
  if (/\b(regopenkey(?:ex)?[a-z]*|regsetvalue(?:ex)?[a-z]*|regqueryvalue(?:ex)?[a-z]*|regcreatekey(?:ex)?[a-z]*)\b/i.test(corpus)) {
    return buildRole('registry_operation_status', 'int', 0.67, ['api:RegOpenKey*/RegSetValue*'])
  }
  if (/\b(internetopen[a-z]*|internetconnect[a-z]*|httpsendrequest[a-z]*|winhttp[a-z]*|socket|connect|send|recv)\b/i.test(corpus)) {
    return buildRole('network_operation_status', 'int', 0.7, [
      'api:InternetConnect*/HttpSendRequest*/socket',
    ])
  }
  if (/\b(createservice[a-z]*|startservice[a-z]*|openscmanager[a-z]*|controlservice|registerservicectrlhandler(?:ex)?[a-z]*)\b/i.test(corpus)) {
    return buildRole('service_control_status', 'int', 0.68, [
      'api:CreateService/OpenSCManager/ControlService',
    ])
  }
  if (/\b(cocreateinstance|queryinterface|dllgetclassobject|class factory|hresult)\b/i.test(corpus)) {
    return buildRole('activation_status_or_hresult', 'HRESULT', 0.72, [
      'api:CoCreateInstance/QueryInterface/DllGetClassObject',
    ])
  }
  if (/\b(dllmain|dllregisterserver|dllunregisterserver|dllinstall|dllcanunloadnow|dll_process_attach)\b/i.test(corpus)) {
    return buildRole('dll_entry_decision', 'BOOL', 0.71, ['summary:dll_lifecycle'])
  }
  if (/\b(export|ordinal|forwarder|dispatch exported|host-facing command)\b/i.test(corpus)) {
    return buildRole('dispatch_status_or_result', 'int', 0.61, ['summary:export_dispatch'])
  }
  if (/\b(packer|protector|upx|vmprotect|themida|entry point in non-first section)\b/i.test(corpus)) {
    return buildRole('heuristic_match_score', 'int', 0.66, ['strings:packer/protector'])
  }
  if (/\breturn 0\b|\breturn 1\b|\breturn true\b|\breturn false\b/i.test(corpus)) {
    return buildRole('status_code', 'int', 0.45, ['pseudocode:return_literal'])
  }

  return null
}

function summarizeParameterRoles(
  parameterRoles: z.infer<typeof FunctionParameterRoleSchema>[]
): string {
  if (parameterRoles.length === 0) {
    return 'none'
  }
  return parameterRoles
    .slice(0, 6)
    .map((item) => `${item.slot}=>${item.role}<${item.inferred_type}>`)
    .join('; ')
}

function summarizeReturnRole(
  returnRole: z.infer<typeof FunctionReturnRoleSchema> | null | undefined
): string {
  if (!returnRole) {
    return 'none'
  }
  return `${returnRole.role}<${returnRole.inferred_type}>`
}

function summarizeStateRoles(stateRoles: z.infer<typeof FunctionStateRoleSchema>[]): string {
  if (stateRoles.length === 0) {
    return 'none'
  }
  return stateRoles
    .slice(0, 6)
    .map((item) => `${item.state_key}=>${item.role}`)
    .join('; ')
}

function summarizeStructInference(
  structInference: z.infer<typeof FunctionStructInferenceSchema>[]
): string {
  if (structInference.length === 0) {
    return 'none'
  }
  return structInference
    .slice(0, 4)
    .map((item) => `${item.semantic_name}${item.rewrite_type_name ? `=>${item.rewrite_type_name}` : ''}`)
    .join('; ')
}

export function buildDefaultSemanticNameSuggestion(
  evidencePack: SemanticEvidencePack
): ConstrainedSemanticNameSuggestion | null {
  const textCorpus = [
    evidencePack.semantic_summary,
    evidencePack.pseudocode_excerpt,
    ...evidencePack.string_hints,
    ...evidencePack.xref_signals.map((item) => item.api),
    ...(evidencePack.runtime_context?.corroborated_stages || []),
    ...(evidencePack.runtime_context?.corroborated_apis || []),
  ]
    .join('\n')
    .toLowerCase()

  const evidenceUsed: string[] = []
  const assumptions: string[] = []
  const pushEvidence = (value: string) => {
    if (value && !evidenceUsed.includes(value)) {
      evidenceUsed.push(value)
    }
  }

  if (/(packer|protector|entry point in non-first section|section entropy|vmprotect|themida|upx)/i.test(textCorpus)) {
    for (const hint of evidencePack.string_hints.filter((value) =>
      /(packer|protector|entry point|vmprotect|themida|upx)/i.test(value)
    )) {
      pushEvidence(`string_hint:${hint}`)
    }
    if (evidencePack.cfg_shape.node_count >= 20) {
      pushEvidence(`cfg_nodes:${evidencePack.cfg_shape.node_count}`)
    }
    assumptions.push('Assumes PE layout and packer heuristics dominate this routine over generic helper duties.')
    return {
      candidate_name: 'scan_pe_layout_or_sections',
      confidence: clamp(0.62 + Math.min(evidenceUsed.length * 0.04, 0.14), 0.55, 0.82),
      why: 'Evidence clusters around packer/protector strings and PE layout style checks.',
      required_assumptions: assumptions,
      evidence_used: evidenceUsed,
    }
  }

  if (
    /\b(writeprocessmemory|setthreadcontext|resumethread|createremotethread|virtualallocex)\b/i.test(
      textCorpus
    )
  ) {
    for (const api of evidencePack.xref_signals.map((item) => item.api)) {
      if (/writeprocessmemory|setthreadcontext|resumethread|createremotethread|virtualallocex/i.test(api)) {
        pushEvidence(`api:${api}`)
      }
    }
    assumptions.push('Assumes remote-process mutation is the primary goal rather than a supporting capability table build.')
    return {
      candidate_name: 'orchestrate_remote_memory_transfer',
      confidence: clamp(0.6 + Math.min(evidenceUsed.length * 0.05, 0.18), 0.56, 0.84),
      why: 'Cross-evidence suggests remote memory write or execution-transfer behavior.',
      required_assumptions: assumptions,
      evidence_used: evidenceUsed,
    }
  }

  if (/\b(openprocess|readprocessmemory|ntqueryinformationprocess|remote process)\b/i.test(textCorpus)) {
    for (const api of evidencePack.xref_signals.map((item) => item.api)) {
      if (/openprocess|readprocessmemory|ntqueryinformationprocess/i.test(api)) {
        pushEvidence(`api:${api}`)
      }
    }
    assumptions.push('Assumes the routine is inspecting or preparing remote process state rather than only dispatching.')
    return {
      candidate_name: 'inspect_remote_process_state',
      confidence: clamp(0.58 + Math.min(evidenceUsed.length * 0.05, 0.16), 0.54, 0.8),
      why: 'Observed APIs and summary both point to remote process state collection or access preparation.',
      required_assumptions: assumptions,
      evidence_used: evidenceUsed,
    }
  }

  if (/\b(createfile|readfile|writefile|deletefile|copyfile|movefile)\b/i.test(textCorpus)) {
    for (const api of evidencePack.xref_signals.map((item) => item.api)) {
      if (/createfile|readfile|writefile|deletefile|copyfile|movefile/i.test(api)) {
        pushEvidence(`api:${api}`)
      }
    }
    assumptions.push('Assumes recovered file APIs are part of a file-materialization path, not incidental support code.')
    return {
      candidate_name: 'prepare_file_artifact_state',
      confidence: clamp(0.57 + Math.min(evidenceUsed.length * 0.05, 0.15), 0.53, 0.78),
      why: 'API and string evidence both lean toward file or artifact staging behavior.',
      required_assumptions: assumptions,
      evidence_used: evidenceUsed,
    }
  }

  if (
    evidencePack.cfg_shape.node_count <= 3 &&
    evidencePack.call_relationships.callers.length >= 8 &&
    evidencePack.call_relationships.callees.length <= 2
  ) {
    pushEvidence(`cfg_nodes:${evidencePack.cfg_shape.node_count}`)
    pushEvidence(`caller_count:${evidencePack.call_relationships.callers.length}`)
    assumptions.push('Assumes the routine is a shared helper or control-flow utility because it is tiny and heavily reused.')
    return {
      candidate_name: 'shared_control_flow_helper',
      confidence: 0.56,
      why: 'Shape suggests a small heavily-reused helper, but semantics remain broad.',
      required_assumptions: assumptions,
      evidence_used: evidenceUsed,
    }
  }

  return null
}

function withNameResolutionHeader(
  sourceLikeSnippet: string,
  nameResolution: FunctionNameResolution | null | undefined
): string {
  const baseLines = sourceLikeSnippet
    .split(/\r?\n/)
    .filter((line) => !line.startsWith('// name_resolution='))

  if (!nameResolution) {
    return baseLines.join('\n')
  }

  return [
    `// name_resolution=source:${nameResolution.resolution_source} rule:${nameResolution.rule_based_name || 'none'} llm:${nameResolution.llm_suggested_name || 'none'} validated:${nameResolution.validated_name || 'none'} unresolved:${nameResolution.unresolved_semantic_name ? 'yes' : 'no'}`,
    ...baseLines,
  ].join('\n')
}

async function finalizeLayeredNameResolution(
  func: ReconstructedFunction,
  externalSuggestion: LoadedSemanticNameSuggestion | null,
  semanticNameSuggester: (
    evidencePack: SemanticEvidencePack
  ) => Promise<ConstrainedSemanticNameSuggestion | null>
): Promise<{
  nameResolution: z.infer<typeof FunctionNameResolutionSchema>
  finalSuggestion: RenameSuggestion
}> {
  const ruleBasedName = func.suggested_name || null
  const evidencePack: SemanticEvidencePack = {
    function_name: func.function,
    address: func.address,
    semantic_summary: func.semantic_summary,
    xref_signals: func.xref_signals,
    call_relationships: {
      callers: func.call_relationships?.callers || [],
      callees: func.call_relationships?.callees || [],
    },
    runtime_context: func.runtime_context || undefined,
    string_hints: func.semantic_evidence?.string_hints || [],
    pseudocode_excerpt:
      func.semantic_evidence?.pseudocode_excerpt || buildPseudocodeExcerpt(func.source_like_snippet),
    cfg_shape:
      func.semantic_evidence?.cfg_shape || {
        node_count: func.evidence.cfg_nodes,
        edge_count: func.evidence.cfg_edges,
        has_loop: false,
        has_branching: func.evidence.cfg_edges > func.evidence.cfg_nodes,
        block_types: [],
        entry_block_type: null,
      },
    parameter_roles: func.parameter_roles || func.semantic_evidence?.parameter_roles || [],
    return_role: func.return_role || func.semantic_evidence?.return_role || null,
    state_roles: func.state_roles || func.semantic_evidence?.state_roles || [],
    struct_inference: func.struct_inference || func.semantic_evidence?.struct_inference || [],
  }

  let llmSuggestion: ConstrainedSemanticNameSuggestion | null = null
  if (externalSuggestion?.normalized_candidate_name) {
    llmSuggestion = {
      candidate_name: externalSuggestion.normalized_candidate_name,
      confidence: clamp(externalSuggestion.confidence, 0, 1),
      why: externalSuggestion.why,
      required_assumptions: externalSuggestion.required_assumptions,
      evidence_used: dedupe([
        ...externalSuggestion.evidence_used,
        ...(externalSuggestion.client_name ? [`client:${externalSuggestion.client_name}`] : []),
        ...(externalSuggestion.model_name ? [`model:${externalSuggestion.model_name}`] : []),
        `artifact:${externalSuggestion.artifact_id}`,
      ]),
    }
  } else if (!ruleBasedName) {
    llmSuggestion = await semanticNameSuggester(evidencePack)
  }

  const validatedName =
    ruleBasedName ||
    (llmSuggestion && llmSuggestion.confidence >= 0.62 ? llmSuggestion.candidate_name : null)
  const resolutionSource: z.infer<typeof FunctionNameResolutionSchema>['resolution_source'] =
    ruleBasedName && llmSuggestion
      ? 'hybrid'
      : ruleBasedName
        ? 'rule'
        : validatedName
          ? 'llm'
          : 'unresolved'

  const nameResolution = {
    rule_based_name: ruleBasedName,
    llm_suggested_name: llmSuggestion?.candidate_name || null,
    llm_confidence: llmSuggestion?.confidence || null,
    llm_why: llmSuggestion?.why || null,
    required_assumptions: llmSuggestion?.required_assumptions || [],
    evidence_used: llmSuggestion?.evidence_used || [],
    validated_name: validatedName,
    resolution_source: resolutionSource,
    unresolved_semantic_name: !validatedName,
  }

  const finalSuggestion: RenameSuggestion = validatedName
    ? {
        suggested_name: validatedName,
        suggested_role:
          ruleBasedName === validatedName
            ? func.suggested_role || llmSuggestion?.why || null
            : llmSuggestion?.why || func.suggested_role || null,
        rename_confidence:
          ruleBasedName === validatedName
            ? Number(func.rename_confidence || 0)
            : Number(llmSuggestion?.confidence || 0),
        rename_evidence:
          ruleBasedName === validatedName
            ? func.rename_evidence || []
            : llmSuggestion?.evidence_used || [],
      }
    : {
        suggested_name: null,
        suggested_role: null,
        rename_confidence: 0,
        rename_evidence: [],
      }

  return {
    nameResolution,
    finalSuggestion,
  }
}

function extractLinkedLabelToken(label: string): { name: string | null; address: string | null } {
  const addressMatch = label.match(/@((?:0x)?[0-9a-f]+)\b/i)
  const nameMatch = label.match(/^([^@[]+)/)
  return {
    name: nameMatch ? nameMatch[1].trim() : null,
    address: addressMatch ? addressMatch[1].replace(/^0x/i, '').toLowerCase() : null,
  }
}

function buildLinkedSuggestedNames(
  func: ReconstructedFunction,
  renamedFunctions: ReconstructedFunction[]
): string[] {
  const byAddress = new Map<string, string>()
  const byName = new Map<string, string>()

  for (const item of renamedFunctions) {
    if (!item.suggested_name) {
      continue
    }
    byAddress.set(item.address.replace(/^0x/i, '').toLowerCase(), item.suggested_name)
    byName.set(item.function.toLowerCase(), item.suggested_name)
  }

  const linked: string[] = []
  for (const label of [
    ...(func.call_context?.callers || []),
    ...(func.call_context?.callees || []),
    ...((func.call_relationships?.callers || []).map((item) => item.target)),
    ...((func.call_relationships?.callees || []).map((item) => item.target)),
  ]) {
    const token = extractLinkedLabelToken(label)
    if (token.address && byAddress.has(token.address)) {
      linked.push(byAddress.get(token.address) as string)
      continue
    }
    if (token.name && byName.has(token.name.toLowerCase())) {
      linked.push(byName.get(token.name.toLowerCase()) as string)
    }
  }

  return dedupe(linked)
}

function scoreLinkedSuggestedName(name: string): number {
  const normalized = name.trim().toLowerCase()
  if (normalized === 'resolve_dynamic_apis') {
    return 120
  }
  if (normalized === 'prepare_remote_process_access') {
    return 112
  }
  if (normalized === 'transfer_remote_execution') {
    return 108
  }
  if (normalized === 'query_remote_process_snapshot') {
    return 104
  }
  if (normalized === 'query_code_integrity_state') {
    return 102
  }
  if (normalized === 'scan_packer_signatures') {
    return 98
  }
  const prefixIndex = LINKED_SUGGESTION_PRIORITY_PREFIXES.findIndex((prefix) =>
    normalized.startsWith(prefix)
  )
  if (prefixIndex >= 0) {
    return 90 - prefixIndex
  }
  if (normalized.startsWith('shared_') || normalized.endsWith('_stub')) {
    return 20
  }
  return 40
}

function pickPreferredLinkedSuggestedName(linkedSuggestedNames: string[]): string | null {
  const candidates = dedupe(linkedSuggestedNames).filter((name) => {
    const normalized = name.trim().toLowerCase()
    if (!normalized) {
      return false
    }
    if (
      normalized.endsWith('_helper') ||
      normalized.endsWith('_guard') ||
      normalized.endsWith('_stub')
    ) {
      return false
    }
    if (normalized.startsWith('shared_')) {
      return false
    }
    return true
  })
  if (candidates.length === 0) {
    return null
  }
  return candidates.sort((a, b) => {
    const scoreDelta = scoreLinkedSuggestedName(b) - scoreLinkedSuggestedName(a)
    if (scoreDelta !== 0) {
      return scoreDelta
    }
    return a.localeCompare(b)
  })[0]
}

function appendSemanticSuffix(baseName: string, suffix: 'helper' | 'guard'): string {
  return baseName.endsWith(`_${suffix}`) ? baseName : `${baseName}_${suffix}`
}

function buildLinkedRefinedSuggestion(
  linkedSuggestedNames: string[],
  kind: 'helper' | 'guard'
): RenameSuggestion | null {
  const linked = pickPreferredLinkedSuggestedName(linkedSuggestedNames)
  if (!linked) {
    return null
  }
  if (linked === 'resolve_dynamic_apis') {
    return {
      suggested_name: appendSemanticSuffix(linked, kind),
      suggested_role:
        kind === 'helper'
          ? 'Trivial helper reached from the dynamic API resolution path.'
          : 'Small guard routine used to gate the dynamic API resolution path.',
      rename_confidence: kind === 'helper' ? 0.68 : 0.67,
      rename_evidence: [`linked_caller:${linked}`],
    }
  }
  if (linked.startsWith('dispatch_')) {
    return {
      suggested_name: kind === 'helper' ? 'dispatch_guard_stub' : 'dispatch_false_guard',
      suggested_role:
        kind === 'helper'
          ? 'Small guard or bookkeeping stub reached from a dispatch path.'
          : 'Small guard routine that returns a branch value for dispatch callers.',
      rename_confidence: 0.66,
      rename_evidence: [`linked_caller:${linked}`],
    }
  }
  if (
    LINKED_SUGGESTION_PRIORITY_PREFIXES.some((prefix) => linked.startsWith(prefix))
  ) {
    return {
      suggested_name: appendSemanticSuffix(linked, kind),
      suggested_role:
        kind === 'helper'
          ? 'Small helper routine attached to a named operational path.'
          : 'Small guard routine attached to a named operational path.',
      rename_confidence: kind === 'helper' ? 0.64 : 0.63,
      rename_evidence: [`linked_caller:${linked}`],
    }
  }
  return null
}

function deriveRefinedRenameSuggestion(
  func: ReconstructedFunction,
  renamedFunctions: ReconstructedFunction[]
): RenameSuggestion | null {
  if (func.suggested_name || KNOWN_LIBRARY_SYMBOL_NAMES.has(func.function.trim().toLowerCase())) {
    return null
  }

  const bodyShape = extractSnippetBodyShape(func.source_like_snippet)
  const linkedSuggestedNames = buildLinkedSuggestedNames(func, renamedFunctions)
  const evidence: string[] = []

  const chooseLinkedHelperName = (): RenameSuggestion | null => {
    return buildLinkedRefinedSuggestion(linkedSuggestedNames, 'helper')
  }

  const chooseLinkedGuardName = (): RenameSuggestion | null => {
    return buildLinkedRefinedSuggestion(linkedSuggestedNames, 'guard')
  }

  if (
    bodyShape.has_trap_tail &&
    func.evidence.cfg_nodes <= 1 &&
    func.evidence.callee_count === 1 &&
    func.evidence.caller_count >= 4
  ) {
    return {
      suggested_name: 'call_then_trap_stub',
      suggested_role:
        'Calls a single callee and then immediately traps or reaches an unreachable edge.',
      rename_confidence: 0.61,
      rename_evidence: [
        'body:trap_after_call',
        `caller_count:${func.evidence.caller_count}`,
        `callee_count:${func.evidence.callee_count}`,
      ],
    }
  }

  if (
    bodyShape.is_void_return_stub &&
    func.evidence.cfg_nodes <= 1 &&
    func.evidence.callee_count === 0 &&
    func.evidence.caller_count >= 4
  ) {
    const linkedSuggestion = chooseLinkedHelperName()
    if (linkedSuggestion) {
      linkedSuggestion.rename_confidence = clamp(linkedSuggestion.rename_confidence + 0.08, 0, 0.95)
      linkedSuggestion.rename_evidence = dedupe([
        ...linkedSuggestion.rename_evidence,
        'body:void_return_stub',
        `caller_count:${func.evidence.caller_count}`,
      ])
      return linkedSuggestion
    }

    evidence.push('body:void_return_stub')
    evidence.push(`caller_count:${func.evidence.caller_count}`)
    evidence.push(`cfg_nodes:${func.evidence.cfg_nodes}`)
    return {
      suggested_name: 'shared_noop_stub',
      suggested_role: 'Tiny shared stub with no observable side effects beyond returning.',
      rename_confidence: 0.58,
      rename_evidence: evidence,
    }
  }

  if (
    bodyShape.constant_return === 0 &&
    func.evidence.cfg_nodes <= 1 &&
    func.evidence.caller_count >= 3
  ) {
    const linkedSuggestion = chooseLinkedGuardName()
    if (linkedSuggestion?.suggested_name) {
      return {
        suggested_name: linkedSuggestion.suggested_name,
        suggested_role:
          linkedSuggestion.suggested_name === 'dispatch_false_guard'
            ? 'Small guard routine that returns a false/zero branch value for dispatch callers.'
            : 'Small guard-like helper attached to a named operational path that returns a false/zero branch value.',
        rename_confidence: 0.67,
        rename_evidence: dedupe([
          ...linkedSuggestion.rename_evidence,
          'body:return_0',
          `caller_count:${func.evidence.caller_count}`,
        ]),
      }
    }

    return {
      suggested_name: 'shared_false_guard',
      suggested_role: 'Small guard-like helper that returns a constant zero/false result.',
      rename_confidence: 0.56,
      rename_evidence: ['body:return_0', `caller_count:${func.evidence.caller_count}`],
    }
  }

  if (
    bodyShape.constant_return === 1 &&
    func.evidence.cfg_nodes <= 1 &&
    func.evidence.caller_count >= 3
  ) {
    const linkedSuggestion = chooseLinkedGuardName()
    if (linkedSuggestion?.suggested_name) {
      const suggestedName =
        linkedSuggestion.suggested_name === 'dispatch_false_guard'
          ? 'dispatch_true_guard'
          : linkedSuggestion.suggested_name
      return {
        suggested_name: suggestedName,
        suggested_role:
          suggestedName === 'dispatch_true_guard'
            ? 'Small guard routine that returns a true/success branch value for dispatch callers.'
            : 'Small guard-like helper attached to a named operational path that returns success.',
        rename_confidence: clamp(linkedSuggestion.rename_confidence + 0.01, 0, 0.95),
        rename_evidence: dedupe([
          ...linkedSuggestion.rename_evidence,
          'body:return_1',
          `caller_count:${func.evidence.caller_count}`,
        ]),
      }
    }
    return {
      suggested_name: 'shared_true_guard',
      suggested_role: 'Small guard-like helper that returns a constant true/success result.',
      rename_confidence: 0.56,
      rename_evidence: ['body:return_1', `caller_count:${func.evidence.caller_count}`],
    }
  }

  return null
}

function refineRenameSuggestions(functions: ReconstructedFunction[]): ReconstructedFunction[] {
  return functions.map((func) => {
    const refined = deriveRefinedRenameSuggestion(func, functions)
    if (!refined?.suggested_name) {
      return func
    }

    return {
      ...func,
      suggested_name: refined.suggested_name,
      suggested_role: refined.suggested_role,
      rename_confidence: refined.rename_confidence,
      rename_evidence: refined.rename_evidence,
      source_like_snippet: withSuggestedNameHeader(func.source_like_snippet, refined),
    }
  })
}

function buildSemanticSummary(
  functionName: string,
  behaviorTags: string[],
  xrefSignals: FunctionXrefSummary[],
  callContext: { callers: string[]; callees: string[] },
  relationshipContext: RelationshipContext,
  gaps: string[],
  rankReasons: string[],
  parameterRoles: z.infer<typeof FunctionParameterRoleSchema>[],
  returnRole: z.infer<typeof FunctionReturnRoleSchema> | null | undefined,
  stateRoles: z.infer<typeof FunctionStateRoleSchema>[],
  structInference: z.infer<typeof FunctionStructInferenceSchema>[],
  runtimeContext?: {
    corroborated_apis: string[]
    corroborated_stages: string[]
    notes: string[]
    confidence: number
    executed?: boolean
    evidence_sources?: string[]
    source_names?: string[]
    artifact_count?: number
    executed_artifact_count?: number
    matched_memory_regions?: string[]
    matched_protections?: string[]
    matched_address_ranges?: string[]
    matched_region_owners?: string[]
    matched_observed_modules?: string[]
    matched_segment_names?: string[]
    suggested_modules?: string[]
    matched_by?: string[]
    provenance_layers?: string[]
    latest_artifact_at?: string | null
    scope_note?: string
  }
): string {
  const phrases: string[] = []
  const topApis = xrefSignals.slice(0, 3).map((item) => item.api)

  if (behaviorTags.length > 0) {
    const described = behaviorTags.slice(0, 2).map(describeBehaviorTag)
    const suffix = topApis.length > 0 ? ` via ${topApis.join(', ')}` : ''
    phrases.push(`Likely handles ${described.join(' and ')}${suffix}`)
  } else if (xrefSignals.length > 0) {
    phrases.push(
      `Likely coordinates API-facing behavior around ${xrefSignals
        .slice(0, 2)
        .map((item) => item.api)
        .join(' and ')}`
    )
  } else {
    phrases.push(`Partial semantic recovery for ${functionName}`)
  }

  if (rankReasons.includes('entry_point')) {
    phrases.push('appears to be an entry or dispatch point')
  } else if (callContext.callers.length > 0 || callContext.callees.length > 0) {
    const parts: string[] = []
    if (callContext.callers.length > 0) {
      parts.push(`called by ${callContext.callers.slice(0, 2).join(', ')}`)
    }
    if (callContext.callees.length > 0) {
      parts.push(`invokes ${callContext.callees.slice(0, 3).join(', ')}`)
    }
    if (parts.length > 0) {
      phrases.push(parts.join(' and '))
    }
  }

  const relationshipInsights = summarizeRelationshipInsights(relationshipContext)
  if (relationshipInsights) {
    phrases.push(relationshipInsights)
  }

  const gapSummary = gaps.filter((gap) =>
    ['missing_cfg', 'unresolved_function_symbols', 'unresolved_data_symbols'].includes(gap)
  )
  if (gapSummary.length > 0) {
    phrases.push(`analysis gaps remain: ${gapSummary.join(', ')}`)
  }

  if (parameterRoles.length > 0) {
    phrases.push(
      `expected inputs resemble ${parameterRoles
        .slice(0, 3)
        .map((item) => item.role)
        .join(', ')}`
    )
  }

  if (returnRole) {
    phrases.push(`likely returns ${returnRole.role}`)
  }

  if (stateRoles.length > 0) {
    phrases.push(
      `likely maintains ${stateRoles
        .slice(0, 2)
        .map((item) => item.state_key)
        .join(' and ')} state`
    )
  }

  if (structInference.length > 0) {
    phrases.push(
      `recovered data contracts suggest ${structInference
        .slice(0, 2)
        .map((item) => item.semantic_name)
        .join(' and ')}`
    )
  }

  if (
    runtimeContext &&
    (
      runtimeContext.corroborated_apis.length > 0 ||
      runtimeContext.corroborated_stages.length > 0 ||
      (runtimeContext.matched_memory_regions || []).length > 0 ||
      (runtimeContext.matched_protections || []).length > 0 ||
      (runtimeContext.matched_region_owners || []).length > 0 ||
      (runtimeContext.matched_observed_modules || []).length > 0 ||
      (runtimeContext.matched_segment_names || []).length > 0
    )
  ) {
    const runtimePhrases: string[] = []
    if (runtimeContext.corroborated_apis.length > 0) {
      runtimePhrases.push(`runtime corroborates ${runtimeContext.corroborated_apis.slice(0, 3).join(', ')}`)
    }
    if (runtimeContext.corroborated_stages.length > 0) {
      runtimePhrases.push(`observed runtime stages include ${runtimeContext.corroborated_stages.slice(0, 2).join(', ')}`)
    }
    if (runtimeContext.executed) {
      runtimePhrases.push('evidence includes executed runtime trace')
    }
    if ((runtimeContext.evidence_sources || []).length > 0) {
      runtimePhrases.push(`runtime sources=${(runtimeContext.evidence_sources || []).slice(0, 3).join(', ')}`)
    }
    if ((runtimeContext.source_names || []).length > 0) {
      runtimePhrases.push(`runtime names=${(runtimeContext.source_names || []).slice(0, 3).join(', ')}`)
    }
    if ((runtimeContext.provenance_layers || []).length > 0) {
      runtimePhrases.push(
        `runtime layers=${(runtimeContext.provenance_layers || []).slice(0, 3).join(', ')}`
      )
    }
    if ((runtimeContext.matched_memory_regions || []).length > 0) {
      runtimePhrases.push(
        `memory regions include ${(runtimeContext.matched_memory_regions || []).slice(0, 2).join(', ')}`
      )
    }
    if ((runtimeContext.matched_protections || []).length > 0) {
      runtimePhrases.push(
        `protections include ${(runtimeContext.matched_protections || []).slice(0, 2).join(', ')}`
      )
    }
    if ((runtimeContext.matched_region_owners || []).length > 0) {
      runtimePhrases.push(
        `region owners include ${(runtimeContext.matched_region_owners || []).slice(0, 2).join(', ')}`
      )
    }
    if ((runtimeContext.matched_observed_modules || []).length > 0) {
      runtimePhrases.push(
        `observed modules include ${(runtimeContext.matched_observed_modules || []).slice(0, 2).join(', ')}`
      )
    }
    if ((runtimeContext.matched_segment_names || []).length > 0) {
      runtimePhrases.push(
        `segments include ${(runtimeContext.matched_segment_names || []).slice(0, 2).join(', ')}`
      )
    }
    if ((runtimeContext.matched_address_ranges || []).length > 0) {
      runtimePhrases.push(
        `address ranges include ${(runtimeContext.matched_address_ranges || []).slice(0, 2).join(', ')}`
      )
    }
    if (runtimeContext.scope_note) {
      runtimePhrases.push(runtimeContext.scope_note)
    }
    if ((runtimeContext.suggested_modules || []).length > 0) {
      runtimePhrases.push(
        `suggested modules=${(runtimeContext.suggested_modules || []).slice(0, 3).join(', ')}`
      )
    }
    phrases.push(runtimePhrases.join(' and '))
  }

  return `${phrases.join('; ')}.`
}

function computeConfidence(
  decompiled: DecompiledFunction | undefined,
  cfg: ControlFlowGraph | undefined,
  instructionCount: number,
  rankScore: number | null,
  runtimeConfidence?: number
): { confidence: number; breakdown: ConfidenceBreakdown } {
  const pseudocodeLines = parsePseudocodeLines(decompiled?.pseudocode)
  const breakdown: ConfidenceBreakdown = {
    decompile: 0,
    cfg: 0,
    assembly: 0,
    context: 0,
  }

  if (decompiled && pseudocodeLines.length > 0) {
    breakdown.decompile = 0.35
    if (pseudocodeLines.length > 20) {
      breakdown.decompile += 0.1
    }
    if (
      decompiled.callers.length +
        decompiled.callees.length +
        (decompiled.caller_relationships?.length || 0) +
        (decompiled.callee_relationships?.length || 0) >
      0
    ) {
      breakdown.decompile += 0.05
    }
  }

  if (cfg && cfg.nodes.length > 0) {
    breakdown.cfg = 0.2
    if (cfg.nodes.length > 3) {
      breakdown.cfg += 0.08
    }
    if (cfg.edges.length > 3) {
      breakdown.cfg += 0.07
    }
  }

  if (instructionCount > 0) {
    breakdown.assembly = 0.08
    if (instructionCount > 30) {
      breakdown.assembly += 0.05
    }
  }

  if (rankScore !== null) {
    breakdown.context = clamp(0.05 + rankScore / 100, 0.05, 0.2)
  }
  if (runtimeConfidence && runtimeConfidence > 0) {
    breakdown.context = clamp(breakdown.context + runtimeConfidence * 0.08, 0.05, 0.28)
  }

  const confidence =
    breakdown.decompile + breakdown.cfg + breakdown.assembly + breakdown.context

  return {
    confidence: clamp(confidence, 0, 1),
    breakdown,
  }
}

function buildSourceLikeSnippet(
  functionName: string,
  confidence: number,
  gaps: string[],
  pseudocodeLines: string[],
  maxPseudocodeLines: number,
  semanticSummary: string,
  xrefSignals: FunctionXrefSummary[],
  callContext: {
    callers: string[]
    callees: string[]
  },
  relationshipContext: RelationshipContext,
  rankReasons: string[],
  parameterRoles: z.infer<typeof FunctionParameterRoleSchema>[],
  returnRole: z.infer<typeof FunctionReturnRoleSchema> | null | undefined,
  stateRoles: z.infer<typeof FunctionStateRoleSchema>[],
  structInference: z.infer<typeof FunctionStructInferenceSchema>[],
  runtimeContext?: {
    corroborated_apis: string[]
    corroborated_stages: string[]
    notes: string[]
    confidence: number
    executed?: boolean
    evidence_sources?: string[]
    source_names?: string[]
    artifact_count?: number
    executed_artifact_count?: number
    matched_memory_regions?: string[]
    matched_protections?: string[]
    matched_address_ranges?: string[]
    matched_region_owners?: string[]
    matched_observed_modules?: string[]
    matched_segment_names?: string[]
    suggested_modules?: string[]
    matched_by?: string[]
    provenance_layers?: string[]
    latest_artifact_at?: string | null
    scope_note?: string
  }
): string {
  const header = `// function=${functionName} confidence=${confidence.toFixed(2)} gaps=${gaps.length > 0 ? gaps.join(',') : 'none'}`
  const commentLines = [header, `// summary=${semanticSummary}`]

  if (xrefSignals.length > 0) {
    commentLines.push(
      `// xrefs=${xrefSignals
        .slice(0, 4)
        .map((item) => `${item.api}[${item.provenance},${item.confidence.toFixed(2)}]`)
        .join('; ')}`
    )
  }

  if (callContext.callers.length > 0 || callContext.callees.length > 0) {
    commentLines.push(
      `// callers=${callContext.callers.join(', ') || 'none'} | callees=${callContext.callees.join(', ') || 'none'}`
    )
  }

  if (relationshipContext.callers.length > 0 || relationshipContext.callees.length > 0) {
    commentLines.push(
      `// relationship_hints=callers:${relationshipContext.callers
        .map((item) => formatRelationshipEntry(item))
        .join(' || ') || 'none'} | callees:${relationshipContext.callees
        .map((item) => formatRelationshipEntry(item))
        .join(' || ') || 'none'}`
    )
  }

  if (rankReasons.length > 0) {
    commentLines.push(`// rank_reasons=${rankReasons.slice(0, 5).join(', ')}`)
  }

  if (parameterRoles.length > 0) {
    commentLines.push(`// parameter_roles=${summarizeParameterRoles(parameterRoles)}`)
  }

  if (returnRole) {
    commentLines.push(`// return_role=${summarizeReturnRole(returnRole)}`)
  }

  if (stateRoles.length > 0) {
    commentLines.push(`// state_roles=${summarizeStateRoles(stateRoles)}`)
  }

  if (structInference.length > 0) {
    commentLines.push(`// struct_inference=${summarizeStructInference(structInference)}`)
  }

  if (
    runtimeContext &&
    (runtimeContext.corroborated_apis.length > 0 ||
      runtimeContext.corroborated_stages.length > 0 ||
      (runtimeContext.matched_memory_regions || []).length > 0 ||
      (runtimeContext.matched_protections || []).length > 0 ||
      (runtimeContext.matched_region_owners || []).length > 0 ||
      (runtimeContext.matched_observed_modules || []).length > 0 ||
      (runtimeContext.matched_segment_names || []).length > 0)
  ) {
    commentLines.push(
      `// runtime_evidence=apis:${runtimeContext.corroborated_apis.join(', ') || 'none'} | stages:${runtimeContext.corroborated_stages.join(', ') || 'none'} | regions:${(runtimeContext.matched_memory_regions || []).join(', ') || 'none'} | protections:${(runtimeContext.matched_protections || []).join(', ') || 'none'} | owners:${(runtimeContext.matched_region_owners || []).join(', ') || 'none'} | observed_modules:${(runtimeContext.matched_observed_modules || []).join(', ') || 'none'} | segments:${(runtimeContext.matched_segment_names || []).join(', ') || 'none'} | ranges:${(runtimeContext.matched_address_ranges || []).join(', ') || 'none'} | modules:${(runtimeContext.suggested_modules || []).join(', ') || 'none'} | confidence:${runtimeContext.confidence.toFixed(2)} | executed:${runtimeContext.executed ? 'yes' : 'no'} | sources:${(runtimeContext.evidence_sources || []).join(', ') || 'unknown'} | names:${(runtimeContext.source_names || []).join(', ') || 'unknown'} | layers:${(runtimeContext.provenance_layers || []).join(', ') || 'unknown'} | latest:${runtimeContext.latest_artifact_at || 'unknown'} | matched_by:${(runtimeContext.matched_by || []).join(', ') || 'unknown'} | artifacts:${runtimeContext.executed_artifact_count || 0}/${runtimeContext.artifact_count || 0}`
    )
    if (runtimeContext.notes.length > 0) {
      commentLines.push(`// runtime_notes=${runtimeContext.notes.join(' || ')}`)
    }
    if (runtimeContext.scope_note) {
      commentLines.push(`// runtime_scope=${runtimeContext.scope_note}`)
    }
  }

  const snippetLines = pseudocodeLines.slice(0, maxPseudocodeLines)

  if (snippetLines.length === 0) {
    return [...commentLines, '// pseudocode unavailable; inspect CFG/assembly manually'].join(
      '\n'
    )
  }

  return [...commentLines, ...snippetLines].join('\n')
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

async function buildDegradedFallbackFunction(
  workspaceManager: WorkspaceManager,
  sampleId: string,
  targetLabel: string
): Promise<ReconstructedFunction> {
  let workspace: Awaited<ReturnType<WorkspaceManager['getWorkspace']>>
  try {
    workspace = await workspaceManager.getWorkspace(sampleId)
  } catch {
    return {
      target: targetLabel,
      function: 'degraded_static_summary',
      address: 'unknown',
      rank_score: null,
      rank_reasons: ['fallback_without_workspace'],
      semantic_summary:
        'Degraded static summary only; no Ghidra workspace was available for deeper recovery.',
      xref_signals: [],
      call_context: {
        callers: [],
        callees: [],
      },
      call_relationships: {
        callers: [],
        callees: [],
      },
      confidence: 0.1,
      confidence_breakdown: {
        decompile: 0,
        cfg: 0,
        assembly: 0,
        context: 0.1,
      },
      gaps: ['missing_ghidra_analysis', 'workspace_unavailable', 'missing_all_primary_evidence'],
      evidence: {
        pseudocode_lines: 0,
        cfg_nodes: 0,
        cfg_edges: 0,
        instruction_count: 0,
        caller_count: 0,
        callee_count: 0,
      },
      behavior_tags: [],
      source_like_snippet: [
        '// degraded fallback: ghidra artifacts unavailable',
        '// workspace not found for this sample',
        '// next step: run sample.ingest (if needed) and ghidra.analyze',
      ].join('\n'),
      assembly_excerpt: '; assembly unavailable in degraded fallback mode',
    }
  }

  const files = fs
    .readdirSync(workspace.original, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort((a, b) => a.localeCompare(b))

  if (files.length === 0) {
    return {
      target: targetLabel,
      function: 'degraded_static_summary',
      address: 'unknown',
      rank_score: null,
      rank_reasons: ['fallback_without_sample_file'],
      semantic_summary:
        'Degraded static summary only; workspace exists but the original sample file is unavailable.',
      xref_signals: [],
      call_context: {
        callers: [],
        callees: [],
      },
      call_relationships: {
        callers: [],
        callees: [],
      },
      confidence: 0.12,
      confidence_breakdown: {
        decompile: 0,
        cfg: 0,
        assembly: 0,
        context: 0.12,
      },
      gaps: ['missing_ghidra_analysis', 'sample_file_unavailable', 'missing_all_primary_evidence'],
      evidence: {
        pseudocode_lines: 0,
        cfg_nodes: 0,
        cfg_edges: 0,
        instruction_count: 0,
        caller_count: 0,
        callee_count: 0,
      },
      behavior_tags: [],
      source_like_snippet: [
        '// degraded fallback: ghidra artifacts unavailable',
        '// sample file missing in workspace.original',
        '// next step: run ghidra.analyze and retry',
      ].join('\n'),
      assembly_excerpt: '; assembly unavailable in degraded fallback mode',
    }
  }

  const samplePath = path.join(workspace.original, files[0])
  const sampleBuffer = fs.readFileSync(samplePath)
  const scanWindow = sampleBuffer.subarray(0, Math.min(sampleBuffer.length, 2 * 1024 * 1024))
  const asciiCorpus = scanWindow
    .toString('latin1')
    .match(/[ -~]{6,}/g)
    ?.slice(0, 500)
    .join('\n') || ''

  const behaviorTags = inferBehaviorTags(undefined, asciiCorpus).slice(0, 8)
  const topHints = asciiCorpus
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .filter((line, index, all) => all.indexOf(line) === index)
    .slice(0, 8)

  const snippetLines = [
    '// degraded fallback: ghidra function artifacts unavailable',
    `// sample_path=${samplePath}`,
    `// inferred_behaviors=${behaviorTags.length > 0 ? behaviorTags.join(',') : 'none'}`,
    '// hint_strings:',
    ...topHints.map((line) => `//   ${line}`),
    '// next step: run ghidra.analyze to unlock function-level pseudocode/cfg',
  ]

  return {
    target: targetLabel,
    function: 'degraded_static_summary',
    address: 'unknown',
    rank_score: null,
    rank_reasons: ['fallback_static_summary'],
    semantic_summary:
      behaviorTags.length > 0
        ? `Static-only fallback suggests ${behaviorTags.map(describeBehaviorTag).join(' and ')}.`
        : 'Static-only fallback summary; run ghidra.analyze for function-level semantics.',
    xref_signals: [],
    call_context: {
      callers: [],
      callees: [],
    },
    call_relationships: {
      callers: [],
      callees: [],
    },
    confidence: behaviorTags.length > 0 ? 0.24 : 0.16,
    confidence_breakdown: {
      decompile: 0,
      cfg: 0,
      assembly: 0,
      context: behaviorTags.length > 0 ? 0.24 : 0.16,
    },
    gaps: ['missing_ghidra_analysis', 'missing_pseudocode', 'missing_cfg'],
    evidence: {
      pseudocode_lines: 0,
      cfg_nodes: 0,
      cfg_edges: 0,
      instruction_count: 0,
      caller_count: 0,
      callee_count: 0,
    },
    behavior_tags: behaviorTags,
    source_like_snippet: snippetLines.join('\n'),
    assembly_excerpt: '; assembly unavailable in degraded fallback mode',
  }
}

export function createCodeFunctionsReconstructHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: CodeFunctionsReconstructDependencies
) {
  const decompilerWorker = new DecompilerWorker(database, workspaceManager)
  const stringsExtractHandler = createStringsExtractHandler(workspaceManager, database, cacheManager)
  const rankFunctions =
    dependencies?.rankFunctions ||
    ((sampleId: string, topK: number) => decompilerWorker.rankFunctions(sampleId, topK))
  const decompileFunction =
    dependencies?.decompileFunction ||
    ((sampleId: string, addressOrSymbol: string, includeXrefs: boolean, timeoutMs: number) =>
      decompilerWorker.decompileFunction(sampleId, addressOrSymbol, includeXrefs, timeoutMs))
  const getFunctionCFG =
    dependencies?.getFunctionCFG ||
    ((sampleId: string, addressOrSymbol: string, timeoutMs: number) =>
      decompilerWorker.getFunctionCFG(sampleId, addressOrSymbol, timeoutMs))
  const runtimeEvidenceLoader =
    dependencies?.runtimeEvidenceLoader ||
    ((sampleId: string, options?: { evidenceScope?: 'all' | 'latest' | 'session'; sessionTag?: string }) =>
      loadDynamicTraceEvidence(workspaceManager, database, sampleId, {
        evidenceScope: options?.evidenceScope,
        sessionTag: options?.sessionTag,
      }))
  const stringEvidenceLoader =
    dependencies?.stringEvidenceLoader ||
    (async (sampleId: string): Promise<SampleStringEvidence | null> => {
      const response = await stringsExtractHandler({
        sample_id: sampleId,
        max_strings: 120,
        max_context_windows: 8,
        max_string_length: 160,
        category_filter: 'all',
      })
      const responseData = response.data as
        | {
            summary?: {
              top_high_value?: SampleStringValue[]
              context_windows?: SampleStringContextWindow[]
            }
          }
        | undefined
      if (!response.ok || !responseData?.summary) {
        return null
      }
      return {
        top_high_value: responseData.summary.top_high_value || [],
        context_windows: responseData.summary.context_windows || [],
      }
    })
  const semanticNameSuggester =
    dependencies?.semanticNameSuggester ||
    (async () => null)
  const externalSemanticSuggestionLoader =
    dependencies?.externalSemanticSuggestionLoader ||
    ((sampleId: string, options?: { scope?: 'all' | 'latest' | 'session'; sessionTag?: string }) =>
      loadSemanticNameSuggestionIndex(workspaceManager, database, sampleId, options))

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = CodeFunctionsReconstructInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      const completedGhidraAnalysis = findBestGhidraAnalysis(
        database.findAnalysesBySample(input.sample_id),
        'function_index'
      )
      const analysisMarker =
        completedGhidraAnalysis?.finished_at || completedGhidraAnalysis?.id || 'none'
      const runtimeArtifacts = [
        ...database.findArtifactsByType(input.sample_id, 'dynamic_trace_json'),
        ...database.findArtifactsByType(input.sample_id, 'sandbox_trace_json'),
      ]
      const runtimeMarker =
        runtimeArtifacts.length > 0
          ? runtimeArtifacts.map((item) => `${item.type}:${item.sha256}`).sort().join('|')
          : 'none'
      const semanticNameArtifacts = database.findArtifactsByType(
        input.sample_id,
        SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE
      )
      const semanticNameMarker =
        semanticNameArtifacts.length > 0
          ? semanticNameArtifacts.map((item) => `${item.id}:${item.sha256}`).sort().join('|')
          : 'none'

      const mode: 'single' | 'topk' = input.address || input.symbol ? 'single' : 'topk'
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          mode,
          address: input.address || null,
          symbol: input.symbol || null,
          topk: input.topk,
          include_xrefs: input.include_xrefs,
          max_pseudocode_lines: input.max_pseudocode_lines,
          max_assembly_lines: input.max_assembly_lines,
          timeout: input.timeout,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag || null,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag || null,
          analysis_marker: analysisMarker,
          runtime_marker: runtimeMarker,
          semantic_name_marker: semanticNameMarker,
          ghidra_valid: ghidraConfig.isValid,
          ghidra_install_dir: ghidraConfig.installDir || 'none',
          ghidra_version: ghidraConfig.version || 'unknown',
        },
      })

      const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
      if (cachedLookup) {
        return {
          ok: true,
          data: cachedLookup.data,
          warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
            cached: true,
            cache_key: cachedLookup.metadata.key,
            cache_tier: cachedLookup.metadata.tier,
            cache_created_at: cachedLookup.metadata.createdAt,
            cache_expires_at: cachedLookup.metadata.expiresAt,
            cache_hit_at: cachedLookup.metadata.fetchedAt,
          },
        }
      }

      const dynamicEvidence = await runtimeEvidenceLoader(input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
      })
      const externalSemanticSuggestions = await externalSemanticSuggestionLoader(input.sample_id, {
        scope: input.semantic_scope,
        sessionTag: input.semantic_session_tag,
      })
      const provenance = {
        runtime: buildRuntimeArtifactProvenance(
          dynamicEvidence,
          input.evidence_scope,
          input.evidence_session_tag
        ),
        semantic_names: buildSemanticArtifactProvenance(
          'semantic naming artifacts',
          externalSemanticSuggestions,
          input.semantic_scope,
          input.semantic_session_tag
        ),
      }
      let targets: FunctionTarget[] = []
      if (mode === 'single') {
        targets = [
          {
            target: input.address || input.symbol || '',
            rankScore: null,
            rankReasons: [],
            xrefSummary: [],
          },
        ]
      } else {
        const ranked = await rankFunctions(input.sample_id, input.topk)
        targets = ranked.map((item) => ({
          target: item.address,
          rankScore: item.score,
          rankReasons: item.reasons || [],
          xrefSummary: item.xref_summary || [],
        }))
      }

      if (targets.length === 0) {
        const fallbackTarget = input.address || input.symbol || `topk:${input.topk}`
        const fallbackFunction = await buildDegradedFallbackFunction(
          workspaceManager,
          input.sample_id,
          fallbackTarget
        )
        const fallbackOutput = {
          sample_id: input.sample_id,
          mode,
          requested_count: mode === 'single' ? 1 : input.topk,
          reconstructed_count: 1,
          overall_confidence: fallbackFunction.confidence,
          provenance,
          confidence_map: [
            {
              function: fallbackFunction.function,
              address: fallbackFunction.address,
              confidence: fallbackFunction.confidence,
              gaps: fallbackFunction.gaps,
            },
          ],
          functions: [fallbackFunction],
        }

        await cacheManager.setCachedResult(cacheKey, fallbackOutput, CACHE_TTL_MS, sample.sha256)

        return {
          ok: true,
          data: fallbackOutput,
          warnings: [
            `No candidate functions available; returned degraded fallback summary. Run ghidra.analyze for full function-level reconstruction on ${input.sample_id}.`,
          ],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const warnings: string[] = []
      const timeoutMs = input.timeout * 1000
      let sampleStringEvidence: SampleStringEvidence | null = null
      try {
        sampleStringEvidence = await stringEvidenceLoader(input.sample_id)
      } catch (error) {
        warnings.push(`String evidence unavailable: ${normalizeError(error)}`)
      }
      const reconstructedFunctions: ReconstructedFunction[] = []
      let fallbackDisasm: EntrypointFallbackPayload | null = null
      let fallbackDisasmAttempted = false

      const resolveFallbackDisasm = async (): Promise<EntrypointFallbackPayload | null> => {
        if (fallbackDisasm) {
          return fallbackDisasm
        }
        if (fallbackDisasmAttempted) {
          return null
        }

        fallbackDisasmAttempted = true
        try {
          const workspace = await workspaceManager.getWorkspace(input.sample_id)
          const fallbackFile = fs
            .readdirSync(workspace.original, { withFileTypes: true })
            .filter((entry) => entry.isFile())
            .map((entry) => entry.name)
            .sort((a, b) => a.localeCompare(b))[0]

          if (!fallbackFile) {
            warnings.push('fallback disassembly unavailable: sample file missing in workspace.original')
            return null
          }

          const samplePath = path.join(workspace.original, fallbackFile)
          fallbackDisasm = await runEntrypointFallbackDisasm(samplePath, {
            max_instructions: 140,
            max_bytes: 1536,
          })
          return fallbackDisasm
        } catch (error) {
          warnings.push(`fallback disassembly failed: ${normalizeError(error)}`)
          return null
        }
      }

      for (const target of targets) {
        let decompiled: DecompiledFunction | undefined
        let cfg: ControlFlowGraph | undefined

        try {
          decompiled = await decompileFunction(
            input.sample_id,
            target.target,
            input.include_xrefs,
            timeoutMs
          )
        } catch (error) {
          warnings.push(`decompile failed for ${target.target}: ${normalizeError(error)}`)
        }

        try {
          cfg = await getFunctionCFG(input.sample_id, target.target, timeoutMs)
        } catch (error) {
          warnings.push(`cfg failed for ${target.target}: ${normalizeError(error)}`)
        }

        const pseudocodeLines = parsePseudocodeLines(decompiled?.pseudocode)
        let assembly = extractAssemblyFromCFG(cfg, input.max_assembly_lines)
        let fallbackUsedForTarget = false
        let fallbackAddress: string | undefined

        if (!decompiled && !cfg && assembly.instructionCount === 0) {
          const fallback = await resolveFallbackDisasm()
          if (fallback) {
            fallbackUsedForTarget = true
            fallbackAddress = fallback.result.address
            assembly = {
              excerpt: fallback.result.assembly,
              instructionCount: fallback.result.instruction_count,
            }
            warnings.push(
              `fallback disassembly used for ${target.target} (${fallback.result.backend}/${fallback.result.parser}, section=${fallback.result.entry_section})`
            )
            if (Array.isArray(fallback.warnings) && fallback.warnings.length > 0) {
              warnings.push(...fallback.warnings.map((item) => `fallback note: ${item}`))
            }
          }
        }

        const gaps = dedupe([
          ...collectGaps(
            pseudocodeLines,
            cfg,
            decompiled,
            input.max_pseudocode_lines
          ),
          ...(fallbackUsedForTarget ? ['ghidra_unavailable_fallback_disasm'] : []),
        ])

        const functionName =
          decompiled?.function || (fallbackUsedForTarget ? 'entrypoint_fallback' : target.target)
        const functionAddress =
          decompiled?.address ||
          cfg?.address ||
          fallbackAddress ||
          (target.target.startsWith('0x') ? target.target : 'unknown')
        const behaviorTags = inferBehaviorTags(decompiled, assembly.excerpt)
        const relationshipContext = buildRelationshipContext(decompiled)
        const callContext = buildCallContext(decompiled)
        const xrefSignals = collectXrefSignals(target, decompiled, assembly.excerpt)
        const runtimeContext = correlateFunctionWithRuntimeEvidence(
          {
            functionName,
            behaviorTags,
            xrefApis: [
              ...xrefSignals.map((item) => item.api),
              ...extractSensitiveApisFromReasons(target.rankReasons),
            ],
            rankReasons: target.rankReasons,
            semanticSummary: decompiled?.pseudocode || assembly.excerpt,
            callTargets: [...callContext.callers, ...callContext.callees],
          },
          dynamicEvidence
        )
        const draftSemanticSummary = buildSemanticSummary(
          functionName,
          behaviorTags,
          xrefSignals,
          callContext,
          relationshipContext,
          gaps,
          target.rankReasons,
          [],
          null,
          [],
          [],
          runtimeContext
        )
        const cfgShape = buildCFGShape(cfg || undefined)
        const renameSuggestion = buildRenameSuggestion(
          functionName,
          behaviorTags,
          xrefSignals,
          callContext,
          relationshipContext,
          gaps,
          target.rankReasons,
          draftSemanticSummary,
          `${decompiled?.pseudocode || ''}\n${assembly.excerpt}`,
          runtimeContext
        )
        const confidence = computeConfidence(
          decompiled,
          cfg,
          assembly.instructionCount,
          target.rankScore,
          runtimeContext?.confidence
        )
        const draftSourceLikeSnippet = buildSourceLikeSnippet(
          functionName,
          confidence.confidence,
          gaps,
          pseudocodeLines,
          input.max_pseudocode_lines,
          draftSemanticSummary,
          xrefSignals,
          callContext,
          relationshipContext,
          target.rankReasons,
          [],
          null,
          [],
          [],
          runtimeContext
        )
        const functionStringHints = buildFunctionStringHints(
          sampleStringEvidence,
          functionName,
          behaviorTags,
          xrefSignals,
          runtimeContext,
          draftSemanticSummary,
          draftSourceLikeSnippet
        )
        const parameterRoles = inferParameterRoles(
          behaviorTags,
          xrefSignals,
          runtimeContext,
          functionStringHints,
          draftSemanticSummary,
          draftSourceLikeSnippet
        )
        const stateRoles = inferStateRoles(
          behaviorTags,
          xrefSignals,
          runtimeContext,
          functionStringHints,
          draftSemanticSummary,
          draftSourceLikeSnippet
        )
        const structInference = inferStructInference(parameterRoles, stateRoles)
        const returnRole = inferReturnRole(
          behaviorTags,
          xrefSignals,
          runtimeContext,
          functionStringHints,
          draftSemanticSummary,
          draftSourceLikeSnippet
        )
        const semanticSummary = buildSemanticSummary(
          functionName,
          behaviorTags,
          xrefSignals,
          callContext,
          relationshipContext,
          gaps,
          target.rankReasons,
          parameterRoles,
          returnRole,
          stateRoles,
          structInference,
          runtimeContext
        )
        const sourceLikeSnippet = buildSourceLikeSnippet(
          functionName,
          confidence.confidence,
          gaps,
          pseudocodeLines,
          input.max_pseudocode_lines,
          semanticSummary,
          xrefSignals,
          callContext,
          relationshipContext,
          target.rankReasons,
          parameterRoles,
          returnRole,
          stateRoles,
          structInference,
          runtimeContext
        )
        const semanticEvidence = {
          semantic_summary: semanticSummary,
          xref_signals: xrefSignals,
          call_relationships: relationshipContext,
          runtime_context: runtimeContext || null,
          string_hints: functionStringHints,
          pseudocode_excerpt: buildPseudocodeExcerpt(sourceLikeSnippet),
          cfg_shape: cfgShape,
          parameter_roles: parameterRoles,
          return_role: returnRole || null,
          state_roles: stateRoles,
          struct_inference: structInference,
        }
        const enrichedSourceLikeSnippet = withSuggestedNameHeader(
          sourceLikeSnippet,
          renameSuggestion
        )

        reconstructedFunctions.push({
          target: target.target,
          function: functionName,
          address: functionAddress,
          rank_score: target.rankScore,
          rank_reasons: target.rankReasons,
          suggested_name: renameSuggestion.suggested_name,
          suggested_role: renameSuggestion.suggested_role,
          rename_confidence: renameSuggestion.suggested_name
            ? renameSuggestion.rename_confidence
            : null,
          rename_evidence: renameSuggestion.rename_evidence,
          semantic_summary: semanticSummary,
          xref_signals: xrefSignals,
          call_context: callContext,
          call_relationships: relationshipContext,
          runtime_context: runtimeContext,
          parameter_roles: parameterRoles,
          return_role: returnRole,
          state_roles: stateRoles,
          struct_inference: structInference,
          semantic_evidence: semanticEvidence,
          confidence_profile: buildReconstructionConfidenceSemantics({
            score: confidence.confidence,
            breakdown: confidence.breakdown,
            runtimeConfidence: runtimeContext?.confidence,
          }),
          runtime_confidence_profile: buildRuntimeConfidenceSemantics({
            score: runtimeContext?.confidence,
            matchedApis: runtimeContext?.corroborated_apis,
            matchedStages: runtimeContext?.corroborated_stages,
            matchedMemoryRegions: runtimeContext?.matched_memory_regions,
            executed: runtimeContext?.executed,
            evidenceSources: runtimeContext?.evidence_sources,
          }),
          naming_confidence_profile: buildNamingConfidenceSemantics({
            resolutionSource: renameSuggestion.suggested_name ? 'rule' : 'unresolved',
            renameConfidence: renameSuggestion.suggested_name
              ? renameSuggestion.rename_confidence
              : null,
            ruleBasedName: renameSuggestion.suggested_name,
            validatedName: renameSuggestion.suggested_name,
          }),
          confidence: confidence.confidence,
          confidence_breakdown: confidence.breakdown,
          gaps,
          evidence: {
            pseudocode_lines: pseudocodeLines.length,
            cfg_nodes: cfg?.nodes.length || 0,
            cfg_edges: cfg?.edges.length || 0,
            instruction_count: assembly.instructionCount,
            caller_count: Math.max(
              decompiled?.callers.length || 0,
              decompiled?.caller_relationships?.length || 0
            ),
            callee_count: Math.max(
              decompiled?.callees.length || 0,
              decompiled?.callee_relationships?.length || 0
            ),
          },
          behavior_tags: behaviorTags,
          source_like_snippet: enrichedSourceLikeSnippet,
          assembly_excerpt: assembly.excerpt,
        })
      }

      const refinedFunctions = refineRenameSuggestions(reconstructedFunctions)
      const layeredFunctions: ReconstructedFunction[] = []
      for (const func of refinedFunctions) {
        const externalSuggestion = findSemanticNameSuggestion(
          externalSemanticSuggestions,
          func.address,
          func.function
        )
        const { nameResolution, finalSuggestion } = await finalizeLayeredNameResolution(
          func,
          externalSuggestion,
          semanticNameSuggester
        )
        const suggestionAppliedSnippet = withSuggestedNameHeader(
          func.source_like_snippet,
          finalSuggestion
        )
        layeredFunctions.push({
          ...func,
          suggested_name: finalSuggestion.suggested_name,
          suggested_role: finalSuggestion.suggested_role,
          rename_confidence: finalSuggestion.suggested_name
            ? finalSuggestion.rename_confidence
            : null,
          rename_evidence: finalSuggestion.rename_evidence,
          name_resolution: nameResolution,
          naming_confidence_profile: buildNamingConfidenceSemantics({
            resolutionSource: nameResolution.resolution_source,
            renameConfidence: finalSuggestion.suggested_name
              ? finalSuggestion.rename_confidence
              : null,
            llmConfidence: nameResolution.llm_confidence,
            ruleBasedName: nameResolution.rule_based_name,
            validatedName: nameResolution.validated_name,
          }),
          source_like_snippet: withNameResolutionHeader(
            suggestionAppliedSnippet,
            nameResolution
          ),
        })
      }
      layeredFunctions.sort((a, b) => b.confidence - a.confidence)
      const overallConfidence =
        layeredFunctions.reduce((sum, item) => sum + item.confidence, 0) /
        layeredFunctions.length

      const outputData = {
        sample_id: input.sample_id,
        mode,
        requested_count: targets.length,
        reconstructed_count: layeredFunctions.length,
        overall_confidence: clamp(overallConfidence, 0, 1),
        provenance,
        confidence_map: layeredFunctions.map((item) => ({
          function: item.function,
          address: item.address,
          confidence: item.confidence,
          gaps: item.gaps,
        })),
        functions: layeredFunctions,
      }

      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: outputData,
        warnings: warnings.length > 0 ? warnings : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
