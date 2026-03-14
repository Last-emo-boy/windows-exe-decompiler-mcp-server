/**
 * code.reconstruct.export tool implementation
 * Module-level regrouping + source-like project skeleton export.
 */

import { createHash, randomUUID } from 'crypto'
import { spawn } from 'child_process'
import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { createCodeFunctionsReconstructHandler } from './code-functions-reconstruct.js'
import { createPEImportsExtractHandler } from './pe-imports-extract.js'
import { createPEExportsExtractHandler } from './pe-exports-extract.js'
import { createPackerDetectHandler } from './packer-detect.js'
import { createStringsExtractHandler } from './strings-extract.js'
import {
  DecompilerWorker,
  type FunctionSearchResult,
  type FunctionXrefSummary,
} from '../decompiler-worker.js'
import { findBestGhidraAnalysis } from '../ghidra-analysis-status.js'
import { ghidraConfig } from '../ghidra-config.js'
import { loadDynamicTraceEvidence, type DynamicTraceSummary } from '../dynamic-trace.js'
import { getPackageRoot } from '../runtime-paths.js'
import {
  correlateFunctionWithRuntimeEvidence,
  modulesSuggestedByRuntimeStages,
} from '../runtime-correlation.js'
import {
  findSemanticFunctionExplanation,
  findSemanticModuleReview,
  loadSemanticFunctionExplanationIndex,
  loadSemanticModuleReviewIndex,
  loadSemanticNameSuggestionIndex,
  type SemanticFunctionExplanationIndex,
  type SemanticModuleReviewIndex,
  SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE,
  SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE,
} from '../semantic-name-suggestion-artifacts.js'
import {
  AnalysisProvenanceSchema,
  buildRuntimeArtifactProvenance,
  buildSemanticArtifactProvenance,
} from '../analysis-provenance.js'

const TOOL_NAME = 'code.reconstruct.export'
const TOOL_VERSION = '0.2.15'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

export const CodeReconstructExportInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  topk: z
    .number()
    .int()
    .min(1)
    .max(40)
    .default(12)
    .describe('How many high-value functions to include for module regrouping'),
  module_limit: z
    .number()
    .int()
    .min(1)
    .max(12)
    .default(6)
    .describe('Maximum module count in exported skeleton'),
  min_module_size: z
    .number()
    .int()
    .min(1)
    .max(20)
    .default(2)
    .describe('Modules with fewer functions than this threshold are merged into core'),
  include_imports: z
    .boolean()
    .default(true)
    .describe('Use import features for module hints'),
  include_strings: z
    .boolean()
    .default(true)
    .describe('Use high-value string clusters for module hints'),
  export_name: z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe('Optional export folder name; default auto-generated'),
  validate_build: z
    .boolean()
    .default(true)
    .describe('Compile the exported C skeleton with clang when available'),
  run_harness: z
    .boolean()
    .default(true)
    .describe('Execute reconstruct_harness after a successful build validation'),
  compiler_path: z
    .string()
    .min(1)
    .max(260)
    .optional()
    .describe('Optional explicit clang compiler path'),
  build_timeout_ms: z
    .number()
    .int()
    .min(5000)
    .max(300000)
    .default(60000)
    .describe('Timeout for clang build validation in milliseconds'),
  run_timeout_ms: z
    .number()
    .int()
    .min(5000)
    .max(300000)
    .default(30000)
    .describe('Timeout for reconstruct_harness execution in milliseconds'),
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
  role_target: z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe('Optional high-level binary role hint from workflow preflight, such as native_rust_executable, dll_library, or com_server'),
  role_focus_areas: z
    .array(z.string().min(1).max(96))
    .max(16)
    .default([])
    .describe('Optional role-aware focus areas that bias module grouping and rewrite prioritization'),
  role_priority_order: z
    .array(z.string().min(1).max(96))
    .max(24)
    .default([])
    .describe('Optional priority-order hints from role-aware planning that influence module ordering and preservation'),
  reuse_cached: z
    .boolean()
    .default(true)
    .describe('When true, reuse cached export result for identical inputs'),
})
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })

export type CodeReconstructExportInput = z.infer<typeof CodeReconstructExportInputSchema>

const ModuleFunctionSchema = z.object({
  function: z.string(),
  address: z.string(),
  confidence: z.number().min(0).max(1),
  gaps: z.array(z.string()),
  suggested_name: z.string().nullable().optional(),
  suggested_role: z.string().nullable().optional(),
  rename_confidence: z.number().min(0).max(1).nullable().optional(),
  rule_based_name: z.string().nullable().optional(),
  llm_suggested_name: z.string().nullable().optional(),
  validated_name: z.string().nullable().optional(),
  name_resolution_source: z.enum(['rule', 'llm', 'hybrid', 'unresolved']).nullable().optional(),
  explanation_summary: z.string().nullable().optional(),
  explanation_behavior: z.string().nullable().optional(),
  explanation_confidence: z.number().min(0).max(1).nullable().optional(),
})

const ModuleSchema = z.object({
  name: z.string(),
  confidence: z.number().min(0).max(1),
  function_count: z.number().int().nonnegative(),
  role_hint: z.string().nullable().optional(),
  focus_matches: z.array(z.string()).optional(),
  refined_name: z.string().nullable().optional(),
  review_summary: z.string().nullable().optional(),
  review_confidence: z.number().min(0).max(1).nullable().optional(),
  import_hints: z.array(z.string()),
  string_hints: z.array(z.string()),
  runtime_apis: z.array(z.string()),
  runtime_stages: z.array(z.string()),
  interface_path: z.string(),
  pseudocode_path: z.string(),
  rewrite_path: z.string(),
  functions: z.array(ModuleFunctionSchema),
})

const CliProfileSchema = z.object({
  tool_name: z.string(),
  help_banner: z.string(),
  command_count: z.number().int().nonnegative(),
  commands: z.array(
    z.object({
      verb: z.string(),
      summary: z.string(),
    })
  ),
})

const BinaryProfileSchema = z.object({
  binary_role: z.string(),
  original_filename: z.string().nullable(),
  export_count: z.number().int().nonnegative(),
  forwarder_count: z.number().int().nonnegative(),
  notable_exports: z.array(z.string()),
  packed: z.boolean(),
  packing_confidence: z.number().min(0).max(1),
  analysis_priorities: z.array(z.string()),
  cli_profile: CliProfileSchema.nullable().optional(),
})

const NativeBuildValidationSchema = z.object({
  attempted: z.boolean(),
  status: z.enum(['passed', 'failed', 'skipped', 'unavailable']),
  compiler: z.string().nullable(),
  compiler_path: z.string().nullable(),
  command: z.string().nullable(),
  exit_code: z.number().int().nullable(),
  timed_out: z.boolean(),
  error: z.string().nullable(),
  log_path: z.string().nullable(),
  executable_path: z.string().nullable(),
})

const HarnessValidationSchema = z.object({
  attempted: z.boolean(),
  status: z.enum(['passed', 'failed', 'skipped', 'unavailable']),
  command: z.string().nullable(),
  exit_code: z.number().int().nullable(),
  timed_out: z.boolean(),
  error: z.string().nullable(),
  log_path: z.string().nullable(),
  matched_entries: z.number().int().nonnegative(),
  mismatched_entries: z.number().int().nonnegative(),
})

export const CodeReconstructExportOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      export_root: z.string(),
      manifest_path: z.string(),
      gaps_path: z.string(),
      notes_path: z.string(),
      cli_model_path: z.string(),
      support_header_path: z.string(),
      harness_path: z.string(),
      build_manifest_path: z.string(),
      build_validation: NativeBuildValidationSchema,
      harness_validation: HarnessValidationSchema,
      module_count: z.number().int().nonnegative(),
      unresolved_count: z.number().int().nonnegative(),
      binary_profile: BinaryProfileSchema,
      runtime_evidence: z
        .object({
          executed: z.boolean(),
          api_count: z.number().int().nonnegative(),
          stage_count: z.number().int().nonnegative(),
          observed_apis: z.array(z.string()),
          region_types: z.array(z.string()).optional(),
          protections: z.array(z.string()).optional(),
          address_ranges: z.array(z.string()).optional(),
          region_owners: z.array(z.string()).optional(),
          observed_modules: z.array(z.string()).optional(),
          segment_names: z.array(z.string()).optional(),
          observed_strings: z.array(z.string()).optional(),
          stages: z.array(z.string()),
          summary: z.string(),
        })
        .nullable(),
      provenance: AnalysisProvenanceSchema,
      modules: z.array(ModuleSchema),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
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

export type CodeReconstructExportOutput = z.infer<typeof CodeReconstructExportOutputSchema>

export const codeReconstructExportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Regroup recovered functions into source-like modules and export project skeleton with manifest and gaps.md.',
  inputSchema: CodeReconstructExportInputSchema,
  outputSchema: CodeReconstructExportOutputSchema,
}

interface ReconstructedFunction {
  function: string
  address: string
  confidence: number
  gaps: string[]
  suggested_name?: string | null
  suggested_role?: string | null
  rename_confidence?: number | null
  rename_evidence?: string[]
  behavior_tags?: string[]
  source_like_snippet: string
  semantic_summary?: string
  xref_signals?: FunctionXrefSummary[]
  call_context?: {
    callers?: string[]
    callees?: string[]
  }
  call_relationships?: {
    callers?: Array<{
      target: string
      relation_types: string[]
      reference_types: string[]
      resolved_by: string | null
      is_exact: boolean | null
    }>
    callees?: Array<{
      target: string
      relation_types: string[]
      reference_types: string[]
      resolved_by: string | null
      is_exact: boolean | null
    }>
  }
  rank_reasons?: string[]
  runtime_context?: {
    corroborated_apis?: string[]
    corroborated_stages?: string[]
    notes?: string[]
    confidence?: number
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
  }
  parameter_roles?: Array<{
    slot: string
    role: string
    inferred_type: string
    confidence: number
    evidence: string[]
  }>
  return_role?: {
    role: string
    inferred_type: string
    confidence: number
    evidence: string[]
  } | null
  state_roles?: Array<{
    state_key: string
    role: string
    confidence: number
    evidence: string[]
  }>
  struct_inference?: Array<{
    semantic_name: string
    rewrite_type_name?: string | null
    kind: 'request' | 'result' | 'context' | 'table' | 'session'
    confidence: number
    fields: Array<{
      name: string
      inferred_type: string
      source_slot?: string | null
    }>
    evidence: string[]
  }>
  semantic_evidence?: {
    string_hints?: string[]
    pseudocode_excerpt?: string
    parameter_roles?: Array<{
      slot: string
      role: string
      inferred_type: string
      confidence: number
      evidence: string[]
    }>
    return_role?: {
      role: string
      inferred_type: string
      confidence: number
      evidence: string[]
    } | null
    state_roles?: Array<{
      state_key: string
      role: string
      confidence: number
      evidence: string[]
    }>
    struct_inference?: Array<{
      semantic_name: string
      rewrite_type_name?: string | null
      kind: 'request' | 'result' | 'context' | 'table' | 'session'
      confidence: number
      fields: Array<{
        name: string
        inferred_type: string
        source_slot?: string | null
      }>
      evidence: string[]
    }>
    cfg_shape?: {
      node_count?: number
      edge_count?: number
      has_loop?: boolean
      has_branching?: boolean
      block_types?: string[]
      entry_block_type?: string | null
    }
  }
  name_resolution?: {
    rule_based_name?: string | null
    llm_suggested_name?: string | null
    llm_confidence?: number | null
    llm_why?: string | null
    required_assumptions?: string[]
    evidence_used?: string[]
    validated_name?: string | null
    resolution_source?: 'rule' | 'llm' | 'hybrid' | 'unresolved'
    unresolved_semantic_name?: boolean
  }
  explanation_resolution?: {
    summary?: string | null
    behavior?: string | null
    confidence?: number | null
    assumptions?: string[]
    evidence_used?: string[]
    rewrite_guidance?: string[]
    source?: 'llm' | 'unknown'
  }
}

interface ReconstructFunctionsData {
  functions: ReconstructedFunction[]
}

interface ModuleBucket {
  name: string
  functions: ReconstructedFunction[]
  roleHint: string | null
  focusMatches: Set<string>
  reviewResolution?: {
    refined_name?: string | null
    summary?: string | null
    role_hint?: string | null
    confidence?: number | null
    assumptions?: string[]
    evidence_used?: string[]
    rewrite_guidance?: string[]
    focus_areas?: string[]
    priority_functions?: string[]
    source?: 'llm' | 'unknown'
  }
  importHints: Set<string>
  stringHints: Set<string>
  runtimeApis: Set<string>
  runtimeStages: Set<string>
  runtimeNotes: Set<string>
}

interface StringsSummary {
  summary?: {
    cluster_counts?: Record<string, number>
    clusters?: Record<string, string[]>
    top_high_value?: Array<{
      string: string
      categories?: string[]
    }>
    context_windows?: Array<{
      start_offset: number
      end_offset: number
      score: number
      categories?: string[]
      strings?: Array<{
        offset: number
        string: string
        encoding: string
        categories?: string[]
      }>
    }>
  }
}

interface ImportsData {
  imports?: Record<string, string[]>
}

interface PEExportsData {
  exports?: Array<{
    ordinal: number
    address: number
    name: string | null
  }>
  forwarders?: Array<{
    ordinal: number
    address: number
    name: string | null
    forwarder: string
  }>
  total_exports?: number
  total_forwarders?: number
}

interface PackerDetectData {
  packed?: boolean
  confidence?: number
  detected?: string[]
}

interface BinaryProfile {
  binary_role: string
  original_filename: string | null
  export_count: number
  forwarder_count: number
  notable_exports: string[]
  packed: boolean
  packing_confidence: number
  analysis_priorities: string[]
  cli_profile?: ReconstructCliProfile | null
}

interface NativeBuildValidationResult {
  attempted: boolean
  status: 'passed' | 'failed' | 'skipped' | 'unavailable'
  compiler: string | null
  compiler_path: string | null
  command: string | null
  exit_code: number | null
  timed_out: boolean
  error: string | null
  stdout: string
  stderr: string
  log_path: string | null
  executable_path: string | null
}

interface HarnessValidationResult {
  attempted: boolean
  status: 'passed' | 'failed' | 'skipped' | 'unavailable'
  command: string | null
  exit_code: number | null
  timed_out: boolean
  error: string | null
  stdout: string
  stderr: string
  log_path: string | null
  matched_entries: number
  mismatched_entries: number
}

interface CodeReconstructExportDependencies {
  reconstructFunctionsHandler?: (args: ToolArgs) => Promise<WorkerResult>
  importsExtractHandler?: (args: ToolArgs) => Promise<WorkerResult>
  exportsExtractHandler?: (args: ToolArgs) => Promise<WorkerResult>
  packerDetectHandler?: (args: ToolArgs) => Promise<WorkerResult>
  stringsExtractHandler?: (args: ToolArgs) => Promise<WorkerResult>
  searchFunctions?: (
    sampleId: string,
    options: {
      apiQuery?: string
      stringQuery?: string
      limit?: number
      timeout?: number
    }
  ) => Promise<FunctionSearchResult>
  runtimeEvidenceLoader?: (
    sampleId: string,
    options?: { evidenceScope?: 'all' | 'latest' | 'session'; sessionTag?: string }
  ) => Promise<DynamicTraceSummary | null>
  nativeBuildValidator?: (args: {
    exportRoot: string
    srcRoot: string
    moduleRewriteFiles: string[]
    compilerPath?: string | null
    timeoutMs: number
  }) => Promise<NativeBuildValidationResult>
  harnessValidator?: (args: {
    executablePath: string
    cwd: string
    timeoutMs: number
  }) => Promise<HarnessValidationResult>
}

interface RoleAwareModuleOptions {
  targetRole: string | null
  focusAreas: string[]
  priorityOrder: string[]
  preferredModules: Set<string>
  stickyModules: Set<string>
  moduleOrder: Map<string, number>
}

function collectRoleFocusMatchesForModule(
  moduleName: string,
  roleOptions?: RoleAwareModuleOptions
): string[] {
  if (!roleOptions) {
    return []
  }

  const normalized = sanitizeModuleName(moduleName)
  const matches = new Set<string>()
  if (
    roleOptions.targetRole &&
    mapRoleSignalToModules(roleOptions.targetRole).some(
      (item) => sanitizeModuleName(item) === normalized
    )
  ) {
    matches.add(`target:${roleOptions.targetRole}`)
  }
  for (const focus of roleOptions.focusAreas) {
    if (mapRoleSignalToModules(focus).some((item) => sanitizeModuleName(item) === normalized)) {
      matches.add(`focus:${focus}`)
    }
  }
  for (const priority of roleOptions.priorityOrder) {
    if (
      mapRoleSignalToModules(priority).some((item) => sanitizeModuleName(item) === normalized)
    ) {
      matches.add(`priority:${priority}`)
    }
  }
  return Array.from(matches)
}

function inferRoleHintForModule(
  moduleName: string,
  roleOptions?: RoleAwareModuleOptions
): string | null {
  const normalized = sanitizeModuleName(moduleName)
  const focusMatches = collectRoleFocusMatchesForModule(normalized, roleOptions)
  if (focusMatches.length === 0) {
    return null
  }

  if (normalized === 'dll_lifecycle') {
    return 'Role-aware focus on DLL entry, attach/detach, and lifecycle side effects.'
  }
  if (normalized === 'com_activation') {
    return 'Role-aware focus on COM activation, registration, and class factory flow.'
  }
  if (normalized === 'export_dispatch') {
    return 'Role-aware focus on exported command dispatch and externally reachable entrypoints.'
  }
  if (normalized === 'callback_surface') {
    return 'Role-aware focus on callback, plugin, and host interaction surfaces.'
  }
  if (normalized === 'service_ops') {
    return 'Role-aware focus on service control, hook, and hosted callback paths.'
  }
  if (normalized === 'process_ops') {
    return 'Role-aware focus on runtime wrappers, process manipulation, and execution-transfer paths.'
  }

  return `Role-aware focus derived from ${focusMatches.join(', ')}.`
}

const BEHAVIOR_TO_MODULE: Record<string, string> = {
  process_injection: 'process_ops',
  process_spawn: 'process_ops',
  networking: 'network_ops',
  file_io: 'file_ops',
  registry: 'registry_ops',
  crypto: 'crypto_ops',
  anti_debug: 'anti_analysis',
  service_control: 'service_ops',
  dll_lifecycle: 'dll_lifecycle',
  export_dispatch: 'export_dispatch',
  com_activation: 'com_activation',
  callback_surface: 'callback_surface',
}

const IMPORT_TO_MODULE_HINT: Array<{ module: string; matcher: RegExp }> = [
  { module: 'network_ops', matcher: /^(ws2_32|wininet|winhttp|dnsapi)\.dll$/i },
  { module: 'registry_ops', matcher: /^advapi32\.dll$/i },
  { module: 'gui_ops', matcher: /^user32\.dll$/i },
  { module: 'file_ops', matcher: /^(kernel32|ntdll)\.dll$/i },
  { module: 'crypto_ops', matcher: /^(crypt32|bcrypt)\.dll$/i },
]

const API_TO_MODULE_HINT: Array<{ module: string; matcher: RegExp }> = [
  {
    module: 'process_ops',
    matcher:
      /\b(OpenProcess|CreateProcess|CreateRemoteThread|WriteProcessMemory|ReadProcessMemory|VirtualAllocEx|SetThreadContext|ResumeThread|NtWriteVirtualMemory|NtQueryInformationProcess)\b/i,
  },
  {
    module: 'network_ops',
    matcher:
      /\b(socket|connect|send|recv|WSAStartup|InternetOpen|InternetConnect|HttpOpenRequest|HttpSendRequest|WinHttp|URLDownloadToFile)\b/i,
  },
  {
    module: 'file_ops',
    matcher:
      /\b(CreateFile\w*|WriteFile\w*|ReadFile\w*|DeleteFile\w*|MoveFile\w*|CopyFile\w*|GetTempPath\w*|FindFirstFile\w*|FindNextFile\w*)\b/i,
  },
  {
    module: 'registry_ops',
    matcher: /\b(Reg(Open|Create|Set|Query|Delete)Key\w*|RegSetValue\w*|RegQueryValue\w*)\b/i,
  },
  {
    module: 'crypto_ops',
    matcher: /\b(CryptAcquire|CryptEncrypt|CryptDecrypt|BCrypt|RtlEncrypt|RtlDecrypt)\b/i,
  },
  {
    module: 'service_ops',
    matcher: /\b(OpenSCManager|CreateService|StartService|ControlService|DeleteService)\b/i,
  },
  {
    module: 'dll_lifecycle',
    matcher:
      /\b(DllMain|DisableThreadLibraryCalls|LdrRegisterDllNotification|DLL_(PROCESS|THREAD)_(ATTACH|DETACH)|ProcessAttach|ThreadAttach|ProcessDetach|ThreadDetach)\b/i,
  },
  {
    module: 'com_activation',
    matcher:
      /\b(DllGetClassObject|DllCanUnloadNow|CoCreateInstance|CLSIDFromProgID|ProgIDFromCLSID|IClassFactory|IUnknown|IDispatch)\b/i,
  },
  {
    module: 'export_dispatch',
    matcher:
      /\b(InvokeCommand|Dispatch(Command|Export)?|HandleCommand|ExecuteCommand|RunCommand|DispatchTable|ForwardedExport)\b/i,
  },
  {
    module: 'callback_surface',
    matcher:
      /\b(InitializePlugin|RegisterCallback|SetCallback|Notify|OnEvent|EventSink|HookProc|Observer|Callback)\b/i,
  },
  {
    module: 'anti_analysis',
    matcher:
      /\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQuerySystemInformation|NtQueryInformationProcess|OutputDebugString)\b/i,
  },
  {
    module: 'packer_analysis',
    matcher:
      /\b(section|entropy|packer|unpack|signature|overlay|pe header|goblin|iced-x86|disasm|recon)\b/i,
  },
]

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}

function toPosixRelative(fromRoot: string, absoluteFile: string): string {
  return path.relative(fromRoot, absoluteFile).split(path.sep).join('/')
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

function normalizeReadableHint(value: string, maxLength = 96): string {
  return value.replace(/\s+/g, ' ').trim().slice(0, maxLength)
}

function normalizeExplanationText(value: string | null | undefined, maxLength = 220): string | null {
  if (!value) {
    return null
  }
  const normalized = value.replace(/\s+/g, ' ').trim()
  return normalized.length > 0 ? normalized.slice(0, maxLength) : null
}

function escapeCString(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t')
}

function isReadableTextCandidate(value: string): boolean {
  const normalized = normalizeReadableHint(value, 160)
  if (normalized.length < 4) {
    return false
  }
  const printable = (normalized.match(/[ -~]/g) || []).length
  const ratio = printable / normalized.length
  return ratio >= 0.8 && /[A-Za-z]/.test(normalized)
}

function sanitizeModuleName(name: string): string {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '')
  return cleaned.length > 0 ? cleaned : 'core'
}

function dedupeLower(values: string[]): string[] {
  return Array.from(new Set(values.map((item) => item.trim()).filter((item) => item.length > 0)))
}

function addRoleModules(target: Set<string>, values: string[]) {
  for (const value of values) {
    target.add(sanitizeModuleName(value))
  }
}

function mapRoleSignalToModules(signal: string): string[] {
  const lowered = signal.toLowerCase()

  if (
    /class_factory|registration|com_activation|com_server|dllgetclassobject|dllcanunloadnow|inprocserver32|localserver32/.test(
      lowered
    )
  ) {
    return ['com_activation', 'export_dispatch', 'dll_lifecycle']
  }
  if (/dllmain|attach_detach|dll_entry|dllmain_and_export_surface|lifecycle/.test(lowered)) {
    return ['dll_lifecycle']
  }
  if (/export_dispatch|dispatch_model|review_exported_command_dispatch_surface/.test(lowered)) {
    return ['export_dispatch']
  }
  if (/host_callback|plugin|extension_contract|callback/.test(lowered)) {
    return ['callback_surface']
  }
  if (/service/.test(lowered)) {
    return ['service_ops', 'callback_surface']
  }
  if (/runtime_wrappers|process_manipulation/.test(lowered)) {
    return ['process_ops']
  }
  if (/network/.test(lowered)) {
    return ['network_ops']
  }
  return []
}

function buildRoleAwareModuleOptions(input: CodeReconstructExportInput): RoleAwareModuleOptions {
  const preferredModules = new Set<string>()
  const stickyModules = new Set<string>()
  const moduleOrder = new Map<string, number>()
  const targetRole = input.role_target?.trim() || null
  const focusAreas = dedupeLower(input.role_focus_areas || [])
  const priorityOrder = dedupeLower(input.role_priority_order || [])

  if (targetRole) {
    addRoleModules(preferredModules, mapRoleSignalToModules(targetRole))
  }
  for (const focus of focusAreas) {
    addRoleModules(preferredModules, mapRoleSignalToModules(focus))
    if (/class_factory|registration|com_activation|dllmain|lifecycle|host_callback|plugin|callback/.test(focus)) {
      addRoleModules(stickyModules, mapRoleSignalToModules(focus))
    }
  }
  for (const priority of priorityOrder) {
    addRoleModules(preferredModules, mapRoleSignalToModules(priority))
    if (
      /trace_com_activation|review_dllmain|identify_host_callbacks|extension_contract|exported_command_dispatch_surface/.test(
        priority
      )
    ) {
      addRoleModules(stickyModules, mapRoleSignalToModules(priority))
    }
  }

  if (targetRole === 'com_server') {
    addRoleModules(stickyModules, ['com_activation', 'dll_lifecycle', 'export_dispatch'])
  } else if (targetRole === 'export_dispatch_dll') {
    addRoleModules(stickyModules, ['export_dispatch', 'dll_lifecycle'])
  } else if (targetRole === 'hosted_plugin_or_service_dll') {
    addRoleModules(stickyModules, ['callback_surface', 'dll_lifecycle', 'service_ops'])
  } else if (targetRole === 'dll_library') {
    addRoleModules(stickyModules, ['dll_lifecycle'])
  }

  let order = 0
  for (const priority of priorityOrder) {
    for (const moduleName of mapRoleSignalToModules(priority)) {
      const normalized = sanitizeModuleName(moduleName)
      if (!moduleOrder.has(normalized)) {
        moduleOrder.set(normalized, order++)
      }
    }
  }
  for (const moduleName of preferredModules) {
    if (!moduleOrder.has(moduleName)) {
      moduleOrder.set(moduleName, order++)
    }
  }

  return {
    targetRole,
    focusAreas,
    priorityOrder,
    preferredModules,
    stickyModules,
    moduleOrder,
  }
}

function sanitizeSymbolForHeader(symbol: string): string {
  const cleaned = symbol.replace(/[^a-zA-Z0-9_]/g, '_')
  if (cleaned.length === 0) {
    return 'func_unknown'
  }
  if (/^[0-9]/.test(cleaned)) {
    return `func_${cleaned}`
  }
  return cleaned
}

async function attachFunctionExplanations(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  functions: ReconstructedFunction[],
  options?: { scope?: 'all' | 'latest' | 'session'; sessionTag?: string }
): Promise<SemanticFunctionExplanationIndex> {
  const explanationIndex = await loadSemanticFunctionExplanationIndex(
    workspaceManager,
    database,
    sampleId,
    {
      scope: options?.scope,
      sessionTag: options?.sessionTag,
    }
  )

  for (const func of functions) {
    const explanation = findSemanticFunctionExplanation(
      explanationIndex,
      func.address,
      func.function
    )
    if (!explanation) {
      continue
    }
    func.explanation_resolution = {
      summary: explanation.summary,
      behavior: explanation.behavior,
      confidence: explanation.confidence,
      assumptions: explanation.assumptions,
      evidence_used: explanation.evidence_used,
      rewrite_guidance: explanation.rewrite_guidance,
      source: 'llm',
    }
  }

  return explanationIndex
}

async function attachModuleReviews(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  modules: ModuleBucket[],
  options?: { scope?: 'all' | 'latest' | 'session'; sessionTag?: string }
): Promise<SemanticModuleReviewIndex> {
  const reviewIndex = await loadSemanticModuleReviewIndex(workspaceManager, database, sampleId, {
    scope: options?.scope,
    sessionTag: options?.sessionTag,
  })

  for (const module of modules) {
    const review = findSemanticModuleReview(reviewIndex, module.name)
    if (!review) {
      continue
    }
    module.reviewResolution = {
      refined_name: review.refined_name,
      summary: review.summary,
      role_hint: review.role_hint,
      confidence: review.confidence,
      assumptions: review.assumptions,
      evidence_used: review.evidence_used,
      rewrite_guidance: review.rewrite_guidance,
      focus_areas: review.focus_areas,
      priority_functions: review.priority_functions,
      source: 'llm',
    }
    if (review.role_hint && (!module.roleHint || module.roleHint.trim().length === 0)) {
      module.roleHint = review.role_hint || module.roleHint
    }
    for (const focus of review.focus_areas || []) {
      module.focusMatches.add(`review:${focus}`)
    }
  }

  return reviewIndex
}

function addHint(hints: Map<string, string[]>, module: string, value: string) {
  const normalized = normalizeReadableHint(value)
  if (!isReadableTextCandidate(normalized)) {
    return
  }
  const current = hints.get(module) || []
  if (!current.includes(normalized)) {
    current.push(normalized)
    hints.set(module, current)
  }
}

function inferModulesFromText(
  text: string,
  categories: string[] = [],
  roleOptions?: RoleAwareModuleOptions
): string[] {
  const modules = new Set<string>()
  const lowered = text.toLowerCase()

  if (categories.includes('network') || categories.includes('url')) {
    modules.add('network_ops')
  }
  if (categories.includes('registry')) {
    modules.add('registry_ops')
  }
  if (categories.includes('file_path')) {
    modules.add('file_ops')
  }
  if (categories.includes('command')) {
    modules.add('process_ops')
  }
  if (categories.includes('suspicious_api')) {
    modules.add('process_ops')
  }

  for (const mapper of API_TO_MODULE_HINT) {
    if (mapper.matcher.test(text)) {
      modules.add(mapper.module)
    }
  }

  if (/\b(akasha|auto recon|recon|telemetry|enumerate|analysis)\b/i.test(text)) {
    modules.add('packer_analysis')
  }
  if (/\b(pack(er)? detection|protection|entropy|section|signature)\b/i.test(lowered)) {
    modules.add('packer_analysis')
  }
  if (
    /\b(dllmain|disablethreadlibrarycalls|dll_process_attach|dll_thread_attach|processattach|threadattach|processdetach|threaddetach|attach\/detach)\b/i.test(
      lowered
    )
  ) {
    modules.add('dll_lifecycle')
  }
  if (
    /\b(dllgetclassobject|dllcanunloadnow|iclassfactory|cocreateinstance|clsid|progid|inprocserver32|localserver32|class factory)\b/i.test(
      lowered
    )
  ) {
    modules.add('com_activation')
  }
  if (
    /\b(export dispatch|dispatch table|invokecommand|handlecommand|executecommand|runcommand|forwarded export|ordinal export|export surface)\b/i.test(
      lowered
    )
  ) {
    modules.add('export_dispatch')
  }
  if (
    /\b(callback|event sink|observer|notify|plugin|addin|extension point|initializeplugin|registercallback|setcallback|hook proc)\b/i.test(
      lowered
    )
  ) {
    modules.add('callback_surface')
  }

  if (roleOptions) {
    if (roleOptions.preferredModules.has('dll_lifecycle') && /\b(dll|attach|detach|module handle|dllmain)\b/i.test(lowered)) {
      modules.add('dll_lifecycle')
    }
    if (roleOptions.preferredModules.has('com_activation') && /\b(class factory|registerserver|clsid|progid|activation)\b/i.test(lowered)) {
      modules.add('com_activation')
    }
    if (roleOptions.preferredModules.has('export_dispatch') && /\b(dispatch|export|command|invoke)\b/i.test(lowered)) {
      modules.add('export_dispatch')
    }
    if (roleOptions.preferredModules.has('callback_surface') && /\b(callback|plugin|notify|hook|host)\b/i.test(lowered)) {
      modules.add('callback_surface')
    }
  }

  return Array.from(modules)
}

function detectModuleByNameOrReasons(
  func: ReconstructedFunction,
  roleOptions?: RoleAwareModuleOptions
): string {
  const xrefApis = (func.xref_signals || []).map((item) => item.api).join(' ')
  const callContext = [
    ...(func.call_context?.callers || []),
    ...(func.call_context?.callees || []),
  ].join(' ')
  const corpus = [
    func.function,
    (func.rank_reasons || []).join(' '),
    func.semantic_summary || '',
    func.source_like_snippet,
    xrefApis,
    callContext,
  ].join(' ')
  const lowered = corpus.toLowerCase()

  if (
    /dllmain|disablethreadlibrarycalls|dll_process_attach|dll_thread_attach|processattach|threadattach|processdetach|threaddetach/.test(
      lowered
    )
  ) {
    return 'dll_lifecycle'
  }
  if (
    /dllgetclassobject|dllcanunloadnow|iclassfactory|cocreateinstance|clsid|progid|inprocserver32|localserver32/.test(
      lowered
    )
  ) {
    return 'com_activation'
  }
  if (
    /initializeplugin|registercallback|setcallback|event sink|notify|hook proc|observer|plugin host/.test(
      lowered
    )
  ) {
    return 'callback_surface'
  }
  if (/export dispatch|dispatch table|invokecommand|handlecommand|executecommand|runcommand|forwarded export/.test(lowered)) {
    return 'export_dispatch'
  }
  if (/socket|http|internet|dns|connect|send|recv/.test(lowered)) {
    return 'network_ops'
  }
  if (/process|createprocess|inject|thread|virtualalloc/.test(lowered)) {
    return 'process_ops'
  }
  if (/reg(set|open|create)|registry/.test(lowered)) {
    return 'registry_ops'
  }
  if (/file|writefile|readfile|deletefile/.test(lowered)) {
    return 'file_ops'
  }
  if (/crypt|bcrypt|hash|encrypt|decrypt/.test(lowered)) {
    return 'crypto_ops'
  }
  if (/service|scm|startservice/.test(lowered)) {
    return 'service_ops'
  }
  if (/debug|antidebug|ntqueryinformationprocess/.test(lowered)) {
    return 'anti_analysis'
  }
  if (/packer|entropy|section|signature|goblin|iced-x86|recon|analysis/.test(lowered)) {
    return 'packer_analysis'
  }

  if (roleOptions?.preferredModules.has('dll_lifecycle') && /\bdll\b/.test(lowered)) {
    return 'dll_lifecycle'
  }
  if (roleOptions?.preferredModules.has('com_activation') && /\b(class factory|registration|activation)\b/.test(lowered)) {
    return 'com_activation'
  }
  if (roleOptions?.preferredModules.has('export_dispatch') && /\b(dispatch|export|command)\b/.test(lowered)) {
    return 'export_dispatch'
  }
  if (roleOptions?.preferredModules.has('callback_surface') && /\b(callback|plugin|host)\b/.test(lowered)) {
    return 'callback_surface'
  }

  return 'core'
}

function computeImportModuleHints(importsData?: ImportsData): Map<string, string[]> {
  const hints = new Map<string, string[]>()
  if (!importsData?.imports) {
    return hints
  }

  for (const [dllName, apiNames] of Object.entries(importsData.imports)) {
    for (const mapper of IMPORT_TO_MODULE_HINT) {
      if (mapper.matcher.test(dllName)) {
        addHint(hints, mapper.module, dllName)
      }
    }

    for (const apiName of apiNames || []) {
      for (const mapper of API_TO_MODULE_HINT) {
        if (mapper.matcher.test(apiName)) {
          addHint(hints, mapper.module, `${dllName}!${apiName}`)
        }
      }
    }
  }

  return hints
}

function computeStringModuleHints(stringsData?: StringsSummary): Map<string, string[]> {
  const hints = new Map<string, string[]>()
  const topHighValue = stringsData?.summary?.top_high_value || []
  const contextWindows = stringsData?.summary?.context_windows || []

  for (const item of topHighValue) {
    for (const module of inferModulesFromText(item.string, item.categories || [])) {
      addHint(hints, module, item.string)
    }
  }

  for (const window of contextWindows) {
    const windowStrings = window.strings || []
    const mergedText = windowStrings.map((item) => item.string).join(' ')
    const categories = dedupe([
      ...(window.categories || []),
      ...windowStrings.flatMap((item) => item.categories || []),
    ])
    for (const module of inferModulesFromText(mergedText, categories)) {
      for (const hint of windowStrings.slice(0, 3).map((item) => item.string)) {
        addHint(hints, module, hint)
      }
    }
  }

  return hints
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.length > 0)))
}

interface FunctionStringSearchHint {
  modules: Set<string>
  strings: Set<string>
}

function scoreStringQuery(text: string, categories: string[]): number {
  let score = 0
  if (categories.includes('command')) {
    score += 3
  }
  if (categories.includes('suspicious_api')) {
    score += 3
  }
  if (categories.includes('network') || categories.includes('url')) {
    score += 2
  }
  if (/\b(pack(er)? detection|protection|entropy|akasha|auto recon|recon|WriteProcessMemory|SetThreadContext)\b/i.test(text)) {
    score += 5
  }
  score += Math.min(Math.floor(text.length / 16), 3)
  return score
}

function buildStringSearchQueries(stringsData?: StringsSummary): Array<{
  query: string
  modules: string[]
}> {
  if (!stringsData?.summary) {
    return []
  }

  const candidates: Array<{ query: string; modules: string[]; score: number }> = []
  const pushCandidate = (query: string, categories: string[] = []) => {
    const normalized = normalizeReadableHint(query)
    if (normalized.length < 8 || normalized.length > 96) {
      return
    }
    if (!isReadableTextCandidate(normalized)) {
      return
    }
    const modules = inferModulesFromText(normalized, categories)
    if (modules.length === 0) {
      return
    }
    candidates.push({
      query: normalized,
      modules,
      score: scoreStringQuery(normalized, categories),
    })
  }

  for (const item of stringsData.summary.top_high_value || []) {
    pushCandidate(item.string, item.categories || [])
  }

  for (const window of stringsData.summary.context_windows || []) {
    for (const item of (window.strings || []).slice(0, 4)) {
      pushCandidate(item.string, dedupe([...(item.categories || []), ...(window.categories || [])]))
    }
  }

  const seen = new Set<string>()
  return candidates
    .sort((a, b) => b.score - a.score || a.query.localeCompare(b.query))
    .filter((item) => {
      const key = item.query.toLowerCase()
      if (seen.has(key)) {
        return false
      }
      seen.add(key)
      return true
    })
    .slice(0, 6)
    .map((item) => ({
      query: item.query,
      modules: item.modules,
    }))
}

async function buildFunctionStringSearchHints(
  sampleId: string,
  stringsData: StringsSummary | undefined,
  searchFunctions:
    | ((
        sampleId: string,
        options: {
          apiQuery?: string
          stringQuery?: string
          limit?: number
          timeout?: number
        }
      ) => Promise<FunctionSearchResult>)
    | undefined,
  warnings: string[],
  enabled: boolean
): Promise<Map<string, FunctionStringSearchHint>> {
  const hints = new Map<string, FunctionStringSearchHint>()
  if (!enabled || !searchFunctions) {
    return hints
  }

  for (const query of buildStringSearchQueries(stringsData)) {
    try {
      const result = await searchFunctions(sampleId, {
        stringQuery: query.query,
        limit: 6,
        timeout: 45000,
      })
      for (const match of result.matches || []) {
        const entry = hints.get(match.address) || {
          modules: new Set<string>(),
          strings: new Set<string>(),
        }
        for (const module of query.modules) {
          entry.modules.add(module)
        }
        const linkedValue = normalizeReadableHint(
          match.string_matches?.find((item) => item.value)?.value || query.query
        )
        if (isReadableTextCandidate(linkedValue)) {
          entry.strings.add(linkedValue)
        }
        hints.set(match.address, entry)
      }
    } catch (error) {
      warnings.push(`string reverse lookup failed for "${query.query}": ${normalizeError(error)}`)
    }
  }

  return hints
}

function enrichFunctionsWithRuntimeContext(
  functions: ReconstructedFunction[],
  dynamicEvidence: DynamicTraceSummary | null | undefined
): ReconstructedFunction[] {
  if (!dynamicEvidence) {
    return functions
  }

  return functions.map((func) => {
    const runtimeContext = correlateFunctionWithRuntimeEvidence(
      {
        functionName: func.function,
        moduleName: detectModuleByNameOrReasons(func),
        behaviorTags: func.behavior_tags || [],
        xrefApis: (func.xref_signals || []).map((item) => item.api),
        rankReasons: func.rank_reasons || [],
        semanticSummary: `${func.semantic_summary || ''}\n${func.source_like_snippet}`,
        stringHints: (func.source_like_snippet || '')
          .split(/\r?\n/)
          .filter((line) => line.startsWith('// strings:'))
          .map((line) => line.replace(/^\/\/ strings:/, '').trim()),
        callTargets: [
          ...(func.call_context?.callers || []),
          ...(func.call_context?.callees || []),
        ],
      },
      dynamicEvidence
    )

    if (!runtimeContext) {
      return func
    }

    if (!func.runtime_context) {
      return { ...func, runtime_context: runtimeContext }
    }

    return {
      ...func,
      runtime_context: {
        corroborated_apis: dedupe([
          ...(func.runtime_context.corroborated_apis || []),
          ...(runtimeContext.corroborated_apis || []),
        ]).slice(0, 8),
        corroborated_stages: dedupe([
          ...(func.runtime_context.corroborated_stages || []),
          ...(runtimeContext.corroborated_stages || []),
        ]).slice(0, 6),
        notes: dedupe([...(func.runtime_context.notes || []), ...(runtimeContext.notes || [])]).slice(0, 6),
        confidence: Math.max(
          Number(func.runtime_context.confidence || 0),
          Number(runtimeContext.confidence || 0)
        ),
        executed: func.runtime_context.executed ?? runtimeContext.executed,
        evidence_sources: dedupe([
          ...(func.runtime_context.evidence_sources || []),
          ...(runtimeContext.evidence_sources || []),
        ]).slice(0, 6),
        source_names: dedupe([
          ...(func.runtime_context.source_names || []),
          ...(runtimeContext.source_names || []),
        ]).slice(0, 6),
        artifact_count: Math.max(
          Number(func.runtime_context.artifact_count || 0),
          Number(runtimeContext.artifact_count || 0)
        ),
        executed_artifact_count: Math.max(
          Number(func.runtime_context.executed_artifact_count || 0),
          Number(runtimeContext.executed_artifact_count || 0)
        ),
        matched_memory_regions: dedupe([
          ...(func.runtime_context.matched_memory_regions || []),
          ...(runtimeContext.matched_memory_regions || []),
        ]).slice(0, 6),
        matched_protections: dedupe([
          ...(func.runtime_context.matched_protections || []),
          ...(runtimeContext.matched_protections || []),
        ]).slice(0, 6),
        matched_address_ranges: dedupe([
          ...(func.runtime_context.matched_address_ranges || []),
          ...(runtimeContext.matched_address_ranges || []),
        ]).slice(0, 6),
        matched_region_owners: dedupe([
          ...(func.runtime_context.matched_region_owners || []),
          ...(runtimeContext.matched_region_owners || []),
        ]).slice(0, 6),
        matched_observed_modules: dedupe([
          ...(func.runtime_context.matched_observed_modules || []),
          ...(runtimeContext.matched_observed_modules || []),
        ]).slice(0, 6),
        matched_segment_names: dedupe([
          ...(func.runtime_context.matched_segment_names || []),
          ...(runtimeContext.matched_segment_names || []),
        ]).slice(0, 6),
        suggested_modules: dedupe([
          ...(func.runtime_context.suggested_modules || []),
          ...(runtimeContext.suggested_modules || []),
        ]).slice(0, 6),
        matched_by: dedupe([
          ...(func.runtime_context.matched_by || []),
          ...(runtimeContext.matched_by || []),
        ]).slice(0, 6),
      },
    }
  })
}

function chooseModuleForFunctionWithScoring(
  func: ReconstructedFunction,
  functionStringHints: Map<string, FunctionStringSearchHint>,
  roleOptions?: RoleAwareModuleOptions
): {
  moduleName: string
  importHints: string[]
  stringHints: string[]
} {
  const scores = new Map<string, number>()
  const importHints = new Map<string, Set<string>>()
  const stringHints = new Map<string, Set<string>>()
  const addScore = (
    module: string,
    score: number,
    hint?: string,
    hintTarget?: Map<string, Set<string>>
  ) => {
    scores.set(module, (scores.get(module) || 0) + score)
    if (hint && hintTarget) {
      const current = hintTarget.get(module) || new Set<string>()
      current.add(hint)
      hintTarget.set(module, current)
    }
  }

  for (const tag of func.behavior_tags || []) {
    const mapped = BEHAVIOR_TO_MODULE[tag]
    if (mapped) {
      addScore(mapped, 7, tag, stringHints)
    }
  }

  const textCorpus = [
    func.function,
    func.semantic_summary || '',
    func.source_like_snippet,
    ...(func.rank_reasons || []),
    ...((func.call_context?.callers || []).slice(0, 3)),
    ...((func.call_context?.callees || []).slice(0, 5)),
  ].join(' ')

  for (const module of inferModulesFromText(textCorpus, [], roleOptions)) {
    addScore(module, 3)
  }

  for (const signal of func.xref_signals || []) {
    for (const mapper of API_TO_MODULE_HINT) {
      if (mapper.matcher.test(signal.api)) {
        addScore(mapper.module, 5 * Math.max(signal.confidence, 0.4), signal.api, importHints)
      }
    }
  }

  for (const reason of func.rank_reasons || []) {
    const apiMatch = /^calls_sensitive_api:(.+)$/i.exec(reason)
    if (!apiMatch) {
      continue
    }
    for (const mapper of API_TO_MODULE_HINT) {
      if (mapper.matcher.test(apiMatch[1])) {
        addScore(mapper.module, 4, apiMatch[1], importHints)
      }
    }
  }

  const linkedStrings = functionStringHints.get(func.address)
  if (linkedStrings) {
    for (const module of linkedStrings.modules) {
      addScore(module, 8)
    }
    for (const module of linkedStrings.modules) {
      for (const hint of linkedStrings.strings) {
        addScore(module, 0, hint, stringHints)
      }
    }
  }

  const runtimeContext = func.runtime_context
  if (runtimeContext) {
    for (const api of runtimeContext.corroborated_apis || []) {
      for (const mapper of API_TO_MODULE_HINT) {
        if (mapper.matcher.test(api)) {
          addScore(mapper.module, 6, api, importHints)
        }
      }
    }
    for (const module of modulesSuggestedByRuntimeStages(runtimeContext.corroborated_stages || [])) {
      addScore(module, 5)
    }
    for (const module of runtimeContext.suggested_modules || []) {
      addScore(module, 6, `runtime:${module}`, stringHints)
    }
    for (const region of runtimeContext.matched_memory_regions || []) {
      for (const mapper of API_TO_MODULE_HINT) {
        if (mapper.matcher.test(region)) {
          addScore(mapper.module, 3, region, stringHints)
        }
      }
      if (/process|thread|dispatch|resolution|command/i.test(region)) {
        addScore('process_ops', 3, region, stringHints)
      }
      if (/registry|key/i.test(region)) {
        addScore('registry_ops', 3, region, stringHints)
      }
      if (/analysis|integrity|environment/i.test(region)) {
        addScore('anti_analysis', 3, region, stringHints)
      }
      if (/packer|entropy|section|layout/i.test(region)) {
        addScore('packer_analysis', 3, region, stringHints)
      }
      if (/network|socket|http|pipe|ipc/i.test(region)) {
        addScore('network_ops', 3, region, stringHints)
      }
    }
    for (const protection of runtimeContext.matched_protections || []) {
      if (/read_write|write|execute|rwx/i.test(protection)) {
        addScore('process_ops', 2, protection, stringHints)
      }
      if (/file|container/i.test(protection)) {
        addScore('file_ops', 1, protection, stringHints)
      }
      if (/image|r-x|read/i.test(protection) && roleOptions?.preferredModules.has('export_dispatch')) {
        addScore('export_dispatch', 2, protection, stringHints)
      }
      if (/image|r-x|read/i.test(protection) && roleOptions?.preferredModules.has('dll_lifecycle')) {
        addScore('dll_lifecycle', 2, protection, stringHints)
      }
    }
    for (const owner of [
      ...(runtimeContext.matched_region_owners || []),
      ...(runtimeContext.matched_observed_modules || []),
    ]) {
      if (/ole32|oleaut32|combase|rpcrt4/i.test(owner)) {
        addScore('com_activation', 4, owner, stringHints)
      }
      if (/plugin|host|extension|addin/i.test(owner)) {
        addScore('callback_surface', 3, owner, stringHints)
      }
      if (/\.dll$|\.ocx$|\.cpl$/i.test(owner) && roleOptions?.preferredModules.has('dll_lifecycle')) {
        addScore('dll_lifecycle', 2, owner, stringHints)
      }
    }
    for (const segment of runtimeContext.matched_segment_names || []) {
      if (/\.edata|export|dispatch/i.test(segment)) {
        addScore('export_dispatch', 4, segment, stringHints)
      }
      if (/\.tls|\.crt|init/i.test(segment)) {
        addScore('dll_lifecycle', 4, segment, stringHints)
      }
      if (/class|factory|\.idata/i.test(segment)) {
        addScore('com_activation', 3, segment, stringHints)
      }
      if (/callback|hook|event|notify/i.test(segment)) {
        addScore('callback_surface', 3, segment, stringHints)
      }
    }
  }

  if (roleOptions) {
    for (const module of roleOptions.preferredModules) {
      if (scores.has(module)) {
        addScore(module, roleOptions.stickyModules.has(module) ? 4 : 2)
      }
    }
    if (
      roleOptions.preferredModules.has('export_dispatch') &&
      /\b(export|dispatch|invoke|command)\b/i.test(textCorpus)
    ) {
      addScore('export_dispatch', 3)
    }
    if (
      roleOptions.preferredModules.has('com_activation') &&
      /\b(class factory|dllgetclassobject|registerserver|activation|clsid|progid)\b/i.test(textCorpus)
    ) {
      addScore('com_activation', 4)
    }
    if (
      roleOptions.preferredModules.has('dll_lifecycle') &&
      /\b(dllmain|attach|detach|disablethreadlibrarycalls|module handle)\b/i.test(textCorpus)
    ) {
      addScore('dll_lifecycle', 4)
    }
    if (
      roleOptions.preferredModules.has('callback_surface') &&
      /\b(callback|notify|plugin|hook|host)\b/i.test(textCorpus)
    ) {
      addScore('callback_surface', 3)
    }
  }

  const top = Array.from(scores.entries()).sort((a, b) => b[1] - a[1])[0]
  const moduleName =
    top && top[1] >= 3
      ? sanitizeModuleName(top[0])
      : sanitizeModuleName(detectModuleByNameOrReasons(func, roleOptions))

  return {
    moduleName,
    importHints: Array.from(importHints.get(moduleName) || []).slice(0, 8),
    stringHints: Array.from(stringHints.get(moduleName) || []).slice(0, 8),
  }
}

function regroupModules(
  functions: ReconstructedFunction[],
  moduleLimit: number,
  minModuleSize: number,
  importsData?: ImportsData,
  stringsData?: StringsSummary,
  functionStringHints?: Map<string, FunctionStringSearchHint>,
  roleOptions?: RoleAwareModuleOptions
): ModuleBucket[] {
  const moduleMap = new Map<string, ModuleBucket>()
  const importHints = computeImportModuleHints(importsData)
  const stringHints = computeStringModuleHints(stringsData)

  for (const func of functions) {
    const decision = chooseModuleForFunctionWithScoring(
      func,
      functionStringHints || new Map(),
      roleOptions
    )
    const moduleName = sanitizeModuleName(decision.moduleName)
    if (!moduleMap.has(moduleName)) {
      moduleMap.set(moduleName, {
        name: moduleName,
        functions: [],
        roleHint: inferRoleHintForModule(moduleName, roleOptions),
        focusMatches: new Set(collectRoleFocusMatchesForModule(moduleName, roleOptions)),
        importHints: new Set(importHints.get(moduleName) || []),
        stringHints: new Set((stringHints.get(moduleName) || []).slice(0, 8)),
        runtimeApis: new Set<string>(),
        runtimeStages: new Set<string>(),
        runtimeNotes: new Set<string>(),
      })
    }
    const bucket = moduleMap.get(moduleName)!
    bucket.functions.push(func)
    for (const hint of decision.importHints) {
      bucket.importHints.add(hint)
    }
    for (const hint of decision.stringHints) {
      bucket.stringHints.add(hint)
    }
    for (const api of func.runtime_context?.corroborated_apis || []) {
      bucket.runtimeApis.add(api)
    }
    for (const stage of func.runtime_context?.corroborated_stages || []) {
      bucket.runtimeStages.add(stage)
    }
    for (const note of func.runtime_context?.notes || []) {
      bucket.runtimeNotes.add(note)
    }
  }

  const modulePriority = (module: ModuleBucket) => {
    if (!roleOptions) {
      return 0
    }
    return roleOptions.moduleOrder.has(module.name)
      ? 100 - (roleOptions.moduleOrder.get(module.name) || 0)
      : 0
  }

  let modules = Array.from(moduleMap.values()).sort((a, b) => {
    const priorityDelta = modulePriority(b) - modulePriority(a)
    if (priorityDelta !== 0) {
      return priorityDelta
    }
    return b.functions.length - a.functions.length
  })

  if (modules.length > moduleLimit) {
    const sticky = roleOptions
      ? modules.filter((module) => roleOptions.stickyModules.has(module.name))
      : []
    const nonSticky = roleOptions
      ? modules.filter((module) => !roleOptions.stickyModules.has(module.name))
      : modules
    const keepCount = Math.max(1, moduleLimit - 1)
    const stickyKept = sticky.slice(0, Math.max(0, keepCount))
    const remainingSlots = Math.max(0, keepCount - stickyKept.length)
    const kept = [...stickyKept, ...nonSticky.slice(0, remainingSlots)]
    const keptNames = new Set(kept.map((module) => module.name))
    const overflow = modules.filter((module) => !keptNames.has(module.name))
    const mergedCore: ModuleBucket = {
      name: 'core',
      functions: overflow.flatMap((module) => module.functions),
      roleHint: inferRoleHintForModule('core', roleOptions),
      focusMatches: new Set(overflow.flatMap((module) => Array.from(module.focusMatches || []))),
      importHints: new Set(overflow.flatMap((module) => Array.from(module.importHints))),
      stringHints: new Set(overflow.flatMap((module) => Array.from(module.stringHints))),
      runtimeApis: new Set(overflow.flatMap((module) => Array.from(module.runtimeApis))),
      runtimeStages: new Set(overflow.flatMap((module) => Array.from(module.runtimeStages))),
      runtimeNotes: new Set(overflow.flatMap((module) => Array.from(module.runtimeNotes))),
    }
    modules = [...kept, mergedCore]
  }

  const small = modules.filter((module) => module.functions.length < minModuleSize)
  if (small.length > 0 && modules.length > 1) {
    const smallMergeable = roleOptions
      ? small.filter((module) => !roleOptions.stickyModules.has(module.name))
      : small
    const large = modules.filter(
      (module) =>
        module.functions.length >= minModuleSize ||
        Boolean(roleOptions?.stickyModules.has(module.name))
    )
    const core = large.find((module) => module.name === 'core') || {
      name: 'core',
      functions: [] as ReconstructedFunction[],
      roleHint: inferRoleHintForModule('core', roleOptions),
      focusMatches: new Set<string>(),
      importHints: new Set<string>(),
      stringHints: new Set<string>(),
      runtimeApis: new Set<string>(),
      runtimeStages: new Set<string>(),
      runtimeNotes: new Set<string>(),
    }
    for (const module of smallMergeable) {
      core.functions.push(...module.functions)
      for (const hint of module.importHints) {
        core.importHints.add(hint)
      }
      for (const hint of module.stringHints) {
        core.stringHints.add(hint)
      }
      for (const api of module.runtimeApis) {
        core.runtimeApis.add(api)
      }
      for (const stage of module.runtimeStages) {
        core.runtimeStages.add(stage)
      }
      for (const note of module.runtimeNotes) {
        core.runtimeNotes.add(note)
      }
      for (const match of module.focusMatches) {
        core.focusMatches.add(match)
      }
      if (!core.roleHint && module.roleHint) {
        core.roleHint = module.roleHint
      }
    }
    modules = large.filter(
      (module) =>
        module.functions.length >= minModuleSize ||
        Boolean(roleOptions?.stickyModules.has(module.name))
    )
    if (!modules.find((module) => module.name === 'core')) {
      modules.push(core)
    }
  }

  return modules.sort((a, b) => {
    const priorityDelta = modulePriority(b) - modulePriority(a)
    if (priorityDelta !== 0) {
      return priorityDelta
    }
    return b.functions.length - a.functions.length
  })
}

interface RewriteEntryNames {
  originalName: string
  semanticAlias: string
  implementationName: string
}

interface CliCommandHint {
  verb: string
  summary: string
}

interface CliHintModel {
  toolName: string
  helpBanner: string
  commands: CliCommandHint[]
}

interface SemanticCliDefaults {
  toolName: string
  helpBanner: string
}

const RESERVED_C_WRAPPER_NAMES = new Set([
  'main',
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
])

function deriveRewriteEntryNames(func: ReconstructedFunction, module: ModuleBucket): RewriteEntryNames {
  const originalBaseName = sanitizeSymbolForHeader(func.function)
  const originalName = RESERVED_C_WRAPPER_NAMES.has(originalBaseName.toLowerCase())
    ? `${sanitizeModuleName(module.name)}_${originalBaseName}_wrapper`
    : originalBaseName
  const semanticAlias = sanitizeSymbolForHeader(buildSemanticAlias(func, module))
  return {
    originalName,
    semanticAlias,
    implementationName: semanticAlias === originalName ? `${semanticAlias}_impl` : semanticAlias,
  }
}

function trimCommandToken(value: string): string {
  const cleaned = value.trim().replace(/^[`"'[\](){}]+|[`"'[\](){}]+$/g, '')
  return cleaned.replace(/[,:;]+$/g, '')
}

function looksLikeCommandToken(value: string): boolean {
  return (
    /^--?[a-z0-9][a-z0-9_-]*$/i.test(value) ||
    /^\/[a-z0-9][a-z0-9_-]*$/i.test(value) ||
    /^(scan|inject|dump|recon|detect|list|enum|query|read|write|copy|delete|spawn|resume|suspend|probe|unpack|help|version)$/i.test(
      value
    )
  )
}

function isCliNoiseCandidate(value: string): boolean {
  const lowered = value.toLowerCase()
  if (
    lowered.includes('internal error: entered unreachable code') ||
    lowered.includes('stack backtrace') ||
    lowered.includes('tokio 1.x context was found') ||
    lowered.includes('.cargo\\registry\\src\\') ||
    lowered.includes('/rustc/')
  ) {
    return true
  }
  const slashCount = (value.match(/[\\/]/g) || []).length
  return slashCount >= 6 && !/\b(akasha|packer|protector|scan|detect|inject|dump|cmd\.exe|writeprocessmemory)\b/i.test(value)
}

function normalizeCliFragment(value: string, maxLength = 160): string {
  return value
    .replace(/\0+/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/\s+\|\s+/g, ' | ')
    .trim()
    .slice(0, maxLength)
}

function stripFeatureNoise(value: string): string {
  return value
    .replace(/internal error: entered unreachable code/gi, ' ')
    .replace(/[A-Z]:\\Users\\[^\\\s]+\\\.cargo\\registry\\src\\[^\s|]+/gi, ' ')
    .replace(/\/rustc\/\S+/gi, ' ')
    .replace(/stack backtrace:?/gi, ' ')
}

function expandCliFragments(value: string): string[] {
  const coarseParts = value
    .split(/\r?\n|\|/g)
    .map((item) => stripFeatureNoise(item))
    .map((item) => normalizeCliFragment(item))
    .filter(Boolean)

  const fragments: string[] = []
  for (const part of coarseParts) {
    const optionExpanded = part
      .replace(/([,;])\s*(--?[a-z][a-z0-9_-]*|\/[a-z][a-z0-9_-]*)/gi, '$1\n$2')
      .split(/\n+/g)
      .map((item) => normalizeCliFragment(item))
      .filter(Boolean)
    fragments.push(...optionExpanded)
  }

  return dedupe(fragments).filter((value) => isReadableTextCandidate(value) && !isCliNoiseCandidate(value))
}

function scoreCliBannerCandidate(value: string, module?: ModuleBucket): number {
  const normalized = normalizeCliFragment(value, 160)
  let score = 0

  if (/\b(usage|help|packer(?:\/protector)? detection|protector detection)\b/i.test(normalized)) {
    score += 8
  }
  if (/\b(akasha|auto recon)\b/i.test(normalized)) {
    score += 4
  }
  if (/\b(scan|inject|dump|recon|detect|list|enum|query|spawn|resume|suspend|probe|unpack)\b/i.test(normalized)) {
    score += 4
  }
  if (normalized.length >= 12 && normalized.length <= 96) {
    score += 2
  } else if (normalized.length > 132) {
    score -= 1
  }
  if (/^[@A-Za-z0-9]/.test(normalized)) {
    score += 1
  }
  if (/^@/.test(normalized)) {
    score += 2
  }
  if (isCliNoiseCandidate(normalized)) {
    score -= 12
  }
  if (module) {
    const lowered = normalized.toLowerCase()
    if (module.name === 'packer_analysis') {
      if (/\b(packer|protector|section|entropy|entry point|upx|vmprotect|themida|aspack)\b/i.test(lowered)) {
        score += 6
      }
      if (/\b(writeprocessmemory|openprocess|createprocess|cmd\.exe)\b/i.test(lowered)) {
        score -= 4
      }
    }
    if (module.name === 'process_ops') {
      if (/\b(writeprocessmemory|readprocessmemory|openprocess|createprocess|setthreadcontext|resumethread|cmd\.exe)\b/i.test(lowered)) {
        score += 6
      }
      if (/\b(packer|protector|entry point|entropy)\b/i.test(lowered)) {
        score -= 3
      }
    }
  }

  return score
}

function scoreCliCommandForModule(command: CliCommandHint, module: ModuleBucket): number {
  const verb = command.verb.toLowerCase()
  let score = 0

  if (module.name === 'packer_analysis') {
    if (verb === 'scan' || verb === 'detect' || verb === 'probe' || verb === 'unpack') {
      score += 10
    }
    if (verb === 'inject' || verb === 'spawn') {
      score -= 3
    }
  }
  if (module.name === 'process_ops') {
    if (verb === 'inject' || verb === 'spawn' || verb === 'resume' || verb === 'suspend' || verb === 'query') {
      score += 10
    }
    if (verb === 'scan' || verb === 'detect') {
      score -= 2
    }
  }
  if (module.name === 'file_ops') {
    if (verb === 'dump' || verb === 'read' || verb === 'write' || verb === 'copy' || verb === 'delete') {
      score += 8
    }
  }
  if (module.name === 'registry_ops') {
    if (verb === 'query' || verb === 'read' || verb === 'write') {
      score += 8
    }
  }

  return score
}

function collectModuleFeatureSnapshot(module: ModuleBucket): RewriteFeatures {
  return module.functions.reduce<RewriteFeatures>(
    (acc, func) => {
      const current = collectRewriteFeatures(func, module)
      return {
        hasDynamicResolver: acc.hasDynamicResolver || current.hasDynamicResolver,
        hasProcessInjection: acc.hasProcessInjection || current.hasProcessInjection,
        hasProcessSpawn: acc.hasProcessSpawn || current.hasProcessSpawn,
        hasFileApiTable: acc.hasFileApiTable || current.hasFileApiTable,
        hasRegistryApiTable: acc.hasRegistryApiTable || current.hasRegistryApiTable,
        hasNtQueryInformationProcess:
          acc.hasNtQueryInformationProcess || current.hasNtQueryInformationProcess,
        hasNtQuerySystemInformation:
          acc.hasNtQuerySystemInformation || current.hasNtQuerySystemInformation,
        hasCodeIntegrity: acc.hasCodeIntegrity || current.hasCodeIntegrity,
        hasPackerScan: acc.hasPackerScan || current.hasPackerScan,
        hasTailJumpHints: acc.hasTailJumpHints || current.hasTailJumpHints,
        hasBodyReferenceHints: acc.hasBodyReferenceHints || current.hasBodyReferenceHints,
      }
    },
    {
      hasDynamicResolver: false,
      hasProcessInjection: false,
      hasProcessSpawn: false,
      hasFileApiTable: false,
      hasRegistryApiTable: false,
      hasNtQueryInformationProcess: false,
      hasNtQuerySystemInformation: false,
      hasCodeIntegrity: false,
      hasPackerScan: false,
      hasTailJumpHints: false,
      hasBodyReferenceHints: false,
    }
  )
}

function humanizeModuleName(value: string): string {
  return value
    .split(/[_\s]+/g)
    .filter(Boolean)
    .map((item) => item.charAt(0).toUpperCase() + item.slice(1))
    .join(' ')
}

function deriveSemanticCliDefaults(module: ModuleBucket): SemanticCliDefaults {
  const features = collectModuleFeatureSnapshot(module)

  if (module.name === 'dll_lifecycle') {
    return {
      toolName: 'DLL Lifecycle Surface',
      helpBanner: 'Review DllMain attach/detach behavior, library initialization, and module-lifetime side effects.',
    }
  }
  if (module.name === 'com_activation') {
    return {
      toolName: 'COM Activation Surface',
      helpBanner: 'Trace class-factory exports, registration paths, and COM activation routines.',
    }
  }
  if (module.name === 'export_dispatch') {
    return {
      toolName: 'Export Dispatch Surface',
      helpBanner: 'Recover exported command handlers, dispatch tables, and forwarded-export routing.',
    }
  }
  if (module.name === 'callback_surface') {
    return {
      toolName: 'Host Callback Surface',
      helpBanner: 'Recover host-driven callbacks, plugin entrypoints, and extension notification paths.',
    }
  }
  if (module.name === 'packer_analysis' || features.hasPackerScan) {
    return {
      toolName: 'Packer/Protector Detection',
      helpBanner: 'Detect packers, protectors, and suspicious PE layout signals.',
    }
  }
  if (module.name === 'process_ops' || features.hasProcessInjection || features.hasProcessSpawn) {
    return {
      toolName: 'Remote Process Operation Dispatcher',
      helpBanner: 'Prepare remote-process access, dynamic API resolution, and execution-transfer operations.',
    }
  }
  if (
    module.name === 'anti_analysis' ||
    features.hasNtQueryInformationProcess ||
    features.hasNtQuerySystemInformation ||
    features.hasCodeIntegrity
  ) {
    return {
      toolName: 'Environment And Code Integrity Probe',
      helpBanner: 'Probe code-integrity state and environment-sensitive process signals.',
    }
  }
  if (module.name === 'registry_ops' || features.hasRegistryApiTable) {
    return {
      toolName: 'Registry Capability Dispatcher',
      helpBanner: 'Resolve and exercise registry inspection and configuration paths.',
    }
  }
  if (module.name === 'file_ops' || features.hasFileApiTable) {
    return {
      toolName: 'File And Artifact Capability Dispatcher',
      helpBanner: 'Stage file, buffer, and artifact materialization capabilities.',
    }
  }

  return {
    toolName: humanizeModuleName(sanitizeModuleName(module.name)),
    helpBanner: 'Recovered command model from string and runtime evidence.',
  }
}

function shouldPreferSemanticBanner(candidate: string, module: ModuleBucket): boolean {
  const normalized = normalizeCliFragment(candidate, 160)
  if (normalized.length < 10 || isCliNoiseCandidate(normalized)) {
    return true
  }
  if (
    /\b(assertion failed|panic|entered unreachable code|stack backtrace)\b/i.test(normalized) ||
    /^[A-Za-z]:\\/.test(normalized) ||
    /^exe\\cmd\.exe/i.test(normalized)
  ) {
    return true
  }
  if (module.name === 'file_ops' && /\b(actual_state|tokio|shutdown)\b/i.test(normalized)) {
    return true
  }
  return false
}

function shouldPreferSemanticToolName(candidate: string, module: ModuleBucket): boolean {
  const normalized = candidate.trim().toLowerCase()
  if (normalized.length === 0 || normalized === sanitizeModuleName(module.name).toLowerCase()) {
    return true
  }
  if (module.name === 'process_ops') {
    return /\b(packer|protector)\b/i.test(normalized)
  }
  if (module.name === 'file_ops') {
    return /\b(packer|protector|process|tokio|assertion)\b/i.test(normalized)
  }
  if (module.name === 'anti_analysis') {
    return /\b(packer|protector|file)\b/i.test(normalized)
  }
  if (module.name === 'packer_analysis') {
    return false
  }
  return false
}

function collectDisplayStringHints(module: ModuleBucket, limit = 8): string[] {
  const curated = collectModuleStringHints(module).filter((value) => {
    if (
      /\b(assertion failed|panic|tokio|snapshot\.is_join_interested|curr\.is_join_interested|sharded_size\.is_power_of_two|actual_state ==|internal exception)\b/i.test(
        value
      )
    ) {
      return false
    }
    if (/^[0-9a-f]{6,}$/i.test(value) || /^00[0-9a-f]{4,}$/i.test(value)) {
      return false
    }
    if (/ret' or hex|base address for encoding/i.test(value)) {
      return false
    }
    if (module.name === 'process_ops' && /^exe\\cmd\.exe/i.test(value)) {
      return false
    }
    return true
  })
  if (curated.length > 0) {
    return curated.slice(0, limit)
  }

  const semanticDefaults = deriveSemanticCliDefaults(module)
  return [semanticDefaults.helpBanner].filter(Boolean).slice(0, limit)
}

function describeModuleRole(module: ModuleBucket): string {
  if (module.reviewResolution?.role_hint) {
    return module.reviewResolution.role_hint
  }
  if (module.roleHint) {
    return module.roleHint
  }
  const defaults = deriveSemanticCliDefaults(module)
  return defaults.helpBanner
}

function collectModuleCliModel(module: ModuleBucket): CliHintModel | null {
  const rawCorpus = dedupe([
    ...Array.from(module.stringHints),
    ...Array.from(module.runtimeNotes),
    ...module.functions.flatMap((func) => {
      const lines = (func.source_like_snippet || '').split(/\r?\n/)
      return lines
        .filter((line) => line.startsWith('// strings:') || line.startsWith('// summary='))
        .map((line) => line.replace(/^\/\/ (strings|summary)=/, '').trim())
    }),
  ])
  const corpus = dedupe(rawCorpus.flatMap((value) => expandCliFragments(value)))

  if (corpus.length === 0) {
    return null
  }

  const semanticDefaults = deriveSemanticCliDefaults(module)

  const bannerCandidate =
    corpus
      .slice()
      .sort((left, right) => scoreCliBannerCandidate(right, module) - scoreCliBannerCandidate(left, module))[0] ||
    corpus.find((value) => value.length >= 24) ||
    corpus[0]

  const toolNameMatch =
    /\b(akasha(?:\s+auto\s+recon)?|auto recon|packer(?:\/protector)? detection|protector detection)\b/i.exec(
      rawCorpus.join(' ')
    ) || /\b(akasha(?:\s+auto\s+recon)?|auto recon|packer(?:\/protector)? detection|protector detection)\b/i.exec(corpus.join(' '))
  const rawToolName = toolNameMatch ? toolNameMatch[1] : sanitizeModuleName(module.name)
  const commands: CliCommandHint[] = []
  const seen = new Set<string>()

  const pushCommand = (verb: string, summary: string) => {
    const normalizedVerb = trimCommandToken(verb)
    const normalizedSummary = normalizeReadableHint(summary, 120)
    if (normalizedVerb.length < 2 || normalizedSummary.length < 4) {
      return
    }
    const key = normalizedVerb.toLowerCase()
    if (seen.has(key)) {
      return
    }
    seen.add(key)
    commands.push({
      verb: normalizedVerb,
      summary: normalizedSummary,
    })
  }

  for (const item of corpus) {
    const usageMatch = /\busage:\s+(?:[^\s]+\s+)?([a-z][a-z0-9_-]{1,31})\b/i.exec(item)
    if (usageMatch) {
      pushCommand(usageMatch[1], item)
    }

    for (const token of item.match(/(?:^|\s)(--?[a-z0-9][a-z0-9_-]*|\/[a-z0-9][a-z0-9_-]*)\b/gi) || []) {
      pushCommand(token.trim(), item)
    }

    const parts = item.split(/\s+/).map((value) => trimCommandToken(value))
    const firstToken = parts[0] || ''
    if (looksLikeCommandToken(firstToken)) {
      pushCommand(firstToken, item)
      continue
    }

    const embedded = item.match(/\b(scan|inject|dump|recon|detect|list|enum|query|spawn|resume|suspend|probe|unpack)\b/i)
    if (embedded) {
      pushCommand(embedded[1], item)
    }
  }

  synthesizeModuleCliCommands(module, bannerCandidate, pushCommand)
  commands.sort((left, right) => scoreCliCommandForModule(right, module) - scoreCliCommandForModule(left, module))
  const finalToolName = shouldPreferSemanticToolName(rawToolName, module)
    ? semanticDefaults.toolName
    : rawToolName
  const finalHelpBanner = shouldPreferSemanticBanner(bannerCandidate, module)
    ? semanticDefaults.helpBanner
    : bannerCandidate

  return {
    toolName: normalizeReadableHint(finalToolName, 48),
    helpBanner: normalizeReadableHint(finalHelpBanner, 160),
    commands: commands.slice(0, 6),
  }
}

function buildExportCliModels(modules: ModuleBucket[]): Array<{
  module: string
  tool_name: string
  help_banner: string
  commands: CliCommandHint[]
}> {
  return modules
    .map((module) => {
      const cliModel = collectModuleCliModel(module)
      if (!cliModel) {
        return null
      }
      return {
        module: module.name,
        tool_name: cliModel.toolName,
        help_banner: cliModel.helpBanner,
        commands: cliModel.commands.slice(0, 8),
      }
    })
    .filter(
      (
        item
      ): item is {
        module: string
        tool_name: string
        help_banner: string
        commands: CliCommandHint[]
      } => Boolean(item)
    )
}

interface ReconstructCliProfile {
  tool_name: string
  help_banner: string
  command_count: number
  commands: CliCommandHint[]
}

function buildReconstructCliProfile(modules: ModuleBucket[]): ReconstructCliProfile | null {
  const seen = new Set<string>()
  const combinedCommands: CliCommandHint[] = []
  let toolName = ''
  let helpBanner = ''
  let bestToolScore = Number.NEGATIVE_INFINITY
  let bestBannerScore = Number.NEGATIVE_INFINITY

  for (const module of modules) {
    const cliModel = collectModuleCliModel(module)
    if (!cliModel) {
      continue
    }
    const hasDescriptiveToolName =
      cliModel.toolName.toLowerCase() !== sanitizeModuleName(module.name).toLowerCase()
    const selectionScore =
      scoreCliBannerCandidate(cliModel.helpBanner, module) +
      cliModel.commands.length * 6 +
      (hasDescriptiveToolName ? 4 : -4)
    if (toolName.length === 0 || selectionScore > bestToolScore) {
      toolName = cliModel.toolName
      bestToolScore = selectionScore
    }
    const bannerScore = scoreCliBannerCandidate(cliModel.helpBanner, module)
    if (helpBanner.length === 0 || bannerScore > bestBannerScore) {
      helpBanner = cliModel.helpBanner
      bestBannerScore = bannerScore
    }
    for (const command of cliModel.commands) {
      const key = command.verb.toLowerCase()
      if (seen.has(key)) {
        continue
      }
      seen.add(key)
      combinedCommands.push(command)
    }
  }

  if (helpBanner.length === 0 && combinedCommands.length === 0) {
    return null
  }

  return {
    tool_name: toolName || 'recovered_tool',
    help_banner: helpBanner || 'Recovered command model from string and runtime evidence.',
    command_count: combinedCommands.length,
    commands: combinedCommands.slice(0, 8),
  }
}

function deriveHarnessSeedText(func: ReconstructedFunction, module: ModuleBucket): string {
  const cliModel = collectModuleCliModel(module)
  const firstCommand = cliModel?.commands[0]
  if (firstCommand) {
    return normalizeReadableHint(`${cliModel?.toolName || sanitizeModuleName(module.name)} ${firstCommand.verb}`, 120)
  }

  const stringHint = Array.from(module.stringHints)
    .flatMap((value) => expandCliFragments(value))
    .find((value) => !isCliNoiseCandidate(value))
  if (stringHint) {
    return normalizeReadableHint(stringHint, 120)
  }

  const runtimeApi = (func.runtime_context?.corroborated_apis || [])[0]
  if (runtimeApi) {
    return normalizeReadableHint(runtimeApi, 64)
  }

  return normalizeReadableHint(func.semantic_summary || func.function, 120)
}

function buildRecoveredContractHints(func: ReconstructedFunction, module: ModuleBucket): string[] {
  const features = collectRewriteFeatures(func, module)
  const cliModel = collectModuleCliModel(module)
  const recoveredVerbs = (cliModel?.commands || [])
    .map((item) => item.verb)
    .filter(Boolean)
    .slice(0, 3)
  const hints = [
    'runtime_ctx stores recovered mutable state and the last observed semantic detail.',
    'outputs captures the stage and status exposed by the reconstructed skeleton.',
  ]
  if (features.hasProcessInjection || features.hasProcessSpawn) {
    hints.push('inputs.string_args[0] seeds remote_request.target_selector and target routing hints.')
    hints.push('inputs.string_args[1] seeds remote_request.launch_command_line when a recovered spawn path is present.')
    hints.push('inputs.pointer_args[0] is treated as remote_request.payload_view for execution-transfer scaffolding.')
    hints.push('inputs.handle_args[0..1] seed remote_request.process_handle and remote_request.thread_handle placeholders.')
  } else if (features.hasFileApiTable) {
    hints.push('inputs.string_args[0] is treated as a path or file-operation hint.')
  } else if (features.hasRegistryApiTable) {
    hints.push('inputs.string_args[1] is treated as a registry key or value hint.')
  } else if (features.hasPackerScan) {
    hints.push('inputs.pointer_args[0] is treated as a PE image or buffer view placeholder.')
    hints.push('outputs.scalar_result carries the recovered packer heuristic score.')
  } else if (recoveredVerbs.length > 0) {
    hints.push(
      `inputs.string_args[0] is treated as a recovered command verb or CLI token (${recoveredVerbs.join(', ')}).`
    )
  } else if (cliModel) {
    hints.push('inputs.string_args[0] is treated as a command verb or CLI token recovered from help text.')
  } else {
    hints.push('inputs.scalar_args[0] is treated as a generic mode or flag bitfield until stronger typing exists.')
  }
  return hints.slice(0, 4)
}

function deriveHarnessExpectedStage(func: ReconstructedFunction, module: ModuleBucket): string | null {
  const features = collectRewriteFeatures(func, module)
  if (features.hasProcessInjection || features.hasProcessSpawn) {
    return 'AK_STAGE_PREPARE_REMOTE_PROCESS_ACCESS'
  }
  if (
    features.hasNtQueryInformationProcess ||
    features.hasNtQuerySystemInformation ||
    features.hasCodeIntegrity
  ) {
    return 'AK_STAGE_ANTI_ANALYSIS_CHECKS'
  }
  if (features.hasRegistryApiTable) {
    return 'AK_STAGE_REGISTRY_OPERATIONS'
  }
  if (features.hasFileApiTable) {
    return 'AK_STAGE_FILE_OPERATIONS'
  }
  if (features.hasPackerScan) {
    return 'AK_STAGE_SCAN_PE_LAYOUT'
  }
  if (collectModuleCliModel(module)) {
    return 'AK_STAGE_COMMAND_MODEL_READY'
  }
  return null
}

function buildSupportHeaderContent(modules: ModuleBucket[]): string {
  const moduleNames = modules.map((module) => module.name).join(', ') || 'none'
  const lines: string[] = []
  lines.push('/* shared support types for semantic reconstruction skeleton */')
  lines.push('#pragma once')
  lines.push('')
  lines.push('#include <stddef.h>')
  lines.push('#include <stdint.h>')
  lines.push('')
  lines.push(`/* modules: ${moduleNames} */`)
  lines.push('enum {')
  lines.push('  AK_STATUS_OK = 0,')
  lines.push('  AK_STATUS_RESOLVE_FAILED = -1,')
  lines.push('  AK_STATUS_QUERY_FAILED = -2,')
  lines.push('  AK_STATUS_UNSUPPORTED = -3,')
  lines.push('};')
  lines.push('')
  lines.push('typedef struct AkCommandSpec {')
  lines.push('  const char *verb;')
  lines.push('  const char *summary;')
  lines.push('} AkCommandSpec;')
  lines.push('')
  lines.push('typedef struct AkCliModel {')
  lines.push('  const char *tool_name;')
  lines.push('  const char *help_banner;')
  lines.push('  AkCommandSpec commands[8];')
  lines.push('  int command_count;')
  lines.push('} AkCliModel;')
  lines.push('')
  lines.push('typedef struct AkResolvedApiTable {')
  lines.push('  int ready;')
  lines.push('  const char *role;')
  lines.push('  const char *apis[8];')
  lines.push('  int api_count;')
  lines.push('} AkResolvedApiTable;')
  lines.push('')
  lines.push('typedef struct AkProcessProbeResult {')
  lines.push('  int status;')
  lines.push('  int remote_process_checked;')
  lines.push('  int code_integrity_checked;')
  lines.push('  const char *last_observation;')
  lines.push('} AkProcessProbeResult;')
  lines.push('')
  lines.push('typedef struct AkPackerHeuristics {')
  lines.push('  int score;')
  lines.push('  const char *matched_signatures[8];')
  lines.push('  int matched_count;')
  lines.push('  const char *entrypoint_signal;')
  lines.push('} AkPackerHeuristics;')
  lines.push('')
  lines.push('typedef struct AkSemanticInputs {')
  lines.push('  uint64_t scalar_args[8];')
  lines.push('  const char *string_args[4];')
  lines.push('  void *pointer_args[8];')
  lines.push('  uintptr_t handle_args[4];')
  lines.push('} AkSemanticInputs;')
  lines.push('')
  lines.push('/* Semantic input helpers keep rewrite code readable while preserving a compact ABI. */')
  lines.push('#define AK_INPUT_PRIMARY_TEXT(inputs) ((inputs) != 0 ? (inputs)->string_args[0] : 0)')
  lines.push('#define AK_INPUT_SECONDARY_TEXT(inputs) ((inputs) != 0 ? (inputs)->string_args[1] : 0)')
  lines.push('#define AK_INPUT_PRIMARY_POINTER(inputs) ((inputs) != 0 ? (inputs)->pointer_args[0] : 0)')
  lines.push('#define AK_INPUT_PRIMARY_HANDLE(inputs) ((inputs) != 0 ? (inputs)->handle_args[0] : 0)')
  lines.push('#define AK_INPUT_SECONDARY_HANDLE(inputs) ((inputs) != 0 ? (inputs)->handle_args[1] : 0)')
  lines.push('#define AK_INPUT_PRIMARY_MODE(inputs) ((inputs) != 0 ? (inputs)->scalar_args[0] : 0)')
  lines.push('')
  lines.push('/* Stage labels are centralized so the rewrite reads like a named state machine. */')
  lines.push('#define AK_STAGE_COMMAND_MODEL_READY "command_model_ready"')
  lines.push('#define AK_STAGE_PREPARE_REMOTE_PROCESS_ACCESS "prepare_remote_process_access"')
  lines.push('#define AK_STAGE_ANTI_ANALYSIS_CHECKS "anti_analysis_checks"')
  lines.push('#define AK_STAGE_REGISTRY_OPERATIONS "registry_operations"')
  lines.push('#define AK_STAGE_FILE_OPERATIONS "file_operations"')
  lines.push('#define AK_STAGE_SCAN_PE_LAYOUT "scan_pe_layout"')
  lines.push('')
  lines.push('typedef struct AkSemanticOutputs {')
  lines.push('  int status_code;')
  lines.push('  uint64_t scalar_result;')
  lines.push('  const char *status_detail;')
  lines.push('  const char *observed_stage;')
  lines.push('} AkSemanticOutputs;')
  lines.push('')
  lines.push('typedef struct AkRemoteProcessRequest {')
  lines.push('  const char *target_selector;')
  lines.push('  const char *launch_command_line;')
  lines.push('  void *payload_view;')
  lines.push('  uintptr_t process_handle;')
  lines.push('  uintptr_t thread_handle;')
  lines.push('  uint64_t mode_flags;')
  lines.push('} AkRemoteProcessRequest;')
  lines.push('')
  lines.push('typedef struct AkExecutionTransferResult {')
  lines.push('  int status_code;')
  lines.push('  const char *stage_name;')
  lines.push('  const char *detail;')
  lines.push('  const char *transfer_mode;')
  lines.push('  uint64_t observed_value;')
  lines.push('} AkExecutionTransferResult;')
  lines.push('')
  lines.push('typedef struct AkProcessOperationSession {')
  lines.push('  AkRemoteProcessRequest remote_request;')
  lines.push('  AkExecutionTransferResult transfer_result;')
  lines.push('} AkProcessOperationSession;')
  lines.push('')
  lines.push('typedef struct AkCapabilityDispatchRequest {')
  lines.push('  const char *primary_hint;')
  lines.push('  const char *secondary_hint;')
  lines.push('  uint64_t mode_flags;')
  lines.push('} AkCapabilityDispatchRequest;')
  lines.push('')
  lines.push('typedef struct AkCapabilityDispatchResult {')
  lines.push('  int status_code;')
  lines.push('  const char *stage_name;')
  lines.push('  const char *detail;')
  lines.push('  uint64_t observed_value;')
  lines.push('} AkCapabilityDispatchResult;')
  lines.push('')
  lines.push('typedef struct AkCapabilityDispatchPlan {')
  lines.push('  AkCapabilityDispatchRequest request;')
  lines.push('  AkCapabilityDispatchResult result;')
  lines.push('} AkCapabilityDispatchPlan;')
  lines.push('')
  lines.push('typedef struct AkPackerScanRequest {')
  lines.push('  const char *command_hint;')
  lines.push('  void *image_view;')
  lines.push('  uint64_t mode_flags;')
  lines.push('} AkPackerScanRequest;')
  lines.push('')
  lines.push('typedef struct AkPackerScanResult {')
  lines.push('  int status_code;')
  lines.push('  const char *stage_name;')
  lines.push('  const char *detail;')
  lines.push('  uint64_t heuristic_score;')
  lines.push('} AkPackerScanResult;')
  lines.push('')
  lines.push('typedef struct AkPackerScanSession {')
  lines.push('  AkPackerScanRequest request;')
  lines.push('  AkPackerScanResult result;')
  lines.push('} AkPackerScanSession;')
  lines.push('')
  lines.push('static inline AkRemoteProcessRequest ak_build_remote_process_request(const AkSemanticInputs *inputs)')
  lines.push('{')
  lines.push('  AkRemoteProcessRequest request = {0};')
  lines.push('  request.target_selector = AK_INPUT_PRIMARY_TEXT(inputs);')
  lines.push('  request.launch_command_line = AK_INPUT_SECONDARY_TEXT(inputs) != 0 ? AK_INPUT_SECONDARY_TEXT(inputs) : AK_INPUT_PRIMARY_TEXT(inputs);')
  lines.push('  request.payload_view = AK_INPUT_PRIMARY_POINTER(inputs);')
  lines.push('  request.process_handle = AK_INPUT_PRIMARY_HANDLE(inputs);')
  lines.push('  request.thread_handle = AK_INPUT_SECONDARY_HANDLE(inputs);')
  lines.push('  request.mode_flags = AK_INPUT_PRIMARY_MODE(inputs);')
  lines.push('  return request;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkExecutionTransferResult ak_init_execution_transfer_result(void)')
  lines.push('{')
  lines.push('  AkExecutionTransferResult result = { AK_STATUS_UNSUPPORTED, 0, 0, 0, 0 };')
  lines.push('  return result;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkProcessOperationSession ak_start_process_session(const AkSemanticInputs *inputs)')
  lines.push('{')
  lines.push('  AkProcessOperationSession session = {0};')
  lines.push('  session.remote_request = ak_build_remote_process_request(inputs);')
  lines.push('  session.transfer_result = ak_init_execution_transfer_result();')
  lines.push('  return session;')
  lines.push('}')
  lines.push('')
  lines.push('static inline void ak_publish_process_result(AkSemanticOutputs *outputs, const AkExecutionTransferResult *result)')
  lines.push('{')
  lines.push('  if (outputs == 0 || result == 0) {')
  lines.push('    return;')
  lines.push('  }')
  lines.push('  outputs->status_code = result->status_code;')
  lines.push('  outputs->scalar_result = result->observed_value;')
  lines.push('  outputs->status_detail = result->detail;')
  lines.push('  outputs->observed_stage = result->stage_name;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkCapabilityDispatchRequest ak_build_capability_request(const AkSemanticInputs *inputs)')
  lines.push('{')
  lines.push('  AkCapabilityDispatchRequest request = {0};')
  lines.push('  request.primary_hint = AK_INPUT_PRIMARY_TEXT(inputs);')
  lines.push('  request.secondary_hint = AK_INPUT_SECONDARY_TEXT(inputs);')
  lines.push('  request.mode_flags = AK_INPUT_PRIMARY_MODE(inputs);')
  lines.push('  return request;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkCapabilityDispatchResult ak_init_capability_result(void)')
  lines.push('{')
  lines.push('  AkCapabilityDispatchResult result = { AK_STATUS_UNSUPPORTED, 0, 0, 0 };')
  lines.push('  return result;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkCapabilityDispatchPlan ak_start_capability_plan(const AkSemanticInputs *inputs)')
  lines.push('{')
  lines.push('  AkCapabilityDispatchPlan plan = {0};')
  lines.push('  plan.request = ak_build_capability_request(inputs);')
  lines.push('  plan.result = ak_init_capability_result();')
  lines.push('  return plan;')
  lines.push('}')
  lines.push('')
  lines.push('static inline void ak_publish_capability_result(AkSemanticOutputs *outputs, const AkCapabilityDispatchResult *result)')
  lines.push('{')
  lines.push('  if (outputs == 0 || result == 0) {')
  lines.push('    return;')
  lines.push('  }')
  lines.push('  outputs->status_code = result->status_code;')
  lines.push('  outputs->scalar_result = result->observed_value;')
  lines.push('  outputs->status_detail = result->detail;')
  lines.push('  outputs->observed_stage = result->stage_name;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkPackerScanRequest ak_build_packer_request(const AkSemanticInputs *inputs)')
  lines.push('{')
  lines.push('  AkPackerScanRequest request = {0};')
  lines.push('  request.command_hint = AK_INPUT_PRIMARY_TEXT(inputs);')
  lines.push('  request.image_view = AK_INPUT_PRIMARY_POINTER(inputs);')
  lines.push('  request.mode_flags = AK_INPUT_PRIMARY_MODE(inputs);')
  lines.push('  return request;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkPackerScanResult ak_init_packer_result(void)')
  lines.push('{')
  lines.push('  AkPackerScanResult result = { AK_STATUS_UNSUPPORTED, 0, 0, 0 };')
  lines.push('  return result;')
  lines.push('}')
  lines.push('')
  lines.push('static inline AkPackerScanSession ak_start_packer_session(const AkSemanticInputs *inputs)')
  lines.push('{')
  lines.push('  AkPackerScanSession session = {0};')
  lines.push('  session.request = ak_build_packer_request(inputs);')
  lines.push('  session.result = ak_init_packer_result();')
  lines.push('  return session;')
  lines.push('}')
  lines.push('')
  lines.push('static inline void ak_publish_packer_result(AkSemanticOutputs *outputs, const AkPackerScanResult *result)')
  lines.push('{')
  lines.push('  if (outputs == 0 || result == 0) {')
  lines.push('    return;')
  lines.push('  }')
  lines.push('  outputs->status_code = result->status_code;')
  lines.push('  outputs->scalar_result = result->heuristic_score;')
  lines.push('  outputs->status_detail = result->detail;')
  lines.push('  outputs->observed_stage = result->stage_name;')
  lines.push('}')
  lines.push('')
  lines.push('typedef struct AkRuntimeContext {')
  lines.push('  AkResolvedApiTable dynamic_apis;')
  lines.push('  AkResolvedApiTable file_apis;')
  lines.push('  AkResolvedApiTable registry_apis;')
  lines.push('  AkProcessProbeResult process_probe;')
  lines.push('  AkPackerHeuristics packer_heuristics;')
  lines.push('  AkCliModel cli;')
  lines.push('  int last_status;')
  lines.push('  const char *last_status_detail;')
  lines.push('} AkRuntimeContext;')
  lines.push('')
  return lines.join('\n') + '\n'
}

function buildInterfaceContent(module: ModuleBucket): string {
  const lines: string[] = []
  lines.push(`/* module: ${module.name} */`)
  if (module.runtimeApis.size > 0 || module.runtimeStages.size > 0) {
    lines.push(
      `/* runtime: apis=${Array.from(module.runtimeApis).slice(0, 6).join(', ') || 'none'} | stages=${Array.from(module.runtimeStages).slice(0, 4).join(', ') || 'none'} */`
    )
  }
  lines.push('#pragma once')
  lines.push('')
  lines.push('#include "reconstruct_support.h"')
  lines.push('')

  for (const func of module.functions) {
    const names = deriveRewriteEntryNames(func, module)
    lines.push(
      `int ${names.originalName}(void); /* ${func.address} confidence=${func.confidence.toFixed(2)} */`
    )
    lines.push(
      `int ${names.implementationName}(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs); /* semantic_alias=${names.semanticAlias} */`
    )
    lines.push(
      `/* contract: ${buildRecoveredContractHints(func, module).map((item) => normalizeReadableHint(item, 96)).join(' | ')} */`
    )
    lines.push('')
  }

  return lines.join('\n') + '\n'
}

function buildPseudocodeContent(module: ModuleBucket): string {
  const lines: string[] = []
  lines.push(`/* module: ${module.name} */`)
  if (module.runtimeApis.size > 0 || module.runtimeStages.size > 0) {
    lines.push(
      `/* runtime: apis=${Array.from(module.runtimeApis).slice(0, 6).join(', ') || 'none'} | stages=${Array.from(module.runtimeStages).slice(0, 4).join(', ') || 'none'} */`
    )
  }
  lines.push('')
  for (const func of module.functions) {
    lines.push(func.source_like_snippet)
    lines.push('')
  }
  return lines.join('\n').trimEnd() + '\n'
}

function summarizeXrefSignals(func: ReconstructedFunction): string {
  const signals = (func.xref_signals || [])
    .map((item) => `${item.api}:${item.provenance}`)
    .slice(0, 6)
  return signals.length > 0 ? signals.join(', ') : 'none'
}

function summarizeRelationshipEntries(
  entries:
    | Array<{
        target: string
        relation_types: string[]
        reference_types: string[]
        resolved_by: string | null
        is_exact: boolean | null
      }>
    | undefined
): string {
  const labels = (entries || [])
    .slice(0, 4)
    .map((entry) => {
      const details = [
        ...(entry.relation_types || []),
        ...(entry.reference_types || []),
        entry.resolved_by ? `resolved_by=${entry.resolved_by}` : '',
        entry.is_exact === false ? 'heuristic' : '',
      ].filter((item) => item.length > 0)
      return details.length > 0 ? `${entry.target} [${details.join('; ')}]` : entry.target
    })
  return labels.length > 0 ? labels.join(', ') : 'none'
}

function summarizeRewriteParameterRoles(func: ReconstructedFunction): string {
  const roles = func.parameter_roles || func.semantic_evidence?.parameter_roles || []
  if (roles.length === 0) {
    return 'none'
  }
  return roles
    .slice(0, 6)
    .map((item) => `${item.slot}=>${item.role}<${item.inferred_type}>`)
    .join('; ')
}

function summarizeRewriteReturnRole(func: ReconstructedFunction): string {
  const role = func.return_role || func.semantic_evidence?.return_role || null
  if (!role) {
    return 'none'
  }
  return `${role.role}<${role.inferred_type}>`
}

function summarizeRewriteStateRoles(func: ReconstructedFunction): string {
  const roles = func.state_roles || func.semantic_evidence?.state_roles || []
  if (roles.length === 0) {
    return 'none'
  }
  return roles
    .slice(0, 6)
    .map((item) => `${item.state_key}=>${item.role}`)
    .join('; ')
}

function summarizeRewriteStructInference(func: ReconstructedFunction): string {
  const structs = func.struct_inference || func.semantic_evidence?.struct_inference || []
  if (structs.length === 0) {
    return 'none'
  }
  return structs
    .slice(0, 4)
    .map((item) => `${item.semantic_name}${item.rewrite_type_name ? `=>${item.rewrite_type_name}` : ''}`)
    .join('; ')
}

interface RewriteFeatures {
  hasDynamicResolver: boolean
  hasProcessInjection: boolean
  hasProcessSpawn: boolean
  hasFileApiTable: boolean
  hasRegistryApiTable: boolean
  hasNtQueryInformationProcess: boolean
  hasNtQuerySystemInformation: boolean
  hasCodeIntegrity: boolean
  hasPackerScan: boolean
  hasTailJumpHints: boolean
  hasBodyReferenceHints: boolean
}

function collectRewriteFeatures(func: ReconstructedFunction, module: ModuleBucket): RewriteFeatures {
  const functionCorpus = [
    func.function,
    func.semantic_summary || '',
    func.source_like_snippet,
    (func.behavior_tags || []).join(' '),
    (func.rank_reasons || []).join(' '),
    (func.xref_signals || []).map((item) => `${item.api} ${item.provenance}`).join(' '),
    (func.call_context?.callers || []).join(' '),
    (func.call_context?.callees || []).join(' '),
    (func.call_relationships?.callers || [])
      .flatMap((item) => [item.target, ...(item.relation_types || []), ...(item.reference_types || [])])
      .join(' '),
    (func.call_relationships?.callees || [])
      .flatMap((item) => [item.target, ...(item.relation_types || []), ...(item.reference_types || [])])
      .join(' '),
  ]
    .join('\n')
    .replace(/\s+/g, ' ')
    .replace(/registry\\src/gi, ' ')
    .replace(/\.cargo\\registry/gi, ' ')
    .replace(/stack backtrace:?/gi, ' ')
    .replace(/internal error: entered unreachable code/gi, ' ')
    .toLowerCase()
  const moduleCorpus = [
    module.name,
    Array.from(module.stringHints)
      .map((value) => stripFeatureNoise(value))
      .filter((value) => !isCliNoiseCandidate(value))
      .join(' '),
    Array.from(module.importHints).join(' '),
  ]
    .join('\n')
    .replace(/\s+/g, ' ')
    .replace(/registry\\src/gi, ' ')
    .replace(/\.cargo\\registry/gi, ' ')
    .toLowerCase()
  const packerPattern =
    /\b(packer|protector|upx|vmprotect|themida|aspack|entry point in non-first section|goblin|iced-x86)\b/i
  const hasDynamicResolver = /\b(getprocaddress|loadlibrary|loadlibraryex)\b/i.test(functionCorpus)
  const hasProcessInjection =
    /\b(writeprocessmemory|setthreadcontext|resumethread|createremotethread|virtualallocex)\b/i.test(
      functionCorpus
    ) || (func.behavior_tags || []).includes('process_injection')
  const hasProcessSpawn =
    /\b(createprocessw|createprocessa|cmd\.exe|shellexecute|winexec)\b/i.test(functionCorpus) ||
    (func.behavior_tags || []).includes('process_spawn')
  const hasFileApiTable =
    /\b(createfile\w*|readfile\w*|writefile\w*|deletefile\w*|copyfile\w*|movefile\w*|findfirstfile\w*|findnextfile\w*|gettemppath\w*)\b/i.test(
      functionCorpus
    ) ||
    ((module.name === 'process_ops' || module.name === 'file_ops') &&
      /\b(createfile\w*|readfile\w*|writefile\w*|deletefile\w*|copyfile\w*|movefile\w*|findfirstfile\w*|findnextfile\w*|gettemppath\w*)\b/i.test(
        moduleCorpus
      ))
  const hasRegistryApiTable =
    /\b(reg(open|set|create|query|delete)key\w*|reg(set|query)value\w*|registry)\b/i.test(
      functionCorpus
    ) ||
    ((module.name === 'process_ops' || module.name === 'registry_ops') &&
      /\b(reg(open|set|create|query|delete)key\w*|reg(set|query)value\w*|registry)\b/i.test(
        moduleCorpus
      ))
  const hasNtQueryInformationProcess = /\bntqueryinformationprocess\b/i.test(functionCorpus)
  const hasNtQuerySystemInformation = /\bntquerysysteminformation\b/i.test(functionCorpus)
  const hasCodeIntegrity =
    /\b(code integrity|codeintegrity|test signing|kernel_code_integrity_status_raw)\b/i.test(
      functionCorpus
    )
  const allowModulePackerBias =
    module.name === 'packer_analysis' &&
    !hasProcessInjection &&
    !hasProcessSpawn &&
    !hasNtQueryInformationProcess &&
    !hasNtQuerySystemInformation &&
    !hasCodeIntegrity

  return {
    hasDynamicResolver,
    hasProcessInjection,
    hasProcessSpawn,
    hasFileApiTable,
    hasRegistryApiTable,
    hasNtQueryInformationProcess,
    hasNtQuerySystemInformation,
    hasCodeIntegrity,
    hasPackerScan: packerPattern.test(functionCorpus) || (allowModulePackerBias && packerPattern.test(moduleCorpus)),
    hasTailJumpHints:
      (func.call_relationships?.callers || []).some((item) =>
        (item.relation_types || []).some((relation) => relation.toLowerCase() === 'tail_jump_hint')
      ) ||
      (func.call_relationships?.callees || []).some((item) =>
        (item.relation_types || []).some((relation) => relation.toLowerCase() === 'tail_jump_hint')
      ),
    hasBodyReferenceHints:
      (func.call_relationships?.callers || []).some((item) =>
        (item.relation_types || []).some((relation) => relation.toLowerCase() === 'body_reference_hint')
      ) ||
      (func.call_relationships?.callees || []).some((item) =>
        (item.relation_types || []).some((relation) => relation.toLowerCase() === 'body_reference_hint')
      ),
  }
}

function synthesizeModuleCliCommands(
  module: ModuleBucket,
  bannerCandidate: string,
  pushCommand: (verb: string, summary: string) => void
) {
  const moduleFeatures = module.functions.map((func) => collectRewriteFeatures(func, module))
  const hasProcessInjection = moduleFeatures.some((item) => item.hasProcessInjection)
  const hasProcessSpawn = moduleFeatures.some((item) => item.hasProcessSpawn)
  const hasFileApiTable = moduleFeatures.some((item) => item.hasFileApiTable)
  const hasRegistryApiTable = moduleFeatures.some((item) => item.hasRegistryApiTable)
  const hasPackerScan = moduleFeatures.some((item) => item.hasPackerScan)
  const helpSummary = normalizeReadableHint(bannerCandidate, 120)

  if (hasPackerScan) {
    pushCommand('scan', helpSummary || 'Recovered PE layout and packer/protector scan pipeline.')
    pushCommand('detect', 'Recovered packer/protector detection flow driven by PE layout and signature hints.')
  }
  if (hasProcessInjection) {
    pushCommand('inject', 'Recovered remote-process memory and thread-context operation pipeline.')
  }
  if (hasProcessSpawn) {
    pushCommand('spawn', 'Recovered process creation and launch orchestration flow.')
  }
  if (hasFileApiTable) {
    pushCommand('dump', 'Recovered file capability table suggests dump or file materialization support.')
  }
  if (hasRegistryApiTable) {
    pushCommand(
      'query',
      'Recovered registry capability table suggests registry inspection or configuration lookup.'
    )
  }
}

function getValidatedSemanticName(func: ReconstructedFunction): string | null {
  const validatedName = func.name_resolution?.validated_name
  if (typeof validatedName === 'string' && validatedName.trim().length > 0) {
    return validatedName
  }
  const suggestedName = func.suggested_name
  if (typeof suggestedName === 'string' && suggestedName.trim().length > 0) {
    return suggestedName
  }
  return null
}

function buildSemanticAlias(func: ReconstructedFunction, module: ModuleBucket): string {
  const features = collectRewriteFeatures(func, module)
  const suffix = func.address.replace(/^0x/i, '').toLowerCase()
  const suggestedName = sanitizeSymbolForHeader(getValidatedSemanticName(func) || '')

  if (suggestedName && Number(func.rename_confidence || 0) >= 0.45) {
    return `${suggestedName}_${suffix}`
  }

  if (features.hasProcessInjection && (features.hasFileApiTable || features.hasRegistryApiTable)) {
    return `build_capability_dispatch_tables_${suffix}`
  }
  if (features.hasProcessInjection || features.hasProcessSpawn) {
    return `dispatch_process_operation_${suffix}`
  }
  if (features.hasFileApiTable || features.hasRegistryApiTable) {
    return `prepare_capability_tables_${suffix}`
  }
  if (features.hasNtQueryInformationProcess && features.hasCodeIntegrity) {
    return `probe_process_and_code_integrity_${suffix}`
  }
  if (features.hasNtQueryInformationProcess) {
    return `query_remote_process_snapshot_${suffix}`
  }
  if (features.hasNtQuerySystemInformation || features.hasCodeIntegrity) {
    return `query_code_integrity_state_${suffix}`
  }
  if (features.hasPackerScan) {
    return `scan_packer_signatures_${suffix}`
  }
  if (features.hasTailJumpHints) {
    return `tailcall_dispatch_thunk_${suffix}`
  }

  const summary = `${module.name} ${func.semantic_summary || ''}`.toLowerCase()
  if (summary.includes('dispatcher')) {
    return `dispatch_${sanitizeModuleName(module.name)}_${suffix}`
  }
  return `${sanitizeModuleName(module.name)}_${sanitizeSymbolForHeader(func.function)}_${suffix}`
}

function extractApiHint(value: string): string {
  const apiName = value.includes('!') ? value.split('!').pop() || value : value
  return normalizeReadableHint(apiName, 96)
}

function collectModuleApiHints(module: ModuleBucket): string[] {
  return dedupe(
    [
      ...Array.from(module.importHints).map((value) => extractApiHint(value)),
      ...Array.from(module.runtimeApis).map((value) => normalizeReadableHint(value, 96)),
      ...module.functions.flatMap((func) =>
        (func.xref_signals || []).map((item) => normalizeReadableHint(item.api, 96))
      ),
    ].filter((value) => isReadableTextCandidate(value))
  )
}

function collectModuleStringHints(module: ModuleBucket): string[] {
  return dedupe(
    Array.from(module.stringHints)
      .map((value) => normalizeReadableHint(stripFeatureNoise(value), 96))
      .filter((value) => isReadableTextCandidate(value) && !isCliNoiseCandidate(value))
  )
}

function selectMatchingHints(values: string[], matcher: RegExp, limit = 8): string[] {
  return values.filter((value) => matcher.test(value)).slice(0, limit)
}

function buildCStringTable(name: string, values: string[]): string[] {
  const hints = dedupe(values.map((value) => normalizeReadableHint(value, 96))).slice(0, 8)
  const lines: string[] = []
  lines.push(`static const int ${name}_COUNT = ${hints.length};`)
  lines.push(`static const char *${name}[] = {`)
  if (hints.length === 0) {
    lines.push('  0,')
  } else {
    for (const hint of hints) {
      lines.push(`  "${escapeCString(hint)}",`)
    }
  }
  lines.push('};')
  lines.push('')
  return lines
}

function buildModuleRewritePrelude(module: ModuleBucket): string[] {
  const moduleFeatures = module.functions.map((func) => collectRewriteFeatures(func, module))
  const needsResolvedApiTable = moduleFeatures.some(
    (item) => item.hasDynamicResolver || item.hasFileApiTable || item.hasRegistryApiTable
  )
  const needsProcessProbe = moduleFeatures.some(
    (item) =>
      item.hasProcessInjection ||
      item.hasProcessSpawn ||
      item.hasNtQueryInformationProcess ||
      item.hasNtQuerySystemInformation ||
      item.hasCodeIntegrity
  )
  const needsPackerHeuristics = moduleFeatures.some((item) => item.hasPackerScan)
  const apiHints = collectModuleApiHints(module)
  const stringHints = collectModuleStringHints(module)
  const combinedHints = dedupe([...apiHints, ...stringHints])
  const dynamicApiHints = selectMatchingHints(
    combinedHints,
    /\b(GetProcAddress|LoadLibrary\w*|GetModuleHandle\w*)\b/i
  )
  const fileApiHints = selectMatchingHints(
    combinedHints,
    /\b(CreateFile\w*|ReadFile\w*|WriteFile\w*|DeleteFile\w*|MoveFile\w*|CopyFile\w*|FindFirstFile\w*|FindNextFile\w*|GetTempPath\w*)\b/i
  )
  const registryApiHints = selectMatchingHints(
    combinedHints,
    /\b(Reg(Open|Create|Set|Query|Delete)Key\w*|RegSetValue\w*|RegQueryValue\w*)\b/i
  )
  const remoteProcessHints = selectMatchingHints(
    combinedHints,
    /\b(OpenProcess|ReadProcessMemory|WriteProcessMemory|SetThreadContext|ResumeThread|CreateProcess\w*|CreateRemoteThread|VirtualAllocEx|NtQueryInformationProcess|process_injection|process_spawn|cmd\.exe)\b/i
  )
  const codeIntegrityHints = selectMatchingHints(
    combinedHints,
    /\b(NtQuerySystemInformation|Kernel_Code_Integrity_Status_Raw|CODEINTEGRITY|test signing|code integrity)\b/i
  )
  const packerSignatureHints = selectMatchingHints(
    combinedHints,
    /\b(UPX|VMProtect|Themida|ASPack|Packer|Protector|goblin|iced-x86)\b/i
  )
  const packerEntrypointHints = selectMatchingHints(
    combinedHints,
    /\b(Entry point|section|entropy|overlay)\b/i
  )
  const cliModel = collectModuleCliModel(module)

  const lines: string[] = []

  if (needsResolvedApiTable || needsProcessProbe || needsPackerHeuristics || cliModel) {
    lines.push('/* Recovered module hints used to keep this rewrite self-contained and readable. */')
    if (needsResolvedApiTable || needsProcessProbe) {
      lines.push(...buildCStringTable('AK_DYNAMIC_API_HINTS', dynamicApiHints))
      lines.push(...buildCStringTable('AK_FILE_API_HINTS', fileApiHints))
      lines.push(...buildCStringTable('AK_REGISTRY_API_HINTS', registryApiHints))
      lines.push(...buildCStringTable('AK_REMOTE_PROCESS_HINTS', remoteProcessHints))
      lines.push(...buildCStringTable('AK_CODE_INTEGRITY_HINTS', codeIntegrityHints))
    }
    if (needsPackerHeuristics) {
      lines.push(...buildCStringTable('AK_PACKER_SIGNATURE_HINTS', packerSignatureHints))
      lines.push(...buildCStringTable('AK_PACKER_ENTRY_HINTS', packerEntrypointHints))
    }
    if (cliModel) {
      lines.push(`static const char *AK_TOOL_NAME = "${escapeCString(cliModel.toolName)}";`)
      lines.push(`static const char *AK_HELP_BANNER = "${escapeCString(cliModel.helpBanner)}";`)
      lines.push('')
      for (const [index, command] of cliModel.commands.entries()) {
        lines.push(
          `static const AkCommandSpec AK_COMMAND_${index} = { "${escapeCString(command.verb)}", "${escapeCString(command.summary)}" };`
        )
      }
      lines.push(`static const int AK_COMMAND_COUNT = ${cliModel.commands.length};`)
      lines.push('')
    }
    lines.push(
      'static int ak_copy_hint_table(const char *const *source, int source_count, const char **destination, int destination_capacity)'
    )
    lines.push('{')
    lines.push('  int copied = 0;')
    lines.push('  int index = 0;')
    lines.push('')
    lines.push('  if (destination == 0 || destination_capacity <= 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push('  for (index = 0; index < source_count && copied < destination_capacity; ++index) {')
    lines.push("    if (source[index] == 0 || source[index][0] == '\\0') {")
    lines.push('      continue;')
    lines.push('    }')
    lines.push('    destination[copied++] = source[index];')
    lines.push('  }')
    lines.push('')
    lines.push('  return copied;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static const char *ak_first_hint(const char *const *source, int source_count, const char *fallback_hint)'
    )
    lines.push('{')
    lines.push('  int index = 0;')
    lines.push('')
    lines.push('  for (index = 0; index < source_count; ++index) {')
    lines.push("    if (source[index] != 0 && source[index][0] != '\\0') {")
    lines.push('      return source[index];')
    lines.push('    }')
    lines.push('  }')
    lines.push('')
    lines.push('  return fallback_hint;')
    lines.push('}')
    lines.push('')
  }

  if (cliModel) {
    lines.push('static int ak_prepare_cli_model(AkCliModel *model)')
    lines.push('{')
    lines.push('  if (model == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push('  model->tool_name = AK_TOOL_NAME;')
    lines.push('  model->help_banner = AK_HELP_BANNER;')
    lines.push('  model->command_count = 0;')
    for (const [index] of cliModel.commands.entries()) {
      lines.push(`  if (model->command_count < 8) {`)
      lines.push(`    model->commands[model->command_count++] = AK_COMMAND_${index};`)
      lines.push('  }')
    }
    lines.push('')
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
  }

  if (needsResolvedApiTable) {
    lines.push('static int resolve_dynamic_api_table(AkResolvedApiTable *table)')
    lines.push('{')
    lines.push('  if (table == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push('  table->ready = 1;')
    lines.push('  table->role = "dynamic_loader";')
    lines.push(
      '  table->api_count = ak_copy_hint_table(AK_DYNAMIC_API_HINTS, AK_DYNAMIC_API_HINTS_COUNT, table->apis, 8);'
    )
    lines.push('  if (table->api_count == 0) {')
    lines.push('    table->apis[0] = "GetProcAddress";')
    lines.push('    table->api_count = 1;')
    lines.push('  }')
    lines.push('')
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push('static int resolve_file_api_table(AkResolvedApiTable *table)')
    lines.push('{')
    lines.push('  if (table == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push('  table->ready = 1;')
    lines.push('  table->role = "file_capabilities";')
    lines.push(
      '  table->api_count = ak_copy_hint_table(AK_FILE_API_HINTS, AK_FILE_API_HINTS_COUNT, table->apis, 8);'
    )
    lines.push('  if (table->api_count == 0) {')
    lines.push('    table->apis[0] = "CreateFileW";')
    lines.push('    table->api_count = 1;')
    lines.push('  }')
    lines.push('')
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push('static int resolve_registry_api_table(AkResolvedApiTable *table)')
    lines.push('{')
    lines.push('  if (table == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push('  table->ready = 1;')
    lines.push('  table->role = "registry_capabilities";')
    lines.push(
      '  table->api_count = ak_copy_hint_table(AK_REGISTRY_API_HINTS, AK_REGISTRY_API_HINTS_COUNT, table->apis, 8);'
    )
    lines.push('  if (table->api_count == 0) {')
    lines.push('    table->apis[0] = "RegOpenKeyExW";')
    lines.push('    table->api_count = 1;')
    lines.push('  }')
    lines.push('')
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static int ak_prepare_runtime_capabilities(AkRuntimeContext *runtime_ctx, int needs_dynamic_loader, int needs_file_capabilities, int needs_registry_capabilities)'
    )
    lines.push('{')
    lines.push('  if (runtime_ctx == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('  if (needs_dynamic_loader && !resolve_dynamic_api_table(&runtime_ctx->dynamic_apis)) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('  if (needs_file_capabilities && !resolve_file_api_table(&runtime_ctx->file_apis)) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('  if (needs_registry_capabilities && !resolve_registry_api_table(&runtime_ctx->registry_apis)) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static void ak_finalize_capability_plan(AkRuntimeContext *runtime_ctx, AkSemanticOutputs *outputs, AkCapabilityDispatchPlan *plan, int recovered_status, const char *stage_name)'
    )
    lines.push('{')
    lines.push('  if (runtime_ctx == 0 || plan == 0) {')
    lines.push('    return;')
    lines.push('  }')
    lines.push('  runtime_ctx->last_status = recovered_status;')
    lines.push('  plan->result.status_code = recovered_status;')
    lines.push('  plan->result.stage_name = stage_name;')
    lines.push('  plan->result.detail = runtime_ctx->last_status_detail;')
    lines.push('  plan->result.observed_value = (uint64_t)recovered_status;')
    lines.push('  ak_publish_capability_result(outputs, &plan->result);')
    lines.push('}')
    lines.push('')
    lines.push(
      'static const char *ak_select_capability_observation(const AkResolvedApiTable *file_apis, const AkResolvedApiTable *registry_apis)'
    )
    lines.push('{')
    lines.push('  if (registry_apis != 0 && registry_apis->ready && registry_apis->api_count > 0) {')
    lines.push('    return registry_apis->apis[0];')
    lines.push('  }')
    lines.push('  if (file_apis != 0 && file_apis->ready && file_apis->api_count > 0) {')
    lines.push('    return file_apis->apis[0];')
    lines.push('  }')
    lines.push('  return 0;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static int finalize_capability_dispatch(const AkResolvedApiTable *file_apis, const AkResolvedApiTable *registry_apis)'
    )
    lines.push('{')
    lines.push('  return ak_select_capability_observation(file_apis, registry_apis) != 0 ? AK_STATUS_OK : AK_STATUS_UNSUPPORTED;')
    lines.push('}')
    lines.push('')
  }

  if (needsProcessProbe) {
    lines.push('static int query_remote_process_snapshot(AkProcessProbeResult *probe)')
    lines.push('{')
    lines.push('  if (probe == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push('  probe->remote_process_checked = 1;')
    lines.push('  probe->status = AK_STATUS_OK;')
    lines.push(
      '  probe->last_observation = ak_first_hint(AK_REMOTE_PROCESS_HINTS, AK_REMOTE_PROCESS_HINTS_COUNT, "remote process capability observed");'
    )
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push('static int query_code_integrity_state(AkProcessProbeResult *probe)')
    lines.push('{')
    lines.push('  if (probe == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push('  probe->code_integrity_checked = 1;')
    lines.push('  probe->status = AK_STATUS_OK;')
    lines.push(
      '  probe->last_observation = ak_first_hint(AK_CODE_INTEGRITY_HINTS, AK_CODE_INTEGRITY_HINTS_COUNT, "code integrity state queried");'
    )
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static int dispatch_process_operation(AkProcessProbeResult *probe, const AkResolvedApiTable *file_apis, const AkResolvedApiTable *registry_apis)'
    )
    lines.push('{')
    lines.push('  const char *observation = 0;')
    lines.push('')
    lines.push('  if (probe == 0) {')
    lines.push('    return AK_STATUS_QUERY_FAILED;')
    lines.push('  }')
    lines.push('  if (file_apis != 0 && file_apis->ready && file_apis->api_count > 0) {')
    lines.push('    observation = file_apis->apis[0];')
    lines.push('  }')
    lines.push('  if (observation == 0 && registry_apis != 0 && registry_apis->ready && registry_apis->api_count > 0) {')
    lines.push('    observation = registry_apis->apis[0];')
    lines.push('  }')
    lines.push('  if (observation == 0) {')
    lines.push(
      '    observation = ak_first_hint(AK_REMOTE_PROCESS_HINTS, AK_REMOTE_PROCESS_HINTS_COUNT, "process capability dispatch");'
    )
    lines.push('  }')
    lines.push('')
    lines.push('  probe->status = AK_STATUS_OK;')
    lines.push('  probe->last_observation = observation;')
    lines.push('  return probe->status;')
    lines.push('}')
    lines.push('')
    lines.push('static int finalize_process_probe(const AkProcessProbeResult *probe)')
    lines.push('{')
    lines.push('  if (probe == 0) {')
    lines.push('    return AK_STATUS_QUERY_FAILED;')
    lines.push('  }')
    lines.push('  if (probe->status != 0) {')
    lines.push('    return probe->status;')
    lines.push('  }')
    lines.push('  if (probe->remote_process_checked || probe->code_integrity_checked) {')
    lines.push('    return AK_STATUS_OK;')
    lines.push('  }')
    lines.push('  return AK_STATUS_UNSUPPORTED;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static int ak_collect_process_context(AkRuntimeContext *runtime_ctx, int needs_remote_probe, int needs_code_integrity)'
    )
    lines.push('{')
    lines.push('  if (runtime_ctx == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('  if (needs_remote_probe && !query_remote_process_snapshot(&runtime_ctx->process_probe)) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('  if (needs_code_integrity && !query_code_integrity_state(&runtime_ctx->process_probe)) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static void ak_finalize_process_session(AkRuntimeContext *runtime_ctx, AkSemanticOutputs *outputs, AkProcessOperationSession *session, int recovered_status, const char *stage_name, const char *transfer_mode)'
    )
    lines.push('{')
    lines.push('  if (runtime_ctx == 0 || session == 0) {')
    lines.push('    return;')
    lines.push('  }')
    lines.push('  runtime_ctx->last_status = recovered_status;')
    lines.push('  if (runtime_ctx->process_probe.last_observation != 0) {')
    lines.push('    runtime_ctx->last_status_detail = runtime_ctx->process_probe.last_observation;')
    lines.push('  }')
    lines.push('  if (runtime_ctx->last_status_detail == 0 && transfer_mode != 0) {')
    lines.push('    runtime_ctx->last_status_detail = transfer_mode;')
    lines.push('  }')
    lines.push('  session->transfer_result.status_code = recovered_status;')
    lines.push('  session->transfer_result.stage_name = stage_name;')
    lines.push('  session->transfer_result.detail = runtime_ctx->last_status_detail;')
    lines.push('  session->transfer_result.transfer_mode = transfer_mode;')
    lines.push('  session->transfer_result.observed_value = (uint64_t)recovered_status;')
    lines.push('  ak_publish_process_result(outputs, &session->transfer_result);')
    lines.push('}')
    lines.push('')
  }

  if (needsPackerHeuristics) {
    lines.push('static int scan_packer_signatures(AkPackerHeuristics *heuristics)')
    lines.push('{')
    lines.push('  if (heuristics == 0) {')
    lines.push('    return 0;')
    lines.push('  }')
    lines.push('')
    lines.push(
      '  heuristics->matched_count = ak_copy_hint_table(AK_PACKER_SIGNATURE_HINTS, AK_PACKER_SIGNATURE_HINTS_COUNT, heuristics->matched_signatures, 8);'
    )
    lines.push(
      '  heuristics->entrypoint_signal = ak_first_hint(AK_PACKER_ENTRY_HINTS, AK_PACKER_ENTRY_HINTS_COUNT, "packer-like section layout");'
    )
    lines.push('  if (heuristics->matched_count == 0) {')
    lines.push('    heuristics->matched_signatures[0] = "generic_packer_signature";')
    lines.push('    heuristics->matched_count = 1;')
    lines.push('  }')
    lines.push('  heuristics->score = heuristics->matched_count * 10;')
    lines.push('  return 1;')
    lines.push('}')
    lines.push('')
    lines.push('static int finalize_packer_assessment(const AkPackerHeuristics *heuristics)')
    lines.push('{')
    lines.push('  if (heuristics == 0) {')
    lines.push('    return AK_STATUS_UNSUPPORTED;')
    lines.push('  }')
    lines.push('  return heuristics->score > 0 ? AK_STATUS_OK : AK_STATUS_UNSUPPORTED;')
    lines.push('}')
    lines.push('')
    lines.push(
      'static void ak_finalize_packer_session(AkRuntimeContext *runtime_ctx, AkSemanticOutputs *outputs, AkPackerScanSession *session, int recovered_status)'
    )
    lines.push('{')
    lines.push('  if (runtime_ctx == 0 || session == 0) {')
    lines.push('    return;')
    lines.push('  }')
    lines.push('  runtime_ctx->last_status = recovered_status;')
    lines.push('  runtime_ctx->last_status_detail = runtime_ctx->packer_heuristics.entrypoint_signal;')
    lines.push('  session->result.status_code = recovered_status;')
    lines.push('  session->result.stage_name = AK_STAGE_SCAN_PE_LAYOUT;')
    lines.push('  session->result.detail = runtime_ctx->packer_heuristics.entrypoint_signal;')
    lines.push('  session->result.heuristic_score = (uint64_t)runtime_ctx->packer_heuristics.score;')
    lines.push('  ak_publish_packer_result(outputs, &session->result);')
    lines.push('}')
    lines.push('')
  }

  return lines
}

function buildSemanticRewriteBody(func: ReconstructedFunction, module: ModuleBucket): string[] {
  const features = collectRewriteFeatures(func, module)
  const cliModel = collectModuleCliModel(module)
  const usesProcessRequestView =
    features.hasProcessInjection ||
    features.hasProcessSpawn ||
    features.hasNtQueryInformationProcess ||
    features.hasNtQuerySystemInformation ||
    features.hasCodeIntegrity
  const lines: string[] = []

  lines.push(`  /* semantic_alias: ${buildSemanticAlias(func, module)} */`)
  lines.push(
    `  /* semantic_parameters: ${buildRecoveredContractHints(func, module).join(' | ')} */`
  )
  lines.push('  if (runtime_ctx == 0) {')
  lines.push('    return AK_STATUS_QUERY_FAILED;')
  lines.push('  }')
  lines.push('  runtime_ctx->last_status = AK_STATUS_UNSUPPORTED;')
  lines.push('  runtime_ctx->last_status_detail = 0;')
  lines.push('  if (outputs != 0) {')
  lines.push('    outputs->status_code = AK_STATUS_UNSUPPORTED;')
  lines.push('    outputs->scalar_result = 0;')
  lines.push('    outputs->status_detail = 0;')
  lines.push('    outputs->observed_stage = 0;')
  lines.push('  }')
  lines.push('')

  if (cliModel) {
    lines.push('  if (!ak_prepare_cli_model(&runtime_ctx->cli)) {')
    lines.push('    return AK_STATUS_QUERY_FAILED;')
    lines.push('  }')
    lines.push('  runtime_ctx->last_status_detail = runtime_ctx->cli.help_banner;')
    lines.push('  if (outputs != 0 && outputs->observed_stage == 0) {')
    lines.push('    outputs->observed_stage = AK_STAGE_COMMAND_MODEL_READY;')
    lines.push('  }')
    lines.push('')
  }

  if (
    features.hasProcessInjection ||
    features.hasProcessSpawn ||
    features.hasFileApiTable ||
    features.hasRegistryApiTable ||
    features.hasNtQueryInformationProcess ||
    features.hasNtQuerySystemInformation ||
    features.hasCodeIntegrity
  ) {
    if (usesProcessRequestView) {
      lines.push('  AkProcessOperationSession process_session = ak_start_process_session(inputs);')
      lines.push('')
      lines.push('  if (process_session.remote_request.target_selector != 0) {')
      lines.push('    runtime_ctx->last_status_detail = process_session.remote_request.target_selector;')
      lines.push('  }')
      lines.push('  if (process_session.remote_request.launch_command_line != 0 && runtime_ctx->last_status_detail == 0) {')
      lines.push('    runtime_ctx->last_status_detail = process_session.remote_request.launch_command_line;')
      lines.push('  }')
      lines.push('  if (process_session.remote_request.payload_view != 0 && runtime_ctx->last_status_detail == 0) {')
      lines.push('    runtime_ctx->last_status_detail = "payload_view_available";')
      lines.push('  }')
    } else {
      lines.push('  AkCapabilityDispatchPlan capability_plan = ak_start_capability_plan(inputs);')
      lines.push('')
      lines.push('  if (capability_plan.request.primary_hint != 0) {')
      lines.push('    runtime_ctx->last_status_detail = capability_plan.request.primary_hint;')
      lines.push('  }')
    }
    lines.push('')

    if (features.hasDynamicResolver) {
      lines.push('  /* Resolve loader pointers before the capability dispatch touches higher-risk APIs. */')
      lines.push('')
    }

    if (features.hasDynamicResolver || features.hasFileApiTable || features.hasRegistryApiTable) {
      lines.push(
        `  if (!ak_prepare_runtime_capabilities(runtime_ctx, ${features.hasDynamicResolver ? 1 : 0}, ${features.hasFileApiTable ? 1 : 0}, ${features.hasRegistryApiTable ? 1 : 0})) {`
      )
      lines.push('    return AK_STATUS_RESOLVE_FAILED;')
      lines.push('  }')
      lines.push('')
    }
    if (
      features.hasNtQueryInformationProcess ||
      features.hasNtQuerySystemInformation ||
      features.hasCodeIntegrity
    ) {
      lines.push(
        `  if (!ak_collect_process_context(runtime_ctx, ${features.hasNtQueryInformationProcess ? 1 : 0}, ${features.hasNtQuerySystemInformation || features.hasCodeIntegrity ? 1 : 0})) {`
      )
      lines.push('    return AK_STATUS_QUERY_FAILED;')
      lines.push('  }')
      lines.push('')
    }
    if (features.hasProcessInjection || features.hasProcessSpawn) {
      lines.push('  recovered_status = dispatch_process_operation(')
      lines.push('    &runtime_ctx->process_probe,')
      lines.push(
        `    ${features.hasDynamicResolver || features.hasFileApiTable ? '&runtime_ctx->file_apis' : '0'},`
      )
      lines.push(`    ${features.hasRegistryApiTable ? '&runtime_ctx->registry_apis' : '0'}`)
      lines.push('  );')
    } else if (usesProcessRequestView) {
      lines.push('  recovered_status = finalize_process_probe(&runtime_ctx->process_probe);')
    } else {
      lines.push(
        `  recovered_status = finalize_capability_dispatch(${features.hasFileApiTable ? '&runtime_ctx->file_apis' : '0'}, ${features.hasRegistryApiTable ? '&runtime_ctx->registry_apis' : '0'});`
      )
      lines.push(
        `  const char *capability_observation = ak_select_capability_observation(${features.hasFileApiTable ? '&runtime_ctx->file_apis' : '0'}, ${features.hasRegistryApiTable ? '&runtime_ctx->registry_apis' : '0'});`
      )
      lines.push('  if (capability_observation != 0) {')
      lines.push('    runtime_ctx->last_status_detail = capability_observation;')
      lines.push('  }')
    }
    if (usesProcessRequestView) {
      if (features.hasProcessInjection || features.hasProcessSpawn) {
        lines.push(
          `  ak_finalize_process_session(runtime_ctx, outputs, &process_session, recovered_status, AK_STAGE_PREPARE_REMOTE_PROCESS_ACCESS, "${features.hasProcessInjection ? 'remote_memory_transfer' : 'process_spawn_transfer'}");`
        )
      } else {
        lines.push(
          '  ak_finalize_process_session(runtime_ctx, outputs, &process_session, recovered_status, AK_STAGE_ANTI_ANALYSIS_CHECKS, "process_probe");'
        )
      }
    } else {
      lines.push('  if (runtime_ctx->process_probe.last_observation != 0) {')
      lines.push('    runtime_ctx->last_status_detail = runtime_ctx->process_probe.last_observation;')
      lines.push('  }')
      if (features.hasRegistryApiTable) {
        lines.push(
          '  ak_finalize_capability_plan(runtime_ctx, outputs, &capability_plan, recovered_status, AK_STAGE_REGISTRY_OPERATIONS);'
        )
      } else {
        lines.push(
          '  ak_finalize_capability_plan(runtime_ctx, outputs, &capability_plan, recovered_status, AK_STAGE_FILE_OPERATIONS);'
        )
      }
    }
    return lines
  }

  if (features.hasPackerScan) {
    lines.push('  AkPackerScanSession packer_session = ak_start_packer_session(inputs);')
    lines.push('')
    lines.push('  if (packer_session.request.command_hint != 0) {')
    lines.push('    runtime_ctx->last_status_detail = packer_session.request.command_hint;')
    lines.push('  }')
    lines.push('')
    lines.push('  if (!scan_packer_signatures(&runtime_ctx->packer_heuristics)) {')
    lines.push('    return AK_STATUS_UNSUPPORTED;')
    lines.push('  }')
    lines.push('')
    lines.push('  recovered_status = finalize_packer_assessment(&runtime_ctx->packer_heuristics);')
    lines.push('  ak_finalize_packer_session(runtime_ctx, outputs, &packer_session, recovered_status);')
    return lines
  }

  lines.push('  recovered_status = AK_STATUS_UNSUPPORTED;')
  lines.push('  runtime_ctx->last_status = recovered_status;')
  lines.push('  if (outputs != 0) {')
  lines.push('    outputs->status_code = recovered_status;')
  lines.push('    outputs->scalar_result = 0;')
  lines.push('    outputs->status_detail = runtime_ctx->last_status_detail;')
  lines.push('  }')
  return lines
}

function buildRewriteSteps(func: ReconstructedFunction): string[] {
  const tags = new Set((func.behavior_tags || []).map((item) => item.toLowerCase()))
  const relationshipTypes = new Set(
    [
      ...(func.call_relationships?.callers || []).flatMap((item) => item.relation_types || []),
      ...(func.call_relationships?.callees || []).flatMap((item) => item.relation_types || []),
    ].map((item) => item.toLowerCase())
  )
  let steps: string[]
  if (tags.has('process_injection')) {
    steps = [
      'Locate or receive the remote process / thread objects required for execution takeover.',
      'Prepare the remote payload buffer or thread context update before writing to the target.',
      'Transfer bytes or register state into the remote process and validate the transition status.',
    ]
  } else if (tags.has('process_spawn')) {
    steps = [
      'Construct the child-process launch context and execution parameters.',
      'Spawn or resume the target process while preserving handles or inherited state.',
      'Validate process creation results and bubble failure information to the caller.',
    ]
  } else if (tags.has('networking')) {
    steps = [
      'Initialize the network client or session state used by this routine.',
      'Exchange request / response data with a remote endpoint or local relay.',
      'Parse the returned data and hand control back to the surrounding dispatcher.',
    ]
  } else if (tags.has('file_io')) {
    steps = [
      'Resolve the path or file handle needed for this operation.',
      'Read, write, or enumerate on-disk data while checking for short or failed operations.',
      'Return status information that influences later persistence or collection logic.',
    ]
  } else if (tags.has('anti_debug')) {
    steps = [
      'Probe the host for analysis or debugging indicators.',
      'Update an internal decision bitfield or branch guard based on the probe result.',
      'Short-circuit or harden later execution stages when the environment looks suspicious.',
    ]
  } else if (tags.has('crypto')) {
    steps = [
      'Prepare cryptographic state, keys, or buffers.',
      'Transform input data through an encode/decode or hash routine.',
      'Propagate the transformed material to downstream storage or transport logic.',
    ]
  } else if (tags.has('registry')) {
    steps = [
      'Resolve the registry hive / key path relevant to this routine.',
      'Create, query, or update registry values used as configuration or persistence state.',
      'Return a success code that influences later bootstrap or cleanup behavior.',
    ]
  } else if ((func.semantic_summary || '').toLowerCase().includes('entropy')) {
    steps = [
      'Inspect PE sections or buffers for compression / packing characteristics.',
      'Compare observed structure against known thresholds or signatures.',
      'Return the classification result to a higher-level analysis dispatcher.',
    ]
  } else {
    steps = [
      'Recover local state and identify the primary control inputs for this routine.',
      'Trace the major side effects that feed other modules or exported entrypoints.',
      'Confirm final branching and status propagation against decompiler / disassembly evidence.',
    ]
  }

  if (relationshipTypes.has('tail_jump_hint') || relationshipTypes.has('body_reference_hint')) {
    steps.push(
      'Validate recovered thunk or body-reference edges before finalizing names, parameters, and module boundaries.'
    )
  }

  return steps
}

function buildAnnotatedRewriteContent(module: ModuleBucket): string {
  const lines: string[] = []
  const orderedFunctions = orderModuleFunctionsForPresentation(module)
  const displayStringHints = collectDisplayStringHints(module)
  lines.push(`/* module: ${module.name} | annotated rewrite */`)
  lines.push(`#include "${sanitizeModuleName(module.name)}.interface.h"`)
  lines.push('')
  lines.push('/*')
  lines.push(` * Analyst summary:`)
  lines.push(` * - function_count: ${module.functions.length}`)
  lines.push(` * - recovered_role: ${describeModuleRole(module)}`)
  lines.push(` * - role_focus: ${Array.from(module.focusMatches).join(', ') || 'none'}`)
  if (module.reviewResolution?.refined_name) {
    lines.push(` * - module_review_name: ${module.reviewResolution.refined_name}`)
  }
  if (module.reviewResolution?.summary) {
    lines.push(
      ` * - module_review_summary: ${normalizeExplanationText(module.reviewResolution.summary) || 'none'}`
    )
  }
  if (typeof module.reviewResolution?.confidence === 'number') {
    lines.push(
      ` * - module_review_confidence: ${Number(module.reviewResolution.confidence).toFixed(2)}`
    )
  }
  lines.push(
    ` * - prioritized_functions: ${orderedFunctions
      .slice(0, 3)
      .map((func) => getValidatedSemanticName(func) || func.function)
      .join(', ') || 'none'}`
  )
  lines.push(
    ` * - import_hints: ${Array.from(module.importHints).slice(0, 8).join(', ') || 'none'}`
  )
  lines.push(` * - string_hints: ${displayStringHints.join(' | ') || 'none'}`)
  lines.push(
    ` * - runtime_apis: ${Array.from(module.runtimeApis).slice(0, 8).join(', ') || 'none'}`
  )
  lines.push(
    ` * - runtime_stages: ${Array.from(module.runtimeStages).slice(0, 6).join(', ') || 'none'}`
  )
  lines.push(
    ` * - runtime_notes: ${Array.from(module.runtimeNotes).slice(0, 4).join(' | ') || 'none'}`
  )
  if ((module.reviewResolution?.rewrite_guidance || []).length > 0) {
    lines.push(
      ` * - module_rewrite_guidance: ${(module.reviewResolution?.rewrite_guidance || []).join(' | ')}`
    )
  }
  lines.push(' * - This file is a human-readable rewrite scaffold, not original source.')
  lines.push(' */')
  lines.push('')
  lines.push(...buildModuleRewritePrelude(module))

  for (const func of orderedFunctions) {
    const names = deriveRewriteEntryNames(func, module)
    const validatedSemanticName = getValidatedSemanticName(func)
    lines.push(
      `int ${names.implementationName}(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs)`
    )
    lines.push('{')
    lines.push('  int recovered_status = AK_STATUS_UNSUPPORTED;')
    lines.push(`  /* original_symbol: ${func.function} @ ${func.address} */`)
    if (validatedSemanticName) {
      lines.push(
        `  /* suggested_name: ${validatedSemanticName} confidence=${Number(func.rename_confidence || 0).toFixed(2)} role=${func.suggested_role || 'unknown'} evidence=${(func.rename_evidence || []).join(', ') || 'none'} */`
      )
    }
    if (func.name_resolution) {
      lines.push(
        `  /* name_resolution: source=${func.name_resolution.resolution_source || 'unknown'} rule=${func.name_resolution.rule_based_name || 'none'} llm=${func.name_resolution.llm_suggested_name || 'none'} validated=${func.name_resolution.validated_name || 'none'} unresolved=${func.name_resolution.unresolved_semantic_name ? 'yes' : 'no'} */`
      )
      if (func.name_resolution.llm_why) {
        lines.push(`  /* llm_why: ${func.name_resolution.llm_why} */`)
      }
      if ((func.name_resolution.required_assumptions || []).length > 0) {
        lines.push(
          `  /* llm_assumptions: ${(func.name_resolution.required_assumptions || []).join(' || ')} */`
        )
      }
      if ((func.name_resolution.evidence_used || []).length > 0) {
        lines.push(
          `  /* llm_evidence: ${(func.name_resolution.evidence_used || []).join(' || ')} */`
        )
      }
    }
    if (func.explanation_resolution) {
      lines.push(
        `  /* explanation: behavior=${func.explanation_resolution.behavior || 'unknown'} confidence=${Number(func.explanation_resolution.confidence || 0).toFixed(2)} source=${func.explanation_resolution.source || 'unknown'} summary=${normalizeExplanationText(func.explanation_resolution.summary) || 'none'} */`
      )
      if ((func.explanation_resolution.assumptions || []).length > 0) {
        lines.push(
          `  /* explanation_assumptions: ${(func.explanation_resolution.assumptions || []).join(' || ')} */`
        )
      }
      if ((func.explanation_resolution.evidence_used || []).length > 0) {
        lines.push(
          `  /* explanation_evidence: ${(func.explanation_resolution.evidence_used || []).join(' || ')} */`
        )
      }
      if ((func.explanation_resolution.rewrite_guidance || []).length > 0) {
        lines.push(
          `  /* rewrite_guidance: ${(func.explanation_resolution.rewrite_guidance || []).join(' || ')} */`
        )
      }
    }
    lines.push(`  /* inferred_role: ${func.semantic_summary || 'semantic role still being refined'} */`)
    lines.push(
      `  /* evidence: confidence=${func.confidence.toFixed(2)} tags=${(func.behavior_tags || []).join(', ') || 'none'} xrefs=${summarizeXrefSignals(func)} */`
    )
    lines.push(
      `  /* call_context: callers=${func.call_context?.callers?.slice(0, 4).join(', ') || 'none'} callees=${func.call_context?.callees?.slice(0, 6).join(', ') || 'none'} */`
    )
    lines.push(
      `  /* relation_hints: callers=${summarizeRelationshipEntries(func.call_relationships?.callers)} callees=${summarizeRelationshipEntries(func.call_relationships?.callees)} */`
    )
    lines.push(`  /* parameter_roles: ${summarizeRewriteParameterRoles(func)} */`)
    lines.push(`  /* return_role: ${summarizeRewriteReturnRole(func)} */`)
    lines.push(`  /* state_roles: ${summarizeRewriteStateRoles(func)} */`)
    lines.push(`  /* struct_inference: ${summarizeRewriteStructInference(func)} */`)
    if (
      (func.runtime_context?.corroborated_apis || []).length > 0 ||
      (func.runtime_context?.corroborated_stages || []).length > 0 ||
      (func.runtime_context?.matched_memory_regions || []).length > 0 ||
      (func.runtime_context?.matched_protections || []).length > 0 ||
      (func.runtime_context?.matched_region_owners || []).length > 0 ||
      (func.runtime_context?.matched_observed_modules || []).length > 0 ||
      (func.runtime_context?.matched_segment_names || []).length > 0
    ) {
      lines.push(
        `  /* runtime_context: apis=${(func.runtime_context?.corroborated_apis || []).join(', ') || 'none'} stages=${(func.runtime_context?.corroborated_stages || []).join(', ') || 'none'} regions=${(func.runtime_context?.matched_memory_regions || []).join(', ') || 'none'} protections=${(func.runtime_context?.matched_protections || []).join(', ') || 'none'} owners=${(func.runtime_context?.matched_region_owners || []).join(', ') || 'none'} observed_modules=${(func.runtime_context?.matched_observed_modules || []).join(', ') || 'none'} segments=${(func.runtime_context?.matched_segment_names || []).join(', ') || 'none'} ranges=${(func.runtime_context?.matched_address_ranges || []).join(', ') || 'none'} modules=${(func.runtime_context?.suggested_modules || []).join(', ') || 'none'} confidence=${Number(func.runtime_context?.confidence || 0).toFixed(2)} executed=${func.runtime_context?.executed ? 'yes' : 'no'} sources=${(func.runtime_context?.evidence_sources || []).join(', ') || 'unknown'} names=${(func.runtime_context?.source_names || []).join(', ') || 'unknown'} matched_by=${(func.runtime_context?.matched_by || []).join(', ') || 'unknown'} artifacts=${func.runtime_context?.executed_artifact_count || 0}/${func.runtime_context?.artifact_count || 0} */`
      )
    }
    if ((func.runtime_context?.notes || []).length > 0) {
      lines.push(`  /* runtime_notes: ${(func.runtime_context?.notes || []).join(' || ')} */`)
    }
    lines.push(
      `  /* gaps: ${(func.gaps || []).join(', ') || 'none'} rank_reasons=${(func.rank_reasons || []).join(', ') || 'none'} */`
    )
    for (const [index, step] of buildRewriteSteps(func).entries()) {
      lines.push(`  /* step_${index + 1}: ${step} */`)
    }
    lines.push('  /* TODO: Confirm parameter contract, buffer ownership, and error propagation. */')
    lines.push('')
    lines.push(...buildSemanticRewriteBody(func, module))
    lines.push('')
    lines.push('  return recovered_status;')
    lines.push('}')
    lines.push('')
    lines.push(`int ${names.originalName}(void)`)
    lines.push('{')
    lines.push('  AkRuntimeContext runtime_ctx = {0};')
    lines.push('  AkSemanticInputs inputs = {0};')
    lines.push('  AkSemanticOutputs outputs = {0};')
    lines.push(`  return ${names.implementationName}(&runtime_ctx, &inputs, &outputs);`)
    lines.push('}')
    lines.push('')
  }

  return lines.join('\n').trimEnd() + '\n'
}

function buildHarnessContent(modules: ModuleBucket[]): string {
  const lines: string[] = []
  lines.push('/* semantic reconstruction harness */')
  lines.push('#include <stdio.h>')
  lines.push('#include <string.h>')
  lines.push('#include "reconstruct_support.h"')
  for (const module of modules) {
    lines.push(`#include "${sanitizeModuleName(module.name)}.interface.h"`)
  }
  lines.push('')
  lines.push('typedef struct AkHarnessEntry {')
  lines.push('  const char *module_name;')
  lines.push('  const char *original_symbol;')
  lines.push('  const char *seed_text;')
  lines.push('  const char *expected_stage;')
  lines.push(
    '  int (*semantic_entry)(AkRuntimeContext *runtime_ctx, const AkSemanticInputs *inputs, AkSemanticOutputs *outputs);'
  )
  lines.push('  int (*wrapper_entry)(void);')
  lines.push('} AkHarnessEntry;')
  lines.push('')
  lines.push('static int ak_stage_matches(const char *expected_stage, const char *observed_stage)')
  lines.push('{')
  lines.push('  if (expected_stage == 0 || expected_stage[0] == \'\\0\') {')
  lines.push('    return 1;')
  lines.push('  }')
  lines.push('  if (observed_stage == 0) {')
  lines.push('    return 0;')
  lines.push('  }')
  lines.push('  return strcmp(expected_stage, observed_stage) == 0;')
  lines.push('}')
  lines.push('')
  lines.push('static const AkHarnessEntry AK_HARNESS_ENTRIES[] = {')
  for (const module of modules) {
    for (const func of module.functions) {
      const names = deriveRewriteEntryNames(func, module)
      const expectedStage = deriveHarnessExpectedStage(func, module)
      lines.push(
        `  { "${escapeCString(module.name)}", "${escapeCString(func.function)}", "${escapeCString(deriveHarnessSeedText(func, module))}", ${expectedStage || '0'}, ${names.implementationName}, ${names.originalName} },`
      )
    }
  }
  lines.push('};')
  lines.push('')
  lines.push('int main(void)')
  lines.push('{')
  lines.push('  size_t index = 0;')
  lines.push('  size_t mismatch_count = 0;')
  lines.push('  for (index = 0; index < (sizeof(AK_HARNESS_ENTRIES) / sizeof(AK_HARNESS_ENTRIES[0])); ++index) {')
    lines.push('    AkRuntimeContext runtime_ctx = {0};')
    lines.push('    AkSemanticInputs inputs = {0};')
    lines.push('    AkSemanticOutputs outputs = {0};')
    lines.push('    inputs.string_args[0] = AK_HARNESS_ENTRIES[index].seed_text;')
    lines.push('    inputs.string_args[1] = AK_HARNESS_ENTRIES[index].seed_text;')
    lines.push('    inputs.scalar_args[0] = (uint64_t)index;')
    lines.push('    inputs.pointer_args[0] = (void *)(uintptr_t)(0x10000000u + ((unsigned int)index * 0x1000u));')
    lines.push('    inputs.handle_args[0] = (uintptr_t)(0x1000u + (unsigned int)index);')
    lines.push('    inputs.handle_args[1] = (uintptr_t)(0x2000u + (unsigned int)index);')
    lines.push('    int status = AK_HARNESS_ENTRIES[index].semantic_entry(&runtime_ctx, &inputs, &outputs);')
    lines.push('    int stage_match = ak_stage_matches(AK_HARNESS_ENTRIES[index].expected_stage, outputs.observed_stage);')
    lines.push('    if (!stage_match) {')
    lines.push('      ++mismatch_count;')
    lines.push('    }')
  lines.push(
    '    printf("[%s] %s => status=%d stage=%s expected=%s match=%s detail=%s\\n", AK_HARNESS_ENTRIES[index].module_name, AK_HARNESS_ENTRIES[index].original_symbol, status, outputs.observed_stage ? outputs.observed_stage : "none", AK_HARNESS_ENTRIES[index].expected_stage ? AK_HARNESS_ENTRIES[index].expected_stage : "none", stage_match ? "ok" : "mismatch", outputs.status_detail ? outputs.status_detail : "none");'
  )
  lines.push('  }')
  lines.push('  return mismatch_count == 0 ? 0 : 1;')
  lines.push('}')
  lines.push('')
  return lines.join('\n')
}

function buildCMakeContent(modules: ModuleBucket[]): string {
  const lines: string[] = []
  lines.push('cmake_minimum_required(VERSION 3.20)')
  lines.push('project(reconstruct_skeleton C)')
  lines.push('')
  lines.push('set(CMAKE_C_STANDARD 99)')
  lines.push('set(CMAKE_C_STANDARD_REQUIRED ON)')
  lines.push('')
  lines.push('add_executable(reconstruct_harness')
  lines.push('  src/reconstruct_harness.c')
  for (const module of modules) {
    lines.push(`  src/${sanitizeModuleName(module.name)}.rewrite.c`)
  }
  lines.push(')')
  lines.push('')
  lines.push('target_include_directories(reconstruct_harness PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)')
  lines.push('')
  return lines.join('\n')
}

async function sha256File(filePath: string): Promise<string> {
  const content = await fs.readFile(filePath)
  return createHash('sha256').update(content).digest('hex')
}

function scoreFunctionForDedup(func: ReconstructedFunction): number {
  return (
    func.confidence * 100 +
    (func.semantic_summary ? Math.min(func.semantic_summary.length, 120) / 10 : 0) +
    (func.source_like_snippet ? Math.min(func.source_like_snippet.length, 400) / 100 : 0) +
    (func.xref_signals?.length || 0) * 4 +
    (func.runtime_context?.corroborated_apis?.length || 0) * 3 +
    (func.runtime_context?.matched_memory_regions?.length || 0) * 2 -
    (func.gaps?.length || 0) * 3
  )
}

function scoreFunctionForRewritePresentation(func: ReconstructedFunction, module: ModuleBucket): number {
  const corpus = [
    func.function,
    func.semantic_summary || '',
    func.source_like_snippet || '',
    ...(func.behavior_tags || []),
    ...(func.rank_reasons || []),
    ...(func.runtime_context?.corroborated_stages || []),
    ...(func.runtime_context?.matched_memory_regions || []),
  ].join(' ')
  let score =
    func.confidence * 100 +
    (func.xref_signals?.length || 0) * 6 +
    (func.runtime_context?.corroborated_apis?.length || 0) * 5 +
    (func.runtime_context?.matched_memory_regions?.length || 0) * 4 +
    (func.parameter_roles?.length || 0) * 2 +
    (func.struct_inference?.length || 0) * 3

  if (func.name_resolution?.validated_name) {
    score += 10
  }
  if (func.explanation_resolution?.summary) {
    score += 8
  }

  const lowered = corpus.toLowerCase()
  if (module.name === 'com_activation' && /\b(dllgetclassobject|class factory|iclassfactory|cocreateinstance|inprocserver32)\b/.test(lowered)) {
    score += 30
  }
  if (module.name === 'dll_lifecycle' && /\b(dllmain|disablethreadlibrarycalls|attach|detach)\b/.test(lowered)) {
    score += 30
  }
  if (module.name === 'export_dispatch' && /\b(dispatch|invokecommand|handlecommand|runcommand|export)\b/.test(lowered)) {
    score += 24
  }
  if (module.name === 'callback_surface' && /\b(callback|plugin|notify|hook|host)\b/.test(lowered)) {
    score += 24
  }
  if (module.name === 'process_ops' && /\b(writeprocessmemory|openprocess|createprocess|setthreadcontext|resumethread)\b/.test(lowered)) {
    score += 20
  }
  if (module.name === 'packer_analysis' && /\b(packer|protector|entropy|section|signature|layout)\b/.test(lowered)) {
    score += 20
  }

  return score
}

function orderModuleFunctionsForPresentation(module: ModuleBucket): ReconstructedFunction[] {
  return [...module.functions].sort((left, right) => {
    const scoreDelta = scoreFunctionForRewritePresentation(right, module) - scoreFunctionForRewritePresentation(left, module)
    if (scoreDelta !== 0) {
      return scoreDelta
    }
    return left.address.localeCompare(right.address)
  })
}

function dedupeReconstructedFunctions(functions: ReconstructedFunction[]): ReconstructedFunction[] {
  const orderedKeys: string[] = []
  const byKey = new Map<string, ReconstructedFunction>()

  for (const func of functions) {
    const key = (func.address || func.function).toLowerCase()
    const existing = byKey.get(key)
    if (!existing) {
      orderedKeys.push(key)
      byKey.set(key, func)
      continue
    }

    if (scoreFunctionForDedup(func) > scoreFunctionForDedup(existing)) {
      byKey.set(key, func)
    }
  }

  return orderedKeys.map((key) => byKey.get(key)!).filter(Boolean)
}

function ensureNameResolution(func: ReconstructedFunction): ReconstructedFunction {
  const existing = func.name_resolution
  const validatedName = existing?.validated_name || func.suggested_name || null
  const ruleBasedName = existing?.rule_based_name || func.suggested_name || null
  const resolutionSource =
    existing?.resolution_source || (validatedName ? 'rule' : 'unresolved')

  return {
    ...func,
    name_resolution: {
      rule_based_name: ruleBasedName,
      llm_suggested_name: existing?.llm_suggested_name || null,
      llm_confidence:
        typeof existing?.llm_confidence === 'number' ? existing.llm_confidence : null,
      llm_why: existing?.llm_why || null,
      required_assumptions: existing?.required_assumptions || [],
      evidence_used: existing?.evidence_used || func.rename_evidence || [],
      validated_name: validatedName,
      resolution_source: resolutionSource,
      unresolved_semantic_name:
        typeof existing?.unresolved_semantic_name === 'boolean'
          ? existing.unresolved_semantic_name
          : !validatedName,
    },
  }
}

async function pathExists(filePath: string | null | undefined): Promise<boolean> {
  if (!filePath) {
    return false
  }
  try {
    await fs.access(filePath)
    return true
  } catch {
    return false
  }
}

function quoteCommand(command: string, args: string[]): string {
  return [command, ...args]
    .map((value) => {
      if (value.length === 0) {
        return '""'
      }
      return /[\s"]/u.test(value) ? `"${value.replace(/"/g, '\\"')}"` : value
    })
    .join(' ')
}

async function runCommandWithTimeout(
  command: string,
  args: string[],
  cwd: string,
  timeoutMs: number
): Promise<{
  command: string
  exitCode: number | null
  timedOut: boolean
  stdout: string
  stderr: string
  error: string | null
}> {
  return new Promise((resolve) => {
    const commandDisplay = quoteCommand(command, args)
    const effectiveTimeoutMs = Math.max(5000, timeoutMs)
    const child = spawn(command, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })

    let stdout = ''
    let stderr = ''
    let settled = false
    let timedOut = false

    const finish = (result: {
      command: string
      exitCode: number | null
      timedOut: boolean
      stdout: string
      stderr: string
      error: string | null
    }) => {
      if (settled) {
        return
      }
      settled = true
      clearTimeout(timer)
      resolve(result)
    }

    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
      finish({
        command: commandDisplay,
        exitCode: null,
        timedOut: true,
        stdout,
        stderr,
        error: `command timed out after ${effectiveTimeoutMs}ms`,
      })
    }, effectiveTimeoutMs)

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })

    child.on('error', (error: NodeJS.ErrnoException) => {
      finish({
        command: commandDisplay,
        exitCode: null,
        timedOut: false,
        stdout,
        stderr,
        error: error.message,
      })
    })

    child.on('close', (code) => {
      if (timedOut) {
        return
      }
      finish({
        command: commandDisplay,
        exitCode: code ?? null,
        timedOut: false,
        stdout,
        stderr,
        error: code === 0 ? null : `command failed with exit code ${code ?? 'unknown'}`,
      })
    })
  })
}

async function resolveCommandFromPath(commandNames: string[]): Promise<string | null> {
  const locator = process.platform === 'win32' ? 'where.exe' : 'which'
  for (const commandName of commandNames) {
    const result = await runCommandWithTimeout(locator, [commandName], getPackageRoot(), 5000)
    if (result.exitCode !== 0) {
      continue
    }
    const firstLine = result.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line.length > 0)
    if (firstLine && (await pathExists(firstLine))) {
      return firstLine
    }
  }
  return null
}

async function collectWindowsClangCandidates(root: string): Promise<string[]> {
  const candidates: string[] = []
  try {
    const level1 = await fs.readdir(root, { withFileTypes: true })
    for (const entry of level1) {
      if (!entry.isDirectory() || !entry.name.toLowerCase().includes('clang+llvm')) {
        continue
      }
      const level1Path = path.join(root, entry.name)
      candidates.push(path.join(level1Path, 'bin', 'clang.exe'))
      try {
        const level2 = await fs.readdir(level1Path, { withFileTypes: true })
        for (const nested of level2) {
          if (!nested.isDirectory() || !nested.name.toLowerCase().includes('clang+llvm')) {
            continue
          }
          const level2Path = path.join(level1Path, nested.name)
          candidates.push(path.join(level2Path, 'bin', 'clang.exe'))
          try {
            const level3 = await fs.readdir(level2Path, { withFileTypes: true })
            for (const deeper of level3) {
              if (!deeper.isDirectory() || !deeper.name.toLowerCase().includes('clang+llvm')) {
                continue
              }
              candidates.push(path.join(level2Path, deeper.name, 'bin', 'clang.exe'))
            }
          } catch {
            // best-effort candidate discovery
          }
        }
      } catch {
        // best-effort candidate discovery
      }
    }
  } catch {
    // root does not exist or is unreadable
  }
  return candidates
}

async function resolveClangCompilerPath(explicitCompilerPath?: string | null): Promise<string | null> {
  const candidates: string[] = []
  if (explicitCompilerPath) {
    candidates.push(explicitCompilerPath)
  }
  if (process.env.CLANG_PATH) {
    candidates.push(process.env.CLANG_PATH)
  }

  const pathLookup = await resolveCommandFromPath(['clang.exe', 'clang'])
  if (pathLookup) {
    candidates.push(pathLookup)
  }

  const pathEntries = (process.env.PATH || '')
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
  for (const entry of pathEntries) {
    candidates.push(path.join(entry, process.platform === 'win32' ? 'clang.exe' : 'clang'))
  }

  candidates.push(
    'C:\\Program Files\\LLVM\\bin\\clang.exe',
    'E:\\clang+llvm-18.1.8-x86_64-pc-windows-msvc\\clang+llvm-18.1.8-x86_64-pc-windows-msvc\\bin\\clang.exe',
    'E:\\clang+llvm-18.1.8-x86_64-pc-windows-msvc.tar\\clang+llvm-18.1.8-x86_64-pc-windows-msvc\\clang+llvm-18.1.8-x86_64-pc-windows-msvc\\bin\\clang.exe'
  )

  if (process.platform === 'win32') {
    candidates.push(...(await collectWindowsClangCandidates('E:\\')))
    candidates.push(...(await collectWindowsClangCandidates('C:\\')))
  }

  for (const candidate of dedupe(candidates)) {
    if (await pathExists(candidate)) {
      return candidate
    }
  }
  return null
}

function buildNativeValidationLog(validation: NativeBuildValidationResult): string {
  const lines: string[] = []
  lines.push('# BUILD_VALIDATION.log')
  lines.push('')
  lines.push(`status: ${validation.status}`)
  lines.push(`attempted: ${validation.attempted}`)
  lines.push(`compiler: ${validation.compiler || 'none'}`)
  lines.push(`compiler_path: ${validation.compiler_path || 'none'}`)
  lines.push(`command: ${validation.command || 'n/a'}`)
  lines.push(`exit_code: ${validation.exit_code === null ? 'n/a' : validation.exit_code}`)
  lines.push(`timed_out: ${validation.timed_out}`)
  lines.push(`error: ${validation.error || 'none'}`)
  lines.push(`executable_path: ${validation.executable_path || 'none'}`)
  lines.push('')
  lines.push('## stdout')
  lines.push('```text')
  lines.push(validation.stdout || '')
  lines.push('```')
  lines.push('')
  lines.push('## stderr')
  lines.push('```text')
  lines.push(validation.stderr || '')
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

function buildHarnessValidationLog(validation: HarnessValidationResult): string {
  const lines: string[] = []
  lines.push('# HARNESS_VALIDATION.log')
  lines.push('')
  lines.push(`status: ${validation.status}`)
  lines.push(`attempted: ${validation.attempted}`)
  lines.push(`command: ${validation.command || 'n/a'}`)
  lines.push(`exit_code: ${validation.exit_code === null ? 'n/a' : validation.exit_code}`)
  lines.push(`timed_out: ${validation.timed_out}`)
  lines.push(`error: ${validation.error || 'none'}`)
  lines.push(`matched_entries: ${validation.matched_entries}`)
  lines.push(`mismatched_entries: ${validation.mismatched_entries}`)
  lines.push('')
  lines.push('## stdout')
  lines.push('```text')
  lines.push(validation.stdout || '')
  lines.push('```')
  lines.push('')
  lines.push('## stderr')
  lines.push('```text')
  lines.push(validation.stderr || '')
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

async function runNativeBuildValidation(args: {
  exportRoot: string
  srcRoot: string
  moduleRewriteFiles: string[]
  compilerPath?: string | null
  timeoutMs: number
}): Promise<NativeBuildValidationResult> {
  const compilerPath = await resolveClangCompilerPath(args.compilerPath)
  if (!compilerPath) {
    return {
      attempted: true,
      status: 'unavailable',
      compiler: 'clang',
      compiler_path: null,
      command: null,
      exit_code: null,
      timed_out: false,
      error: 'clang compiler is not available in PATH or known install locations',
      stdout: '',
      stderr: '',
      log_path: null,
      executable_path: null,
    }
  }

  const harnessSource = path.join(args.srcRoot, 'reconstruct_harness.c')
  const executablePath = path.join(args.exportRoot, 'reconstruct_harness.exe')
  const buildArgs = [
    '-std=c99',
    '-Wall',
    '-Wextra',
    '-I',
    args.srcRoot,
    '-o',
    executablePath,
    harnessSource,
    ...args.moduleRewriteFiles,
  ]
  const result = await runCommandWithTimeout(compilerPath, buildArgs, args.exportRoot, args.timeoutMs)

  return {
    attempted: true,
    status:
      result.error && result.exitCode === null && /enoent/i.test(result.error)
        ? 'unavailable'
        : result.exitCode === 0
          ? 'passed'
          : 'failed',
    compiler: 'clang',
    compiler_path: compilerPath,
    command: result.command,
    exit_code: result.exitCode,
    timed_out: result.timedOut,
    error:
      result.exitCode === 0 && !result.timedOut
        ? null
        : result.error || `clang build failed with exit code ${result.exitCode ?? 'unknown'}`,
    stdout: result.stdout,
    stderr: result.stderr,
    log_path: null,
    executable_path: result.exitCode === 0 ? executablePath : null,
  }
}

async function runHarnessValidation(args: {
  executablePath: string
  cwd: string
  timeoutMs: number
}): Promise<HarnessValidationResult> {
  if (!(await pathExists(args.executablePath))) {
    return {
      attempted: true,
      status: 'unavailable',
      command: quoteCommand(args.executablePath, []),
      exit_code: null,
      timed_out: false,
      error: 'reconstruct_harness executable is not present',
      stdout: '',
      stderr: '',
      log_path: null,
      matched_entries: 0,
      mismatched_entries: 0,
    }
  }

  const result = await runCommandWithTimeout(args.executablePath, [], args.cwd, args.timeoutMs)
  const combinedOutput = `${result.stdout}\n${result.stderr}`
  const matchedEntries = (combinedOutput.match(/match=ok/g) || []).length
  const mismatchedEntries = (combinedOutput.match(/match=mismatch/g) || []).length

  return {
    attempted: true,
    status: result.exitCode === 0 && mismatchedEntries === 0 ? 'passed' : 'failed',
    command: result.command,
    exit_code: result.exitCode,
    timed_out: result.timedOut,
    error:
      result.exitCode === 0 && mismatchedEntries === 0
        ? null
        : result.error || `reconstruct_harness failed with exit code ${result.exitCode ?? 'unknown'}`,
    stdout: result.stdout,
    stderr: result.stderr,
    log_path: null,
    matched_entries: matchedEntries,
    mismatched_entries: mismatchedEntries,
  }
}

function averageConfidence(functions: ReconstructedFunction[]): number {
  if (functions.length === 0) {
    return 0
  }
  const sum = functions.reduce((acc, item) => acc + item.confidence, 0)
  return clamp(sum / functions.length, 0, 1)
}

function buildGapsMarkdown(
  modules: ModuleBucket[],
  warnings: string[],
  functionSet: ReconstructedFunction[]
): string {
  const lines: string[] = []
  lines.push('# gaps.md')
  lines.push('')

  lines.push('## Global Warnings')
  if (warnings.length === 0) {
    lines.push('- None')
  } else {
    for (const warning of warnings) {
      lines.push(`- ${warning}`)
    }
  }
  lines.push('')

  lines.push('## Low Confidence Modules')
  const lowConfidenceModules = modules
    .map((module) => ({
      name: module.name,
      confidence: averageConfidence(module.functions),
      count: module.functions.length,
    }))
    .filter((item) => item.confidence < 0.55)

  if (lowConfidenceModules.length === 0) {
    lines.push('- None')
  } else {
    for (const item of lowConfidenceModules) {
      lines.push(`- ${item.name}: confidence=${item.confidence.toFixed(2)}, functions=${item.count}`)
    }
  }
  lines.push('')

  lines.push('## Function Gaps')
  const unresolved = functionSet.filter((func) => func.gaps.length > 0)
  if (unresolved.length === 0) {
    lines.push('- None')
  } else {
    for (const func of unresolved) {
      lines.push(`- ${func.function} (${func.address}): ${func.gaps.join(', ')}`)
    }
  }
  lines.push('')

  lines.push('## Notes')
  lines.push('- Source-like export is semantic reconstruction, not original source recovery.')
  lines.push('- Validate low-confidence blocks with disassembly and runtime context.')
  lines.push('')

  return lines.join('\n')
}

function inferBinaryRole(
  originalFilename: string | null,
  sampleFileType: string | null | undefined,
  exportCount: number
): string {
  const loweredName = (originalFilename || '').toLowerCase()
  const loweredType = (sampleFileType || '').toLowerCase()

  if (loweredName.endsWith('.sys') || loweredType.includes('driver')) {
    return 'driver'
  }
  if (
    loweredName.endsWith('.dll') ||
    loweredName.endsWith('.ocx') ||
    loweredName.endsWith('.cpl') ||
    loweredType.includes('dll')
  ) {
    return 'dll'
  }
  if (loweredName.endsWith('.exe') || loweredType.includes('exe') || loweredType.includes('pe32')) {
    return exportCount > 0 ? 'executable_with_exports' : 'executable'
  }
  if (exportCount > 0) {
    return 'library_like_pe'
  }
  return 'pe_image'
}

function buildBinaryProfile(
  sampleFileType: string | null | undefined,
  originalFilename: string | null,
  exportsData: PEExportsData | undefined,
  packerData: PackerDetectData | undefined,
  modules: Array<z.infer<typeof ModuleSchema>>,
  cliProfile?: ReconstructCliProfile | null
): BinaryProfile {
  const derivedCliProfile =
    cliProfile ||
    buildReconstructCliProfile(
    modules.map((module) => ({
      name: module.name,
      functions: [],
      roleHint: module.role_hint || null,
      focusMatches: new Set(module.focus_matches || []),
      importHints: new Set(module.import_hints || []),
      stringHints: new Set(module.string_hints || []),
      runtimeApis: new Set(module.runtime_apis || []),
      runtimeStages: new Set(module.runtime_stages || []),
      runtimeNotes: new Set<string>(),
    })) as unknown as ModuleBucket[]
  )
  const exportEntries = exportsData?.exports || []
  const exportCount = typeof exportsData?.total_exports === 'number'
    ? exportsData.total_exports
    : exportEntries.length
  const forwarderCount = typeof exportsData?.total_forwarders === 'number'
    ? exportsData.total_forwarders
    : (exportsData?.forwarders || []).length
  const notableExports = exportEntries
    .map((item) => item.name || `ordinal_${item.ordinal}`)
    .filter((item, index, all) => all.indexOf(item) === index)
    .slice(0, 8)
  const binaryRole = inferBinaryRole(originalFilename, sampleFileType, exportCount)
  const packed = packerData?.packed === true
  const packingConfidence = clamp(packerData?.confidence ?? 0, 0, 1)
  const priorities: string[] = []

  if (packed || packingConfidence >= 0.45) {
    priorities.push('unpack_or_deobfuscate_before_deep_semantics')
  }
  if (exportCount > 0) {
    priorities.push('trace_export_surface_first')
  }
  if (forwarderCount > 0) {
    priorities.push('inspect_forwarded_exports')
  }
  if (modules.some((module) => module.name === 'process_ops')) {
    priorities.push('review_process_manipulation_paths')
  }
  if (modules.some((module) => module.name === 'network_ops')) {
    priorities.push('review_network_reachability')
  }
  if (modules.some((module) => module.name === 'packer_analysis')) {
    priorities.push('review_packer_or_format_analysis_logic')
  }
  if (derivedCliProfile && (derivedCliProfile.command_count > 0 || derivedCliProfile.help_banner.length > 0)) {
    priorities.push('recover_cli_and_command_model')
  }

  return {
    binary_role: binaryRole,
    original_filename: originalFilename,
    export_count: exportCount,
    forwarder_count: forwarderCount,
    notable_exports: notableExports,
    packed,
    packing_confidence: packingConfidence,
    analysis_priorities: priorities.slice(0, 6),
    cli_profile: derivedCliProfile,
  }
}

function buildReverseNotesMarkdown(
  profile: BinaryProfile,
  modules: Array<z.infer<typeof ModuleSchema>>,
  warnings: string[],
  runtimeEvidence: DynamicTraceSummary | null,
  cliModels: Array<{
    module: string
    tool_name: string
    help_banner: string
    commands: CliCommandHint[]
  }>,
  buildValidation: NativeBuildValidationResult,
  harnessValidation: HarnessValidationResult
): string {
  const lines: string[] = []
  lines.push('# reverse_notes.md')
  lines.push('')
  lines.push('## Binary Profile')
  lines.push(`- binary_role: ${profile.binary_role}`)
  lines.push(`- original_filename: ${profile.original_filename || 'unknown'}`)
  lines.push(`- packed: ${profile.packed} (confidence=${profile.packing_confidence.toFixed(2)})`)
  lines.push(`- export_count: ${profile.export_count}`)
  lines.push(`- forwarder_count: ${profile.forwarder_count}`)
  lines.push(
    `- notable_exports: ${profile.notable_exports.length > 0 ? profile.notable_exports.join(', ') : 'none'}`
  )
  if (profile.cli_profile) {
    lines.push('## Primary CLI Model')
    lines.push(`- tool_name: ${profile.cli_profile.tool_name}`)
    lines.push(`- help_banner: ${profile.cli_profile.help_banner}`)
    lines.push(`- command_count: ${profile.cli_profile.command_count}`)
    lines.push(
      `- commands: ${profile.cli_profile.commands.map((item) => `${item.verb} => ${item.summary}`).join(' | ') || 'none'}`
    )
    lines.push('')
  }
  lines.push('## Analysis Priorities')
  if (profile.analysis_priorities.length === 0) {
    lines.push('- Start from the highest-confidence reconstructed modules and function summaries.')
  } else {
    for (const item of profile.analysis_priorities) {
      lines.push(`- ${item}`)
    }
  }
  lines.push('')
  lines.push('## Module Guide')
  for (const module of modules) {
    const moduleBucket = {
      name: module.name,
      functions: [],
      roleHint: module.role_hint || null,
      focusMatches: new Set(module.focus_matches || []),
      reviewResolution:
        module.review_summary || module.refined_name || module.role_hint
          ? {
              refined_name: module.refined_name || null,
              summary: module.review_summary || null,
              role_hint: module.role_hint || null,
              confidence: typeof module.review_confidence === 'number' ? module.review_confidence : null,
              assumptions: [],
              evidence_used: [],
              rewrite_guidance: [],
              focus_areas: module.focus_matches || [],
              priority_functions: [],
              source: 'llm' as const,
            }
          : undefined,
      importHints: new Set(module.import_hints || []),
      stringHints: new Set(module.string_hints || []),
      runtimeApis: new Set(module.runtime_apis || []),
      runtimeStages: new Set(module.runtime_stages || []),
      runtimeNotes: new Set<string>(),
    }
    const displayHints = collectDisplayStringHints(moduleBucket).slice(0, 3)
    const semanticRole = describeModuleRole(moduleBucket)
    lines.push(
      `- ${module.name}${module.refined_name ? ` [${module.refined_name}]` : ''}: role=${semanticRole} confidence=${module.confidence.toFixed(2)}, focus=${(module.focus_matches || []).join(', ') || 'none'}, functions=${module.function_count}, strings=${displayHints.join(' | ') || 'none'}, runtime=${module.runtime_stages.slice(0, 2).join(', ') || 'none'}${module.review_summary ? `, review=${normalizeExplanationText(module.review_summary)}` : ''}`
    )
  }
  lines.push('')
  if (runtimeEvidence) {
    lines.push('## Runtime Evidence')
    lines.push(`- executed: ${runtimeEvidence.executed}`)
    lines.push(`- api_count: ${runtimeEvidence.api_count}`)
    lines.push(`- stage_count: ${runtimeEvidence.stage_count}`)
    lines.push(`- observed_apis: ${runtimeEvidence.observed_apis.slice(0, 8).join(', ') || 'none'}`)
    lines.push(`- region_types: ${(runtimeEvidence.region_types || []).slice(0, 8).join(', ') || 'none'}`)
    lines.push(`- observed_modules: ${(runtimeEvidence.observed_modules || []).slice(0, 6).join(', ') || 'none'}`)
    lines.push(`- stages: ${runtimeEvidence.stages.slice(0, 6).join(', ') || 'none'}`)
    lines.push(`- summary: ${runtimeEvidence.summary}`)
    lines.push('')
  }

  lines.push('## Native Validation')
  lines.push(
    `- build: status=${buildValidation.status}, compiler=${buildValidation.compiler || 'none'}, exit_code=${buildValidation.exit_code === null ? 'n/a' : buildValidation.exit_code}, executable=${buildValidation.executable_path || 'none'}`
  )
  lines.push(
    `- harness: status=${harnessValidation.status}, exit_code=${harnessValidation.exit_code === null ? 'n/a' : harnessValidation.exit_code}, matched=${harnessValidation.matched_entries}, mismatched=${harnessValidation.mismatched_entries}`
  )
  if (buildValidation.error) {
    lines.push(`- build_error: ${buildValidation.error}`)
  }
  if (harnessValidation.error) {
    lines.push(`- harness_error: ${harnessValidation.error}`)
  }
  lines.push('')

  if (cliModels.length > 0) {
    lines.push('## Module CLI Models')
    for (const cliModel of cliModels) {
      lines.push(
        `- ${cliModel.module}: tool=${cliModel.tool_name}, help=${cliModel.help_banner || 'none'}, commands=${cliModel.commands.map((item) => item.verb).join(', ') || 'none'}`
      )
    }
    lines.push('')
  }
  lines.push('## Reverse-Engineering Notes')
  if (profile.binary_role.includes('dll') || profile.export_count > 0) {
    lines.push('- Treat the export surface as an entry map and trace each exported routine into internal dispatchers.')
  }
  if (profile.packed || profile.packing_confidence >= 0.45) {
    lines.push('- Packer or obfuscation indicators are present; unpacking may be required before claiming source-equivalent recovery.')
  }
  lines.push('- Generated pseudocode is reconstructed and commented for analyst use; it is not original author source.')
  lines.push('- Export also includes a shared support header, a semantic harness, and a CMake skeleton for compile-oriented review.')
  lines.push('')
  if (warnings.length > 0) {
    lines.push('## Recent Warnings')
    for (const warning of warnings.slice(0, 10)) {
      lines.push(`- ${warning}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}

export function createCodeReconstructExportHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: CodeReconstructExportDependencies
) {
  const decompilerWorker = new DecompilerWorker(database, workspaceManager)
  const reconstructFunctionsHandler =
    dependencies?.reconstructFunctionsHandler ||
    createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager)
  const importsExtractHandler =
    dependencies?.importsExtractHandler ||
    createPEImportsExtractHandler(workspaceManager, database, cacheManager)
  const exportsExtractHandler =
    dependencies?.exportsExtractHandler ||
    createPEExportsExtractHandler(workspaceManager, database, cacheManager)
  const packerDetectHandler =
    dependencies?.packerDetectHandler ||
    createPackerDetectHandler(workspaceManager, database, cacheManager)
  const stringsExtractHandler =
    dependencies?.stringsExtractHandler ||
    createStringsExtractHandler(workspaceManager, database, cacheManager)
  const runNativeBuild = dependencies?.nativeBuildValidator || runNativeBuildValidation
  const runHarness = dependencies?.harnessValidator || runHarnessValidation
  const searchFunctions =
    dependencies?.searchFunctions ||
    ((sampleId: string, options: { apiQuery?: string; stringQuery?: string; limit?: number; timeout?: number }) =>
      decompilerWorker.searchFunctions(sampleId, options))
  const runtimeEvidenceLoader =
    dependencies?.runtimeEvidenceLoader ||
    ((sampleId: string, options?: { evidenceScope?: 'all' | 'latest' | 'session'; sessionTag?: string }) =>
      loadDynamicTraceEvidence(workspaceManager, database, sampleId, {
        evidenceScope: options?.evidenceScope,
        sessionTag: options?.sessionTag,
      }))

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = CodeReconstructExportInputSchema.parse(args)
    const startTime = Date.now()

    try {
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
      const decompileReadyAnalysis = findBestGhidraAnalysis(
        database.findAnalysesBySample(input.sample_id),
        'decompile'
      )
      const analysisMarker =
        decompileReadyAnalysis?.finished_at ||
        completedGhidraAnalysis?.finished_at ||
        decompileReadyAnalysis?.id ||
        completedGhidraAnalysis?.id ||
        'none'
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
      const semanticExplanationArtifacts = database.findArtifactsByType(
        input.sample_id,
        SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE
      )
      const semanticExplanationMarker =
        semanticExplanationArtifacts.length > 0
          ? semanticExplanationArtifacts.map((item) => `${item.id}:${item.sha256}`).sort().join('|')
          : 'none'

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          topk: input.topk,
          module_limit: input.module_limit,
          min_module_size: input.min_module_size,
          include_imports: input.include_imports,
          include_strings: input.include_strings,
          export_name: input.export_name || null,
          validate_build: input.validate_build,
          run_harness: input.run_harness,
          compiler_path: input.compiler_path || null,
          build_timeout_ms: input.build_timeout_ms,
          run_timeout_ms: input.run_timeout_ms,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag || null,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag || null,
          role_target: input.role_target || null,
          role_focus_areas: input.role_focus_areas,
          role_priority_order: input.role_priority_order,
          analysis_marker: analysisMarker,
          runtime_marker: runtimeMarker,
          semantic_name_marker: semanticNameMarker,
          semantic_explanation_marker: semanticExplanationMarker,
          ghidra_valid: ghidraConfig.isValid,
          ghidra_install_dir: ghidraConfig.installDir || 'none',
          ghidra_version: ghidraConfig.version || 'unknown',
        },
      })

      if (input.reuse_cached) {
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
      }

      const warnings: string[] = []
      const dynamicEvidence = await runtimeEvidenceLoader(input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
      })
      const semanticNameIndex = await loadSemanticNameSuggestionIndex(
        workspaceManager,
        database,
        input.sample_id,
        {
          scope: input.semantic_scope,
          sessionTag: input.semantic_session_tag,
        }
      )

      const reconstructResult = await reconstructFunctionsHandler({
        sample_id: input.sample_id,
        topk: input.topk,
        include_xrefs: true,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
        semantic_scope: input.semantic_scope,
        semantic_session_tag: input.semantic_session_tag,
      })
      if (!reconstructResult.ok || !reconstructResult.data) {
        return {
          ok: false,
          errors: reconstructResult.errors || ['Failed to reconstruct functions'],
          warnings: reconstructResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (reconstructResult.warnings && reconstructResult.warnings.length > 0) {
        warnings.push(...reconstructResult.warnings.map((item) => `reconstruct: ${item}`))
      }

      const reconstructedData = reconstructResult.data as ReconstructFunctionsData
      const reconstructedFunctions = dedupeReconstructedFunctions(
        enrichFunctionsWithRuntimeContext(reconstructedData.functions || [], dynamicEvidence).map(
          (func) => ensureNameResolution(func)
        )
      )
      if (reconstructedFunctions.length === 0) {
        return {
          ok: false,
          errors: ['No reconstructed functions available. Run ghidra.analyze and retry.'],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      let importsData: ImportsData | undefined
      if (input.include_imports) {
        const importsResult = await importsExtractHandler({
          sample_id: input.sample_id,
          group_by_dll: true,
        })
        if (importsResult.ok && importsResult.data) {
          importsData = importsResult.data as ImportsData
        } else {
          warnings.push(
            `imports unavailable: ${(importsResult.errors || ['unknown error']).join('; ')}`
          )
        }
      }

      let exportsData: PEExportsData | undefined
      const exportsResult = await exportsExtractHandler({
        sample_id: input.sample_id,
      })
      if (exportsResult.ok && exportsResult.data) {
        exportsData = exportsResult.data as PEExportsData
      } else {
        warnings.push(
          `exports unavailable: ${(exportsResult.errors || ['unknown error']).join('; ')}`
        )
      }

      let packerData: PackerDetectData | undefined
      const packerResult = await packerDetectHandler({
        sample_id: input.sample_id,
      })
      if (packerResult.ok && packerResult.data) {
        packerData = packerResult.data as PackerDetectData
      } else {
        warnings.push(
          `packer unavailable: ${(packerResult.errors || ['unknown error']).join('; ')}`
        )
      }

      let stringsData: StringsSummary | undefined
      if (input.include_strings) {
        const stringsResult = await stringsExtractHandler({
          sample_id: input.sample_id,
          min_len: 6,
          max_strings: 350,
          context_window_bytes: 2048,
          max_context_windows: 20,
          category_filter: 'all',
        })
        if (stringsResult.ok && stringsResult.data) {
          stringsData = stringsResult.data as StringsSummary
        } else {
          warnings.push(
            `strings unavailable: ${(stringsResult.errors || ['unknown error']).join('; ')}`
          )
        }
      }

      const functionStringHints = await buildFunctionStringSearchHints(
        input.sample_id,
        stringsData,
        searchFunctions,
        warnings,
        Boolean(decompileReadyAnalysis)
      )

      const mergedFunctions = [...reconstructedFunctions]
      const knownAddresses = new Set(mergedFunctions.map((item) => item.address))
      const supplementalAddresses = Array.from(functionStringHints.keys())
        .filter((address) => !knownAddresses.has(address))
        .slice(0, 4)

      for (const address of supplementalAddresses) {
        const supplemental = await reconstructFunctionsHandler({
          sample_id: input.sample_id,
          address,
          include_xrefs: true,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag,
        })
        if (!supplemental.ok || !supplemental.data) {
          warnings.push(
            `supplemental reconstruct unavailable for ${address}: ${(supplemental.errors || ['unknown error']).join('; ')}`
          )
          continue
        }
        if (supplemental.warnings && supplemental.warnings.length > 0) {
          warnings.push(...supplemental.warnings.map((item) => `supplemental: ${item}`))
        }
        for (const func of (supplemental.data as ReconstructFunctionsData).functions || []) {
          if (knownAddresses.has(func.address)) {
            continue
          }
          const [enriched] = enrichFunctionsWithRuntimeContext([func], dynamicEvidence).map((item) =>
            ensureNameResolution(item)
          )
          mergedFunctions.push(enriched)
          knownAddresses.add(func.address)
        }
      }

      const normalizedFunctions = dedupeReconstructedFunctions(mergedFunctions)
      const explanationIndex = await attachFunctionExplanations(
        workspaceManager,
        database,
        input.sample_id,
        normalizedFunctions,
        {
          scope: input.semantic_scope,
          sessionTag: input.semantic_session_tag,
        }
      )
      const provenance = {
        runtime: buildRuntimeArtifactProvenance(
          dynamicEvidence,
          input.evidence_scope,
          input.evidence_session_tag
        ),
        semantic_names: buildSemanticArtifactProvenance(
          'semantic naming artifacts',
          semanticNameIndex,
          input.semantic_scope,
          input.semantic_session_tag
        ),
        semantic_explanations: buildSemanticArtifactProvenance(
          'semantic explanation artifacts',
          explanationIndex,
          input.semantic_scope,
          input.semantic_session_tag
        ),
      }
      const roleAwareModules = buildRoleAwareModuleOptions(input)

      const modules = regroupModules(
        normalizedFunctions,
        input.module_limit,
        input.min_module_size,
        importsData,
        stringsData,
        functionStringHints,
        roleAwareModules
      )
      const moduleReviewIndex = await attachModuleReviews(
        workspaceManager,
        database,
        input.sample_id,
        modules,
        {
          scope: input.semantic_scope,
          sessionTag: input.semantic_session_tag,
        }
      )
      ;(provenance as any).semantic_module_reviews = buildSemanticArtifactProvenance(
        'semantic module review artifacts',
        moduleReviewIndex,
        input.semantic_scope,
        input.semantic_session_tag
      )

      const workspace = await workspaceManager.getWorkspace(input.sample_id)
      const originalEntries = await fs.readdir(workspace.original)
      const originalFilename = originalEntries.length > 0 ? originalEntries[0] : null
      const exportFolderName =
        input.export_name ||
        `export_${new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')}`
      const exportRoot = path.join(workspace.reports, 'reconstruct', exportFolderName)
      const srcRoot = path.join(exportRoot, 'src')
      const supportHeaderPath = path.join(srcRoot, 'reconstruct_support.h')
      const harnessPath = path.join(srcRoot, 'reconstruct_harness.c')
      const buildManifestPath = path.join(exportRoot, 'CMakeLists.txt')
      const cliModelPath = path.join(exportRoot, 'cli_model.json')

      await fs.mkdir(srcRoot, { recursive: true })
      await fs.writeFile(supportHeaderPath, buildSupportHeaderContent(modules), 'utf-8')

      const outputModules: Array<z.infer<typeof ModuleSchema>> = []
      const artifacts: ArtifactRef[] = []
      const moduleRewriteFiles: string[] = []

      for (const module of modules) {
        const safeName = sanitizeModuleName(module.name)
        const interfaceFile = path.join(srcRoot, `${safeName}.interface.h`)
        const pseudoFile = path.join(srcRoot, `${safeName}.pseudo.c`)
        const rewriteFile = path.join(srcRoot, `${safeName}.rewrite.c`)

        await fs.writeFile(interfaceFile, buildInterfaceContent(module), 'utf-8')
        await fs.writeFile(pseudoFile, buildPseudocodeContent(module), 'utf-8')
        await fs.writeFile(rewriteFile, buildAnnotatedRewriteContent(module), 'utf-8')
        moduleRewriteFiles.push(rewriteFile)

        outputModules.push({
          name: safeName,
          confidence: averageConfidence(module.functions),
          function_count: module.functions.length,
          role_hint: module.reviewResolution?.role_hint || module.roleHint,
          focus_matches: Array.from(module.focusMatches),
          refined_name: module.reviewResolution?.refined_name || null,
          review_summary: module.reviewResolution?.summary || null,
          review_confidence:
            typeof module.reviewResolution?.confidence === 'number'
              ? module.reviewResolution.confidence
              : null,
          import_hints: Array.from(module.importHints).slice(0, 10),
          string_hints: Array.from(module.stringHints).slice(0, 10),
          runtime_apis: Array.from(module.runtimeApis).slice(0, 10),
          runtime_stages: Array.from(module.runtimeStages).slice(0, 10),
          interface_path: toPosixRelative(workspace.root, interfaceFile),
          pseudocode_path: toPosixRelative(workspace.root, pseudoFile),
          rewrite_path: toPosixRelative(workspace.root, rewriteFile),
          functions: module.functions.map((func) => ({
            function: func.function,
            address: func.address,
            confidence: func.confidence,
            gaps: func.gaps,
            suggested_name: func.suggested_name || null,
            suggested_role: func.suggested_role || null,
            rename_confidence:
              typeof func.rename_confidence === 'number' ? func.rename_confidence : null,
            rule_based_name: func.name_resolution?.rule_based_name || null,
            llm_suggested_name: func.name_resolution?.llm_suggested_name || null,
            validated_name: func.name_resolution?.validated_name || func.suggested_name || null,
            name_resolution_source: func.name_resolution?.resolution_source || null,
            explanation_summary: func.explanation_resolution?.summary || null,
            explanation_behavior: func.explanation_resolution?.behavior || null,
            explanation_confidence:
              typeof func.explanation_resolution?.confidence === 'number'
                ? func.explanation_resolution.confidence
                : null,
          })),
        })
      }

      const cliModels = buildExportCliModels(modules)
      const cliProfile = buildReconstructCliProfile(modules)

      await fs.writeFile(harnessPath, buildHarnessContent(modules), 'utf-8')
      await fs.writeFile(buildManifestPath, buildCMakeContent(modules), 'utf-8')
      await fs.writeFile(cliModelPath, JSON.stringify(cliModels, null, 2), 'utf-8')

      let buildValidation: NativeBuildValidationResult = {
        attempted: false,
        status: 'skipped',
        compiler: null,
        compiler_path: null,
        command: null,
        exit_code: null,
        timed_out: false,
        error: null,
        stdout: '',
        stderr: '',
        log_path: null,
        executable_path: null,
      }
      let harnessValidation: HarnessValidationResult = {
        attempted: false,
        status: 'skipped',
        command: null,
        exit_code: null,
        timed_out: false,
        error: null,
        stdout: '',
        stderr: '',
        log_path: null,
        matched_entries: 0,
        mismatched_entries: 0,
      }

      if (input.validate_build) {
        buildValidation = await runNativeBuild({
          exportRoot,
          srcRoot,
          moduleRewriteFiles,
          compilerPath: input.compiler_path || null,
          timeoutMs: input.build_timeout_ms,
        })
        if (buildValidation.status === 'passed' && input.run_harness && buildValidation.executable_path) {
          harnessValidation = await runHarness({
            executablePath: buildValidation.executable_path,
            cwd: exportRoot,
            timeoutMs: input.run_timeout_ms,
          })
        } else if (input.run_harness) {
          harnessValidation = {
            attempted: false,
            status: buildValidation.status === 'unavailable' ? 'unavailable' : 'skipped',
            command: null,
            exit_code: null,
            timed_out: false,
            error:
              buildValidation.status === 'passed'
                ? 'reconstruct_harness executable was not produced'
                : 'Build validation must pass before harness execution.',
            stdout: '',
            stderr: '',
            log_path: null,
            matched_entries: 0,
            mismatched_entries: 0,
          }
        }
      } else if (input.run_harness) {
        harnessValidation = {
          attempted: false,
          status: 'skipped',
          command: null,
          exit_code: null,
          timed_out: false,
          error: 'Build validation is disabled; harness execution was skipped.',
          stdout: '',
          stderr: '',
          log_path: null,
          matched_entries: 0,
          mismatched_entries: 0,
        }
      }

      if (input.validate_build && buildValidation.status !== 'passed') {
        warnings.push(`build_validation: ${buildValidation.error || buildValidation.status}`)
      }
      if (input.run_harness && harnessValidation.status === 'failed') {
        warnings.push(`harness_validation: ${harnessValidation.error || 'reconstruct_harness reported mismatches'}`)
      }

      const buildLogPath = path.join(exportRoot, 'BUILD_VALIDATION.log')
      const harnessLogPath = path.join(exportRoot, 'HARNESS_VALIDATION.log')
      buildValidation = {
        ...buildValidation,
        log_path: buildLogPath,
      }
      harnessValidation = {
        ...harnessValidation,
        log_path: harnessLogPath,
      }
      await fs.writeFile(buildLogPath, buildNativeValidationLog(buildValidation), 'utf-8')
      await fs.writeFile(harnessLogPath, buildHarnessValidationLog(harnessValidation), 'utf-8')

      const gapsContent = buildGapsMarkdown(modules, warnings, normalizedFunctions)
      const gapsPath = path.join(exportRoot, 'gaps.md')
      await fs.writeFile(gapsPath, gapsContent, 'utf-8')
      const binaryProfile = buildBinaryProfile(
        sample.file_type,
        originalFilename,
        exportsData,
        packerData,
        outputModules,
        cliProfile
      )
      const notesContent = buildReverseNotesMarkdown(
        binaryProfile,
        outputModules,
        warnings,
        dynamicEvidence,
        cliModels,
        buildValidation,
        harnessValidation
      )
      const notesPath = path.join(exportRoot, 'reverse_notes.md')
      await fs.writeFile(notesPath, notesContent, 'utf-8')

      const executableAbsolute =
        buildValidation.executable_path && path.isAbsolute(buildValidation.executable_path)
          ? buildValidation.executable_path
          : buildValidation.executable_path
            ? path.join(exportRoot, buildValidation.executable_path)
            : null
      const buildLogRelative = toPosixRelative(workspace.root, buildLogPath)
      const harnessLogRelative = toPosixRelative(workspace.root, harnessLogPath)
      const executableRelative =
        executableAbsolute && (await pathExists(executableAbsolute))
          ? toPosixRelative(workspace.root, executableAbsolute)
          : null
      const buildValidationOutput = {
        ...buildValidation,
        log_path: buildLogRelative,
        executable_path: executableRelative,
      }
      const harnessValidationOutput = {
        ...harnessValidation,
        log_path: harnessLogRelative,
      }

      const manifest = {
        sample_id: input.sample_id,
        tool_version: TOOL_VERSION,
        exported_at: new Date().toISOString(),
        module_count: outputModules.length,
        topk: input.topk,
        module_limit: input.module_limit,
        min_module_size: input.min_module_size,
        include_imports: input.include_imports,
        include_strings: input.include_strings,
        validate_build: input.validate_build,
        run_harness: input.run_harness,
        warnings,
        binary_profile: binaryProfile,
        provenance,
        build_validation: buildValidationOutput,
        harness_validation: harnessValidationOutput,
        runtime_evidence: dynamicEvidence
          ? {
              executed: dynamicEvidence.executed,
              api_count: dynamicEvidence.api_count,
              stage_count: dynamicEvidence.stage_count,
              observed_apis: dynamicEvidence.observed_apis.slice(0, 12),
              region_types: (dynamicEvidence.region_types || []).slice(0, 12),
              protections: (dynamicEvidence.protections || []).slice(0, 12),
              address_ranges: (dynamicEvidence.address_ranges || []).slice(0, 8),
              region_owners: (dynamicEvidence.region_owners || []).slice(0, 8),
              observed_modules: (dynamicEvidence.observed_modules || []).slice(0, 8),
              segment_names: (dynamicEvidence.segment_names || []).slice(0, 8),
              observed_strings: (dynamicEvidence.observed_strings || []).slice(0, 8),
              stages: dynamicEvidence.stages.slice(0, 12),
              summary: dynamicEvidence.summary,
            }
          : null,
        cli_models: cliModels,
        modules: outputModules.map((module) => ({
          name: module.name,
          confidence: module.confidence,
          function_count: module.function_count,
          role_hint: module.role_hint || null,
          focus_matches: module.focus_matches || [],
          refined_name: module.refined_name || null,
          review_summary: module.review_summary || null,
          review_confidence:
            typeof module.review_confidence === 'number' ? module.review_confidence : null,
          interface_path: module.interface_path,
          pseudocode_path: module.pseudocode_path,
          rewrite_path: module.rewrite_path,
          import_hints: module.import_hints,
          string_hints: module.string_hints,
          runtime_apis: module.runtime_apis,
          runtime_stages: module.runtime_stages,
        })),
        files: {
          support_header: toPosixRelative(workspace.root, supportHeaderPath),
          harness: toPosixRelative(workspace.root, harnessPath),
          build_manifest: toPosixRelative(workspace.root, buildManifestPath),
          build_validation_log: buildLogRelative,
          harness_validation_log: harnessLogRelative,
          harness_binary: executableRelative,
          cli_model: toPosixRelative(workspace.root, cliModelPath),
          gaps: toPosixRelative(workspace.root, gapsPath),
          notes: toPosixRelative(workspace.root, notesPath),
        },
      }

      const manifestPath = path.join(exportRoot, 'manifest.json')
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8')

      const manifestRelative = toPosixRelative(workspace.root, manifestPath)
      const supportHeaderRelative = toPosixRelative(workspace.root, supportHeaderPath)
      const harnessRelative = toPosixRelative(workspace.root, harnessPath)
      const buildManifestRelative = toPosixRelative(workspace.root, buildManifestPath)
      const cliModelRelative = toPosixRelative(workspace.root, cliModelPath)
      const gapsRelative = toPosixRelative(workspace.root, gapsPath)
      const notesRelative = toPosixRelative(workspace.root, notesPath)
      const executableRelativePath = buildValidationOutput.executable_path
      const manifestSha = await sha256File(manifestPath)
      const supportHeaderSha = await sha256File(supportHeaderPath)
      const harnessSha = await sha256File(harnessPath)
      const buildManifestSha = await sha256File(buildManifestPath)
      const buildLogSha = await sha256File(buildLogPath)
      const harnessLogSha = await sha256File(harnessLogPath)
      const cliModelSha = await sha256File(cliModelPath)
      const gapsSha = await sha256File(gapsPath)
      const notesSha = await sha256File(notesPath)

      const manifestArtifactId = randomUUID()
      database.insertArtifact({
        id: manifestArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_manifest',
        path: manifestRelative,
        sha256: manifestSha,
        mime: 'application/json',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: manifestArtifactId,
        type: 'reconstruct_manifest',
        path: manifestRelative,
        sha256: manifestSha,
        mime: 'application/json',
      })

      const supportHeaderArtifactId = randomUUID()
      database.insertArtifact({
        id: supportHeaderArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_support_header',
        path: supportHeaderRelative,
        sha256: supportHeaderSha,
        mime: 'text/x-c',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: supportHeaderArtifactId,
        type: 'reconstruct_support_header',
        path: supportHeaderRelative,
        sha256: supportHeaderSha,
        mime: 'text/x-c',
      })

      const harnessArtifactId = randomUUID()
      database.insertArtifact({
        id: harnessArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_harness',
        path: harnessRelative,
        sha256: harnessSha,
        mime: 'text/x-c',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: harnessArtifactId,
        type: 'reconstruct_harness',
        path: harnessRelative,
        sha256: harnessSha,
        mime: 'text/x-c',
      })

      const buildManifestArtifactId = randomUUID()
      database.insertArtifact({
        id: buildManifestArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_build_manifest',
        path: buildManifestRelative,
        sha256: buildManifestSha,
        mime: 'text/plain',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: buildManifestArtifactId,
        type: 'reconstruct_build_manifest',
        path: buildManifestRelative,
        sha256: buildManifestSha,
        mime: 'text/plain',
      })

      const buildLogArtifactId = randomUUID()
      database.insertArtifact({
        id: buildLogArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_build_log',
        path: buildLogRelative,
        sha256: buildLogSha,
        mime: 'text/markdown',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: buildLogArtifactId,
        type: 'reconstruct_build_log',
        path: buildLogRelative,
        sha256: buildLogSha,
        mime: 'text/markdown',
      })

      const harnessLogArtifactId = randomUUID()
      database.insertArtifact({
        id: harnessLogArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_run_log',
        path: harnessLogRelative,
        sha256: harnessLogSha,
        mime: 'text/markdown',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: harnessLogArtifactId,
        type: 'reconstruct_run_log',
        path: harnessLogRelative,
        sha256: harnessLogSha,
        mime: 'text/markdown',
      })

      const cliModelArtifactId = randomUUID()
      database.insertArtifact({
        id: cliModelArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_cli_model',
        path: cliModelRelative,
        sha256: cliModelSha,
        mime: 'application/json',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: cliModelArtifactId,
        type: 'reconstruct_cli_model',
        path: cliModelRelative,
        sha256: cliModelSha,
        mime: 'application/json',
      })

      const gapsArtifactId = randomUUID()
      database.insertArtifact({
        id: gapsArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_gaps',
        path: gapsRelative,
        sha256: gapsSha,
        mime: 'text/markdown',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: gapsArtifactId,
        type: 'reconstruct_gaps',
        path: gapsRelative,
        sha256: gapsSha,
        mime: 'text/markdown',
      })

      const notesArtifactId = randomUUID()
      database.insertArtifact({
        id: notesArtifactId,
        sample_id: input.sample_id,
        type: 'reconstruct_notes',
        path: notesRelative,
        sha256: notesSha,
        mime: 'text/markdown',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: notesArtifactId,
        type: 'reconstruct_notes',
        path: notesRelative,
        sha256: notesSha,
        mime: 'text/markdown',
      })

      if (executableAbsolute && executableRelativePath && (await pathExists(executableAbsolute))) {
        const executableSha = await sha256File(executableAbsolute)
        const executableArtifactId = randomUUID()
        database.insertArtifact({
          id: executableArtifactId,
          sample_id: input.sample_id,
          type: 'reconstruct_harness_binary',
          path: executableRelativePath,
          sha256: executableSha,
          mime: 'application/vnd.microsoft.portable-executable',
          created_at: new Date().toISOString(),
        })
        artifacts.push({
          id: executableArtifactId,
          type: 'reconstruct_harness_binary',
          path: executableRelativePath,
          sha256: executableSha,
          mime: 'application/vnd.microsoft.portable-executable',
        })
      }

      for (const module of outputModules) {
        const interfaceRelative = module.interface_path
        const pseudocodeRelative = module.pseudocode_path
        const rewriteRelative = module.rewrite_path
        const interfaceAbs = workspaceManager.normalizePath(workspace.root, interfaceRelative)
        const pseudocodeAbs = workspaceManager.normalizePath(workspace.root, pseudocodeRelative)
        const rewriteAbs = workspaceManager.normalizePath(workspace.root, rewriteRelative)
        const interfaceSha = await sha256File(interfaceAbs)
        const pseudocodeSha = await sha256File(pseudocodeAbs)
        const rewriteSha = await sha256File(rewriteAbs)

        const interfaceArtifactId = randomUUID()
        database.insertArtifact({
          id: interfaceArtifactId,
          sample_id: input.sample_id,
          type: 'report',
          path: interfaceRelative,
          sha256: interfaceSha,
          mime: 'text/plain',
          created_at: new Date().toISOString(),
        })
        artifacts.push({
          id: interfaceArtifactId,
          type: 'report',
          path: interfaceRelative,
          sha256: interfaceSha,
          mime: 'text/plain',
        })

        const pseudocodeArtifactId = randomUUID()
        database.insertArtifact({
          id: pseudocodeArtifactId,
          sample_id: input.sample_id,
          type: 'ghidra_pseudocode',
          path: pseudocodeRelative,
          sha256: pseudocodeSha,
          mime: 'text/x-c',
          created_at: new Date().toISOString(),
        })
        artifacts.push({
          id: pseudocodeArtifactId,
          type: 'ghidra_pseudocode',
          path: pseudocodeRelative,
          sha256: pseudocodeSha,
          mime: 'text/x-c',
        })

        const rewriteArtifactId = randomUUID()
        database.insertArtifact({
          id: rewriteArtifactId,
          sample_id: input.sample_id,
          type: 'reconstruct_rewrite',
          path: rewriteRelative,
          sha256: rewriteSha,
          mime: 'text/x-c',
          created_at: new Date().toISOString(),
        })
        artifacts.push({
          id: rewriteArtifactId,
          type: 'reconstruct_rewrite',
          path: rewriteRelative,
          sha256: rewriteSha,
          mime: 'text/x-c',
        })
      }

      const unresolvedCount = normalizedFunctions.filter((func) => func.gaps.length > 0).length
      const outputData = {
        sample_id: input.sample_id,
        export_root: toPosixRelative(workspace.root, exportRoot),
        manifest_path: manifestRelative,
        gaps_path: gapsRelative,
        notes_path: notesRelative,
        cli_model_path: cliModelRelative,
        support_header_path: supportHeaderRelative,
        harness_path: harnessRelative,
        build_manifest_path: buildManifestRelative,
        build_validation: buildValidationOutput,
        harness_validation: harnessValidationOutput,
        module_count: outputModules.length,
        unresolved_count: unresolvedCount,
        binary_profile: binaryProfile,
        runtime_evidence: dynamicEvidence
          ? {
              executed: dynamicEvidence.executed,
              api_count: dynamicEvidence.api_count,
              stage_count: dynamicEvidence.stage_count,
              observed_apis: dynamicEvidence.observed_apis.slice(0, 12),
              region_types: (dynamicEvidence.region_types || []).slice(0, 12),
              protections: (dynamicEvidence.protections || []).slice(0, 12),
              address_ranges: (dynamicEvidence.address_ranges || []).slice(0, 8),
              region_owners: (dynamicEvidence.region_owners || []).slice(0, 8),
              observed_modules: (dynamicEvidence.observed_modules || []).slice(0, 8),
              segment_names: (dynamicEvidence.segment_names || []).slice(0, 8),
              observed_strings: (dynamicEvidence.observed_strings || []).slice(0, 8),
              stages: dynamicEvidence.stages.slice(0, 12),
              summary: dynamicEvidence.summary,
            }
          : null,
        provenance,
        modules: outputModules,
      }

      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: outputData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
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
