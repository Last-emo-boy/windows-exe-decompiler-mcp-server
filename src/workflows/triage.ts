/**
 * Triage workflow implementation
 * Quick threat assessment workflow that completes within 5 minutes
 * Requirements: 15.1, 15.2, 15.4, 15.5
 */

import fs from 'fs'
import path from 'path'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createPEFingerprintHandler } from '../tools/pe-fingerprint.js'
import { createRuntimeDetectHandler } from '../tools/runtime-detect.js'
import { createPEImportsExtractHandler } from '../tools/pe-imports-extract.js'
import { createStringsExtractHandler } from '../tools/strings-extract.js'
import { createYaraScanHandler } from '../tools/yara-scan.js'
import { createStaticCapabilityTriageHandler } from '../tools/static-capability-triage.js'
import { createPEStructureAnalyzeHandler } from '../tools/pe-structure-analyze.js'
import { createCompilerPackerDetectHandler } from '../tools/compiler-packer-detect.js'
import { createAnalysisContextLinkHandler } from '../tools/analysis-context-link.js'
import {
  AnalysisIntentDepthSchema,
  BackendPolicySchema,
  BackendRoutingMetadataSchema,
  buildIntentBackendPlan,
  mergeRoutingMetadata,
  selectedBackendTools,
} from '../intent-routing.js'
import {
  CoverageEnvelopeSchema,
  buildBudgetDowngradeReasons,
  buildCoverageEnvelope,
  classifySampleSizeTier,
  deriveAnalysisBudgetProfile,
  mergeCoverageEnvelope,
} from '../analysis-coverage.js'
import { resolveAnalysisBackends } from '../static-backend-discovery.js'
import {
  createRizinAnalyzeHandler,
  createUPXInspectHandler,
  createYaraXScanHandler,
} from '../tools/docker-backend-tools.js'
import { collectCryptoApiNames } from '../crypto-breakpoint-analysis.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'workflow.triage'

// Suspicious API patterns for IOC detection
const HIGH_RISK_APIS = [
  'CreateRemoteThread',
  'VirtualAllocEx',
  'WriteProcessMemory',
  'SetWindowsHookEx',
]

const CONTEXT_DEPENDENT_APIS = [
  'GetAsyncKeyState',
  'InternetOpen',
  'InternetConnect',
  'HttpSendRequest',
  'URLDownloadToFile',
  'WinExec',
  'ShellExecute',
  'CreateProcess',
  'RegSetValue',
  'RegCreateKey',
  'CryptEncrypt',
  'CryptDecrypt',
]

const SUSPICIOUS_APIS = [...new Set([...HIGH_RISK_APIS, ...CONTEXT_DEPENDENT_APIS])]

const LibraryProfileSchema = z.object({
  ecosystems: z.array(z.string()),
  top_crates: z.array(z.string()),
  notable_libraries: z.array(z.string()),
  evidence: z.array(z.string()),
})

const NOTABLE_LIBRARY_HINTS: Array<{ name: string; patterns: RegExp[] }> = [
  { name: 'tokio', patterns: [/\btokio\b/i] },
  { name: 'goblin', patterns: [/\bgoblin\b/i] },
  { name: 'iced-x86', patterns: [/\biced[-_]?x86\b/i] },
  { name: 'clap', patterns: [/\bclap\b/i] },
  { name: 'sysinfo', patterns: [/\bsysinfo\b/i] },
  { name: 'reqwest', patterns: [/\breqwest\b/i] },
  { name: 'serde', patterns: [/\bserde\b/i] },
  { name: 'mio', patterns: [/\bmio\b/i] },
  { name: 'pelite', patterns: [/\bpelite\b/i] },
  { name: 'object', patterns: [/\bobject\b/i] },
  { name: 'winapi', patterns: [/\bwinapi\b/i] },
  { name: 'ntapi', patterns: [/\bntapi\b/i] },
  { name: 'windows-sys', patterns: [/\bwindows[-_]?sys\b/i] },
]

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for triage workflow
 * Requirements: 15.1
 */
export const TriageWorkflowInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache in dependent static tools'),
  raw_result_mode: z
    .enum(['compact', 'full'])
    .optional()
    .default('compact')
    .describe('Return compact per-tool previews by default; use `full` only when the complete child tool payloads are required for a targeted smaller-sample review. Large samples should stay compact.'),
  depth: AnalysisIntentDepthSchema
    .optional()
    .default('balanced')
    .describe('Controls how aggressively safe corroborating backends are auto-selected.'),
  backend_policy: BackendPolicySchema
    .optional()
    .default('auto')
    .describe('Controls whether newer installed backends are auto-preferred, suppressed, or only used when baseline evidence is weak.'),
  allow_transformations: z
    .boolean()
    .optional()
    .default(false)
    .describe('Keep false for normal triage. True suppresses automatic unpack-style backend actions so transformations remain explicit.'),
})

export type TriageWorkflowInput = z.infer<typeof TriageWorkflowInputSchema>

/**
 * IOC (Indicators of Compromise) structure
 * Requirements: 15.2, 15.5
 */
const IOCSchema = z.object({
  suspicious_imports: z.array(z.string()).describe('Suspicious imported functions'),
  suspicious_strings: z.array(z.string()).describe('Suspicious strings found'),
  yara_matches: z.array(z.string()).describe('YARA rule matches'),
  yara_low_confidence: z.array(z.string()).optional().describe('YARA matches downgraded due to weak evidence'),
  urls: z.array(z.string()).optional().describe('URLs found in strings'),
  ip_addresses: z.array(z.string()).optional().describe('IP addresses found'),
  file_paths: z.array(z.string()).optional().describe('File paths found'),
  registry_keys: z.array(z.string()).optional().describe('Registry keys found'),
  high_value_iocs: z
    .object({
      suspicious_apis: z.array(z.string()).optional(),
      commands: z.array(z.string()).optional(),
      pipes: z.array(z.string()).optional(),
      urls: z.array(z.string()).optional(),
      network: z.array(z.string()).optional(),
    })
    .optional()
    .describe('Layered high-value IOC view'),
  compiler_artifacts: z
    .object({
      cargo_paths: z.array(z.string()).optional(),
      rust_markers: z.array(z.string()).optional(),
      library_profile: LibraryProfileSchema.optional(),
    })
    .optional()
    .describe('Build/toolchain breadcrumbs separated from high-risk IOC signals'),
})

const IntentAssessmentSchema = z.object({
  label: z.enum(['dual_use_tool', 'operator_utility', 'malware_like_payload', 'unknown']),
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
  counter_evidence: z.array(z.string()),
})

const ToolingAssessmentSchema = z.object({
  help_text_detected: z.boolean(),
  cli_surface_detected: z.boolean(),
  framework_hints: z.array(z.string()),
  toolchain_markers: z.array(z.string()),
  library_profile: LibraryProfileSchema.optional(),
})

/**
 * Output schema for triage workflow
 * Requirements: 15.2, 15.4, 15.5
 */
export const TriageWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    summary: z.string().describe('Natural language summary of the analysis'),
    confidence: z.number().min(0).max(1).describe('Confidence score (0-1)'),
    threat_level: z.enum(['clean', 'suspicious', 'malicious', 'unknown']).describe('Assessed threat level'),
    iocs: IOCSchema.describe('Indicators of Compromise'),
    evidence: z.array(z.string()).describe('Evidence supporting the assessment'),
    evidence_weights: z
      .object({
        import: z.number().min(0).max(1),
        string: z.number().min(0).max(1),
        runtime: z.number().min(0).max(1),
      })
      .describe('Relative evidence contribution weights for this conclusion'),
    inference: z
      .object({
        classification: z.enum(['benign', 'suspicious', 'malicious', 'unknown']),
        hypotheses: z.array(z.string()),
        false_positive_risks: z.array(z.string()),
        intent_assessment: IntentAssessmentSchema.optional(),
        tooling_assessment: ToolingAssessmentSchema.optional(),
      })
      .optional()
      .describe('Inference layer derived from evidence, separated for auditability'),
    recommendation: z.string().describe('Recommended next steps'),
    result_mode: z.literal('quick_profile').describe('Routing hint indicating this workflow is a quick-profile stage rather than deep reverse engineering'),
    tool_surface_role: ToolSurfaceRoleSchema.describe('Marks this workflow as a primary or compatibility surface for AI routing.'),
    preferred_primary_tools: z.array(z.string()).describe('Primary staged-runtime alternatives that should be preferred for full lifecycle analysis.'),
    recommended_next_tools: z.array(z.string()).describe('Machine-readable immediate follow-up tool suggestions'),
    next_actions: z.array(z.string()).describe('Machine-readable next-step guidance for clients'),
    raw_results: z.object({
      fingerprint: z.any().optional(),
      runtime: z.any().optional(),
      imports: z.any().optional(),
      strings: z.any().optional(),
      yara: z.any().optional(),
      static_capability: z.any().optional(),
      pe_structure: z.any().optional(),
      compiler_packer: z.any().optional(),
      string_context: z.any().optional(),
      backend_enrichments: z
        .object({
          upx: z.any().optional(),
          yara_x: z.any().optional(),
          rizin: z.any().optional(),
      })
        .optional(),
    }).describe('Raw results from individual tools'),
  })
    .extend(CoverageEnvelopeSchema.shape)
    .extend(BackendRoutingMetadataSchema.shape)
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type TriageWorkflowOutput = z.infer<typeof TriageWorkflowOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for triage workflow
 */
export const triageWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compatibility quick-profile workflow for first-pass static assessment within minutes. Use this after sample registration when you explicitly want a compact threat-oriented profile, not the primary staged analysis lifecycle. ' +
    'When the user has not chosen a workflow yet, prefer workflow.analyze.auto so the server can route by intent first. ' +
    'Do not treat this as the final reverse-engineering step; deeper analysis continues through workflow.analyze.start/status/promote, with ghidra.analyze and workflow.reconstruct as downstream deep surfaces. ' +
    'Read coverage_level, completion_state, coverage_gaps, and upgrade_paths to see exactly what quick triage did not cover yet. ' +
    '\n\nDecision guide:\n' +
    '- Use when: you need fast threat posture, runtime hints, strings/imports/YARA context, and compact triage output.\n' +
    '- Best for: small/medium samples or an explicitly requested quick profile.\n' +
    '- Large-sample pattern: prefer workflow.analyze.auto or workflow.analyze.start, then follow with workflow.analyze.status/promote instead of repeatedly calling workflow.triage.\n' +
    '- Do not use when: you already need function-level decompilation or source-like reconstruction.\n' +
    '- Typical next step: continue with workflow.analyze.start/status/promote for staged analysis, or use ghidra.analyze/workflow.reconstruct only when you intentionally need those deeper surfaces.\n' +
    '- Common mistake: assuming workflow.triage alone completes reverse engineering.',
  inputSchema: TriageWorkflowInputSchema,
  outputSchema: TriageWorkflowOutputSchema,
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Analyze imports for suspicious APIs
 * Requirements: 15.5
 */
function analyzeSuspiciousImports(imports: Record<string, string[]>): string[] {
  const suspicious: string[] = []
  
  try {
    for (const [dll, functions] of Object.entries(imports)) {
      // Ensure functions is an array
      if (!Array.isArray(functions)) {
        continue
      }
      
      for (const func of functions) {
        if (typeof func === 'string' && SUSPICIOUS_APIS.some(api => func.toLowerCase().includes(api.toLowerCase()))) {
          suspicious.push(`${dll}!${func}`)
        }
      }
    }
  } catch (error) {
    // Silently handle errors to prevent workflow failure
    console.error('Error analyzing suspicious imports:', error)
  }
  
  return suspicious
}

function summarizeStaticCapabilityResult(data: Record<string, unknown> | null | undefined) {
  if (!data || data.status !== 'ready') {
    return {
      summary: null as string | null,
      evidence: [] as string[],
      recommendation: null as string | null,
      threat_hint: false,
    }
  }

  const capabilityCount = Number(data.capability_count || 0)
  const capabilityGroups =
    data.capability_groups && typeof data.capability_groups === 'object'
      ? Object.entries(data.capability_groups as Record<string, unknown>)
          .map(([key, value]) => ({ key, count: Number(value) || 0 }))
          .sort((left, right) => right.count - left.count)
      : []
  const topGroups = capabilityGroups.slice(0, 4).map((item) => item.key)
  const threatHint = topGroups.some((item) =>
    ['persistence', 'execution', 'injection', 'command-and-control', 'c2', 'network', 'service'].includes(
      item.toLowerCase()
    )
  )

  return {
    summary:
      capabilityCount > 0
        ? `Static capability triage matched ${capabilityCount} capability finding(s)${
            topGroups.length > 0 ? ` across ${topGroups.join(', ')}` : ''
          }.`
        : null,
    evidence:
      capabilityCount > 0
        ? [
            `Static capability triage matched ${capabilityCount} capability finding(s).`,
            ...(topGroups.length > 0
              ? [`Capability groups: ${topGroups.join(', ')}.`]
              : []),
          ]
        : [],
    recommendation:
      capabilityCount > 0
        ? 'Map the recovered capability groups to concrete functions with code.functions.search, code.functions.reconstruct, or workflow.reconstruct.'
        : null,
    threat_hint: threatHint,
  }
}

function summarizePeStructureResult(data: Record<string, unknown> | null | undefined) {
  if (!data || (data.status !== 'ready' && data.status !== 'partial')) {
    return {
      summary: null as string | null,
      evidence: [] as string[],
      recommendation: null as string | null,
      packer_hint: false,
    }
  }

  const summary =
    data.summary && typeof data.summary === 'object' ? (data.summary as Record<string, unknown>) : {}
  const overlayPresent = Boolean(summary.overlay_present)
  const sectionCount = Number(summary.section_count || 0)
  const resourceCount = Number(summary.resource_count || 0)
  const forwarderCount = Number(summary.forwarder_count || 0)
  const parserPreference = typeof summary.parser_preference === 'string' ? summary.parser_preference : 'unknown'
  const overlaySuggestsPacking =
    overlayPresent &&
    data.status === 'ready' &&
    (sectionCount > 0 || resourceCount > 0 || forwarderCount > 0)

  const evidence = [
    `PE structure analysis used parser preference ${parserPreference}.`,
    `PE sections=${sectionCount}, resources=${resourceCount}, forwarders=${forwarderCount}.`,
    ...(overlayPresent ? ['PE overlay detected.'] : []),
  ]

  return {
    summary:
      sectionCount > 0
        ? `PE structure analysis recovered ${sectionCount} section(s)${
            overlayPresent ? ' and detected an overlay.' : '.'
          }`
        : null,
    evidence,
    recommendation:
      overlayPresent || resourceCount > 0
        ? 'Inspect recovered resources and any detected overlay before assuming the file layout is benign or complete.'
        : null,
    packer_hint: overlaySuggestsPacking,
  }
}

function summarizeCompilerPackerResult(data: Record<string, unknown> | null | undefined) {
  if (!data || data.status !== 'ready') {
    return {
      summary: null as string | null,
      evidence: [] as string[],
      recommendation: null as string | null,
      packer_hint: false,
    }
  }

  const summary =
    data.summary && typeof data.summary === 'object' ? (data.summary as Record<string, unknown>) : {}
  const compilerCount = Number(summary.compiler_count || 0)
  const packerCount = Number(summary.packer_count || 0)
  const protectorCount = Number(summary.protector_count || 0)
  const primaryFileType =
    typeof summary.likely_primary_file_type === 'string' ? summary.likely_primary_file_type : null

  const findingsByCategory = (field: string) =>
    Array.isArray(data[field]) ? (data[field] as Array<Record<string, unknown>>) : []
  const compilerNames = findingsByCategory('compiler_findings')
    .slice(0, 3)
    .map((item) => String(item.name))
  const packerNames = [
    ...findingsByCategory('packer_findings').slice(0, 3),
    ...findingsByCategory('protector_findings').slice(0, 3),
  ].map((item) => String(item.name))

  return {
    summary:
      compilerCount + packerCount + protectorCount > 0
        ? `Toolchain attribution suggests ${
            packerNames.length > 0
              ? `packer/protector signals (${packerNames.join(', ')})`
              : compilerNames.length > 0
                ? `compiler signals (${compilerNames.join(', ')})`
                : 'additional toolchain hints'
          }.`
        : null,
    evidence: [
      `Compiler/packer attribution found compiler=${compilerCount}, packer=${packerCount}, protector=${protectorCount}.`,
      ...(primaryFileType ? [`Primary file type attribution: ${primaryFileType}.`] : []),
    ],
    recommendation:
      packerCount > 0 || protectorCount > 0
        ? 'Treat this sample as packed or protected until deeper static analysis or runtime evidence disproves it.'
        : null,
    packer_hint: packerCount > 0 || protectorCount > 0,
  }
}

function summarizeStringContextResult(data: Record<string, unknown> | null | undefined) {
  if (!data || (data.status !== 'ready' && data.status !== 'partial')) {
    return {
      summary: null as string | null,
      evidence: [] as string[],
      recommendation: null as string | null,
      context_hint: false,
    }
  }

  const mergedStrings =
    data.merged_strings && typeof data.merged_strings === 'object'
      ? (data.merged_strings as Record<string, unknown>)
      : {}
  const functionContexts = Array.isArray(data.function_contexts)
    ? (data.function_contexts as Array<Record<string, unknown>>)
    : []
  const analystRelevantCount = Number(mergedStrings.analyst_relevant_count || 0)
  const topFunctions = functionContexts
    .slice(0, 3)
    .map((item) => String(item.function || item.address || 'unknown'))
  const xrefStatus = typeof data.xref_status === 'string' ? data.xref_status : 'unavailable'

  return {
    summary:
      analystRelevantCount > 0 || functionContexts.length > 0
        ? xrefStatus === 'available'
          ? `Context-linking retained ${analystRelevantCount} analyst-relevant string(s) and mapped them to ${functionContexts.length} compact function context(s).`
          : `Context-linking retained ${analystRelevantCount} analyst-relevant string(s), but Ghidra-backed function attribution is still unavailable.`
        : null,
    evidence: [
      `Context-linking retained ${analystRelevantCount} analyst-relevant string(s).`,
      ...(xrefStatus === 'available'
        ? [`Compact function contexts recovered: ${functionContexts.length}.`]
        : ['Compact string context is currently string-only because Ghidra-backed attribution is unavailable.']),
      ...(topFunctions.length > 0 ? [`Top correlated functions: ${topFunctions.join(', ')}.`] : []),
    ],
    recommendation:
      xrefStatus === 'available' && functionContexts.length > 0
        ? 'Use code.xrefs.analyze or code.function.decompile on the highest-signal correlated function before jumping to full reconstruction.'
        : xrefStatus !== 'available'
          ? 'Run ghidra.analyze first if you need string-to-function or API-to-function attribution before deeper reconstruction.'
          : null,
    context_hint: functionContexts.length > 0,
  }
}

function findDefaultYaraXRulesPath(): string | null {
  const candidates = [
    path.join(process.cwd(), 'workers', 'yara_rules', 'malware_families.yar'),
    path.join(process.cwd(), 'workers', 'yara_rules', 'default.yar'),
  ]

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate
    }
  }

  return null
}

function trimText(value: unknown, maxLength = 180): string {
  const text = String(value ?? '')
  if (text.length <= maxLength) {
    return text
  }
  return `${text.slice(0, Math.max(0, maxLength - 3))}...`
}

function compactGroupedImports(
  value: unknown,
  maxGroups = 10,
  maxFunctionsPerGroup = 8
): { values: Record<string, string[]>; totalGroups: number; totalFunctions: number; truncated: boolean } {
  if (!value || typeof value !== 'object') {
    return {
      values: {},
      totalGroups: 0,
      totalFunctions: 0,
      truncated: false,
    }
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .map(([name, functions]) => ({
      name,
      functions: Array.isArray(functions)
        ? functions
            .map((item) => String(item).trim())
            .filter((item) => item.length > 0)
        : [],
    }))
    .filter((entry) => entry.functions.length > 0)
    .sort((left, right) => right.functions.length - left.functions.length || left.name.localeCompare(right.name))

  const previewEntries = entries.slice(0, maxGroups).map((entry) => [
    entry.name,
    entry.functions.slice(0, maxFunctionsPerGroup),
  ] as const)

  const previewFunctionCount = previewEntries.reduce((total, [, functions]) => total + functions.length, 0)
  const totalFunctions = entries.reduce((total, entry) => total + entry.functions.length, 0)

  return {
    values: Object.fromEntries(previewEntries),
    totalGroups: entries.length,
    totalFunctions,
    truncated: entries.length > maxGroups || previewFunctionCount < totalFunctions,
  }
}

function compactFingerprintRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  return {
    machine: record.machine ?? null,
    machine_name: record.machine_name ?? null,
    subsystem: record.subsystem ?? null,
    subsystem_name: record.subsystem_name ?? null,
    timestamp_iso: record.timestamp_iso ?? null,
    imphash: record.imphash ?? null,
    entry_point: record.entry_point ?? null,
    image_base: record.image_base ?? null,
    sections: Array.isArray(record.sections) ? record.sections.slice(0, 8) : [],
    section_count: Array.isArray(record.sections) ? record.sections.length : 0,
    signature: record.signature ?? null,
    _parser: record._parser ?? null,
    _pefile_error: record._pefile_error ?? null,
  }
}

function compactRuntimeRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  const suspected = Array.isArray(record.suspected)
    ? record.suspected.slice(0, 8).map((item) => {
        const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
        return {
          runtime: entry.runtime ?? null,
          confidence: entry.confidence ?? null,
          evidence: Array.isArray(entry.evidence) ? entry.evidence.slice(0, 4).map((value) => trimText(value, 140)) : [],
        }
      })
    : []
  const importDlls = Array.isArray(record.import_dlls)
    ? record.import_dlls.slice(0, 20).map((item) => String(item))
    : []

  return {
    is_dotnet: record.is_dotnet ?? false,
    dotnet_version: record.dotnet_version ?? null,
    target_framework: record.target_framework ?? null,
    suspected,
    import_dlls: importDlls,
    import_dll_count: Array.isArray(record.import_dlls) ? record.import_dlls.length : importDlls.length,
  }
}

function compactImportsRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  const imports = compactGroupedImports(record.imports, 10, 8)
  const delayImports = compactGroupedImports(record.delay_imports, 8, 6)

  return {
    imports: imports.values,
    total_dlls: imports.totalGroups,
    total_functions: imports.totalFunctions,
    imports_truncated: imports.truncated,
    delay_imports: delayImports.values,
    total_delay_dlls: delayImports.totalGroups,
    total_delay_functions: delayImports.totalFunctions,
    delay_imports_truncated: delayImports.truncated,
    _parser: record._parser ?? null,
    _pefile_error: record._pefile_error ?? null,
  }
}

function compactStringsRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  const strings = Array.isArray(record.strings) ? record.strings.slice(0, 20) : []
  const summary = record.summary && typeof record.summary === 'object' ? (record.summary as Record<string, unknown>) : null
  const topHighValue = Array.isArray(summary?.top_high_value)
    ? summary!.top_high_value.slice(0, 12).map((item) => {
        const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
        return {
          offset: entry.offset ?? null,
          string: trimText(entry.string ?? '', 160),
          encoding: entry.encoding ?? null,
          categories: Array.isArray(entry.categories) ? entry.categories.slice(0, 6).map((value) => String(value)) : [],
        }
      })
    : []
  const contextWindows = Array.isArray(summary?.context_windows)
    ? summary!.context_windows.slice(0, 4).map((item) => {
        const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
        const stringsInWindow = Array.isArray(entry.strings)
          ? entry.strings.slice(0, 5).map((windowItem) => {
              const stringEntry =
                windowItem && typeof windowItem === 'object' ? (windowItem as Record<string, unknown>) : {}
              return {
                offset: stringEntry.offset ?? null,
                string: trimText(stringEntry.string ?? '', 140),
                encoding: stringEntry.encoding ?? null,
                categories: Array.isArray(stringEntry.categories)
                  ? stringEntry.categories.slice(0, 4).map((value) => String(value))
                  : [],
              }
            })
          : []
        return {
          start_offset: entry.start_offset ?? null,
          end_offset: entry.end_offset ?? null,
          score: entry.score ?? null,
          categories: Array.isArray(entry.categories) ? entry.categories.slice(0, 6).map((value) => String(value)) : [],
          strings: stringsInWindow,
        }
      })
    : []

  return {
    strings,
    count: record.count ?? null,
    total_count: record.total_count ?? null,
    pre_filter_count: record.pre_filter_count ?? null,
    truncated: record.truncated ?? null,
    max_strings: record.max_strings ?? null,
    max_string_length: record.max_string_length ?? null,
    min_len: record.min_len ?? null,
    encoding_filter: record.encoding_filter ?? null,
    category_filter: record.category_filter ?? null,
    summary: summary
      ? {
          cluster_counts: summary.cluster_counts ?? {},
          top_high_value: topHighValue,
          context_windows: contextWindows,
        }
      : null,
  }
}

function compactYaraRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  const matches = Array.isArray(record.matches)
    ? record.matches.slice(0, 12).map((item) => {
        const match = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
        return {
          rule: match.rule ?? null,
          tags: Array.isArray(match.tags) ? match.tags.slice(0, 8).map((value) => String(value)) : [],
          meta: match.meta ?? {},
          strings: Array.isArray(match.strings)
            ? match.strings.slice(0, 5).map((matchString) => {
                const stringEntry =
                  matchString && typeof matchString === 'object' ? (matchString as Record<string, unknown>) : {}
                return {
                  identifier: stringEntry.identifier ?? null,
                  offset: stringEntry.offset ?? null,
                  matched_data: trimText(stringEntry.matched_data ?? '', 96),
                  location: stringEntry.location ?? null,
                }
              })
            : [],
          confidence: match.confidence ?? null,
          evidence: match.evidence
            ? {
                import_dll_hits: Array.isArray((match.evidence as Record<string, unknown>).import_dll_hits)
                  ? ((match.evidence as Record<string, unknown>).import_dll_hits as unknown[]).slice(0, 8).map(String)
                  : [],
                import_api_hits: Array.isArray((match.evidence as Record<string, unknown>).import_api_hits)
                  ? ((match.evidence as Record<string, unknown>).import_api_hits as unknown[]).slice(0, 8).map(String)
                  : [],
                section_hits: Array.isArray((match.evidence as Record<string, unknown>).section_hits)
                  ? ((match.evidence as Record<string, unknown>).section_hits as unknown[]).slice(0, 8).map(String)
                  : [],
                near_entrypoint_hits: (match.evidence as Record<string, unknown>).near_entrypoint_hits ?? null,
                string_only: (match.evidence as Record<string, unknown>).string_only ?? null,
              }
            : null,
          inference: match.inference ?? null,
        }
      })
    : []

  return {
    matches,
    match_count: Array.isArray(record.matches) ? record.matches.length : matches.length,
    ruleset_version: record.ruleset_version ?? null,
    timed_out: record.timed_out ?? null,
    rule_set: record.rule_set ?? null,
    rule_tier: record.rule_tier ?? null,
    confidence_summary: record.confidence_summary ?? null,
    import_evidence: record.import_evidence ?? null,
    quality_notes: Array.isArray(record.quality_notes)
      ? record.quality_notes.slice(0, 8).map((item) => trimText(item, 180))
      : [],
  }
}

function compactStaticCapabilityRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  return {
    status: record.status ?? null,
    sample_id: record.sample_id ?? null,
    capability_count: record.capability_count ?? 0,
    behavior_namespaces: Array.isArray(record.behavior_namespaces)
      ? record.behavior_namespaces.slice(0, 12).map((item) => String(item))
      : [],
    capability_groups: record.capability_groups ?? {},
    capabilities: Array.isArray(record.capabilities)
      ? record.capabilities.slice(0, 15).map((item) => {
          const capability = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          return {
            rule_id: capability.rule_id ?? null,
            name: capability.name ?? null,
            namespace: capability.namespace ?? null,
            scopes: Array.isArray(capability.scopes) ? capability.scopes.slice(0, 6).map((value) => String(value)) : [],
            group: capability.group ?? null,
            confidence: capability.confidence ?? null,
            match_count: capability.match_count ?? null,
            evidence_summary: trimText(capability.evidence_summary ?? '', 180),
          }
        })
      : [],
    summary: record.summary ?? null,
    backend: record.backend ?? null,
    confidence_semantics: record.confidence_semantics ?? null,
    analysis_id: record.analysis_id ?? null,
    artifact: record.artifact ?? null,
  }
}

function compactPeStructureRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  const imports = record.imports && typeof record.imports === 'object' ? (record.imports as Record<string, unknown>) : {}
  const importPreview = compactGroupedImports(imports.imports, 10, 8)
  const delayedImportPreview = compactGroupedImports(imports.delayed_imports, 8, 6)
  const exportsValue =
    record.exports && typeof record.exports === 'object' ? (record.exports as Record<string, unknown>) : {}
  const resourcesValue =
    record.resources && typeof record.resources === 'object' ? (record.resources as Record<string, unknown>) : {}
  const backendDetails =
    record.backend_details && typeof record.backend_details === 'object'
      ? Object.fromEntries(
          Object.entries(record.backend_details as Record<string, unknown>).map(([backendName, backendValue]) => {
            const backendRecord =
              backendValue && typeof backendValue === 'object' ? (backendValue as Record<string, unknown>) : {}
            return [
              backendName,
              {
                parser: backendRecord.parser ?? null,
                available: backendRecord.available ?? null,
                status: backendRecord.status ?? null,
                warnings: Array.isArray(backendRecord.warnings)
                  ? backendRecord.warnings.slice(0, 3).map((item) => trimText(item, 160))
                  : [],
                error: backendRecord.error ? trimText(backendRecord.error, 180) : null,
              },
            ]
          })
        )
      : {}

  return {
    status: record.status ?? null,
    sample_id: record.sample_id ?? null,
    summary: record.summary ?? null,
    headers: record.headers ?? null,
    entry_point: record.entry_point ?? null,
    sections: Array.isArray(record.sections) ? record.sections.slice(0, 8) : [],
    imports: {
      imports: importPreview.values,
      delayed_imports: delayedImportPreview.values,
      total_dlls:
        imports.total_dlls ??
        importPreview.totalGroups,
      total_delayed_dlls:
        imports.total_delayed_dlls ??
        delayedImportPreview.totalGroups,
      total_functions:
        imports.total_functions ??
        importPreview.totalFunctions,
      total_delayed_functions:
        imports.total_delayed_functions ??
        delayedImportPreview.totalFunctions,
      truncated: importPreview.truncated || delayedImportPreview.truncated,
    },
    exports: {
      exports: Array.isArray(exportsValue.exports) ? exportsValue.exports.slice(0, 12) : [],
      forwarders: Array.isArray(exportsValue.forwarders) ? exportsValue.forwarders.slice(0, 12) : [],
      total_exports: exportsValue.total_exports ?? 0,
      total_forwarders: exportsValue.total_forwarders ?? 0,
    },
    resources: {
      present: resourcesValue.present ?? null,
      type_count: resourcesValue.type_count ?? 0,
      entry_count: resourcesValue.entry_count ?? 0,
      types: Array.isArray(resourcesValue.types) ? resourcesValue.types.slice(0, 12) : [],
      entries: Array.isArray(resourcesValue.entries) ? resourcesValue.entries.slice(0, 12) : [],
    },
    overlay: record.overlay ?? null,
    backend_details: backendDetails,
    confidence_semantics: record.confidence_semantics ?? null,
    analysis_id: record.analysis_id ?? null,
    artifact: record.artifact ?? null,
  }
}

function compactCompilerPackerRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  const limitFindings = (value: unknown) =>
    Array.isArray(value)
      ? value.slice(0, 10).map((item) => {
          const finding = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          return {
            name: finding.name ?? null,
            category: finding.category ?? null,
            confidence: finding.confidence ?? null,
            evidence_summary: trimText(finding.evidence_summary ?? '', 180),
            source: finding.source ?? null,
          }
        })
      : []

  return {
    status: record.status ?? null,
    sample_id: record.sample_id ?? null,
    compiler_findings: limitFindings(record.compiler_findings),
    packer_findings: limitFindings(record.packer_findings),
    protector_findings: limitFindings(record.protector_findings),
    file_type_findings: limitFindings(record.file_type_findings),
    summary: record.summary ?? null,
    backend: record.backend ?? null,
    confidence_semantics: record.confidence_semantics ?? null,
    analysis_id: record.analysis_id ?? null,
    artifact: record.artifact ?? null,
  }
}

function compactArtifactRefs(value: unknown, maxItems = 4) {
  return Array.isArray(value)
    ? value.slice(0, maxItems).map((item) => {
        const record = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
        return {
          id: record.id ?? null,
          type: record.type ?? null,
          path: record.path ?? null,
        }
      })
    : []
}

function compactStringContextRawResult(data: unknown) {
  if (!data || typeof data !== 'object') {
    return data ?? null
  }

  const record = data as Record<string, unknown>
  const mergedStrings =
    record.merged_strings && typeof record.merged_strings === 'object'
      ? (record.merged_strings as Record<string, unknown>)
      : {}
  const topHighlights = (field: string, limit: number) =>
    Array.isArray(mergedStrings[field])
      ? (mergedStrings[field] as unknown[]).slice(0, limit).map((item) => {
          const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          return {
            value: trimText(entry.value ?? '', 140),
            offset: entry.offset ?? null,
            categories: Array.isArray(entry.categories)
              ? entry.categories.slice(0, 4).map((value) => String(value))
              : [],
            labels: Array.isArray(entry.labels)
              ? entry.labels.slice(0, 4).map((value) => String(value))
              : [],
            confidence: entry.confidence ?? null,
            score: entry.score ?? null,
          }
        })
      : []
  const functionContexts = Array.isArray(record.function_contexts)
    ? record.function_contexts.slice(0, 6).map((item) => {
        const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
        return {
          function: entry.function ?? null,
          address: entry.address ?? null,
          score: entry.score ?? null,
          top_strings: Array.isArray(entry.top_strings)
            ? entry.top_strings.slice(0, 3).map((value) => trimText(value, 120))
            : [],
          top_categories: Array.isArray(entry.top_categories)
            ? entry.top_categories.slice(0, 5).map((value) => String(value))
            : [],
          sensitive_apis: Array.isArray(entry.sensitive_apis)
            ? entry.sensitive_apis.slice(0, 5).map((value) => String(value))
            : [],
          rationale: Array.isArray(entry.rationale)
            ? entry.rationale.slice(0, 4).map((value) => trimText(value, 120))
            : [],
        }
      })
    : []

  return {
    status: record.status ?? null,
    xref_status: record.xref_status ?? null,
    summary: trimText(record.summary ?? '', 220),
    merged_strings: {
      status: mergedStrings.status ?? null,
      total_records: mergedStrings.total_records ?? 0,
      kept_records: mergedStrings.kept_records ?? 0,
      analyst_relevant_count: mergedStrings.analyst_relevant_count ?? 0,
      runtime_noise_count: mergedStrings.runtime_noise_count ?? 0,
      encoded_candidate_count: mergedStrings.encoded_candidate_count ?? 0,
      merged_sources: mergedStrings.merged_sources ?? false,
      truncated: mergedStrings.truncated ?? false,
      top_suspicious: topHighlights('top_suspicious', 6),
      top_iocs: topHighlights('top_iocs', 6),
      top_decoded: topHighlights('top_decoded', 4),
      context_windows: Array.isArray(mergedStrings.context_windows)
        ? (mergedStrings.context_windows as unknown[]).slice(0, 3)
        : [],
    },
    function_contexts: functionContexts,
    source_artifact_refs: compactArtifactRefs(record.source_artifact_refs, 4),
    artifact:
      record.artifact && typeof record.artifact === 'object'
        ? compactArtifactRefs([record.artifact], 1)[0]
        : null,
  }
}

function buildCompactRawResults(results: {
  fingerprint: unknown
  runtime: unknown
  imports: unknown
  strings: unknown
  yara: unknown
  staticCapability: unknown
  peStructure: unknown
  compilerPacker: unknown
  stringContext: unknown
  backendEnrichments?: unknown
}) {
  return {
    fingerprint: compactFingerprintRawResult(results.fingerprint),
    runtime: compactRuntimeRawResult(results.runtime),
    imports: compactImportsRawResult(results.imports),
    strings: compactStringsRawResult(results.strings),
    yara: compactYaraRawResult(results.yara),
    static_capability: compactStaticCapabilityRawResult(results.staticCapability),
    pe_structure: compactPeStructureRawResult(results.peStructure),
    compiler_packer: compactCompilerPackerRawResult(results.compilerPacker),
    string_context: compactStringContextRawResult(results.stringContext),
    backend_enrichments: results.backendEnrichments ?? null,
  }
}

function summarizeWorkflowWarnings(allWarnings: string[]) {
  const uniqueWarnings = Array.from(new Set(allWarnings.filter((item) => item.trim().length > 0)))
  const cacheTiers = new Set<string>()
  let cacheResultCount = 0
  const nonCacheWarnings: string[] = []

  for (const warning of uniqueWarnings) {
    if (/^Result from cache$/i.test(warning)) {
      cacheResultCount += 1
      continue
    }

    const cacheMatch = warning.match(/^Cache details:\s*tier=([^,]+)/i)
    if (cacheMatch) {
      cacheResultCount += 1
      cacheTiers.add(cacheMatch[1])
      continue
    }

    nonCacheWarnings.push(trimText(warning, 220))
  }

  const summarized = [...nonCacheWarnings]
  if (cacheResultCount > 0) {
    summarized.unshift(
      `Reused ${cacheResultCount} cached sub-result(s)${
        cacheTiers.size > 0 ? ` from ${Array.from(cacheTiers).join(', ')} cache` : ''
      }.`
    )
  }

  return summarized.slice(0, 12)
}

function hasCryptoCapabilitySignals(result: WorkerResult | undefined): boolean {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  const namespaces = Array.isArray(data.behavior_namespaces)
    ? data.behavior_namespaces.map((item) => String(item))
    : []
  if (namespaces.some((item) => /(crypt|aes|rsa|hash|cipher|key|decrypt|encrypt)/i.test(item))) {
    return true
  }
  const groups = data.capability_groups && typeof data.capability_groups === 'object'
    ? Object.keys(data.capability_groups as Record<string, unknown>)
    : []
  if (groups.some((item) => /(crypt|aes|rsa|hash|cipher|key|decrypt|encrypt)/i.test(item))) {
    return true
  }
  const capabilities = Array.isArray(data.capabilities) ? data.capabilities : []
  return capabilities.some((item) => {
    const capability = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
    return [capability.name, capability.namespace, capability.group]
      .map((entry) => (typeof entry === 'string' ? entry : ''))
      .some((entry) => /(crypt|aes|rsa|hash|cipher|key|decrypt|encrypt)/i.test(entry))
  })
}

function hasCryptoContextSignals(result: WorkerResult | undefined): boolean {
  const data = result?.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  const contexts = Array.isArray(data.function_contexts) ? data.function_contexts : []
  return contexts.some((item) => {
    const context = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
    const values = [
      ...(Array.isArray(context.sensitive_apis) ? context.sensitive_apis.map((entry) => String(entry)) : []),
      ...(Array.isArray(context.top_strings) ? context.top_strings.map((entry) => String(entry)) : []),
      ...(Array.isArray(context.rationale) ? context.rationale.map((entry) => String(entry)) : []),
    ]
    return values.some((entry) => /(crypt|aes|rsa|hash|cipher|key|decrypt|encrypt|cbc|gcm|ctr|rc4|chacha|salsa)/i.test(entry))
  })
}

/**
 * Analyze strings for suspicious patterns
 * Requirements: 15.5
 */
function normalizeStringEntry(entry: unknown): string | null {
  if (typeof entry === 'string') {
    return entry
  }

  if (
    entry &&
    typeof entry === 'object' &&
    'string' in entry &&
    typeof (entry as { string?: unknown }).string === 'string'
  ) {
    return (entry as { string: string }).string
  }

  return null
}

export function extractCrateNameFromCargoPath(input: string): string | null {
  const normalized = input.replace(/\//g, '\\')
  const match = normalized.match(
    /cargo\\(?:registry\\src|git\\checkouts)\\[^\\]+\\([^\\]+)(?:\\|$)/i
  )
  if (!match?.[1]) {
    return null
  }

  const rawCrate = match[1].trim()
  if (!rawCrate) {
    return null
  }

  const versionMatch = rawCrate.match(/^(.*)-\d[\w.+-]*$/)
  const crateName = versionMatch?.[1] || rawCrate
  return crateName.trim() || null
}

function detectLibraryHints(str: string): string[] {
  return NOTABLE_LIBRARY_HINTS
    .filter((hint) => hint.patterns.some((pattern) => pattern.test(str)))
    .map((hint) => hint.name)
}

function analyzeSuspiciousStrings(strings: unknown[]): {
  suspicious: string[]
  urls: string[]
  ips: string[]
  paths: string[]
  registry: string[]
  commands: string[]
  pipes: string[]
  cargoPaths: string[]
  rustMarkers: string[]
  crateNames: string[]
  libraryHints: string[]
} {
  const suspicious: string[] = []
  const urls: string[] = []
  const ips: string[] = []
  const paths: string[] = []
  const registry: string[] = []
  const commands: string[] = []
  const pipes: string[] = []
  const cargoPaths: string[] = []
  const rustMarkers: string[] = []
  const crateNames: string[] = []
  const libraryHints: string[] = []
  
  for (const rawEntry of strings) {
    const str = normalizeStringEntry(rawEntry)
    if (!str) {
      continue
    }

    // Check for URLs
    const urlMatch = str.match(/https?:\/\/[^\s]+/i)
    if (urlMatch) {
      urls.push(urlMatch[0])
      suspicious.push(str)
    }
    
    // Check for IP addresses
    const ipMatch = str.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    if (ipMatch) {
      ips.push(ipMatch[0])
      suspicious.push(str)
    }
    
    // Check for file paths
    const pathMatch = str.match(/[A-Za-z]:\\[^\s]+/)
    if (pathMatch) {
      paths.push(pathMatch[0])
      if (pathMatch[0].toLowerCase().includes('temp') || 
          pathMatch[0].toLowerCase().includes('appdata')) {
        suspicious.push(str)
      }
    }
    
    // Check for registry keys
    const regMatch = str.match(/HKEY_[A-Z_]+\\[^\s]+/i)
    if (regMatch) {
      registry.push(regMatch[0])
      suspicious.push(str)
    }
    
    // Check for shell executables
    if (/cmd\.exe|powershell\.exe|wscript\.exe/i.test(str)) {
      suspicious.push(str)
      commands.push(str)
    }

    // Check for named pipes / IPC
    const pipeMatch = str.match(/\\\\\.\\pipe\\[^\s]+|\\\\pipe\\[^\s]+/i)
    if (pipeMatch) {
      pipes.push(pipeMatch[0])
      suspicious.push(str)
    }

    // Split compiler/toolchain artifacts from high-value IOC
    const cargoMatch = str.match(/cargo\\registry\\src\\[^\s]+/i)
    if (cargoMatch) {
      cargoPaths.push(cargoMatch[0])
      const crateName = extractCrateNameFromCargoPath(cargoMatch[0])
      if (crateName) {
        crateNames.push(crateName)
      }
    }

    if (/rust_panic|core::panicking|\\src\\main\.rs|\\src\\lib\.rs/i.test(str)) {
      rustMarkers.push(str)
    }

    libraryHints.push(...detectLibraryHints(str))
  }
  
  return {
    suspicious: [...new Set(suspicious)],  // Remove duplicates
    urls: [...new Set(urls)],
    ips: [...new Set(ips)],
    paths: [...new Set(paths)],
    registry: [...new Set(registry)],
    commands: [...new Set(commands)],
    pipes: [...new Set(pipes)],
    cargoPaths: [...new Set(cargoPaths)],
    rustMarkers: [...new Set(rustMarkers)],
    crateNames: [...new Set(crateNames)],
    libraryHints: [...new Set(libraryHints)],
  }
}

interface YaraSignal {
  rule: string
  level: 'low' | 'medium' | 'high' | 'unknown'
  score: number
  stringOnly: boolean
  generic: boolean
}

interface IntentAssessment {
  label: 'dual_use_tool' | 'operator_utility' | 'malware_like_payload' | 'unknown'
  confidence: number
  evidence: string[]
  counter_evidence: string[]
}

export interface LibraryProfile {
  ecosystems: string[]
  top_crates: string[]
  notable_libraries: string[]
  evidence: string[]
}

interface ToolingAssessment {
  help_text_detected: boolean
  cli_surface_detected: boolean
  framework_hints: string[]
  toolchain_markers: string[]
  library_profile?: LibraryProfile
}

function normalizeEcosystemLabel(value: string): string | null {
  const lowered = value.toLowerCase()
  if (lowered.includes('rust')) {
    return 'rust'
  }
  if (lowered.includes('dotnet') || lowered.includes('.net') || lowered.includes('clr')) {
    return '.net'
  }
  if (lowered.includes('go')) {
    return 'go'
  }
  if (lowered.includes('native') || lowered.includes('c++') || lowered.includes('pe')) {
    return 'native'
  }
  return null
}

export function buildLibraryProfile(
  stringAnalysis: Pick<
    ReturnType<typeof analyzeSuspiciousStrings>,
    'cargoPaths' | 'crateNames' | 'libraryHints' | 'rustMarkers'
  >,
  runtime: any
): LibraryProfile | undefined {
  const ecosystems = new Set<string>()
  const crateCounts = new Map<string, number>()

  for (const runtimeHint of Array.isArray(runtime?.suspected) ? runtime.suspected : []) {
    const runtimeName = typeof runtimeHint?.runtime === 'string' ? runtimeHint.runtime : ''
    const ecosystem = normalizeEcosystemLabel(runtimeName)
    if (ecosystem) {
      ecosystems.add(ecosystem)
    }
  }

  if (
    stringAnalysis.cargoPaths.length > 0 ||
    stringAnalysis.rustMarkers.length > 0 ||
    stringAnalysis.crateNames.length > 0
  ) {
    ecosystems.add('rust')
  }

  for (const crateName of [...stringAnalysis.crateNames, ...stringAnalysis.libraryHints]) {
    const normalized = crateName.trim().toLowerCase()
    if (!normalized) {
      continue
    }
    crateCounts.set(normalized, (crateCounts.get(normalized) || 0) + 1)
  }

  const rankedCrates = Array.from(crateCounts.entries())
    .sort((left, right) => {
      if (right[1] !== left[1]) {
        return right[1] - left[1]
      }
      return left[0].localeCompare(right[0])
    })
    .map(([crate]) => crate)

  const topCrates = rankedCrates.slice(0, 8)
  const notableLibraries = Array.from(
    new Set(
      rankedCrates.filter((crate) =>
        NOTABLE_LIBRARY_HINTS.some((hint) => hint.name.toLowerCase() === crate)
      )
    )
  ).slice(0, 8)

  const evidence: string[] = []
  if (topCrates.length > 0) {
    evidence.push(`Cargo/library references observed: ${topCrates.slice(0, 5).join(', ')}`)
  }
  if (stringAnalysis.cargoPaths.length > 0) {
    evidence.push(
      `Cargo registry paths observed: ${stringAnalysis.cargoPaths.slice(0, 2).join(' | ')}`
    )
  }
  if (stringAnalysis.rustMarkers.length > 0) {
    evidence.push(
      `Rust toolchain markers observed: ${stringAnalysis.rustMarkers.slice(0, 2).join(' | ')}`
    )
  }
  if (ecosystems.size > 0) {
    evidence.push(`Ecosystem hints: ${Array.from(ecosystems).join(', ')}`)
  }

  if (ecosystems.size === 0 && topCrates.length === 0 && notableLibraries.length === 0) {
    return undefined
  }

  return {
    ecosystems: Array.from(ecosystems),
    top_crates: topCrates,
    notable_libraries: notableLibraries,
    evidence: Array.from(new Set(evidence)),
  }
}

function summarizeLibraryProfile(profile?: LibraryProfile): string {
  if (!profile) {
    return ''
  }

  const libraries = profile.notable_libraries.length > 0
    ? profile.notable_libraries
    : profile.top_crates
  if (libraries.length === 0) {
    return profile.ecosystems.join(', ')
  }

  return libraries.slice(0, 3).join(' + ')
}

function downgradeYaraLevel(level: YaraSignal['level']): YaraSignal['level'] {
  if (level === 'high') {
    return 'medium'
  }
  if (level === 'medium') {
    return 'low'
  }
  return 'low'
}

function normalizeYaraSignals(matches: unknown[]): YaraSignal[] {
  if (!Array.isArray(matches)) {
    return []
  }

  return matches
    .map((match) => {
      const rule = typeof (match as { rule?: unknown })?.rule === 'string'
        ? String((match as { rule: string }).rule)
        : ''
      if (!rule) {
        return null
      }

      const levelRaw = typeof (match as { confidence?: { level?: unknown } })?.confidence?.level === 'string'
        ? String((match as { confidence?: { level?: string } }).confidence?.level).toLowerCase()
        : 'unknown'
      const level: YaraSignal['level'] =
        levelRaw === 'high' || levelRaw === 'medium' || levelRaw === 'low'
          ? levelRaw
          : 'unknown'
      const numericScore = Number((match as { confidence?: { score?: unknown } })?.confidence?.score || 0)
      const stringOnly = Boolean((match as { evidence?: { string_only?: unknown } })?.evidence?.string_only)
      const loweredRule = rule.toLowerCase()

      return {
        rule,
        level,
        score: Number.isFinite(numericScore) ? numericScore : 0,
        stringOnly,
        generic:
          loweredRule.includes('generic') ||
          (loweredRule.includes('trojan') && !loweredRule.includes('downloader') && !loweredRule.includes('backdoor')),
      } satisfies YaraSignal
    })
    .filter((item): item is YaraSignal => Boolean(item))
}

function assessIntentAndTooling(
  stringsSummary: any,
  suspiciousImports: string[],
  stringAnalysis: ReturnType<typeof analyzeSuspiciousStrings>,
  yaraSignals: YaraSignal[],
  runtime: any
): { intent: IntentAssessment; tooling: ToolingAssessment } {
  const contextWindows = Array.isArray(stringsSummary?.context_windows)
    ? stringsSummary.context_windows
    : []
  const windowTexts = contextWindows.map((window: any) =>
    Array.isArray(window?.strings)
      ? window.strings
          .map((entry: any) => String(entry?.string || ''))
          .filter((item: string) => item.length > 0)
          .join('\n')
      : ''
  )
  const joinedWindows = windowTexts.join('\n').toLowerCase()
  const helpTextDetected = /usage:|options?:|examples?:|--help\b|-h\b|commands?:|syntax:/.test(
    joinedWindows
  )
  const cliSurfaceDetected =
    /--[a-z0-9_-]+|-[a-z0-9]\b/.test(joinedWindows) ||
    /\b(pid|process|thread|target|list|inject|suspend|resume|kill|dump)\b/.test(joinedWindows)

  const importApis = suspiciousImports.map((item) => (item.split('!').pop() || item).toLowerCase())
  const processOpsCount = importApis.filter((api) =>
    [
      'openprocess',
      'writeprocessmemory',
      'createremotethread',
      'virtualallocex',
      'suspendthread',
      'resumethread',
      'terminatethread',
      'terminateprocess',
    ].some((needle) => api.includes(needle))
  ).length

  const malwareSpecificYara = yaraSignals.some((signal) =>
    /ransomware|backdoor|downloader|keylogger/.test(signal.rule.toLowerCase()) &&
    signal.level !== 'low'
  )
  const networkBehavior = stringAnalysis.urls.length > 0 || stringAnalysis.ips.length > 0
  const persistenceBehavior = stringAnalysis.registry.length > 0
  const suspectedRuntimes: string[] = Array.isArray(runtime?.suspected)
    ? runtime.suspected
        .map((item: any) => String(item?.runtime || '').trim())
        .filter((item: string) => item.length > 0)
    : []
  const toolchainMarkers: string[] = [
    ...(
      Array.isArray(runtime?.suspected)
        ? runtime.suspected
            .map((item: any) =>
              `${String(item?.runtime || '').trim()}${
                typeof item?.confidence === 'number' ? `(${item.confidence.toFixed(2)})` : ''
              }`
            )
            .filter((item: string) => item.length > 0)
        : []
    ),
    ...stringAnalysis.cargoPaths.slice(0, 5),
    ...stringAnalysis.rustMarkers.slice(0, 5),
  ]

  const libraryProfile = buildLibraryProfile(stringAnalysis, runtime)
  const frameworkHints: string[] = Array.from(
    new Set([
      ...suspectedRuntimes,
      ...(libraryProfile?.ecosystems || []),
      ...(libraryProfile?.notable_libraries.slice(0, 3) || []),
    ])
  )

  if (
    helpTextDetected &&
    cliSurfaceDetected &&
    processOpsCount > 0 &&
    !malwareSpecificYara &&
    !networkBehavior &&
    !persistenceBehavior
  ) {
    return {
      intent: {
        label: 'dual_use_tool',
        confidence: 0.78,
        evidence: [
          'Long-form help/usage text grouped in nearby string windows.',
          'CLI-style options and operator verbs are present.',
          'Process-operation APIs are present without stronger malware-specific corroboration.',
        ],
        counter_evidence: [
          'Static evidence alone cannot rule out malicious repurposing of the tool.',
        ],
      },
      tooling: {
        help_text_detected: helpTextDetected,
        cli_surface_detected: cliSurfaceDetected,
        framework_hints: frameworkHints,
        toolchain_markers: toolchainMarkers.slice(0, 10),
        library_profile: libraryProfile,
      },
    }
  }

  if (helpTextDetected || cliSurfaceDetected) {
    return {
      intent: {
        label: 'operator_utility',
        confidence: 0.62,
        evidence: [
          'Operator-facing help or CLI surface detected in grouped string windows.',
        ],
        counter_evidence: malwareSpecificYara
          ? ['Malware-specific YARA evidence is also present; treat as suspicious until validated.']
          : [],
      },
      tooling: {
        help_text_detected: helpTextDetected,
        cli_surface_detected: cliSurfaceDetected,
        framework_hints: frameworkHints,
        toolchain_markers: toolchainMarkers.slice(0, 10),
        library_profile: libraryProfile,
      },
    }
  }

  if (malwareSpecificYara) {
    return {
      intent: {
        label: 'malware_like_payload',
        confidence: 0.74,
        evidence: ['Malware-family-like YARA evidence is present.'],
        counter_evidence: [],
      },
      tooling: {
        help_text_detected: helpTextDetected,
        cli_surface_detected: cliSurfaceDetected,
        framework_hints: frameworkHints,
        toolchain_markers: toolchainMarkers.slice(0, 10),
        library_profile: libraryProfile,
      },
    }
  }

  return {
    intent: {
      label: 'unknown',
      confidence: 0.35,
      evidence: [],
      counter_evidence: [],
    },
    tooling: {
      help_text_detected: helpTextDetected,
      cli_surface_detected: cliSurfaceDetected,
      framework_hints: frameworkHints,
      toolchain_markers: toolchainMarkers.slice(0, 10),
      library_profile: libraryProfile,
    },
  }
}

export function applyIntentAwareYaraAdjustments(
  yaraSignals: YaraSignal[],
  intentAssessment: IntentAssessment
): YaraSignal[] {
  if (
    !Array.isArray(yaraSignals) ||
    yaraSignals.length === 0 ||
    !['dual_use_tool', 'operator_utility'].includes(intentAssessment.label) ||
    intentAssessment.confidence < 0.55
  ) {
    return yaraSignals
  }

  return yaraSignals.map((signal) => {
    if (!signal.generic || hasMalwareSpecificSignal(signal)) {
      return signal
    }

    const dualUse = intentAssessment.label === 'dual_use_tool'
    const adjustedLevel = dualUse ? 'low' : downgradeYaraLevel(signal.level)
    const adjustedScore = Number((Math.max(0, signal.score) * (dualUse ? 0.45 : 0.7)).toFixed(2))

    return {
      ...signal,
      level: adjustedLevel,
      score: adjustedScore,
    }
  })
}

/**
 * Calculate threat level based on IOCs
 * Requirements: 15.2, 15.4
 */
function calculateThreatLevel(
  yaraMatches: string[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  lowConfidenceYaraCount: number = 0
): { level: 'clean' | 'suspicious' | 'malicious' | 'unknown'; confidence: number } {
  let score = 0
  let maxScore = 0
  
  // YARA matches (highest weight)
  maxScore += 50
  if (yaraMatches.length > 0) {
    // Check for malware family matches
    const hasMalwareMatch = yaraMatches.some(rule => 
      rule.toLowerCase().includes('trojan') ||
      rule.toLowerCase().includes('ransomware') ||
      rule.toLowerCase().includes('backdoor') ||
      rule.toLowerCase().includes('malware')
    )
    
    if (hasMalwareMatch) {
      score += 50
    } else {
      // Packer or other matches
      score += 20
    }
  } else if (lowConfidenceYaraCount > 0) {
    // Weak YARA-only signal: keep as low weight to reduce false positives.
    score += Math.min(lowConfidenceYaraCount * 2, 6)
  }
  
  // Suspicious imports (context-aware weighting to reduce false positives)
  maxScore += 30
  if (suspiciousImports.length > 0) {
    const importApis = suspiciousImports
      .map((item) => item.split('!').pop() || item)
      .map((item) => item.toLowerCase())

    const highRiskCount = importApis.filter((name) =>
      HIGH_RISK_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length

    const contextDependentCount = importApis.filter((name) =>
      CONTEXT_DEPENDENT_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length

    let importScore = 0

    // High-risk primitives (injection/hooking) are strong signals.
    importScore += Math.min(highRiskCount * 8, 22)
    // Context-dependent APIs are weaker alone (debuggers/installers use them too).
    importScore += Math.min(contextDependentCount * 2, 8)

    const hasWriteProcessMemory = importApis.some((name) => name.includes('writeprocessmemory'))
    const hasCreateRemoteThread = importApis.some((name) => name.includes('createremotethread'))
    const hasVirtualAllocEx = importApis.some((name) => name.includes('virtualallocex'))
    if (hasWriteProcessMemory && (hasCreateRemoteThread || hasVirtualAllocEx)) {
      importScore += 6
    }

    score += Math.min(importScore, 30)
  }
  
  // Suspicious strings (lower weight)
  maxScore += 20
  if (suspiciousStrings.length > 0) {
    score += Math.min(suspiciousStrings.length * 2, 20)
  }
  
  // Calculate confidence
  const confidence = maxScore > 0 ? score / maxScore : 0
  
  // Determine threat level
  let level: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  if (score >= 40) {
    level = 'malicious'
  } else if (score >= 15) {
    level = 'suspicious'
  } else if (score > 0) {
    level = 'suspicious'
  } else {
    level = 'clean'
  }
  
  return { level, confidence }
}

/**
 * Generate evidence list
 * Requirements: 15.2
 */
function generateEvidence(
  yaraMatches: string[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any
): string[] {
  const evidence: string[] = []
  
  if (yaraMatches.length > 0) {
    evidence.push(`YARA 规则匹配: ${yaraMatches.join(', ')}`)
  }
  
  if (suspiciousImports.length > 0) {
    evidence.push(`检测到 ${suspiciousImports.length} 个可疑导入函数`)
    if (suspiciousImports.length <= 5) {
      evidence.push(`可疑导入: ${suspiciousImports.join(', ')}`)
    }
  }
  
  if (suspiciousStrings.length > 0) {
    evidence.push(`检测到 ${suspiciousStrings.length} 个可疑字符串`)
  }
  
  if (runtime?.is_dotnet) {
    evidence.push(`.NET 程序 (${runtime.dotnet_version || 'unknown version'})`)
  }
  
  if (runtime?.suspected && runtime.suspected.length > 0) {
    const runtimes = runtime.suspected.map((s: any) => s.runtime).join(', ')
    evidence.push(`检测到运行时: ${runtimes}`)
  }
  
  return evidence
}

/**
 * Generate summary and recommendation
 * Requirements: 15.2
 */
function generateSummaryAndRecommendation(
  threatLevel: string,
  yaraMatches: string[],
  runtime: any
): { summary: string; recommendation: string } {
  let summary = ''
  let recommendation = ''
  
  // Generate summary based on threat level
  if (threatLevel === 'malicious') {
    const malwareTypes = yaraMatches
      .filter(rule => 
        rule.toLowerCase().includes('trojan') ||
        rule.toLowerCase().includes('ransomware') ||
        rule.toLowerCase().includes('backdoor')
      )
      .map(rule => rule.split('_')[0])
    
    if (malwareTypes.length > 0) {
      summary = `检测到恶意软件: ${malwareTypes.join(', ')}`
    } else {
      summary = '检测到高度可疑的恶意行为特征'
    }
    
    recommendation = '强烈建议在隔离环境中进行深度分析，不要在生产环境执行此文件'
  } else if (threatLevel === 'suspicious') {
    const packerMatches = yaraMatches.filter(rule => 
      rule.toLowerCase().includes('upx') ||
      rule.toLowerCase().includes('packer') ||
      rule.toLowerCase().includes('themida') ||
      rule.toLowerCase().includes('vmprotect')
    )
    
    if (packerMatches.length > 0) {
      summary = `检测到加壳器: ${packerMatches.join(', ')}`
      recommendation = '建议进行脱壳分析或深度静态分析以了解真实行为'
    } else {
      summary = '检测到可疑行为特征，需要进一步分析'
      recommendation = '建议进行深度静态分析或在隔离环境中进行动态分析'
    }
  } else if (threatLevel === 'clean') {
    summary = '未检测到明显的恶意行为特征'
    recommendation = '样本看起来相对安全，但建议根据具体使用场景进行进一步验证'
  } else {
    summary = '无法确定威胁等级，需要更多信息'
    recommendation = '建议进行深度静态分析以获取更多信息'
  }
  
  // Add runtime info to summary
  if (runtime?.is_dotnet) {
    summary += ` (.NET 程序)`
  }
  
  return { summary, recommendation }
}

function calculateEvidenceWeights(
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any,
  yaraMatches: string[],
  yaraLowConfidenceMatches: string[]
): { import: number; string: number; runtime: number } {
  let importWeight = Math.min(0.9, suspiciousImports.length * 0.06)
  let stringWeight =
    Math.min(0.8, suspiciousStrings.length * 0.03) +
    Math.min(0.35, yaraMatches.length * 0.09 + yaraLowConfidenceMatches.length * 0.03)
  let runtimeWeight = 0.05

  if (runtime?.is_dotnet) {
    runtimeWeight += 0.25
  }
  if (Array.isArray(runtime?.suspected) && runtime.suspected.length > 0) {
    const topConfidence = Number(runtime.suspected[0]?.confidence || 0)
    runtimeWeight += Math.min(0.45, Math.max(0, topConfidence) * 0.5)
  }

  const total = importWeight + stringWeight + runtimeWeight
  if (total <= 0) {
    return { import: 0.34, string: 0.33, runtime: 0.33 }
  }

  return {
    import: Number((importWeight / total).toFixed(2)),
    string: Number((stringWeight / total).toFixed(2)),
    runtime: Number((runtimeWeight / total).toFixed(2)),
  }
}

function buildInferenceLayer(
  threatLevel: 'clean' | 'suspicious' | 'malicious' | 'unknown',
  yaraMatches: string[],
  yaraLowConfidenceMatches: string[],
  suspiciousImports: string[],
  suspiciousStrings: string[]
): {
  classification: 'benign' | 'suspicious' | 'malicious' | 'unknown'
  hypotheses: string[]
  false_positive_risks: string[]
} {
  const hypotheses: string[] = []
  const falsePositiveRisks: string[] = []

  if (yaraMatches.length > 0) {
    hypotheses.push(`YARA medium/high confidence match: ${yaraMatches.slice(0, 5).join(', ')}`)
  }
  if (yaraLowConfidenceMatches.length > 0) {
    hypotheses.push(
      `YARA low-confidence hints: ${yaraLowConfidenceMatches.slice(0, 5).join(', ')}`
    )
    falsePositiveRisks.push(
      'Low-confidence YARA hits may be string overlap without strong import/API corroboration.'
    )
  }
  if (suspiciousImports.length > 0) {
    hypotheses.push(`Suspicious API imports observed: ${Math.min(suspiciousImports.length, 10)}`)
    const hasOnlyContextDependentAPIs =
      suspiciousImports.every((item) =>
        CONTEXT_DEPENDENT_APIS.some((api) =>
          (item.split('!').pop() || item).toLowerCase().includes(api.toLowerCase())
        )
      ) && suspiciousImports.length > 0
    if (hasOnlyContextDependentAPIs) {
      falsePositiveRisks.push(
        'Import evidence is mostly context-dependent APIs (debuggers/installers may also use them).'
      )
    }
  }
  if (suspiciousStrings.length > 0) {
    hypotheses.push(`Behavior-related strings observed: ${Math.min(suspiciousStrings.length, 20)}`)
  }

  let classification: 'benign' | 'suspicious' | 'malicious' | 'unknown' = 'unknown'
  if (threatLevel === 'clean') {
    classification = 'benign'
  } else if (threatLevel === 'malicious') {
    classification = 'malicious'
  } else if (threatLevel === 'suspicious') {
    classification = 'suspicious'
  }

  if (hypotheses.length === 0) {
    hypotheses.push('Insufficient evidence to build high-confidence behavioral inference.')
  }

  return {
    classification,
    hypotheses,
    false_positive_risks: falsePositiveRisks,
  }
}

void [
  calculateThreatLevel,
  generateEvidence,
  generateSummaryAndRecommendation,
  calculateEvidenceWeights,
  buildInferenceLayer,
]

function hasMalwareSpecificSignal(signal: YaraSignal): boolean {
  return /ransomware|backdoor|downloader|keylogger|stealer|rat|loader/.test(
    signal.rule.toLowerCase()
  )
}

export function calculateThreatLevelV2(
  yaraSignals: YaraSignal[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  intentAssessment: IntentAssessment
): { level: 'clean' | 'suspicious' | 'malicious' | 'unknown'; confidence: number } {
  let score = 0
  const maxScore = 90

  let yaraScore = 0
  for (const signal of yaraSignals) {
    const levelWeight =
      signal.level === 'high'
        ? 16
        : signal.level === 'medium'
          ? 10
          : signal.level === 'low'
            ? 4
            : 6
    let signalScore = levelWeight + Math.min(4, Math.max(0, signal.score) * 3)

    if (signal.stringOnly) {
      signalScore *= 0.35
    }
    if (signal.generic) {
      signalScore *= 0.55
    }
    if (
      (intentAssessment.label === 'dual_use_tool' ||
        intentAssessment.label === 'operator_utility') &&
      signal.generic
    ) {
      signalScore *= 0.55
    }
    if (
      intentAssessment.label === 'dual_use_tool' &&
      signal.stringOnly &&
      !hasMalwareSpecificSignal(signal)
    ) {
      signalScore *= 0.7
    }

    yaraScore += signalScore
  }
  score += Math.min(36, yaraScore)

  if (suspiciousImports.length > 0) {
    const importApis = suspiciousImports
      .map((item) => item.split('!').pop() || item)
      .map((item) => item.toLowerCase())

    const highRiskCount = importApis.filter((name) =>
      HIGH_RISK_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length
    const contextDependentCount = importApis.filter((name) =>
      CONTEXT_DEPENDENT_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length
    const hasWriteProcessMemory = importApis.some((name) => name.includes('writeprocessmemory'))
    const hasCreateRemoteThread = importApis.some((name) => name.includes('createremotethread'))
    const hasVirtualAllocEx = importApis.some((name) => name.includes('virtualallocex'))

    let importScore = Math.min(highRiskCount * 7, 22) + Math.min(contextDependentCount * 2, 8)
    if (hasWriteProcessMemory && (hasCreateRemoteThread || hasVirtualAllocEx)) {
      importScore += 6
    }

    if (intentAssessment.label === 'dual_use_tool') {
      importScore *= 0.8
    } else if (intentAssessment.label === 'operator_utility') {
      importScore *= 0.9
    }

    score += Math.min(28, importScore)
  }

  let stringScore = Math.min(suspiciousStrings.length * 1.4, 18)
  if (intentAssessment.label === 'dual_use_tool') {
    stringScore *= 0.7
  } else if (intentAssessment.label === 'operator_utility') {
    stringScore *= 0.85
  }
  score += Math.min(18, stringScore)

  if (intentAssessment.label === 'malware_like_payload') {
    score += 8
  } else if (intentAssessment.label === 'dual_use_tool') {
    score -= 4
  }

  const boundedScore = Math.max(0, score)
  const confidence = Number(Math.max(0, Math.min(1, boundedScore / maxScore)).toFixed(2))
  const strongMalwareYara = yaraSignals.some(
    (signal) =>
      !signal.generic &&
      !signal.stringOnly &&
      hasMalwareSpecificSignal(signal) &&
      signal.level !== 'low'
  )

  let level: 'clean' | 'suspicious' | 'malicious' | 'unknown' = 'clean'
  if (strongMalwareYara && boundedScore >= 34 && intentAssessment.label !== 'dual_use_tool') {
    level = 'malicious'
  } else if (boundedScore >= 44 && intentAssessment.label !== 'dual_use_tool') {
    level = 'malicious'
  } else if (boundedScore >= 12) {
    level = 'suspicious'
  }

  const hasMeaningfulStaticCapability =
    suspiciousImports.length > 0 || suspiciousStrings.length > 0 || yaraSignals.length > 0
  if (
    level === 'clean' &&
    hasMeaningfulStaticCapability &&
    (intentAssessment.label === 'dual_use_tool' || intentAssessment.label === 'operator_utility')
  ) {
    level = 'suspicious'
  }

  return { level, confidence }
}

function generateEvidenceV2(
  yaraSignals: YaraSignal[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any,
  intentAssessment: IntentAssessment,
  toolingAssessment: ToolingAssessment
): string[] {
  const evidence: string[] = []
  const strongSignals = yaraSignals
    .filter((signal) => signal.level !== 'low')
    .map((signal) =>
      `${signal.rule}${signal.stringOnly ? ' [string-only]' : ''}${signal.generic ? ' [generic]' : ''}`
    )
  const downgradedSignals = yaraSignals
    .filter((signal) => signal.level === 'low')
    .map((signal) => signal.rule)

  if (strongSignals.length > 0) {
    evidence.push(`YARA medium/high confidence matches: ${strongSignals.slice(0, 6).join(', ')}`)
  }
  if (downgradedSignals.length > 0) {
    evidence.push(`YARA low-confidence hints: ${downgradedSignals.slice(0, 6).join(', ')}`)
  }
  if (suspiciousImports.length > 0) {
    evidence.push(`Suspicious imports observed: ${suspiciousImports.length}`)
    if (suspiciousImports.length <= 5) {
      evidence.push(`Import details: ${suspiciousImports.join(', ')}`)
    }
  }
  if (suspiciousStrings.length > 0) {
    evidence.push(`Behavior-related strings observed: ${suspiciousStrings.length}`)
  }
  if (toolingAssessment.help_text_detected || toolingAssessment.cli_surface_detected) {
    evidence.push('Grouped strings indicate operator-facing help text or CLI options.')
  }
  if (toolingAssessment.library_profile) {
    const librarySummary = summarizeLibraryProfile(toolingAssessment.library_profile)
    if (librarySummary) {
      evidence.push(`Library/crate profile: ${librarySummary}`)
    }
    evidence.push(...toolingAssessment.library_profile.evidence.slice(0, 2))
  }
  if (intentAssessment.evidence.length > 0) {
    evidence.push(...intentAssessment.evidence.slice(0, 2))
  }
  if (runtime?.is_dotnet) {
    evidence.push(`.NET program detected (${runtime.dotnet_version || 'unknown version'})`)
  }
  if (Array.isArray(runtime?.suspected) && runtime.suspected.length > 0) {
    const runtimes = runtime.suspected
      .map((item: any) => String(item?.runtime || '').trim())
      .filter((item: string) => item.length > 0)
    if (runtimes.length > 0) {
      evidence.push(`Runtime hints: ${Array.from(new Set(runtimes)).join(', ')}`)
    }
  }

  return Array.from(new Set(evidence))
}

function generateSummaryAndRecommendationV2(
  threatLevel: string,
  yaraSignals: YaraSignal[],
  runtime: any,
  intentAssessment: IntentAssessment,
  toolingAssessment: ToolingAssessment
): { summary: string; recommendation: string } {
  const strongRules = yaraSignals
    .filter((signal) => signal.level !== 'low')
    .map((signal) => signal.rule)
  const packerMatches = strongRules.filter((rule) => /upx|packer|themida|vmprotect/i.test(rule))
  const runtimeSuffix = runtime?.is_dotnet ? ' (.NET)' : ''
  const librarySuffix = summarizeLibraryProfile(toolingAssessment.library_profile)
    ? ` Tooling stack hints: ${summarizeLibraryProfile(toolingAssessment.library_profile)}.`
    : ''

  if (intentAssessment.label === 'dual_use_tool') {
    return {
      summary:
        'Static evidence is more consistent with a dual-use operator utility than a pure malware payload.' +
        runtimeSuffix +
        librarySuffix,
      recommendation:
        'Validate provenance, operator workflow, and deployment context before labeling it malicious. ' +
        'Treat generic or string-only YARA hits as weak until dynamic or function-level evidence confirms abuse.',
    }
  }

  if (intentAssessment.label === 'operator_utility') {
    return {
      summary:
        'The sample exposes an operator-facing CLI/help surface and should be treated as a suspicious utility pending validation.' +
        runtimeSuffix +
        librarySuffix,
      recommendation:
        'Correlate with execution context, parent process, and any dropped artifacts before concluding malicious intent.',
    }
  }

  if (threatLevel === 'malicious') {
    const malwareRules = strongRules.filter((rule) =>
      /trojan|ransomware|backdoor|loader|stealer/i.test(rule)
    )
    return {
      summary:
        malwareRules.length > 0
          ? `Static evidence aligns with malware-like behavior: ${malwareRules.slice(0, 4).join(', ')}${runtimeSuffix}${librarySuffix}`
          : `Static evidence indicates a high-risk malicious payload${runtimeSuffix}${librarySuffix}`,
      recommendation:
        'Handle the sample in an isolated environment and collect dynamic evidence before any operational use.',
    }
  }

  if (threatLevel === 'suspicious') {
    if (packerMatches.length > 0) {
      return {
        summary: `Packed or protected traits detected: ${packerMatches.slice(0, 4).join(', ')}${runtimeSuffix}${librarySuffix}`,
        recommendation:
          'Unpack or deepen static analysis before making a final malware classification.',
      }
    }

    return {
      summary:
        toolingAssessment.help_text_detected || toolingAssessment.cli_surface_detected
          ? `Suspicious capability set detected, but the sample also exposes an operator-facing surface${runtimeSuffix}${librarySuffix}`
          : `Suspicious static behavior detected${runtimeSuffix}${librarySuffix}`,
      recommendation:
        'Escalate to deeper static analysis or controlled dynamic execution to resolve intent and capability.',
    }
  }

  if (threatLevel === 'clean') {
    return {
      summary: `No strong malicious indicators were confirmed from current static evidence${runtimeSuffix}${librarySuffix}`,
      recommendation:
        'Retain the sample for context-aware review if provenance is unknown, but current evidence alone is weak.',
    }
  }

  return {
    summary: `Threat level could not be determined with current evidence${runtimeSuffix}${librarySuffix}`,
    recommendation:
      'Collect additional static or dynamic evidence before drawing behavioral conclusions.',
  }
}

function calculateEvidenceWeightsV2(
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any,
  yaraSignals: YaraSignal[],
  intentAssessment: IntentAssessment
): { import: number; string: number; runtime: number } {
  let importWeight = Math.min(0.9, suspiciousImports.length * 0.06)
  const strongYara = yaraSignals.filter((signal) => signal.level !== 'low').length
  const weakYara = yaraSignals.length - strongYara
  let stringWeight =
    Math.min(0.8, suspiciousStrings.length * 0.03) +
    Math.min(0.28, strongYara * 0.07 + weakYara * 0.02)
  let runtimeWeight = 0.05

  if (runtime?.is_dotnet) {
    runtimeWeight += 0.25
  }
  if (Array.isArray(runtime?.suspected) && runtime.suspected.length > 0) {
    const topConfidence = Number(runtime.suspected[0]?.confidence || 0)
    runtimeWeight += Math.min(0.45, Math.max(0, topConfidence) * 0.5)
  }
  if (intentAssessment.label === 'dual_use_tool') {
    stringWeight *= 0.85
  }

  const total = importWeight + stringWeight + runtimeWeight
  if (total <= 0) {
    return { import: 0.34, string: 0.33, runtime: 0.33 }
  }

  return {
    import: Number((importWeight / total).toFixed(2)),
    string: Number((stringWeight / total).toFixed(2)),
    runtime: Number((runtimeWeight / total).toFixed(2)),
  }
}

function buildInferenceLayerV2(
  threatLevel: 'clean' | 'suspicious' | 'malicious' | 'unknown',
  yaraSignals: YaraSignal[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  intentAssessment: IntentAssessment,
  toolingAssessment: ToolingAssessment
): {
  classification: 'benign' | 'suspicious' | 'malicious' | 'unknown'
  hypotheses: string[]
  false_positive_risks: string[]
  intent_assessment: IntentAssessment
  tooling_assessment: ToolingAssessment
} {
  const hypotheses: string[] = []
  const falsePositiveRisks: string[] = []
  const strongYara = yaraSignals.filter((signal) => signal.level !== 'low')
  const weakYara = yaraSignals.filter((signal) => signal.level === 'low')

  if (strongYara.length > 0) {
    hypotheses.push(
      `YARA medium/high confidence match: ${strongYara
        .map((signal) => signal.rule)
        .slice(0, 5)
        .join(', ')}`
    )
  }
  if (weakYara.length > 0) {
    hypotheses.push(
      `YARA low-confidence hints: ${weakYara
        .map((signal) => signal.rule)
        .slice(0, 5)
        .join(', ')}`
    )
    falsePositiveRisks.push(
      'Low-confidence YARA hits may be string overlap without strong import/API corroboration.'
    )
  }
  if (strongYara.some((signal) => signal.stringOnly)) {
    falsePositiveRisks.push(
      'Some medium/high YARA hits remain string-heavy and should not be treated as execution proof.'
    )
  }
  if (strongYara.some((signal) => signal.generic)) {
    falsePositiveRisks.push(
      'Generic malware-family YARA matches can overlap with dual-use process tooling.'
    )
  }
  if (suspiciousImports.length > 0) {
    hypotheses.push(`Suspicious API imports observed: ${Math.min(suspiciousImports.length, 10)}`)
  }
  if (suspiciousStrings.length > 0) {
    hypotheses.push(`Behavior-related strings observed: ${Math.min(suspiciousStrings.length, 20)}`)
  }
  if (intentAssessment.evidence.length > 0) {
    hypotheses.push(...intentAssessment.evidence.slice(0, 2))
  }
  if (toolingAssessment.library_profile) {
    const librarySummary = summarizeLibraryProfile(toolingAssessment.library_profile)
    if (librarySummary) {
      hypotheses.push(`Observed crate/library profile: ${librarySummary}`)
    }
  }
  falsePositiveRisks.push(...intentAssessment.counter_evidence)

  let classification: 'benign' | 'suspicious' | 'malicious' | 'unknown' = 'unknown'
  if (threatLevel === 'clean') {
    classification = 'benign'
  } else if (threatLevel === 'malicious') {
    classification = 'malicious'
  } else if (threatLevel === 'suspicious') {
    classification = 'suspicious'
  }

  if (hypotheses.length === 0) {
    hypotheses.push('Insufficient evidence to build high-confidence behavioral inference.')
  }

  return {
    classification,
    hypotheses: Array.from(new Set(hypotheses)),
    false_positive_risks: Array.from(new Set(falsePositiveRisks)),
    intent_assessment: intentAssessment,
    tooling_assessment: toolingAssessment,
  }
}

// ============================================================================
// Standalone Workflow Function
// ============================================================================

/**
 * Execute triage workflow
 * Requirements: 15.1, 15.2, 15.4, 15.5
 * 
 * This is a standalone function that can be called by other workflows
 */
export async function triageWorkflow(
  sampleId: string,
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
): Promise<TriageWorkflowOutput> {
  const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager);
  const result = await handler({ sample_id: sampleId });
  
  // Convert WorkerResult to TriageWorkflowOutput
  return {
    ok: result.ok,
    data: result.data as any,
    errors: result.errors,
    warnings: result.warnings
  };
}

// ============================================================================
// Workflow Handler
// ============================================================================

interface TriageWorkflowDependencies {
  analyzeStart?: (args: ToolArgs) => Promise<WorkerResult>
  peFingerprint?: ReturnType<typeof createPEFingerprintHandler>
  runtimeDetect?: ReturnType<typeof createRuntimeDetectHandler>
  peImportsExtract?: ReturnType<typeof createPEImportsExtractHandler>
  stringsExtract?: ReturnType<typeof createStringsExtractHandler>
  yaraScan?: ReturnType<typeof createYaraScanHandler>
  staticCapabilityTriage?: ReturnType<typeof createStaticCapabilityTriageHandler>
  peStructureAnalyze?: ReturnType<typeof createPEStructureAnalyzeHandler>
  compilerPackerDetect?: ReturnType<typeof createCompilerPackerDetectHandler>
  analysisContextLink?: ReturnType<typeof createAnalysisContextLinkHandler>
  upxInspect?: ReturnType<typeof createUPXInspectHandler>
  yaraXScan?: ReturnType<typeof createYaraXScanHandler>
  rizinAnalyze?: ReturnType<typeof createRizinAnalyzeHandler>
  resolveBackends?: typeof resolveAnalysisBackends
}

/**
 * Create triage workflow handler
 * Requirements: 15.1, 15.2, 15.4, 15.5
 */
export function createTriageWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: TriageWorkflowDependencies = {}
) {
  // Create tool handlers
  const peFingerprintHandler =
    dependencies.peFingerprint || createPEFingerprintHandler(workspaceManager, database, cacheManager)
  const runtimeDetectHandler =
    dependencies.runtimeDetect || createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const peImportsExtractHandler =
    dependencies.peImportsExtract || createPEImportsExtractHandler(workspaceManager, database, cacheManager)
  const stringsExtractHandler =
    dependencies.stringsExtract || createStringsExtractHandler(workspaceManager, database, cacheManager)
  const yaraScanHandler =
    dependencies.yaraScan || createYaraScanHandler(workspaceManager, database, cacheManager)
  const staticCapabilityTriageHandler =
    dependencies.staticCapabilityTriage || createStaticCapabilityTriageHandler(workspaceManager, database)
  const peStructureAnalyzeHandler =
    dependencies.peStructureAnalyze || createPEStructureAnalyzeHandler(workspaceManager, database)
  const compilerPackerDetectHandler =
    dependencies.compilerPackerDetect || createCompilerPackerDetectHandler(workspaceManager, database)
  const analysisContextLinkHandler =
    dependencies.analysisContextLink || createAnalysisContextLinkHandler(workspaceManager, database, cacheManager)
  const upxInspectHandler =
    dependencies.upxInspect || createUPXInspectHandler(workspaceManager, database)
  const yaraXScanHandler =
    dependencies.yaraXScan || createYaraXScanHandler(workspaceManager, database)
  const rizinAnalyzeHandler =
    dependencies.rizinAnalyze || createRizinAnalyzeHandler(workspaceManager, database)
  
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = TriageWorkflowInputSchema.parse(args)
    const startTime = Date.now()
    const warnings: string[] = []
    const errors: string[] = []
    
    try {
      if (dependencies.analyzeStart) {
        const delegated = await dependencies.analyzeStart({
          sample_id: input.sample_id,
          goal: 'triage',
          depth: input.depth,
          backend_policy: input.backend_policy,
          allow_transformations: input.allow_transformations,
          allow_live_execution: false,
          force_refresh: input.force_refresh,
        })
        if (!delegated.ok || !delegated.data) {
          return {
            ok: delegated.ok,
            errors: delegated.errors,
            warnings: delegated.warnings,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
            },
          }
        }

        const delegatedPayload =
          delegated.data && typeof delegated.data === 'object'
            ? (delegated.data as Record<string, unknown>)
            : {}
        const stageResult =
          delegatedPayload.stage_result && typeof delegatedPayload.stage_result === 'object'
            ? (delegatedPayload.stage_result as Record<string, unknown>)
            : delegatedPayload

        return {
          ok: true,
          data: {
            ...stageResult,
            run_id: delegatedPayload.run_id,
            deferred_jobs: delegatedPayload.deferred_jobs,
            recommended_next_tools:
              (stageResult.recommended_next_tools as string[] | undefined) || [
                'workflow.analyze.promote',
                'workflow.analyze.status',
              ],
            next_actions:
              (stageResult.next_actions as string[] | undefined) || [
                'Promote the persisted run instead of rerunning triage when you need deeper stages.',
              ],
          },
          warnings: delegated.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      // Verify sample exists
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }
      const sampleSizeTier = classifySampleSizeTier(sample.size || 0)
      const analysisBudgetProfile = deriveAnalysisBudgetProfile(input.depth, sampleSizeTier)
      
      // Step 1: PE Fingerprint (fast mode)
      // Requirement: 15.1
      const fingerprintResult = await peFingerprintHandler({ 
        sample_id: input.sample_id, 
        fast: true,
        force_refresh: input.force_refresh,
      })
      
      if (!fingerprintResult.ok) {
        errors.push('PE fingerprint extraction failed')
      }
      if (fingerprintResult.warnings) {
        warnings.push(...fingerprintResult.warnings)
      }
      
      // Step 2: Runtime Detection
      // Requirement: 15.1
      const runtimeResult = await runtimeDetectHandler({ 
        sample_id: input.sample_id,
        force_refresh: input.force_refresh,
      })
      
      if (!runtimeResult.ok) {
        errors.push('Runtime detection failed')
      }
      if (runtimeResult.warnings) {
        warnings.push(...runtimeResult.warnings)
      }
      
      // Step 3: Import Table Extraction
      // Requirement: 15.1
      const importsResult = await peImportsExtractHandler({ 
        sample_id: input.sample_id,
        group_by_dll: true,
        force_refresh: input.force_refresh,
      })
      
      if (!importsResult.ok) {
        errors.push('Import table extraction failed')
      }
      if (importsResult.warnings) {
        warnings.push(...importsResult.warnings)
      }
      
      // Step 4: String Extraction
      // Requirement: 15.1
      const stringsResult = await stringsExtractHandler({ 
        sample_id: input.sample_id,
        min_len: 6,
        encoding: 'all',
        force_refresh: input.force_refresh,
      })
      
      if (!stringsResult.ok) {
        errors.push('String extraction failed')
      }
      if (stringsResult.warnings) {
        warnings.push(...stringsResult.warnings)
      }
      
      // Step 5: YARA Scan
      // Requirement: 15.1
      const yaraResult = await yaraScanHandler({ 
        sample_id: input.sample_id,
        rule_set: 'malware_families',
        rule_tier: 'production',
        force_refresh: input.force_refresh,
      })
      
      if (!yaraResult.ok) {
        errors.push('YARA scan failed')
      }
      if (yaraResult.warnings) {
        warnings.push(...yaraResult.warnings)
      }

      // Step 6: Static capability triage
      const staticCapabilityResult = await staticCapabilityTriageHandler({
        sample_id: input.sample_id,
      })
      if (!staticCapabilityResult.ok) {
        errors.push('Static capability triage failed')
      }
      if (staticCapabilityResult.warnings) {
        warnings.push(...staticCapabilityResult.warnings)
      }

      // Step 7: Canonical PE structure analysis
      const peStructureResult = await peStructureAnalyzeHandler({
        sample_id: input.sample_id,
      })
      if (!peStructureResult.ok) {
        errors.push('PE structure analysis failed')
      }
      if (peStructureResult.warnings) {
        warnings.push(...peStructureResult.warnings)
      }

      // Step 8: Compiler / packer attribution
      const compilerPackerResult = await compilerPackerDetectHandler({
        sample_id: input.sample_id,
      })
      if (!compilerPackerResult.ok) {
        errors.push('Compiler/packer attribution failed')
      }
      if (compilerPackerResult.warnings) {
        warnings.push(...compilerPackerResult.warnings)
      }

      // Step 9: Compact string/Xref context correlation
      const stringContextResult = await analysisContextLinkHandler({
        sample_id: input.sample_id,
        include_decoded: true,
        max_records: 40,
        max_functions: 6,
        max_strings_per_function: 3,
        xref_depth: 1,
        persist_artifact: true,
        reuse_cached: !input.force_refresh,
        force_refresh: input.force_refresh,
      })
      if (!stringContextResult.ok) {
        const contextErrors = stringContextResult.errors || ['analysis.context.link failed']
        warnings.push(`analysis.context.link unavailable: ${contextErrors.join('; ')}`)
      }
      if (stringContextResult.warnings) {
        warnings.push(...stringContextResult.warnings)
      }
      
      // If all tools failed, return error
      if (errors.length >= 8) {
        return {
          ok: false,
          errors: ['All analysis tools failed', ...errors],
          warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }
      
      // Step 10: Aggregate results and generate structured summary
      // Requirements: 15.2, 15.4, 15.5
      
      // Extract YARA matches
      let yaraSignals: YaraSignal[] = []
      if (yaraResult.ok && yaraResult.data) {
        const yaraData = yaraResult.data as any
        if (yaraData.matches && Array.isArray(yaraData.matches)) {
          yaraSignals = normalizeYaraSignals(yaraData.matches)
        }
      }
      
      // Analyze imports for suspicious APIs
      const suspiciousImports: string[] = []
      if (importsResult.ok && importsResult.data) {
        const importsData = importsResult.data as any
        if (importsData.imports && typeof importsData.imports === 'object') {
          suspiciousImports.push(...analyzeSuspiciousImports(importsData.imports))
        }
      }
      
      // Analyze strings for suspicious patterns
      const stringAnalysis = {
        suspicious: [] as string[],
        urls: [] as string[],
        ips: [] as string[],
        paths: [] as string[],
        registry: [] as string[],
        commands: [] as string[],
        pipes: [] as string[],
        cargoPaths: [] as string[],
        rustMarkers: [] as string[],
        crateNames: [] as string[],
        libraryHints: [] as string[],
      }
      if (stringsResult.ok && stringsResult.data) {
        const stringsData = stringsResult.data as any
        if (stringsData.strings && Array.isArray(stringsData.strings)) {
          const analysis = analyzeSuspiciousStrings(stringsData.strings)
          stringAnalysis.suspicious = analysis.suspicious
          stringAnalysis.urls = analysis.urls
          stringAnalysis.ips = analysis.ips
          stringAnalysis.paths = analysis.paths
          stringAnalysis.registry = analysis.registry
          stringAnalysis.commands = analysis.commands
          stringAnalysis.pipes = analysis.pipes
          stringAnalysis.cargoPaths = analysis.cargoPaths
          stringAnalysis.rustMarkers = analysis.rustMarkers
          stringAnalysis.crateNames = analysis.crateNames
          stringAnalysis.libraryHints = analysis.libraryHints
        }
      }

      const stringsSummary = (stringsResult.data as any)?.summary
      const { intent, tooling } = assessIntentAndTooling(
        stringsSummary,
        suspiciousImports,
        stringAnalysis,
        yaraSignals,
        runtimeResult.data
      )
      yaraSignals = applyIntentAwareYaraAdjustments(yaraSignals, intent)

      const yaraMatches = Array.from(
        new Set(
          yaraSignals
            .filter((signal) => signal.level !== 'low')
            .map((signal) => signal.rule)
        )
      )
      const yaraLowConfidenceMatches = Array.from(
        new Set(
          yaraSignals
            .filter((signal) => signal.level === 'low')
            .map((signal) => signal.rule)
        )
      )
      
      // Calculate threat level and confidence
      const { level: threatLevel, confidence } = calculateThreatLevelV2(
        yaraSignals,
        suspiciousImports,
        stringAnalysis.suspicious,
        intent
      )
      
      // Generate evidence
      const evidence = generateEvidenceV2(
        yaraSignals,
        suspiciousImports,
        stringAnalysis.suspicious,
        runtimeResult.data,
        intent,
        tooling
      )
      if (yaraLowConfidenceMatches.length > 0) {
        evidence.push(
          `YARA low-confidence matches (downgraded): ${yaraLowConfidenceMatches.join(', ')}`
        )
      }
      
      // Generate summary and recommendation
      let { summary, recommendation } = generateSummaryAndRecommendationV2(
        threatLevel,
        yaraSignals,
        runtimeResult.data,
        intent,
        tooling
      )
      const inference = buildInferenceLayerV2(
        threatLevel,
        yaraSignals,
        suspiciousImports,
        stringAnalysis.suspicious,
        intent,
        tooling
      )
      const evidenceWeights = calculateEvidenceWeightsV2(
        suspiciousImports,
        stringAnalysis.suspicious,
        runtimeResult.data,
        yaraSignals,
        intent
      )

      const highValueIocs = {
        suspicious_apis:
          suspiciousImports.length > 0 ? suspiciousImports.slice(0, 20) : undefined,
        commands: stringAnalysis.commands.length > 0 ? stringAnalysis.commands.slice(0, 15) : undefined,
        pipes: stringAnalysis.pipes.length > 0 ? stringAnalysis.pipes.slice(0, 15) : undefined,
        urls: stringAnalysis.urls.length > 0 ? stringAnalysis.urls.slice(0, 15) : undefined,
        network:
          stringAnalysis.ips.length > 0 ? stringAnalysis.ips.slice(0, 15) : undefined,
      }

      const compilerArtifacts = {
        cargo_paths:
          stringAnalysis.cargoPaths.length > 0 ? stringAnalysis.cargoPaths.slice(0, 10) : undefined,
        rust_markers:
          stringAnalysis.rustMarkers.length > 0 ? stringAnalysis.rustMarkers.slice(0, 10) : undefined,
        library_profile: tooling.library_profile,
      }

      const hasHighValue =
        Boolean(highValueIocs.suspicious_apis?.length) ||
        Boolean(highValueIocs.commands?.length) ||
        Boolean(highValueIocs.pipes?.length) ||
        Boolean(highValueIocs.urls?.length) ||
        Boolean(highValueIocs.network?.length)
      const hasCompilerArtifacts =
        Boolean(compilerArtifacts.cargo_paths?.length) ||
        Boolean(compilerArtifacts.rust_markers?.length) ||
        Boolean(compilerArtifacts.library_profile)
      
      // Build IOCs
      const iocs = {
        suspicious_imports: suspiciousImports,
        suspicious_strings: stringAnalysis.suspicious.slice(0, 20),  // Limit to top 20
        yara_matches: yaraMatches,
        yara_low_confidence:
          yaraLowConfidenceMatches.length > 0 ? yaraLowConfidenceMatches : undefined,
        urls: stringAnalysis.urls.length > 0 ? stringAnalysis.urls : undefined,
        ip_addresses: stringAnalysis.ips.length > 0 ? stringAnalysis.ips : undefined,
        file_paths: stringAnalysis.paths.length > 0 ? stringAnalysis.paths.slice(0, 10) : undefined,
        registry_keys: stringAnalysis.registry.length > 0 ? stringAnalysis.registry.slice(0, 10) : undefined,
        high_value_iocs: hasHighValue ? highValueIocs : undefined,
        compiler_artifacts: hasCompilerArtifacts ? compilerArtifacts : undefined,
      }

      const staticCapabilityInsights = summarizeStaticCapabilityResult(
        staticCapabilityResult.ok && staticCapabilityResult.data
          ? (staticCapabilityResult.data as Record<string, unknown>)
          : null
      )
      const peStructureInsights = summarizePeStructureResult(
        peStructureResult.ok && peStructureResult.data
          ? (peStructureResult.data as Record<string, unknown>)
          : null
      )
      const compilerPackerInsights = summarizeCompilerPackerResult(
        compilerPackerResult.ok && compilerPackerResult.data
          ? (compilerPackerResult.data as Record<string, unknown>)
          : null
      )
      const stringContextInsights = summarizeStringContextResult(
        stringContextResult.ok && stringContextResult.data
          ? (stringContextResult.data as Record<string, unknown>)
          : null
      )

      if (
        staticCapabilityInsights.summary ||
        peStructureInsights.summary ||
        compilerPackerInsights.summary ||
        stringContextInsights.summary
      ) {
        summary = [
          summary,
          staticCapabilityInsights.summary,
          peStructureInsights.summary,
          compilerPackerInsights.summary,
          stringContextInsights.summary,
        ]
          .filter((item): item is string => Boolean(item && item.trim().length > 0))
          .join(' ')
      }

      const recommendationAddenda = [
        staticCapabilityInsights.recommendation,
        peStructureInsights.recommendation,
        compilerPackerInsights.recommendation,
        stringContextInsights.recommendation,
      ].filter((item): item is string => Boolean(item && item.trim().length > 0))
      if (recommendationAddenda.length > 0) {
        recommendation = `${recommendation} ${Array.from(new Set(recommendationAddenda)).join(' ')}`
      }

      evidence.push(
        ...[
          ...staticCapabilityInsights.evidence,
          ...peStructureInsights.evidence,
          ...compilerPackerInsights.evidence,
          ...stringContextInsights.evidence,
        ].filter((item) => item.trim().length > 0)
      )

      let adjustedThreatLevel = threatLevel
      let adjustedConfidence = confidence
      if (
        adjustedThreatLevel === 'clean' &&
        (staticCapabilityInsights.threat_hint ||
          peStructureInsights.packer_hint ||
          compilerPackerInsights.packer_hint)
      ) {
        adjustedThreatLevel = 'suspicious'
        adjustedConfidence = Math.max(adjustedConfidence, 0.58)
      }

      const defaultYaraXRulesPath = findDefaultYaraXRulesPath()
      const routingMetadata = buildIntentBackendPlan({
        goal: 'triage',
        depth: input.depth,
        backendPolicy: input.backend_policy,
        allowTransformations: input.allow_transformations,
        readiness: (dependencies.resolveBackends || resolveAnalysisBackends)(),
        signals: {
          packer_suspected:
            compilerPackerInsights.packer_hint || peStructureInsights.packer_hint,
          legacy_yara_weak:
            yaraMatches.length === 0 ||
            (yaraMatches.length <= 1 && yaraLowConfidenceMatches.length > 0),
          degraded_structure:
            !peStructureResult.ok ||
            !peStructureResult.data ||
            ((peStructureResult.data as Record<string, unknown>)?.status !== 'ready' &&
              (peStructureResult.data as Record<string, unknown>)?.status !== 'partial'),
          import_parsing_weak: !importsResult.ok,
          yara_x_rules_ready: Boolean(defaultYaraXRulesPath),
        },
      })

      const selectedBackends = new Set(selectedBackendTools(routingMetadata))
      let upxEnrichment: unknown = null
      let yaraXEnrichment: unknown = null
      let rizinEnrichment: unknown = null

      if (selectedBackends.has('upx.inspect')) {
        const upxResult = await upxInspectHandler({
          sample_id: input.sample_id,
          operation: 'test',
          timeout_sec: 20,
          persist_artifact: true,
        })
        if (upxResult.ok && upxResult.data) {
          upxEnrichment = upxResult.data
          evidence.push(`UPX corroboration: ${String((upxResult.data as Record<string, unknown>).summary || 'validation completed.')}`)
        } else {
          warnings.push(
            `upx.inspect unavailable: ${(upxResult.errors || ['unknown error']).join('; ')}`
          )
        }
        if (upxResult.warnings?.length) {
          warnings.push(...upxResult.warnings.map((item) => `upx.inspect: ${item}`))
        }
      }

      if (selectedBackends.has('yara_x.scan') && defaultYaraXRulesPath) {
        const yaraXResult = await yaraXScanHandler({
          sample_id: input.sample_id,
          rules_path: defaultYaraXRulesPath,
          timeout_sec: 25,
          persist_artifact: true,
        })
        if (yaraXResult.ok && yaraXResult.data) {
          yaraXEnrichment = yaraXResult.data
          const matchCount = Number((yaraXResult.data as Record<string, unknown>).match_count || 0)
          if (matchCount > 0) {
            evidence.push(`YARA-X corroboration produced ${matchCount} match(es).`)
          }
        } else {
          warnings.push(
            `yara_x.scan unavailable: ${(yaraXResult.errors || ['unknown error']).join('; ')}`
          )
        }
        if (yaraXResult.warnings?.length) {
          warnings.push(...yaraXResult.warnings.map((item) => `yara_x.scan: ${item}`))
        }
      }

      if (selectedBackends.has('rizin.analyze')) {
        const rizinOperation =
          !importsResult.ok ? 'imports' : !peStructureResult.ok ? 'sections' : 'info'
        const rizinResult = await rizinAnalyzeHandler({
          sample_id: input.sample_id,
          operation: rizinOperation,
          max_items: 20,
          timeout_sec: 30,
          persist_artifact: true,
        })
        if (rizinResult.ok && rizinResult.data) {
          rizinEnrichment = rizinResult.data
          evidence.push(
            `Rizin corroboration completed ${String((rizinResult.data as Record<string, unknown>).operation || rizinOperation)} inspection.`
          )
        } else {
          warnings.push(
            `rizin.analyze unavailable: ${(rizinResult.errors || ['unknown error']).join('; ')}`
          )
        }
        if (rizinResult.warnings?.length) {
          warnings.push(...rizinResult.warnings.map((item) => `rizin.analyze: ${item}`))
        }
      }
      
      // Return structured result
      const backendEnrichments = {
        ...(upxEnrichment ? { upx: upxEnrichment } : {}),
        ...(yaraXEnrichment ? { yara_x: yaraXEnrichment } : {}),
        ...(rizinEnrichment ? { rizin: rizinEnrichment } : {}),
      }
      const rawResults =
        input.raw_result_mode === 'full'
          ? {
              fingerprint: fingerprintResult.data || null,
              runtime: runtimeResult.data || null,
              imports: importsResult.data || null,
              strings: stringsResult.data || null,
              yara: yaraResult.data || null,
              static_capability: staticCapabilityResult.data || null,
              pe_structure: peStructureResult.data || null,
              compiler_packer: compilerPackerResult.data || null,
              string_context: stringContextResult.data || null,
              backend_enrichments: backendEnrichments,
            }
          : buildCompactRawResults({
              fingerprint: fingerprintResult.data || null,
              runtime: runtimeResult.data || null,
              imports: importsResult.data || null,
              strings: stringsResult.data || null,
              yara: yaraResult.data || null,
              staticCapability: staticCapabilityResult.data || null,
              peStructure: peStructureResult.data || null,
              compilerPacker: compilerPackerResult.data || null,
              stringContext: stringContextResult.data || null,
              backendEnrichments,
            })
      const summarizedWarnings = summarizeWorkflowWarnings(warnings)
      const stringContextReady =
        stringContextResult.ok &&
        stringContextResult.data &&
        typeof stringContextResult.data === 'object' &&
        (stringContextResult.data as Record<string, unknown>).xref_status === 'available'
      const importsMap =
        importsResult.ok &&
        importsResult.data &&
        typeof importsResult.data === 'object' &&
        (importsResult.data as Record<string, unknown>).imports &&
        typeof (importsResult.data as Record<string, unknown>).imports === 'object'
          ? ((importsResult.data as Record<string, unknown>).imports as Record<string, string[]>)
          : undefined
      const cryptoSignalsPresent =
        collectCryptoApiNames(importsMap).length > 0 ||
        hasCryptoCapabilitySignals(staticCapabilityResult) ||
        hasCryptoContextSignals(stringContextResult)
      const recommendedNextTools = Array.from(
        new Set(
          stringContextReady
            ? ['analysis.context.link', 'code.xrefs.analyze', 'ghidra.analyze', 'workflow.reconstruct', 'binary.role.profile']
            : ['ghidra.analyze', 'analysis.context.link', 'code.xrefs.analyze', 'workflow.reconstruct', 'binary.role.profile']
        )
      )
      if (cryptoSignalsPresent) {
        recommendedNextTools.unshift('trace.condition')
        recommendedNextTools.unshift('breakpoint.smart')
        recommendedNextTools.unshift('crypto.identify')
      }
      const nextActions = stringContextReady
        ? [
            'Use analysis.context.link or code.xrefs.analyze to inspect the highest-signal correlated function before deep reverse engineering.',
            'Use ghidra.analyze when you need function-level reverse engineering and decompilation.',
            'Use workflow.reconstruct when you want source-like export after quick profiling.',
            'Use binary.role.profile if you need a more role-aware DLL/COM/plugin classification before deep analysis.',
          ]
        : [
            'Run ghidra.analyze first if you need string-to-function or API-to-function attribution before deeper reverse engineering.',
            'Retry analysis.context.link or use code.xrefs.analyze after Ghidra function_index readiness is available.',
            'Use workflow.reconstruct when you want source-like export after quick profiling.',
            'Use binary.role.profile if you need a more role-aware DLL/COM/plugin classification before deep analysis.',
          ]
      if (cryptoSignalsPresent) {
        nextActions.unshift(
          'Use crypto.identify to turn crypto-related imports, strings, and function context into compact algorithm and constant findings before planning instrumentation.'
        )
        nextActions.unshift(
          'Then use breakpoint.smart and trace.condition to build a bounded Frida-oriented breakpoint and trace plan without immediately executing instrumentation.'
        )
      }
      const coverageEnvelope = buildCoverageEnvelope({
        coverageLevel: 'quick',
        completionState: 'bounded',
        sampleSizeTier,
        analysisBudgetProfile,
        downgradeReasons: buildBudgetDowngradeReasons({
          requestedDepth: input.depth,
          sampleSizeTier,
          analysisBudgetProfile,
          extraReasons: [
            input.depth === 'deep'
              ? 'workflow.triage remains a quick-profile workflow even when depth=deep; depth only expands bounded corroborating backends.'
              : null,
            sampleSizeTier === 'large' || sampleSizeTier === 'oversized'
              ? `Sample size tier ${sampleSizeTier} reinforces that this result is a first-pass profile rather than full reverse engineering.`
              : null,
          ],
        }),
        coverageGaps: [
          {
            domain: 'ghidra_analysis',
            status: 'missing',
            reason: 'Quick triage does not perform a queued Ghidra decompiler pass.',
          },
          {
            domain: 'function_attribution',
            status: stringContextReady ? 'degraded' : 'missing',
            reason: stringContextReady
              ? 'Some string or API context was correlated, but full function-level attribution remains incomplete.'
              : 'String and API evidence is not yet mapped to a full Ghidra-backed function index.',
          },
          {
            domain: 'dynamic_behavior',
            status: 'missing',
            reason: 'No dynamic execution, imported trace replay, or sandbox verification was performed.',
          },
          cryptoSignalsPresent
            ? {
                domain: 'crypto_analysis',
                status: 'missing',
                reason: 'Crypto-related imports or context were observed, but dedicated crypto identification was not run yet.',
              }
            : null,
        ],
        confidenceByDomain: {
          imports: evidenceWeights.import,
          strings: evidenceWeights.string,
          iocs: adjustedConfidence,
          packer:
            compilerPackerInsights.packer_hint || peStructureInsights.packer_hint
              ? Math.max(0.55, adjustedConfidence)
              : 0.3,
          capabilities: staticCapabilityInsights.evidence.length > 0 ? Math.max(0.55, adjustedConfidence) : 0.35,
          graph_context: stringContextReady ? 0.65 : 0.2,
          crypto: cryptoSignalsPresent ? 0.55 : 0.15,
        },
        knownFindings: [
          ...evidence.slice(0, 4),
          adjustedThreatLevel !== 'clean'
            ? `Threat posture assessed as ${adjustedThreatLevel} with confidence ${adjustedConfidence.toFixed(2)}.`
            : null,
        ],
        suspectedFindings: [
          ...inference.hypotheses.slice(0, 3),
          ...yaraLowConfidenceMatches.slice(0, 2).map((item) => `Low-confidence YARA match: ${item}`),
          compilerPackerInsights.packer_hint ? 'Packer or protector indicators suggest additional hidden logic may exist.' : null,
        ],
        unverifiedAreas: [
          'Full function-level decompilation was not performed.',
          'Dynamic behavior and runtime-only indicators remain unverified.',
          cryptoSignalsPresent ? 'Crypto algorithm identity and constant extraction remain unverified.' : null,
        ],
        upgradePaths: [
          {
            tool: 'ghidra.analyze',
            purpose: 'Recover function-level decompilation and attribution.',
            closes_gaps: ['ghidra_analysis', 'function_attribution'],
            expected_coverage_gain: 'Adds function index, decompiler output, and stronger API or string-to-function attribution.',
            cost_tier: 'high',
          },
          {
            tool: stringContextReady ? 'code.xrefs.analyze' : 'analysis.context.link',
            purpose: 'Deepen string, API, and Xref correlation before full reconstruction.',
            closes_gaps: ['function_attribution'],
            expected_coverage_gain: 'Clarifies which functions, strings, and APIs are linked to the top triage findings.',
            cost_tier: 'medium',
          },
          {
            tool: 'workflow.reconstruct',
            purpose: 'Move from quick profile to source-like reconstruction artifacts.',
            closes_gaps: ['reconstruction_export'],
            expected_coverage_gain: 'Adds planning, export, and corroborating backend artifacts beyond triage.',
            cost_tier: 'high',
          },
          cryptoSignalsPresent
            ? {
                tool: 'crypto.identify',
                purpose: 'Turn crypto-related signals into algorithm and constant findings.',
                closes_gaps: ['crypto_analysis'],
                expected_coverage_gain: 'Adds crypto routine, constant, and mode hints before breakpoint planning.',
                cost_tier: 'medium',
              }
            : null,
        ],
      })

      return {
        ok: true,
        data: mergeRoutingMetadata(
          mergeCoverageEnvelope(
            {
              summary,
              confidence: adjustedConfidence,
              threat_level: adjustedThreatLevel,
              iocs,
              evidence: Array.from(new Set(evidence)),
              evidence_weights: evidenceWeights,
              inference,
              recommendation,
              result_mode: 'quick_profile',
              tool_surface_role: 'compatibility',
              preferred_primary_tools: ['workflow.analyze.start', 'workflow.analyze.status', 'workflow.analyze.promote'],
              recommended_next_tools: recommendedNextTools,
              next_actions: nextActions,
              raw_results: rawResults,
            },
            coverageEnvelope
          ),
          routingMetadata
        ),
        warnings: summarizedWarnings.length > 0 ? summarizedWarnings : undefined,
        errors: errors.length > 0 ? errors : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message, ...errors],
        warnings: warnings.length > 0 ? warnings : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
