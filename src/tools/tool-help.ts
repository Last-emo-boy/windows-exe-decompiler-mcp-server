import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import {
  ToolSurfaceRoleSchema,
  buildPreferredPrimaryTools,
} from '../tool-surface-guidance.js'
import {
  rewriteToolReferencesInValue,
  rewriteToolReferencesInText,
  toTransportToolName,
} from '../tool-name-normalization.js'

const TOOL_NAME = 'tool.help'

const ToolFieldSchema = z.object({
  path: z.string(),
  type: z.string(),
  required: z.boolean(),
  nullable: z.boolean(),
  description: z.string().nullable(),
  help_hint: z.string().nullable().optional(),
  default_value: z.any().optional(),
  enum_values: z.array(z.string()).optional(),
})

const ToolSchemaSummarySchema = z.object({
  field_count: z.number().int().nonnegative(),
  fields: z.array(ToolFieldSchema),
})

export const toolHelpInputSchema = z.object({
  tool_name: z.string().optional().describe('Optional exact tool name for a detailed schema/help lookup'),
  include_output_schema: z
    .boolean()
    .default(true)
    .describe('Include output schema field help when the tool defines one'),
  include_fields: z
    .boolean()
    .default(true)
    .describe('When false, only return name/description counts without flattened field help'),
})

export const toolHelpOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    count: z.number().int().nonnegative(),
    tools: z.array(
      z.object({
        name: z.string(),
        description: z.string(),
        surface_role: ToolSurfaceRoleSchema,
        preferred_primary_tools: z.array(z.string()).optional(),
        usage_notes: z.array(z.string()).optional(),
        input: ToolSchemaSummarySchema.optional(),
        output: ToolSchemaSummarySchema.optional(),
      })
    ),
  }),
  errors: z.array(z.string()).optional(),
})

export const toolHelpToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Query normalized schema/help for registered MCP tools, including enum values, defaults, field descriptions, and primary-versus-compatibility surface roles.',
  inputSchema: toolHelpInputSchema,
  outputSchema: toolHelpOutputSchema,
}

function classifyToolSurfaceRole(toolName: string): z.infer<typeof ToolSurfaceRoleSchema> {
  if (
    [
      'workflow.analyze.start',
      'workflow.analyze.status',
      'workflow.analyze.promote',
      'workflow.summarize',
      'sample.ingest',
      'sample.request_upload',
    ].includes(toolName)
  ) {
    return 'primary'
  }

  if (['report.generate'].includes(toolName)) {
    return 'export_only'
  }

  if (['graphviz.render'].includes(toolName)) {
    return 'renderer_helper'
  }

  if (
    [
      'workflow.triage',
      'task.status',
      'report.summarize',
    ].includes(toolName)
  ) {
    return 'compatibility'
  }

  return 'primary'
}

function preferredPrimaryToolsFor(toolName: string) {
  switch (toolName) {
    case 'workflow.triage':
      return ['workflow.analyze.start', 'workflow.analyze.status', 'workflow.analyze.promote']
    case 'task.status':
      return ['workflow.analyze.status']
    case 'report.summarize':
      return ['workflow.summarize']
    case 'report.generate':
      return ['workflow.summarize', 'report.summarize']
    case 'graphviz.render':
      return ['code.function.cfg', 'workflow.summarize', 'report.summarize']
    default:
      return []
  }
}

type FieldSummary = z.infer<typeof ToolFieldSchema>

function unwrapSchema(
  schema: z.ZodTypeAny
): {
  schema: z.ZodTypeAny
  required: boolean
  nullable: boolean
  defaultValue?: unknown
} {
  let current = schema
  let required = true
  let nullable = false
  let defaultValue: unknown

  while (true) {
    if (current instanceof z.ZodOptional) {
      required = false
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodDefault) {
      required = false
      try {
        defaultValue = current._def.defaultValue()
      } catch {
        defaultValue = undefined
      }
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodNullable) {
      nullable = true
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodCatch) {
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodEffects) {
      current = current._def.schema
      continue
    }
    if (current instanceof z.ZodBranded) {
      current = current._def.type
      continue
    }
    if (current instanceof z.ZodReadonly) {
      current = current._def.innerType
      continue
    }
    break
  }

  return {
    schema: current,
    required,
    nullable,
    defaultValue,
  }
}

function describeSchemaType(schema: z.ZodTypeAny): string {
  if (schema instanceof z.ZodString) return 'string'
  if (schema instanceof z.ZodNumber) return 'number'
  if (schema instanceof z.ZodBoolean) return 'boolean'
  if (schema instanceof z.ZodEnum) return 'enum'
  if (schema instanceof z.ZodLiteral) return 'literal'
  if (schema instanceof z.ZodObject) return 'object'
  if (schema instanceof z.ZodArray) {
    const itemInfo = unwrapSchema(schema._def.type)
    return `array<${describeSchemaType(itemInfo.schema)}>`
  }
  if (schema instanceof z.ZodUnion) return 'union'
  if (schema instanceof z.ZodTuple) return 'tuple'
  return 'unknown'
}

function collectSchemaFields(schema: z.ZodTypeAny, prefix = '', toolName?: string): FieldSummary[] {
  const info = unwrapSchema(schema)
  const current = info.schema

  if (current instanceof z.ZodObject) {
    const shape = current.shape as Record<string, z.ZodTypeAny>
    return Object.entries(shape).flatMap(([key, value]) =>
      collectSchemaFields(value, prefix ? `${prefix}.${key}` : key, toolName)
    )
  }

  const field: FieldSummary = {
    path: prefix || '$',
    type: describeSchemaType(current),
    required: info.required,
    nullable: info.nullable,
    description: schema.description || current.description || null,
    help_hint: buildFieldHelpHint(prefix || '$', toolName),
  }

  if (info.defaultValue !== undefined) {
    field.default_value = info.defaultValue
  }
  if (current instanceof z.ZodEnum) {
    field.enum_values = [...current._def.values]
  } else if (current instanceof z.ZodLiteral) {
    field.enum_values = [String(current._def.value)]
  }

  return [field]
}

function buildFieldHelpHint(path: string, toolName?: string): string | null {
  const suffix = path.split('.').pop() || path
  if (toolName === 'sample.ingest') {
    if (path === 'path') {
      return 'Preferred for local files. Pass an absolute path when the MCP client can read the same filesystem as the MCP server.'
    }
    if (path === 'bytes_b64') {
      return 'Fallback only. Use this when the MCP client cannot read the local file path directly, such as remote or browser-hosted clients.'
    }
    if (path === 'filename') {
      return 'Optional display/original filename. Useful when ingesting from bytes_b64 because there is no source path-derived filename.'
    }
    if (path === 'upload_url') {
      return 'Compatibility-only path. Prefer reading sample_id directly from the HTTP upload response and only pass upload_url here for legacy finalize flows.'
    }
  }

  if (toolName === 'sample.request_upload') {
    if (path === 'filename') {
      return 'Optional original filename used to label the upload session and improve later sample display metadata.'
    }
    if (path === 'ttl_seconds') {
      return 'Short-lived upload-session lifetime in seconds. Increase only when the client cannot upload immediately after requesting the URL.'
    }
  }

  if (toolName === 'report.summarize') {
    if (path === 'detail_level') {
      return 'compact is the default AI-facing digest mode and the preferred choice for normal or large samples. Use full only for targeted smaller-sample review; it is still bounded and may omit heavyweight inline fields.'
    }
  }

  if (toolName === 'workflow.summarize') {
    if (path === 'through_stage') {
      return 'Stop after triage/static/deep when you want bounded staged digests, especially for medium or large samples. Use final for the full compact analyst summary workflow.'
    }
    if (path === 'synthesis_mode') {
      return 'auto prefers client-mediated sampling only when supported. deterministic always uses staged digests without client sampling.'
    }
    if (path === 'session_tag') {
      return 'Optional summary-digest session tag used to persist and later reuse a coherent staged summary set.'
    }
  }

  if (toolName === 'workflow.analyze.auto') {
    if (path === 'goal') {
      return 'Use triage for quick profiling, static for queued deep static analysis, reverse for source-like reconstruction, dynamic for readiness plus safe simulation, and report for staged summary synthesis.'
    }
    if (path === 'depth') {
      return 'safe minimizes automatic corroboration, balanced enables bounded safe enrichments, and deep is the most aggressive artifact-first corroboration mode. Prefer safe/balanced first on medium or larger samples; deep is best after a smaller sample or an existing persisted run already established a stable baseline.'
    }
    if (path === 'backend_policy') {
      return 'auto selects corroborating backends only when baseline quality is weak, prefer_new is more eager to use newly installed backends, legacy_only suppresses them, and strict avoids opportunistic escalation.'
    }
    if (path === 'raw_result_mode') {
      return 'Keep compact for ordinary analysis and all large-sample triage. Use full only for targeted smaller-sample debugging when you truly need child tool payloads inline.'
    }
    if (path === 'allow_transformations') {
      return 'This does not auto-unpack or mutate the sample. It only prevents the router from choosing future transform-capable paths by surprise when false.'
    }
    if (path === 'allow_live_execution') {
      return 'Dynamic routing still starts with readiness and safe simulation. Wine remains manual-only and still requires approved=true even when this flag is true.'
    }
  }

  if (
    toolName === 'workflow.analyze.start' ||
    toolName === 'workflow.analyze.status' ||
    toolName === 'workflow.analyze.promote' ||
    toolName === 'workflow.summarize' ||
    toolName === 'report.summarize'
  ) {
    if (path.endsWith('unpack_plan.strategy')) {
      return 'This names the unpack branch the runtime selected, for example none_needed, upx_decompress, guided_memory_dump, or manual_debug_rebuild.'
    }
    if (path.endsWith('unpack_plan.next_safe_step')) {
      return 'Use this as the safe-next-step boundary. It tells you whether the runtime expects preview-only work, dump-oriented progression, rebuild-oriented debugging, or an approval-gated branch.'
    }
  }

  if (suffix === 'coverage_level') {
    return 'Read this first on workflow-style outputs. It tells you whether the result is only a quick profile, static-core digest, deep static pass, reconstruction-level output, or a dynamic-verified result.'
  }
  if (suffix === 'completion_state') {
    return 'Use this instead of guessing from prose. queued means not finished, bounded means intentionally partial, degraded means a deeper stage failed or fell back, and completed means this workflow reached its intended boundary.'
  }
  if (suffix === 'coverage_gaps') {
    return 'Each entry names a domain that is still missing, queued, skipped, blocked, or degraded. Prefer this over free-form warnings when choosing the next step.'
  }
  if (suffix === 'sample_size_tier') {
    return 'Large or oversized samples may trigger bounded workflows first. This field explains part of that cost decision.'
  }
  if (suffix === 'analysis_budget_profile') {
    return 'quick, balanced, and deep describe the cost envelope that shaped the workflow result. A bounded result may still be correct within that budget.'
  }
  if (suffix === 'execution_bucket') {
    return 'This names the scheduler lane that admitted or deferred the work, for example preview-static, enrich-static, deep-attribution, dynamic-plan, or manual-execution.'
  }
  if (suffix === 'cost_class') {
    return 'cheap, moderate, expensive, and manual-only describe how aggressively the runtime will try to admit this work under current budget pressure.'
  }
  if (suffix === 'worker_family') {
    return 'This identifies the pooled backend family or isolated execution family that handled the request. Repeated same-sample requests may reuse a warm compatible family.'
  }
  if (suffix === 'budget_deferral_reason') {
    return 'When present, this explains why the scheduler deferred the work instead of running it immediately.'
  }
  if (suffix === 'warm_reuse') {
    return 'True means the runtime reused a warm compatible worker instead of cold-starting a fresh helper.'
  }
  if (suffix === 'cold_start') {
    return 'True means no compatible warm worker was available, so the runtime paid a fresh startup cost for this request.'
  }
  if (suffix === 'known_findings') {
    return 'Treat these as the currently strongest evidence-backed conclusions within the completed workflow boundary.'
  }
  if (suffix === 'suspected_findings') {
    return 'These are plausible but still heuristic conclusions. They should not be restated as confirmed behavior without a deeper upgrade.'
  }
  if (suffix === 'unverified_areas') {
    return 'These are the main domains the current workflow did not actually cover. Mention them when summarizing to avoid over-claiming.'
  }
  if (suffix === 'upgrade_paths') {
    return 'This is the machine-readable next-step contract. Each path says which gap it closes, what coverage gain it provides, and whether it is ready, blocked, or manual-only.'
  }
  if (suffix === 'packed_state') {
    return 'Read this before assuming the original binary is suitable for deep reconstruction. suspected_packed or confirmed_packed means unpack/debug-aware planning is still relevant.'
  }
  if (suffix === 'unpack_state') {
    return 'This is the unpack lifecycle state, not a generic success flag. approval_gated, unpack_planned, rebuild_required, or unpack_failed_recoverable all mean there is still a bounded next step before treating the sample as fully unpacked.'
  }
  if (suffix === 'unpack_confidence') {
    return 'This is the runtime confidence that packing or unpack progression is real enough to justify the unpack/debug branch. Use it together with packed_state and unpack_state before escalating.'
  }
  if (suffix === 'unpack_plan') {
    return 'This is the machine-readable unpack plan. Read strategy, next_safe_step, proposed_backends, and expected_artifacts instead of improvising a packed-sample workflow.'
  }
  if (suffix === 'debug_state') {
    return 'This names the persisted debug progression. planned or armed means the runtime only prepared a session; captured or correlated means bounded trace evidence already exists.'
  }
  if (suffix === 'debug_session') {
    return 'This is the persisted debug-session envelope. Use its session_tag, guidance, and artifact_refs to continue a session-aware dynamic workflow instead of chaining one-off debug tools.'
  }
  if (suffix === 'diff_digests' || suffix === 'unpack_debug_diffs') {
    return 'These are bounded before/after digests for packed-versus-unpacked or dynamic pre/post changes. Prefer them over raw dump or trace trees when summarizing for AI clients.'
  }

  if (toolName === 'crypto.identify') {
    if (path === 'include_runtime_evidence') {
      return 'Enable this when imported Frida, sandbox, or memory-trace evidence exists and you want static crypto findings strengthened by observed runtime APIs.'
    }
    if (path === 'runtime_evidence_scope') {
      return 'latest is the normal AI-facing mode. Use session only when you need one specific imported runtime session, and all only when comparing multiple trace imports.'
    }
    if (path === 'max_findings') {
      return 'Keep this low for compact AI-facing results. Increase it only when a crypto-heavy sample likely contains multiple distinct routines or algorithm families.'
    }
    if (path === 'max_constants') {
      return 'This caps inline key, IV, S-box, round-constant, or KDF hints. Larger or noisier constant material stays artifact-first.'
    }
  }

  if (toolName === 'breakpoint.smart') {
    if (path === 'max_candidates') {
      return 'Use a small shortlist first. The tool is a planner, not an execution step, so compact high-confidence candidates are usually better than a broad noisy set.'
    }
    if (path === 'include_runtime_evidence') {
      return 'Enable this when imported dynamic evidence exists and you want observed crypto or sensitive API hits to boost breakpoint confidence.'
    }
  }

  if (toolName === 'trace.condition') {
    if (path === 'breakpoint_index') {
      return 'Used only when breakpoint is omitted. It selects a candidate from the latest smart breakpoint artifact, with 0 meaning the top-ranked recommendation.'
    }
    if (path === 'breakpoint') {
      return 'Pass this when you already know the exact planner candidate and do not want trace.condition to look up a breakpoint artifact first.'
    }
    if (path === 'condition') {
      return 'This is a bounded planning DSL, not arbitrary JavaScript. Use predicates over registers, arguments, hit counts, and module/function identity only.'
    }
    if (path === 'capture') {
      return 'Use this to refine registers, arguments, stack bytes, and bounded memory slices. The tool will still cap the total serialized scope to honor max_memory_bytes.'
    }
    if (path === 'max_memory_bytes') {
      return 'This is the total serialization budget across stack capture and bounded memory slices. Oversized capture requests are reduced instead of silently accepted.'
    }
  }

  if (toolName === 'binary.role.profile') {
    if (path === 'mode') {
      return 'Use mode=fast first for normal or large samples. Escalate to mode=full only when export/import/string correlation must be complete.'
    }
    if (path === 'max_exports') {
      return 'Controls how many exports/forwarders are surfaced in the summarized DLL or EXE export map.'
    }
    if (path === 'max_strings') {
      return 'Controls how many strings are inspected for COM/service/plugin heuristics. Increase when profiling installer/plugin-heavy samples.'
    }
  }

  if (toolName === 'dll.export.profile') {
    if (path === 'sample_id') {
      return 'Use this when you want a DLL-first view of exports, callback surfaces, DllMain lifecycle hints, and host/plugin style invocation patterns.'
    }
    if (path === 'max_exports') {
      return 'Increase this for DLLs with broad export surfaces, command dispatch tables, or heavy use of forwarded exports.'
    }
  }

  if (toolName === 'com.role.profile') {
    if (path === 'sample_id') {
      return 'Use this when a PE sample looks like a COM server or exposes registration/class-factory style exports.'
    }
    if (path === 'max_strings') {
      return 'Increase this when CLSID, ProgID, InprocServer32, or interface strings are sparse and you need stronger COM confidence.'
    }
  }

  if (toolName === 'strings.extract') {
    if (path === 'mode') {
      return 'Use mode=preview first for ordinary and large-sample triage. Escalate to mode=full only when a later stage explicitly needs complete extraction.'
    }
  }

  if (toolName === 'analysis.context.link') {
    if (path === 'mode') {
      return 'Use mode=preview first for indicator-to-function triage, especially on medium or larger samples. Escalate to mode=full only when FLOSS plus function-aware Xref context is worth the extra cost.'
    }
  }

  if (toolName === 'crypto.identify') {
    if (path === 'mode') {
      return 'Use mode=preview first for normal and large-sample crypto triage. Escalate to mode=full only when decoded/context correlation is directly needed for breakpoint planning or deeper validation.'
    }
  }

  if (toolName === 'ghidra.analyze') {
    if (path === 'options.processor') {
      return 'Use this when you want analyzeHeadless to force a specific processor/language family. Prefer options.language_id when you already know the exact Ghidra language ID.'
    }
    if (path === 'options.language_id') {
      return 'Useful for Rust/Go/C++ binaries when auto-detection under-identifies functions. Example: x86:LE:64:default.'
    }
    if (path === 'options.cspec') {
      return 'Optional compiler specification override. Use only when the default calling-convention model is clearly wrong.'
    }
    if (path === 'options.script_paths') {
      return 'Appends additional post-script directories to the default Ghidra script path. Useful for custom Rust-aware extraction scripts.'
    }
  }

  if (toolName === 'code.function.cfg') {
    if (path === 'format') {
      return 'json returns a bounded structural preview; dot and mermaid return compact inline text previews plus artifact refs for the full graph.'
    }
    if (path === 'render') {
      return 'svg and png are artifact-first only. The rendered asset is written to reports and returned as an artifact ref; it is not inlined into the MCP response.'
    }
    if (path === 'include_call_relationships') {
      return 'Enable this when you want a bounded local caller/callee graph around the same function. It is not a whole-program call graph.'
    }
    if (path === 'call_relationship_depth') {
      return 'Use depth=1 for direct callers/callees and depth=2 for one extra hop. Higher values are intentionally capped to keep payloads bounded.'
    }
    if (path === 'call_relationship_limit') {
      return 'Caps returned call-graph edges so related-call previews stay compact for MCP clients.'
    }
    if (path === 'preview_max_chars') {
      return 'Controls the inline dot/mermaid preview only. Read the returned graph artifact when you need the full text export.'
    }
    if (path === 'persist_artifacts') {
      return 'Keep this enabled for normal analyst workflows so full graph text and rendered assets can be read later via artifact.read.'
    }
  }

  if (toolName === 'graphviz.render') {
    if (path === 'graph_text') {
      return 'Pass DOT source here. For CFG exports, code.function.cfg already produces DOT artifacts; use graphviz.render when you want a direct backend render step.'
    }
    if (path === 'format') {
      return 'svg is usually the best default for artifact-first graph viewing. png is useful when the downstream client expects a raster image.'
    }
    if (path === 'persist_artifact') {
      return 'Keep this enabled so the rendered graph is written to reports/backend_tools and can be read later via artifact.read.'
    }
  }

  if (toolName === 'rizin.analyze') {
    if (path === 'operation') {
      return 'Use info, sections, imports, or strings for quick file triage; functions is the heaviest option because it asks Rizin to analyze function boundaries first.'
    }
  }

  if (toolName === 'yara_x.scan') {
    if (path === 'rules_text') {
      return 'Use inline rules_text for ad hoc rule experiments from the MCP client. Provide rules_path instead when the rules already exist on the same filesystem as the MCP server.'
    }
    if (path === 'rules_path') {
      return 'This should be a server-readable absolute file path. It is best for reusing a checked-in or mounted YARA-X rule file.'
    }
  }

  if (toolName === 'upx.inspect') {
    if (path === 'operation') {
      return 'test checks whether UPX can validate the sample, list prints packing metadata, and decompress writes an unpacked binary artifact.'
    }
  }

  if (toolName === 'retdec.decompile') {
    if (path === 'output_format') {
      return 'plain returns C-like output; json-human returns a heavier JSON-oriented output file. plain is usually easier for quick analyst review.'
    }
  }

  if (toolName === 'angr.analyze') {
    if (path === 'analysis') {
      return 'cfg_fast is the bounded default and the only currently exposed angr analysis mode in MCP.'
    }
  }

  if (toolName === 'qiling.inspect') {
    if (path === 'operation') {
      return 'Use preflight first. rootfs_probe is for checking whether the mounted Windows rootfs looks usable before trying any emulation-oriented workflow.'
    }
  }

  if (toolName === 'wine.run') {
    if (path === 'mode') {
      return 'preflight never launches the sample. run uses Wine, debug uses winedbg, and both require approved=true.'
    }
    if (path === 'approved') {
      return 'This must be true before MCP will attempt to start the sample under Wine or winedbg.'
    }
  }

  if (toolName === 'pe.pdata.extract') {
    if (path === 'sample_id') {
      return 'Use this first when a PE32+ / Rust sample has zero Ghidra functions. It reads the exception directory / .pdata directly without requiring Ghidra function discovery.'
    }
  }

  if (toolName === 'code.functions.smart_recover') {
    if (path === 'sample_id') {
      return 'Use this when Ghidra function extraction fails or returns zero functions. It recovers candidate boundaries from .pdata, exports, and the entry point.'
    }
  }

  if (toolName === 'pe.symbols.recover') {
    if (path === 'sample_id') {
      return 'Use this after pe.pdata.extract or code.functions.smart_recover when you need more descriptive recovered symbol names for Rust/Go/C++ binaries.'
    }
    if (path === 'max_string_hints') {
      return 'Increase this when you want more Rust crate path or runtime string hints to influence recovered names.'
    }
  }

  if (toolName === 'code.functions.define') {
    if (path === 'definitions') {
      return 'Accepts manual definitions or outputs adapted from code.functions.smart_recover / pe.symbols.recover. Each entry needs address, va, or rva.'
    }
    if (path === 'replace_all') {
      return 'When true, the current function index for this sample is deleted before the imported definitions are inserted.'
    }
    if (path === 'source') {
      return 'Use pdata, symbols_recover, smart_recover, manual, or external so later reports clearly show where this function index came from.'
    }
  }

  if (toolName === 'rust_binary.analyze') {
    if (path === 'sample_id') {
      return 'Use this as a high-level Rust triage entrypoint when a PE sample looks Rust-like or Ghidra returns zero functions.'
    }
    if (path === 'max_strings') {
      return 'Increase this when Rust crate paths, panic strings, or async/runtime markers are sparse and you need stronger crate/runtime evidence.'
    }
    if (path === 'max_symbol_preview') {
      return 'Controls how many recovered symbol names are surfaced from pe.symbols.recover in one response.'
    }
  }

  if (toolName === 'workflow.function_index_recover') {
    if (path === 'define_from') {
      return 'auto prefers pe.symbols.recover names when available; smart_recover keeps synthetic/import/export-derived names only.'
    }
    if (path === 'max_string_hints') {
      return 'Forwarded to pe.symbols.recover so recovered names can use more Rust/Go/C++ crate and runtime hints.'
    }
    if (path === 'replace_all') {
      return 'Recommended when you want the recovered index to replace an empty or stale function index from a failed Ghidra run.'
    }
  }

  if (toolName === 'static.capability.triage') {
    if (path === 'sample_id') {
      return 'Use this after sample.ingest for capability-style behavior recognition. It is most useful early in triage before deep reconstruct.'
    }
    if (path === 'rules_path') {
      return 'Optional override for a capa rules directory or rules file. Prefer CAPA_RULES_PATH or workers.static.capaRulesPath for persistent configuration.'
    }
  }

  if (toolName === 'pe.structure.analyze') {
    if (path === 'sample_id') {
      return 'Use this when you need one canonical PE structure view that merges pefile and LIEF outputs instead of calling separate import/export/header tools.'
    }
  }

  if (toolName === 'compiler.packer.detect') {
    if (path === 'sample_id') {
      return 'Use this during early-stage triage when you want compiler, packer, protector, and file-type attribution from Detect It Easy.'
    }
    if (path === 'timeout_sec') {
      return 'Increase this for large or heavily packed binaries when Detect It Easy classification is slow.'
    }
  }

  if (toolName === 'code.module.review.prepare') {
    if (path === 'sample_id') {
      return 'Use this when reconstruct already produces grouped modules and you want an external LLM to review module roles, summaries, and rewrite guidance.'
    }
    if (path === 'role_target') {
      return 'Forward a binary-role hint such as dll_library, com_server, or native_rust_executable so module preparation keeps role-aware modules visible.'
    }
  }

  if (toolName === 'code.module.review') {
    if (path === 'role_focus_areas') {
      return 'Useful for DLL/COM/plugin samples when you want module review to emphasize export dispatch, class factory, callback surface, or lifecycle modules.'
    }
  }

  if (toolName === 'workflow.module_reconstruction_review') {
    if (path === 'rerun_export') {
      return 'When true, the workflow refreshes reconstruct/export after module reviews are applied so rewrite headers and reverse_notes.md reflect the new module guidance.'
    }
    if (path === 'export_path') {
      return 'auto is usually correct. Override to native or dotnet only when you already know the reconstruction path that should be refreshed after module review.'
    }
  }

  if (toolName === 'system.setup.guide') {
    if (path === 'focus') {
      return 'Use all for a first-run bootstrap guide, static for PE/graph/toolchain extras such as Graphviz/Rizin/YARA-X/RetDec, ghidra for install path/project-root guidance, and dynamic for runtime-analysis extras such as Frida/Qiling/angr/PANDA/Wine.'
    }
    if (path === 'include_optional') {
      return 'When false, only required setup steps are returned. Leave true to include optional extras such as PyGhidra, Graphviz/Rizin/RetDec, and dynamic-analysis components like Qiling/angr/PANDA.'
    }
  }

  if (path === 'evidence_scope') {
    return 'Controls runtime evidence selection only. Use session for one runtime import/replay lineage, latest for the newest artifact window, all to aggregate historical runtime evidence.'
  }
  if (path === 'evidence_session_tag') {
    return 'Required when evidence_scope=session. You can also pass it with all/latest to narrow runtime evidence to one named session.'
  }
  if (path === 'static_scope') {
    return 'Controls static-analysis artifact selection only. Use session to consume one capability/PE-structure/toolchain triage session, latest for the newest static-analysis artifact window, all to aggregate historical static-analysis artifacts.'
  }
  if (path === 'static_session_tag') {
    return 'Required when static_scope=session. Usually set this to the session_tag used when persisting static capability, PE structure, or compiler/packer artifacts.'
  }
  if (path === 'semantic_scope') {
    return 'Controls semantic naming/explanation artifact selection only. Use session to consume one naming or explanation review pass, latest for the newest semantic artifact window, all to aggregate historical semantic artifacts.'
  }
  if (path === 'semantic_session_tag') {
    return 'Required when semantic_scope=session. Usually set this to the naming or explanation review session_tag you want reconstruct/export/report to consume.'
  }
  if (path === 'session_tag') {
    return 'Session tag groups newly created artifacts so later MCP calls can select this exact review/export/import session.'
  }
  if (path === 'path_prefix') {
    return 'Use this to narrow artifact tools to one export directory such as reports/reconstruct/<session>.'
  }
  return null
}

function buildUsageNotes(definition: ToolDefinition): string[] {
  const notes: string[] = []
  if (definition.name === 'system.setup.guide') {
    notes.push(
      'Use this before first-run or after a degraded health probe when the MCP client needs exact pip install commands and required user-supplied paths such as JAVA_HOME, GHIDRA_PATH, or GHIDRA_PROJECT_ROOT.'
    )
    notes.push(
      'For Docker-heavy environments, use focus=static to review Graphviz/Rizin/YARA-X/RetDec setup and focus=dynamic to review Frida/Qiling/angr/PANDA/Wine guidance.'
    )
  }
  if (
    definition.name === 'dynamic.dependencies' ||
    definition.name === 'system.health' ||
    definition.name === 'ghidra.health'
  ) {
    notes.push(
      'When the environment is degraded, inspect setup_actions and required_user_inputs before retrying. These fields are intended for MCP clients to present exact pip install commands and missing path inputs.'
    )
  }
  const inputFields = buildSchemaSummary(definition.inputSchema, definition.name).fields.map((item) => item.path)
  const outputFields = definition.outputSchema
    ? buildSchemaSummary(definition.outputSchema, definition.name).fields.map((item) => item.path)
    : []

  const hasEvidenceScope = inputFields.includes('evidence_scope')
  const hasStaticScope = inputFields.includes('static_scope')
  const hasSemanticScope = inputFields.includes('semantic_scope')
  const hasSessionTag = inputFields.includes('session_tag')

  if (hasEvidenceScope && hasStaticScope && hasSemanticScope) {
    notes.push(
      'This tool separates runtime, static-analysis, and semantic artifact scopes. Set all three explicitly when you need fully reproducible session-only results.'
    )
  } else if (hasEvidenceScope && hasSemanticScope) {
    notes.push(
      'This tool separates runtime evidence scope from semantic artifact scope. Set both when you need fully reproducible session-only results.'
    )
  } else if (hasEvidenceScope) {
    notes.push(
      'This tool consumes runtime evidence artifacts. Prefer evidence_scope=session plus evidence_session_tag for one replay/import session.'
    )
  }

  if (hasStaticScope) {
    notes.push(
      'This tool consumes static-analysis artifacts such as capability triage, PE structure analysis, and compiler/packer attribution. Prefer static_scope=session plus static_session_tag to avoid mixing historical triage runs.'
    )
  }

  if (hasSemanticScope) {
    notes.push(
      'This tool consumes naming/explanation artifacts. Prefer semantic_scope=session plus semantic_session_tag to avoid mixing historical LLM outputs.'
    )
  }

  if (hasSessionTag) {
    notes.push(
      'session_tag labels newly created artifacts. Reuse that tag in later semantic_scope=session or artifacts.diff calls.'
    )
  }

  if (
    outputFields.includes('data.coverage_level') ||
    outputFields.includes('coverage_level')
  ) {
    notes.push(
      'On workflow-style outputs, read coverage_level, completion_state, coverage_gaps, known_findings, suspected_findings, unverified_areas, and upgrade_paths before treating the result as complete.'
    )
  }

  if (definition.name === 'artifacts.list') {
    notes.push(
      'Use session_tag, path_prefix, or latest_only to narrow artifact views before reading or diffing files.'
    )
  }

  if (definition.name === 'artifacts.diff') {
    notes.push(
      'Diff two session_tag values after export, naming review, explanation review, or runtime import to see what changed between analysis rounds.'
    )
  }

  if (definition.name === 'tool.help') {
    notes.push(
      'Query this tool first when an MCP client needs exact enum values, defaults, or scope/session usage guidance before calling another tool.'
    )
    notes.push(
      'For explicit backend requests, inspect graphviz.render, rizin.analyze, yara_x.scan, upx.inspect, retdec.decompile, angr.analyze, qiling.inspect, panda.inspect, and wine.run.'
    )
  }

  if (definition.name === 'task.status') {
    notes.push(
      'For queued or running jobs, inspect polling_guidance and prefer one client-side sleep/wait before the next status check instead of repeated immediate polling.'
    )
    notes.push(
      'Read execution_bucket, cost_class, worker_family, warm_reuse, cold_start, and budget_deferral_reason to understand whether the job is waiting on lane capacity, approval, or cold-start overhead.'
    )
  }

  if (definition.name === 'sample.ingest') {
    notes.push(
      'Prefer path for local files. Use bytes_b64 only when the MCP client cannot access the same local filesystem as the MCP server.'
    )
    notes.push(
      'When both path and bytes_b64 are provided, path wins. Passing an absolute file path is the most reliable option for local VS Code/Copilot clients.'
    )
    notes.push(
      'For host-machine files outside the container, prefer sample.request_upload and read sample_id directly from the HTTP upload response instead of calling sample.ingest(path).'
    )
  }

  if (definition.name === 'sample.request_upload') {
    notes.push(
      'Use this as the primary host-file ingest entrypoint when the MCP worker cannot read the host path directly.'
    )
    notes.push(
      'The usual follow-up is HTTP POST to upload_url, then continue analysis with the returned sample_id. sample.ingest(upload_url) is compatibility-only.'
    )
  }

  if (definition.name === 'workflow.triage') {
    notes.push(
      'This is a bounded fast-profile facade over the persisted staged runtime, not the final reverse-engineering step.'
    )
    notes.push(
      'If the user only asked to analyze a sample without naming a workflow, prefer workflow.analyze.auto first so the server can route by intent.'
    )
    notes.push(
      'Use workflow.triage directly mainly for small/medium samples or when the user explicitly asks for a quick profile. For large samples, prefer workflow.analyze.start or workflow.analyze.auto so the result can persist and queue deeper stages.'
    )
    notes.push(
      'Use coverage_gaps and upgrade_paths instead of prose to decide whether you still need workflow.analyze.promote, analysis.context.link, crypto.identify, or workflow.reconstruct.'
    )
  }

  if (definition.name === 'workflow.analyze.start') {
    notes.push(
      'This starts or reuses a persisted staged analysis run. Only the fast_profile stage executes inline; heavier stages are queued by default.'
    )
    notes.push(
      'Use workflow.analyze.status to monitor run progress and workflow.analyze.promote to queue deeper stages without rerunning completed work.'
    )
    notes.push(
      'Large or expensive samples benefit from this nonblocking pattern. The run persists stage completion, artifact refs, and reuse metadata.'
    )
    notes.push(
      'Practical pattern: small samples may go start -> summarize quickly, but medium/large samples should usually go start -> status -> promote instead of jumping straight to heavyweight tools.'
    )
    notes.push(
      'Use workflow.analyze.status to inspect scheduler bucket, worker-family reuse, and deferred-stage reasons instead of treating queued work as a generic FIFO backlog.'
    )
    notes.push(
      'On packed samples, fast_profile now emits packed_state, unpack_state, and unpack_plan. Treat that as the first-class unpack routing contract instead of jumping straight into Ghidra or reconstruction.'
    )
    notes.push(
      'allow_transformations only enables later safe unpack attempts such as UPX decompress; it does not mutate the sample during workflow.analyze.start itself.'
    )
  }

  if (definition.name === 'workflow.analyze.status') {
    notes.push(
      'Query this to inspect deferred jobs, completed stages, and reusable artifact refs for a persisted analysis run.'
    )
    notes.push(
      'Use the returned recommended_next_tools and next_actions instead of repeating the same start call.'
    )
    notes.push(
      'Read recovery_state, recoverable_stages, evidence_state, and provenance_visibility before assuming the persisted run is complete after a worker restart or interrupted queue job.'
    )
    notes.push(
      'Stage rows now include execution_bucket, cost_class, worker_family, warm_reuse, and budget_deferral_reason so you can tell whether a result came from a warm preview lane or was deferred behind deeper work.'
    )
    notes.push(
      'Read expected_rss_mb, current_rss_mb, memory_limit_mb, and control_plane_headroom_mb when large-sample work is deferred. Those fields explain whether the runtime protected the MCP control plane from OOM.'
    )
    notes.push(
      'On medium/large samples, this is the normal next call after workflow.analyze.start or workflow.analyze.promote. Do not repeat the original start/triage call while the run is already queued or partial.'
    )
    notes.push(
      'For packed or dynamically planned samples, read packed_state, unpack_state, debug_state, unpack_plan, debug_session, and diff_digests before assuming the original sample is ready for deeper static reconstruction.'
    )
  }

  if (definition.name === 'workflow.analyze.promote') {
    notes.push(
      'Use this to promote an existing run to deeper stages (enrich_static, function_map, reconstruct, etc.) without rerunning the fast_profile stage.'
    )
    notes.push(
      'Pass stages to promote specific stages, or through_stage to promote through a target stage boundary.'
    )
    notes.push(
      'Promoted stages are scheduler-governed. Deep stages may remain deferred while cheaper preview or artifact-only lanes are draining.'
    )
    notes.push(
      'If a large-sample stage is deferred for memory headroom, do not retry it immediately. Wait for workflow.analyze.status to show earlier heavy work cleared, then promote again only if the deeper stage is still needed.'
    )
    notes.push(
      'Typical large-sample order is enrich_static first, then function_map, then reconstruct only when code-level output is actually needed.'
    )
    notes.push(
      'For packed samples, prefer promoting into dynamic_plan first so the server can persist debug-session guidance and safe unpack preparation before any heavier execution-oriented stage.'
    )
    notes.push(
      'Only promote dynamic_execute when the run was created with the required transformation or live-execution policy and status still says the unpack/debug branch is needed.'
    )
  }

  if (definition.name === 'strings.extract') {
    notes.push(
      'mode=preview is bounded and safe for synchronous MCP use. mode=full scans the complete sample and may be deferred to the background queue for large samples.'
    )
    notes.push(
      'Use mode=preview when you only need a bounded first-pass IOC and noise-filtered string view. Promote to mode=full when FLOSS or complete string extraction is required.'
    )
    notes.push(
      'Small samples can often tolerate mode=full when strings are the main question. Medium/large samples should stay in mode=preview unless a later stage explicitly needs complete extraction.'
    )
    notes.push(
      'Large-sample full results may return a bounded inline digest plus chunk_manifest and persisted chunk artifacts. Use artifact.read instead of expecting one monolithic inline payload.'
    )
  }

  if (definition.name === 'binary.role.profile') {
    notes.push(
      'mode=fast reuses preview strings and bounded heuristics. mode=full requests complete supporting evidence and may be deferred.'
    )
    notes.push(
      'Use mode=fast for an immediate role hint. Promote to mode=full when you need complete export/import/string correlation.'
    )
    notes.push(
      'On larger DLLs or plugin-style samples, keep this in mode=fast during the first pass and only escalate after the persisted run proves the deeper correlation is worth the budget.'
    )
  }

  if (definition.name === 'analysis.context.link') {
    notes.push(
      'mode=preview provides string-level context without waiting on Ghidra-backed attribution. mode=full includes FLOSS and function-aware Xref correlation.'
    )
    notes.push(
      'Use mode=preview for first-pass indicator-to-function context. Promote to mode=full when you need merged FLOSS output and deeper Xref attribution.'
    )
    notes.push(
      'Check evidence_state to tell whether the compact context came from fresh correlation, canonical reuse, or a deferred full pass.'
    )
    notes.push(
      'For larger samples, use preview first and wait for function-level readiness before escalating. full is most useful after persisted function attribution or when the current question is explicitly about merged FLOSS plus Xref context.'
    )
    notes.push(
      'Large-sample full outputs may be chunked. Treat chunk_manifest plus artifact refs as the authoritative continuation path instead of reissuing the same full request.'
    )
  }

  if (definition.name === 'crypto.identify') {
    notes.push(
      'mode=preview is the bounded default and avoids full decoded/context correlation on larger samples. mode=full may defer to the queue when the sample exceeds the synchronous budget.'
    )
    notes.push(
      'Use evidence_state to distinguish fresh crypto correlation from persisted artifact reuse or deferred full execution.'
    )
    notes.push(
      'For larger samples, preview is the normal planning pass. Escalate to full only when crypto findings directly drive breakpoint planning or you need stronger constant/context corroboration.'
    )
    notes.push(
      'Full crypto results on larger samples may return only a bounded inline digest plus chunked persisted findings. Follow chunk_manifest or workflow.analyze.status rather than retrying immediately.'
    )
  }

  if (definition.name === 'workflow.dynamic.analyze') {
    notes.push(
      'Staged dynamic behavior analysis with simulation-first defaults.'
    )
    notes.push(
      'Use mode=safe_simulation for non-executing behavioral analysis, or mode=auto_frida for automated Frida instrumentation.'
    )
    notes.push(
      'The auto_frida mode automatically generates Frida scripts based on static capability analysis and correlates results to functions.'
    )
    notes.push(
      'Stages: preflight → simulation → trace_capture → correlation → digest'
    )
  }

  if (definition.name === 'workflow.analyze.auto') {
    notes.push(
      'Prefer this when the user asks for analysis, reverse engineering, dynamic checks, or reporting without naming a specific workflow or backend.'
    )
    notes.push(
      'This router now translates intent into workflow.analyze.start and workflow.analyze.promote operations instead of launching legacy heavyweight chains directly.'
    )
    notes.push(
      'Execution-capable backends such as wine.run remain manual-only. allow_live_execution does not bypass approved=true.'
    )
    notes.push(
      'Large or expensive samples may intentionally downshift to a bounded persisted profile first. Check run_id, sample_size_tier, analysis_budget_profile, downgrade_reasons, and upgrade_paths before escalating.'
    )
    notes.push(
      'Practical playbook: for small samples, auto(goal=triage, depth=balanced) is usually fine. For medium/large samples, use auto(goal=triage, depth=safe|balanced), keep outputs compact, then continue with workflow.analyze.status and workflow.analyze.promote.'
    )
  }

  if (definition.name === 'workflow.triage') {
    notes.push(
      'workflow.triage is a compatibility quick-profile surface. The primary staged analysis path is workflow.analyze.start followed by workflow.analyze.status and workflow.analyze.promote.'
    )
  }

  if (definition.name === 'task.status') {
    notes.push(
      'task.status is the raw job-state view. Prefer workflow.analyze.status when you have a run_id and want the primary staged-runtime view.'
    )
  }

  if (definition.name === 'report.generate') {
    notes.push(
      'report.generate is export-oriented. Use workflow.summarize or report.summarize for AI-facing analysis synthesis, and treat this tool as an archival/export helper.'
    )
  }

  if (definition.name === 'llm.analyze') {
    notes.push(
      'Unified LLM analysis interface. Use this instead of the deprecated 3-step tools (code.function.rename.*, code.function.explain.*, code.module.review.*).'
    )
    notes.push(
      'Supports 4 task types: summarize (concise summaries), explain (clear explanations), recommend (actionable recommendations), review (critical review).'
    )
    notes.push(
      'Automatically handles context management, smart triggering, and token tracking through MCP Client sampling.'
    )
    notes.push(
      'Migration: See docs/MIGRATION-LLM-TOOLS.md for examples of migrating from old 3-step API to new unified interface.'
    )
  }

  if (definition.name === 'system.health') {
    notes.push(
      'Use this after setup_required or degraded-environment failures. In a healthy environment, continue with analysis workflows instead of repeatedly calling health probes.'
    )
    notes.push(
      'In the full Docker image, this probe also reports Graphviz, Rizin, YARA-X, UPX, Wine/winedbg, Frida CLI, Qiling, angr, PANDA, and RetDec readiness together with their caveats.'
    )
  }

  if (definition.name === 'dynamic.dependencies') {
    notes.push(
      'This probe is broader than Speakeasy/Frida. It also surfaces Frida CLI, Qiling, angr, PANDA, and Wine/winedbg readiness plus QILING_ROOTFS caveats.'
    )
  }

  if (definition.name === 'workflow.deep_static' || definition.name === 'workflow.reconstruct') {
    notes.push(
      'If the user has not explicitly chosen this workflow, prefer workflow.analyze.auto so the server can select the appropriate workflow by intent first.'
    )
    notes.push(
      'Inspect completion_state and coverage_gaps before assuming queued, bounded, or degraded results contain the same depth as a fully completed run.'
    )
  }

  if (definition.name === 'workflow.summarize' || definition.name === 'report.summarize') {
    notes.push(
      'These summary surfaces restate the current analysis boundary. Use known_findings, suspected_findings, and unverified_areas instead of flattening everything into one confidence claim.'
    )
    notes.push(
      'Read persisted_state_visibility to see which run stages were reused and which deeper prerequisites remain deferred instead of assuming the report backfilled missing analysis.'
    )
    notes.push(
      'When packed_state, unpack_state, debug_state, or unpack_debug_diffs are present, summarize them explicitly. They explain whether the current conclusion is still based on the original packed binary, an unpacked derivative, or bounded debug-session artifacts.'
    )
    if (definition.name === 'workflow.summarize') {
      notes.push(
        'Prefer workflow.summarize for medium/large samples or whenever analysis already progressed through queued stages. It keeps the final output staged and compact.'
      )
    } else {
      notes.push(
        'Prefer report.summarize(detail_level=compact) for quick deterministic snapshots. Avoid detail_level=full on large samples; use workflow.summarize plus artifact.read instead.'
      )
    }
  }

  if (
    definition.name === 'frida.runtime.instrument' ||
    definition.name === 'frida.script.inject' ||
    definition.name === 'frida.trace.capture'
  ) {
    notes.push(
      'The full Docker image also bundles frida-tools CLI, but these MCP tools remain the primary entrypoints when a user explicitly asks for Frida-driven tracing or instrumentation.'
    )
  }

  if (definition.name === 'graphviz.render') {
    notes.push(
      'graphviz.render is a renderer/export helper over an existing graph. Use it when an MCP client explicitly asks for Graphviz rendering; it is not itself a deeper analysis step.'
    )
    notes.push(
      'For Ghidra-backed CFG semantics, code.function.cfg remains the main upstream graph surface and Graphviz is only the render target.'
    )
  }

  if (definition.name === 'rizin.analyze') {
    notes.push(
      'This is the direct Rizin wrapper. Use it when the user explicitly requests Rizin output or when you want a lightweight second opinion before deeper Ghidra work.'
    )
    notes.push(
      'Rizin is often the better first static backend for medium/large samples when you need fast sections/imports/strings/functions previews before escalating to Ghidra.'
    )
  }

  if (definition.name === 'ghidra.analyze') {
    notes.push(
      'Use Ghidra after fast triage or Rizin-backed preview when function attribution, decompilation, or source-like reconstruction is actually needed. It is usually not the best first call for large samples.'
    )
  }

  if (definition.name === 'yara_x.scan') {
    notes.push(
      'Use this when the user explicitly asks for YARA-X or when you want to compare newer-engine matches with the legacy yara.scan output.'
    )
  }

  if (definition.name === 'upx.inspect') {
    notes.push(
      'Use this when the user explicitly asks for UPX validation or unpacking. decompress writes an unpacked artifact instead of modifying the original sample in place.'
    )
    notes.push(
      'This is the preferred safe unpack probe for suspected or confirmed UPX samples. Use test or list first, then decompress only when the packed-sample plan already points to a bounded UPX path.'
    )
    notes.push(
      'After a successful decompress artifact is produced, continue analysis from the unpacked artifact or unpacked sample_id and use the packed-vs-unpacked diff digest instead of comparing raw trees inline.'
    )
  }

  if (definition.name === 'retdec.decompile') {
    notes.push(
      'Use this when the user explicitly asks for RetDec output or wants an alternate decompiler artifact to compare against Ghidra.'
    )
  }

  if (definition.name === 'angr.analyze') {
    notes.push(
      'Use this when the user explicitly asks for angr or when you want a bounded CFGFast pass as a cross-check for function recovery.'
    )
  }

  if (definition.name === 'qiling.inspect') {
    notes.push(
      'Use this when the user explicitly asks about Qiling or when you need to confirm QILING_ROOTFS readiness before any emulation-oriented workflow.'
    )
  }

  if (definition.name === 'panda.inspect') {
    notes.push(
      'Use this when the user explicitly asks about PANDA. It confirms bindings and caveats, but guest images and trace assets still live outside the MCP server.'
    )
  }

  if (definition.name === 'wine.run') {
    notes.push(
      'Use this only for explicit Wine or winedbg requests. preflight is safe; run and debug require approved=true because they attempt to launch the sample.'
    )
  }

  if (definition.name === 'binary.role.profile') {
    notes.push(
      'Use this tool before deep reconstruct when you need a universal EXE/DLL/driver/COM/plugin role summary and export/import entry map.'
    )
    notes.push(
      'The returned analysis_priorities are intended to guide later MCP calls such as code.functions.search, ghidra.analyze, workflow.reconstruct, or dynamic.memory.import.'
    )
  }

  if (definition.name === 'dll.export.profile') {
    notes.push(
      'Use this tool when a sample is DLL-like and you want a focused view of exports, forwarders, DllMain-style lifecycle hints, and plugin/host callback behavior.'
    )
    notes.push(
      'Prefer this before workflow.reconstruct for DLLs, shell extensions, plugins, and command-dispatch libraries so later analysis is role-aware.'
    )
  }

  if (definition.name === 'com.role.profile') {
    notes.push(
      'Use this tool when you suspect COM registration or class-factory behavior. It highlights CLSID, ProgID, registration strings, and DllGetClassObject-style exports.'
    )
    notes.push(
      'Prefer this before reconstruct or semantic review on COM servers so naming and explanation passes start from activation-flow context instead of generic DLL assumptions.'
    )
  }

  if (definition.name === 'pe.pdata.extract') {
    notes.push(
      'Use this tool when Ghidra post-scripts fail or a Rust x64 sample reports zero functions. It parses PE unwind metadata directly and does not require successful Ghidra function indexing.'
    )
  }

  if (definition.name === 'code.functions.smart_recover') {
    notes.push(
      'Use this tool after pe.pdata.extract or failed ghidra.analyze runs to recover candidate function boundaries for Rust/Go/C++ binaries with degraded Ghidra support.'
    )
  }

  if (definition.name === 'pe.symbols.recover') {
    notes.push(
      'Use this after code.functions.smart_recover when you want more descriptive recovered names derived from exports, entry point, runtime hints, and Rust crate strings.'
    )
    notes.push(
      'The returned symbols can be fed into code.functions.define to establish a reusable function index with recovered names.'
    )
  }

  if (definition.name === 'code.functions.define') {
    notes.push(
      'Use this to import function boundaries from pe.pdata.extract, code.functions.smart_recover, pe.symbols.recover, or external reverse-engineering tooling.'
    )
    notes.push(
      'This establishes function-index readiness only. It does not imply Ghidra decompile or CFG readiness.'
    )
  }

  if (definition.name === 'rust_binary.analyze') {
    notes.push(
      'This tool aggregates runtime.detect, strings.extract, code.functions.smart_recover, pe.symbols.recover, and binary.role.profile into one Rust-focused assessment.'
    )
    notes.push(
      'Use it before manual recovery on Rust/Go/C++ samples when you need crate hints, recovered symbol previews, and concrete next steps for code.functions.define.'
    )
  }

  if (definition.name === 'workflow.function_index_recover') {
    notes.push(
      'This workflow chains code.functions.smart_recover, pe.symbols.recover, and code.functions.define so difficult Rust/Go/C++ samples can materialize a reusable function index without a successful Ghidra decompile pass.'
    )
    notes.push(
      'Use this after ghidra.analyze returns zero functions or degraded function_index readiness. The output includes imported function previews and an optional ranked preview.'
    )
  }

  if (definition.name === 'static.capability.triage') {
    notes.push(
      'Use this after sample.ingest to recover capa-style behavior capabilities such as service installation, HTTP communication, injection, persistence, or crypto behavior.'
    )
    notes.push(
      'When setup_actions or required_user_inputs are returned, install flare-capa and configure CAPA_RULES_PATH before retrying.'
    )
  }

  if (definition.name === 'pe.structure.analyze') {
    notes.push(
      'Use this when you need one canonical PE structure response with headers, sections, imports, exports, resources, overlay, and backend-specific detail blocks.'
    )
  }

  if (definition.name === 'compiler.packer.detect') {
    notes.push(
      'Use this tool early in triage to identify likely compiler, packer, protector, and primary file-type attribution with Detect It Easy.'
    )
    notes.push(
      'If Detect It Easy is missing, inspect setup_actions and required_user_inputs instead of retrying blindly. Provide DIE_PATH or put diec.exe on PATH.'
    )
  }

  if (definition.name === 'code.module.review.prepare') {
    notes.push(
      'Use this when grouped modules already exist and you want an external LLM to review module roles, summaries, and rewrite guidance instead of focusing on individual functions.'
    )
  }

  if (definition.name === 'code.module.review') {
    notes.push(
      'This is the module-level analogue of code.function.explain.review. It uses MCP sampling when available and otherwise returns a prompt contract for any tool-calling LLM client.'
    )
  }

  if (definition.name === 'workflow.module_reconstruction_review') {
    notes.push(
      'Use this high-level workflow when you want module review plus an optional reconstruct/export refresh in one MCP call.'
    )
  }

  if (
    definition.name === 'analysis.context.link' ||
    definition.name === 'code.xrefs.analyze'
  ) {
    notes.push(
      'Use these before workflow.reconstruct when you want bounded indicator-to-function correlation without paying for full export or module reconstruction.'
    )
  }

  if (definition.name === 'strings.extract') {
    notes.push(
      'strings.extract is now compact-first and enriched with runtime-noise, IOC-like, and encoded-candidate labels. Prefer analysis.context.link when you need merged FLOSS output and function-aware attribution.'
    )
  }

  if (definition.name === 'strings.floss.decode') {
    notes.push(
      'Use this when stack/tight/decoded strings matter. analysis.context.link can merge FLOSS output with raw extraction and xref-derived function context.'
    )
  }

  if (definition.name === 'crypto.identify') {
    notes.push(
      'This is a correlation layer over imports, enriched strings, compact xrefs, capability hints, and optional imported runtime evidence. It does not require live execution.'
    )
    notes.push(
      'Use it before breakpoint.smart when static capability triage says cryptography is present but you still need concrete functions, addresses, and bounded constant summaries.'
    )
  }

  if (definition.name === 'breakpoint.smart') {
    notes.push(
      'This tool is planning-only. It ranks likely crypto and sensitive API breakpoint sites but does not start or attach to any process.'
    )
    notes.push(
      'Use trace.condition after this to turn a top candidate into a bounded Frida-oriented trace plan with capture limits and readiness guidance.'
    )
    notes.push(
      'For packed or session-aware dynamic analysis, treat this as the bridge from unpack planning into a persisted debug session. It should refine what to capture, not start live instrumentation immediately.'
    )
  }

  if (definition.name === 'trace.condition') {
    notes.push(
      'trace.condition consumes either an explicit breakpoint candidate or the latest smart breakpoint artifact and turns it into a bounded normalized trace plan.'
    )
    notes.push(
      'It does not execute instrumentation. Instead it tells you which existing runtime tool to invoke next and keeps setup_required boundaries explicit when Frida is not ready.'
    )
    notes.push(
      'Use the returned plan as a debug-session artifact. The normal follow-up is workflow.analyze.status, explicit Frida capture, or another approved execution surface, not an ad hoc one-off trace command.'
    )
  }

  if (
    definition.name === 'ghidra.analyze' ||
    definition.name === 'workflow.deep_static' ||
    definition.name === 'workflow.reconstruct' ||
    definition.name === 'workflow.semantic_name_review' ||
    definition.name === 'workflow.function_explanation_review' ||
    definition.name === 'workflow.module_reconstruction_review'
  ) {
    notes.push(
      'Queued responses include polling_guidance. If your MCP client can sleep or wait, follow that guidance instead of repeatedly polling task.status.'
    )
  }

  if (definition.name === 'ghidra.analyze') {
    notes.push(
      'For Rust or other hard-to-index binaries, combine ghidra.analyze with pe.pdata.extract or code.functions.smart_recover. When auto-detection is weak, set options.language_id, options.cspec, or options.script_paths explicitly.'
    )
  }

  if (
    definition.name === 'sample.request_upload' ||
    definition.name === 'sample.ingest' ||
    definition.name === 'workflow.triage' ||
    definition.name === 'system.health'
  ) {
    notes.push(
      'These tools return explicit next-step guidance fields. Prefer those machine-readable hints before inventing a custom follow-up sequence.'
    )
  }

  return notes
}

function buildSchemaSummary(schema: z.ZodTypeAny, toolName?: string): z.infer<typeof ToolSchemaSummarySchema> {
  const fields = collectSchemaFields(schema, '', toolName)
  return {
    field_count: fields.length,
    fields,
  }
}

export function createToolHelpHandler(
  getDefinitions: () => ToolDefinition[]
): (args: ToolArgs) => Promise<WorkerResult> {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    try {
      const input = toolHelpInputSchema.parse(args)
      const definitions = getDefinitions()
      const nameMappings = definitions.map((item) => [item.name, toTransportToolName(item.name)] as const)
      const filtered = input.tool_name
        ? definitions.filter(
            (item) => item.name === input.tool_name || toTransportToolName(item.name) === input.tool_name
          )
        : definitions

      if (input.tool_name && filtered.length === 0) {
        return {
          ok: false,
          errors: [`Tool not found: ${input.tool_name}`],
        }
      }

      const toolData = {
        count: filtered.length,
        tools: filtered.map((definition) => ({
          name: toTransportToolName(definition.name),
          description: definition.description,
          surface_role: classifyToolSurfaceRole(definition.name),
          preferred_primary_tools: buildPreferredPrimaryTools(
            classifyToolSurfaceRole(definition.name),
            preferredPrimaryToolsFor(definition.name)
          ).map((item) => toTransportToolName(item)),
          usage_notes: buildUsageNotes(definition).map((item) =>
            rewriteToolReferencesInText(item, nameMappings)
          ),
          input: input.include_fields
            ? buildSchemaSummary(definition.inputSchema, definition.name)
            : undefined,
          output:
            input.include_fields && input.include_output_schema && definition.outputSchema
              ? buildSchemaSummary(definition.outputSchema, definition.name)
              : undefined,
        })),
      }

      return {
        ok: true,
        data: rewriteToolReferencesInValue(toolData, nameMappings) as z.infer<typeof toolHelpOutputSchema>['data'],
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
      }
    }
  }
}
