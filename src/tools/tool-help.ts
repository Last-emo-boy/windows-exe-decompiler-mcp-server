import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'

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
    'Query normalized schema/help for registered MCP tools, including enum values, defaults, and field descriptions.',
  inputSchema: toolHelpInputSchema,
  outputSchema: toolHelpOutputSchema,
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
  }

  if (toolName === 'binary.role.profile') {
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
      return 'Use all for a first-run bootstrap guide, ghidra when you specifically need the install path/environment guidance, and dynamic when you only need runtime-analysis extras.'
    }
    if (path === 'include_optional') {
      return 'When false, only required setup steps are returned. Leave true to include optional extras such as PyGhidra and dynamic-analysis components.'
    }
  }

  if (path === 'evidence_scope') {
    return 'Controls runtime evidence selection only. Use session for one runtime import/replay lineage, latest for the newest artifact window, all to aggregate historical runtime evidence.'
  }
  if (path === 'evidence_session_tag') {
    return 'Required when evidence_scope=session. You can also pass it with all/latest to narrow runtime evidence to one named session.'
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
      'Use this before first-run or after a degraded health probe when the MCP client needs exact pip install commands and required user-supplied paths such as GHIDRA_PATH.'
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

  const hasEvidenceScope = inputFields.includes('evidence_scope')
  const hasSemanticScope = inputFields.includes('semantic_scope')
  const hasSessionTag = inputFields.includes('session_tag')

  if (hasEvidenceScope && hasSemanticScope) {
    notes.push(
      'This tool separates runtime evidence scope from semantic artifact scope. Set both when you need fully reproducible session-only results.'
    )
  } else if (hasEvidenceScope) {
    notes.push(
      'This tool consumes runtime evidence artifacts. Prefer evidence_scope=session plus evidence_session_tag for one replay/import session.'
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
  }

  if (definition.name === 'sample.ingest') {
    notes.push(
      'Prefer path for local files. Use bytes_b64 only when the MCP client cannot access the same local filesystem as the MCP server.'
    )
    notes.push(
      'When both path and bytes_b64 are provided, path wins. Passing an absolute file path is the most reliable option for local VS Code/Copilot clients.'
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

  if (definition.name === 'ghidra.analyze') {
    notes.push(
      'For Rust or other hard-to-index binaries, combine ghidra.analyze with pe.pdata.extract or code.functions.smart_recover. When auto-detection is weak, set options.language_id, options.cspec, or options.script_paths explicitly.'
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
      const filtered = input.tool_name
        ? definitions.filter((item) => item.name === input.tool_name)
        : definitions

      if (input.tool_name && filtered.length === 0) {
        return {
          ok: false,
          errors: [`Tool not found: ${input.tool_name}`],
        }
      }

      return {
        ok: true,
        data: {
          count: filtered.length,
          tools: filtered.map((definition) => ({
            name: definition.name,
            description: definition.description,
            usage_notes: buildUsageNotes(definition),
            input: input.include_fields
              ? buildSchemaSummary(definition.inputSchema, definition.name)
              : undefined,
            output:
              input.include_fields && input.include_output_schema && definition.outputSchema
                ? buildSchemaSummary(definition.outputSchema, definition.name)
                : undefined,
          })),
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
      }
    }
  }
}
