import { describe, test, expect } from '@jest/globals'
import { z } from 'zod'
import type { ToolDefinition } from '../../src/types.js'
import { createToolHelpHandler } from '../../src/tools/tool-help.js'

describe('tool.help tool', () => {
  test('should summarize input and output schemas with enum/default metadata', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'sandbox.execute',
        description: 'Execute sandbox mode',
        inputSchema: z.object({
          sample_id: z.string().describe('Target sample'),
          mode: z
            .enum(['safe_simulation', 'memory_guided', 'speakeasy'])
            .default('safe_simulation')
            .describe('Dynamic backend mode'),
          network: z
            .enum(['block', 'simulate'])
            .optional()
            .describe('Network policy'),
        }),
        outputSchema: z.object({
          ok: z.boolean(),
          data: z.object({
            executed: z.boolean().optional(),
          }),
        }),
      },
      {
        name: 'workflow.reconstruct',
        description: 'Reconstruct with separate runtime and semantic scopes',
        inputSchema: z.object({
          sample_id: z.string(),
          evidence_scope: z.enum(['all', 'latest', 'session']).default('all'),
          evidence_session_tag: z.string().optional(),
          semantic_scope: z.enum(['all', 'latest', 'session']).default('all'),
          semantic_session_tag: z.string().optional(),
          session_tag: z.string().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'sandbox.execute',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.count).toBe(1)
    expect(data.tools[0].name).toBe('sandbox.execute')
    expect(data.tools[0].input.field_count).toBeGreaterThan(0)

    const modeField = data.tools[0].input.fields.find((item: any) => item.path === 'mode')
    expect(modeField.type).toBe('enum')
    expect(modeField.required).toBe(false)
    expect(modeField.description).toContain('Dynamic backend mode')
    expect(modeField.default_value).toBe('safe_simulation')
    expect(modeField.enum_values).toEqual(['safe_simulation', 'memory_guided', 'speakeasy'])

    const networkField = data.tools[0].input.fields.find((item: any) => item.path === 'network')
    expect(networkField.required).toBe(false)
    expect(networkField.enum_values).toEqual(['block', 'simulate'])

    const outputField = data.tools[0].output.fields.find((item: any) => item.path === 'data.executed')
    expect(outputField.type).toBe('boolean')
    expect(outputField.required).toBe(false)
  })

  test('should include scope/session usage hints for workflow tools', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'workflow.reconstruct',
        description: 'Reconstruct with separate runtime and semantic scopes',
        inputSchema: z.object({
          sample_id: z.string(),
          evidence_scope: z.enum(['all', 'latest', 'session']).default('all'),
          evidence_session_tag: z.string().optional(),
          semantic_scope: z.enum(['all', 'latest', 'session']).default('all'),
          semantic_session_tag: z.string().optional(),
          session_tag: z.string().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'workflow.reconstruct',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('runtime evidence scope'))).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('naming/explanation artifacts'))).toBe(true)

    const evidenceScopeField = data.tools[0].input.fields.find((item: any) => item.path === 'evidence_scope')
    const semanticScopeField = data.tools[0].input.fields.find((item: any) => item.path === 'semantic_scope')
    const sessionTagField = data.tools[0].input.fields.find((item: any) => item.path === 'session_tag')

    expect(evidenceScopeField.help_hint).toContain('runtime evidence')
    expect(semanticScopeField.help_hint).toContain('semantic')
    expect(sessionTagField.help_hint).toContain('newly created artifacts')
  })

  test('should return not found for unknown tool names', async () => {
    const handler = createToolHelpHandler(() => [])
    const result = await handler({
      tool_name: 'missing.tool',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('Tool not found: missing.tool')
  })

  test('should explain that sample.ingest prefers path over bytes_b64', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'sample.ingest',
        description:
          'Register a new sample from a local file path or Base64 bytes. Prefer path for local files.',
        inputSchema: z.object({
          path: z.string().optional().describe('Preferred local file path'),
          bytes_b64: z.string().optional().describe('Fallback Base64 bytes'),
          filename: z.string().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'sample.ingest',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('Prefer path'))).toBe(true)

    const pathField = data.tools[0].input.fields.find((item: any) => item.path === 'path')
    const bytesField = data.tools[0].input.fields.find((item: any) => item.path === 'bytes_b64')
    const filenameField = data.tools[0].input.fields.find((item: any) => item.path === 'filename')

    expect(pathField.help_hint).toContain('absolute path')
    expect(bytesField.help_hint).toContain('Fallback only')
    expect(filenameField.help_hint).toContain('bytes_b64')
  })

  test('should explain Rust recovery paths for ghidra.analyze and pdata-based tools', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'ghidra.analyze',
        description: 'Analyze with Ghidra',
        inputSchema: z.object({
          sample_id: z.string(),
          options: z
            .object({
              language_id: z.string().optional(),
              cspec: z.string().optional(),
              script_paths: z.array(z.string()).optional(),
            })
            .optional(),
        }),
      },
      {
        name: 'pe.pdata.extract',
        description: 'Extract runtime functions from .pdata',
        inputSchema: z.object({
          sample_id: z.string(),
        }),
      },
      {
        name: 'code.functions.smart_recover',
        description: 'Recover functions from .pdata and exports',
        inputSchema: z.object({
          sample_id: z.string(),
        }),
      },
      {
        name: 'pe.symbols.recover',
        description: 'Recover symbolic names from PE metadata',
        inputSchema: z.object({
          sample_id: z.string(),
          max_string_hints: z.number().optional(),
        }),
      },
      {
        name: 'code.functions.define',
        description: 'Import recovered function boundaries',
        inputSchema: z.object({
          sample_id: z.string(),
          source: z.enum(['manual', 'pdata', 'symbols_recover', 'smart_recover', 'external']).default('manual'),
          replace_all: z.boolean().default(false),
          definitions: z.array(z.object({ address: z.string().optional(), rva: z.number().optional() })),
        }),
      },
      {
        name: 'rust_binary.analyze',
        description: 'Analyze Rust-oriented PE binaries',
        inputSchema: z.object({
          sample_id: z.string(),
          max_strings: z.number().optional(),
          max_symbol_preview: z.number().optional(),
        }),
      },
      {
        name: 'workflow.function_index_recover',
        description: 'Recover and materialize a non-Ghidra function index',
        inputSchema: z.object({
          sample_id: z.string(),
          define_from: z.enum(['auto', 'smart_recover', 'symbols_recover']).default('auto'),
          max_string_hints: z.number().optional(),
          replace_all: z.boolean().default(true),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const ghidraResult = await handler({ tool_name: 'ghidra.analyze' })
    const ghidraData = ghidraResult.data as any
    const languageIdField = ghidraData.tools[0].input.fields.find((item: any) => item.path === 'options.language_id')
    expect(languageIdField.help_hint).toContain('Rust/Go/C++')
    expect(ghidraData.tools[0].usage_notes.some((item: string) => item.includes('pe.pdata.extract'))).toBe(true)

    const pdataResult = await handler({ tool_name: 'pe.pdata.extract' })
    const pdataData = pdataResult.data as any
    expect(pdataData.tools[0].usage_notes.some((item: string) => item.includes('zero functions'))).toBe(true)

    const smartRecoverResult = await handler({ tool_name: 'code.functions.smart_recover' })
    const smartRecoverData = smartRecoverResult.data as any
    expect(smartRecoverData.tools[0].usage_notes.some((item: string) => item.includes('Rust/Go/C++'))).toBe(true)

    const symbolsResult = await handler({ tool_name: 'pe.symbols.recover' })
    const symbolsData = symbolsResult.data as any
    expect(symbolsData.tools[0].usage_notes.some((item: string) => item.includes('code.functions.define'))).toBe(
      true
    )

    const defineResult = await handler({ tool_name: 'code.functions.define' })
    const defineData = defineResult.data as any
    expect(defineData.tools[0].usage_notes.some((item: string) => item.includes('function-index readiness'))).toBe(
      true
    )
    const definitionsField = defineData.tools[0].input.fields.find((item: any) => item.path === 'definitions')
    expect(definitionsField.help_hint).toContain('code.functions.smart_recover')

    const rustAnalyzeResult = await handler({ tool_name: 'rust_binary.analyze' })
    const rustAnalyzeData = rustAnalyzeResult.data as any
    expect(rustAnalyzeData.tools[0].usage_notes.some((item: string) => item.includes('runtime.detect'))).toBe(true)
    const maxStringsField = rustAnalyzeData.tools[0].input.fields.find((item: any) => item.path === 'max_strings')
    expect(maxStringsField.help_hint).toContain('crate paths')

    const workflowResult = await handler({ tool_name: 'workflow.function_index_recover' })
    const workflowData = workflowResult.data as any
    expect(workflowData.tools[0].usage_notes.some((item: string) => item.includes('code.functions.smart_recover'))).toBe(true)
    const defineFromField = workflowData.tools[0].input.fields.find((item: any) => item.path === 'define_from')
    expect(defineFromField.help_hint).toContain('auto prefers pe.symbols.recover')
  })

  test('should explain DLL and COM profiling entrypoints', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'dll.export.profile',
        description: 'Profile DLL export surfaces',
        inputSchema: z.object({
          sample_id: z.string(),
          max_exports: z.number().optional(),
        }),
      },
      {
        name: 'com.role.profile',
        description: 'Profile COM-oriented PE samples',
        inputSchema: z.object({
          sample_id: z.string(),
          max_strings: z.number().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)

    const dllResult = await handler({ tool_name: 'dll.export.profile' })
    const dllData = dllResult.data as any
    expect(dllData.tools[0].usage_notes.some((item: string) => item.includes('DllMain'))).toBe(true)
    const dllSampleField = dllData.tools[0].input.fields.find((item: any) => item.path === 'sample_id')
    expect(dllSampleField.help_hint).toContain('DLL-first view')

    const comResult = await handler({ tool_name: 'com.role.profile' })
    const comData = comResult.data as any
    expect(comData.tools[0].usage_notes.some((item: string) => item.includes('COM'))).toBe(true)
    const maxStringsField = comData.tools[0].input.fields.find((item: any) => item.path === 'max_strings')
    expect(maxStringsField.help_hint).toContain('CLSID')
  })

  test('should explain explicit setup guidance fields', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'system.setup.guide',
        description: 'Explain bootstrap commands and required environment variables',
        inputSchema: z.object({
          focus: z.enum(['all', 'python', 'dynamic', 'ghidra']).default('all'),
          include_optional: z.boolean().default(true),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({ tool_name: 'system.setup.guide' })
    const data = result.data as any

    expect(data.tools[0].usage_notes.some((item: string) => item.includes('pip install commands'))).toBe(true)
    const focusField = data.tools[0].input.fields.find((item: any) => item.path === 'focus')
    const includeOptionalField = data.tools[0].input.fields.find((item: any) => item.path === 'include_optional')

    expect(focusField.help_hint).toContain('first-run bootstrap guide')
    expect(includeOptionalField.help_hint).toContain('only required setup steps')
  })
})
