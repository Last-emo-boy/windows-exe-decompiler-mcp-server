import { describe, test, expect } from '@jest/globals'
import { z } from 'zod'
import type { ToolDefinition } from '../../src/types.js'
import { createToolHelpHandler } from '../../src/tools/tool-help.js'
import { toTransportToolName } from '../../src/tool-name-normalization'

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
        description: 'Reconstruct with separate runtime, static, and semantic scopes',
        inputSchema: z.object({
          sample_id: z.string(),
          evidence_scope: z.enum(['all', 'latest', 'session']).default('all'),
          evidence_session_tag: z.string().optional(),
          static_scope: z.enum(['all', 'latest', 'session']).default('latest'),
          static_session_tag: z.string().optional(),
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
    expect(data.tools[0].name).toBe(toTransportToolName('sandbox.execute'))
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
        description: 'Reconstruct with separate runtime, static, and semantic scopes',
        inputSchema: z.object({
          sample_id: z.string(),
          evidence_scope: z.enum(['all', 'latest', 'session']).default('all'),
          evidence_session_tag: z.string().optional(),
          static_scope: z.enum(['all', 'latest', 'session']).default('latest'),
          static_session_tag: z.string().optional(),
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
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('runtime, static-analysis, and semantic artifact scopes'))).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('static-analysis artifacts'))).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('naming/explanation artifacts'))).toBe(true)

    const evidenceScopeField = data.tools[0].input.fields.find((item: any) => item.path === 'evidence_scope')
    const staticScopeField = data.tools[0].input.fields.find((item: any) => item.path === 'static_scope')
    const semanticScopeField = data.tools[0].input.fields.find((item: any) => item.path === 'semantic_scope')
    const sessionTagField = data.tools[0].input.fields.find((item: any) => item.path === 'session_tag')

    expect(evidenceScopeField.help_hint).toContain('runtime evidence')
    expect(staticScopeField.help_hint).toContain('static-analysis artifact selection')
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

  test('should accept underscore tool_name queries and return underscore next-tool guidance', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'workflow.analyze.auto',
        description: 'Intent-routed analysis entrypoint',
        inputSchema: z.object({
          sample_id: z.string(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'workflow_analyze_auto',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.tools[0].name).toBe('workflow_analyze_auto')
    expect(
      data.tools[0].usage_notes.some(
        (item: string) =>
          item.includes('workflow_analyze_start') || item.includes('workflow_analyze_promote')
      )
    ).toBe(true)
  })

  test('should explain workflow.analyze.auto intent-routing fields', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'workflow.analyze.auto',
        description: 'Intent-routed analysis entrypoint',
        inputSchema: z.object({
          sample_id: z.string(),
          goal: z.enum(['triage', 'static', 'reverse', 'dynamic', 'report']).default('triage'),
          depth: z.enum(['safe', 'balanced', 'deep']).default('balanced'),
          backend_policy: z.enum(['auto', 'prefer_new', 'legacy_only', 'strict']).default('auto'),
          allow_transformations: z.boolean().default(false),
          allow_live_execution: z.boolean().default(false),
        }),
        outputSchema: z.object({
          ok: z.boolean(),
          data: z.object({
            coverage_level: z.string(),
            completion_state: z.string(),
            coverage_gaps: z.array(z.any()),
            upgrade_paths: z.array(z.any()),
          }),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'workflow.analyze.auto',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(
      data.tools[0].usage_notes.some(
        (item: string) =>
          item.includes(toTransportToolName('workflow.analyze.start')) ||
          item.includes(toTransportToolName('workflow.analyze.promote'))
      )
    ).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('small samples'))).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('medium/large samples'))).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('manual-only'))).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('coverage_level'))).toBe(true)
    const goalField = data.tools[0].input.fields.find((item: any) => item.path === 'goal')
    const depthField = data.tools[0].input.fields.find((item: any) => item.path === 'depth')
    const policyField = data.tools[0].input.fields.find((item: any) => item.path === 'backend_policy')
    const liveField = data.tools[0].input.fields.find((item: any) => item.path === 'allow_live_execution')

    expect(goalField.help_hint).toContain('triage')
    expect(depthField.help_hint).toContain('balanced')
    expect(policyField.help_hint).toContain('prefer_new')
    expect(liveField.help_hint).toContain('approved=true')
    const coverageField = data.tools[0].output.fields.find((item: any) => item.path === 'data.coverage_level')
    expect(coverageField.help_hint).toContain('workflow-style outputs')
  })

  test('should explain that sample.ingest prefers path over bytes_b64', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'sample.request_upload',
        description:
          'Primary host-file upload entrypoint for containerized MCP workers.',
        inputSchema: z.object({
          filename: z.string().optional(),
          ttl_seconds: z.number().default(300),
        }),
      },
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

    const uploadResult = await handler({
      tool_name: 'sample.request_upload',
    })
    const uploadData = uploadResult.data as any
    expect(uploadData.tools[0].usage_notes.some((item: string) => item.includes('host-file ingest entrypoint'))).toBe(true)
    const ttlField = uploadData.tools[0].input.fields.find((item: any) => item.path === 'ttl_seconds')
    expect(ttlField.help_hint).toContain('upload-session lifetime')
  })

  test('should explain polling_guidance for long-running job tools', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'task.status',
        description: 'Query queued and running jobs',
        inputSchema: z.object({
          job_id: z.string().optional(),
        }),
      },
      {
        name: 'workflow.reconstruct',
        description: 'Queued reconstruct workflow',
        inputSchema: z.object({
          sample_id: z.string(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const taskStatusResult = await handler({ tool_name: 'task.status' })
    const taskStatusData = taskStatusResult.data as any
    expect(taskStatusData.tools[0].surface_role).toBe('compatibility')
    expect(taskStatusData.tools[0].preferred_primary_tools).toContain(
      toTransportToolName('workflow.analyze.status')
    )
    expect(taskStatusData.tools[0].usage_notes.some((item: string) => item.includes('polling_guidance'))).toBe(true)

    const workflowResult = await handler({ tool_name: 'workflow.reconstruct' })
    const workflowData = workflowResult.data as any
    expect(workflowData.tools[0].usage_notes.some((item: string) => item.includes('sleep or wait'))).toBe(true)
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
    expect(
      ghidraData.tools[0].usage_notes.some((item: string) =>
        item.includes(toTransportToolName('pe.pdata.extract'))
      )
    ).toBe(true)

    const pdataResult = await handler({ tool_name: 'pe.pdata.extract' })
    const pdataData = pdataResult.data as any
    expect(pdataData.tools[0].usage_notes.some((item: string) => item.includes('zero functions'))).toBe(true)

    const smartRecoverResult = await handler({ tool_name: 'code.functions.smart_recover' })
    const smartRecoverData = smartRecoverResult.data as any
    expect(smartRecoverData.tools[0].usage_notes.some((item: string) => item.includes('Rust/Go/C++'))).toBe(true)

    const symbolsResult = await handler({ tool_name: 'pe.symbols.recover' })
    const symbolsData = symbolsResult.data as any
    expect(
      symbolsData.tools[0].usage_notes.some((item: string) =>
        item.includes(toTransportToolName('code.functions.define'))
      )
    ).toBe(true)

    const defineResult = await handler({ tool_name: 'code.functions.define' })
    const defineData = defineResult.data as any
    expect(defineData.tools[0].usage_notes.some((item: string) => item.includes('function-index readiness'))).toBe(
      true
    )
    const definitionsField = defineData.tools[0].input.fields.find((item: any) => item.path === 'definitions')
    expect(definitionsField.help_hint).toContain(toTransportToolName('code.functions.smart_recover'))

    const rustAnalyzeResult = await handler({ tool_name: 'rust_binary.analyze' })
    const rustAnalyzeData = rustAnalyzeResult.data as any
    expect(
      rustAnalyzeData.tools[0].usage_notes.some((item: string) =>
        item.includes(toTransportToolName('runtime.detect'))
      )
    ).toBe(true)
    const maxStringsField = rustAnalyzeData.tools[0].input.fields.find((item: any) => item.path === 'max_strings')
    expect(maxStringsField.help_hint).toContain('crate paths')

    const workflowResult = await handler({ tool_name: 'workflow.function_index_recover' })
    const workflowData = workflowResult.data as any
    expect(
      workflowData.tools[0].usage_notes.some((item: string) =>
        item.includes(toTransportToolName('code.functions.smart_recover'))
      )
    ).toBe(true)
    const defineFromField = workflowData.tools[0].input.fields.find((item: any) => item.path === 'define_from')
    expect(defineFromField.help_hint).toContain(
      `auto prefers ${toTransportToolName('pe.symbols.recover')}`
    )
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
        name: 'dynamic.dependencies',
        description: 'Explain dynamic dependency readiness',
        inputSchema: z.object({}),
      },
      {
        name: 'system.health',
        description: 'Explain full environment health',
        inputSchema: z.object({}),
      },
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

    const dynamicResult = await handler({ tool_name: 'dynamic.dependencies' })
    const dynamicData = dynamicResult.data as any
    expect(dynamicData.tools[0].usage_notes.some((item: string) => item.includes('QILING_ROOTFS'))).toBe(true)

    const healthResult = await handler({ tool_name: 'system.health' })
    const healthData = healthResult.data as any
    expect(healthData.tools[0].usage_notes.some((item: string) => item.includes('RetDec'))).toBe(true)
  })

  test('should explain compact string-context and xref entrypoints', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'analysis.context.link',
        description: 'Build compact string and xref correlation before full reconstruction',
        inputSchema: z.object({
          sample_id: z.string(),
          mode: z.enum(['preview', 'full']).default('preview'),
          include_decoded: z.boolean().default(true),
        }),
      },
      {
        name: 'code.xrefs.analyze',
        description: 'Analyze bounded xrefs for function, string, api, or data targets',
        inputSchema: z.object({
          sample_id: z.string(),
          target_type: z.enum(['function', 'api', 'string', 'data']),
          depth: z.number().default(1),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)

    const contextResult = await handler({ tool_name: 'analysis.context.link' })
    const contextData = contextResult.data as any
    expect(contextData.tools[0].usage_notes.some((item: string) => item.includes('bounded indicator-to-function correlation'))).toBe(true)
    const contextModeField = contextData.tools[0].input.fields.find((item: any) => item.path === 'mode')
    expect(contextModeField.help_hint).toContain('preview first')

    const xrefResult = await handler({ tool_name: 'code.xrefs.analyze' })
    const xrefData = xrefResult.data as any
    expect(xrefData.tools[0].usage_notes.some((item: string) => item.includes('bounded indicator-to-function correlation'))).toBe(true)
  })

  test('should explain graph-export and render guidance for code.function.cfg', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'code.function.cfg',
        description: 'Bounded CFG export tool',
        inputSchema: z.object({
          sample_id: z.string(),
          address: z.string().optional(),
          symbol: z.string().optional(),
          format: z.enum(['json', 'dot', 'mermaid']).default('json'),
          render: z.enum(['none', 'svg', 'png']).default('none'),
          include_call_relationships: z.boolean().default(false),
          call_relationship_depth: z.number().int().default(1),
          call_relationship_limit: z.number().int().default(8),
          preview_max_chars: z.number().int().default(3000),
          persist_artifacts: z.boolean().default(true),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'code.function.cfg',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const formatField = data.tools[0].input.fields.find((item: any) => item.path === 'format')
    const renderField = data.tools[0].input.fields.find((item: any) => item.path === 'render')
    const relationshipsField = data.tools[0].input.fields.find(
      (item: any) => item.path === 'include_call_relationships'
    )
    const previewField = data.tools[0].input.fields.find(
      (item: any) => item.path === 'preview_max_chars'
    )

    expect(formatField.help_hint).toContain('dot and mermaid')
    expect(renderField.help_hint).toContain('artifact-first')
    expect(relationshipsField.help_hint).toContain('whole-program call graph')
    expect(previewField.help_hint).toContain('full text export')
  })

  test('should classify primary, compatibility, and export-oriented surfaces', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'workflow.analyze.start',
        description: 'Primary staged analysis entrypoint',
        inputSchema: z.object({ sample_id: z.string() }),
      },
      {
        name: 'workflow.triage',
        description: 'Compatibility quick-profile workflow',
        inputSchema: z.object({ sample_id: z.string() }),
      },
      {
        name: 'report.generate',
        description: 'Export archival report artifacts',
        inputSchema: z.object({ sample_id: z.string() }),
      },
      {
        name: 'graphviz.render',
        description: 'Render DOT to SVG',
        inputSchema: z.object({ sample_id: z.string(), graph_text: z.string() }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({})

    expect(result.ok).toBe(true)
    const data = result.data as any
    const byName = new Map<string, any>(data.tools.map((item: any) => [item.name, item]))

    expect(byName.get(toTransportToolName('workflow.analyze.start')).surface_role).toBe('primary')
    expect(byName.get(toTransportToolName('workflow.triage')).surface_role).toBe('compatibility')
    expect(byName.get(toTransportToolName('workflow.triage')).preferred_primary_tools).toContain(
      toTransportToolName('workflow.analyze.start')
    )
    expect(byName.get(toTransportToolName('report.generate')).surface_role).toBe('export_only')
    expect(byName.get(toTransportToolName('report.generate')).preferred_primary_tools).toContain(
      toTransportToolName('workflow.summarize')
    )
    expect(byName.get(toTransportToolName('graphviz.render')).surface_role).toBe('renderer_helper')
    expect(byName.get(toTransportToolName('graphviz.render')).preferred_primary_tools).toContain(
      toTransportToolName('code.function.cfg')
    )
  })

  test('should expose usage notes for explicit backend wrapper tools', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'rizin.analyze',
        description: 'Direct Rizin wrapper',
        inputSchema: z.object({
          sample_id: z.string(),
          operation: z.enum(['info', 'imports']).default('info'),
        }),
      },
      {
        name: 'wine.run',
        description: 'Wine execution wrapper',
        inputSchema: z.object({
          sample_id: z.string(),
          mode: z.enum(['preflight', 'run', 'debug']).default('preflight'),
          approved: z.boolean().default(false),
        }),
      },
      {
        name: 'tool.help',
        description: 'Tool help index',
        inputSchema: z.object({
          tool_name: z.string().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const rizinResult = await handler({ tool_name: 'rizin.analyze' })
    const rizinData = rizinResult.data as any
    expect(rizinData.tools[0].usage_notes.some((item: string) => item.includes('explicitly requests Rizin'))).toBe(true)
    expect(rizinData.tools[0].usage_notes.some((item: string) => item.includes('medium/large samples'))).toBe(true)

    const wineResult = await handler({ tool_name: 'wine.run' })
    const wineData = wineResult.data as any
    expect(wineData.tools[0].usage_notes.some((item: string) => item.includes('approved=true'))).toBe(true)
    const approvedField = wineData.tools[0].input.fields.find((item: any) => item.path === 'approved')
    expect(approvedField.help_hint).toContain('must be true')

    const toolHelpResult = await handler({ tool_name: 'tool.help' })
    const toolHelpData = toolHelpResult.data as any
    expect(
      toolHelpData.tools[0].usage_notes.some((item: string) =>
        item.includes(toTransportToolName('rizin.analyze'))
      )
    ).toBe(true)
  })

  test('should explain planning-first crypto and breakpoint tools', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'crypto.identify',
        description: 'Identify crypto routines from compact evidence',
        inputSchema: z.object({
          sample_id: z.string(),
          mode: z.enum(['preview', 'full']).default('preview'),
          include_runtime_evidence: z.boolean().default(true),
          runtime_evidence_scope: z.enum(['all', 'latest', 'session']).default('latest'),
          max_findings: z.number().default(6),
          max_constants: z.number().default(8),
        }),
      },
      {
        name: 'breakpoint.smart',
        description: 'Rank breakpoint candidates',
        inputSchema: z.object({
          sample_id: z.string(),
          max_candidates: z.number().default(8),
          include_runtime_evidence: z.boolean().default(true),
        }),
      },
      {
        name: 'trace.condition',
        description: 'Compile bounded trace plans',
        inputSchema: z.object({
          sample_id: z.string(),
          breakpoint_index: z.number().default(0),
          breakpoint: z.any().optional(),
          condition: z.any().optional(),
          capture: z.any().optional(),
          max_memory_bytes: z.number().default(256),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)

    const cryptoResult = await handler({ tool_name: 'crypto.identify' })
    const cryptoData = cryptoResult.data as any
    expect(cryptoData.tools[0].usage_notes.some((item: string) => item.includes('correlation layer'))).toBe(true)
    expect(cryptoData.tools[0].usage_notes.some((item: string) => item.includes('larger samples'))).toBe(true)
    const cryptoModeField = cryptoData.tools[0].input.fields.find((item: any) => item.path === 'mode')
    expect(cryptoModeField.help_hint).toContain('preview first')
    const cryptoRuntimeScope = cryptoData.tools[0].input.fields.find((item: any) => item.path === 'runtime_evidence_scope')
    expect(cryptoRuntimeScope.help_hint).toContain('latest is the normal AI-facing mode')

    const breakpointResult = await handler({ tool_name: 'breakpoint.smart' })
    const breakpointData = breakpointResult.data as any
    expect(breakpointData.tools[0].usage_notes.some((item: string) => item.includes('planning-only'))).toBe(true)
    const maxCandidatesField = breakpointData.tools[0].input.fields.find((item: any) => item.path === 'max_candidates')
    expect(maxCandidatesField.help_hint).toContain('compact high-confidence candidates')

    const traceResult = await handler({ tool_name: 'trace.condition' })
    const traceData = traceResult.data as any
    expect(traceData.tools[0].usage_notes.some((item: string) => item.includes('does not execute instrumentation'))).toBe(true)
    const conditionField = traceData.tools[0].input.fields.find((item: any) => item.path === 'condition')
    const memoryField = traceData.tools[0].input.fields.find((item: any) => item.path === 'max_memory_bytes')
    expect(conditionField.help_hint).toContain('bounded planning DSL')
    expect(memoryField.help_hint).toContain('total serialization budget')
  })

  test('should explain packed-sample and debug-session playbooks', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'workflow.analyze.start',
        description: 'Start or reuse a persisted run',
        inputSchema: z.object({
          sample_id: z.string(),
          allow_transformations: z.boolean().default(false),
        }),
        outputSchema: z.object({
          ok: z.boolean(),
          data: z.object({
            packed_state: z.enum(['unknown', 'not_packed', 'suspected_packed', 'confirmed_packed']).optional(),
            unpack_state: z
              .enum([
                'not_applicable',
                'not_started',
                'unpack_planned',
                'unpack_in_progress',
                'partially_unpacked',
                'unpacked',
                'rebuild_required',
                'unpack_failed_recoverable',
                'approval_gated',
              ])
              .optional(),
            unpack_plan: z.object({
              strategy: z.string(),
            }).optional(),
          }),
        }),
      },
      {
        name: 'workflow.analyze.status',
        description: 'Read persisted run status',
        inputSchema: z.object({
          run_id: z.string(),
        }),
        outputSchema: z.object({
          ok: z.boolean(),
          data: z.object({
            packed_state: z.enum(['unknown', 'not_packed', 'suspected_packed', 'confirmed_packed']).optional(),
            unpack_state: z.string().optional(),
            debug_state: z
              .enum([
                'not_requested',
                'planned',
                'armed',
                'capturing',
                'captured',
                'correlated',
                'interrupted_recoverable',
                'approval_gated',
              ])
              .optional(),
            diff_digests: z.array(z.object({ diff_type: z.string() })).optional(),
          }),
        }),
      },
      {
        name: 'workflow.analyze.promote',
        description: 'Promote persisted run stages',
        inputSchema: z.object({
          run_id: z.string(),
          through_stage: z.enum(['dynamic_plan', 'dynamic_execute']).optional(),
        }),
      },
      {
        name: 'upx.inspect',
        description: 'Inspect or unpack UPX',
        inputSchema: z.object({
          sample_id: z.string(),
          operation: z.enum(['test', 'list', 'decompress']).default('test'),
        }),
      },
      {
        name: 'breakpoint.smart',
        description: 'Rank debug breakpoint candidates',
        inputSchema: z.object({
          sample_id: z.string(),
          max_candidates: z.number().default(8),
        }),
      },
      {
        name: 'trace.condition',
        description: 'Compile bounded trace plans',
        inputSchema: z.object({
          sample_id: z.string(),
          breakpoint_index: z.number().default(0),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)

    const startResult = await handler({ tool_name: 'workflow.analyze.start' })
    const startData = startResult.data as any
    expect(startData.tools[0].usage_notes.some((item: string) => item.includes('packed_state'))).toBe(true)
    expect(
      startData.tools[0].usage_notes.some((item: string) => item.includes('allow_transformations'))
    ).toBe(true)
    const packedField = startData.tools[0].output.fields.find((item: any) => item.path === 'data.packed_state')
    const unpackPlanField = startData.tools[0].output.fields.find((item: any) => item.path === 'data.unpack_plan.strategy')
    expect(packedField.help_hint).toContain('suspected_packed')
    expect(unpackPlanField.help_hint).toContain('upx_decompress')

    const statusResult = await handler({ tool_name: 'workflow.analyze.status' })
    const statusData = statusResult.data as any
    expect(statusData.tools[0].usage_notes.some((item: string) => item.includes('debug_state'))).toBe(true)
    const debugField = statusData.tools[0].output.fields.find((item: any) => item.path === 'data.debug_state')
    const diffField = statusData.tools[0].output.fields.find((item: any) => item.path === 'data.diff_digests')
    expect(debugField.help_hint).toContain('persisted debug progression')
    expect(diffField.help_hint).toContain('before/after digests')

    const promoteResult = await handler({ tool_name: 'workflow.analyze.promote' })
    const promoteData = promoteResult.data as any
    expect(promoteData.tools[0].usage_notes.some((item: string) => item.includes('dynamic_plan first'))).toBe(
      true
    )

    const upxResult = await handler({ tool_name: 'upx.inspect' })
    const upxData = upxResult.data as any
    expect(upxData.tools[0].usage_notes.some((item: string) => item.includes('safe unpack probe'))).toBe(true)

    const breakpointResult = await handler({ tool_name: 'breakpoint.smart' })
    const breakpointData = breakpointResult.data as any
    expect(breakpointData.tools[0].usage_notes.some((item: string) => item.includes('persisted debug session'))).toBe(true)

    const traceResult = await handler({ tool_name: 'trace.condition' })
    const traceData = traceResult.data as any
    expect(traceData.tools[0].usage_notes.some((item: string) => item.includes('debug-session artifact'))).toBe(
      true
    )
  })
})
