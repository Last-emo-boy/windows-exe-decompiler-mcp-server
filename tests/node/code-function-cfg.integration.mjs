import assert from 'node:assert/strict'

const { createCodeFunctionCFGHandler } = await import('../../dist/tools/code-function-cfg.js')

const sampleCFG = {
  function: 'FUN_140001000',
  address: '0x140001000',
  nodes: [
    {
      id: 'block_0',
      address: '0x140001000',
      instructions: ['push rbp', 'mov rbp, rsp'],
      type: 'entry',
    },
    {
      id: 'block_1',
      address: '0x140001010',
      instructions: ['call VirtualAlloc', 'jmp 0x140001020'],
      type: 'call',
    },
  ],
  edges: [{ from: 'block_0', to: 'block_1', type: 'fallthrough' }],
}

function artifact(id, type) {
  return {
    id,
    type,
    path: `reports/graphs/default/${id}`,
    sha256: `${id}-sha`,
    mime: type.includes('svg') ? 'image/svg+xml' : 'text/plain',
  }
}

function createDatabaseMock() {
  return {
    findSample(sampleId) {
      return {
        id: sampleId,
        sha256: 'a'.repeat(64),
        md5: 'b'.repeat(32),
        size: 1024,
        file_type: 'PE32+',
        created_at: '2026-03-23T00:00:00.000Z',
        source: 'test',
      }
    },
    findFunctions() {
      return [
        {
          sample_id: 'sha256:' + 'a'.repeat(64),
          address: '0x140001000',
          name: 'FUN_140001000',
          size: 32,
          score: 0,
          tags: '[]',
          summary: null,
          caller_count: 1,
          callee_count: 1,
          is_entry_point: 1,
          is_exported: 0,
          callees: JSON.stringify(['callee_fn']),
        },
        {
          sample_id: 'sha256:' + 'a'.repeat(64),
          address: '0x140000900',
          name: 'caller_fn',
          size: 24,
          score: 0,
          tags: '[]',
          summary: null,
          caller_count: 0,
          callee_count: 1,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify(['FUN_140001000']),
        },
        {
          sample_id: 'sha256:' + 'a'.repeat(64),
          address: '0x140002000',
          name: 'callee_fn',
          size: 48,
          score: 0,
          tags: '[]',
          summary: null,
          caller_count: 1,
          callee_count: 0,
          is_entry_point: 0,
          is_exported: 0,
          callees: JSON.stringify([]),
        },
      ]
    },
  }
}

async function runBoundedPreviewCase() {
  const persistGraphArtifact = async (...args) => {
    const options = args[3]
    return options.scope === 'cfg'
      ? artifact('cfg-dot', 'cfg_graph_dot')
      : artifact('call-dot', 'cfg_graph_dot')
  }

  const handler = createCodeFunctionCFGHandler({}, createDatabaseMock(), {
    getFunctionCFG: async () => sampleCFG,
    persistGraphArtifact,
  })

  const result = await handler({
    sample_id: 'sha256:' + 'a'.repeat(64),
    address: '0x140001000',
    format: 'dot',
    include_call_relationships: true,
    preview_max_chars: 500,
    persist_artifacts: true,
  })

  assert.equal(result.ok, true)
  assert.equal(result.data.tool_surface_role, 'primary')
  assert.equal(result.data.graph_semantics.surface_role, 'local_navigation_aid')
  assert.equal(result.data.graph_semantics.confidence_state, 'observed')
  assert.equal(result.data.preview.format, 'dot')
  assert.match(result.data.preview.inline_text, /digraph/)
  assert.equal(result.data.call_relationships.status, 'available')
  assert.equal(result.data.artifact_refs.primary_graph.id, 'cfg-dot')
  assert.equal(result.data.artifact_refs.call_relationship_graph.id, 'call-dot')
}

async function runUnavailableRenderCase() {
  const handler = createCodeFunctionCFGHandler({}, createDatabaseMock(), {
    getFunctionCFG: async () => sampleCFG,
    persistGraphArtifact: async () => artifact('cfg-mermaid', 'cfg_graph_mermaid'),
    renderGraphvizArtifact: async () => artifact('unused', 'cfg_graph_svg'),
    detectRendererAvailability: () => ({
      available: false,
      backend: 'none',
      version: null,
      error: 'dot not found',
    }),
  })

  const result = await handler({
    sample_id: 'sha256:' + 'a'.repeat(64),
    symbol: 'FUN_140001000',
    format: 'mermaid',
    render: 'svg',
  })

  assert.equal(result.ok, true)
  assert.equal(result.data.graph_semantics.surface_role, 'local_navigation_aid')
  assert.equal(result.data.render.status, 'unavailable')
  assert.equal(result.setup_actions[0].id, 'install_graphviz')
  assert.match(result.warnings[0], /Graphviz renderer is unavailable/)
}

async function runRenderedArtifactCase() {
  const handler = createCodeFunctionCFGHandler({}, createDatabaseMock(), {
    getFunctionCFG: async () => sampleCFG,
    persistGraphArtifact: async () => artifact('cfg-json', 'cfg_graph_json'),
    renderGraphvizArtifact: async () => artifact('cfg-svg', 'cfg_graph_svg'),
    detectRendererAvailability: () => ({
      available: true,
      backend: 'graphviz',
      version: 'dot - graphviz version 10.0.1',
    }),
  })

  const result = await handler({
    sample_id: 'sha256:' + 'a'.repeat(64),
    address: '0x140001000',
    format: 'json',
    render: 'svg',
  })

  assert.equal(result.ok, true)
  assert.equal(result.data.render.status, 'rendered')
  assert.equal(result.data.graph_semantics.surface_role, 'local_navigation_aid')
  assert.equal(result.data.render.artifact.id, 'cfg-svg')
  assert.equal(result.data.artifact_refs.rendered_graph.id, 'cfg-svg')
}

await runBoundedPreviewCase()
await runUnavailableRenderCase()
await runRenderedArtifactCase()

console.log('code-function-cfg integration checks passed')
