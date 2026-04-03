/**
 * Knowledge Base & Collaboration Plugin
 *
 * Function signature matching and analysis template management.
 */

import type { Plugin } from '../sdk.js'
import { kbFunctionMatchToolDefinition, createKbFunctionMatchHandler } from './tools/kb-function-match.js'
import { analysisTemplateToolDefinition, createAnalysisTemplateHandler } from './tools/analysis-template.js'

const kbCollaborationPlugin: Plugin = {
  id: 'kb-collaboration',
  name: 'Knowledge Base & Collaboration',
  description: 'Function signature matching and analysis template management',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(kbFunctionMatchToolDefinition, createKbFunctionMatchHandler(deps))
    server.registerTool(analysisTemplateToolDefinition, createAnalysisTemplateHandler(deps))
    return ['kb.function_match', 'analysis.template']
  },
}

export default kbCollaborationPlugin
