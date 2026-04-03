/**
 * Cross-Module Analysis Plugin
 *
 * Cross-binary comparison, cross-module call graphs, and DLL dependency trees.
 */

import type { Plugin } from '../sdk.js'
import { crossBinaryCompareToolDefinition, createCrossBinaryCompareHandler } from './tools/cross-binary-compare.js'
import { callGraphCrossModuleToolDefinition, createCallGraphCrossModuleHandler } from './tools/call-graph-cross-module.js'
import { dllDependencyTreeToolDefinition, createDllDependencyTreeHandler } from './tools/dll-dependency-tree.js'

const crossModulePlugin: Plugin = {
  id: 'cross-module',
  name: 'Cross-Module Analysis',
  description: 'Cross-binary comparison, cross-module call graphs, and DLL dependency trees',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(crossBinaryCompareToolDefinition, createCrossBinaryCompareHandler(deps))
    server.registerTool(callGraphCrossModuleToolDefinition, createCallGraphCrossModuleHandler(deps))
    server.registerTool(dllDependencyTreeToolDefinition, createDllDependencyTreeHandler(deps))
    return ['cross_binary.compare', 'call_graph.cross_module', 'dll.dependency_tree']
  },
}

export default crossModulePlugin
