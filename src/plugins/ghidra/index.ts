/**
 * Ghidra Integration Plugin
 *
 * Headless Ghidra analysis and health checks.
 */

import { accessSync } from 'fs'
import type { Plugin } from '../sdk.js'
import {
  ghidraAnalyzeToolDefinition, createGhidraAnalyzeHandler,
} from './tools/ghidra-analyze.js'
import {
  ghidraHealthToolDefinition, createGhidraHealthHandler,
} from './tools/ghidra-health.js'

const ghidraPlugin: Plugin = {
  id: 'ghidra',
  name: 'Ghidra Integration',
  description: 'Headless Ghidra analysis and health checks',
  version: '1.0.0',
  configSchema: [
    { envVar: 'GHIDRA_INSTALL_DIR', description: 'Path to Ghidra installation directory', required: true },
    { envVar: 'GHIDRA_PROJECT_DIR', description: 'Directory for Ghidra project files', required: false },
  ],
  check() {
    const ghidraDir = process.env.GHIDRA_INSTALL_DIR
    if (!ghidraDir) return false
    try { accessSync(ghidraDir); return true } catch { return false }
  },
  register(server, deps) {
    server.registerTool(ghidraAnalyzeToolDefinition, createGhidraAnalyzeHandler(deps))
    server.registerTool(ghidraHealthToolDefinition, createGhidraHealthHandler(deps))
    return ['ghidra.analyze', 'ghidra.health']
  },
}

export default ghidraPlugin
