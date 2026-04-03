/**
 * PE (Portable Executable) Analysis Plugin
 *
 * Structure parsing, import/export tables, fingerprinting, symbols recovery.
 * Core analysis tooling for Windows binaries.
 */

import type { Plugin } from '../sdk.js'
import {
  peStructureAnalyzeToolDefinition, createPEStructureAnalyzeHandler,
} from './tools/pe-structure-analyze.js'
import {
  peImportsExtractToolDefinition, createPEImportsExtractHandler,
} from './tools/pe-imports-extract.js'
import {
  peExportsExtractToolDefinition, createPEExportsExtractHandler,
} from './tools/pe-exports-extract.js'
import {
  peFingerprintToolDefinition, createPEFingerprintHandler,
} from './tools/pe-fingerprint.js'
import {
  pePdataExtractToolDefinition, createPEPdataExtractHandler,
} from './tools/pe-pdata-extract.js'
import {
  peSymbolsRecoverToolDefinition, createPESymbolsRecoverHandler,
} from './tools/pe-symbols-recover.js'

const peAnalysisPlugin: Plugin = {
  id: 'pe-analysis',
  name: 'PE Analysis',
  description: 'Windows PE structure analysis, import/export extraction, fingerprinting, and symbol recovery',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(peStructureAnalyzeToolDefinition, createPEStructureAnalyzeHandler(deps))
    server.registerTool(peImportsExtractToolDefinition, createPEImportsExtractHandler(deps))
    server.registerTool(peExportsExtractToolDefinition, createPEExportsExtractHandler(deps))
    server.registerTool(peFingerprintToolDefinition, createPEFingerprintHandler(deps))
    server.registerTool(pePdataExtractToolDefinition, createPEPdataExtractHandler(deps))
    server.registerTool(peSymbolsRecoverToolDefinition, createPESymbolsRecoverHandler(deps))
    return [
      'pe.structure.analyze', 'pe.imports.extract', 'pe.exports.extract',
      'pe.fingerprint', 'pe.pdata.extract', 'pe.symbols.recover',
    ]
  },
}

export default peAnalysisPlugin
