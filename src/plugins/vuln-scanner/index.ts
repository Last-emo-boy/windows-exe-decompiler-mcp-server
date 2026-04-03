/**
 * Vulnerability Scanner Plugin
 *
 * CWE-based vulnerability pattern scanning on decompiled functions.
 * Uses curated pattern database (data/vuln-patterns.json).
 */

import type { Plugin } from '../sdk.js'
import {
  vulnPatternScanToolDefinition, createVulnPatternScanHandler,
} from './tools/vuln-pattern-scan.js'
import {
  vulnPatternSummaryToolDefinition, createVulnPatternSummaryHandler,
} from './tools/vuln-pattern-summary.js'

const vulnScannerPlugin: Plugin = {
  id: 'vuln-scanner',
  name: 'Vulnerability Scanner',
  description: 'CWE-based vulnerability pattern scanning on decompiled code',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(vulnPatternScanToolDefinition, createVulnPatternScanHandler(deps))
    server.registerTool(vulnPatternSummaryToolDefinition, createVulnPatternSummaryHandler(deps))
    return ['vuln.pattern.scan', 'vuln.pattern.summary']
  },
}

export default vulnScannerPlugin
