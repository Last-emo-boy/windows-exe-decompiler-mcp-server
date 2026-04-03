/**
 * CrackMe Automation Plugin
 *
 * Validation routine location, symbolic execution, patching, and keygen verification.
 */

import type { Plugin } from '../sdk.js'
import {
  crackmeLocateValidationToolDefinition, createCrackmeLocateValidationHandler,
} from './tools/crackme-locate-validation.js'
import {
  symbolicExploreToolDefinition, createSymbolicExploreHandler,
} from './tools/symbolic-explore.js'
import {
  patchGenerateToolDefinition, createPatchGenerateHandler,
} from './tools/patch-generate.js'
import {
  keygenVerifyToolDefinition, createKeygenVerifyHandler,
} from './tools/keygen-verify.js'

const crackmePlugin: Plugin = {
  id: 'crackme',
  name: 'CrackMe Automation',
  description: 'Validation routine location, symbolic execution, patching, and keygen verification',
  version: '1.0.0',
  dependencies: [],
  configSchema: [
    { envVar: 'ANGR_AVAILABLE', description: 'Whether angr is installed for symbolic execution', required: false },
  ],
  check() {
    return true
  },
  register(server, deps) {
    server.registerTool(crackmeLocateValidationToolDefinition, createCrackmeLocateValidationHandler(deps))
    server.registerTool(symbolicExploreToolDefinition, createSymbolicExploreHandler(deps))
    server.registerTool(patchGenerateToolDefinition, createPatchGenerateHandler(deps))
    server.registerTool(keygenVerifyToolDefinition, createKeygenVerifyHandler(deps))
    return ['crackme.locate_validation', 'symbolic.explore', 'patch.generate', 'keygen.verify']
  },
}

export default crackmePlugin
