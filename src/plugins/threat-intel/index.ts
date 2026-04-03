/**
 * Threat Intelligence Plugin
 *
 * MITRE ATT&CK mapping and IOC export (JSON/CSV/STIX2).
 */

import type { Plugin } from '../sdk.js'
import {
  attackMapToolDefinition, createAttackMapHandler,
} from './tools/attack-map.js'
import {
  iocExportToolDefinition, createIOCExportHandler,
} from './tools/ioc-export.js'

const threatIntelPlugin: Plugin = {
  id: 'threat-intel',
  name: 'Threat Intelligence',
  description: 'MITRE ATT&CK technique mapping and IOC export (JSON, CSV, STIX2)',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(attackMapToolDefinition, createAttackMapHandler(deps))
    server.registerTool(iocExportToolDefinition, createIOCExportHandler(deps))
    return ['attack.map', 'ioc.export']
  },
}

export default threatIntelPlugin
