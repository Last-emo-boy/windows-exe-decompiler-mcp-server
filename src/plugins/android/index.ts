/**
 * Android / APK Analysis Plugin
 *
 * APK manifest extraction, DEX decompilation, packer detection.
 */

import { accessSync } from 'fs'
import type { Plugin } from '../sdk.js'
import {
  apkStructureAnalyzeToolDefinition, createApkStructureAnalyzeHandler,
} from './tools/apk-structure-analyze.js'
import {
  dexDecompileToolDefinition, createDexDecompileHandler,
} from './tools/dex-decompile.js'
import {
  dexClassesListToolDefinition, createDexClassesListHandler,
} from './tools/dex-classes-list.js'
import {
  apkPackerDetectToolDefinition, createApkPackerDetectHandler,
} from './tools/apk-packer-detect.js'

const androidPlugin: Plugin = {
  id: 'android',
  name: 'Android / APK Analysis',
  description: 'APK manifest extraction, DEX decompilation, and packer detection',
  version: '1.0.0',
  configSchema: [
    { envVar: 'JADX_PATH', description: 'Path to jadx binary for DEX decompilation', required: false, defaultValue: '/opt/jadx/bin/jadx' },
  ],
  check() {
    const jadx = process.env.JADX_PATH ?? '/opt/jadx/bin/jadx'
    try { accessSync(jadx); return true } catch { return false }
  },
  register(server, deps) {
    server.registerTool(apkStructureAnalyzeToolDefinition, createApkStructureAnalyzeHandler(deps))
    server.registerTool(dexDecompileToolDefinition, createDexDecompileHandler(deps))
    server.registerTool(dexClassesListToolDefinition, createDexClassesListHandler(deps))
    server.registerTool(apkPackerDetectToolDefinition, createApkPackerDetectHandler(deps))
    return ['apk.structure.analyze', 'dex.decompile', 'dex.classes.list', 'apk.packer.detect']
  },
}

export default androidPlugin
