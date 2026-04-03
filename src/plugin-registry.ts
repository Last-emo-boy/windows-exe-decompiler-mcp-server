/**
 * Plugin Registry — discovery, manifest validation, and remote plugin listing.
 *
 * Supports:
 *  - Local plugin scanning from plugins/ directory
 *  - Plugin manifest validation
 *  - Registry index for listing available plugins
 */

import fs from 'fs/promises'
import path from 'path'
import { logger } from './logger.js'
import type { Plugin, PluginConfigField } from './plugins.js'

/** Manifest describing a plugin for registry purposes. */
export interface PluginManifest {
  id: string
  name: string
  version: string
  description: string
  author?: string
  license?: string
  homepage?: string
  repository?: string
  keywords?: string[]
  configFields?: PluginConfigField[]
  dependencies?: string[]
  minServerVersion?: string
  entryPoint?: string
}

/** Registry entry combining manifest + installed state. */
export interface RegistryEntry {
  manifest: PluginManifest
  installed: boolean
  loaded: boolean
  localPath?: string
}

export class PluginRegistry {
  private entries = new Map<string, RegistryEntry>()

  /**
   * Scan a directory for local plugins and build the registry.
   */
  async scanLocalPlugins(pluginsDir: string): Promise<RegistryEntry[]> {
    const results: RegistryEntry[] = []

    try {
      const entries = await fs.readdir(pluginsDir, { withFileTypes: true })

      for (const entry of entries) {
        if (!entry.isDirectory()) continue

        const pluginPath = path.join(pluginsDir, entry.name)
        const manifest = await this.readPluginManifest(pluginPath, entry.name)

        if (manifest) {
          const regEntry: RegistryEntry = {
            manifest,
            installed: true,
            loaded: false,
            localPath: pluginPath,
          }
          this.entries.set(manifest.id, regEntry)
          results.push(regEntry)
        }
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        logger.warn({ err, pluginsDir }, 'Failed to scan plugins directory')
      }
    }

    return results
  }

  /**
   * Attempt to read a plugin manifest from a directory.
   * Looks for a plugin-manifest.json or infers from the default export.
   */
  private async readPluginManifest(pluginDir: string, dirName: string): Promise<PluginManifest | null> {
    // Try explicit manifest file first
    const manifestPath = path.join(pluginDir, 'plugin-manifest.json')
    try {
      const content = await fs.readFile(manifestPath, 'utf-8')
      const parsed = JSON.parse(content)
      return this.validateManifest(parsed)
    } catch {
      // No manifest file — try to infer from the plugin module
    }

    // Try to check for an index.ts / index.js
    for (const filename of ['index.ts', 'index.js']) {
      const filePath = path.join(pluginDir, filename)
      try {
        await fs.access(filePath)
        // File exists — create a minimal manifest from the directory name
        return {
          id: dirName,
          name: dirName.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join(' '),
          version: '0.0.0',
          description: `Plugin discovered from ${dirName}/`,
          entryPoint: filename,
        }
      } catch {
        // File doesn't exist — continue
      }
    }

    return null
  }

  /**
   * Validate a parsed manifest has required fields.
   */
  private validateManifest(data: unknown): PluginManifest | null {
    if (!data || typeof data !== 'object') return null
    const obj = data as Record<string, unknown>

    if (typeof obj.id !== 'string' || typeof obj.name !== 'string' || typeof obj.version !== 'string') {
      return null
    }

    return {
      id: obj.id,
      name: obj.name,
      version: obj.version,
      description: typeof obj.description === 'string' ? obj.description : '',
      author: typeof obj.author === 'string' ? obj.author : undefined,
      license: typeof obj.license === 'string' ? obj.license : undefined,
      homepage: typeof obj.homepage === 'string' ? obj.homepage : undefined,
      repository: typeof obj.repository === 'string' ? obj.repository : undefined,
      keywords: Array.isArray(obj.keywords) ? obj.keywords.filter((k): k is string => typeof k === 'string') : undefined,
      dependencies: Array.isArray(obj.dependencies) ? obj.dependencies.filter((d): d is string => typeof d === 'string') : undefined,
      minServerVersion: typeof obj.minServerVersion === 'string' ? obj.minServerVersion : undefined,
      entryPoint: typeof obj.entryPoint === 'string' ? obj.entryPoint : undefined,
    }
  }

  /**
   * Mark a plugin as loaded (called by PluginManager after successful load).
   */
  markLoaded(pluginId: string): void {
    const entry = this.entries.get(pluginId)
    if (entry) entry.loaded = true
  }

  /**
   * Get all registry entries.
   */
  getAll(): RegistryEntry[] {
    return Array.from(this.entries.values())
  }

  /**
   * Get a single registry entry by plugin ID.
   */
  get(pluginId: string): RegistryEntry | undefined {
    return this.entries.get(pluginId)
  }

  /**
   * Register a plugin manifest manually (e.g. from a built-in plugin).
   */
  registerBuiltin(plugin: Plugin): void {
    this.entries.set(plugin.id, {
      manifest: {
        id: plugin.id,
        name: plugin.name,
        version: plugin.version || '0.0.0',
        description: plugin.description || '',
        configFields: plugin.configSchema,
        dependencies: plugin.dependencies,
      },
      installed: true,
      loaded: false,
    })
  }
}
