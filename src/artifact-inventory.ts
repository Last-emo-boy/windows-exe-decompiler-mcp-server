import fs from 'fs/promises'
import path from 'path'
import { createHash } from 'crypto'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager, Artifact } from './database.js'

export interface ArtifactInventoryItem extends Artifact {
  exists: boolean
  size_bytes: number | null
  modified_at: string | null
  tracked: boolean
  session_tag: string | null
  retention_bucket: 'active' | 'recent' | 'archive'
  age_days: number
}

export interface ArtifactInventoryOptions {
  artifactTypes?: Iterable<string>
  includeMissing?: boolean
  includeUntrackedFiles?: boolean
  recursive?: boolean
  scanRoots?: string[]
}

export function normalizeRelativeArtifactPath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.?\//, '')
}

export function inferUntrackedArtifactType(relativePath: string): string {
  const normalized = relativePath.toLowerCase()
  if (normalized.endsWith('.pseudo.c') || normalized.includes('pseudo')) {
    return 'ghidra_pseudocode'
  }
  if (normalized.includes('manifest')) {
    return 'manifest'
  }
  if (normalized.includes('gaps')) {
    return 'gaps'
  }
  if (normalized.includes('summary')) {
    return 'summary'
  }
  if (normalized.includes('report')) {
    return 'report'
  }
  if (normalized.includes('ioc_export')) {
    return 'ioc_export'
  }
  return 'filesystem_untracked'
}

export function deriveArtifactSessionTag(relativePath: string): string | null {
  const normalized = normalizeRelativeArtifactPath(relativePath)
  const segments = normalized.split('/').filter((item) => item.length > 0)
  if (segments.length < 2) {
    return null
  }
  if (segments[0] === 'reports' && segments.length >= 4) {
    return `${segments[0]}/${segments[1]}/${segments[2]}`
  }
  if (segments[0] === 'reports' && segments.length >= 2) {
    return `${segments[0]}/${segments[1]}`
  }
  return `${segments[0]}/${segments[1]}`
}

function deriveArtifactAgeDays(referenceIso: string | null | undefined): number {
  const timestamp = referenceIso ? new Date(referenceIso).getTime() : Number.NaN
  if (!Number.isFinite(timestamp)) {
    return 0
  }
  return Math.max(0, Math.floor((Date.now() - timestamp) / (24 * 60 * 60 * 1000)))
}

function deriveRetentionBucket(ageDays: number): 'active' | 'recent' | 'archive' {
  if (ageDays <= 3) {
    return 'active'
  }
  if (ageDays <= 14) {
    return 'recent'
  }
  return 'archive'
}

async function collectFiles(
  rootPath: string,
  recursive: boolean
): Promise<Array<{ absolute: string; stat: { size: number; mtime: Date } }>> {
  const items: Array<{ absolute: string; stat: { size: number; mtime: Date } }> = []
  let entries: Array<{ name: string; isFile: () => boolean; isDirectory: () => boolean }> = []

  try {
    entries = (await fs.readdir(rootPath, {
      withFileTypes: true,
      encoding: 'utf8',
    })) as Array<{ name: string; isFile: () => boolean; isDirectory: () => boolean }>
  } catch {
    return items
  }

  for (const entry of entries) {
    const absolute = path.join(rootPath, String(entry.name))
    if (entry.isFile()) {
      try {
        const stat = await fs.stat(absolute)
        items.push({ absolute, stat: { size: stat.size, mtime: stat.mtime } })
      } catch {
        // Ignore transient file errors.
      }
      continue
    }

    if (recursive && entry.isDirectory()) {
      const nested = await collectFiles(absolute, recursive)
      items.push(...nested)
    }
  }

  return items
}

async function enrichTrackedArtifact(
  workspaceManager: WorkspaceManager,
  workspaceRoot: string,
  artifact: Artifact
): Promise<ArtifactInventoryItem> {
  const absolutePath = workspaceManager.normalizePath(workspaceRoot, artifact.path)
  const sessionTag = deriveArtifactSessionTag(artifact.path)
  try {
    const stat = await fs.stat(absolutePath)
    const ageDays = deriveArtifactAgeDays(artifact.created_at || stat.mtime.toISOString())
    return {
      ...artifact,
      exists: true,
      size_bytes: stat.size,
      modified_at: stat.mtime.toISOString(),
      tracked: true,
      session_tag: sessionTag,
      retention_bucket: deriveRetentionBucket(ageDays),
      age_days: ageDays,
    }
  } catch {
    const ageDays = deriveArtifactAgeDays(artifact.created_at)
    return {
      ...artifact,
      exists: false,
      size_bytes: null,
      modified_at: null,
      tracked: true,
      session_tag: sessionTag,
      retention_bucket: deriveRetentionBucket(ageDays),
      age_days: ageDays,
    }
  }
}

export async function listArtifactInventory(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: ArtifactInventoryOptions = {}
): Promise<ArtifactInventoryItem[]> {
  const includeMissing = options.includeMissing !== false
  const includeUntrackedFiles = options.includeUntrackedFiles !== false
  const recursive = options.recursive !== false
  const scanRoots = options.scanRoots || ['reports', 'ghidra', 'dotnet']
  const typeFilter = new Set<string>()
  for (const item of options.artifactTypes || []) {
    if (typeof item === 'string' && item.length > 0) {
      typeFilter.add(item)
    }
  }

  const trackedArtifacts = database.findArtifacts(sampleId)
  const filteredTracked =
    typeFilter.size > 0
      ? trackedArtifacts.filter((item) => typeFilter.has(item.type))
      : trackedArtifacts

  const workspace = await workspaceManager.getWorkspace(sampleId)
  const tracked = await Promise.all(
    filteredTracked.map((artifact) =>
      enrichTrackedArtifact(workspaceManager, workspace.root, artifact)
    )
  )

  const trackedPathSet = new Set<string>(
    tracked.map((item) => normalizeRelativeArtifactPath(item.path).toLowerCase())
  )
  const untracked: ArtifactInventoryItem[] = []

  if (includeUntrackedFiles) {
    for (const scanRoot of scanRoots) {
      const rootAbsolute = path.join(workspace.root, scanRoot)
      const files = await collectFiles(rootAbsolute, recursive)
      for (const file of files) {
        const relative = normalizeRelativeArtifactPath(path.relative(workspace.root, file.absolute))
        const key = relative.toLowerCase()
        if (trackedPathSet.has(key)) {
          continue
        }
        trackedPathSet.add(key)

        const inferredType = inferUntrackedArtifactType(relative)
        const ageDays = deriveArtifactAgeDays(file.stat.mtime.toISOString())
        if (typeFilter.size > 0 && !typeFilter.has(inferredType)) {
          continue
        }

        untracked.push({
          id: `fs:${createHash('sha1').update(relative).digest('hex')}`,
          sample_id: sampleId,
          type: inferredType,
          path: relative,
          sha256: '',
          mime: null,
          created_at: file.stat.mtime.toISOString(),
          exists: true,
          size_bytes: file.stat.size,
          modified_at: file.stat.mtime.toISOString(),
          tracked: false,
          session_tag: deriveArtifactSessionTag(relative),
          retention_bucket: deriveRetentionBucket(ageDays),
          age_days: ageDays,
        })
      }
    }
  }

  const merged = [...tracked, ...untracked]
  return includeMissing ? merged : merged.filter((item) => item.exists)
}
