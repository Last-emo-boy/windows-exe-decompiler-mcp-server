import fs from 'fs/promises'
import path from 'path'
import type { WorkspaceManager } from './workspace-manager.js'

export type SampleWorkspaceStatus =
  | 'ready'
  | 'workspace_missing'
  | 'original_dir_missing'
  | 'original_file_missing'

export interface SampleWorkspaceIntegrity {
  status: SampleWorkspaceStatus
  workspace_root: string | null
  original_dir: string | null
  reports_dir: string | null
  ghidra_dir: string | null
  workspace_exists: boolean
  original_dir_exists: boolean
  reports_dir_exists: boolean
  ghidra_dir_exists: boolean
  original_present: boolean
  original_file_count: number
  original_files: string[]
  alternate_workspace_root: string | null
  alternate_original_dir: string | null
  alternate_original_present: boolean
  alternate_original_files: string[]
  remediation: string[]
}

function buildRemediation(status: SampleWorkspaceStatus, sampleId: string): string[] {
  const shared = [
    `Re-ingest the sample with sample.ingest(path=<absolute path>) for ${sampleId}.`,
    'Or restore the original binary into workspace/original before running PE/Ghidra recovery tools.',
  ]

  if (status === 'workspace_missing') {
    return [
      `Workspace directory is missing for ${sampleId}.`,
      ...shared,
    ]
  }

  if (status === 'original_dir_missing') {
    return [
      'workspace/original is missing even though the sample record still exists.',
      ...shared,
    ]
  }

  if (status === 'original_file_missing') {
    return [
      'workspace/original exists but contains no sample file.',
      ...shared,
    ]
  }

  return []
}

function inferStatus(options: {
  workspaceExists: boolean
  originalDirExists: boolean
  originalFileCount: number
}): SampleWorkspaceStatus {
  if (!options.workspaceExists) {
    return 'workspace_missing'
  }
  if (!options.originalDirExists) {
    return 'original_dir_missing'
  }
  if (options.originalFileCount <= 0) {
    return 'original_file_missing'
  }
  return 'ready'
}

export async function inspectSampleWorkspace(
  workspaceManager: WorkspaceManager,
  sampleId: string
): Promise<SampleWorkspaceIntegrity> {
  const workspaceRootBase = workspaceManager.getWorkspaceRoot()
  let workspaceRoot: string | null = null
  let originalDir: string | null = null
  let reportsDir: string | null = null
  let ghidraDir: string | null = null
  let workspaceExists = false
  let originalDirExists = false
  let reportsDirExists = false
  let ghidraDirExists = false
  let originalFiles: string[] = []
  let alternateWorkspaceRoot: string | null = null
  let alternateOriginalDir: string | null = null
  let alternateOriginalFiles: string[] = []

  try {
    const workspace = await workspaceManager.getWorkspace(sampleId)
    workspaceRoot = workspace.root
    originalDir = workspace.original
    reportsDir = workspace.reports
    ghidraDir = workspace.ghidra

    try {
      await fs.access(workspace.root)
      workspaceExists = true
    } catch {
      workspaceExists = false
    }

    try {
      await fs.access(workspace.original)
      originalDirExists = true
      const entries = await fs.readdir(workspace.original, { withFileTypes: true })
      originalFiles = entries
        .filter((entry) => entry.isFile())
        .map((entry) => entry.name)
        .sort()
    } catch {
      originalDirExists = false
    }

    try {
      await fs.access(workspace.reports)
      reportsDirExists = true
    } catch {
      reportsDirExists = false
    }

    try {
      await fs.access(workspace.ghidra)
      ghidraDirExists = true
    } catch {
      ghidraDirExists = false
    }
  } catch {
    workspaceExists = false
  }

  const status = inferStatus({
    workspaceExists,
    originalDirExists,
    originalFileCount: originalFiles.length,
  })

  if (status !== 'ready') {
    const workspaceParent = path.dirname(path.dirname(workspaceRootBase))
    const candidateRoots = Array.from(
      new Set([
        path.join(workspaceParent, 'workspaces'),
      ])
    ).filter((candidate) => path.resolve(candidate) !== path.resolve(workspaceRootBase))

    const sampleHash = sampleId.startsWith('sha256:') ? sampleId.slice(7).toLowerCase() : null
    if (sampleHash && /^[a-f0-9]{64}$/.test(sampleHash)) {
      for (const candidateRoot of candidateRoots) {
        const candidateOriginalDir = path.join(
          candidateRoot,
          sampleHash.slice(0, 2),
          sampleHash.slice(2, 4),
          sampleHash,
          'original'
        )
        try {
          const entries = await fs.readdir(candidateOriginalDir, { withFileTypes: true })
          const files = entries.filter((entry) => entry.isFile()).map((entry) => entry.name).sort()
          if (files.length > 0) {
            alternateWorkspaceRoot = candidateRoot
            alternateOriginalDir = candidateOriginalDir
            alternateOriginalFiles = files
            break
          }
        } catch {
          // ignore missing legacy workspace candidates
        }
      }
    }
  }

  return {
    status,
    workspace_root: workspaceRoot,
    original_dir: originalDir,
    reports_dir: reportsDir,
    ghidra_dir: ghidraDir,
    workspace_exists: workspaceExists,
    original_dir_exists: originalDirExists,
    reports_dir_exists: reportsDirExists,
    ghidra_dir_exists: ghidraDirExists,
    original_present: originalFiles.length > 0,
    original_file_count: originalFiles.length,
    original_files: originalFiles,
    alternate_workspace_root: alternateWorkspaceRoot,
    alternate_original_dir: alternateOriginalDir,
    alternate_original_present: alternateOriginalFiles.length > 0,
    alternate_original_files: alternateOriginalFiles,
    remediation: buildRemediation(status, sampleId),
  }
}

export function formatMissingOriginalError(
  sampleId: string,
  integrity: SampleWorkspaceIntegrity
): string {
  const parts = [
    `Sample original file is unavailable for ${sampleId}.`,
    `status=${integrity.status}`,
  ]
  if (integrity.workspace_root) {
    parts.push(`workspace_root=${integrity.workspace_root}`)
  }
  if (integrity.original_dir) {
    parts.push(`original_dir=${integrity.original_dir}`)
  }
  if (integrity.alternate_original_present && integrity.alternate_original_dir) {
    parts.push(`alternate_original_dir=${integrity.alternate_original_dir}`)
    parts.push('alternate_workspace_fallback=available')
  }
  if (integrity.remediation.length > 0) {
    parts.push(`remediation=${integrity.remediation.join(' ')}`)
  }
  return parts.join(' ')
}

export async function resolvePrimarySamplePath(
  workspaceManager: WorkspaceManager,
  sampleId: string
): Promise<{ samplePath: string; integrity: SampleWorkspaceIntegrity }> {
  const integrity = await inspectSampleWorkspace(workspaceManager, sampleId)
  if (integrity.original_present && integrity.original_dir) {
    return {
      samplePath: path.join(integrity.original_dir, integrity.original_files[0]),
      integrity,
    }
  }
  if (integrity.alternate_original_present && integrity.alternate_original_dir) {
    return {
      samplePath: path.join(integrity.alternate_original_dir, integrity.alternate_original_files[0]),
      integrity,
    }
  }
  if (!integrity.original_present || !integrity.original_dir) {
    throw new Error(formatMissingOriginalError(sampleId, integrity))
  }
  throw new Error(formatMissingOriginalError(sampleId, integrity))
}
