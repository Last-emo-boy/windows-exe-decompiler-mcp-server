import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import type { ArtifactRef } from './types.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import { deriveArtifactSessionTag } from './artifact-inventory.js'

export const SUMMARY_STAGE_VALUES = ['triage', 'static', 'deep', 'final'] as const
export type SummaryStage = (typeof SUMMARY_STAGE_VALUES)[number]

export const SUMMARY_TRIAGE_DIGEST_ARTIFACT_TYPE = 'summary_triage_digest'
export const SUMMARY_STATIC_DIGEST_ARTIFACT_TYPE = 'summary_static_digest'
export const SUMMARY_DEEP_DIGEST_ARTIFACT_TYPE = 'summary_deep_digest'
export const SUMMARY_FINAL_DIGEST_ARTIFACT_TYPE = 'summary_final_digest'

export type SummaryDigestScope = 'all' | 'latest' | 'session'

export interface SummaryDigestSelectionOptions {
  scope?: SummaryDigestScope
  sessionTag?: string
}

export interface SummaryDigestSelection<TPayload = unknown> {
  artifacts: Array<{
    artifact_id: string
    created_at: string
    session_tags: string[]
    payload: TPayload
  }>
  latest_payload: TPayload | null
  artifact_ids: string[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  scope_note: string
}

const LATEST_SUMMARY_DIGEST_WINDOW_MS = 10 * 1000

function sanitizePathSegment(value: string | undefined, fallback: string): string {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

function matchesSessionTag(sessionTags: string[], selector?: string | null): boolean {
  if (!selector || !selector.trim()) {
    return false
  }
  const normalized = selector.trim()
  return sessionTags.some((tag) => tag === normalized)
}

export function getSummaryDigestArtifactType(stage: SummaryStage): string {
  switch (stage) {
    case 'triage':
      return SUMMARY_TRIAGE_DIGEST_ARTIFACT_TYPE
    case 'static':
      return SUMMARY_STATIC_DIGEST_ARTIFACT_TYPE
    case 'deep':
      return SUMMARY_DEEP_DIGEST_ARTIFACT_TYPE
    case 'final':
      return SUMMARY_FINAL_DIGEST_ARTIFACT_TYPE
  }
}

export function getSummaryDigestFilePrefix(stage: SummaryStage): string {
  return `${stage}_digest`
}

export async function persistSummaryDigestArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  stage: SummaryStage,
  payload: unknown,
  sessionTag?: string | null
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = sanitizePathSegment(sessionTag || undefined, 'default')
  const reportDir = path.join(workspace.reports, 'summary', sessionSegment)
  await fs.mkdir(reportDir, { recursive: true })

  const fileName = `${getSummaryDigestFilePrefix(stage)}_${Date.now()}.json`
  const absolutePath = path.join(reportDir, fileName)
  const serialized = JSON.stringify(payload, null, 2)
  await fs.writeFile(absolutePath, serialized, 'utf8')

  const artifactId = randomUUID()
  const artifactSha256 = createHash('sha256').update(serialized).digest('hex')
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const createdAt = new Date().toISOString()

  database.insertArtifact({
    id: artifactId,
    sample_id: sampleId,
    type: getSummaryDigestArtifactType(stage),
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
    created_at: createdAt,
  })

  return {
    id: artifactId,
    type: getSummaryDigestArtifactType(stage),
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
    metadata: {
      summary_stage: stage,
      session_tag: sessionTag || null,
    },
  }
}

export async function loadSummaryDigestArtifactSelection<TPayload>(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  stage: SummaryStage,
  options: SummaryDigestSelectionOptions = {}
): Promise<SummaryDigestSelection<TPayload>> {
  const scope = options.scope || 'latest'
  const sessionTag = options.sessionTag?.trim() || null
  const artifactType = getSummaryDigestArtifactType(stage)
  const artifacts = database.findArtifactsByType(sampleId, artifactType)
  if (artifacts.length === 0) {
    return {
      artifacts: [],
      latest_payload: null,
      artifact_ids: [],
      session_tags: [],
      earliest_created_at: null,
      latest_created_at: null,
      scope_note:
        scope === 'session' && sessionTag
          ? `No ${artifactType} artifacts matched session selector "${sessionTag}".`
          : scope === 'latest'
            ? `No ${artifactType} artifacts matched the latest selection window.`
            : `No ${artifactType} artifacts were selected.`,
    }
  }

  const workspace = await workspaceManager.getWorkspace(sampleId)
  const loaded: Array<{
    artifact_id: string
    created_at: string
    session_tags: string[]
    payload: TPayload
  }> = []

  for (const artifact of artifacts) {
    try {
      const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
      const content = await fs.readFile(absolutePath, 'utf8')
      const payload = JSON.parse(content) as TPayload
      const sessionTags = Array.from(
        new Set(
          [
            deriveArtifactSessionTag(artifact.path),
            typeof (payload as { session_tag?: unknown })?.session_tag === 'string'
              ? String((payload as { session_tag?: string }).session_tag).trim()
              : null,
          ].filter((item): item is string => Boolean(item && item.trim()))
        )
      )

      loaded.push({
        artifact_id: artifact.id,
        created_at: artifact.created_at,
        session_tags: sessionTags,
        payload,
      })
    } catch {
      continue
    }
  }

  let selected = loaded
  if (scope === 'session' && sessionTag) {
    selected = loaded.filter((item) => matchesSessionTag(item.session_tags, sessionTag))
  } else if (scope === 'latest' && loaded.length > 0) {
    const latestCreated = new Date(loaded[0].created_at).getTime()
    selected = loaded.filter(
      (item) => latestCreated - new Date(item.created_at).getTime() <= LATEST_SUMMARY_DIGEST_WINDOW_MS
    )
  }

  const artifactIds = selected.map((item) => item.artifact_id)
  const sessionTags = Array.from(new Set(selected.flatMap((item) => item.session_tags)))
  const createdAtValues = selected.map((item) => item.created_at).filter((item) => item && item.length > 0)
  const latestCreatedAt = createdAtValues.length > 0 ? createdAtValues[0] : null
  const earliestCreatedAt =
    createdAtValues.length > 0 ? createdAtValues[createdAtValues.length - 1] : null
  const scopeNote =
    selected.length > 0
      ? `Selected ${selected.length} ${artifactType} artifact(s) using scope=${scope}${sessionTag ? ` selector=${sessionTag}` : ''}.`
      : scope === 'session' && sessionTag
        ? `No ${artifactType} artifacts matched session selector "${sessionTag}".`
        : scope === 'latest'
          ? `No ${artifactType} artifacts matched the latest selection window.`
          : `No ${artifactType} artifacts were selected.`

  return {
    artifacts: selected,
    latest_payload: selected.length > 0 ? selected[0].payload : null,
    artifact_ids: artifactIds,
    session_tags: sessionTags,
    earliest_created_at: earliestCreatedAt,
    latest_created_at: latestCreatedAt,
    scope_note: scopeNote,
  }
}
