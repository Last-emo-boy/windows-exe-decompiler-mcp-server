import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import type { ArtifactRef } from './types.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import { deriveArtifactSessionTag } from './artifact-inventory.js'

export const SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE = 'semantic_name_suggestions'
export const SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE = 'semantic_name_prepare_bundle'
export const SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE =
  'semantic_explanation_prepare_bundle'
export const SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE = 'semantic_function_explanations'
export const SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE =
  'semantic_module_review_prepare_bundle'
export const SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE = 'semantic_module_reviews'

export interface SemanticNameSuggestionEntry {
  address?: string | null
  function?: string | null
  candidate_name: string
  normalized_candidate_name?: string | null
  confidence: number
  why: string
  required_assumptions?: string[]
  evidence_used?: string[]
}

export interface SemanticNameSuggestionArtifactPayload {
  schema_version: 1
  sample_id: string
  created_at: string
  session_tag?: string | null
  client_name?: string | null
  model_name?: string | null
  prepare_artifact_id?: string | null
  suggestions: SemanticNameSuggestionEntry[]
}

export interface LoadedSemanticNameSuggestion {
  address: string | null
  function: string | null
  candidate_name: string
  normalized_candidate_name: string | null
  confidence: number
  why: string
  required_assumptions: string[]
  evidence_used: string[]
  artifact_id: string
  created_at: string
  client_name: string | null
  model_name: string | null
  session_tag: string | null
  prepare_artifact_id: string | null
}

export interface SemanticNameSuggestionIndex {
  byAddress: Map<string, LoadedSemanticNameSuggestion>
  byFunction: Map<string, LoadedSemanticNameSuggestion>
  marker: string
  artifact_ids: string[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  scope_note: string
}

export type SemanticArtifactScope = 'all' | 'latest' | 'session'

export interface LoadSemanticArtifactOptions {
  scope?: SemanticArtifactScope
  sessionTag?: string
}

export interface SemanticFunctionExplanationEntry {
  address?: string | null
  function?: string | null
  summary: string
  behavior: string
  confidence: number
  assumptions?: string[]
  evidence_used?: string[]
  rewrite_guidance?: string[]
}

export interface SemanticFunctionExplanationArtifactPayload {
  schema_version: 1
  sample_id: string
  created_at: string
  session_tag?: string | null
  client_name?: string | null
  model_name?: string | null
  prepare_artifact_id?: string | null
  explanations: SemanticFunctionExplanationEntry[]
}

export interface LoadedSemanticFunctionExplanation {
  address: string | null
  function: string | null
  summary: string
  behavior: string
  confidence: number
  assumptions: string[]
  evidence_used: string[]
  rewrite_guidance: string[]
  artifact_id: string
  created_at: string
  client_name: string | null
  model_name: string | null
  session_tag: string | null
  prepare_artifact_id: string | null
}

export interface SemanticFunctionExplanationIndex {
  byAddress: Map<string, LoadedSemanticFunctionExplanation>
  byFunction: Map<string, LoadedSemanticFunctionExplanation>
  marker: string
  artifact_ids: string[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  scope_note: string
}

export interface SemanticModuleReviewEntry {
  module_name: string
  refined_name?: string | null
  summary: string
  role_hint?: string | null
  confidence: number
  assumptions?: string[]
  evidence_used?: string[]
  rewrite_guidance?: string[]
  focus_areas?: string[]
  priority_functions?: string[]
}

export interface SemanticModuleReviewArtifactPayload {
  schema_version: 1
  sample_id: string
  created_at: string
  session_tag?: string | null
  client_name?: string | null
  model_name?: string | null
  prepare_artifact_id?: string | null
  reviews: SemanticModuleReviewEntry[]
}

export interface LoadedSemanticModuleReview {
  module_name: string
  refined_name: string | null
  summary: string
  role_hint: string | null
  confidence: number
  assumptions: string[]
  evidence_used: string[]
  rewrite_guidance: string[]
  focus_areas: string[]
  priority_functions: string[]
  artifact_id: string
  created_at: string
  client_name: string | null
  model_name: string | null
  session_tag: string | null
  prepare_artifact_id: string | null
}

export interface SemanticModuleReviewIndex {
  byModule: Map<string, LoadedSemanticModuleReview>
  marker: string
  artifact_ids: string[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  scope_note: string
}

const LATEST_SEMANTIC_ARTIFACT_WINDOW_MS = 10 * 1000

function sanitizePathSegment(value: string | undefined, fallback: string): string {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

export function normalizeFunctionKey(value: string | null | undefined): string | null {
  if (!value) {
    return null
  }
  const normalized = value.trim().toLowerCase()
  return normalized.length > 0 ? normalized : null
}

export function normalizeAddressKey(value: string | null | undefined): string | null {
  if (!value) {
    return null
  }
  const normalized = value.trim().replace(/^0x/i, '').toLowerCase()
  return normalized.length > 0 ? normalized : null
}

export function sanitizeSemanticName(value: string | null | undefined): string | null {
  if (!value) {
    return null
  }

  const collapsed = value
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase()

  if (!collapsed) {
    return null
  }

  if (/^[0-9]/.test(collapsed)) {
    return `fn_${collapsed}`
  }

  return collapsed
}

export function normalizeModuleKey(value: string | null | undefined): string | null {
  const normalized = sanitizeSemanticName(value)
  return normalized && normalized.length > 0 ? normalized : null
}

async function persistSemanticNamingJsonArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactType: string,
  filePrefix: string,
  payload: unknown,
  sessionTag?: string | null
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = sanitizePathSegment(sessionTag || undefined, 'default')
  const reportDir = path.join(workspace.reports, 'semantic_naming', sessionSegment)
  await fs.mkdir(reportDir, { recursive: true })

  const fileName = `${filePrefix}_${Date.now()}.json`
  const absolutePath = path.join(reportDir, fileName)
  const serialized = JSON.stringify(payload, null, 2)
  await fs.writeFile(absolutePath, serialized, 'utf-8')

  const artifactId = randomUUID()
  const artifactSha256 = createHash('sha256').update(serialized).digest('hex')
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const createdAt = new Date().toISOString()

  database.insertArtifact({
    id: artifactId,
    sample_id: sampleId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
    created_at: createdAt,
  })

  return {
    id: artifactId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
  }
}

export async function persistSemanticNamePrepareBundleArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  payload: unknown,
  sessionTag?: string | null
): Promise<ArtifactRef> {
  return persistSemanticNamingJsonArtifact(
    workspaceManager,
    database,
    sampleId,
    SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE,
    'prepare_bundle',
    payload,
    sessionTag
  )
}

export async function persistSemanticExplanationPrepareBundleArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  payload: unknown,
  sessionTag?: string | null
): Promise<ArtifactRef> {
  return persistSemanticNamingJsonArtifact(
    workspaceManager,
    database,
    sampleId,
    SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE,
    'explain_bundle',
    payload,
    sessionTag
  )
}

export async function persistSemanticFunctionExplanationsArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  payload: SemanticFunctionExplanationArtifactPayload
): Promise<ArtifactRef> {
  return persistSemanticNamingJsonArtifact(
    workspaceManager,
    database,
    payload.sample_id,
    SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE,
    'semantic_function_explanations',
    payload,
    payload.session_tag
  )
}

export async function persistSemanticModuleReviewPrepareBundleArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  payload: unknown,
  sessionTag?: string | null
): Promise<ArtifactRef> {
  return persistSemanticNamingJsonArtifact(
    workspaceManager,
    database,
    sampleId,
    SEMANTIC_MODULE_REVIEW_PREPARE_BUNDLE_ARTIFACT_TYPE,
    'module_review_bundle',
    payload,
    sessionTag
  )
}

export async function persistSemanticModuleReviewsArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  payload: SemanticModuleReviewArtifactPayload
): Promise<ArtifactRef> {
  return persistSemanticNamingJsonArtifact(
    workspaceManager,
    database,
    payload.sample_id,
    SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE,
    'semantic_module_reviews',
    payload,
    payload.session_tag
  )
}

export async function persistSemanticNameSuggestionsArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  payload: SemanticNameSuggestionArtifactPayload
): Promise<ArtifactRef> {
  return persistSemanticNamingJsonArtifact(
    workspaceManager,
    database,
    payload.sample_id,
    SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE,
    'semantic_name_suggestions',
    payload,
    payload.session_tag
  )
}

async function readArtifactJson(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactId: string
): Promise<unknown | null> {
  const artifact = database.findArtifacts(sampleId).find((item) => item.id === artifactId)
  if (!artifact) {
    return null
  }
  try {
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
    const content = await fs.readFile(absolutePath, 'utf-8')
    return JSON.parse(content) as unknown
  } catch {
    return null
  }
}

function collectSemanticArtifactSessionTags(
  artifactPath: string,
  payloadSessionTag?: string | null
): string[] {
  const sessionTags = new Set<string>()
  const derivedSessionTag = deriveArtifactSessionTag(artifactPath)
  if (derivedSessionTag) {
    sessionTags.add(derivedSessionTag)
  }
  if (typeof payloadSessionTag === 'string' && payloadSessionTag.trim().length > 0) {
    sessionTags.add(payloadSessionTag.trim())
  }
  const basename = path.basename(artifactPath, path.extname(artifactPath)).trim()
  if (basename.length > 0) {
    sessionTags.add(basename)
  }
  return Array.from(sessionTags)
}

function filterSemanticArtifactsByScope<
  TArtifact extends { id: string; path: string; created_at: string; sha256: string },
  TPayload extends { session_tag?: string | null }
>(
  artifacts: Array<{ artifact: TArtifact; payload: TPayload | null }>,
  options: LoadSemanticArtifactOptions = {}
): Array<{ artifact: TArtifact; payload: TPayload | null }> {
  const scope = options.scope || 'all'
  const normalizedSelector = options.sessionTag?.trim().toLowerCase() || null
  let selectedArtifacts = artifacts

  if (normalizedSelector) {
    selectedArtifacts = selectedArtifacts.filter(({ artifact, payload }) => {
      if (artifact.path.toLowerCase().includes(normalizedSelector)) {
        return true
      }
      return collectSemanticArtifactSessionTags(artifact.path, payload?.session_tag).some(
        (tag) => tag.toLowerCase() === normalizedSelector
      )
    })
  }

  if (scope === 'latest' && selectedArtifacts.length > 1) {
    const latestTimestamp = selectedArtifacts.reduce((maxValue, { artifact }) => {
      const timestamp = new Date(artifact.created_at).getTime()
      return Number.isFinite(timestamp) && timestamp > maxValue ? timestamp : maxValue
    }, Number.NEGATIVE_INFINITY)

    if (Number.isFinite(latestTimestamp)) {
      selectedArtifacts = selectedArtifacts.filter(({ artifact }) => {
        const timestamp = new Date(artifact.created_at).getTime()
        return Number.isFinite(timestamp) && latestTimestamp - timestamp <= LATEST_SEMANTIC_ARTIFACT_WINDOW_MS
      })
    }
  }

  return selectedArtifacts
}

export async function loadSemanticNameSuggestionIndex(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: LoadSemanticArtifactOptions = {}
): Promise<SemanticNameSuggestionIndex> {
  const byAddress = new Map<string, LoadedSemanticNameSuggestion>()
  const byFunction = new Map<string, LoadedSemanticNameSuggestion>()
  const artifacts = database.findArtifactsByType(sampleId, SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE)
  const loadedArtifacts: Array<{
    artifact: (typeof artifacts)[number]
    payload: SemanticNameSuggestionArtifactPayload | null
  }> = []

  for (const artifact of artifacts) {
    const payload = (await readArtifactJson(
      workspaceManager,
      database,
      sampleId,
      artifact.id
    )) as SemanticNameSuggestionArtifactPayload | null
    loadedArtifacts.push({ artifact, payload })
  }

  const filteredArtifacts = filterSemanticArtifactsByScope(loadedArtifacts, options)

  for (const { artifact, payload } of filteredArtifacts) {
    if (!payload || !Array.isArray(payload.suggestions)) {
      continue
    }

    for (const suggestion of payload.suggestions) {
      const normalizedCandidateName =
        suggestion.normalized_candidate_name || sanitizeSemanticName(suggestion.candidate_name)
      const loaded: LoadedSemanticNameSuggestion = {
        address: suggestion.address || null,
        function: suggestion.function || null,
        candidate_name: suggestion.candidate_name,
        normalized_candidate_name: normalizedCandidateName,
        confidence: suggestion.confidence,
        why: suggestion.why,
        required_assumptions: suggestion.required_assumptions || [],
        evidence_used: suggestion.evidence_used || [],
        artifact_id: artifact.id,
        created_at: artifact.created_at,
        client_name: payload.client_name || null,
        model_name: payload.model_name || null,
        session_tag: payload.session_tag || null,
        prepare_artifact_id: payload.prepare_artifact_id || null,
      }

      const addressKey = normalizeAddressKey(suggestion.address)
      if (addressKey && !byAddress.has(addressKey)) {
        byAddress.set(addressKey, loaded)
      }

      const functionKey = normalizeFunctionKey(suggestion.function)
      if (functionKey && !byFunction.has(functionKey)) {
        byFunction.set(functionKey, loaded)
      }
    }
  }

  return {
    byAddress,
    byFunction,
    marker:
      filteredArtifacts.length > 0
        ? filteredArtifacts.map(({ artifact }) => `${artifact.id}:${artifact.sha256}`).join('|')
        : 'none',
    artifact_ids: filteredArtifacts.map(({ artifact }) => artifact.id),
    session_tags: Array.from(
      new Set(
        filteredArtifacts.flatMap(({ artifact, payload }) =>
          collectSemanticArtifactSessionTags(artifact.path, payload?.session_tag)
        )
      )
    ),
    earliest_created_at:
      filteredArtifacts.length > 0
        ? filteredArtifacts
            .map(({ artifact }) => artifact.created_at)
            .filter((item) => typeof item === 'string' && item.length > 0)
            .sort()[0] || null
        : null,
    latest_created_at:
      filteredArtifacts.length > 0
        ? filteredArtifacts
            .map(({ artifact }) => artifact.created_at)
            .filter((item) => typeof item === 'string' && item.length > 0)
            .sort()
            .slice(-1)[0] || null
        : null,
    scope_note:
      options.scope === 'session' && options.sessionTag?.trim()
        ? `Semantic naming artifacts are limited to session selector "${options.sessionTag.trim()}".`
        : options.scope === 'latest'
          ? 'Semantic naming artifacts are limited to the latest artifact window.'
          : 'Semantic naming artifacts reflect the selected artifact scope.',
  }
}

export async function loadSemanticFunctionExplanationIndex(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: LoadSemanticArtifactOptions = {}
): Promise<SemanticFunctionExplanationIndex> {
  const byAddress = new Map<string, LoadedSemanticFunctionExplanation>()
  const byFunction = new Map<string, LoadedSemanticFunctionExplanation>()
  const artifacts = database.findArtifactsByType(sampleId, SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE)
  const loadedArtifacts: Array<{
    artifact: (typeof artifacts)[number]
    payload: SemanticFunctionExplanationArtifactPayload | null
  }> = []

  for (const artifact of artifacts) {
    const payload = (await readArtifactJson(
      workspaceManager,
      database,
      sampleId,
      artifact.id
    )) as SemanticFunctionExplanationArtifactPayload | null
    loadedArtifacts.push({ artifact, payload })
  }

  const filteredArtifacts = filterSemanticArtifactsByScope(loadedArtifacts, options)

  for (const { artifact, payload } of filteredArtifacts) {
    if (!payload || !Array.isArray(payload.explanations)) {
      continue
    }

    for (const explanation of payload.explanations) {
      const loaded: LoadedSemanticFunctionExplanation = {
        address: explanation.address || null,
        function: explanation.function || null,
        summary: explanation.summary,
        behavior: explanation.behavior,
        confidence: explanation.confidence,
        assumptions: explanation.assumptions || [],
        evidence_used: explanation.evidence_used || [],
        rewrite_guidance: explanation.rewrite_guidance || [],
        artifact_id: artifact.id,
        created_at: artifact.created_at,
        client_name: payload.client_name || null,
        model_name: payload.model_name || null,
        session_tag: payload.session_tag || null,
        prepare_artifact_id: payload.prepare_artifact_id || null,
      }

      const addressKey = normalizeAddressKey(explanation.address)
      if (addressKey && !byAddress.has(addressKey)) {
        byAddress.set(addressKey, loaded)
      }

      const functionKey = normalizeFunctionKey(explanation.function)
      if (functionKey && !byFunction.has(functionKey)) {
        byFunction.set(functionKey, loaded)
      }
    }
  }

  return {
    byAddress,
    byFunction,
    marker:
      filteredArtifacts.length > 0
        ? filteredArtifacts.map(({ artifact }) => `${artifact.id}:${artifact.sha256}`).join('|')
        : 'none',
    artifact_ids: filteredArtifacts.map(({ artifact }) => artifact.id),
    session_tags: Array.from(
      new Set(
        filteredArtifacts.flatMap(({ artifact, payload }) =>
          collectSemanticArtifactSessionTags(artifact.path, payload?.session_tag)
        )
      )
    ),
    earliest_created_at:
      filteredArtifacts.length > 0
        ? filteredArtifacts
            .map(({ artifact }) => artifact.created_at)
            .filter((item) => typeof item === 'string' && item.length > 0)
            .sort()[0] || null
        : null,
    latest_created_at:
      filteredArtifacts.length > 0
        ? filteredArtifacts
            .map(({ artifact }) => artifact.created_at)
            .filter((item) => typeof item === 'string' && item.length > 0)
            .sort()
            .slice(-1)[0] || null
        : null,
    scope_note:
      options.scope === 'session' && options.sessionTag?.trim()
        ? `Semantic explanation artifacts are limited to session selector "${options.sessionTag.trim()}".`
        : options.scope === 'latest'
          ? 'Semantic explanation artifacts are limited to the latest artifact window.'
        : 'Semantic explanation artifacts reflect the selected artifact scope.',
  }
}

export async function loadSemanticModuleReviewIndex(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: LoadSemanticArtifactOptions = {}
): Promise<SemanticModuleReviewIndex> {
  const byModule = new Map<string, LoadedSemanticModuleReview>()
  const artifacts = database.findArtifactsByType(sampleId, SEMANTIC_MODULE_REVIEWS_ARTIFACT_TYPE)
  const loadedArtifacts: Array<{
    artifact: (typeof artifacts)[number]
    payload: SemanticModuleReviewArtifactPayload | null
  }> = []

  for (const artifact of artifacts) {
    const payload = (await readArtifactJson(
      workspaceManager,
      database,
      sampleId,
      artifact.id
    )) as SemanticModuleReviewArtifactPayload | null
    loadedArtifacts.push({ artifact, payload })
  }

  const filteredArtifacts = filterSemanticArtifactsByScope(loadedArtifacts, options)

  for (const { artifact, payload } of filteredArtifacts) {
    if (!payload || !Array.isArray(payload.reviews)) {
      continue
    }

    for (const review of payload.reviews) {
      const moduleKey = normalizeModuleKey(review.module_name)
      if (!moduleKey || byModule.has(moduleKey)) {
        continue
      }
      byModule.set(moduleKey, {
        module_name: review.module_name,
        refined_name: review.refined_name || null,
        summary: review.summary,
        role_hint: review.role_hint || null,
        confidence: review.confidence,
        assumptions: review.assumptions || [],
        evidence_used: review.evidence_used || [],
        rewrite_guidance: review.rewrite_guidance || [],
        focus_areas: review.focus_areas || [],
        priority_functions: review.priority_functions || [],
        artifact_id: artifact.id,
        created_at: artifact.created_at,
        client_name: payload.client_name || null,
        model_name: payload.model_name || null,
        session_tag: payload.session_tag || null,
        prepare_artifact_id: payload.prepare_artifact_id || null,
      })
    }
  }

  return {
    byModule,
    marker:
      filteredArtifacts.length > 0
        ? filteredArtifacts.map(({ artifact }) => `${artifact.id}:${artifact.sha256}`).join('|')
        : 'none',
    artifact_ids: filteredArtifacts.map(({ artifact }) => artifact.id),
    session_tags: Array.from(
      new Set(
        filteredArtifacts.flatMap(({ artifact, payload }) =>
          collectSemanticArtifactSessionTags(artifact.path, payload?.session_tag)
        )
      )
    ),
    earliest_created_at:
      filteredArtifacts.length > 0
        ? filteredArtifacts
            .map(({ artifact }) => artifact.created_at)
            .filter((item) => typeof item === 'string' && item.length > 0)
            .sort()[0] || null
        : null,
    latest_created_at:
      filteredArtifacts.length > 0
        ? filteredArtifacts
            .map(({ artifact }) => artifact.created_at)
            .filter((item) => typeof item === 'string' && item.length > 0)
            .sort()
            .slice(-1)[0] || null
        : null,
    scope_note:
      options.scope === 'session' && options.sessionTag?.trim()
        ? `Semantic module review artifacts are limited to session selector "${options.sessionTag.trim()}".`
        : options.scope === 'latest'
          ? 'Semantic module review artifacts are limited to the latest artifact window.'
          : 'Semantic module review artifacts reflect the selected artifact scope.',
  }
}

export function findSemanticNameSuggestion(
  index: SemanticNameSuggestionIndex | null | undefined,
  address: string | null | undefined,
  funcName: string | null | undefined
): LoadedSemanticNameSuggestion | null {
  if (!index) {
    return null
  }

  const addressKey = normalizeAddressKey(address)
  if (addressKey && index.byAddress.has(addressKey)) {
    return index.byAddress.get(addressKey) || null
  }

  const functionKey = normalizeFunctionKey(funcName)
  if (functionKey && index.byFunction.has(functionKey)) {
    return index.byFunction.get(functionKey) || null
  }

  return null
}

export function findSemanticFunctionExplanation(
  index: SemanticFunctionExplanationIndex | null | undefined,
  address: string | null | undefined,
  funcName: string | null | undefined
): LoadedSemanticFunctionExplanation | null {
  if (!index) {
    return null
  }

  const addressKey = normalizeAddressKey(address)
  if (addressKey && index.byAddress.has(addressKey)) {
    return index.byAddress.get(addressKey) || null
  }

  const functionKey = normalizeFunctionKey(funcName)
  if (functionKey && index.byFunction.has(functionKey)) {
    return index.byFunction.get(functionKey) || null
  }

  return null
}

export function findSemanticModuleReview(
  index: SemanticModuleReviewIndex | null | undefined,
  moduleName: string | null | undefined
): LoadedSemanticModuleReview | null {
  if (!index) {
    return null
  }

  const moduleKey = normalizeModuleKey(moduleName)
  if (moduleKey && index.byModule.has(moduleKey)) {
    return index.byModule.get(moduleKey) || null
  }

  return null
}
