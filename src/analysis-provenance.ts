import { z } from 'zod'
import type { DynamicEvidenceScope, DynamicTraceSummary } from './dynamic-trace.js'
import type {
  SemanticArtifactScope,
  SemanticFunctionExplanationIndex,
  SemanticModuleReviewIndex,
  SemanticNameSuggestionIndex,
} from './semantic-name-suggestion-artifacts.js'

export const ArtifactSelectionProvenanceSchema = z.object({
  scope: z.enum(['all', 'latest', 'session']),
  session_selector: z.string().nullable(),
  artifact_count: z.number().int().nonnegative(),
  artifact_ids: z.array(z.string()),
  session_tags: z.array(z.string()),
  earliest_artifact_at: z.string().nullable(),
  latest_artifact_at: z.string().nullable(),
  scope_note: z.string(),
})

export const AnalysisProvenanceSchema = z.object({
  runtime: ArtifactSelectionProvenanceSchema,
  semantic_names: ArtifactSelectionProvenanceSchema.optional(),
  semantic_explanations: ArtifactSelectionProvenanceSchema.optional(),
  semantic_module_reviews: ArtifactSelectionProvenanceSchema.optional(),
})

type ArtifactSelectionProvenance = z.infer<typeof ArtifactSelectionProvenanceSchema>

function emptyScopeNote(
  label: string,
  scope: 'all' | 'latest' | 'session',
  sessionTag?: string | null
): string {
  if (scope === 'session' && sessionTag?.trim()) {
    return `No ${label} matched session selector "${sessionTag.trim()}".`
  }
  if (scope === 'latest') {
    return `No ${label} matched the latest selection window.`
  }
  return `No ${label} were selected.`
}

export function buildRuntimeArtifactProvenance(
  dynamicEvidence: DynamicTraceSummary | null | undefined,
  scope: DynamicEvidenceScope,
  sessionTag?: string | null
): ArtifactSelectionProvenance {
  if (!dynamicEvidence) {
    return {
      scope,
      session_selector: sessionTag?.trim() || null,
      artifact_count: 0,
      artifact_ids: [],
      session_tags: [],
      earliest_artifact_at: null,
      latest_artifact_at: null,
      scope_note: emptyScopeNote('runtime evidence artifacts', scope, sessionTag),
    }
  }

  return {
    scope,
    session_selector: dynamicEvidence.session_selector || sessionTag?.trim() || null,
    artifact_count: dynamicEvidence.artifact_count,
    artifact_ids: dynamicEvidence.artifact_ids || [],
    session_tags: dynamicEvidence.session_tags || [],
    earliest_artifact_at: dynamicEvidence.earliest_imported_at || null,
    latest_artifact_at: dynamicEvidence.latest_imported_at || null,
    scope_note:
      dynamicEvidence.scope_note || emptyScopeNote('runtime evidence artifacts', scope, sessionTag),
  }
}

export function buildSemanticArtifactProvenance(
  label:
    | 'semantic naming artifacts'
    | 'semantic explanation artifacts'
    | 'semantic module review artifacts',
  index:
    | SemanticNameSuggestionIndex
    | SemanticFunctionExplanationIndex
    | SemanticModuleReviewIndex
    | null
    | undefined,
  scope: SemanticArtifactScope,
  sessionTag?: string | null
): ArtifactSelectionProvenance {
  if (!index) {
    return {
      scope,
      session_selector: sessionTag?.trim() || null,
      artifact_count: 0,
      artifact_ids: [],
      session_tags: [],
      earliest_artifact_at: null,
      latest_artifact_at: null,
      scope_note: emptyScopeNote(label, scope, sessionTag),
    }
  }

  return {
    scope,
    session_selector: sessionTag?.trim() || null,
    artifact_count: index.artifact_ids.length,
    artifact_ids: index.artifact_ids,
    session_tags: index.session_tags,
    earliest_artifact_at: index.earliest_created_at,
    latest_artifact_at: index.latest_created_at,
    scope_note:
      index.scope_note || emptyScopeNote(label, scope, sessionTag),
  }
}
