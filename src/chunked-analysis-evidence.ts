import type { ArtifactRef } from './types.js'
import {
  type AnalysisEvidenceChunkManifest,
  buildChunkedEvidenceManifest,
} from './analysis-evidence.js'

export interface ChunkedArrayPersistenceResult<T> {
  inline_items: T[]
  manifest: AnalysisEvidenceChunkManifest | null
  chunk_artifacts: ArtifactRef[]
}

export async function persistChunkedArrayArtifacts<T>(
  items: T[],
  options: {
    family: string
    inlineLimit: number
    chunkSize: number
    notes?: string[]
    buildLabel?: (index: number, itemCount: number) => string
    persistChunk: (input: {
      index: number
      itemCount: number
      items: T[]
    }) => Promise<ArtifactRef>
  }
): Promise<ChunkedArrayPersistenceResult<T>> {
  const inlineLimit = Math.max(1, options.inlineLimit)
  const chunkSize = Math.max(1, options.chunkSize)
  const inlineItems = items.slice(0, inlineLimit)

  if (items.length <= inlineLimit) {
    return {
      inline_items: items,
      manifest: null,
      chunk_artifacts: [],
    }
  }

  const chunks: Array<{
    index: number
    itemCount: number
    label: string
    artifactRef: ArtifactRef
  }> = []

  let chunkIndex = 0
  for (let offset = inlineLimit; offset < items.length; offset += chunkSize) {
    const chunkItems = items.slice(offset, offset + chunkSize)
    const artifactRef = await options.persistChunk({
      index: chunkIndex,
      itemCount: chunkItems.length,
      items: chunkItems,
    })
    chunks.push({
      index: chunkIndex,
      itemCount: chunkItems.length,
      label:
        options.buildLabel?.(chunkIndex, chunkItems.length) ||
        `${options.family} chunk ${chunkIndex + 1}`,
      artifactRef,
    })
    chunkIndex += 1
  }

  return {
    inline_items: inlineItems,
    manifest: buildChunkedEvidenceManifest({
      family: options.family,
      totalItems: items.length,
      inlineItems: inlineItems.length,
      chunkSize,
      chunks,
      completeness: 'complete',
      notes: options.notes,
    }),
    chunk_artifacts: chunks.map((chunk) => chunk.artifactRef),
  }
}
