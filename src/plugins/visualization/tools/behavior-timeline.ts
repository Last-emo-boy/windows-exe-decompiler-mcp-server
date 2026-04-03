/**
 * behavior.timeline MCP tool — Generate a timeline of behavioral events
 * from sandbox / Frida trace data, grouped by time interval.
 * Helps analysts understand the temporal sequence of malware behavior.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'behavior.timeline'

export const BehaviorTimelineInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  bucket_ms: z
    .number()
    .optional()
    .default(1000)
    .describe('Time bucket size in milliseconds for grouping events'),
  max_events: z
    .number()
    .optional()
    .default(2000)
    .describe('Maximum events to process'),
})

export const behaviorTimelineToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a temporal timeline of behavioral events from dynamic analysis traces. ' +
    'Groups API calls by time intervals, highlights phase transitions (init → ' +
    'network → persistence → payload), and identifies behavioral bursts.',
  inputSchema: BehaviorTimelineInputSchema,
}

const PHASE_KEYWORDS: Record<string, string[]> = {
  initialization: ['LoadLibrary', 'GetProcAddress', 'GetModuleHandle', 'VirtualAlloc', 'HeapCreate'],
  file_activity: ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'MoveFile', 'CopyFile'],
  registry: ['RegOpenKey', 'RegSetValue', 'RegQueryValue', 'RegCreateKey', 'RegDeleteKey'],
  network: ['WSAStartup', 'connect', 'send', 'recv', 'InternetOpen', 'HttpSendRequest', 'InternetConnect', 'URLDownloadToFile'],
  process: ['CreateProcess', 'OpenProcess', 'TerminateProcess', 'ShellExecute'],
  injection: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtMapViewOfSection'],
  persistence: ['CreateService', 'RegSetValue', 'schtasks', 'startup'],
  crypto: ['CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 'BCryptEncrypt'],
  anti_analysis: ['IsDebuggerPresent', 'CheckRemoteDebugger', 'NtQueryInformationProcess', 'GetTickCount', 'Sleep'],
}

function classifyApi(api: string): string {
  for (const [phase, keywords] of Object.entries(PHASE_KEYWORDS)) {
    if (keywords.some((kw) => api.includes(kw))) return phase
  }
  return 'other'
}

export function createBehaviorTimelineHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof BehaviorTimelineInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // Collect dynamic events with timestamps
      interface TraceEvent {
        api: string
        timestamp: number
        phase: string
        args?: unknown
      }

      const events: TraceEvent[] = []
      const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          const family = entry.evidence_family ?? ''
          if (!['dynamic_trace', 'frida_trace', 'sandbox_execution', 'speakeasy_trace', 'runtime_trace'].includes(family)) continue

          try {
            const data =
              typeof entry.result_json === 'string'
                ? JSON.parse(entry.result_json)
                : entry.result_json
            const rawEvents = data?.data?.events ?? data?.events ?? data?.data?.trace ?? data?.trace ?? data?.data?.api_calls ?? []

            for (let i = 0; i < rawEvents.length && events.length < args.max_events; i++) {
              const ev = rawEvents[i]
              const api = ev.api ?? ev.name ?? ev.function ?? 'unknown'
              const ts = ev.timestamp ?? ev.time ?? i
              events.push({
                api,
                timestamp: typeof ts === 'number' ? ts : i,
                phase: classifyApi(api),
                args: ev.args ?? ev.params,
              })
            }
          } catch { /* skip */ }
        }
      }

      if (events.length === 0) {
        return { ok: false, errors: ['No dynamic trace events found for timeline'] }
      }

      // Sort by timestamp
      events.sort((a, b) => a.timestamp - b.timestamp)

      // Bucket events
      const minTs = events[0].timestamp
      const maxTs = events[events.length - 1].timestamp
      const bucketMs = args.bucket_ms

      interface Bucket {
        start_ms: number
        end_ms: number
        event_count: number
        phases: Record<string, number>
        top_apis: Array<{ api: string; count: number }>
      }

      const buckets: Bucket[] = []
      let currentBucketStart = minTs
      let bucketEvents: TraceEvent[] = []

      function flushBucket() {
        if (bucketEvents.length === 0) return
        const phases: Record<string, number> = {}
        const apiCounts = new Map<string, number>()
        for (const ev of bucketEvents) {
          phases[ev.phase] = (phases[ev.phase] ?? 0) + 1
          apiCounts.set(ev.api, (apiCounts.get(ev.api) ?? 0) + 1)
        }
        const topApis = [...apiCounts.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([api, count]) => ({ api, count }))

        buckets.push({
          start_ms: currentBucketStart,
          end_ms: currentBucketStart + bucketMs,
          event_count: bucketEvents.length,
          phases,
          top_apis: topApis,
        })
        bucketEvents = []
      }

      for (const ev of events) {
        while (ev.timestamp >= currentBucketStart + bucketMs) {
          flushBucket()
          currentBucketStart += bucketMs
        }
        bucketEvents.push(ev)
      }
      flushBucket()

      // Phase transition detection
      const phaseSequence: Array<{ phase: string; start_ms: number; end_ms: number; event_count: number }> = []
      let currentPhase = ''
      let phaseStart = minTs
      let phaseCount = 0

      for (const ev of events) {
        if (ev.phase !== 'other' && ev.phase !== currentPhase) {
          if (currentPhase) {
            phaseSequence.push({
              phase: currentPhase,
              start_ms: phaseStart,
              end_ms: ev.timestamp,
              event_count: phaseCount,
            })
          }
          currentPhase = ev.phase
          phaseStart = ev.timestamp
          phaseCount = 0
        }
        phaseCount++
      }
      if (currentPhase) {
        phaseSequence.push({
          phase: currentPhase,
          start_ms: phaseStart,
          end_ms: maxTs,
          event_count: phaseCount,
        })
      }

      // Burst detection (buckets with >2x average event count)
      const avgEventCount = events.length / Math.max(buckets.length, 1)
      const bursts = buckets
        .filter((b) => b.event_count > avgEventCount * 2)
        .map((b) => ({
          start_ms: b.start_ms,
          event_count: b.event_count,
          dominant_phase: Object.entries(b.phases).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'other',
        }))

      const resultData = {
        sample_id: args.sample_id,
        total_events: events.length,
        time_span_ms: maxTs - minTs,
        bucket_count: buckets.length,
        bucket_ms: bucketMs,
        phase_sequence: phaseSequence,
        bursts,
        phase_distribution: events.reduce(
          (acc, ev) => {
            acc[ev.phase] = (acc[ev.phase] ?? 0) + 1
            return acc
          },
          {} as Record<string, number>
        ),
        timeline_buckets: buckets.slice(0, 500),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id,
          'behavior_timeline', 'behavior-timeline', resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
