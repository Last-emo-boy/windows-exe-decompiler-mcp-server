import { v4 as uuidv4 } from 'uuid'
import { config } from '../config.js'
import type { DatabaseManager } from '../database.js'
import {
  buildStaticWorkerCompatibilityKey,
  getRuntimeWorkerPool,
} from '../runtime-worker-pool.js'

export interface StaticWorkerRequest {
  job_id: string
  tool: string
  sample: {
    sample_id: string
    path: string
  }
  args: Record<string, unknown>
  context: {
    request_time_utc: string
    policy: {
      allow_dynamic: boolean
      allow_network: boolean
    }
    versions: Record<string, string>
  }
}

export interface StaticWorkerResponse {
  job_id: string
  ok: boolean
  warnings: string[]
  errors: string[]
  data: unknown
  artifacts: unknown[]
  metrics: Record<string, unknown>
}

export function buildStaticWorkerRequest(input: {
  tool: string
  sampleId: string
  samplePath: string
  args?: Record<string, unknown>
  toolVersion: string
}): StaticWorkerRequest {
  return {
    job_id: uuidv4(),
    tool: input.tool,
    sample: {
      sample_id: input.sampleId,
      path: input.samplePath,
    },
    args: input.args || {},
    context: {
      request_time_utc: new Date().toISOString(),
      policy: {
        allow_dynamic: false,
        allow_network: false,
      },
      versions: {
        tool_version: input.toolVersion,
      },
    },
  }
}

export async function callStaticWorker(
  request: StaticWorkerRequest,
  options: {
    database?: DatabaseManager
    family?: string
    compatibilityKey?: string
    timeoutMs?: number
  } = {}
): Promise<StaticWorkerResponse> {
  const compatibilityKey = options.compatibilityKey || buildStaticWorkerCompatibilityKey(request)
  const family =
    options.family ||
    (request.tool === 'strings.extract' && request.args?.scan_mode === 'full'
      ? 'static_python.full'
      : 'static_python.preview')

  const { response, lease } = await getRuntimeWorkerPool().executeStaticWorker(request as StaticWorkerRequest & Record<string, unknown>, {
    database: options.database,
    family,
    compatibilityKey,
    timeoutMs:
      options.timeoutMs ||
      ((config.workers.static.timeout || 60) * 1000),
  })

  return {
    job_id: typeof response.job_id === 'string' ? response.job_id : request.job_id,
    ok: Boolean(response.ok),
    warnings: Array.isArray(response.warnings) ? response.warnings : [],
    errors: Array.isArray(response.errors) ? response.errors : [],
    data: response.data,
    artifacts: Array.isArray(response.artifacts) ? response.artifacts : [],
    metrics: {
      ...(response.metrics || {}),
      worker_pool: {
        family: lease.family,
        compatibility_key: lease.compatibility_key,
        deployment_key: lease.deployment_key,
        worker_id: lease.worker_id,
        pool_kind: lease.pool_kind,
        warm_reuse: lease.warm_reuse,
        cold_start: lease.cold_start,
      },
    },
  }
}
