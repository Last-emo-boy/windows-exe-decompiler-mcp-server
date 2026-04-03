/**
 * LLM Multi-Model Adapter
 *
 * Provides a unified interface for routing LLM calls to different model providers.
 * Supports the MCP sampling protocol, plus optional direct API backends for
 * scenarios like ensemble analysis or model comparison.
 */

import { logger } from '../logger.js'

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

export interface ModelMessage {
  role: 'user' | 'assistant' | 'system'
  content: string
}

export interface ModelRequest {
  messages: ModelMessage[]
  model?: string
  maxTokens?: number
  temperature?: number
  stopSequences?: string[]
}

export interface ModelResponse {
  content: string
  model: string
  provider: string
  usage?: {
    inputTokens: number
    outputTokens: number
  }
  finishReason?: 'stop' | 'max_tokens' | 'error'
}

/** Interface that a model provider backend must implement. */
export interface ModelProvider {
  /** Provider identifier, e.g. 'mcp-sampling', 'openai', 'local-ollama'. */
  id: string
  /** Human-readable name. */
  name: string
  /** Supported model identifiers. */
  models: string[]
  /** Send a completion request. */
  complete(request: ModelRequest): Promise<ModelResponse>
  /** Check if the provider is available. */
  isAvailable(): Promise<boolean>
}

export interface ModelRouterConfig {
  /** Default model to use when not specified. */
  defaultModel?: string
  /** Default provider to use when not specified. */
  defaultProvider?: string
  /** Timeout for model calls in ms. */
  timeoutMs?: number
}

// ═══════════════════════════════════════════════════════════════════════════
// MCP Sampling Provider — uses the MCP client's built-in sampling
// ═══════════════════════════════════════════════════════════════════════════

export class McpSamplingProvider implements ModelProvider {
  readonly id = 'mcp-sampling'
  readonly name = 'MCP Client Sampling'
  readonly models = ['client-default']
  private createMessage: ((request: any) => Promise<any>) | null = null

  /**
   * Bind the MCP server's createMessage function.
   * Called after server initialization when client capabilities are known.
   */
  bind(createMessageFn: (request: any) => Promise<any>): void {
    this.createMessage = createMessageFn
  }

  async complete(request: ModelRequest): Promise<ModelResponse> {
    if (!this.createMessage) {
      throw new Error('MCP sampling not available — client does not support createMessage')
    }

    const result = await this.createMessage({
      messages: request.messages.map(m => ({
        role: m.role === 'system' ? 'user' : m.role,
        content: { type: 'text', text: m.content },
      })),
      maxTokens: request.maxTokens || 4096,
    })

    const text = typeof result.content === 'string'
      ? result.content
      : result.content?.text || JSON.stringify(result.content)

    return {
      content: text,
      model: result.model || 'client-default',
      provider: this.id,
      finishReason: result.stopReason === 'end_turn' ? 'stop' : 'max_tokens',
    }
  }

  async isAvailable(): Promise<boolean> {
    return this.createMessage !== null
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Model Router
// ═══════════════════════════════════════════════════════════════════════════

export class ModelRouter {
  private providers = new Map<string, ModelProvider>()
  private config: ModelRouterConfig

  constructor(config: ModelRouterConfig = {}) {
    this.config = {
      defaultModel: config.defaultModel,
      defaultProvider: config.defaultProvider || 'mcp-sampling',
      timeoutMs: config.timeoutMs || 120_000,
    }
  }

  /** Register a model provider. */
  registerProvider(provider: ModelProvider): void {
    this.providers.set(provider.id, provider)
    logger.info({ providerId: provider.id, models: provider.models }, 'Registered model provider')
  }

  /** Get a registered provider by ID. */
  getProvider(id: string): ModelProvider | undefined {
    return this.providers.get(id)
  }

  /** List all registered providers with availability. */
  async listProviders(): Promise<Array<{ id: string; name: string; models: string[]; available: boolean }>> {
    const results = []
    for (const provider of this.providers.values()) {
      results.push({
        id: provider.id,
        name: provider.name,
        models: provider.models,
        available: await provider.isAvailable(),
      })
    }
    return results
  }

  /**
   * Send a completion request, routing to the appropriate provider.
   */
  async complete(request: ModelRequest): Promise<ModelResponse> {
    const providerId = this.config.defaultProvider || 'mcp-sampling'
    const provider = this.providers.get(providerId)

    if (!provider) {
      throw new Error(`No model provider registered with id '${providerId}'. Available: [${Array.from(this.providers.keys()).join(', ')}]`)
    }

    if (!(await provider.isAvailable())) {
      // Try fallback providers
      for (const [id, fallback] of this.providers) {
        if (id !== providerId && await fallback.isAvailable()) {
          logger.info({ primary: providerId, fallback: id }, 'Primary provider unavailable, using fallback')
          return this.executeWithTimeout(fallback, request)
        }
      }
      throw new Error(`Model provider '${providerId}' is not available and no fallback found`)
    }

    return this.executeWithTimeout(provider, request)
  }

  /**
   * Ensemble: send the same request to multiple providers and return all responses.
   */
  async ensemble(request: ModelRequest, providerIds?: string[]): Promise<ModelResponse[]> {
    const ids = providerIds || Array.from(this.providers.keys())
    const results: ModelResponse[] = []

    const promises = ids.map(async (id) => {
      const provider = this.providers.get(id)
      if (!provider) return null
      if (!(await provider.isAvailable())) return null
      try {
        return await this.executeWithTimeout(provider, request)
      } catch (err) {
        logger.warn({ providerId: id, err }, 'Ensemble provider failed')
        return null
      }
    })

    const responses = await Promise.all(promises)
    for (const r of responses) {
      if (r) results.push(r)
    }

    return results
  }

  private async executeWithTimeout(provider: ModelProvider, request: ModelRequest): Promise<ModelResponse> {
    const timeoutMs = this.config.timeoutMs!

    return new Promise<ModelResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Model call to ${provider.id} timed out after ${timeoutMs}ms`))
      }, timeoutMs)

      provider.complete(request)
        .then(result => {
          clearTimeout(timer)
          resolve(result)
        })
        .catch(err => {
          clearTimeout(timer)
          reject(err)
        })
    })
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Singleton setup
// ═══════════════════════════════════════════════════════════════════════════

let _router: ModelRouter | null = null

export function getModelRouter(): ModelRouter {
  if (!_router) {
    _router = new ModelRouter()
    // Register the default MCP sampling provider
    _router.registerProvider(new McpSamplingProvider())
  }
  return _router
}
