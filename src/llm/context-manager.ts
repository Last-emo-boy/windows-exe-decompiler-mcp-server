/**
 * LLM Context Manager
 * Manages analysis context for LLM interactions
 * Tasks: llm-assisted-analysis-enhancement 1.2
 */

import type { DatabaseManager } from '../database.js'

export interface AnalysisContext {
  sampleId: string
  analysisGoal: 'triage' | 'reverse' | 'report'
  userPreferences: {
    detailLevel: 'brief' | 'standard' | 'detailed'
    autoTrigger: boolean
  }
  history: Array<{
    timestamp: string
    action: string
    result: string
  }>
  sampleContext: {
    binaryType?: string
    capabilities?: string[]
    threatLevel?: string
  }
  createdAt: string
  updatedAt: string
}

export interface ContextManagerOptions {
  ttlMs?: number  // Context TTL in milliseconds (default: 24 hours)
  maxHistory?: number  // Maximum history entries (default: 50)
}

export class ContextManager {
  private database: DatabaseManager
  private options: ContextManagerOptions

  constructor(database: DatabaseManager, options: ContextManagerOptions = {}) {
    this.database = database
    this.options = {
      ttlMs: options.ttlMs ?? (24 * 60 * 60 * 1000),  // 24 hours
      maxHistory: options.maxHistory ?? 50,
    }
  }

  /**
   * Get or create context for a sample
   */
  async getContext(sampleId: string): Promise<AnalysisContext | null> {
    const context = await this.loadContext(sampleId)
    
    if (!context) {
      return null
    }

    // Check if expired
    const age = Date.now() - new Date(context.updatedAt).getTime()
    if (age > this.options.ttlMs!) {
      await this.deleteContext(sampleId)
      return null
    }

    return context
  }

  /**
   * Create or update context
   */
  async setContext(sampleId: string, context: Partial<AnalysisContext>): Promise<void> {
    const existing = await this.loadContext(sampleId)
    
    const updated: AnalysisContext = {
      sampleId,
      analysisGoal: existing?.analysisGoal || 'triage',
      userPreferences: existing?.userPreferences || {
        detailLevel: 'standard',
        autoTrigger: true,
      },
      history: existing?.history || [],
      sampleContext: existing?.sampleContext || {},
      createdAt: existing?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...context,
    }

    // Trim history if needed
    if (updated.history.length > this.options.maxHistory!) {
      updated.history = updated.history.slice(-this.options.maxHistory!)
    }

    await this.saveContext(updated)
  }

  /**
   * Add history entry
   */
  async addHistory(sampleId: string, action: string, result: string): Promise<void> {
    const context = await this.getContext(sampleId)
    
    if (context) {
      context.history.push({
        timestamp: new Date().toISOString(),
        action,
        result,
      })
      await this.setContext(sampleId, context)
    }
  }

  /**
   * Update user preferences
   */
  async setPreferences(
    sampleId: string,
    preferences: Partial<AnalysisContext['userPreferences']>
  ): Promise<void> {
    const context = await this.getContext(sampleId)
    
    if (context) {
      context.userPreferences = {
        ...context.userPreferences,
        ...preferences,
      }
      await this.setContext(sampleId, context)
    }
  }

  /**
   * Update sample context
   */
  async setSampleContext(
    sampleId: string,
    sampleContext: Partial<AnalysisContext['sampleContext']>
  ): Promise<void> {
    const context = await this.getContext(sampleId)
    
    if (context) {
      context.sampleContext = {
        ...context.sampleContext,
        ...sampleContext,
      }
      await this.setContext(sampleId, context)
    }
  }

  /**
   * Delete context
   */
  async deleteContext(sampleId: string): Promise<void> {
    // Implementation depends on storage strategy
    // For now, this is a placeholder
  }

  /**
   * Load context from storage
   */
  private async loadContext(sampleId: string): Promise<AnalysisContext | null> {
    // TODO: Implement database storage
    // For now, return null (will create new context)
    return null
  }

  /**
   * Save context to storage
   */
  private async saveContext(context: AnalysisContext): Promise<void> {
    // TODO: Implement database storage
  }

  /**
   * Build context summary for LLM
   */
  buildContextSummary(context: AnalysisContext): string {
    const lines: string[] = []

    lines.push(`Analysis Goal: ${context.analysisGoal}`)
    lines.push(`Detail Level: ${context.userPreferences.detailLevel}`)

    if (context.sampleContext.binaryType) {
      lines.push(`Binary Type: ${context.sampleContext.binaryType}`)
    }

    if (context.sampleContext.capabilities && context.sampleContext.capabilities.length > 0) {
      lines.push(`Capabilities: ${context.sampleContext.capabilities.join(', ')}`)
    }

    if (context.sampleContext.threatLevel) {
      lines.push(`Threat Level: ${context.sampleContext.threatLevel}`)
    }

    if (context.history.length > 0) {
      lines.push('\nRecent History:')
      context.history.slice(-5).forEach(h => {
        lines.push(`  - ${h.timestamp}: ${h.action}`)
      })
    }

    return lines.join('\n')
  }
}
