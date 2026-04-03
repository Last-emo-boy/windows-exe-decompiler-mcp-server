/**
 * Policy Guard Component
 * Enforces authorization rules for dangerous operations
 * Requirements: 18.1, 18.2, 18.3, 18.4
 */

import fs from 'fs'
import { logger } from './logger.js'
import path from 'path'

// ============================================================================
// Types
// ============================================================================

/**
 * Operation types that can be checked by Policy Guard
 */
export type OperationType =
  | 'static_analysis'
  | 'decompile'
  | 'dynamic_execution'
  | 'network_access'
  | 'external_upload'
  | 'bulk_decompile'

/**
 * Operation to be checked
 */
export interface Operation {
  type: OperationType
  tool: string
  args: Record<string, unknown>
}

/**
 * Context for policy decision
 */
export interface PolicyContext {
  user?: string
  sampleId?: string
  timestamp?: string
}

/**
 * Policy decision result
 */
export interface PolicyDecision {
  allowed: boolean
  reason?: string
  requiresApproval?: boolean
}

/**
 * Dangerous operation requiring approval
 */
export interface DangerousOperation {
  type: string
  description: string
  risks: string[]
  sampleId: string
}

/**
 * Audit event for logging
 */
export interface AuditEvent {
  timestamp: string
  operation: string
  user?: string
  sampleId: string
  decision: 'allow' | 'deny'
  reason?: string
  metadata?: Record<string, unknown>
}

/**
 * Policy rule configuration
 */
export interface PolicyRule {
  defaultAllow: boolean
  requiresApproval: boolean
  requiresIsolation?: boolean
  auditLevel: 'info' | 'warning' | 'critical'
  maxLimit?: number
}

// ============================================================================
// Policy Rules Configuration
// ============================================================================

/**
 * Policy rules for different operation types
 * Requirements: 18.1, 18.2, 18.3, 18.4
 */
export const POLICY_RULES: Record<string, PolicyRule> = {
  // Requirement 18.1: Dynamic execution requires approval
  dynamic_execution: {
    defaultAllow: false,
    requiresApproval: true,
    requiresIsolation: true,
    auditLevel: 'critical',
  },

  // Requirement 18.3: External upload requires approval
  external_upload: {
    defaultAllow: false,
    requiresApproval: true,
    auditLevel: 'critical',
  },

  // Requirement 18.4: Bulk decompilation requires approval
  bulk_decompile: {
    defaultAllow: false,
    requiresApproval: true,
    auditLevel: 'warning',
    maxLimit: 100,
  },

  // Static analysis is generally allowed
  static_analysis: {
    defaultAllow: true,
    requiresApproval: false,
    auditLevel: 'info',
  },

  // Regular decompilation is allowed
  decompile: {
    defaultAllow: true,
    requiresApproval: false,
    auditLevel: 'info',
  },

  // Network access requires approval
  network_access: {
    defaultAllow: false,
    requiresApproval: true,
    requiresIsolation: true,
    auditLevel: 'critical',
  },
}

// ============================================================================
// Policy Guard Implementation
// ============================================================================

/**
 * Policy Guard class for enforcing authorization rules
 */
export class PolicyGuard {
  private auditLogPath: string

  constructor(auditLogPath: string = './audit.log') {
    this.auditLogPath = auditLogPath
    this.ensureAuditLogExists()
  }

  /**
   * Ensure audit log file exists
   */
  private ensureAuditLogExists(): void {
    const dir = path.dirname(this.auditLogPath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
    if (!fs.existsSync(this.auditLogPath)) {
      fs.writeFileSync(this.auditLogPath, '', 'utf-8')
    }
  }

  /**
   * Check permission for an operation
   * Requirements: 18.1, 18.2
   */
  async checkPermission(
    operation: Operation,
    _context: PolicyContext
  ): Promise<PolicyDecision> {
    // Detect dangerous operations
    const dangerousType = this.detectDangerousOperation(operation)

    // Get policy rule for the operation type
    const rule = POLICY_RULES[dangerousType] || POLICY_RULES[operation.type]

    if (!rule) {
      // Unknown operation type - deny by default
      return {
        allowed: false,
        reason: `Unknown operation type: ${operation.type}`,
      }
    }

    // Check specific limits FIRST (e.g., bulk decompile limit)
    if (rule.maxLimit !== undefined) {
      const limitExceeded = this.checkLimitExceeded(operation, rule.maxLimit)
      if (limitExceeded) {
        return {
          allowed: false,
          reason: `Operation exceeds maximum limit of ${rule.maxLimit}`,
          requiresApproval: true,
        }
      }
    }

    // Check if operation requires approval
    if (rule.requiresApproval) {
      // Check if approval was explicitly provided
      const hasApproval = this.checkApprovalProvided(operation)

      if (!hasApproval) {
        return {
          allowed: false,
          reason: `Operation '${operation.type}' requires explicit approval`,
          requiresApproval: true,
        }
      }
    }

    // Operation is allowed
    return {
      allowed: rule.defaultAllow || this.checkApprovalProvided(operation),
      reason: rule.defaultAllow ? undefined : 'Approved by user',
    }
  }

  /**
   * Detect if operation is dangerous based on tool and arguments
   * Requirements: 18.1, 18.3, 18.4
   */
  private detectDangerousOperation(operation: Operation): string {
    // Check for dynamic execution
    if (
      operation.tool === 'sandbox.execute' ||
      operation.type === 'dynamic_execution'
    ) {
      return 'dynamic_execution'
    }

    // Check for external upload
    if (
      operation.tool.includes('upload') ||
      operation.args.backend === 'online_sandbox' ||
      operation.args.external === true
    ) {
      return 'external_upload'
    }

    // Check for bulk decompilation - check multiple parameters
    if (operation.type === 'decompile') {
      // Check count parameter
      if (typeof operation.args.count === 'number' && operation.args.count > 100) {
        return 'bulk_decompile'
      }
      
      // Check topk parameter
      if (typeof operation.args.topk === 'number' && operation.args.topk > 100) {
        return 'bulk_decompile'
      }
      
      // Check addresses array
      if (Array.isArray(operation.args.addresses) && operation.args.addresses.length > 100) {
        return 'bulk_decompile'
      }
      
      // Check functions array
      if (Array.isArray(operation.args.functions) && operation.args.functions.length > 100) {
        return 'bulk_decompile'
      }
    }

    // Check for network access
    if (
      operation.args.network === 'enabled' ||
      operation.args.network === 'fake'
    ) {
      return 'network_access'
    }

    return operation.type
  }

  /**
   * Check if approval was provided in operation arguments
   */
  private checkApprovalProvided(operation: Operation): boolean {
    // Check for explicit approval flag
    if (operation.args.require_user_approval === true) {
      return true
    }

    if (operation.args.approved === true) {
      return true
    }

    return false
  }

  /**
   * Check if operation exceeds limit
   */
  private checkLimitExceeded(operation: Operation, maxLimit: number): boolean {
    // Check count parameter
    if (typeof operation.args.count === 'number') {
      return operation.args.count > maxLimit
    }

    // Check topk parameter (for bulk operations)
    if (typeof operation.args.topk === 'number') {
      return operation.args.topk > maxLimit
    }

    // Check array length parameters
    if (Array.isArray(operation.args.addresses)) {
      return operation.args.addresses.length > maxLimit
    }

    if (Array.isArray(operation.args.functions)) {
      return operation.args.functions.length > maxLimit
    }

    return false
  }

  /**
   * Require user approval for dangerous operation (placeholder)
   * Requirements: 18.1
   * Note: This is a placeholder for V0.5 when human-in-the-loop is implemented
   */
  async requireUserApproval(
    _operation: DangerousOperation
  ): Promise<boolean> {
    // Placeholder implementation - always returns false
    // In V0.5, this will implement actual human approval mechanism
    return false
  }

  /**
   * Record audit log event
   * Requirements: 18.5, 18.6, 23.1, 23.2, 23.4, 23.5
   */
  async auditLog(event: AuditEvent): Promise<void> {
    // Ensure timestamp is set
    if (!event.timestamp) {
      event.timestamp = new Date().toISOString()
    }

    // Format as JSON Lines (one JSON object per line)
    const logLine = JSON.stringify(event) + '\n'

    // Append to audit log file
    try {
      fs.appendFileSync(this.auditLogPath, logLine, 'utf-8')
    } catch (error) {
      // Log to stderr if file write fails
      logger.error({ err: error, event }, 'Failed to write audit log')
    }
  }

  /**
   * Get audit log path
   */
  getAuditLogPath(): string {
    return this.auditLogPath
  }
}

// ============================================================================
// Exports
// ============================================================================

export default PolicyGuard
