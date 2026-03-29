/**
 * 结构化日志模块
 * 
 * 使用 pino 库实现结构化日志记录，支持：
 * - 操作日志
 * - 错误日志（包含完整堆栈）
 * - 性能指标日志
 * - 审计日志
 * 
 * 验收标准：
 * - 需求 30.4: 使用 pino 库记录结构化日志
 * - 需求 30.5: 记录完整的错误堆栈和上下文信息
 */

import pino from 'pino';
import { config } from './config.js';

/**
 * 日志级别
 */
export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

/**
 * 性能指标
 */
export interface PerformanceMetrics {
  elapsedMs: number;
  peakRssMb?: number;
  cpuPercent?: number;
}

/**
 * 操作上下文
 */
export interface OperationContext {
  operation: string;
  sampleId?: string;
  toolName?: string;
  userId?: string;
  [key: string]: unknown;
}

/**
 * 审计事件
 */
export interface AuditEvent {
  operation: string;
  user?: string;
  sampleId?: string;
  decision: 'allow' | 'deny' | 'partial';
  reason?: string;
  metadata?: Record<string, unknown>;
}

/**
 * 创建 pino logger 实例
 *
 * CRITICAL: All logs must go to stderr to avoid interfering with MCP protocol on stdout
 */
function createLogger() {
  // Create destination that writes to stderr (fd 2)
  // Use sync mode to ensure logs are written immediately
  const destination = pino.destination({ dest: 2, sync: true });

  return pino({
    level: config.logging.level || 'info',
    // Simple text format for MCP stdio compatibility
    messageKey: 'msg',
    // 基础字段
    base: {
      pid: process.pid,
      hostname: undefined,
    },
    // 时间戳
    timestamp: pino.stdTimeFunctions.isoTime,
    // 序列化错误对象
    serializers: {
      err: pino.stdSerializers.err,
      error: pino.stdSerializers.err,
    },
  }, destination);
}

/**
 * 全局 logger 实例
 */
export const logger = createLogger();

/**
 * 创建子 logger（带上下文）
 */
export function createChildLogger(context: Record<string, unknown>) {
  return logger.child(context);
}

/**
 * 记录操作开始
 */
export function logOperationStart(context: OperationContext): void {
  logger.info(context, `Operation started: ${context.operation}`);
}

/**
 * 记录操作完成
 */
export function logOperationComplete(
  context: OperationContext,
  metrics: PerformanceMetrics
): void {
  logger.info(
    { ...context, metrics },
    `Operation completed: ${context.operation} (${metrics.elapsedMs}ms)`
  );
}

/**
 * 记录操作失败
 */
export function logOperationError(
  context: OperationContext,
  error: Error,
  metrics?: Partial<PerformanceMetrics>
): void {
  logger.error(
    {
      ...context,
      err: error,
      metrics,
      // 确保记录完整的错误堆栈
      stack: error.stack,
      errorName: error.name,
      errorMessage: error.message,
    },
    `Operation failed: ${context.operation} - ${error.message}`
  );
}

/**
 * 记录审计事件
 */
export function logAudit(event: AuditEvent): void {
  logger.info(
    {
      audit: true,
      ...event,
    },
    `Audit: ${event.operation} - ${event.decision}`
  );
}

/**
 * 记录性能指标
 */
export function logMetrics(
  operation: string,
  metrics: PerformanceMetrics,
  context?: Record<string, unknown>
): void {
  logger.info(
    {
      metrics: true,
      operation,
      ...metrics,
      ...context,
    },
    `Metrics: ${operation} - ${metrics.elapsedMs}ms`
  );
}

/**
 * 记录警告
 */
export function logWarning(message: string, context?: Record<string, unknown>): void {
  logger.warn(context, message);
}

/**
 * 记录调试信息
 */
export function logDebug(message: string, context?: Record<string, unknown>): void {
  logger.debug(context, message);
}

/**
 * 记录错误（通用）
 */
export function logError(error: Error, context?: Record<string, unknown>): void {
  logger.error(
    {
      ...context,
      err: error,
      stack: error.stack,
      errorName: error.name,
      errorMessage: error.message,
    },
    error.message
  );
}

/**
 * 创建性能计时器
 */
export function createTimer() {
  const startTime = Date.now();

  return {
    /**
     * 结束计时并返回性能指标
     */
    end(): PerformanceMetrics {
      const endTime = Date.now();
      const endMemory = process.memoryUsage();

      return {
        elapsedMs: endTime - startTime,
        peakRssMb: Math.round(endMemory.rss / 1024 / 1024),
      };
    },
  };
}

/**
 * 包装异步操作，自动记录日志和性能指标
 */
export async function withLogging<T>(
  context: OperationContext,
  fn: () => Promise<T>
): Promise<T> {
  const timer = createTimer();
  logOperationStart(context);

  try {
    const result = await fn();
    const metrics = timer.end();
    logOperationComplete(context, metrics);
    return result;
  } catch (error) {
    const metrics = timer.end();
    logOperationError(context, error as Error, metrics);
    throw error;
  }
}

/**
 * 包装同步操作，自动记录日志和性能指标
 */
export function withLoggingSync<T>(
  context: OperationContext,
  fn: () => T
): T {
  const timer = createTimer();
  logOperationStart(context);

  try {
    const result = fn();
    const metrics = timer.end();
    logOperationComplete(context, metrics);
    return result;
  } catch (error) {
    const metrics = timer.end();
    logOperationError(context, error as Error, metrics);
    throw error;
  }
}

export default logger;
