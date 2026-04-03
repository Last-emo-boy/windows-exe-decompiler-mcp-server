/**
 * Worker Pool - Manages worker processes for job execution
 * 
 * Implements requirements 21.3, 27.2, and operational constraint 4:
 * - Worker process management
 * - Task allocation and status updates
 * - Concurrency control (max 4 concurrent Ghidra analyses)
 */

import { EventEmitter } from 'events';
import type { Job, JobResult } from './types.js';
import { JobQueue } from './job-queue.js';
import { logger } from './logger.js';

/**
 * Worker process state
 */
interface WorkerState {
  id: string;
  type: 'static' | 'decompile' | 'dotnet' | 'sandbox';
  status: 'idle' | 'busy' | 'failed';
  currentJob?: Job;
  startedAt?: string;
  lastHeartbeat?: string;
  timeoutTimer?: NodeJS.Timeout;
}

/**
 * Worker pool configuration
 */
export interface WorkerPoolConfig {
  maxStaticWorkers?: number;
  maxDecompileWorkers?: number;
  maxDotNetWorkers?: number;
  maxSandboxWorkers?: number;
  heartbeatIntervalMs?: number;
  workerTimeoutMs?: number;
  // Test mode: allows injecting custom job executor for testing
  testExecutor?: (job: Job) => Promise<JobResult>;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: Omit<Required<WorkerPoolConfig>, 'testExecutor'> = {
  maxStaticWorkers: 8,
  maxDecompileWorkers: 4, // Operational constraint 4: limit Ghidra concurrency to 4
  maxDotNetWorkers: 4,
  maxSandboxWorkers: 2,
  heartbeatIntervalMs: 5000,
  workerTimeoutMs: 30000
};

/**
 * Worker pool that manages worker processes and allocates jobs
 * 
 * Features:
 * - Per-worker-type concurrency limits
 * - Automatic worker allocation
 * - Job status tracking
 * - Worker health monitoring
 */
export class WorkerPool extends EventEmitter {
  private workers: Map<string, WorkerState> = new Map();
  private config: Omit<Required<WorkerPoolConfig>, 'testExecutor'> & { testExecutor?: (job: Job) => Promise<JobResult> };
  private jobQueue: JobQueue;
  private heartbeatTimer?: NodeJS.Timeout;
  private allocationTimer?: NodeJS.Timeout;
  private isRunning = false;
  private jobHandlers?: Map<string, (job: Job) => Promise<unknown>>;

  constructor(jobQueue: JobQueue, config: WorkerPoolConfig = {}) {
    super();
    this.jobQueue = jobQueue;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.jobHandlers = new Map();
  }

  /**
   * Register a handler function for a given job type or tool name.
   */
  registerHandler(key: string, handler: (job: Job) => Promise<unknown>): void {
    this.jobHandlers!.set(key, handler);
  }

  /**
   * Start the worker pool
   * 
   * Begins monitoring the job queue and allocating jobs to workers
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Worker pool already running');
      return;
    }

    this.isRunning = true;
    logger.info({
      maxStaticWorkers: this.config.maxStaticWorkers,
      maxDecompileWorkers: this.config.maxDecompileWorkers,
      maxDotNetWorkers: this.config.maxDotNetWorkers,
      maxSandboxWorkers: this.config.maxSandboxWorkers
    }, 'Starting worker pool');

    // Start job allocation loop
    this.allocationTimer = setInterval(() => {
      this.allocateJobs();
    }, 1000);

    // Start heartbeat monitoring
    this.heartbeatTimer = setInterval(() => {
      this.checkWorkerHealth();
    }, this.config.heartbeatIntervalMs);

    // Listen for job queue events
    this.jobQueue.on('job:enqueued', () => {
      this.allocateJobs();
    });

    this.emit('pool:started');
  }

  /**
   * Stop the worker pool
   * 
   * Stops allocating new jobs and waits for running jobs to complete
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      return;
    }

    this.isRunning = false;
    logger.info('Stopping worker pool');

    // Clear timers
    if (this.allocationTimer) {
      clearInterval(this.allocationTimer);
      this.allocationTimer = undefined;
    }

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }

    // Clear all timeout timers
    for (const worker of this.workers.values()) {
      if (worker.timeoutTimer) {
        clearTimeout(worker.timeoutTimer);
        worker.timeoutTimer = undefined;
      }
    }

    // Wait for all workers to finish
    await this.waitForWorkers();

    this.emit('pool:stopped');
  }

  /**
   * Allocate jobs from the queue to available workers
   * 
   * Requirements: 21.3 - Task allocation
   */
  private allocateJobs(): void {
    if (!this.isRunning) {
      return;
    }

    // Try to allocate jobs while we have capacity
    let allocated = 0;
    while (this.hasCapacity()) {
      const job = this.jobQueue.dequeue();
      if (!job) {
        break; // No more jobs in queue
      }

      const worker = this.allocateWorker(job);
      if (worker) {
        this.executeJob(worker, job);
        allocated++;
      } else {
        // No worker available, put job back in queue
        // This shouldn't happen if hasCapacity() is correct
        logger.warn({ jobId: job.id, jobType: job.type }, 'Failed to allocate worker for job');
        break;
      }
    }

    if (allocated > 0) {
      logger.debug(`Allocated ${allocated} jobs to workers`);
    }
  }

  /**
   * Check if we have capacity to run more jobs
   */
  private hasCapacity(): boolean {
    // Check if any worker type has capacity
    const staticBusy = this.getWorkerCountByType('static', 'busy');
    const decompileBusy = this.getWorkerCountByType('decompile', 'busy');
    const dotnetBusy = this.getWorkerCountByType('dotnet', 'busy');
    const sandboxBusy = this.getWorkerCountByType('sandbox', 'busy');
    
    if (staticBusy < this.config.maxStaticWorkers) return true;
    if (decompileBusy < this.config.maxDecompileWorkers) return true;
    if (dotnetBusy < this.config.maxDotNetWorkers) return true;
    if (sandboxBusy < this.config.maxSandboxWorkers) return true;
    
    return false;
  }

  /**
   * Allocate a worker for a job
   * 
   * @param job - Job to allocate worker for
   * @returns Worker state or undefined if no capacity
   */
  private allocateWorker(job: Job): WorkerState | undefined {
    const maxWorkers = this.getMaxWorkers(job.type);
    
    // Check if we have capacity for this job type
    const busyCount = this.getWorkerCountByType(job.type, 'busy');
    if (busyCount >= maxWorkers) {
      return undefined;
    }

    // Try to find an idle worker of the same type
    for (const worker of this.workers.values()) {
      if (worker.type === job.type && worker.status === 'idle') {
        return worker;
      }
    }

    // Create a new worker if we haven't reached the limit
    const totalCount = this.getWorkerCountByType(job.type, 'idle') + 
                       this.getWorkerCountByType(job.type, 'busy');
    
    if (totalCount < maxWorkers) {
      return this.createWorker(job.type);
    }

    return undefined;
  }

  /**
   * Create a new worker
   * 
   * @param type - Worker type
   * @returns New worker state
   */
  private createWorker(type: Job['type']): WorkerState {
    const workerId = `${type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const worker: WorkerState = {
      id: workerId,
      type,
      status: 'idle',
      lastHeartbeat: new Date().toISOString()
    };

    this.workers.set(workerId, worker);
    
    logger.debug({ workerId, type }, 'Created new worker');
    this.emit('worker:created', workerId, type);
    
    return worker;
  }

  /**
   * Execute a job on a worker
   * 
   * Requirements: 21.3 - Task allocation and status updates
   * Requirements: 21.5, 28.2 - Failure retry mechanism with exponential backoff
   * Requirements: 21.6, 操作约束 5 - Timeout control and worker termination
   * 
   * @param worker - Worker to execute job on
   * @param job - Job to execute
   */
  private async executeJob(worker: WorkerState, job: Job): Promise<void> {
    worker.status = 'busy';
    worker.currentJob = job;
    worker.startedAt = new Date().toISOString();
    worker.lastHeartbeat = new Date().toISOString();

    logger.info({
      workerId: worker.id,
      jobId: job.id,
      jobType: job.type,
      tool: job.tool,
      attempt: job.attempts + 1,
      timeout: job.timeout
    }, 'Executing job on worker');

    // Set up timeout timer for this job
    // Requirements: 21.6 - Task timeout detection
    worker.timeoutTimer = setTimeout(() => {
      this.handleJobTimeout(worker, job);
    }, job.timeout);

    this.emit('worker:job:started', worker.id, job.id);

    try {
      // Execute the job based on type
      const result = await this.executeJobByType(job);
      
      // Clear timeout timer if job completed before timeout
      if (worker.timeoutTimer) {
        clearTimeout(worker.timeoutTimer);
        worker.timeoutTimer = undefined;
      }
      
      // Update job status
      this.jobQueue.complete(job.id, result);
      
      // Update worker state
      worker.status = 'idle';
      worker.currentJob = undefined;
      worker.startedAt = undefined;
      worker.lastHeartbeat = new Date().toISOString();

      logger.info({
        workerId: worker.id,
        jobId: job.id,
        elapsedMs: result.metrics.elapsedMs
      }, 'Job completed successfully');

      this.emit('worker:job:completed', worker.id, job.id, result);

      // Try to allocate more jobs
      this.allocateJobs();

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Clear timeout timer if it exists
      if (worker.timeoutTimer) {
        clearTimeout(worker.timeoutTimer);
        worker.timeoutTimer = undefined;
      }
      
      logger.error({
        workerId: worker.id,
        jobId: job.id,
        error: errorMessage,
        attempt: job.attempts + 1
      }, 'Job execution failed');

      // Create failure result
      const result: JobResult = {
        jobId: job.id,
        ok: false,
        errors: [errorMessage],
        warnings: [],
        artifacts: [],
        metrics: {
          elapsedMs: Date.now() - new Date(worker.startedAt!).getTime(),
          peakRssMb: 0
        }
      };

      // Update worker state
      worker.status = 'idle';
      worker.currentJob = undefined;
      worker.startedAt = undefined;
      worker.lastHeartbeat = new Date().toISOString();

      // Check if job should be retried
      const shouldRetry = this.shouldRetryJob(job, errorMessage);
      
      if (shouldRetry) {
        // Retry the job with exponential backoff
        await this.retryJob(job);
        // Emit event with the NEW attempt number (after increment)
        this.emit('worker:job:retrying', worker.id, job.id, job.attempts);
      } else {
        // Job failed permanently
        this.jobQueue.complete(job.id, result);
        this.emit('worker:job:failed', worker.id, job.id, error);
      }

      // Try to allocate more jobs
      this.allocateJobs();
    }
  }

  /**
   * Handle job timeout
   * 
   * Requirements: 21.6 - Terminate worker process and mark task as failed when timeout occurs
   * Requirements: 操作约束 5 - Enforce configurable timeout limits
   * 
   * @param worker - Worker that timed out
   * @param job - Job that timed out
   */
  private handleJobTimeout(worker: WorkerState, job: Job): void {
    if (!worker.currentJob || worker.currentJob.id !== job.id) {
      // Job already completed or worker is processing a different job
      return;
    }

    const elapsedMs = Date.now() - new Date(worker.startedAt!).getTime();
    
    logger.error({
      workerId: worker.id,
      jobId: job.id,
      jobType: job.type,
      tool: job.tool,
      timeout: job.timeout,
      elapsedMs,
      attempt: job.attempts + 1
    }, 'Job timeout detected');

    // Create timeout error result
    const result: JobResult = {
      jobId: job.id,
      ok: false,
      errors: [`E_TIMEOUT: Job exceeded timeout of ${job.timeout}ms (elapsed: ${elapsedMs}ms)`],
      warnings: [],
      artifacts: [],
      metrics: {
        elapsedMs,
        peakRssMb: 0
      }
    };

    // Terminate the worker process
    // Requirements: 21.6 - Worker process termination
    this.terminateWorker(worker);

    // Update worker state
    worker.status = 'idle';
    worker.currentJob = undefined;
    worker.startedAt = undefined;
    worker.lastHeartbeat = new Date().toISOString();
    worker.timeoutTimer = undefined;

    // Emit timeout event BEFORE checking retry
    this.emit('worker:job:timeout', worker.id, job.id, elapsedMs);

    // Check if job should be retried (timeout is a retryable error)
    const shouldRetry = this.shouldRetryJob(job, 'E_TIMEOUT');
    
    if (shouldRetry) {
      // Retry the job with exponential backoff
      this.retryJob(job).then(() => {
        this.emit('worker:job:retrying', worker.id, job.id, job.attempts);
      });
    } else {
      // Job failed permanently due to timeout
      this.jobQueue.complete(job.id, result);
    }

    // Try to allocate more jobs
    this.allocateJobs();
  }

  /**
   * Terminate a worker process
   * 
   * Requirements: 21.6 - Worker process termination on timeout
   * 
   * This method terminates the worker process to free up resources.
   * In a real implementation, this would kill the actual subprocess.
   * 
   * @param worker - Worker to terminate
   */
  private terminateWorker(worker: WorkerState): void {
    logger.warn({
      workerId: worker.id,
      type: worker.type,
      currentJob: worker.currentJob?.id
    }, 'Terminating worker process');

    // In a real implementation, this would:
    // 1. Send SIGTERM to the worker process
    // 2. Wait for graceful shutdown (with timeout)
    // 3. Send SIGKILL if process doesn't terminate
    // 4. Clean up any resources (temp files, sockets, etc.)
    
    // For now, we just emit an event
    this.emit('worker:terminated', worker.id, worker.type);
    
    // Clear the timeout timer if it exists
    if (worker.timeoutTimer) {
      clearTimeout(worker.timeoutTimer);
      worker.timeoutTimer = undefined;
    }
  }

  /**
   * Determine if a job should be retried
   * 
   * Requirements: 21.5, 28.2 - Retry policy with max 3 attempts
   * 
   * @param job - Job that failed
   * @param errorMessage - Error message from failure
   * @returns True if job should be retried
   */
  private shouldRetryJob(job: Job, errorMessage: string): boolean {
    // Check if we've exceeded max retries
    if (job.attempts >= job.retryPolicy.maxRetries) {
      logger.info({
        jobId: job.id,
        attempts: job.attempts,
        maxRetries: job.retryPolicy.maxRetries
      }, 'Job exceeded max retries');
      return false;
    }

    // Check if error is retryable
    const isRetryable = job.retryPolicy.retryableErrors.some(retryableError => 
      errorMessage.includes(retryableError)
    );

    if (!isRetryable) {
      logger.info({
        jobId: job.id,
        error: errorMessage,
        retryableErrors: job.retryPolicy.retryableErrors
      }, 'Job error is not retryable');
      return false;
    }

    return true;
  }

  /**
   * Retry a failed job with exponential backoff
   * 
   * Requirements: 21.5, 28.2 - Exponential backoff retry
   * 
   * @param job - Job to retry
   */
  private async retryJob(job: Job): Promise<void> {
    // Increment attempt counter
    job.attempts++;

    // Calculate exponential backoff delay
    // Formula: backoffMs * (2 ^ (attempts - 1))
    const backoffDelay = job.retryPolicy.backoffMs * Math.pow(2, job.attempts - 1);

    logger.info({
      jobId: job.id,
      attempt: job.attempts,
      backoffMs: backoffDelay,
      maxRetries: job.retryPolicy.maxRetries
    }, 'Retrying job with exponential backoff');

    // Wait for backoff period
    await new Promise(resolve => setTimeout(resolve, backoffDelay));

    // Re-enqueue the job with updated attempt count
    this.jobQueue.requeue(job);
    
    logger.debug({
      jobId: job.id,
      attempt: job.attempts
    }, 'Job re-enqueued after backoff');
  }

  /**
   * Execute a job based on its type
   * 
   * This is a placeholder that will be implemented by specific worker implementations
   * 
   * @param job - Job to execute
   * @returns Job result
   */
  private async executeJobByType(job: Job): Promise<JobResult> {
    // Use test executor if provided (for testing)
    if (this.config.testExecutor) {
      return this.config.testExecutor(job);
    }

    const startTime = Date.now();

    logger.debug({
      jobId: job.id,
      type: job.type,
      tool: job.tool
    }, 'Executing job via worker dispatch');

    try {
      // Dispatch to the appropriate handler registered on the pool
      const handler = this.jobHandlers?.get(job.type) ?? this.jobHandlers?.get(job.tool);
      if (handler) {
        const result = await handler(job);
        const memUsage = process.memoryUsage();
        return {
          jobId: job.id,
          ok: true,
          data: result,
          errors: [],
          warnings: [],
          artifacts: [],
          metrics: {
            elapsedMs: Date.now() - startTime,
            peakRssMb: Math.round(memUsage.rss / 1024 / 1024 * 100) / 100
          }
        };
      }

      // Fallback: no handler registered — return a descriptive error
      logger.warn({ jobId: job.id, type: job.type }, 'No handler registered for job type');
      return {
        jobId: job.id,
        ok: false,
        data: null,
        errors: [`No execution handler registered for job type '${job.type}'`],
        warnings: [],
        artifacts: [],
        metrics: {
          elapsedMs: Date.now() - startTime,
          peakRssMb: Math.round(process.memoryUsage().rss / 1024 / 1024 * 100) / 100
        }
      };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        jobId: job.id,
        ok: false,
        data: null,
        errors: [errorMsg],
        warnings: [],
        artifacts: [],
        metrics: {
          elapsedMs: Date.now() - startTime,
          peakRssMb: Math.round(process.memoryUsage().rss / 1024 / 1024 * 100) / 100
        }
      };
    }
  }

  /**
   * Check worker health and handle timeouts
   * 
   * Requirements: 27.2 - Worker process management
   */
  private checkWorkerHealth(): void {
    const now = Date.now();
    const timeoutMs = this.config.workerTimeoutMs;

    for (const [workerId, worker] of this.workers.entries()) {
      if (worker.status === 'busy' && worker.lastHeartbeat) {
        const lastHeartbeat = new Date(worker.lastHeartbeat).getTime();
        const elapsed = now - lastHeartbeat;

        if (elapsed > timeoutMs) {
          logger.warn({
            workerId,
            jobId: worker.currentJob?.id,
            elapsedMs: elapsed
          }, 'Worker timeout detected');

          // Mark worker as failed
          worker.status = 'failed';

          // Fail the current job
          if (worker.currentJob) {
            const result: JobResult = {
              jobId: worker.currentJob.id,
              ok: false,
              errors: ['Worker timeout'],
              warnings: [],
              artifacts: [],
              metrics: {
                elapsedMs: elapsed,
                peakRssMb: 0
              }
            };

            this.jobQueue.complete(worker.currentJob.id, result);
            this.emit('worker:timeout', workerId, worker.currentJob.id);
          }

          // Remove failed worker
          this.workers.delete(workerId);
          this.emit('worker:removed', workerId);
        }
      }
    }
  }

  /**
   * Wait for all workers to finish their current jobs
   */
  private async waitForWorkers(): Promise<void> {
    const busyWorkers = Array.from(this.workers.values()).filter(w => w.status === 'busy');
    
    if (busyWorkers.length === 0) {
      return;
    }

    logger.info(`Waiting for ${busyWorkers.length} workers to finish`);

    // Wait for all busy workers to become idle
    await Promise.all(
      busyWorkers.map(worker => 
        new Promise<void>(resolve => {
          const checkInterval = setInterval(() => {
            const currentWorker = this.workers.get(worker.id);
            if (!currentWorker || currentWorker.status !== 'busy') {
              clearInterval(checkInterval);
              resolve();
            }
          }, 100);
        })
      )
    );
  }

  /**
   * Get worker counts by type and status
   */
  private getWorkerCounts() {
    const counts = {
      static: { idle: 0, busy: 0, failed: 0 },
      decompile: { idle: 0, busy: 0, failed: 0 },
      dotnet: { idle: 0, busy: 0, failed: 0 },
      sandbox: { idle: 0, busy: 0, failed: 0 }
    };

    for (const worker of this.workers.values()) {
      counts[worker.type][worker.status]++;
    }

    return counts;
  }

  /**
   * Get count of workers by type and status
   */
  private getWorkerCountByType(type: Job['type'], status: WorkerState['status']): number {
    let count = 0;
    for (const worker of this.workers.values()) {
      if (worker.type === type && worker.status === status) {
        count++;
      }
    }
    return count;
  }

  /**
   * Get maximum workers for a job type
   */
  private getMaxWorkers(type: Job['type']): number {
    switch (type) {
      case 'static':
        return this.config.maxStaticWorkers;
      case 'decompile':
        return this.config.maxDecompileWorkers;
      case 'dotnet':
        return this.config.maxDotNetWorkers;
      case 'sandbox':
        return this.config.maxSandboxWorkers;
      default:
        return 1;
    }
  }

  /**
   * Get pool statistics
   */
  getStats() {
    const counts = this.getWorkerCounts();
    
    return {
      isRunning: this.isRunning,
      queueLength: this.jobQueue.getQueueLength(),
      workers: {
        static: {
          total: counts.static.idle + counts.static.busy + counts.static.failed,
          idle: counts.static.idle,
          busy: counts.static.busy,
          failed: counts.static.failed,
          max: this.config.maxStaticWorkers
        },
        decompile: {
          total: counts.decompile.idle + counts.decompile.busy + counts.decompile.failed,
          idle: counts.decompile.idle,
          busy: counts.decompile.busy,
          failed: counts.decompile.failed,
          max: this.config.maxDecompileWorkers
        },
        dotnet: {
          total: counts.dotnet.idle + counts.dotnet.busy + counts.dotnet.failed,
          idle: counts.dotnet.idle,
          busy: counts.dotnet.busy,
          failed: counts.dotnet.failed,
          max: this.config.maxDotNetWorkers
        },
        sandbox: {
          total: counts.sandbox.idle + counts.sandbox.busy + counts.sandbox.failed,
          idle: counts.sandbox.idle,
          busy: counts.sandbox.busy,
          failed: counts.sandbox.failed,
          max: this.config.maxSandboxWorkers
        }
      }
    };
  }

  /**
   * Update worker heartbeat
   * 
   * Should be called by worker implementations to indicate they're still alive
   * 
   * @param workerId - Worker identifier
   */
  updateHeartbeat(workerId: string): void {
    const worker = this.workers.get(workerId);
    if (worker) {
      worker.lastHeartbeat = new Date().toISOString();
    }
  }
}
