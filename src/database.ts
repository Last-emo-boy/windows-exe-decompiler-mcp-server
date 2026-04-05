/**
 * Database module for Rikune
 * Manages SQLite database schema and operations
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { randomUUID } from 'crypto';
import { logger, logDebug } from './logger.js';

/**
 * Database schema SQL statements
 */
const SCHEMA_SQL = `
-- samples 表：存储样本基础信息
CREATE TABLE IF NOT EXISTS samples (
  id TEXT PRIMARY KEY,
  sha256 TEXT UNIQUE NOT NULL,
  md5 TEXT,
  size INTEGER NOT NULL,
  file_type TEXT,
  created_at TEXT NOT NULL,
  source TEXT
);

CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256);
CREATE INDEX IF NOT EXISTS idx_samples_created_at ON samples(created_at);

-- analyses 表：存储分析任务记录
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  backend TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  output_json TEXT,
  metrics_json TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_analyses_sample_stage ON analyses(sample_id, stage);
CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);

-- analysis_runs 表：存储非阻塞 staged analysis run
CREATE TABLE IF NOT EXISTS analysis_runs (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  goal TEXT NOT NULL,
  depth TEXT NOT NULL,
  backend_policy TEXT NOT NULL,
  compatibility_marker TEXT NOT NULL,
  pipeline_version TEXT NOT NULL,
  sample_size_tier TEXT,
  analysis_budget_profile TEXT,
  status TEXT NOT NULL,
  latest_stage TEXT,
  stage_plan_json TEXT,
  artifact_refs_json TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT,
  reused_from_run_id TEXT,
  last_accessed_at TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_sample_goal ON analysis_runs(sample_id, goal, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_compatibility ON analysis_runs(sample_id, compatibility_marker, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_status ON analysis_runs(status);

-- analysis_run_stages 表：存储 staged run 的每个阶段状态
CREATE TABLE IF NOT EXISTS analysis_run_stages (
  run_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  execution_state TEXT,
  tool TEXT,
  job_id TEXT,
  result_json TEXT,
  artifact_refs_json TEXT,
  coverage_json TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  PRIMARY KEY (run_id, stage),
  FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_run_stages_run ON analysis_run_stages(run_id, stage);
CREATE INDEX IF NOT EXISTS idx_analysis_run_stages_job ON analysis_run_stages(job_id);
CREATE INDEX IF NOT EXISTS idx_analysis_run_stages_status ON analysis_run_stages(status);

-- analysis_evidence 表：存储可复用的规范化分析证据
CREATE TABLE IF NOT EXISTS analysis_evidence (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  evidence_family TEXT NOT NULL,
  backend TEXT NOT NULL,
  mode TEXT NOT NULL,
  compatibility_marker TEXT NOT NULL,
  freshness_marker TEXT,
  provenance_json TEXT,
  metadata_json TEXT,
  result_json TEXT NOT NULL,
  artifact_refs_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_accessed_at TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_evidence_sample_family ON analysis_evidence(sample_id, evidence_family, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_compatibility ON analysis_evidence(sample_id, evidence_family, compatibility_marker, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_backend ON analysis_evidence(sample_id, backend, updated_at DESC);

-- debug_sessions 表：存储持久化调试会话状态
CREATE TABLE IF NOT EXISTS debug_sessions (
  id TEXT PRIMARY KEY,
  run_id TEXT,
  sample_id TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,
  debug_state TEXT NOT NULL,
  backend TEXT,
  current_phase TEXT,
  session_tag TEXT,
  artifact_refs_json TEXT,
  guidance_json TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_debug_sessions_run ON debug_sessions(run_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_debug_sessions_sample ON debug_sessions(sample_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_debug_sessions_status ON debug_sessions(status, updated_at DESC);

-- functions 表：存储函数信息
CREATE TABLE IF NOT EXISTS functions (
  sample_id TEXT NOT NULL,
  address TEXT NOT NULL,
  name TEXT,
  size INTEGER,
  score REAL,
  tags TEXT,
  summary TEXT,
  caller_count INTEGER DEFAULT 0,
  callee_count INTEGER DEFAULT 0,
  is_entry_point INTEGER DEFAULT 0,
  is_exported INTEGER DEFAULT 0,
  callees TEXT,
  PRIMARY KEY (sample_id, address),
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(sample_id, name);
CREATE INDEX IF NOT EXISTS idx_functions_score ON functions(sample_id, score DESC);

-- artifacts 表：存储分析产物
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  type TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  mime TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_sample_type ON artifacts(sample_id, type);

-- upload_sessions 表：存储持久化上传会话
CREATE TABLE IF NOT EXISTS upload_sessions (
  id TEXT PRIMARY KEY,
  token TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL,
  filename TEXT,
  source TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  uploaded_at TEXT,
  staged_path TEXT,
  size INTEGER,
  sha256 TEXT,
  md5 TEXT,
  sample_id TEXT,
  error TEXT,
  metadata_json TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_upload_sessions_token ON upload_sessions(token);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_expires_at ON upload_sessions(expires_at);

-- cache 表：存储缓存结果
CREATE TABLE IF NOT EXISTS cache (
  key TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  sample_sha256 TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_cache_expires_at ON cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_cache_sample_sha256 ON cache(sample_sha256);

-- jobs 表：存储异步作业（用于 async job pattern）
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  tool TEXT NOT NULL,
  sample_id TEXT NOT NULL,
  args_json TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 5,
  timeout INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  progress INTEGER DEFAULT 0,
  error TEXT,
  result_json TEXT,
  estimated_duration_ms INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_sample ON jobs(sample_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);

-- runtime_worker_family_state 表：存储运行时 worker 池族摘要
CREATE TABLE IF NOT EXISTS runtime_worker_family_state (
  family TEXT NOT NULL,
  compatibility_key TEXT NOT NULL,
  deployment_key TEXT,
  pool_kind TEXT NOT NULL,
  live_workers INTEGER NOT NULL DEFAULT 0,
  idle_workers INTEGER NOT NULL DEFAULT 0,
  busy_workers INTEGER NOT NULL DEFAULT 0,
  unhealthy_workers INTEGER NOT NULL DEFAULT 0,
  warm_reuse_count INTEGER NOT NULL DEFAULT 0,
  cold_start_count INTEGER NOT NULL DEFAULT 0,
  eviction_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_used_at TEXT,
  PRIMARY KEY (family, compatibility_key)
);

CREATE INDEX IF NOT EXISTS idx_runtime_worker_family_state_family ON runtime_worker_family_state(family, updated_at DESC);

-- scheduler_events 表：存储预算调度与延期/准入遥测
CREATE TABLE IF NOT EXISTS scheduler_events (
  id TEXT PRIMARY KEY,
  job_id TEXT,
  run_id TEXT,
  sample_id TEXT,
  tool TEXT,
  stage TEXT,
  execution_bucket TEXT NOT NULL,
  cost_class TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT,
  worker_family TEXT,
  warm_reuse INTEGER,
  cold_start INTEGER,
  metadata_json TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scheduler_events_job_id ON scheduler_events(job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scheduler_events_run_id ON scheduler_events(run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scheduler_events_bucket ON scheduler_events(execution_bucket, created_at DESC);

-- batches 表：存储批量提交元数据
CREATE TABLE IF NOT EXISTS batches (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  total_samples INTEGER NOT NULL,
  completed_samples INTEGER NOT NULL DEFAULT 0,
  failed_samples INTEGER NOT NULL DEFAULT 0,
  cancelled_samples INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_batches_status ON batches(status);
CREATE INDEX IF NOT EXISTS idx_batches_created_at ON batches(created_at);

-- batch_samples 表：存储批量中的样本映射
CREATE TABLE IF NOT EXISTS batch_samples (
  batch_id TEXT NOT NULL,
  sample_id TEXT NOT NULL,
  status TEXT NOT NULL,
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  artifact_refs_json TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (batch_id, sample_id),
  FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_batch_samples_batch ON batch_samples(batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_samples_status ON batch_samples(status);
`;

/**
 * Database interface types
 */
export interface Sample {
  id: string; // sha256:<hex>
  sha256: string;
  md5: string | null;
  size: number;
  file_type: string | null;
  created_at: string;
  source: string | null;
}

export interface Analysis {
  id: string; // UUID
  sample_id: string; // FK -> samples.id
  stage: string; // fingerprint/strings/ghidra/dotnet/sandbox
  backend: string; // static/ghidra/dotnet/...
  status: string; // queued/running/done/failed
  started_at: string | null;
  finished_at: string | null;
  output_json: string | null; // 结构化结果
  metrics_json: string | null; // 性能指标
}

export interface AnalysisRun {
  id: string;
  sample_id: string;
  sample_sha256: string;
  goal: string;
  depth: string;
  backend_policy: string;
  compatibility_marker: string;
  pipeline_version: string;
  sample_size_tier: string | null;
  analysis_budget_profile: string | null;
  status: string;
  latest_stage: string | null;
  stage_plan_json: string | null;
  artifact_refs_json: string | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
  reused_from_run_id: string | null;
  last_accessed_at: string | null;
}

export interface AnalysisRunStage {
  run_id: string;
  stage: string;
  status: string;
  execution_state: string | null;
  tool: string | null;
  job_id: string | null;
  result_json: string | null;
  artifact_refs_json: string | null;
  coverage_json: string | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface AnalysisEvidence {
  id: string;
  sample_id: string;
  sample_sha256: string;
  evidence_family: string;
  backend: string;
  mode: string;
  compatibility_marker: string;
  freshness_marker: string | null;
  provenance_json: string | null;
  metadata_json: string | null;
  result_json: string;
  artifact_refs_json: string | null;
  created_at: string;
  updated_at: string;
  last_accessed_at: string | null;
}

export interface DebugSession {
  id: string;
  run_id: string | null;
  sample_id: string;
  sample_sha256: string;
  status: string;
  debug_state: string;
  backend: string | null;
  current_phase: string | null;
  session_tag: string | null;
  artifact_refs_json: string | null;
  guidance_json: string | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
}

export interface RuntimeWorkerFamilyState {
  family: string;
  compatibility_key: string;
  deployment_key: string | null;
  pool_kind: string;
  live_workers: number;
  idle_workers: number;
  busy_workers: number;
  unhealthy_workers: number;
  warm_reuse_count: number;
  cold_start_count: number;
  eviction_count: number;
  last_error: string | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
}

export interface SchedulerEvent {
  id: string;
  job_id: string | null;
  run_id: string | null;
  sample_id: string | null;
  tool: string | null;
  stage: string | null;
  execution_bucket: string;
  cost_class: string;
  decision: string;
  reason: string | null;
  worker_family: string | null;
  warm_reuse: number | null;
  cold_start: number | null;
  metadata_json: string | null;
  created_at: string;
}

export interface Function {
  sample_id: string; // FK
  address: string;
  name: string | null;
  size: number | null;
  score: number | null; // 兴趣函数排序分
  tags: string | null; // JSON array
  summary: string | null;
  caller_count: number | null;
  callee_count: number | null;
  is_entry_point: number | null; // SQLite uses INTEGER for boolean (0/1)
  is_exported: number | null; // SQLite uses INTEGER for boolean (0/1)
  callees: string | null; // JSON array of callee names
}

export interface Artifact {
  id: string; // UUID
  sample_id: string; // FK
  type: string; // strings/json/report/resource_dump/cfg
  path: string; // workspace 相对路径
  sha256: string;
  mime: string | null;
  created_at: string;
}

export interface CachedResult {
  key: string;
  data: unknown;
  created_at: string;
  expires_at: string | null;
}

export type UploadSessionStatus =
  | 'pending'
  | 'uploaded'
  | 'registered'
  | 'expired'
  | 'failed';

export interface UploadSession {
  id: string;
  token: string;
  status: UploadSessionStatus;
  filename: string | null;
  source: string | null;
  created_at: string;
  expires_at: string;
  uploaded_at: string | null;
  staged_path: string | null;
  size: number | null;
  sha256: string | null;
  md5: string | null;
  sample_id: string | null;
  error: string | null;
  metadata_json: string | null;
}

export interface CreateUploadSessionInput {
  filename?: string | null;
  source?: string | null;
  expires_at: string;
  metadata_json?: string | null;
  token?: string;
}

export interface Batch {
  id: string;
  status: string;
  total_samples: number;
  completed_samples: number;
  failed_samples: number;
  cancelled_samples: number;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

export interface BatchSample {
  batch_id: string;
  sample_id: string;
  status: string;
  filename: string;
  size: number;
  sha256: string;
  artifact_refs_json: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Database manager class
 */
export class DatabaseManager {
  private db: Database.Database;

  constructor(dbPath: string) {
    // Ensure directory exists
    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
      logDebug('Created database directory', { path: dbDir });
    }

    // Initialize database
    logger.info({ dbPath }, 'Initializing database');
    this.db = new Database(dbPath);

    // Enable foreign keys
    this.db.pragma('foreign_keys = ON');

    // Initialize schema
    this.initializeSchema();
    logger.info('Database initialized successfully');
  }

  /**
   * Get the raw underlying database handle.
   * Use sparingly — prefer higher-level methods.
   */
  getDb(): Database.Database {
    return this.db
  }

  /**
   * Get logger
   */
  getLogger() {
    return logger
  }

  /**
   * Execute SQL statement
   */
  runSql(sql: string, params?: any[]): void {
    if (params && params.length > 0) {
      const stmt = this.db.prepare(sql)
      stmt.run(...params)
    } else {
      this.db.exec(sql)
    }
  }

  /**
   * Query SQL statement
   */
  querySql<T>(sql: string, params?: any[]): T[] {
    const stmt = this.db.prepare(sql)
    return params ? stmt.all(...params) as T[] : stmt.all() as T[]
  }

  /**
   * Get single row from SQL query
   */
  queryOneSql<T>(sql: string, params?: any[]): T | undefined {
    const stmt = this.db.prepare(sql)
    return params ? stmt.get(...params) as T : stmt.get() as T
  }

  /**
   * Initialize database schema
   */
  private initializeSchema(): void {
    this.db.exec(SCHEMA_SQL);
    this.ensureColumnExists('jobs', 'updated_at', "ALTER TABLE jobs ADD COLUMN updated_at TEXT");
    this.db.exec(`
      UPDATE jobs
      SET updated_at = COALESCE(updated_at, finished_at, started_at, created_at)
      WHERE updated_at IS NULL
    `)
  }

  private ensureColumnExists(tableName: string, columnName: string, alterSql: string): void {
    const stmt = this.db.prepare(`PRAGMA table_info(${tableName})`)
    const columns = stmt.all() as Array<{ name: string }>
    if (!columns.some((column) => column.name === columnName)) {
      this.db.exec(alterSql)
    }
  }

  /**
   * Get the underlying database instance
   */
  getDatabase(): Database.Database {
    return this.db;
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
  }

  /**
   * Execute a transaction
   */
  transaction<T>(fn: () => T): T {
    const txn = this.db.transaction(fn);
    return txn();
  }

  // ==================== Sample Operations ====================

  /**
   * Insert a new sample
   */
  insertSample(sample: Sample): void {
    const stmt = this.db.prepare(`
      INSERT INTO samples (id, sha256, md5, size, file_type, created_at, source)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      sample.id,
      sample.sha256,
      sample.md5,
      sample.size,
      sample.file_type,
      sample.created_at,
      sample.source
    );
  }

  /**
   * Find a sample by ID
   */
  findSample(sampleId: string): Sample | undefined {
    const stmt = this.db.prepare('SELECT * FROM samples WHERE id = ?');
    return stmt.get(sampleId) as Sample | undefined;
  }

  /**
   * Find a sample by SHA256
   */
  findSampleBySha256(sha256: string): Sample | undefined {
    const stmt = this.db.prepare('SELECT * FROM samples WHERE sha256 = ?');
    return stmt.get(sha256) as Sample | undefined;
  }

  // ==================== Upload Session Operations ====================

  /**
   * Create a new upload session with a durable token.
   */
  createUploadSession(input: CreateUploadSessionInput): UploadSession {
    const session: UploadSession = {
      id: randomUUID(),
      token: input.token || randomUUID(),
      status: 'pending',
      filename: input.filename ?? null,
      source: input.source ?? null,
      created_at: new Date().toISOString(),
      expires_at: input.expires_at,
      uploaded_at: null,
      staged_path: null,
      size: null,
      sha256: null,
      md5: null,
      sample_id: null,
      error: null,
      metadata_json: input.metadata_json ?? null,
    };

    const stmt = this.db.prepare(`
      INSERT INTO upload_sessions (
        id, token, status, filename, source, created_at, expires_at,
        uploaded_at, staged_path, size, sha256, md5, sample_id, error, metadata_json
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      session.id,
      session.token,
      session.status,
      session.filename,
      session.source,
      session.created_at,
      session.expires_at,
      session.uploaded_at,
      session.staged_path,
      session.size,
      session.sha256,
      session.md5,
      session.sample_id,
      session.error,
      session.metadata_json
    );

    return session;
  }

  /**
   * Find an upload session by token.
   */
  findUploadSessionByToken(token: string): UploadSession | undefined {
    const stmt = this.db.prepare('SELECT * FROM upload_sessions WHERE token = ?');
    return stmt.get(token) as UploadSession | undefined;
  }

  /**
   * Update an upload session by token.
   */
  updateUploadSessionByToken(
    token: string,
    updates: Partial<Omit<UploadSession, 'id' | 'token' | 'created_at'>>
  ): void {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.status !== undefined) {
      fields.push('status = ?');
      values.push(updates.status);
    }
    if (updates.filename !== undefined) {
      fields.push('filename = ?');
      values.push(updates.filename);
    }
    if (updates.source !== undefined) {
      fields.push('source = ?');
      values.push(updates.source);
    }
    if (updates.expires_at !== undefined) {
      fields.push('expires_at = ?');
      values.push(updates.expires_at);
    }
    if (updates.uploaded_at !== undefined) {
      fields.push('uploaded_at = ?');
      values.push(updates.uploaded_at);
    }
    if (updates.staged_path !== undefined) {
      fields.push('staged_path = ?');
      values.push(updates.staged_path);
    }
    if (updates.size !== undefined) {
      fields.push('size = ?');
      values.push(updates.size);
    }
    if (updates.sha256 !== undefined) {
      fields.push('sha256 = ?');
      values.push(updates.sha256);
    }
    if (updates.md5 !== undefined) {
      fields.push('md5 = ?');
      values.push(updates.md5);
    }
    if (updates.sample_id !== undefined) {
      fields.push('sample_id = ?');
      values.push(updates.sample_id);
    }
    if (updates.error !== undefined) {
      fields.push('error = ?');
      values.push(updates.error);
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?');
      values.push(updates.metadata_json);
    }

    if (fields.length === 0) {
      return;
    }

    values.push(token);
    const stmt = this.db.prepare(`
      UPDATE upload_sessions SET ${fields.join(', ')} WHERE token = ?
    `);
    stmt.run(...values);
  }

  /**
   * Mark an upload session as uploaded.
   */
  markUploadSessionUploaded(
    token: string,
    details: {
      staged_path: string;
      size: number;
      filename?: string | null;
    }
  ): void {
    this.updateUploadSessionByToken(token, {
      status: 'uploaded',
      filename: details.filename ?? undefined,
      uploaded_at: new Date().toISOString(),
      staged_path: details.staged_path,
      size: details.size,
      error: null,
    });
  }

  /**
   * Mark an upload session as registered.
   */
  markUploadSessionRegistered(
    token: string,
    details: {
      sample_id: string;
      size?: number | null;
      sha256?: string | null;
      md5?: string | null;
      clearStagedPath?: boolean;
    }
  ): void {
    this.updateUploadSessionByToken(token, {
      status: 'registered',
      sample_id: details.sample_id,
      size: details.size ?? undefined,
      sha256: details.sha256 ?? undefined,
      md5: details.md5 ?? undefined,
      staged_path: details.clearStagedPath ? null : undefined,
      error: null,
    });
  }

  /**
   * Mark an upload session as failed.
   */
  markUploadSessionFailed(token: string, error: string): void {
    this.updateUploadSessionByToken(token, {
      status: 'failed',
      error,
    });
  }

  /**
   * Mark an upload session as expired.
   */
  markUploadSessionExpired(token: string): void {
    this.updateUploadSessionByToken(token, {
      status: 'expired',
      error: 'Upload session expired',
    });
  }

  /**
   * Expire all non-terminal upload sessions past their expiration time.
   */
  expireUploadSessions(nowIso: string = new Date().toISOString()): number {
    const stmt = this.db.prepare(`
      UPDATE upload_sessions
      SET status = 'expired', error = COALESCE(error, 'Upload session expired')
      WHERE status IN ('pending', 'uploaded')
        AND expires_at < ?
    `);
    const result = stmt.run(nowIso);
    return result.changes;
  }

  // ==================== Analysis Operations ====================

  /**
   * Insert a new analysis
   */
  insertAnalysis(analysis: Analysis): void {
    const stmt = this.db.prepare(`
      INSERT INTO analyses (id, sample_id, stage, backend, status, started_at, finished_at, output_json, metrics_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      analysis.id,
      analysis.sample_id,
      analysis.stage,
      analysis.backend,
      analysis.status,
      analysis.started_at,
      analysis.finished_at,
      analysis.output_json,
      analysis.metrics_json
    );
  }

  /**
   * Update an analysis
   */
  updateAnalysis(
    analysisId: string,
    updates: Partial<Omit<Analysis, 'id' | 'sample_id'>>
  ): void {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.stage !== undefined) {
      fields.push('stage = ?');
      values.push(updates.stage);
    }
    if (updates.backend !== undefined) {
      fields.push('backend = ?');
      values.push(updates.backend);
    }
    if (updates.status !== undefined) {
      fields.push('status = ?');
      values.push(updates.status);
    }
    if (updates.started_at !== undefined) {
      fields.push('started_at = ?');
      values.push(updates.started_at);
    }
    if (updates.finished_at !== undefined) {
      fields.push('finished_at = ?');
      values.push(updates.finished_at);
    }
    if (updates.output_json !== undefined) {
      fields.push('output_json = ?');
      values.push(updates.output_json);
    }
    if (updates.metrics_json !== undefined) {
      fields.push('metrics_json = ?');
      values.push(updates.metrics_json);
    }

    if (fields.length === 0) {
      return; // No updates to perform
    }

    values.push(analysisId);
    const stmt = this.db.prepare(`
      UPDATE analyses SET ${fields.join(', ')} WHERE id = ?
    `);
    stmt.run(...values);
  }

  /**
   * Find an analysis by ID
   */
  findAnalysis(analysisId: string): Analysis | undefined {
    const stmt = this.db.prepare('SELECT * FROM analyses WHERE id = ?');
    return stmt.get(analysisId) as Analysis | undefined;
  }

  /**
   * Find all analyses for a sample
   */
  findAnalysesBySample(sampleId: string): Analysis[] {
    const stmt = this.db.prepare('SELECT * FROM analyses WHERE sample_id = ? ORDER BY started_at DESC');
    return stmt.all(sampleId) as Analysis[];
  }

  // ==================== Analysis Run Operations ====================

  insertAnalysisRun(run: AnalysisRun): void {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_runs (
        id, sample_id, sample_sha256, goal, depth, backend_policy,
        compatibility_marker, pipeline_version, sample_size_tier,
        analysis_budget_profile, status, latest_stage, stage_plan_json,
        artifact_refs_json, metadata_json, created_at, updated_at,
        finished_at, reused_from_run_id, last_accessed_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      run.id,
      run.sample_id,
      run.sample_sha256,
      run.goal,
      run.depth,
      run.backend_policy,
      run.compatibility_marker,
      run.pipeline_version,
      run.sample_size_tier,
      run.analysis_budget_profile,
      run.status,
      run.latest_stage,
      run.stage_plan_json,
      run.artifact_refs_json,
      run.metadata_json,
      run.created_at,
      run.updated_at,
      run.finished_at,
      run.reused_from_run_id,
      run.last_accessed_at
    )
  }

  updateAnalysisRun(
    runId: string,
    updates: Partial<Omit<AnalysisRun, 'id' | 'sample_id' | 'sample_sha256' | 'goal' | 'depth' | 'backend_policy' | 'compatibility_marker' | 'pipeline_version' | 'created_at'>>
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.sample_size_tier !== undefined) {
      fields.push('sample_size_tier = ?')
      values.push(updates.sample_size_tier)
    }
    if (updates.analysis_budget_profile !== undefined) {
      fields.push('analysis_budget_profile = ?')
      values.push(updates.analysis_budget_profile)
    }
    if (updates.status !== undefined) {
      fields.push('status = ?')
      values.push(updates.status)
    }
    if (updates.latest_stage !== undefined) {
      fields.push('latest_stage = ?')
      values.push(updates.latest_stage)
    }
    if (updates.stage_plan_json !== undefined) {
      fields.push('stage_plan_json = ?')
      values.push(updates.stage_plan_json)
    }
    if (updates.artifact_refs_json !== undefined) {
      fields.push('artifact_refs_json = ?')
      values.push(updates.artifact_refs_json)
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?')
      values.push(updates.metadata_json)
    }
    if (updates.updated_at !== undefined) {
      fields.push('updated_at = ?')
      values.push(updates.updated_at)
    }
    if (updates.finished_at !== undefined) {
      fields.push('finished_at = ?')
      values.push(updates.finished_at)
    }
    if (updates.reused_from_run_id !== undefined) {
      fields.push('reused_from_run_id = ?')
      values.push(updates.reused_from_run_id)
    }
    if (updates.last_accessed_at !== undefined) {
      fields.push('last_accessed_at = ?')
      values.push(updates.last_accessed_at)
    }

    if (fields.length === 0) {
      return
    }

    values.push(runId)
    const stmt = this.db.prepare(`
      UPDATE analysis_runs SET ${fields.join(', ')} WHERE id = ?
    `)
    stmt.run(...values)
  }

  findAnalysisRun(runId: string): AnalysisRun | undefined {
    const stmt = this.db.prepare('SELECT * FROM analysis_runs WHERE id = ?')
    return stmt.get(runId) as AnalysisRun | undefined
  }

  findAnalysisRunsBySample(sampleId: string): AnalysisRun[] {
    const stmt = this.db.prepare(
      'SELECT * FROM analysis_runs WHERE sample_id = ? ORDER BY datetime(updated_at) DESC'
    )
    return stmt.all(sampleId) as AnalysisRun[]
  }

  findLatestCompatibleAnalysisRun(
    sampleId: string,
    compatibilityMarker: string
  ): AnalysisRun | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_runs
      WHERE sample_id = ?
        AND compatibility_marker = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(sampleId, compatibilityMarker) as AnalysisRun | undefined
  }

  insertAnalysisEvidence(evidence: AnalysisEvidence): void {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_evidence (
        id, sample_id, sample_sha256, evidence_family, backend, mode, compatibility_marker,
        freshness_marker, provenance_json, metadata_json, result_json, artifact_refs_json,
        created_at, updated_at, last_accessed_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      evidence.id,
      evidence.sample_id,
      evidence.sample_sha256,
      evidence.evidence_family,
      evidence.backend,
      evidence.mode,
      evidence.compatibility_marker,
      evidence.freshness_marker,
      evidence.provenance_json,
      evidence.metadata_json,
      evidence.result_json,
      evidence.artifact_refs_json,
      evidence.created_at,
      evidence.updated_at,
      evidence.last_accessed_at
    )
  }

  updateAnalysisEvidence(
    evidenceId: string,
    updates: Partial<Omit<AnalysisEvidence, 'id' | 'sample_id' | 'sample_sha256' | 'created_at'>>
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.evidence_family !== undefined) {
      fields.push('evidence_family = ?')
      values.push(updates.evidence_family)
    }
    if (updates.backend !== undefined) {
      fields.push('backend = ?')
      values.push(updates.backend)
    }
    if (updates.mode !== undefined) {
      fields.push('mode = ?')
      values.push(updates.mode)
    }
    if (updates.compatibility_marker !== undefined) {
      fields.push('compatibility_marker = ?')
      values.push(updates.compatibility_marker)
    }
    if (updates.freshness_marker !== undefined) {
      fields.push('freshness_marker = ?')
      values.push(updates.freshness_marker)
    }
    if (updates.provenance_json !== undefined) {
      fields.push('provenance_json = ?')
      values.push(updates.provenance_json)
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?')
      values.push(updates.metadata_json)
    }
    if (updates.result_json !== undefined) {
      fields.push('result_json = ?')
      values.push(updates.result_json)
    }
    if (updates.artifact_refs_json !== undefined) {
      fields.push('artifact_refs_json = ?')
      values.push(updates.artifact_refs_json)
    }
    if (updates.updated_at !== undefined) {
      fields.push('updated_at = ?')
      values.push(updates.updated_at)
    }
    if (updates.last_accessed_at !== undefined) {
      fields.push('last_accessed_at = ?')
      values.push(updates.last_accessed_at)
    }

    if (fields.length === 0) {
      return
    }

    values.push(evidenceId)
    const stmt = this.db.prepare(`
      UPDATE analysis_evidence SET ${fields.join(', ')} WHERE id = ?
    `)
    stmt.run(...values)
  }

  findAnalysisEvidence(evidenceId: string): AnalysisEvidence | undefined {
    const stmt = this.db.prepare('SELECT * FROM analysis_evidence WHERE id = ?')
    return stmt.get(evidenceId) as AnalysisEvidence | undefined
  }

  findAnalysisEvidenceBySample(sampleId: string, family?: string, limit?: number): AnalysisEvidence[] {
    let sql = 'SELECT * FROM analysis_evidence WHERE sample_id = ?'
    const params: any[] = [sampleId]
    if (family) {
      sql += ' AND evidence_family = ?'
      params.push(family)
    }
    sql += ' ORDER BY datetime(updated_at) DESC'
    if (typeof limit === 'number') {
      sql += ' LIMIT ?'
      params.push(limit)
    }
    const stmt = this.db.prepare(sql)
    return stmt.all(...params) as AnalysisEvidence[]
  }

  findLatestCompatibleAnalysisEvidence(
    sampleId: string,
    evidenceFamily: string,
    compatibilityMarker: string
  ): AnalysisEvidence | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_evidence
      WHERE sample_id = ? AND evidence_family = ? AND compatibility_marker = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(sampleId, evidenceFamily, compatibilityMarker) as AnalysisEvidence | undefined
  }

  insertDebugSession(session: DebugSession): void {
    const stmt = this.db.prepare(`
      INSERT INTO debug_sessions (
        id, run_id, sample_id, sample_sha256, status, debug_state, backend, current_phase,
        session_tag, artifact_refs_json, guidance_json, metadata_json, created_at, updated_at, finished_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      session.id,
      session.run_id,
      session.sample_id,
      session.sample_sha256,
      session.status,
      session.debug_state,
      session.backend,
      session.current_phase,
      session.session_tag,
      session.artifact_refs_json,
      session.guidance_json,
      session.metadata_json,
      session.created_at,
      session.updated_at,
      session.finished_at
    )
  }

  updateDebugSession(
    sessionId: string,
    updates: Partial<Omit<DebugSession, 'id' | 'sample_id' | 'sample_sha256' | 'created_at'>>
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.run_id !== undefined) {
      fields.push('run_id = ?')
      values.push(updates.run_id)
    }
    if (updates.status !== undefined) {
      fields.push('status = ?')
      values.push(updates.status)
    }
    if (updates.debug_state !== undefined) {
      fields.push('debug_state = ?')
      values.push(updates.debug_state)
    }
    if (updates.backend !== undefined) {
      fields.push('backend = ?')
      values.push(updates.backend)
    }
    if (updates.current_phase !== undefined) {
      fields.push('current_phase = ?')
      values.push(updates.current_phase)
    }
    if (updates.session_tag !== undefined) {
      fields.push('session_tag = ?')
      values.push(updates.session_tag)
    }
    if (updates.artifact_refs_json !== undefined) {
      fields.push('artifact_refs_json = ?')
      values.push(updates.artifact_refs_json)
    }
    if (updates.guidance_json !== undefined) {
      fields.push('guidance_json = ?')
      values.push(updates.guidance_json)
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?')
      values.push(updates.metadata_json)
    }
    if (updates.updated_at !== undefined) {
      fields.push('updated_at = ?')
      values.push(updates.updated_at)
    }
    if (updates.finished_at !== undefined) {
      fields.push('finished_at = ?')
      values.push(updates.finished_at)
    }

    if (fields.length === 0) {
      return
    }

    values.push(sessionId)
    const stmt = this.db.prepare(`
      UPDATE debug_sessions SET ${fields.join(', ')} WHERE id = ?
    `)
    stmt.run(...values)
  }

  findDebugSession(sessionId: string): DebugSession | undefined {
    const stmt = this.db.prepare('SELECT * FROM debug_sessions WHERE id = ?')
    return stmt.get(sessionId) as DebugSession | undefined
  }

  findLatestDebugSessionByRun(runId: string): DebugSession | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM debug_sessions
      WHERE run_id = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(runId) as DebugSession | undefined
  }

  findLatestDebugSessionBySample(sampleId: string): DebugSession | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM debug_sessions
      WHERE sample_id = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(sampleId) as DebugSession | undefined
  }

  findDebugSessionsBySample(sampleId: string, limit: number = 20): DebugSession[] {
    const stmt = this.db.prepare(`
      SELECT * FROM debug_sessions
      WHERE sample_id = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT ?
    `)
    return stmt.all(sampleId, Math.max(1, Math.min(limit, 200))) as DebugSession[]
  }

  upsertAnalysisRunStage(stage: AnalysisRunStage): void {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_run_stages (
        run_id, stage, status, execution_state, tool, job_id,
        result_json, artifact_refs_json, coverage_json, metadata_json,
        created_at, updated_at, started_at, finished_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(run_id, stage) DO UPDATE SET
        status = excluded.status,
        execution_state = excluded.execution_state,
        tool = excluded.tool,
        job_id = excluded.job_id,
        result_json = excluded.result_json,
        artifact_refs_json = excluded.artifact_refs_json,
        coverage_json = excluded.coverage_json,
        metadata_json = excluded.metadata_json,
        updated_at = excluded.updated_at,
        started_at = excluded.started_at,
        finished_at = excluded.finished_at
    `)
    stmt.run(
      stage.run_id,
      stage.stage,
      stage.status,
      stage.execution_state,
      stage.tool,
      stage.job_id,
      stage.result_json,
      stage.artifact_refs_json,
      stage.coverage_json,
      stage.metadata_json,
      stage.created_at,
      stage.updated_at,
      stage.started_at,
      stage.finished_at
    )
  }

  findAnalysisRunStage(runId: string, stage: string): AnalysisRunStage | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_run_stages WHERE run_id = ? AND stage = ?
    `)
    return stmt.get(runId, stage) as AnalysisRunStage | undefined
  }

  findAnalysisRunStages(runId: string): AnalysisRunStage[] {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_run_stages
      WHERE run_id = ?
      ORDER BY datetime(created_at) ASC, stage ASC
    `)
    return stmt.all(runId) as AnalysisRunStage[]
  }

  /**
   * Find recent samples ordered by creation time.
   */
  findRecentSamples(limit: number = 20): Sample[] {
    const safeLimit = Math.max(1, Math.min(limit, 500))
    const stmt = this.db.prepare(
      'SELECT * FROM samples ORDER BY datetime(created_at) DESC LIMIT ?'
    )
    return stmt.all(safeLimit) as Sample[]
  }

  /**
   * Mark stale running analyses as failed so persisted status does not remain misleading.
   */
  reapStaleAnalyses(maxRuntimeMs: number, sampleId?: string): Analysis[] {
    const cutoffIso = new Date(Date.now() - maxRuntimeMs).toISOString()
    const params: any[] = [cutoffIso]
    const sampleClause = sampleId ? ' AND sample_id = ?' : ''
    if (sampleId) {
      params.push(sampleId)
    }

    const selectStmt = this.db.prepare(
      `SELECT * FROM analyses
       WHERE status = 'running'
         AND started_at IS NOT NULL
         AND started_at < ?${sampleClause}
       ORDER BY started_at ASC`
    )
    const stale = selectStmt.all(...params) as Analysis[]
    if (stale.length === 0) {
      return []
    }

    const updateStmt = this.db.prepare(`
      UPDATE analyses
      SET status = ?, finished_at = ?, output_json = ?, metrics_json = ?
      WHERE id = ?
    `)
    const finishedAt = new Date().toISOString()

    const updated = this.db.transaction((rows: Analysis[]) => {
      for (const row of rows) {
        const error = `E_TIMEOUT: stale persisted analysis reaped after exceeding ${maxRuntimeMs}ms`
        let output: Record<string, unknown> = {}
        try {
          output =
            row.output_json && row.output_json.trim().length > 0
              ? (JSON.parse(row.output_json) as Record<string, unknown>)
              : {}
        } catch {
          output = {}
        }

        output = {
          ...output,
          error,
          stale_reaped: true,
          stale_reaped_at: finishedAt,
        }

        let metrics: Record<string, unknown> = {}
        try {
          metrics =
            row.metrics_json && row.metrics_json.trim().length > 0
              ? (JSON.parse(row.metrics_json) as Record<string, unknown>)
              : {}
        } catch {
          metrics = {}
        }

        const startedAtMs = row.started_at ? new Date(row.started_at).getTime() : NaN
        const elapsedMs = Number.isFinite(startedAtMs)
          ? Math.max(0, Date.now() - startedAtMs)
          : maxRuntimeMs

        metrics = {
          ...metrics,
          elapsed_ms: elapsedMs,
          stale_reaped: true,
        }

        updateStmt.run(
          'failed',
          finishedAt,
          JSON.stringify(output),
          JSON.stringify(metrics),
          row.id
        )
      }
    })

    updated(stale)

    return stale.map((row) => ({
      ...row,
      status: 'failed',
      finished_at: finishedAt,
      output_json: JSON.stringify({
        ...(row.output_json ? (() => {
          try {
            return JSON.parse(row.output_json)
          } catch {
            return {}
          }
        })() : {}),
        error: `E_TIMEOUT: stale persisted analysis reaped after exceeding ${maxRuntimeMs}ms`,
        stale_reaped: true,
        stale_reaped_at: finishedAt,
      }),
      metrics_json: JSON.stringify({
        ...(row.metrics_json ? (() => {
          try {
            return JSON.parse(row.metrics_json)
          } catch {
            return {}
          }
        })() : {}),
        stale_reaped: true,
      }),
    }))
  }

  // ==================== Function Operations ====================

  /**
   * Insert a new function
   */
  insertFunction(func: Function): void {
    const stmt = this.db.prepare(`
      INSERT INTO functions (sample_id, address, name, size, score, tags, summary, caller_count, callee_count, is_entry_point, is_exported, callees)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      func.sample_id,
      func.address,
      func.name,
      func.size,
      func.score,
      func.tags,
      func.summary,
      func.caller_count ?? 0,
      func.callee_count ?? 0,
      func.is_entry_point ?? 0,
      func.is_exported ?? 0,
      func.callees
    );
  }

  /**
   * Find all functions for a sample
   */
  findFunctions(sampleId: string): Function[] {
    const stmt = this.db.prepare('SELECT * FROM functions WHERE sample_id = ? ORDER BY address');
    return stmt.all(sampleId) as Function[];
  }

  /**
   * Find functions by sample with score ordering
   */
  findFunctionsByScore(sampleId: string, limit?: number): Function[] {
    let sql = 'SELECT * FROM functions WHERE sample_id = ? ORDER BY score DESC';
    if (limit !== undefined) {
      sql += ` LIMIT ${limit}`;
    }
    const stmt = this.db.prepare(sql);
    return stmt.all(sampleId) as Function[];
  }

  /**
   * Update a function
   */
  updateFunction(
    sampleId: string,
    address: string,
    updates: Partial<Omit<Function, 'sample_id' | 'address'>>
  ): void {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }
    if (updates.size !== undefined) {
      fields.push('size = ?');
      values.push(updates.size);
    }
    if (updates.score !== undefined) {
      fields.push('score = ?');
      values.push(updates.score);
    }
    if (updates.tags !== undefined) {
      fields.push('tags = ?');
      values.push(updates.tags);
    }
    if (updates.summary !== undefined) {
      fields.push('summary = ?');
      values.push(updates.summary);
    }

    if (fields.length === 0) {
      return; // No updates to perform
    }

    values.push(sampleId, address);
    const stmt = this.db.prepare(`
      UPDATE functions SET ${fields.join(', ')} WHERE sample_id = ? AND address = ?
    `);
    stmt.run(...values);
  }

  // ==================== Artifact Operations ====================

  /**
   * Insert a new artifact
   */
  insertArtifact(artifact: Artifact): void {
    const stmt = this.db.prepare(`
      INSERT INTO artifacts (id, sample_id, type, path, sha256, mime, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      artifact.id,
      artifact.sample_id,
      artifact.type,
      artifact.path,
      artifact.sha256,
      artifact.mime,
      artifact.created_at
    );
  }

  /**
   * Find all artifacts for a sample
   */
  findArtifacts(sampleId: string): Artifact[] {
    const stmt = this.db.prepare('SELECT * FROM artifacts WHERE sample_id = ? ORDER BY created_at DESC');
    return stmt.all(sampleId) as Artifact[];
  }

  /**
   * Find all artifacts across all samples
   */
  findAllArtifacts(): Artifact[] {
    const stmt = this.db.prepare('SELECT * FROM artifacts ORDER BY created_at DESC')
    return stmt.all() as Artifact[]
  }

  /**
   * Find artifact by ID
   */
  findArtifact(artifactId: string): Artifact | null {
    const stmt = this.db.prepare('SELECT * FROM artifacts WHERE id = ?')
    return stmt.get(artifactId) as Artifact | null
  }

  /**
   * Delete artifact by ID
   */
  deleteArtifact(artifactId: string): void {
    const stmt = this.db.prepare('DELETE FROM artifacts WHERE id = ?')
    stmt.run(artifactId)
  }

  /**
   * Find artifacts by sample and type
   */
  findArtifactsByType(sampleId: string, type: string): Artifact[] {
    const stmt = this.db.prepare('SELECT * FROM artifacts WHERE sample_id = ? AND type = ? ORDER BY created_at DESC');
    return stmt.all(sampleId, type) as Artifact[];
  }

  // ==================== Cache Operations ====================

  /**
   * Get cached result from database
   * Requirements: 20.5
   */
  async getCachedResult(key: string): Promise<{
    data: unknown
    createdAt?: string
    expiresAt?: string
    sampleSha256?: string
  } | null> {
    const stmt = this.db.prepare('SELECT data, created_at, expires_at, sample_sha256 FROM cache WHERE key = ?');
    const row = stmt.get(key) as {
      data: string
      created_at: string | null
      expires_at: string | null
      sample_sha256: string | null
    } | undefined;

    if (!row) {
      return null;
    }

    try {
      const data = JSON.parse(row.data);
      return {
        data,
        createdAt: row.created_at || undefined,
        expiresAt: row.expires_at || undefined,
        sampleSha256: row.sample_sha256 || undefined,
      };
    } catch (error) {
      // Invalid JSON, remove from cache
      this.db.prepare('DELETE FROM cache WHERE key = ?').run(key);
      return null;
    }
  }

  /**
   * Set cached result in database
   * Requirements: 20.5
   */
  async setCachedResult(key: string, data: unknown, expiresAt?: string, sampleSha256?: string): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO cache (key, data, sample_sha256, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      key,
      JSON.stringify(data),
      sampleSha256 || null,
      new Date().toISOString(),
      expiresAt || null
    );
  }

  /**
   * Delete expired cache entries
   */
  cleanExpiredCache(): number {
    const stmt = this.db.prepare('DELETE FROM cache WHERE expires_at IS NOT NULL AND expires_at < ?');
    const result = stmt.run(new Date().toISOString());
    return result.changes;
  }

  /**
   * Get recent cache entries for prewarming
   * Requirements: 26.1 (cache prewarming), 26.2 (query optimization)
   * 
   * @param limit - Maximum number of entries to return
   * @returns Array of cache entries ordered by creation time (most recent first)
   */
  async getRecentCacheEntries(limit: number): Promise<Array<{ key: string; data: string; expires_at: string | null }>> {
    const stmt = this.db.prepare(`
      SELECT key, data, expires_at 
      FROM cache 
      WHERE expires_at IS NULL OR expires_at > ?
      ORDER BY created_at DESC 
      LIMIT ?
    `);
    return stmt.all(new Date().toISOString(), limit) as Array<{ key: string; data: string; expires_at: string | null }>;
  }

  /**
   * Get cache entries for a specific sample
   * Requirements: 26.1 (cache prewarming), 26.2 (query optimization)
   * 
   * @param sampleSha256 - SHA256 hash of the sample
   * @returns Array of cache entries for the sample
   */
  async getCacheEntriesBySample(sampleSha256: string): Promise<Array<{ key: string; data: string; expires_at: string | null }>> {
    // Query cache entries by sample_sha256 column
    const stmt = this.db.prepare(`
      SELECT key, data, expires_at 
      FROM cache 
      WHERE sample_sha256 = ?
        AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY created_at DESC
    `);
    return stmt.all(sampleSha256, new Date().toISOString()) as Array<{ key: string; data: string; expires_at: string | null }>;
  }

  /**
   * Batch insert functions for better performance
   * Requirements: 26.2 (database query optimization)
   * 
   * @param functions - Array of functions to insert
   */
  insertFunctionsBatch(functions: Function[]): void {
    if (functions.length === 0) {
      return;
    }

    // Use transaction for batch insert
    const insertStmt = this.db.prepare(`
      INSERT OR REPLACE INTO functions (sample_id, address, name, size, score, tags, summary, caller_count, callee_count, is_entry_point, is_exported, callees)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertMany = this.db.transaction((funcs: Function[]) => {
      for (const func of funcs) {
        insertStmt.run(
          func.sample_id,
          func.address,
          func.name,
          func.size,
          func.score,
          func.tags,
          func.summary,
          func.caller_count ?? 0,
          func.callee_count ?? 0,
          func.is_entry_point ?? 0,
          func.is_exported ?? 0,
          func.callees
        );
      }
    });

    insertMany(functions);
  }

  /**
   * Batch insert artifacts for better performance
   * Requirements: 26.2 (database query optimization)
   * 
   * @param artifacts - Array of artifacts to insert
   */
  insertArtifactsBatch(artifacts: Artifact[]): void {
    if (artifacts.length === 0) {
      return;
    }

    // Use transaction for batch insert
    const insertStmt = this.db.prepare(`
      INSERT INTO artifacts (id, sample_id, type, path, sha256, mime, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const insertMany = this.db.transaction((arts: Artifact[]) => {
      for (const artifact of arts) {
        insertStmt.run(
          artifact.id,
          artifact.sample_id,
          artifact.type,
          artifact.path,
          artifact.sha256,
          artifact.mime,
          artifact.created_at
        );
      }
    });

    insertMany(artifacts);
  }

  /**
   * Optimize database by running VACUUM and ANALYZE
   * Requirements: 26.2 (database query optimization)
   * 
   * Should be run periodically to maintain performance
   */
  optimizeDatabase(): void {
    // ANALYZE updates statistics for query planner
    this.db.exec('ANALYZE');
    
    // VACUUM reclaims space and defragments
    // Note: VACUUM can be slow on large databases
    this.db.exec('VACUUM');
  }

  /**
   * Get database statistics for monitoring
   * Requirements: 26.2 (database query optimization)
   * 
   * @returns Object with database statistics
   */
  getDatabaseStats(): {
    sampleCount: number;
    analysisCount: number;
    functionCount: number;
    artifactCount: number;
    cacheCount: number;
    dbSizeBytes: number;
  } {
    const sampleCount = this.db.prepare('SELECT COUNT(*) as count FROM samples').get() as { count: number };
    const analysisCount = this.db.prepare('SELECT COUNT(*) as count FROM analyses').get() as { count: number };
    const functionCount = this.db.prepare('SELECT COUNT(*) as count FROM functions').get() as { count: number };
    const artifactCount = this.db.prepare('SELECT COUNT(*) as count FROM artifacts').get() as { count: number };
    const cacheCount = this.db.prepare('SELECT COUNT(*) as count FROM cache').get() as { count: number };
    
    // Get database file size
    const dbPath = (this.db as { name?: string }).name; // Access internal property
    let dbSizeBytes = 0;
    try {
      if (typeof dbPath === 'string' && dbPath.length > 0) {
        const stats = fs.statSync(dbPath);
        dbSizeBytes = stats.size;
      }
    } catch {
      // Ignore errors
    }

    return {
      sampleCount: sampleCount.count,
      analysisCount: analysisCount.count,
      functionCount: functionCount.count,
      artifactCount: artifactCount.count,
      cacheCount: cacheCount.count,
      dbSizeBytes
    };
  }

  // Batch submission methods

  createBatch(batch: Batch): void {
    const stmt = this.db.prepare(`
      INSERT INTO batches (id, status, total_samples, completed_samples, failed_samples, cancelled_samples, metadata_json, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      batch.id,
      batch.status,
      batch.total_samples,
      batch.completed_samples,
      batch.failed_samples,
      batch.cancelled_samples,
      batch.metadata_json,
      batch.created_at,
      batch.updated_at
    )
  }

  findBatch(batchId: string): Batch | null {
    const stmt = this.db.prepare('SELECT * FROM batches WHERE id = ?')
    return stmt.get(batchId) as Batch | null
  }

  updateBatch(batchId: string, batch: Batch): void {
    const stmt = this.db.prepare(`
      UPDATE batches
      SET status = ?, total_samples = ?, completed_samples = ?, failed_samples = ?, cancelled_samples = ?, metadata_json = ?, updated_at = ?
      WHERE id = ?
    `)
    stmt.run(
      batch.status,
      batch.total_samples,
      batch.completed_samples,
      batch.failed_samples,
      batch.cancelled_samples,
      batch.metadata_json,
      batch.updated_at,
      batchId
    )
  }

  deleteBatch(batchId: string): void {
    const stmt = this.db.prepare('DELETE FROM batches WHERE id = ?')
    stmt.run(batchId)
  }

  findBatches(options?: { status?: string; limit?: number; offset?: number }): Batch[] {
    let sql = 'SELECT * FROM batches'
    const params: any[] = []

    if (options?.status) {
      sql += ' WHERE status = ?'
      params.push(options.status)
    }

    sql += ' ORDER BY created_at DESC'

    if (options?.limit) {
      sql += ' LIMIT ?'
      params.push(options.limit)
    }

    if (options?.offset) {
      sql += ' OFFSET ?'
      params.push(options.offset)
    }

    const stmt = this.db.prepare(sql)
    return stmt.all(...params) as Batch[]
  }

  createBatchSample(batchSample: BatchSample): void {
    const stmt = this.db.prepare(`
      INSERT INTO batch_samples (batch_id, sample_id, status, filename, size, sha256, artifact_refs_json, error, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      batchSample.batch_id,
      batchSample.sample_id,
      batchSample.status,
      batchSample.filename,
      batchSample.size,
      batchSample.sha256,
      batchSample.artifact_refs_json,
      batchSample.error,
      batchSample.created_at,
      batchSample.updated_at
    )
  }

  findBatchSamples(batchId: string): BatchSample[] {
    const stmt = this.db.prepare('SELECT * FROM batch_samples WHERE batch_id = ?')
    return stmt.all(batchId) as BatchSample[]
  }

  findBatchSample(batchId: string, sampleId: string): BatchSample | null {
    const stmt = this.db.prepare('SELECT * FROM batch_samples WHERE batch_id = ? AND sample_id = ?')
    return stmt.get(batchId, sampleId) as BatchSample | null
  }

  updateBatchSampleStatus(batchId: string, sampleId: string, status: string): void {
    const stmt = this.db.prepare(`
      UPDATE batch_samples
      SET status = ?, updated_at = ?
      WHERE batch_id = ? AND sample_id = ?
    `)
    stmt.run(status, new Date().toISOString(), batchId, sampleId)
  }

  // ============================================================================
  // Job Methods (for async job pattern)
  // Tasks: mcp-async-job-pattern 1.3
  // ============================================================================

  createJob(job: {
    id: string
    type: string
    tool: string
    sampleId: string
    args: Record<string, unknown>
    priority: number
    timeout: number
    estimatedDurationMs?: number
  }): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO jobs (
        id, type, tool, sample_id, args_json, priority, timeout,
        estimated_duration_ms, status, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)
    `)
    const now = new Date().toISOString()
    stmt.run(
      job.id,
      job.type,
      job.tool,
      job.sampleId,
      JSON.stringify(job.args),
      job.priority,
      job.timeout,
      job.estimatedDurationMs,
      now,
      now
    )
  }

  findJob(jobId: string): any | null {
    const stmt = this.db.prepare('SELECT * FROM jobs WHERE id = ?')
    const row = stmt.get(jobId) as any
    if (!row) return null

    return {
      ...row,
      args: JSON.parse(row.args_json),
      result: row.result_json ? JSON.parse(row.result_json) : null,
    }
  }

  updateJobStatus(jobId: string, status: string, progress?: number, error?: string): void {
    const updates: string[] = ['status = ?']
    const params: any[] = [status]

    if (progress !== undefined) {
      updates.push('progress = ?')
      params.push(progress)
    }

    if (error !== undefined) {
      updates.push('error = ?')
      params.push(error)
    }

    if (status === 'running' && progress === 0) {
      updates.push('started_at = ?')
      params.push(new Date().toISOString())
    }

    if (['completed', 'failed', 'cancelled'].includes(status)) {
      updates.push('finished_at = ?')
      params.push(new Date().toISOString())
    }

    updates.push('updated_at = ?')
    params.push(new Date().toISOString())

    params.push(jobId)

    const stmt = this.db.prepare(`
      UPDATE jobs SET ${updates.join(', ')} WHERE id = ?
    `)
    stmt.run(...params)
  }

  setJobResult(jobId: string, result: any): void {
    const stmt = this.db.prepare(`
      UPDATE jobs
      SET result_json = ?, status = 'completed', finished_at = ?, updated_at = ?
      WHERE id = ?
    `)
    const now = new Date().toISOString()
    stmt.run(JSON.stringify(result), now, now, jobId)
  }

  findJobsByStatus(status: string, limit: number = 100): any[] {
    const stmt = this.db.prepare('SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?')
    return stmt.all(status, limit) as any[]
  }

  findJobsByStatuses(statuses: string[], limit: number = 200): any[] {
    if (statuses.length === 0) {
      return []
    }
    const placeholders = statuses.map(() => '?').join(', ')
    const stmt = this.db.prepare(
      `SELECT * FROM jobs WHERE status IN (${placeholders}) ORDER BY created_at DESC LIMIT ?`
    )
    return stmt.all(...statuses, limit) as any[]
  }

  markJobInterrupted(jobId: string, reason: string, result?: unknown): void {
    const updates: string[] = ['status = ?', 'error = ?', 'finished_at = ?', 'updated_at = ?']
    const now = new Date().toISOString()
    const params: any[] = ['interrupted', reason, now, now]
    if (result !== undefined) {
      updates.unshift('result_json = ?')
      params.unshift(JSON.stringify(result))
    }
    params.push(jobId)
    const stmt = this.db.prepare(`
      UPDATE jobs SET ${updates.join(', ')} WHERE id = ?
    `)
    stmt.run(...params)
  }

  findJobsBySample(sampleId: string, limit: number = 50): any[] {
    const stmt = this.db.prepare('SELECT * FROM jobs WHERE sample_id = ? ORDER BY created_at DESC LIMIT ?')
    return stmt.all(sampleId, limit) as any[]
  }

  cleanupOldJobs(retentionHours: number = 24): number {
    const cutoff = new Date(Date.now() - retentionHours * 60 * 60 * 1000).toISOString()
    const stmt = this.db.prepare('DELETE FROM jobs WHERE created_at < ? AND status IN (\'completed\', \'failed\', \'cancelled\')')
    const result = stmt.run(cutoff)
    return result.changes
  }

  // ============================================================================
  // Runtime worker family state
  // ============================================================================

  upsertRuntimeWorkerFamilyState(state: RuntimeWorkerFamilyState): void {
    const stmt = this.db.prepare(`
      INSERT INTO runtime_worker_family_state (
        family, compatibility_key, deployment_key, pool_kind,
        live_workers, idle_workers, busy_workers, unhealthy_workers,
        warm_reuse_count, cold_start_count, eviction_count,
        last_error, metadata_json, created_at, updated_at, last_used_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(family, compatibility_key) DO UPDATE SET
        deployment_key = excluded.deployment_key,
        pool_kind = excluded.pool_kind,
        live_workers = excluded.live_workers,
        idle_workers = excluded.idle_workers,
        busy_workers = excluded.busy_workers,
        unhealthy_workers = excluded.unhealthy_workers,
        warm_reuse_count = excluded.warm_reuse_count,
        cold_start_count = excluded.cold_start_count,
        eviction_count = excluded.eviction_count,
        last_error = excluded.last_error,
        metadata_json = excluded.metadata_json,
        updated_at = excluded.updated_at,
        last_used_at = excluded.last_used_at
    `)
    stmt.run(
      state.family,
      state.compatibility_key,
      state.deployment_key,
      state.pool_kind,
      state.live_workers,
      state.idle_workers,
      state.busy_workers,
      state.unhealthy_workers,
      state.warm_reuse_count,
      state.cold_start_count,
      state.eviction_count,
      state.last_error,
      state.metadata_json,
      state.created_at,
      state.updated_at,
      state.last_used_at
    )
  }

  findRuntimeWorkerFamilyStates(family?: string): RuntimeWorkerFamilyState[] {
    const sql = family
      ? 'SELECT * FROM runtime_worker_family_state WHERE family = ? ORDER BY datetime(updated_at) DESC'
      : 'SELECT * FROM runtime_worker_family_state ORDER BY datetime(updated_at) DESC'
    const stmt = this.db.prepare(sql)
    return (family ? stmt.all(family) : stmt.all()) as RuntimeWorkerFamilyState[]
  }

  // ============================================================================
  // Scheduler telemetry
  // ============================================================================

  insertSchedulerEvent(event: SchedulerEvent): void {
    const stmt = this.db.prepare(`
      INSERT INTO scheduler_events (
        id, job_id, run_id, sample_id, tool, stage,
        execution_bucket, cost_class, decision, reason,
        worker_family, warm_reuse, cold_start, metadata_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      event.id,
      event.job_id,
      event.run_id,
      event.sample_id,
      event.tool,
      event.stage,
      event.execution_bucket,
      event.cost_class,
      event.decision,
      event.reason,
      event.worker_family,
      event.warm_reuse,
      event.cold_start,
      event.metadata_json,
      event.created_at
    )
  }

  findLatestSchedulerEventForJob(jobId: string): SchedulerEvent | null {
    const stmt = this.db.prepare(
      'SELECT * FROM scheduler_events WHERE job_id = ? ORDER BY datetime(created_at) DESC LIMIT 1'
    )
    return stmt.get(jobId) as SchedulerEvent | null
  }

  findLatestSchedulerEventForRun(runId: string): SchedulerEvent | null {
    const stmt = this.db.prepare(
      'SELECT * FROM scheduler_events WHERE run_id = ? ORDER BY datetime(created_at) DESC LIMIT 1'
    )
    return stmt.get(runId) as SchedulerEvent | null
  }
}

/**
 * Create and initialize a database instance
 */
export function createDatabase(dbPath: string): DatabaseManager {
  return new DatabaseManager(dbPath);
}
