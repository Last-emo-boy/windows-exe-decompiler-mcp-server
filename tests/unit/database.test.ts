/**
 * Unit tests for database module
 */

import { DatabaseManager, createDatabase, Function } from '../../src/database';
import fs from 'fs';
import path from 'path';
import os from 'os';

// Helper function to create a complete Function object for testing
function createTestFunction(partial: Partial<Function> & { sample_id: string; address: string }): Function {
  return {
    sample_id: partial.sample_id,
    address: partial.address,
    name: partial.name ?? null,
    size: partial.size ?? null,
    score: partial.score ?? null,
    tags: partial.tags ?? null,
    summary: partial.summary ?? null,
    caller_count: partial.caller_count ?? null,
    callee_count: partial.callee_count ?? null,
    is_entry_point: partial.is_entry_point ?? null,
    is_exported: partial.is_exported ?? null,
    callees: partial.callees ?? null,
  };
}

describe('DatabaseManager', () => {
  let dbPath: string;
  let dbManager: DatabaseManager;

  beforeEach(() => {
    // Create a temporary database file for testing
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-test-'));
    dbPath = path.join(tmpDir, 'test.db');
    dbManager = createDatabase(dbPath);
  });

  afterEach(() => {
    // Clean up
    dbManager.close();
    const dbDir = path.dirname(dbPath);
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
    if (fs.existsSync(dbDir)) {
      fs.rmdirSync(dbDir);
    }
  });

  describe('Schema Creation', () => {
    it('should create samples table with correct schema', () => {
      const db = dbManager.getDatabase();
      const tableInfo = db.pragma('table_info(samples)') as any[];

      expect(tableInfo).toHaveLength(7);
      expect(tableInfo.map((col: any) => col.name)).toEqual([
        'id',
        'sha256',
        'md5',
        'size',
        'file_type',
        'created_at',
        'source',
      ]);
    });

    it('should create analyses table with correct schema', () => {
      const db = dbManager.getDatabase();
      const tableInfo = db.pragma('table_info(analyses)') as any[];

      expect(tableInfo).toHaveLength(9);
      expect(tableInfo.map((col: any) => col.name)).toEqual([
        'id',
        'sample_id',
        'stage',
        'backend',
        'status',
        'started_at',
        'finished_at',
        'output_json',
        'metrics_json',
      ]);
    });

    it('should create functions table with correct schema', () => {
      const db = dbManager.getDatabase();
      const tableInfo = db.pragma('table_info(functions)') as any[];

      expect(tableInfo).toHaveLength(12);
      expect(tableInfo.map((col: any) => col.name)).toEqual([
        'sample_id',
        'address',
        'name',
        'size',
        'score',
        'tags',
        'summary',
        'caller_count',
        'callee_count',
        'is_entry_point',
        'is_exported',
        'callees',
      ]);
    });

    it('should create artifacts table with correct schema', () => {
      const db = dbManager.getDatabase();
      const tableInfo = db.pragma('table_info(artifacts)') as any[];

      expect(tableInfo).toHaveLength(7);
      expect(tableInfo.map((col: any) => col.name)).toEqual([
        'id',
        'sample_id',
        'type',
        'path',
        'sha256',
        'mime',
        'created_at',
      ]);
    });

    it('should create upload_sessions table with correct schema', () => {
      const db = dbManager.getDatabase();
      const tableInfo = db.pragma('table_info(upload_sessions)') as any[];

      expect(tableInfo).toHaveLength(15);
      expect(tableInfo.map((col: any) => col.name)).toEqual([
        'id',
        'token',
        'status',
        'filename',
        'source',
        'created_at',
        'expires_at',
        'uploaded_at',
        'staged_path',
        'size',
        'sha256',
        'md5',
        'sample_id',
        'error',
        'metadata_json',
      ]);
    });

    it('should create indexes for samples table', () => {
      const db = dbManager.getDatabase();
      const indexes = db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='samples'")
        .all();

      const indexNames = indexes.map((idx: any) => idx.name);
      expect(indexNames).toContain('idx_samples_sha256');
      expect(indexNames).toContain('idx_samples_created_at');
    });

    it('should create indexes for analyses table', () => {
      const db = dbManager.getDatabase();
      const indexes = db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='analyses'")
        .all();

      const indexNames = indexes.map((idx: any) => idx.name);
      expect(indexNames).toContain('idx_analyses_sample_stage');
      expect(indexNames).toContain('idx_analyses_status');
    });

    it('should create indexes for functions table', () => {
      const db = dbManager.getDatabase();
      const indexes = db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='functions'")
        .all();

      const indexNames = indexes.map((idx: any) => idx.name);
      expect(indexNames).toContain('idx_functions_name');
      expect(indexNames).toContain('idx_functions_score');
    });

    it('should create indexes for artifacts table', () => {
      const db = dbManager.getDatabase();
      const indexes = db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='artifacts'")
        .all();

      const indexNames = indexes.map((idx: any) => idx.name);
      expect(indexNames).toContain('idx_artifacts_sample_type');
    });

    it('should create indexes for upload_sessions table', () => {
      const db = dbManager.getDatabase();
      const indexes = db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='upload_sessions'")
        .all();

      const indexNames = indexes.map((idx: any) => idx.name);
      expect(indexNames).toContain('idx_upload_sessions_token');
      expect(indexNames).toContain('idx_upload_sessions_status');
      expect(indexNames).toContain('idx_upload_sessions_expires_at');
    });

    it('should enable foreign keys', () => {
      const db = dbManager.getDatabase();
      const result = db.pragma('foreign_keys') as any[];
      expect(result[0].foreign_keys).toBe(1);
    });
  });

  describe('Foreign Key Constraints', () => {
    it('should enforce foreign key constraint on analyses.sample_id', () => {
      const db = dbManager.getDatabase();

      // Try to insert analysis without corresponding sample
      expect(() => {
        db.prepare(
          `INSERT INTO analyses (id, sample_id, stage, backend, status) 
           VALUES (?, ?, ?, ?, ?)`
        ).run('analysis-1', 'sha256:nonexistent', 'test', 'test', 'queued');
      }).toThrow();
    });

    it('should enforce foreign key constraint on functions.sample_id', () => {
      const db = dbManager.getDatabase();

      // Try to insert function without corresponding sample
      expect(() => {
        db.prepare(
          `INSERT INTO functions (sample_id, address) 
           VALUES (?, ?)`
        ).run('sha256:nonexistent', '0x1000');
      }).toThrow();
    });

    it('should enforce foreign key constraint on artifacts.sample_id', () => {
      const db = dbManager.getDatabase();

      // Try to insert artifact without corresponding sample
      expect(() => {
        db.prepare(
          `INSERT INTO artifacts (id, sample_id, type, path, sha256, created_at) 
           VALUES (?, ?, ?, ?, ?, ?)`
        ).run('artifact-1', 'sha256:nonexistent', 'test', '/test', 'abc123', '2024-01-01');
      }).toThrow();
    });
  });

  describe('Unique Constraints', () => {
    it('should enforce unique constraint on samples.sha256', () => {
      const db = dbManager.getDatabase();

      // Insert first sample
      db.prepare(
        `INSERT INTO samples (id, sha256, size, created_at) 
         VALUES (?, ?, ?, ?)`
      ).run('sha256:abc123', 'abc123', 1000, '2024-01-01T00:00:00Z');

      // Try to insert duplicate sha256
      expect(() => {
        db.prepare(
          `INSERT INTO samples (id, sha256, size, created_at) 
           VALUES (?, ?, ?, ?)`
        ).run('sha256:abc123-2', 'abc123', 2000, '2024-01-02T00:00:00Z');
      }).toThrow();
    });

    it('should enforce primary key constraint on samples.id', () => {
      const db = dbManager.getDatabase();

      // Insert first sample
      db.prepare(
        `INSERT INTO samples (id, sha256, size, created_at) 
         VALUES (?, ?, ?, ?)`
      ).run('sha256:abc123', 'abc123', 1000, '2024-01-01T00:00:00Z');

      // Try to insert duplicate id
      expect(() => {
        db.prepare(
          `INSERT INTO samples (id, sha256, size, created_at) 
           VALUES (?, ?, ?, ?)`
        ).run('sha256:abc123', 'def456', 2000, '2024-01-02T00:00:00Z');
      }).toThrow();
    });

    it('should enforce composite primary key on functions', () => {
      const db = dbManager.getDatabase();

      // Insert sample first
      db.prepare(
        `INSERT INTO samples (id, sha256, size, created_at) 
         VALUES (?, ?, ?, ?)`
      ).run('sha256:abc123', 'abc123', 1000, '2024-01-01T00:00:00Z');

      // Insert first function
      db.prepare(
        `INSERT INTO functions (sample_id, address, name) 
         VALUES (?, ?, ?)`
      ).run('sha256:abc123', '0x1000', 'main');

      // Try to insert duplicate (sample_id, address)
      expect(() => {
        db.prepare(
          `INSERT INTO functions (sample_id, address, name) 
           VALUES (?, ?, ?)`
        ).run('sha256:abc123', '0x1000', 'duplicate');
      }).toThrow();
    });
  });

  describe('Transaction Support', () => {
    it('should support transactions', () => {
      const result = dbManager.transaction(() => {
        const db = dbManager.getDatabase();
        db.prepare(
          `INSERT INTO samples (id, sha256, size, created_at) 
           VALUES (?, ?, ?, ?)`
        ).run('sha256:abc123', 'abc123', 1000, '2024-01-01T00:00:00Z');

        const sample = db.prepare('SELECT * FROM samples WHERE id = ?').get('sha256:abc123');
        return sample;
      });

      expect(result).toBeDefined();
      expect((result as any).sha256).toBe('abc123');
    });

    it('should rollback transaction on error', () => {
      const db = dbManager.getDatabase();

      try {
        dbManager.transaction(() => {
          db.prepare(
            `INSERT INTO samples (id, sha256, size, created_at) 
             VALUES (?, ?, ?, ?)`
          ).run('sha256:abc123', 'abc123', 1000, '2024-01-01T00:00:00Z');

          // This should fail and rollback the transaction
          throw new Error('Test error');
        });
      } catch (error) {
        // Expected error
      }

      // Verify sample was not inserted
      const sample = db.prepare('SELECT * FROM samples WHERE id = ?').get('sha256:abc123');
      expect(sample).toBeUndefined();
    });
  });

  describe('Sample Operations', () => {
    it('should insert a sample', () => {
      dbManager.insertSample({
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1000,
        file_type: 'PE32',
        created_at: '2024-01-01T00:00:00Z',
        source: 'upload',
      });

      const sample = dbManager.findSample('sha256:abc123');
      expect(sample).toBeDefined();
      expect(sample?.sha256).toBe('abc123');
      expect(sample?.md5).toBe('def456');
      expect(sample?.size).toBe(1000);
      expect(sample?.file_type).toBe('PE32');
      expect(sample?.source).toBe('upload');
    });

    it('should find sample by SHA256', () => {
      dbManager.insertSample({
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: null,
        size: 1000,
        file_type: null,
        created_at: '2024-01-01T00:00:00Z',
        source: null,
      });

      const sample = dbManager.findSampleBySha256('abc123');
      expect(sample).toBeDefined();
      expect(sample?.id).toBe('sha256:abc123');
    });

    it('should return undefined for non-existent sample', () => {
      const sample = dbManager.findSample('sha256:nonexistent');
      expect(sample).toBeUndefined();
    });
  });

  describe('Upload Session Operations', () => {
    it('should create and fetch an upload session', () => {
      const session = dbManager.createUploadSession({
        filename: 'sample.exe',
        source: 'mcp_upload',
        expires_at: '2099-01-01T00:00:00.000Z',
      });

      const fetched = dbManager.findUploadSessionByToken(session.token);
      expect(fetched).toBeDefined();
      expect(fetched?.status).toBe('pending');
      expect(fetched?.filename).toBe('sample.exe');
      expect(fetched?.source).toBe('mcp_upload');
    });

    it('should update and finalize upload session lifecycle state', () => {
      const session = dbManager.createUploadSession({
        filename: 'sample.dll',
        source: 'mcp_upload',
        expires_at: '2099-01-01T00:00:00.000Z',
      });

      dbManager.insertSample({
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 123,
        file_type: 'PE32',
        created_at: '2024-01-01T00:00:00Z',
        source: 'mcp_upload',
      });

      dbManager.markUploadSessionUploaded(session.token, {
        staged_path: '/app/storage/uploads/session_sample.dll',
        size: 123,
        filename: 'sample.dll',
      });
      dbManager.markUploadSessionRegistered(session.token, {
        sample_id: 'sha256:abc123',
        size: 123,
        sha256: 'abc123',
        md5: 'def456',
        clearStagedPath: true,
      });

      const fetched = dbManager.findUploadSessionByToken(session.token);
      expect(fetched?.status).toBe('registered');
      expect(fetched?.sample_id).toBe('sha256:abc123');
      expect(fetched?.staged_path).toBeNull();
      expect(fetched?.sha256).toBe('abc123');
      expect(fetched?.md5).toBe('def456');
    });

    it('should expire pending sessions past expiration time', () => {
      const session = dbManager.createUploadSession({
        filename: 'old.bin',
        source: 'mcp_upload',
        expires_at: '2000-01-01T00:00:00.000Z',
      });

      const changes = dbManager.expireUploadSessions('2026-01-01T00:00:00.000Z');
      const fetched = dbManager.findUploadSessionByToken(session.token);

      expect(changes).toBeGreaterThan(0);
      expect(fetched?.status).toBe('expired');
      expect(fetched?.error).toContain('expired');
    });
  });

  describe('Analysis Operations', () => {
    beforeEach(() => {
      // Insert a sample for foreign key constraint
      dbManager.insertSample({
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: null,
        size: 1000,
        file_type: null,
        created_at: '2024-01-01T00:00:00Z',
        source: null,
      });
    });

    it('should insert an analysis', () => {
      dbManager.insertAnalysis({
        id: 'analysis-1',
        sample_id: 'sha256:abc123',
        stage: 'fingerprint',
        backend: 'static',
        status: 'queued',
        started_at: null,
        finished_at: null,
        output_json: null,
        metrics_json: null,
      });

      const analysis = dbManager.findAnalysis('analysis-1');
      expect(analysis).toBeDefined();
      expect(analysis?.sample_id).toBe('sha256:abc123');
      expect(analysis?.stage).toBe('fingerprint');
      expect(analysis?.status).toBe('queued');
    });

    it('should update an analysis', () => {
      dbManager.insertAnalysis({
        id: 'analysis-1',
        sample_id: 'sha256:abc123',
        stage: 'fingerprint',
        backend: 'static',
        status: 'queued',
        started_at: null,
        finished_at: null,
        output_json: null,
        metrics_json: null,
      });

      dbManager.updateAnalysis('analysis-1', {
        status: 'running',
        started_at: '2024-01-01T00:00:00Z',
      });

      const analysis = dbManager.findAnalysis('analysis-1');
      expect(analysis?.status).toBe('running');
      expect(analysis?.started_at).toBe('2024-01-01T00:00:00Z');
    });

    it('should find analyses by sample', () => {
      dbManager.insertAnalysis({
        id: 'analysis-1',
        sample_id: 'sha256:abc123',
        stage: 'fingerprint',
        backend: 'static',
        status: 'done',
        started_at: '2024-01-01T00:00:00Z',
        finished_at: '2024-01-01T00:01:00Z',
        output_json: null,
        metrics_json: null,
      });

      dbManager.insertAnalysis({
        id: 'analysis-2',
        sample_id: 'sha256:abc123',
        stage: 'ghidra',
        backend: 'ghidra',
        status: 'running',
        started_at: '2024-01-01T00:02:00Z',
        finished_at: null,
        output_json: null,
        metrics_json: null,
      });

      const analyses = dbManager.findAnalysesBySample('sha256:abc123');
      expect(analyses).toHaveLength(2);
      expect(analyses[0].id).toBe('analysis-2'); // Most recent first
      expect(analyses[1].id).toBe('analysis-1');
    });
  });

  describe('Function Operations', () => {
    beforeEach(() => {
      // Insert a sample for foreign key constraint
      dbManager.insertSample({
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: null,
        size: 1000,
        file_type: null,
        created_at: '2024-01-01T00:00:00Z',
        source: null,
      });
    });

    it('should insert a function', () => {
      dbManager.insertFunction(createTestFunction({
        sample_id: 'sha256:abc123',
        address: '0x1000',
        name: 'main',
        size: 256,
        score: 10.5,
        tags: '["entry"]',
        summary: 'Entry point function',
        is_entry_point: 1,
      }));

      const functions = dbManager.findFunctions('sha256:abc123');
      expect(functions).toHaveLength(1);
      expect(functions[0].address).toBe('0x1000');
      expect(functions[0].name).toBe('main');
      expect(functions[0].score).toBe(10.5);
    });

    it('should update a function', () => {
      dbManager.insertFunction(createTestFunction({
        sample_id: 'sha256:abc123',
        address: '0x1000',
        name: 'main',
        size: 256,
      }));

      dbManager.updateFunction('sha256:abc123', '0x1000', {
        score: 25.0,
        tags: '["entry", "high_score"]',
        summary: 'Updated summary',
      });

      const functions = dbManager.findFunctions('sha256:abc123');
      expect(functions[0].score).toBe(25.0);
      expect(functions[0].tags).toBe('["entry", "high_score"]');
      expect(functions[0].summary).toBe('Updated summary');
    });

    it('should find functions by score', () => {
      dbManager.insertFunction(createTestFunction({
        sample_id: 'sha256:abc123',
        address: '0x1000',
        name: 'func1',
        size: 100,
        score: 10.0,
      }));

      dbManager.insertFunction(createTestFunction({
        sample_id: 'sha256:abc123',
        address: '0x2000',
        name: 'func2',
        size: 200,
        score: 25.0,
      }));

      dbManager.insertFunction(createTestFunction({
        sample_id: 'sha256:abc123',
        address: '0x3000',
        name: 'func3',
        size: 150,
        score: 15.0,
      }));

      const functions = dbManager.findFunctionsByScore('sha256:abc123', 2);
      expect(functions).toHaveLength(2);
      expect(functions[0].address).toBe('0x2000'); // Highest score
      expect(functions[1].address).toBe('0x3000'); // Second highest
    });
  });

  describe('Artifact Operations', () => {
    beforeEach(() => {
      // Insert a sample for foreign key constraint
      dbManager.insertSample({
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: null,
        size: 1000,
        file_type: null,
        created_at: '2024-01-01T00:00:00Z',
        source: null,
      });
    });

    it('should insert an artifact', () => {
      dbManager.insertArtifact({
        id: 'artifact-1',
        sample_id: 'sha256:abc123',
        type: 'strings',
        path: 'cache/strings.json',
        sha256: 'def456',
        mime: 'application/json',
        created_at: '2024-01-01T00:00:00Z',
      });

      const artifacts = dbManager.findArtifacts('sha256:abc123');
      expect(artifacts).toHaveLength(1);
      expect(artifacts[0].type).toBe('strings');
      expect(artifacts[0].path).toBe('cache/strings.json');
    });

    it('should find artifacts by type', () => {
      dbManager.insertArtifact({
        id: 'artifact-1',
        sample_id: 'sha256:abc123',
        type: 'strings',
        path: 'cache/strings.json',
        sha256: 'def456',
        mime: 'application/json',
        created_at: '2024-01-01T00:00:00Z',
      });

      dbManager.insertArtifact({
        id: 'artifact-2',
        sample_id: 'sha256:abc123',
        type: 'report',
        path: 'reports/triage.md',
        sha256: 'ghi789',
        mime: 'text/markdown',
        created_at: '2024-01-01T00:01:00Z',
      });

      const stringArtifacts = dbManager.findArtifactsByType('sha256:abc123', 'strings');
      expect(stringArtifacts).toHaveLength(1);
      expect(stringArtifacts[0].type).toBe('strings');

      const reportArtifacts = dbManager.findArtifactsByType('sha256:abc123', 'report');
      expect(reportArtifacts).toHaveLength(1);
      expect(reportArtifacts[0].type).toBe('report');
    });

    it('should order artifacts by created_at descending', () => {
      dbManager.insertArtifact({
        id: 'artifact-1',
        sample_id: 'sha256:abc123',
        type: 'strings',
        path: 'cache/strings.json',
        sha256: 'def456',
        mime: 'application/json',
        created_at: '2024-01-01T00:00:00Z',
      });

      dbManager.insertArtifact({
        id: 'artifact-2',
        sample_id: 'sha256:abc123',
        type: 'report',
        path: 'reports/triage.md',
        sha256: 'ghi789',
        mime: 'text/markdown',
        created_at: '2024-01-01T00:02:00Z',
      });

      const artifacts = dbManager.findArtifacts('sha256:abc123');
      expect(artifacts).toHaveLength(2);
      expect(artifacts[0].id).toBe('artifact-2'); // Most recent first
      expect(artifacts[1].id).toBe('artifact-1');
    });
  });
});
