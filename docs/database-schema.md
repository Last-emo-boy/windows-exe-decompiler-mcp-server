# Database Schema Documentation

## Overview

This document describes the SQLite database schema for the Rikune.

## Schema Implementation

The database schema has been implemented in `src/database.ts` with the following components:

### Tables

#### 1. samples
Stores basic information about binary samples.

```sql
CREATE TABLE IF NOT EXISTS samples (
  id TEXT PRIMARY KEY,              -- Format: sha256:<hex>
  sha256 TEXT UNIQUE NOT NULL,      -- SHA256 hash of the sample
  md5 TEXT,                         -- MD5 hash of the sample
  size INTEGER NOT NULL,            -- File size in bytes
  file_type TEXT,                   -- Detected file type
  created_at TEXT NOT NULL,         -- ISO 8601 timestamp
  source TEXT                       -- Source of the sample (e.g., "upload")
);
```

**Indexes:**
- `idx_samples_sha256` - For fast SHA256 lookups
- `idx_samples_created_at` - For time-based queries

#### 2. analyses
Stores analysis task records and results.

```sql
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,              -- UUID
  sample_id TEXT NOT NULL,          -- FK -> samples.id
  stage TEXT NOT NULL,              -- Analysis stage (fingerprint/strings/ghidra/dotnet/sandbox)
  backend TEXT NOT NULL,            -- Backend used (static/ghidra/dotnet/...)
  status TEXT NOT NULL,             -- Status (queued/running/done/failed)
  started_at TEXT,                  -- ISO 8601 timestamp
  finished_at TEXT,                 -- ISO 8601 timestamp
  output_json TEXT,                 -- Structured analysis results (JSON)
  metrics_json TEXT,                -- Performance metrics (JSON)
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);
```

**Indexes:**
- `idx_analyses_sample_stage` - For querying analyses by sample and stage
- `idx_analyses_status` - For filtering by status

#### 3. functions
Stores function information extracted from binaries.

```sql
CREATE TABLE IF NOT EXISTS functions (
  sample_id TEXT NOT NULL,          -- FK -> samples.id
  address TEXT NOT NULL,            -- Function address (e.g., "0x1000")
  name TEXT,                        -- Function name
  size INTEGER,                     -- Function size in bytes
  score REAL,                       -- Interest score for ranking
  tags TEXT,                        -- JSON array of tags
  summary TEXT,                     -- Function summary
  PRIMARY KEY (sample_id, address),
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);
```

**Indexes:**
- `idx_functions_name` - For searching functions by name
- `idx_functions_score` - For ranking functions by interest score (DESC)

#### 4. artifacts
Stores analysis artifacts (reports, decompiled code, etc.).

```sql
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,              -- UUID
  sample_id TEXT NOT NULL,          -- FK -> samples.id
  type TEXT NOT NULL,               -- Artifact type (strings/json/report/resource_dump/cfg)
  path TEXT NOT NULL,               -- Relative path in workspace
  sha256 TEXT NOT NULL,             -- SHA256 hash of artifact
  mime TEXT,                        -- MIME type
  created_at TEXT NOT NULL,         -- ISO 8601 timestamp
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);
```

**Indexes:**
- `idx_artifacts_sample_type` - For querying artifacts by sample and type

## TypeScript Interfaces

The schema is accompanied by TypeScript interfaces for type safety:

```typescript
export interface Sample {
  id: string;
  sha256: string;
  md5: string | null;
  size: number;
  file_type: string | null;
  created_at: string;
  source: string | null;
}

export interface Analysis {
  id: string;
  sample_id: string;
  stage: string;
  backend: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  output_json: string | null;
  metrics_json: string | null;
}

export interface Function {
  sample_id: string;
  address: string;
  name: string | null;
  size: number | null;
  score: number | null;
  tags: string | null;
  summary: string | null;
}

export interface Artifact {
  id: string;
  sample_id: string;
  type: string;
  path: string;
  sha256: string;
  mime: string | null;
  created_at: string;
}
```

## DatabaseManager Class

The `DatabaseManager` class provides:

- **Schema initialization**: Automatically creates tables and indexes
- **Foreign key enforcement**: Ensures referential integrity
- **Transaction support**: Atomic operations with rollback capability
- **Connection management**: Proper resource cleanup

### Usage Example

```typescript
import { createDatabase } from './database';

// Create database instance
const dbManager = createDatabase('./data/analysis.db');

// Get database instance for queries
const db = dbManager.getDatabase();

// Use transactions
dbManager.transaction(() => {
  db.prepare('INSERT INTO samples ...').run(...);
  db.prepare('INSERT INTO analyses ...').run(...);
});

// Close when done
dbManager.close();
```

## Features

1. **Foreign Key Constraints**: Ensures data integrity across related tables
2. **Unique Constraints**: Prevents duplicate samples (by SHA256)
3. **Composite Primary Keys**: Functions table uses (sample_id, address)
4. **Optimized Indexes**: Fast lookups for common query patterns
5. **Transaction Support**: Atomic operations with automatic rollback on errors

## Requirements Mapping

This schema implementation satisfies the following requirements from the design document:

- **Data Model**: All four core tables (samples, analyses, functions, artifacts)
- **Indexes**: Performance indexes on SHA256, sample_id, status, and score
- **Foreign Keys**: Referential integrity between tables
- **Type Safety**: TypeScript interfaces for all table structures

## Testing

Comprehensive unit tests are provided in `tests/unit/database.test.ts` covering:

- Schema creation verification
- Index creation verification
- Foreign key constraint enforcement
- Unique constraint enforcement
- Transaction support
- Rollback behavior

## Notes

- The database uses SQLite initially, with support for PostgreSQL migration planned
- All timestamps use ISO 8601 format
- JSON fields (output_json, metrics_json, tags) store structured data as TEXT
- The schema supports the full analysis workflow from sample ingestion to artifact storage
