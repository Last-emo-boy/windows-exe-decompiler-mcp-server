# Durable Upload Sessions

This document replaces the older "temporary upload server" description.

## What changed

The upload flow is now daemon-backed and container-scoped:

- `sample.request_upload` creates a persisted upload session in SQLite.
- The compose-managed HTTP daemon owns the upload endpoint.
- The upload URL remains valid across `docker exec ... node dist/index.js` worker processes.
- Successful upload returns `sample_id` directly.

This design fixes the old failure mode where one process created the token and a different process received the HTTP upload.

## Current endpoints

Primary endpoints:

- `POST /api/v1/uploads/:token`
- `GET /api/v1/uploads/:token/status`

Legacy aliases still accepted by the daemon:

- `POST /upload?token=...`
- `GET /status?token=...`

New clients should use the `/api/v1/uploads/:token` form returned by `sample.request_upload`.

## Current workflow

### 1. Create the upload session

```json
{
  "tool": "sample.request_upload",
  "arguments": {
    "filename": "Weixin.dll",
    "ttl_seconds": 300
  }
}
```

Example response:

```json
{
  "ok": true,
  "data": {
    "upload_url": "http://localhost:18080/api/v1/uploads/abc123...",
    "status_url": "http://localhost:18080/api/v1/uploads/abc123.../status",
    "token": "abc123...",
    "expires_at": "2026-03-22T15:20:00.000Z",
    "ttl_seconds": 300
  }
}
```

### 2. Upload the file

```bash
curl -X POST "http://localhost:18080/api/v1/uploads/abc123..." \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@D:\Playground\reverse-test\Weixin.dll"
```

### 3. Read the sample registration result

```json
{
  "ok": true,
  "data": {
    "status": "registered",
    "sample_id": "sha256:abc123...",
    "filename": "Weixin.dll",
    "size": 175461416,
    "file_type": "PE",
    "existed": false
  }
}
```

### 4. Optional compatibility step

If an older client still expects to call `sample.ingest(upload_url)`, that remains supported:

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "upload_url": "http://localhost:18080/api/v1/uploads/abc123..."
  }
}
```

## Why this works with `docker compose up` plus `docker exec`

```text
compose daemon process
  ├─ listens on 18080
  ├─ validates upload tokens
  └─ finalizes samples

docker exec MCP worker
  ├─ handles stdio requests
  └─ creates upload session records in SQLite
```

The worker and daemon do not share JS memory. They do share the same database and storage volume, so persisted upload sessions solve the cross-process handoff cleanly.

## Operator notes

- Port `18080` is sufficient for both the API and daemon-backed upload sessions.
- Port `18081` should not be treated as the primary upload path anymore.
- Expired `pending` or `uploaded` sessions are marked `expired` during cleanup.
