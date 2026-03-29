# API File Server Guide

## Overview

The compose-managed daemon exposes an HTTP API on port `18080`. It now owns both direct API uploads and MCP upload-session finalization.

Current responsibilities:

- `POST /api/v1/samples` for authenticated direct file upload
- `GET /api/v1/samples/:id` for sample metadata
- `POST /api/v1/uploads/:token` for daemon-backed upload sessions created by `sample.request_upload`
- `GET /api/v1/uploads/:token/status` for upload-session state
- `GET /api/v1/health` for health checks

## Default behavior

- `API_ENABLED=true` by default
- `API_PORT=18080`
- `API_KEY` is optional; if not set, direct upload and sample metadata routes are unauthenticated
- Upload session endpoints created through `sample.request_upload` do not rely on process-local memory

## Start the container

```bash
docker compose up -d mcp-server
curl http://localhost:18080/api/v1/health
```

## Direct API upload

This path is useful for external automation that already has an API key and wants to bypass MCP.

```bash
curl -X POST http://localhost:18080/api/v1/samples \
  -H "X-API-Key: your-api-key" \
  -F "file=@sample.exe" \
  -F "source=manual_upload"
```

Example response:

```json
{
  "ok": true,
  "data": {
    "sample_id": "sha256:abc123...",
    "filename": "sample.exe",
    "size": 1048576,
    "uploaded_at": "2026-03-22T15:20:00.000Z",
    "existed": false,
    "file_type": "PE"
  }
}
```

## MCP durable upload flow

This is the recommended path for `docker compose up` plus `docker exec` MCP clients.

### 1. Request session from MCP

```json
{
  "tool": "sample.request_upload",
  "arguments": {
    "filename": "Weixin.dll",
    "ttl_seconds": 300
  }
}
```

### 2. Upload through the daemon

```bash
curl -X POST "http://localhost:18080/api/v1/uploads/<token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@D:\Playground\reverse-test\Weixin.dll"
```

Example response:

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

### 3. Continue analysis with `sample_id`

The upload response already contains the final `sample_id`. New clients should use that ID directly in analysis tools.

Compatibility note: `sample.ingest(upload_url)` still works for older clients and resolves the persisted session state from SQLite.

## API reference

### `GET /api/v1/health`

Response:

```json
{
  "status": "healthy",
  "uptime": 86400,
  "timestamp": "2026-03-22T15:20:00.000Z",
  "version": "1.0.0-beta.1"
}
```

### `POST /api/v1/samples`

- Requires `multipart/form-data`
- Requires `X-API-Key` only when API key auth is configured
- Returns `201`

### `GET /api/v1/samples/:id`

- Requires `X-API-Key` only when API key auth is configured

Response shape:

```json
{
  "ok": true,
  "data": {
    "sample_id": "sha256:abc123...",
    "filename": null,
    "size": 1048576,
    "uploaded_at": "2026-03-22T15:20:00.000Z",
    "file_type": "PE",
    "analyses": []
  }
}
```

### `POST /api/v1/uploads/:token`

- Accepts raw bytes in the request body
- Requires `Content-Type: application/octet-stream`
- Registers the sample before replying
- Returns `201` on first successful upload
- Returns `200` with the existing `sample_id` if the session is already registered

### `GET /api/v1/uploads/:token/status`

Response shape:

```json
{
  "ok": true,
  "data": {
    "token": "abc123...",
    "status": "registered",
    "uploaded": true,
    "expires_at": "2026-03-22T15:20:00.000Z",
    "uploaded_at": "2026-03-22T15:18:30.000Z",
    "filename": "Weixin.dll",
    "size": 175461416,
    "sample_id": "sha256:abc123...",
    "error": null
  }
}
```

Legacy aliases also supported:

- `POST /upload?token=...`
- `GET /status?token=...`

## Docker notes

For the durable-session workflow, port `18080` is the important published port. The daemon handles both the HTTP API and the upload-session endpoints on that port.

Recommended compose environment:

```yaml
environment:
  - API_ENABLED=true
  - API_PORT=18080
  - API_STORAGE_ROOT=/app/storage
  - API_MAX_FILE_SIZE=524288000
  - API_RETENTION_DAYS=30
```

## Troubleshooting

### Upload token works in MCP but fails over HTTP

That failure used to happen when token state lived in process memory. The durable upload session flow fixes it by storing session state in SQLite. If you still see it, verify the worker and daemon point at the same `DB_PATH`.

### `401` or `403` on direct API uploads

Check `X-API-Key` and the configured `API_KEY`.

### `413 Payload Too Large`

Increase `API_MAX_FILE_SIZE` if the sample legitimately exceeds the current limit.
