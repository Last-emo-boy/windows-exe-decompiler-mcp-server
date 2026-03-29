# MCP Server Upload Guide

## When to use this flow

Use this workflow when the sample file is on the host machine and the MCP worker is running inside Docker through `docker exec`. In that deployment model, the worker cannot read `D:\...` paths directly, so it must create a durable upload session and send the bytes through the daemon HTTP server.

## Primary workflow

### 1. Request an upload session

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

### 2. Upload the file bytes with HTTP POST

`curl`:

```bash
curl -X POST "http://localhost:18080/api/v1/uploads/abc123..." \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@D:\Playground\reverse-test\Weixin.dll"
```

PowerShell:

```powershell
Invoke-WebRequest `
  -Uri "http://localhost:18080/api/v1/uploads/abc123..." `
  -Method POST `
  -ContentType "application/octet-stream" `
  -InFile "D:\Playground\reverse-test\Weixin.dll"
```

Successful upload returns the registered sample directly:

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

Once the upload endpoint returns `sample_id`, use that ID in downstream tools such as `workflow.triage`, `workflow.reconstruct`, or other sample-based tools.

## Compatibility mode

Older clients may still call `sample.ingest` with the returned `upload_url`:

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "upload_url": "http://localhost:18080/api/v1/uploads/abc123..."
  }
}
```

That path is kept for compatibility. New clients should prefer reading `sample_id` directly from the upload response and skip the extra `sample.ingest` step.

## Qwen / agent prompt

Use wording like:

```text
请先调用 sample.request_upload 获取上传链接。
然后使用 curl -X POST 或 PowerShell Invoke-WebRequest -Method POST 上传宿主机上的 D:\Playground\reverse-test\Weixin.dll。
上传成功后直接读取返回结果里的 sample_id，并继续分析。
如果客户端坚持旧流程，再用 upload_url 调用 sample.ingest。
```

## Status endpoint

You can inspect the upload session state with:

```bash
curl http://localhost:18080/api/v1/uploads/abc123.../status
```

Example response:

```json
{
  "ok": true,
  "data": {
    "token": "abc123...",
    "status": "registered",
    "uploaded": true,
    "expires_at": "2026-03-22T15:20:00.000Z",
    "uploaded_at": "2026-03-22T15:16:12.000Z",
    "filename": "Weixin.dll",
    "size": 175461416,
    "sample_id": "sha256:abc123...",
    "error": null
  }
}
```

## Troubleshooting

### `Invalid or expired token`

This means the daemon cannot find the persisted upload session, or the session has expired. Request a new upload URL and upload again.

### `Upload session is not pending`

This usually means the same upload URL was already used, already finalized, or failed previously. Check `status_url` and create a new session if needed.

### Connection refused on `localhost:18080`

Make sure the compose-managed container is running and port `18080` is published:

```bash
docker compose ps
docker compose logs -f mcp-server
curl http://localhost:18080/api/v1/health
```

## Important notes

- The primary upload endpoint is `http://localhost:18080/api/v1/uploads/<token>`.
- The old `18081` temporary upload server is no longer the primary design.
- The upload session is durable across MCP worker processes because session state is stored in SQLite, not process memory.
