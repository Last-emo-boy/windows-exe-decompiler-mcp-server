# Agent Upload Instructions

Use these instructions when the user asks an MCP client to analyze a file that exists on the host machine instead of inside the container.

## Required behavior

1. Call `sample.request_upload` first.
2. Use the returned `upload_url` with HTTP `POST`.
3. Send raw bytes with `Content-Type: application/octet-stream`.
4. Read `sample_id` directly from the upload response.
5. Continue analysis with that `sample_id`.
6. Only call `sample.ingest(upload_url)` if the client still expects the legacy compatibility flow.

## Correct request sequence

### Step 1

```json
{
  "tool": "sample.request_upload",
  "arguments": {
    "filename": "Weixin.dll",
    "ttl_seconds": 300
  }
}
```

### Step 2

```bash
curl -X POST "http://localhost:18080/api/v1/uploads/<token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@D:\Playground\reverse-test\Weixin.dll"
```

PowerShell alternative:

```powershell
Invoke-WebRequest `
  -Uri "http://localhost:18080/api/v1/uploads/<token>" `
  -Method POST `
  -ContentType "application/octet-stream" `
  -InFile "D:\Playground\reverse-test\Weixin.dll"
```

### Step 3

Expected response shape:

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

### Step 4

Continue with the returned `sample_id`, for example:

```json
{
  "tool": "workflow.triage",
  "arguments": {
    "sample_id": "sha256:abc123..."
  }
}
```

## Legacy compatibility

Older clients may still do:

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "upload_url": "http://localhost:18080/api/v1/uploads/<token>"
  }
}
```

That is supported, but it is not the preferred path anymore.

## Do not do these things

- Do not use `PUT`.
- Do not use `GET`.
- Do not switch to port `18081` unless you are intentionally testing legacy aliases.
- Do not expect the upload token to live only in the current MCP worker process.
- Do not ask the user to mount the file into the container if the upload session flow is available.
