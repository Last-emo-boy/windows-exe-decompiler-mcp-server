# API Reference

## Base URL

```
http://localhost:18080
```

## Authentication

Most endpoints require API key authentication via the `X-API-Key` header.

```bash
curl -H "X-API-Key: your-api-key" http://localhost:18080/api/v1/...
```

If `API_KEY` environment variable is not set, authentication is disabled.

## Endpoints

### Health Check

#### `GET /api/v1/health`

Check server health and version.

**Request:**
```bash
curl http://localhost:18080/api/v1/health
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0-beta.1",
    "timestamp": "2026-03-24T10:00:00.000Z"
  }
}
```

### Samples

#### `POST /api/v1/samples`

Upload a sample file for analysis.

**Request:**
```bash
curl -X POST http://localhost:18080/api/v1/samples \
  -H "X-API-Key: your-api-key" \
  -F "file=@sample.exe" \
  -F "filename=sample.exe" \
  -F "source=api_upload"
```

**Headers:**
- `Content-Type: multipart/form-data`
- `X-API-Key: <your-api-key>` (if authentication enabled)

**Response (201 Created):**
```json
{
  "ok": true,
  "data": {
    "sample_id": "sha256:abc123...",
    "filename": "sample.exe",
    "size": 1048576,
    "uploaded_at": "2026-03-24T10:00:00.000Z",
    "existed": false,
    "file_type": ".exe"
  }
}
```

**Error Responses:**
- `400 Bad Request` - Invalid request format
- `401 Unauthorized` - Invalid API key
- `413 Payload Too Large` - File exceeds size limit

#### `GET /api/v1/samples/:id`

Retrieve sample metadata.

**Request:**
```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:18080/api/v1/samples/sha256:abc123...
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "sample_id": "sha256:abc123...",
    "filename": "sample.exe",
    "size": 1048576,
    "sha256": "abc123...",
    "file_type": ".exe",
    "created_at": "2026-03-24T10:00:00.000Z",
    "analyses": [
      {
        "id": "analysis-123",
        "stage": "triage",
        "status": "completed",
        "completed_at": "2026-03-24T10:05:00.000Z"
      }
    ]
  }
}
```

**Query Parameters:**
- `download=true` - Download the sample file (binary response)

#### `GET /api/v1/samples/:id?download=true`

Download the sample file.

**Request:**
```bash
curl -H "X-API-Key: your-api-key" \
  -o sample.exe \
  "http://localhost:18080/api/v1/samples/sha256:abc123...?download=true"
```

**Response:** Binary file content

### Artifacts

#### `GET /api/v1/artifacts`

List all artifacts or filter by sample.

**Request:**
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:18080/api/v1/artifacts?sample_id=sha256:abc123..."
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "artifacts": [
      {
        "id": "artifact-123",
        "sample_id": "sha256:abc123...",
        "type": "triage_report",
        "sha256": "def456...",
        "created_at": "2026-03-24T10:05:00.000Z"
      }
    ],
    "total": 1
  }
}
```

#### `GET /api/v1/artifacts/:id`

Get artifact metadata.

**Request:**
```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:18080/api/v1/artifacts/artifact-123
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "id": "artifact-123",
    "sample_id": "sha256:abc123...",
    "type": "triage_report",
    "path": "/app/storage/artifacts/sha256:abc123/triage_report.json",
    "sha256": "def456...",
    "mime": "application/json",
    "created_at": "2026-03-24T10:05:00.000Z"
  }
}
```

**Query Parameters:**
- `download=true` - Download the artifact file
- `content=true` - Include parsed JSON content (for JSON artifacts)

#### `DELETE /api/v1/artifacts/:id`

Delete an artifact.

**Request:**
```bash
curl -X DELETE \
  -H "X-API-Key: your-api-key" \
  http://localhost:18080/api/v1/artifacts/artifact-123
```

**Response:**
```json
{
  "ok": true,
  "message": "Artifact deleted"
}
```

### Upload Sessions

#### `POST /api/v1/uploads/:token`

Complete an upload session.

**Request:**
```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -F "file=@sample.exe" \
  http://localhost:18080/api/v1/uploads/token-123
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "status": "registered",
    "sample_id": "sha256:abc123..."
  }
}
```

#### `GET /api/v1/uploads/:token/status`

Check upload session status.

**Request:**
```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:18080/api/v1/uploads/token-123/status
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "status": "registered",
    "sample_id": "sha256:abc123...",
    "filename": "sample.exe",
    "size": 1048576
  }
}
```

## MCP Resources

The server exposes helper scripts as MCP resources. Clients discover them via
the standard MCP `resources/list` method and read content via `resources/read`.

### `resources/list`

Returns all registered resources.

**Example response (partial):**
```json
{
  "resources": [
    {
      "uri": "script://frida/api_trace.js",
      "name": "Frida: api_trace.js",
      "description": "Windows API tracing with argument logging",
      "mimeType": "text/javascript"
    },
    {
      "uri": "script://ghidra/ExtractFunctions.java",
      "name": "Ghidra: ExtractFunctions.java",
      "description": "Function extraction",
      "mimeType": "text/x-java-source"
    }
  ]
}
```

### `resources/read`

Read the content of a specific resource by URI.

**Request:**
```json
{
  "method": "resources/read",
  "params": {
    "uri": "script://frida/api_trace.js"
  }
}
```

**Response:**
```json
{
  "contents": [
    {
      "uri": "script://frida/api_trace.js",
      "mimeType": "text/javascript",
      "text": "// api_trace.js\n'use strict';\n..."
    }
  ]
}
```

### Available resources

| URI | Type | Description |
|-----|------|-------------|
| `script://frida/api_trace.js` | Frida | Windows API tracing with argument logging |
| `script://frida/string_decoder.js` | Frida | Runtime string decryption |
| `script://frida/anti_debug_bypass.js` | Frida | Anti-debug bypass |
| `script://frida/crypto_finder.js` | Frida | Cryptographic API detection |
| `script://frida/file_registry_monitor.js` | Frida | File/registry monitoring |
| `script://ghidra/ExtractFunctions.java` | Ghidra | Function extraction |
| `script://ghidra/ExtractFunctions.py` | Ghidra | Function extraction (Python) |
| `script://ghidra/DecompileFunction.java` | Ghidra | Function decompilation |
| `script://ghidra/DecompileFunction.py` | Ghidra | Function decompilation (Python) |
| `script://ghidra/ExtractCFG.java` | Ghidra | CFG extraction |
| `script://ghidra/ExtractCFG.py` | Ghidra | CFG extraction (Python) |
| `script://ghidra/AnalyzeCrossReferences.java` | Ghidra | Cross-reference analysis |
| `script://ghidra/SearchFunctionReferences.java` | Ghidra | Function reference search |

## MCP Progress Notifications

Long-running tools support progress reporting via MCP `notifications/progress`.

### Requesting progress updates

Include `_meta.progressToken` in the tool call:

```json
{
  "method": "tools/call",
  "params": {
    "name": "workflow.analyze.start",
    "arguments": { "sample_id": "sha256:abc123..." },
    "_meta": { "progressToken": "my-progress-1" }
  }
}
```

### Progress notification format

```json
{
  "method": "notifications/progress",
  "params": {
    "progressToken": "my-progress-1",
    "progress": 50,
    "total": 100,
    "message": "Enriching static analysis..."
  }
}
```

Progress ranges from 0 to 100. Not all tools emit progress notifications — only
those with significant runtimes.
```

## Error Handling

All errors follow this format:

```json
{
  "error": "ErrorType",
  "message": "Human-readable error message"
}
```

### Common Error Codes

| Status | Error | Description |
|--------|-------|-------------|
| 400 | Bad Request | Invalid request format or parameters |
| 401 | Unauthorized | Invalid or missing API key |
| 403 | Forbidden | API key missing when required |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 410 | Gone | Resource expired |
| 413 | Payload Too Large | File exceeds size limit |
| 500 | Internal Server Error | Server error |

## Rate Limiting

Currently no rate limiting is implemented. Consider implementing at the reverse proxy level for production deployments.

## Examples

### Complete Upload Workflow

```bash
# 1. Upload sample
RESPONSE=$(curl -s -X POST \
  -H "X-API-Key: your-key" \
  -F "file=@sample.exe" \
  http://localhost:18080/api/v1/samples)

SAMPLE_ID=$(echo $RESPONSE | jq -r '.data.sample_id')

# 2. Check sample status
curl -H "X-API-Key: your-key" \
  http://localhost:18080/api/v1/samples/$SAMPLE_ID

# 3. Download analysis artifacts
curl -H "X-API-Key: your-key" \
  "http://localhost:18080/api/v1/artifacts?sample_id=$SAMPLE_ID"
```

### Using PowerShell

```powershell
# Upload sample
$response = Invoke-RestMethod `
  -Uri "http://localhost:18080/api/v1/samples" `
  -Method Post `
  -Headers @{ "X-API-Key" = "your-key" } `
  -Form @{ file = Get-Item "sample.exe" }

# Get sample info
Invoke-RestMethod `
  -Uri "http://localhost:18080/api/v1/samples/$($response.data.sample_id)" `
  -Headers @{ "X-API-Key" = "your-key" }
```
