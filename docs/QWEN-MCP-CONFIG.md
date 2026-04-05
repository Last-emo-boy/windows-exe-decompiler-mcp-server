# Qwen MCP Configuration

This guide documents the recommended single-container deployment:

1. Start the daemon once with `docker compose up -d mcp-server`
2. Connect the MCP client with `docker exec -i rikune node dist/index.js`

This model keeps a single named container and shared persistent volumes. Because the client-scoped MCP worker runs inside the same container, keep the compose memory limit at `8G` or above for heavy analysis.

## Recommended configuration

### Qwen / generic stdio client

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "rikune",
        "node",
        "dist/index.js"
      ],
      "env": {
        "NODE_ENV": "production",
        "PYTHONUNBUFFERED": "1",
        "WORKSPACE_ROOT": "/app/workspaces",
        "DB_PATH": "/app/data/database.db",
        "CACHE_ROOT": "/app/cache",
        "GHIDRA_PROJECT_ROOT": "/ghidra-projects",
        "GHIDRA_LOG_ROOT": "/ghidra-logs"
      },
      "timeout": 300000
    }
  }
}
```

This matches the checked-in example in [settings.json](/D:/Playground/rikune/settings.json).

## Why `docker exec` is preferred here

```text
docker compose daemon
  ├─ HTTP API on 18080
  ├─ upload session finalization
  ├─ shared DB and storage volumes
  └─ long-lived container state

Qwen MCP connection
  └─ docker exec -i rikune node dist/index.js
```

Benefits:

- one container to operate
- shared persistent storage
- durable upload sessions across worker restarts
- no need to rebuild a throwaway container per MCP connection

## Startup sequence

```bash
docker compose up -d mcp-server
docker compose ps
curl http://localhost:18080/api/v1/health
```

Then start or reload Qwen so it picks up the `docker exec` MCP config.

## Upload behavior in this deployment

For host files such as `D:\Playground\reverse-test\Weixin.dll`, the client should:

1. call `sample.request_upload`
2. upload to the returned `http://localhost:18080/api/v1/uploads/<token>` URL
3. read `sample_id` from the HTTP response
4. continue analysis with that `sample_id`

This works because the token/session state is persisted in SQLite instead of living only in the current MCP worker process.

## Troubleshooting

### Qwen cannot connect to the MCP server

Check:

```bash
docker compose ps
docker exec -i rikune node dist/index.js
```

The `docker exec` command should stay attached to stdio instead of exiting immediately.

### Upload returns connection refused

Check the daemon, not the `docker exec` worker:

```bash
docker compose logs -f mcp-server
curl http://localhost:18080/api/v1/health
```

### Upload returns `Invalid or expired token`

Make sure the worker and daemon use the same database path:

- `DB_PATH=/app/data/database.db`
- compose volume mounted to `/app/data`

If those are aligned, request a new upload session and retry.
