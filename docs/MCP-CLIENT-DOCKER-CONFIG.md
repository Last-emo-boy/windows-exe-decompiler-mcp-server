# MCP Client Docker Configuration

Recommended deployment model:

1. Start the container once with `docker compose up -d mcp-server`
2. Point MCP clients at either:
   - the published npm launcher: `npx -y rikune docker-stdio`
   - or the direct Docker path: `docker exec -i rikune node dist/index.js`

This keeps a single named container for storage, upload handling, and API access while the client gets a fresh stdio MCP process inside that container. Keep the compose container memory at `8G` or higher if you run heavy analyses.

## Published npm package plus Docker runtime

Use this when you want npm and Docker separated but still strongly bound:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "npx",
      "args": ["-y", "rikune", "docker-stdio"],
      "timeout": 300000
    }
  }
}
```

The launcher will refuse to start unless the compose container is already running.

## Generic config

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

## Client-specific notes

### Qwen / generic stdio clients

Use the generic config above as-is.

### Claude Desktop / Codex / Copilot

If the client supports stdio MCP servers, the same `docker exec` pattern applies. Only the config file location changes.

## Compose requirements

The compose-managed container should mount persistent volumes for:

- `/app/workspaces`
- `/app/data`
- `/app/cache`
- `/ghidra-projects`
- `/ghidra-logs`
- `/app/storage`

The daemon should publish `18080` so host-side uploads can use the durable upload-session endpoint:

```yaml
ports:
  - "18080:18080"
```

## Why this model is preferred

```text
compose container
  ├─ HTTP daemon on 18080
  ├─ shared SQLite database
  ├─ shared storage volumes
  └─ long-lived service state

MCP client
  └─ docker exec -i rikune node dist/index.js
```

This gives you one named container to operate and keeps upload/session state aligned with the MCP worker's volumes and database.

## Validation

```bash
docker compose up -d mcp-server
docker compose ps
curl http://localhost:18080/api/v1/health
docker exec -i rikune node dist/index.js
```
