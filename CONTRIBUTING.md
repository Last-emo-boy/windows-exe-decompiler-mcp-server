# Contributing

## Development setup

### Option 1: Docker Development (Recommended)

Using Docker provides a consistent development environment with all dependencies pre-installed:

1. Install Docker 20.10+ and Docker Compose v2+

2. Build the Docker image:

```bash
npm run docker:build
```

3. Test the toolchain:

```bash
npm run docker:test
```

4. Enter the container for debugging:

```bash
npm run docker:run
```

5. Run tests inside container:

```bash
docker run --rm -it \
  -v $(pwd):/app \
  -w /app \
  rikune:latest \
  npm test
```

### Option 2: Native Development

1. Install Node.js 22 or newer.
2. Install Python 3.11 or newer.
3. Install dependencies:

```powershell
npm ci
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

4. Build the TypeScript sources:

```powershell
npm run build
```

## Recommended validation

Run the checks below before opening a pull request:

### Docker-based validation (Recommended)

```bash
# Build and test in container
npm run docker:build
npm run docker:test
docker run --rm -v $(pwd):/app -w /app rikune:latest npm run build
docker run --rm -v $(pwd):/app -w /app rikune:latest python -m py_compile workers/static_worker.py workers/speakeasy_compat.py
```

### Native validation

```powershell
npm run build
python -m py_compile workers/static_worker.py workers/speakeasy_compat.py
npm test -- --runInBand
npm run pack:dry-run
```

If you changed Ghidra, .NET, packaging, or runtime orchestration code, prefer
running the closest focused tests in `tests/unit/` instead of relying only on
full-suite execution.

## Docker-specific guidelines

### Building the image

- Use multi-stage builds to minimize final image size
- Test changes with `docker build --no-cache` periodically
- Keep image size under 3GB (current: ~2.5GB)

### Running containers

- Always use `--network=none` for malware analysis
- Mount volumes for persistent data:
  ```bash
  -v ~/.rikune/workspaces:/app/workspaces
  -v ~/.rikune/data:/app/data
  ```
- Use security options: `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`

### Testing Docker changes

```bash
# Test basic toolchain
docker run --rm rikune:latest node --version
docker run --rm rikune:latest python3 --version
docker run --rm rikune:latest java -version
docker run --rm rikune:latest /opt/ghidra/support/analyzeHeadless -help

# Test Python packages
docker run --rm rikune:latest python3 -c "import pefile, lief, yara, capa, floss, dnfile, speakeasy"

# Test MCP server stdio
echo '{"jsonrpc":"2.0","method":"initialize","params":{}}' | \
  docker run -i --rm rikune:latest node dist/index.js
```

## Adding tools and plugins

### Registering a new tool

All MCP tools are registered in `src/tool-registry.ts` (not `src/index.ts`).

1. Create `src/tools/my-tool.ts` exporting a tool definition and handler factory.
2. Import both in `src/tool-registry.ts`.
3. Add `server.registerTool(definition, handler)` in the appropriate category section.
4. Add `tests/unit/my-tool.test.ts`.
5. Rebuild and run tests:

```powershell
npm run build
npm test -- --testPathPattern my-tool
```

See [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) for the full `ToolDeps`
interface and handler factory pattern.

### Developing a plugin

If your tool belongs to a toggleable category (e.g. a new analysis backend),
consider packaging it as a plugin. See [docs/PLUGINS.md](./docs/PLUGINS.md) for
the `Plugin` interface, lifecycle, and registration instructions.

## Repository conventions

- Keep MCP tool schemas, tool descriptions, and `tool.help` output aligned.
- Prefer stable artifacts over untracked workspace files.
- Preserve provenance fields when adding new report or workflow outputs.
- Register new tools in `src/tool-registry.ts` (the centralised registry).
- Use `src/safe-command.ts` wrappers for any external command invocations.
- Use `src/logger.ts` (Pino) instead of `console.log` / `console.error`.
- Avoid committing generated workspace outputs, caches, and temporary reports.
- Include Docker configuration changes in the same commit as code changes.

## Release flow

### Docker Image Release

Docker images are automatically built and pushed on:
- Push to `main` branch (tagged with branch name and SHA)
- Git tags (tagged with semantic version)

Manual release:

```bash
# Build and tag
docker build -t rikune:latest -t rikune:<version> .

# Push to registry
docker push rikune:latest
docker push rikune:<version>
```

### npm Package Release

1. Update `CHANGELOG.md`.
2. Run `npm run release:check`.
3. Bump the package version:

```powershell
npm version prerelease --preid beta
```

4. Push the commit and tag:

```powershell
git push origin main --follow-tags
```

The `publish-npm.yml` workflow publishes tagged releases, and `docker-build.yml` 
pushes Docker images to GitHub Container Registry.
