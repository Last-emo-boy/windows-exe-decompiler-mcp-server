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
  windows-exe-decompiler:latest \
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
docker run --rm -v $(pwd):/app -w /app windows-exe-decompiler:latest npm run build
docker run --rm -v $(pwd):/app -w /app windows-exe-decompiler:latest python -m py_compile workers/static_worker.py workers/speakeasy_compat.py
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
  -v ~/.windows-exe-decompiler-mcp-server/workspaces:/app/workspaces
  -v ~/.windows-exe-decompiler-mcp-server/data:/app/data
  ```
- Use security options: `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`

### Testing Docker changes

```bash
# Test basic toolchain
docker run --rm windows-exe-decompiler:latest node --version
docker run --rm windows-exe-decompiler:latest python3 --version
docker run --rm windows-exe-decompiler:latest java -version
docker run --rm windows-exe-decompiler:latest /opt/ghidra/support/analyzeHeadless -help

# Test Python packages
docker run --rm windows-exe-decompiler:latest python3 -c "import pefile, lief, yara, capa, floss, dnfile, speakeasy"

# Test MCP server stdio
echo '{"jsonrpc":"2.0","method":"initialize","params":{}}' | \
  docker run -i --rm windows-exe-decompiler:latest node dist/index.js
```

## Repository conventions

- Keep MCP tool schemas, tool descriptions, and `tool.help` output aligned.
- Prefer stable artifacts over untracked workspace files.
- Preserve provenance fields when adding new report or workflow outputs.
- When adding a new MCP tool or prompt, register it in `src/index.ts` and make
  sure route coverage tests still pass.
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
docker build -t windows-exe-decompiler:latest -t windows-exe-decompiler:<version> .

# Push to registry
docker push windows-exe-decompiler:latest
docker push windows-exe-decompiler:<version>
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
