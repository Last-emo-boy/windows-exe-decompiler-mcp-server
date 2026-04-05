# Docker 使用指南

Rikune 的完整 Docker 容器化部署指南。

## 目录

- [快速开始](#快速开始)
- [Docker 服务一览](#docker-服务一览)
- [构建镜像](#构建镜像)
- [运行容器](#运行容器)
- [Web Dashboard（看板）](#web-dashboard看板)
- [MCP 客户端配置](#mcp-客户端配置)
- [数据持久化](#数据持久化)
- [安全配置](#安全配置)
- [故障排除](#故障排除)
- [高级用法](#高级用法)

## 快速开始

### 前提条件

- Docker 20.10+ 和 Docker Compose v2+
- 至少 10GB 可用磁盘空间
- 8GB+ RAM（推荐 16GB+）

### 5 分钟快速启动

```bash
# 1. 克隆项目
git clone https://github.com/Last-emo-boy/rikune.git
cd rikune

# 2. 构建 Docker 镜像（约 10-15 分钟）
docker build -t rikune:latest .

# 3. 创建样本目录
mkdir -p samples

# 4. 运行容器测试
docker run --rm \
  -v ./samples:/samples:ro \
  rikune:latest \
  node --version

# 5. 配置 MCP 客户端（见下方配置章节）
```

## 构建镜像

### 标准构建

```bash
docker build -t rikune:latest .
```

### 使用构建缓存加速

```bash
# 第一次构建（完整）
docker build -t rikune:latest .

# 后续构建（使用缓存）
docker build --cache-from rikune:latest -t rikune:latest .
```

### 验证完整工具链

```bash
docker run --rm --entrypoint /usr/local/bin/validate-docker-full-stack.sh rikune:latest
```

### 多平台构建（可选）

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t rikune:latest \
  --push .
```

### 镜像大小优化

```bash
# 查看镜像大小
docker images rikune

# 预期大小：明显大于基础镜像（该镜像现在默认内置完整 Linux 侧分析栈）
# - Node.js + npm
# - Python 基线 + 动态扩展包（含 Qiling/PANDA/Frida CLI/YARA-X）
# - angr 隔离运行时
# - Ghidra 12.0.4
# - Graphviz / Rizin / UPX / Wine / RetDec
# - 应用代码
```

```

## Docker 服务一览

容器启动后，以下服务同时运行在同一个 Node.js 进程中：

### 1. MCP Server（stdio 传输）

| 项目 | 说明 |
|------|------|
| 协议 | MCP (Model Context Protocol) over stdio |
| 连接方式 | `docker exec -i <container> node dist/index.js` 或 `docker run -i` |
| 用途 | LLM 客户端（Claude / Copilot / Codex）通过 MCP 调用分析工具 |

提供 **148+ MCP 工具**、**3 MCP prompts**、**16 MCP resources**。

### 2. HTTP API File Server（端口 18080）

| 项目 | 说明 |
|------|------|
| 默认端口 | `18080`（通过 `API_PORT` 环境变量配置） |
| 认证 | 可选 API Key（`X-API-Key` header，通过 `API_KEY` 环境变量配置） |
| 用途 | 样本上传、产物下载、健康检查、SSE 实时事件、**Web Dashboard** |

完整 HTTP 端点列表：

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET` | `/` 或 `/dashboard` | **Web Dashboard** — 系统运行看板 |
| `GET` | `/api/v1/health` | 健康检查（uptime, version, status） |
| `GET` | `/api/v1/events` | SSE 实时事件流（样本入库、分析完成等） |
| `POST` | `/api/v1/samples` | 直接上传样本（multipart/form-data） |
| `GET` | `/api/v1/samples/:id` | 获取样本元数据或下载原始文件 |
| `GET` | `/api/v1/artifacts` | 列出分析产物（可按 sample_id 过滤） |
| `GET` | `/api/v1/artifacts/:id` | 获取/下载单个产物 |
| `DELETE` | `/api/v1/artifacts/:id` | 删除指定产物 |
| `POST` | `/api/v1/uploads/:token` | 上传会话续传 |
| `GET` | `/api/v1/uploads/:token` | 上传会话状态查询 |
| `GET` | `/api/v1/dashboard/overview` | Dashboard API — 服务总览（uptime、版本、工具/插件/样本计数、内存） |
| `GET` | `/api/v1/dashboard/tools` | Dashboard API — 全部工具列表（按类别分组） |
| `GET` | `/api/v1/dashboard/plugins` | Dashboard API — 插件状态 |
| `GET` | `/api/v1/dashboard/samples` | Dashboard API — 样本列表（分页） |
| `GET` | `/api/v1/dashboard/workers` | Dashboard API — 进程/系统资源统计 |
| `GET` | `/api/v1/dashboard/config` | Dashboard API — 配置校验报告 |
| `GET` | `/api/v1/dashboard/system` | Dashboard API — 系统信息（CPU/内存/主机名） |

### 3. Web Dashboard（看板）

浏览器访问 `http://localhost:18080/dashboard` 即可打开暗色主题看板。

| 选项卡 | 内容 |
|--------|------|
| **Overview** | 服务运行时间、版本、工具/插件/样本数量、内存使用、最近 24h 分析统计 |
| **Tools** | 148+ MCP 工具按类别（pe / code / ghidra / dynamic 等）分组展示，支持搜索 |
| **Plugins** | 9 个内建插件 + 自定义插件的加载状态（loaded / skipped / error） |
| **Samples** | 已入库样本分页表格（名称、SHA-256、大小、入库时间） |
| **Config** | 当前配置概要 + 配置校验诊断结果 |
| **System** | 主机名、CPU、内存、Node.js 版本、日志级别 |

看板还包括：
- **SSE 实时事件面板**：自动订阅 `/api/v1/events`，实时展示分析事件
- **自动刷新**：Overview 标签每 15 秒自动拉取最新数据

### 4. 后台分析引擎

| 组件 | 说明 |
|------|------|
| **AnalysisTaskRunner** | 后台异步任务执行器，处理排队的分析任务 |
| **JobQueue** | 持久化作业队列（SQLite），支持任务状态查询、取消、清扫 |
| **Python Worker Pool** | 并发受限的 Python 进程池（`MAX_PYTHON_WORKERS`），用于 capa/FLOSS/Rizin 等 |
| **Plugin Manager** | 9 内建插件 + 第三方插件自动发现和热加载 |

### 服务架构图

```
┌──────────────────────────────────────────────────────────┐
│                    Docker Container                       │
│                                                          │
│  ┌─────────────────────┐   ┌──────────────────────────┐  │
│  │   MCP Server        │   │  HTTP File Server :18080 │  │
│  │   (stdio transport) │   │                          │  │
│  │                     │   │  /dashboard  → Web UI    │  │
│  │  148+ tools         │   │  /api/v1/samples → CRUD  │  │
│  │  3 prompts          │   │  /api/v1/artifacts       │  │
│  │  16 resources       │   │  /api/v1/events → SSE    │  │
│  │  9 plugins          │   │  /api/v1/dashboard/* API │  │
│  └────────┬────────────┘   └────────────┬─────────────┘  │
│           │                             │                │
│  ┌────────┴─────────────────────────────┴──────────────┐ │
│  │              Shared Core Infrastructure              │ │
│  │                                                     │ │
│  │  DatabaseManager (SQLite)  │  WorkspaceManager      │ │
│  │  CacheManager              │  StorageManager        │ │
│  │  PolicyGuard (audit)       │  PluginManager         │ │
│  │  JobQueue + TaskRunner     │  Python Worker Pool    │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Bundled Analysis Toolchain              │ │
│  │                                                     │ │
│  │  Ghidra 12.0.4  │  capa + rules  │  DIE (diec)     │ │
│  │  Rizin           │  FLOSS         │  YARA-X         │ │
│  │  UPX             │  Wine/winedbg  │  Graphviz       │ │
│  │  RetDec          │  frida-tools   │  jadx           │ │
│  │  angr (venv)     │  Qiling (venv) │  pandare        │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 端口映射

| 宿主机端口 | 容器端口 | 服务 |
|-----------|----------|------|
| `18080` | `18080` | HTTP File Server + Dashboard + SSE |
| _stdio_ | _stdio_ | MCP Server（通过 `docker exec -i` 或 `docker run -i`） |

## 运行容器

> **提示**：容器启动后将同时运行以下服务，详见 [Docker 服务一览](#docker-服务一览)。

### 基本运行（测试模式）

```bash
docker run --rm -it \
  --network=none \
  -v ./samples:/samples:ro \
  rikune:latest \
  bash
```

### 生产模式（MCP Server）

```bash
docker run --rm -i \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --security-opt no-new-privileges:true \
  --cap-drop=ALL \
  --memory=8g \
  --cpus=2 \
  -v ~/.rikune/workspaces:/app/workspaces \
  -v ~/.rikune/data:/app/data \
  -v ~/.rikune/cache:/app/cache \
  -v ~/.rikune/ghidra-projects:/ghidra-projects \
  -v ~/.rikune/ghidra-logs:/ghidra-logs \
  -v /path/to/qiling-rootfs:/opt/qiling-rootfs:ro \
  -e WORKSPACE_ROOT=/app/workspaces \
  -e DB_PATH=/app/data/database.db \
  -e GHIDRA_PROJECT_ROOT=/ghidra-projects \
  rikune:latest
```

### 使用 Docker Compose

```bash
# 启动服务
docker-compose up -d mcp-server

# 查看日志
docker-compose logs -f mcp-server

# 进入容器
docker-compose exec mcp-server bash

# 停止服务
docker-compose down
```

`docker compose` 适合提供持久卷和 HTTP 上传 API。
如果 MCP 客户端通过 stdio 连接，请继续使用单独的 `docker run -i --rm ... rikune:latest` 配置，不要在 compose 容器里再执行 `docker exec ... node dist/index.js`，否则会在同一个容器里双开 MCP server。

### 环境变量配置

| 变量名 | 默认值 | 描述 |
|--------|--------|------|
| `WORKSPACE_ROOT` | `/app/workspaces` | 工作空间根目录 |
| `DB_PATH` | `/app/data/database.db` | SQLite 数据库路径 |
| `CACHE_ROOT` | `/app/cache` | 缓存根目录 |
| `CAPA_PATH` | `/usr/local/bin/capa` | 容器内置的 capa CLI 包装入口 |
| `CAPA_RULES_PATH` | `/opt/capa-rules` | 容器内置的 capa rules 目录 |
| `CAPA signatures` | `/opt/capa-sigs` | 容器内置的 capa signatures 数据，wrapper 会自动传入 |
| `DIE_PATH` | `/usr/bin/diec` | 容器内置的 Detect It Easy CLI 路径 |
| `GRAPHVIZ_DOT_PATH` | `/usr/bin/dot` | Graphviz `dot` 渲染器路径 |
| `RIZIN_PATH` | `/opt/rizin/bin/rizin` | Rizin 主二进制路径 |
| `UPX_PATH` | `/usr/local/bin/upx` | UPX CLI 路径 |
| `WINE_PATH` | `/usr/bin/wine` | Wine CLI 路径 |
| `WINEDBG_PATH` | `/usr/bin/winedbg` | Wine 自带调试器路径 |
| `YARAX_PYTHON` | `/usr/local/bin/python3` | 可导入 `yara_x` 的 Python 解释器 |
| `QILING_PYTHON` | `/opt/qiling-venv/bin/python` | 隔离 Qiling 运行时解释器 |
| `QILING_ROOTFS` | `/opt/qiling-rootfs` | Qiling Windows rootfs 挂载点 |
| `ANGR_PYTHON` | `/opt/angr-venv/bin/python` | 隔离 angr 运行时解释器 |
| `PANDA_PYTHON` | `/usr/local/bin/python3` | 可导入 `pandare` 的 Python 解释器 |
| `RETDEC_PATH` | `/opt/retdec/bin/retdec-decompiler` | RetDec 反编译器路径 |
| `RETDEC_INSTALL_DIR` | `/opt/retdec` | RetDec 安装根目录 |
| `AUDIT_LOG_PATH` | `/app/logs/audit.log` | 审计日志路径 |
| `XDG_CONFIG_HOME` | `/app/logs/.config` | Ghidra/Java 类工具的用户配置目录 |
| `XDG_CACHE_HOME` | `/app/cache/xdg` | Ghidra/Java 类工具的用户缓存目录 |
| `GHIDRA_PROJECT_ROOT` | `/ghidra-projects` | Ghidra 项目根目录 |
| `GHIDRA_LOG_ROOT` | `/ghidra-logs` | Ghidra 日志根目录 |
| `LOG_LEVEL` | `info` | 日志级别（trace/debug/info/warn/error） |
| `NODE_ENV` | `production` | Node.js 环境 |

镜像默认已经包含：

- `flare-capa` Python 包
- `capa` CLI 包装入口
- `capa-rules` 规则集
- `capa` signatures 数据
- `Detect It Easy` CLI (`diec`，固定为稳定可用的 `3.10 Debian 12` 构建)
- `Graphviz`
- `Rizin`
- `YARA-X` Python 绑定
- `UPX`
- `Wine` / `winedbg`
- `frida-tools`
- `Qiling`
- `angr`（隔离解释器）
- `pandare`
- `RetDec`

因此正常情况下不需要再手工设置 `CAPA_RULES_PATH` 或 `DIE_PATH`。

其中需要额外注意的只有：

- `Qiling` 不会自带 Windows DLL/注册表，必须通过卷挂载方式提供 `QILING_ROOTFS`
- `Wine` / `winedbg` 适合 Linux 下的 Windows 用户态辅助调试，不是完整 Windows VM 替代
- `RetDec` 体积较大，建议走 artifact-first 流程而不是把结果整段塞回 MCP 响应

## Web Dashboard（看板）

Docker 容器启动后，在浏览器中访问：

```
http://localhost:18080/dashboard
```

即可打开 Web 看板。看板完全内嵌于 HTTP File Server，无需额外端口或配置。

### 功能概览

- **6 个选项卡**：Overview / Tools / Plugins / Samples / Config / System
- **暗色主题**：GitHub Dark 风格，对比度友好
- **SSE 实时推送**：右侧事件面板自动展示来自 `/api/v1/events` 的分析事件流
- **工具搜索**：在 Tools 选项卡中搜索关键词，快速定位工具
- **分页浏览**：Samples 支持翻页（默认每页 50 条）
- **自动刷新**：Overview 选项卡每 15 秒自动拉取最新数据

### Dashboard API

所有 Dashboard 数据均通过 JSON API 提供，方便自定义集成：

```bash
# 查看总览
curl http://localhost:18080/api/v1/dashboard/overview

# 查看所有工具
curl http://localhost:18080/api/v1/dashboard/tools

# 查看插件状态
curl http://localhost:18080/api/v1/dashboard/plugins

# 分页查看样本（limit/offset）
curl "http://localhost:18080/api/v1/dashboard/samples?limit=20&offset=0"

# 查看系统信息
curl http://localhost:18080/api/v1/dashboard/system

# 查看配置校验
curl http://localhost:18080/api/v1/dashboard/config
```

## MCP 客户端配置

### Claude Desktop

编辑 `~/.config/Claude/claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--network=none",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop=ALL",
        "-v",
        "${workspace}:/samples:ro",
        "-v",
        "~/.rikune/workspaces:/app/workspaces",
        "-v",
        "~/.rikune/data:/app/data",
        "rikune:latest"
      ]
    }
  }
}
```

### GitHub Copilot

编辑 `~/.config/github-copilot/mcp.json`：

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--network=none",
        "-v",
        "${workspaceFolder}:/samples:ro",
        "-v",
        "~/.rikune/workspaces:/app/workspaces",
        "rikune:latest"
      ]
    }
  }
}
```

### 通用 stdio 配置

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--network=none",
        "-v",
        "/path/to/samples:/samples:ro",
        "-v",
        "~/.rikune/workspaces:/app/workspaces",
        "rikune:latest"
      ]
    }
  }
}
```

完整配置示例见 [`docs/MCP-CLIENT-DOCKER-CONFIG.md`](./MCP-CLIENT-DOCKER-CONFIG.md)。

## 数据持久化

### 目录结构

```
~/.rikune/
├── workspaces/          # 样本工作空间
│   └── <sha256>/
│       ├── original/    # 原始样本
│       ├── cache/       # 分析缓存
│       ├── ghidra/      # Ghidra 输出
│       └── reports/     # 分析报告
├── data/                # SQLite 数据库
│   └── database.db
├── cache/               # 文件缓存
├── ghidra-projects/     # Ghidra 分析项目
├── ghidra-logs/         # Ghidra 运行日志
└── logs/                # MCP Server 日志
```

### 备份和恢复

```bash
# 备份所有数据
tar -czf mcp-data-backup.tar.gz \
  ~/.rikune/

# 恢复数据
tar -xzf mcp-data-backup.tar.gz \
  -C ~/
```

### 清理旧数据

```bash
# 清理缓存（安全）
docker run --rm \
  -v ~/.rikune/cache:/app/cache \
  rikune:latest \
  rm -rf /app/cache/*

# 清理 Ghidra 项目（谨慎）
rm -rf ~/.rikune/ghidra-projects/*
```

## 安全配置

### 推荐的安全选项

```bash
# 网络隔离
--network=none

# 只读文件系统
--read-only

# 临时文件
--tmpfs /tmp:rw,noexec,nosuid,size=512m

# 禁止提权
--security-opt no-new-privileges:true

# 删除所有能力
--cap-drop=ALL

# 资源限制
--memory=8g
--cpus=2
--pids-limit=100
```

### 安全级别对比

| 配置 | 网络 | 文件系统 | 能力 | 适用场景 |
|------|------|----------|------|----------|
| 严格 | none | read-only | drop ALL | 恶意软件分析 |
| 标准 | none | rw | drop ALL | 普通样本分析 |
| 宽松 | host | rw | default | 受信任样本 |

### 动态分析安全

```bash
# 安全模拟模式（推荐）
docker run --rm \
  --network=none \
  rikune:latest \
  node dist/index.js  # 使用 sandbox.execute mode=safe_simulation

# 实时分析模式（危险，需显式启用）
docker run --rm \
  --network=host \
  rikune:latest \
  node dist/index.js  # 使用 sandbox.execute mode=live_local
```

## 故障排除

### 容器无法启动

```bash
# 检查 Docker 状态
docker info

# 查看容器日志
docker run --rm rikune:latest node --version

# 检查镜像完整性
docker images rikune
```

### Ghidra 分析失败

```bash
# 验证 Ghidra 安装
docker run --rm \
  rikune:latest \
  /opt/ghidra/support/analyzeHeadless -help

# 检查 Java 版本和 JDK 工具链
docker run --rm \
  rikune:latest \
  bash -lc "java -version && javac -version"

# 查看 Ghidra 日志
cat ~/.rikune/ghidra-logs/*.log
```

### 权限问题

```bash
# 修复权限
sudo chown -R $(whoami):$(whoami) \
  ~/.rikune/

# 或重新创建目录
rm -rf ~/.rikune/
mkdir -p ~/.rikune/{workspaces,data,cache,ghidra-projects,ghidra-logs}
```

### 内存不足

```bash
# 增加内存限制
docker run --rm \
  --memory=8g \
  --cpus=4 \
  ...

# 减少并发分析数
# 在 config.json 中设置:
# "workers": { "ghidra": { "maxConcurrent": 2 } }
```

### MCP 通信失败

```bash
# 测试 stdio 通信
echo '{"jsonrpc":"2.0","method":"initialize","params":{}}' | \
  docker run -i --rm \
  rikune:latest \
  node dist/index.js

# 检查 MCP Server 日志
docker run --rm \
  -v ~/.rikune/logs:/app/logs \
  rikune:latest \
  tail -f /app/logs/*.log
```

## 高级用法

### 自定义 Ghidra 版本

```dockerfile
# Dockerfile
ARG GHIDRA_VERSION=11.2.1  # 修改为你需要的版本
```

### 轻量版镜像（不含 Ghidra）

```dockerfile
# Dockerfile.slim
FROM python:3.11-slim AS runtime
# ... 仅包含 Python 分析工具，不包含 Ghidra
```

```bash
# 构建轻量版
docker build -f Dockerfile.slim -t rikune:slim .
```

### CI/CD 集成

```yaml
# .github/workflows/analyze.yml
jobs:
  analyze:
    runs-on: ubuntu-latest
    container: rikune:latest
    steps:
      - uses: actions/checkout@v4
      - name: Analyze sample
        run: |
          echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"sample.ingest","arguments":{"path":"/samples/test.exe"}}}' | \
          node dist/index.js > result.json
```

### 批量分析

```bash
#!/bin/bash
# batch-analyze.sh
for sample in samples/*.exe; do
  docker run --rm -i \
    -v $(pwd)/samples:/samples:ro \
    -v $(pwd)/results:/app/reports \
    rikune:latest \
    node dist/index.js < request.json > results/$(basename $sample).json
done
```

### 性能调优

```bash
# 使用 Docker BuildKit 加速构建
export DOCKER_BUILDKIT=1
docker build -t rikune:latest .

# 使用 registry 镜像加速拉取
# /etc/docker/daemon.json
{
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn",
    "https://registry.docker-cn.com"
  ]
}
```

## 参考资源

- [Docker 官方文档](https://docs.docker.com/)
- [MCP Protocol 规范](https://modelcontextprotocol.io/)
- [Ghidra Headless 使用指南](https://ghidra-sre.org/InstallationGuide.html)
- [项目 README](../README.md)
- [MCP 客户端配置示例](./MCP-CLIENT-DOCKER-CONFIG.md)
