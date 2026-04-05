# Docker 一键安装指南

本文档说明如何使用一键安装脚本快速部署 Rikune。

## 快速开始

### 1. 运行安装脚本

以**管理员身份**打开 PowerShell，导航到项目目录，然后运行：

```powershell
.\install-docker.ps1
```

### 2. 按照提示操作

安装脚本会引导你完成以下步骤：

1. **检查 Docker 安装** - 自动检测 Docker Desktop 是否已安装并运行
2. **选择数据目录** - 选择数据存储位置（推荐选择空间充足的磁盘）
3. **创建目录结构** - 自动创建所有必需的目录
4. **构建 Docker 镜像** - 构建包含所有工具链的镜像（约 10-15 分钟）
5. **配置 MCP 客户端** - 选择要配置的 MCP 客户端（Claude Desktop/Copilot/Codex）
6. **测试安装** - 运行基础测试验证安装

### 3. 启动服务

安装完成后，使用快速启动脚本：

```powershell
.\start-docker.ps1
```

如果你在 MCP 客户端里使用已发布的 npm 包，推荐配置为：

```json
{
  "mcpServers": {
    "rikune": {
      "command": "npx",
      "args": ["-y", "rikune", "docker-stdio"]
    }
  }
}
```

这里的 `npx` 负责启动 MCP launcher，`docker compose` 启动的 `mcp-server` 容器负责真正的分析 runtime。

---

## API 文件服务器配置

Docker 部署默认启用 HTTP API 文件服务器，允许通过 HTTP API 上传和下载样本。

### 默认配置

- **API 端口**: 18080
- **API 地址**: `http://localhost:18080`
- **认证**: 可选（通过 `API_KEY` 环境变量配置）
- **存储路径**: `<DataRoot>/storage`

### 启用/禁用 API

在 `.env` 文件中配置：

```bash
# 启用 API（默认）
API_ENABLED=true

# API 端口
API_PORT=18080

# API Key（可选，不设置则无需认证）
API_KEY=your-secret-key-here

# 最大文件大小（默认 500MB）
API_MAX_FILE_SIZE=524288000

# 文件保留天数（默认 30 天）
API_RETENTION_DAYS=30
```

### 使用 API 上传样本

```bash
# 使用 curl 上传
curl -X POST http://localhost:18080/api/v1/samples \
  -H "X-API-Key: your-api-key" \
  -F "file=@sample.exe" \
  -F "filename=sample.exe"

# 使用 PowerShell 上传
.\scripts\upload-api.ps1 -Path "C:\path\to\sample.exe" -ApiKey "your-api-key"
```

### 使用 API 下载产物

```bash
# 下载产物
curl -H "X-API-Key: your-api-key" \
  -o artifact.json \
  "http://localhost:18080/api/v1/artifacts/artifact-id?download=true"

# 使用 PowerShell 下载
.\scripts\download-artifact.ps1 -ArtifactId "artifact-id" -ApiKey "your-api-key"
```

### 访问存储目录

样本和产物存储在 `<DataRoot>/storage` 目录：

```
<DataRoot>/storage/
├── samples/          # 样本文件（按日期分区）
├── artifacts/        # 分析产物
├── uploads/          # 临时上传文件
└── .metadata/        # 元数据日志
```

---

## 安装脚本参数

### 基本用法

```powershell
# 交互式安装（推荐）
.\install-docker.ps1

# 指定数据根目录（非交互式）
.\install-docker.ps1 -DataRoot "D:\Docker\rikune"

# 跳过镜像构建（用于重新配置）
.\install-docker.ps1 -SkipBuild

# 详细输出模式
.\install-docker.ps1 -Verbose

# 使用代理（自动检测系统代理）
.\install-docker.ps1 -UseProxy

# 手动指定代理地址
.\install-docker.ps1 -HttpProxy "http://127.0.0.1:7890" -HttpsProxy "http://127.0.0.1:7890"
```

### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `-DataRoot` | string | 用户选择 | 数据根目录路径 |
| `-ProjectRoot` | string | 脚本所在目录 | 项目根目录 |
| `-SkipBuild` | switch | false | 跳过 Docker 镜像构建 |
| `-Verbose` | switch | false | 启用详细输出 |
| `-UseProxy` | switch | false | 使用代理（自动检测或手动输入） |
| `-HttpProxy` | string | 自动检测 | HTTP 代理地址 |
| `-HttpsProxy` | string | 自动检测 | HTTPS 代理地址 |

---

## 快速启动脚本参数

### 基本用法

```powershell
# 使用默认配置启动
.\start-docker.ps1

# 指定数据根目录
.\start-docker.ps1 -DataRoot "D:\Docker\rikune"

# 使用 Docker Compose 模式
.\start-docker.ps1 -Mode compose

# 交互模式（调试用）
.\start-docker.ps1 -Mode interactive
```

### 启动模式

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `stdio` | MCP stdio 模式（默认） | MCP 客户端调用 |
| `compose` | Docker Compose 模式 | 后台服务运行 |
| `interactive` | 交互模式 | 调试和故障排除 |

---

## 数据目录结构

安装脚本会创建以下目录结构：

```
D:\Docker\rikune\
├── samples/              # 待分析的样本文件（只读挂载）
├── workspaces/           # 分析工作空间
│   └── <sha256>/
│       ├── original/     # 原始样本副本
│       ├── cache/        # 分析缓存
│       ├── ghidra/       # Ghidra 输出
│       └── reports/      # 分析报告
├── data/                 # SQLite 数据库
│   └── database.db
├── cache/                # 文件缓存
├── ghidra-projects/      # Ghidra 分析项目（可能很大）
├── ghidra-logs/          # Ghidra 运行日志
├── logs/                 # MCP Server 日志
└── config/               # 配置文件
    ├── config.json       # 服务器配置
    ├── install-info.json # 安装信息
    └── mcp-client-config.json  # MCP 客户端配置
```

---

## 代理配置

### 为什么需要代理？

在中国大陆或其他网络受限地区，以下资源可能下载缓慢或失败：

- **Docker Hub 镜像** - 基础镜像拉取
- **Ghidra** - 约 600MB，从 GitHub 下载
- **Python/Node.js 依赖** - 部分包从国外源下载

### 代理配置方式

#### 方式 1: 交互式配置（推荐）

运行安装脚本时会自动询问：

```powershell
.\install-docker.ps1
```

脚本会：
1. 自动检测系统代理
2. 提供常用代理工具的预设（Clash/V2Ray/Shadowsocks）
3. 测试代理连通性
4. 将代理配置应用到 Docker 构建和运行

#### 方式 2: 命令行指定

```powershell
# 使用 Clash 代理（默认端口 7890）
.\install-docker.ps1 -HttpProxy "http://127.0.0.1:7890" -HttpsProxy "http://127.0.0.1:7890"

# 使用 V2Ray 代理（默认端口 10809）
.\install-docker.ps1 -HttpProxy "http://127.0.0.1:10809" -HttpsProxy "http://127.0.0.1:10809"

# 使用带认证的代理
.\install-docker.ps1 -HttpProxy "http://user:pass@127.0.0.1:7890" -HttpsProxy "http://user:pass@127.0.0.1:7890"
```

#### 方式 3: 使用系统代理

```powershell
# 自动使用 Windows 系统代理设置
.\install-docker.ps1 -UseProxy
```

### 常用代理工具端口

| 代理工具 | HTTP 端口 | HTTPS 端口 | 说明 |
|---------|----------|-----------|------|
| Clash | 7890 | 7890 | 推荐，支持规则分流 |
| V2Ray | 10809 | 10809 | 需要 V2Ray 客户端 |
| Shadowsocks | 1080 | 1080 | 传统代理工具 |
| Trojan | 1080 | 1080 | 基于 TLS 的代理 |

### Docker 代理配置文件

安装脚本会自动创建 Docker 代理配置：

```json
// %USERPROFILE%\.docker\config.json
{
  "proxies": {
    "default": {
      "httpProxy": "http://127.0.0.1:7890",
      "httpsProxy": "http://127.0.0.1:7890"
    }
  }
}
```

这将使所有 Docker 容器都使用配置的代理。

### 手动配置 Docker 代理

如果安装时未配置代理，可以手动配置：

```powershell
# 创建或编辑 Docker 配置
notepad "$env:USERPROFILE\.docker\config.json"

# 添加以下内容：
{
  "proxies": {
    "default": {
      "httpProxy": "http://127.0.0.1:7890",
      "httpsProxy": "http://127.0.0.1:7890"
    }
  }
}

# 重启 Docker Desktop
```

### 代理故障排除

#### 测试代理是否工作

```powershell
# 测试代理连通性
$proxy = "http://127.0.0.1:7890"
$env:HTTP_PROXY = $proxy
$env:HTTPS_PROXY = $proxy

# 测试 Google
try {
    Invoke-WebRequest -Uri "https://www.google.com" -TimeoutSec 5 -UseBasicParsing
    Write-Host "代理工作正常" -ForegroundColor Green
} catch {
    Write-Host "代理无法连接" -ForegroundColor Red
}
```

#### Docker 构建使用代理

```powershell
# 临时设置代理
$env:HTTP_PROXY="http://127.0.0.1:7890"
$env:HTTPS_PROXY="http://127.0.0.1:7890"

# 构建时传递代理参数
docker build `
  --build-arg HTTP_PROXY=$env:HTTP_PROXY `
  --build-arg HTTPS_PROXY=$env:HTTPS_PROXY `
  -t rikune:latest .
```

#### 常见问题

**Q: 配置代理后仍然下载缓慢？**

A: 检查代理是否支持目标网站：
```powershell
# 测试 GitHub 访问
curl -I https://github.com

# 测试 Docker Hub 访问
curl -I https://hub.docker.com
```

**Q: 代理认证失败？**

A: 在代理地址中包含用户名和密码：
```powershell
.\install-docker.ps1 `
  -HttpProxy "http://username:password@127.0.0.1:7890" `
  -HttpsProxy "http://username:password@127.0.0.1:7890"
```

**Q: 如何禁用代理？**

A: 删除或重命名 Docker 配置文件：
```powershell
# 重命名配置文件（备份）
Rename-Item "$env:USERPROFILE\.docker\config.json" "config.json.bak"

# 重启 Docker Desktop
```

---

## 系统要求

### 硬件要求

- **CPU**: 4 核心以上（推荐 8 核心）
- **内存**: 8GB 以上（推荐 16GB）
- **磁盘**: 至少 15GB 可用空间
  - Docker 镜像：~2.5GB
  - Ghidra 项目：可变（每个样本 100MB-1GB）
  - 分析数据：可变

### 软件要求

- **操作系统**: Windows 10/11 64 位
- **Docker**: Docker Desktop 20.10+ with WSL2
- **PowerShell**: 5.1+（推荐 7+）

---

## 常见问题

### Q1: 脚本提示"需要管理员权限"

**A**: 右键点击 PowerShell，选择"以管理员身份运行"，然后重新执行脚本。

```powershell
# 或者使用以下命令提升权限
Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; .\install-docker.ps1"
```

---

### Q2: Docker 镜像构建失败

**A**: 可能原因：

1. **网络问题**（Ghidra 下载失败）
   ```powershell
   # 使用国内镜像源
   # 编辑 Dockerfile，修改 Ghidra 下载 URL 为国内镜像
   ```

2. **磁盘空间不足**
   ```powershell
   # 检查可用空间
   Get-PSDrive -PSProvider FileSystem
   
   # 清理 Docker 缓存
   docker system prune -af
   ```

3. **Docker 未运行**
   ```powershell
   # 启动 Docker Desktop
   Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
   ```

---

### Q3: 想更改数据目录位置

**A**: 重新运行安装脚本，选择新的数据目录：

```powershell
.\install-docker.ps1 -SkipBuild
```

然后手动更新 MCP 客户端配置中的路径。

---

### Q4: MCP 客户端无法连接

**A**: 检查配置：

1. **验证配置文件位置**
   - Claude Desktop: `%APPDATA%\Claude\claude_desktop_config.json`
   - GitHub Copilot: `%APPDATA%\GitHub Copilot\mcp.json`
   - Codex: `%USERPROFILE%\.codex\mcp.json`

2. **测试 Docker 镜像**
   ```powershell
   docker run --rm rikune:latest node --version
   ```

3. **测试 stdio 通信**
   ```powershell
   echo '{"jsonrpc":"2.0","method":"initialize","params":{}}' | `
     docker run -i --rm rikune:latest node dist/index.js
   ```

---

### Q5: 如何卸载

**A**: 执行以下步骤：

```powershell
# 1. 停止所有容器
docker-compose down  # 如果使用 Compose
docker stop $(docker ps -aq)  # 停止所有容器

# 2. 删除镜像
docker rmi rikune:latest

# 3. 删除数据（谨慎！这会删除所有分析数据）
Remove-Item -Recurse -Force "D:\Docker\rikune"

# 4. 删除 MCP 客户端配置
Remove-Item "$env:APPDATA\Claude\claude_desktop_config.json" -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\GitHub Copilot\mcp.json" -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\.codex\mcp.json" -ErrorAction SilentlyContinue
```

---

## 高级用法

### 自定义 Docker 构建参数

```powershell
# 不使用缓存构建
docker build --no-cache -t rikune:latest .

# 多平台构建
docker buildx build --platform linux/amd64,linux/arm64 -t rikune:latest .

# 构建时设置变量
docker build --build-arg GHIDRA_VERSION=11.2.1 -t rikune:latest .
```

### 批量部署

```powershell
# 在多台机器上部署
$servers = @("server1", "server2", "server3")
foreach ($server in $servers) {
    Invoke-Command -ComputerName $server -ScriptBlock {
        param($dataRoot)
        Set-Location "C:\MCP-Server"
        .\install-docker.ps1 -DataRoot $dataRoot -SkipBuild
    } -ArgumentList "\\$server\Docker\MCP-Data"
}
```

### 自动化测试

```powershell
# 运行安装后测试
.\start-docker.ps1 -Mode interactive -Command "
    node --version;
    python3 --version;
    java -version;
    /opt/ghidra/support/analyzeHeadless -help
"
```

---

## 参考资源

- [Docker 官方文档](https://docs.docker.com/)
- [Docker Desktop for Windows](https://docs.docker.com/desktop/windows/)
- [WSL2 安装指南](https://docs.microsoft.com/windows/wsl/install)
- [项目 Docker 文档](./docs/DOCKER.md)
- [故障排除指南](./docs/DOCKER-TROUBLESHOOTING.md)

---

## 获取帮助

如果遇到问题：

1. **查看安装日志**: `$DataRoot\logs\install.log`
2. **查看 Docker 日志**: `docker logs <container-id>`
3. **提交 Issue**: https://github.com/Last-emo-boy/rikune/issues
4. **查看讨论区**: https://github.com/Last-emo-boy/rikune/discussions
