# Docker 环境下直接上传样本

## ✨ 最简单的方式

### 一键上传

```powershell
# 方式 1: 使用快捷脚本
.\scripts\upload.ps1 "C:\path\to\sample.exe"

# 方式 2: 使用完整脚本
.\scripts\upload-sample-direct.ps1 -Path "C:\path\to\sample.exe"
```

**自动完成以下步骤：**
1. ✅ 检查容器是否运行（未运行则自动启动）
2. ✅ 直接上传文件到容器内 `/samples/` 目录
3. ✅ 返回 MCP 调用 JSON，可直接使用

---

## 🚀 使用示例

### 示例 1: 快速上传

```powershell
# 上传样本
.\scripts\upload.ps1 "C:\Downloads\suspicious.exe"
```

输出：
```
========================================
  Direct Sample Upload to Docker
========================================

File: suspicious.exe
Size: 256.5 KB

Checking container status...
✓ Container is running

Uploading sample to container...
✓ Sample uploaded successfully

Container path: /samples/suspicious.exe

Ready-to-use MCP Call:

{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/samples/suspicious.exe",
    "filename": "suspicious.exe",
    "source": "direct_upload"
  }
}
```

### 示例 2: 获取 JSON 输出

```powershell
# 获取 JSON 格式，方便集成到自动化流程
.\scripts\upload-sample-direct.ps1 -Path "C:\sample.exe" -OutputFormat json
```

---

## 📋 完整的 MCP 工作流

### 步骤 1: 上传样本

```powershell
.\scripts\upload.ps1 "C:\malware\suspicious.dll"
```

### 步骤 2: 在 Qwen 中调用

复制输出的 JSON，在 Qwen 中说：

```
调用 sample.ingest 工具分析这个样本
```

或者直接告诉 Qwen：

```
使用 sample.ingest 分析 /samples/suspicious.dll
```

### 步骤 3: 执行分析

```
使用 workflow.triage 分析这个样本
```

---

## 🔧 高级用法

### 批量上传

```powershell
# 上传多个样本
Get-ChildItem "C:\samples\*.exe" | ForEach-Object {
    .\scripts\upload.ps1 $_.FullName
}
```

### 大文件上传（> 100MB）

```powershell
# 脚本会自动处理大文件，无需特殊配置
.\scripts\upload-sample-direct.ps1 -Path "C:\large_sample.dll"
```

---

## 📊 上传方式对比

| 方式 | 命令 | 适用场景 |
|------|------|---------|
| **直接上传** | `.\scripts\upload.ps1 "..."` | ✅ 推荐，最简单 |
| 挂载目录 | `Copy-Item ... D:\Docker\...\samples\` | 批量上传 |
| docker cp | `docker cp ... container:/samples/` | 熟悉 Docker 用户 |
| Base64 | `bytes_b64: "..."` | 小文件（< 10MB） |

---

## ⚠️ 注意事项

### 文件大小限制

- **推荐**: < 500MB
- **支持**: 最大 500MB（由 MCP Server 配置决定）

### 容器状态

脚本会自动检查并启动容器，但需要 Docker Desktop 正在运行。

### 权限问题

确保 PowerShell 有权限读取样本文件。

---

## 🔍 故障排除

### 问题 1: 容器未运行

```powershell
# 手动启动容器
docker-compose up -d

# 然后重新上传
.\scripts\upload.ps1 "C:\sample.exe"
```

### 问题 2: 上传失败

```powershell
# 检查容器日志
docker-compose logs mcp-server

# 重启容器
docker-compose restart
```

### 问题 3: 文件不存在

```powershell
# 验证文件路径
Test-Path "C:\sample.exe"

# 使用绝对路径
.\scripts\upload.ps1 "C:\full\path\to\sample.exe"
```

---

## 📦 脚本说明

### upload.ps1

**快捷脚本**，一键上传并返回 MCP 调用格式。

**参数**:
- `Path` (必需): 样本文件路径

**示例**:
```powershell
.\scripts\upload.ps1 "C:\sample.exe"
```

### upload-sample-direct.ps1

**完整脚本**，提供更多选项。

**参数**:
- `Path` (必需): 样本文件路径
- `OutputFormat` (可选): `path`, `json`, `mcp`（默认：`path`）

**示例**:
```powershell
# 简单上传
.\scripts\upload-sample-direct.ps1 -Path "C:\sample.exe"

# 获取 JSON 输出
.\scripts\upload-sample-direct.ps1 -Path "C:\sample.exe" -OutputFormat json

# 获取 MCP 调用格式
.\scripts\upload-sample-direct.ps1 -Path "C:\sample.exe" -OutputFormat mcp
```

---

## 🎯 最佳实践

1. **使用 upload.ps1** - 最简单，一键完成
2. **大文件使用直接上传** - 避免 Base64 编码开销
3. **批量上传使用循环** - 自动化工作流
4. **保存上传路径** - 方便后续分析调用

---

现在你可以**直接上传样本**到 Docker 容器，无需手动复制文件！🎉
