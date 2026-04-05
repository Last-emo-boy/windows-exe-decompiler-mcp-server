# Docker 环境下样本上传指南

## 问题说明

MCP Server 运行在 Docker 容器内，无法直接访问宿主机文件系统。需要通过 volume 挂载来传递样本文件。

## 解决方案

### 方案 1: 使用挂载目录（推荐）

#### 1. 放置样本到挂载目录

将样本文件复制到 Docker volume 挂载的目录：

```powershell
# Windows PowerShell
Copy-Item "C:\path\to\sample.exe" "D:\Docker\rikune\samples\sample.exe"
```

或者使用 `docker cp`：

```powershell
docker cp "C:\path\to\sample.exe" rikune:/samples/sample.exe
```

#### 2. 调用 MCP 工具

使用容器内路径调用 `sample.ingest`：

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/samples/sample.exe",
    "filename": "malware.exe",
    "source": "upload"
  }
}
```

---

### 方案 2: 使用 Base64 编码（适合小文件）

对于小文件（< 10MB），可以直接传递 Base64 编码：

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "bytes_b64": "TVqQAAMAAAAEAAAA...",
    "filename": "sample.exe",
    "source": "upload"
  }
}
```

---

### 方案 3: 使用辅助脚本（最方便）

创建 PowerShell 辅助函数：

```powershell
function Invoke-SampleIngest {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SamplePath,
        
        [string]$Filename,
        
        [string]$Source = "upload"
    )
    
    # 检查文件是否存在
    if (-not (Test-Path $SamplePath)) {
        Write-Error "Sample file not found: $SamplePath"
        return
    }
    
    # 获取文件名
    if (-not $Filename) {
        $Filename = Split-Path $SamplePath -Leaf
    }
    
    # 复制到挂载目录
    $samplesDir = "D:\Docker\rikune\samples"
    if (-not (Test-Path $samplesDir)) {
        New-Item -ItemType Directory -Path $samplesDir -Force | Out-Null
    }
    
    $destPath = Join-Path $samplesDir $Filename
    Copy-Item $SamplePath -Destination $destPath -Force
    
    Write-Host "✓ Sample copied to: $destPath" -ForegroundColor Green
    
    # 返回容器内路径
    return "/samples/$Filename"
}

# 使用示例
$containerPath = Invoke-SampleIngest -SamplePath "C:\malware\suspicious.exe"
# 然后在 Qwen 中使用返回的路径调用 sample.ingest
```

---

## Qwen Code 集成

### 创建 Qwen Skill

在 `~/.qwen/skills/upload-sample/` 创建：

**skill.json**:
```json
{
  "name": "upload-sample",
  "description": "Upload a sample file to the Docker container for analysis",
  "version": "1.0.0"
}
```

**index.js**:
```javascript
const { execSync } = require('child_process');
const path = require('path');

module.exports = {
  name: 'upload-sample',
  description: 'Upload a sample file to Docker container',
  execute: async (params) => {
    const { samplePath } = params;
    
    if (!samplePath) {
      return { error: 'samplePath is required' };
    }
    
    const samplesDir = 'D:\\Docker\\rikune\\samples';
    const filename = path.basename(samplePath);
    
    // Copy file to mounted directory
    execSync(`Copy-Item "${samplePath}" -Destination "${samplesDir}\\${filename}" -Force`, {
      shell: 'powershell'
    });
    
    return {
      success: true,
      containerPath: `/samples/${filename}`,
      message: `Sample uploaded. Use path: /samples/${filename} in sample.ingest`
    };
  }
};
```

---

## 完整工作流示例

### 1. 上传样本

```powershell
# 复制样本到挂载目录
Copy-Item "C:\malware\suspicious.exe" "D:\Docker\rikune\samples\suspicious.exe"
```

### 2. 在 Qwen 中调用

告诉 Qwen：

```
使用 sample.ingest 工具分析 /samples/suspicious.exe
```

或者直接使用工具调用：

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/samples/suspicious.exe",
    "filename": "suspicious.exe",
    "source": "manual_upload"
  }
}
```

### 3. 执行分析

```
使用 workflow.triage 分析这个样本
```

---

## 故障排除

### 问题 1: 文件权限

确保 Docker 有权限访问挂载目录：

```powershell
# 检查目录权限
Get-Acl "D:\Docker\rikune\samples" | Format-List
```

### 问题 2: 容器未挂载 samples

检查 docker-compose.yml：

```yaml
volumes:
  - ./samples:/samples:ro
```

确认挂载：

```powershell
docker inspect rikune --format '{{ json .Mounts }}' | jq
```

### 问题 3: 文件太大

对于大文件（> 100MB），建议：

1. 使用方案 1（挂载目录）
2. 避免使用 Base64 编码
3. 考虑压缩文件

---

## 自动化脚本

创建 `scripts/upload-sample.ps1`：

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    
    [string]$OutputFormat = "path"  # "path" or "json"
)

$samplesDir = "D:\Docker\rikune\samples"
$filename = Split-Path $Path -Leaf

# Ensure directory exists
if (-not (Test-Path $samplesDir)) {
    New-Item -ItemType Directory -Path $samplesDir -Force | Out-Null
}

# Copy file
Copy-Item $Path -Destination "$samplesDir\$filename" -Force

if ($OutputFormat -eq "json") {
    # Output JSON for direct use in MCP call
    @{
        path = "/samples/$filename"
        filename = $filename
    } | ConvertTo-Json
} else {
    Write-Output "/samples/$filename"
}
```

使用：

```powershell
# 获取容器内路径
$containerPath = .\scripts\upload-sample.ps1 -Path "C:\malware\sample.exe"

# 或者获取 JSON
$json = .\scripts\upload-sample.ps1 -Path "C:\malware\sample.exe" -OutputFormat json
```

---

## 总结

| 方法 | 适用场景 | 优点 | 缺点 |
|------|---------|------|------|
| **挂载目录** | 所有文件 | 简单、快速、支持大文件 | 需要手动复制 |
| **Base64** | 小文件（< 10MB） | 无需复制 | 编码慢、占用内存 |
| **辅助脚本** | 频繁上传 | 自动化、方便 | 需要额外脚本 |

**推荐**: 使用挂载目录方式，配合辅助脚本自动化。
