# 使用指南

> 注意
>
> 本文档包含较早期的逐工具说明，仍可作为字段参考，但当前推荐的主调用模式已经切换为 staged runtime：
>
> - `workflow.analyze.start`
> - `workflow.analyze.status`
> - `workflow.analyze.promote`
>
> 先阅读 [ANALYSIS-RUNTIME.md](./ANALYSIS-RUNTIME.md) 和 [ASYNC-JOB-PATTERN.md](./ASYNC-JOB-PATTERN.md)，再把本页当作补充字段手册使用。

本文档详细介绍 Rikune V0.1 的所有工具和功能。

## 目录

- [工具概览](#工具概览)
- [样本管理工具](#样本管理工具)
- [PE 分析工具](#pe-分析工具)
- [静态分析工具](#静态分析工具)
- [工作流工具](#工作流工具)
- [报告工具](#报告工具)
- [错误处理](#错误处理)

## 工具概览

V0.1 提供以下 12 个 MCP Tools:

| 工具名称 | 功能 | 平均耗时 |
|---------|------|---------|
| `sample.ingest` | 摄入样本到系统 | < 1s |
| `sample.profile.get` | 获取样本基础信息 | < 0.1s |
| `pe.fingerprint` | 提取 PE 文件指纹 | < 0.5s |
| `pe.imports.extract` | 提取导入表 | < 0.5s |
| `pe.exports.extract` | 提取导出表 | < 0.5s |
| `strings.extract` | 提取字符串 | 1-2s |
| `strings.floss.decode` | FLOSS 解码混淆字符串 | 10-60s |
| `yara.scan` | YARA 规则扫描 | 3-30s |
| `runtime.detect` | 检测运行时类型 | < 1s |
| `packer.detect` | 检测加壳器 | 2-5s |
| `workflow.triage` | 快速画像工作流 | 2-5 分钟 |
| `report.summarize` | 生成分析报告 | < 1s |

## 样本管理工具

### sample.ingest

**功能**: 上传并注册新样本到系统

**输入参数**:

```typescript
{
  // 必需：以下二选一
  "path"?: string,           // 本地文件路径
  "bytes_b64"?: string,      // Base64 编码的文件内容
  
  // 可选
  "filename"?: string,       // 原始文件名
  "source"?: string          // 样本来源标签（如 "email", "download"）
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "sample_id": string,     // 格式: "sha256:<hex>"
    "size": number,          // 文件大小（字节）
    "file_type": string,     // 文件类型（如 "PE32 executable"）
    "existed": boolean       // 是否已存在（去重）
  }
}
```

**使用示例**:

```json
// 通过本地路径摄入
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/tmp/suspicious.exe",
    "filename": "malware.exe",
    "source": "email_attachment"
  }
}

// 通过 Base64 内容摄入
{
  "tool": "sample.ingest",
  "arguments": {
    "bytes_b64": "TVqQAAMAAAAEAAAA...",
    "filename": "sample.exe",
    "source": "upload"
  }
}
```

**注意事项**:
- 样本大小限制：默认 500MB
- 自动 SHA256 去重：相同文件只存储一次
- 自动创建独立 workspace
- 记录审计日志

---

### sample.profile.get

**功能**: 获取样本的基础信息和分析历史

**输入参数**:

```typescript
{
  "sample_id": string        // 样本 ID（格式: "sha256:<hex>"）
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "sample": {
      "id": string,
      "sha256": string,
      "md5": string,
      "size": number,
      "file_type": string,
      "created_at": string,
      "source": string
    },
    "analyses": [
      {
        "id": string,
        "stage": string,       // "fingerprint", "strings", "yara", etc.
        "backend": string,
        "status": string,      // "done", "failed", "running"
        "started_at": string,
        "finished_at": string
      }
    ]
  }
}
```

**使用示例**:

```json
{
  "tool": "sample.profile.get",
  "arguments": {
    "sample_id": "sha256:abc123..."
  }
}
```

## PE 分析工具

### pe.fingerprint

**功能**: 提取 PE 文件的基础特征和指纹信息

**输入参数**:

```typescript
{
  "sample_id": string,
  "fast"?: boolean           // 快速模式（默认 false）
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "sha256": string,
    "md5": string,
    "imphash": string,       // 导入表哈希
    "machine": string,       // 机器类型（如 "I386", "AMD64"）
    "subsystem": string,     // 子系统（如 "WINDOWS_GUI", "WINDOWS_CUI"）
    "timestamp": string,     // 编译时间戳
    "is_dll": boolean,
    "is_64bit": boolean,
    
    // 仅 fast=false 时包含
    "sections"?: [
      {
        "name": string,
        "virtual_size": number,
        "raw_size": number,
        "entropy": number    // 节区熵值（0-8）
      }
    ],
    "signature"?: {
      "signed": boolean,
      "valid": boolean,
      "signer": string
    }
  }
}
```

**使用示例**:

```json
// 快速模式
{
  "tool": "pe.fingerprint",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "fast": true
  }
}

// 完整模式（包含节区熵值和签名）
{
  "tool": "pe.fingerprint",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "fast": false
  }
}
```

**注意事项**:
- 快速模式耗时 < 0.5s，完整模式耗时 1-2s
- 结果自动缓存（TTL: 30 天）
- 如果 pefile 解析失败，自动尝试 LIEF 备用解析器

---

### pe.imports.extract

**功能**: 提取 PE 文件的导入表（DLL 和函数）

**输入参数**:

```typescript
{
  "sample_id": string,
  "group_by_dll"?: boolean   // 按 DLL 分组（默认 true）
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    // group_by_dll=true 时
    "kernel32.dll": ["CreateFileA", "ReadFile", "WriteFile"],
    "user32.dll": ["MessageBoxA", "CreateWindowExA"],
    
    // group_by_dll=false 时
    "imports": [
      {
        "dll": "kernel32.dll",
        "function": "CreateFileA",
        "ordinal": null,
        "delayed": false
      }
    ]
  }
}
```

**使用示例**:

```json
{
  "tool": "pe.imports.extract",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "group_by_dll": true
  }
}
```

**注意事项**:
- 自动识别延迟加载 DLL（标记 `delayed: true`）
- 自动解析转发器（forwarder）
- 结果缓存

---

### pe.exports.extract

**功能**: 提取 PE 文件的导出表

**输入参数**:

```typescript
{
  "sample_id": string
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "exports": [
      {
        "name": string,      // 导出函数名
        "ordinal": number,   // 序号
        "address": string    // RVA 地址（十六进制）
      }
    ]
  }
}
```

**使用示例**:

```json
{
  "tool": "pe.exports.extract",
  "arguments": {
    "sample_id": "sha256:abc123..."
  }
}
```

## 静态分析工具

### strings.extract

**功能**: 提取程序中的可读字符串（ASCII 和 Unicode）

**输入参数**:

```typescript
{
  "sample_id": string,
  "min_len"?: number,        // 最小字符串长度（默认 4）
  "encoding"?: string        // 编码类型："ascii" | "unicode" | "all"（默认）
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "strings": [
      {
        "value": string,     // 字符串内容
        "offset": number,    // 文件偏移量
        "encoding": string   // "ascii" | "utf-16le"
      }
    ],
    "count": number
  }
}
```

**使用示例**:

```json
{
  "tool": "strings.extract",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "min_len": 6,
    "encoding": "all"
  }
}
```

**注意事项**:
- 支持 ASCII、UTF-16LE、UTF-8、GBK 编码
- 较大文件（> 10MB）可能耗时较长
- 结果缓存

---

### strings.floss.decode

**功能**: 使用 FLOSS 工具解码混淆和加密的字符串

**输入参数**:

```typescript
{
  "sample_id": string,
  "timeout_sec"?: number     // 超时时间（默认 60 秒）
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "decoded_strings": [
      {
        "value": string,
        "method": string,    // 解码方法（如 "stack", "tight"）
        "address": string
      }
    ],
    "static_strings": [...], // 静态字符串
    "stack_strings": [...]   // 栈字符串
  },
  "warnings": string[]       // 如果超时，包含警告信息
}
```

**使用示例**:

```json
{
  "tool": "strings.floss.decode",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "timeout_sec": 120
  }
}
```

**注意事项**:
- FLOSS 分析耗时较长（10-60 秒）
- 超时后返回部分结果
- 适用于混淆严重的样本

---

### yara.scan

**功能**: 使用 YARA 规则扫描样本，识别恶意软件家族和加壳器

**输入参数**:

```typescript
{
  "sample_id": string,
  "rule_set": string,        // 规则集名称
  "timeout_ms"?: number      // 超时时间（默认 30000 毫秒）
}
```

**可用规则集**:
- `malware_families` - 恶意软件家族规则
- `packers` - 加壳器检测规则
- `capabilities` - 行为能力规则
- `all` - 所有规则

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "matches": [
      {
        "rule": string,      // 规则名称
        "tags": string[],    // 标签
        "meta": {            // 元数据
          "description": string,
          "author": string,
          "date": string
        },
        "strings": [         // 匹配的字符串
          {
            "offset": number,
            "identifier": string,
            "data": string
          }
        ]
      }
    ],
    "ruleset_version": string
  }
}
```

**使用示例**:

```json
{
  "tool": "yara.scan",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "rule_set": "malware_families",
    "timeout_ms": 30000
  }
}
```

**注意事项**:
- 规则集版本影响缓存失效
- 超时后返回已匹配的规则
- 结果缓存

---

### runtime.detect

**功能**: 自动检测程序的运行时类型（.NET、C++、Go 等）

**输入参数**:

```typescript
{
  "sample_id": string
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "is_dotnet": boolean,
    "dotnet_version"?: string,     // 如 "v4.0.30319"
    "target_framework"?: string,   // 如 ".NETFramework,Version=v4.5"
    "suspected": [
      {
        "runtime": string,         // "cpp", "go", "rust", etc.
        "confidence": number,      // 0.0 - 1.0
        "evidence": string[]       // 证据（如导入的 DLL）
      }
    ]
  }
}
```

**使用示例**:

```json
{
  "tool": "runtime.detect",
  "arguments": {
    "sample_id": "sha256:abc123..."
  }
}
```

**检测逻辑**:
- .NET: 检查 CLR 头部和 `mscoree.dll` 导入
- C++: 检查 MSVC 运行时 DLL（`msvcp*.dll`, `vcruntime*.dll`）
- Go: 检查 Go 特征字符串和节区名
- Rust: 检查 Rust 特征符号

---

### packer.detect

**功能**: 检测程序是否加壳及加壳器类型

**输入参数**:

```typescript
{
  "sample_id": string
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "is_packed": boolean,
    "packers": [
      {
        "name": string,          // 加壳器名称（如 "UPX", "Themida"）
        "confidence": number,    // 0.0 - 1.0
        "method": string         // 检测方法（"yara", "entropy", "entry_point"）
      }
    ],
    "entropy": {
      "average": number,         // 平均熵值
      "max": number,             // 最大熵值
      "suspicious_sections": [   // 可疑节区
        {
          "name": string,
          "entropy": number
        }
      ]
    },
    "entry_point": {
      "section": string,
      "is_suspicious": boolean   // 入口点是否在非标准节区
    }
  }
}
```

**使用示例**:

```json
{
  "tool": "packer.detect",
  "arguments": {
    "sample_id": "sha256:abc123..."
  }
}
```

**检测方法**:
1. YARA 规则匹配（最准确）
2. 节区熵值分析（熵值 > 7.0 可疑）
3. 入口点位置检查（非 `.text` 节区可疑）

## 工作流工具

### workflow.triage

**功能**: 快速画像工作流，5 分钟内完成基础威胁评估

**输入参数**:

```typescript
{
  "sample_id": string
}
```

**执行步骤**:
1. PE 指纹提取（fast 模式）
2. 运行时检测
3. 导入表提取
4. 字符串提取（min_len=6）
5. YARA 扫描（malware_families 规则集）
6. 加壳器检测
7. 生成结构化摘要

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "summary": string,           // 威胁摘要
    "confidence": number,        // 置信度（0.0 - 1.0）
    "threat_level": string,      // "low" | "medium" | "high" | "critical"
    "iocs": {
      "suspicious_imports": string[],
      "suspicious_strings": string[],
      "yara_matches": string[],
      "network_indicators": string[]
    },
    "evidence": string[],        // 证据列表
    "recommendation": string,    // 建议
    "results": {                 // 各步骤的详细结果
      "fingerprint": {...},
      "runtime": {...},
      "imports": {...},
      "strings": {...},
      "yara": {...},
      "packer": {...}
    }
  }
}
```

**使用示例**:

```json
{
  "tool": "workflow.triage",
  "arguments": {
    "sample_id": "sha256:abc123..."
  }
}
```

**威胁评估逻辑**:

| 威胁等级 | 条件 |
|---------|------|
| Critical | YARA 匹配已知恶意家族 + 可疑导入 |
| High | 可疑导入 + 可疑字符串 + 加壳 |
| Medium | 可疑导入或可疑字符串 |
| Low | 无明显威胁特征 |

**注意事项**:
- 目标完成时间：2-5 分钟
- 自动缓存所有中间结果
- 适合批量样本初步筛选

## 报告工具

### report.summarize

**功能**: 生成分析报告摘要

**输入参数**:

```typescript
{
  "sample_id": string,
  "mode"?: string              // "triage" | "full"（默认 "triage"）
}
```

**输出**:

```typescript
{
  "ok": boolean,
  "data": {
    "sample_id": string,
    "generated_at": string,
    "mode": string,
    "summary": {
      "threat_assessment": string,
      "key_findings": string[],
      "iocs": {...},
      "recommendations": string[]
    },
    "details": {
      // 包含所有已完成分析的详细结果
    }
  }
}
```

**使用示例**:

```json
{
  "tool": "report.summarize",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "mode": "triage"
  }
}
```

## 错误处理

### 错误类型

所有工具返回统一的错误格式:

```typescript
{
  "ok": false,
  "errors": [
    {
      "code": string,          // 错误代码
      "message": string,       // 错误信息
      "category": string       // 错误类别
    }
  ],
  "warnings": string[]         // 警告信息（可选）
}
```

### 常见错误代码

| 错误代码 | 含义 | 可重试 |
|---------|------|--------|
| `E_NOT_FOUND` | 样本不存在 | 否 |
| `E_INVALID_INPUT` | 输入参数无效 | 否 |
| `E_PARSE_PE` | PE 文件解析失败 | 否 |
| `E_TIMEOUT` | 操作超时 | 是 |
| `E_WORKER_UNAVAILABLE` | Worker 不可用 | 是 |
| `E_POLICY_DENY` | 策略拒绝 | 否 |
| `E_RESOURCE_EXHAUSTED` | 资源耗尽 | 是 |

### 错误处理示例

```typescript
// 处理样本不存在错误
{
  "ok": false,
  "errors": [
    {
      "code": "E_NOT_FOUND",
      "message": "Sample not found: sha256:invalid",
      "category": "NOT_FOUND"
    }
  ]
}

// 处理超时错误（可重试）
{
  "ok": false,
  "errors": [
    {
      "code": "E_TIMEOUT",
      "message": "YARA scan timed out after 30000ms",
      "category": "TIMEOUT"
    }
  ],
  "warnings": ["Partial results may be available"]
}

// 处理 PE 解析失败（尝试备用解析器）
{
  "ok": true,
  "data": {...},
  "warnings": ["pefile parser failed, used LIEF fallback"]
}
```

### 重试策略

对于可重试错误（`E_TIMEOUT`, `E_WORKER_UNAVAILABLE`, `E_RESOURCE_EXHAUSTED`），建议使用指数退避重试:

```typescript
async function retryWithBackoff(fn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn()
    } catch (error) {
      if (!isRetryable(error) || i === maxRetries - 1) {
        throw error
      }
      const backoff = Math.pow(2, i) * 1000  // 1s, 2s, 4s
      await sleep(backoff)
    }
  }
}
```

## 性能优化建议

### 1. 使用缓存

所有工具结果自动缓存，重复查询同一样本时直接返回缓存结果。

### 2. 批量分析

对于多个样本，使用并发调用:

```typescript
const sampleIds = ["sha256:abc...", "sha256:def...", "sha256:ghi..."]
const results = await Promise.all(
  sampleIds.map(id => callTool("workflow.triage", {sample_id: id}))
)
```

### 3. 选择合适的模式

- 快速筛选：使用 `pe.fingerprint` (fast=true) + `yara.scan`
- 深度分析：使用 `workflow.triage` 完整工作流
- 字符串分析：优先使用 `strings.extract`，仅在需要时使用 `strings.floss.decode`

### 4. 超时控制

根据样本大小调整超时参数:

```typescript
// 小样本（< 1MB）
{timeout_ms: 10000}

// 中等样本（1-10MB）
{timeout_ms: 30000}

// 大样本（> 10MB）
{timeout_ms: 60000}
```

## 下一步

- 查看 [使用示例](EXAMPLES.md) 了解实际使用案例
- 查看 [常见问题](FAQ.md) 解决常见问题
- 查看 [数据库 Schema](database-schema.md) 了解数据结构
