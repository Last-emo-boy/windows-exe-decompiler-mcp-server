# 使用示例

本文档提供 Rikune 的实际使用案例和最佳实践。

## 目录

- [场景 1: 快速威胁评估](#场景-1-快速威胁评估)
- [场景 2: 恶意软件家族识别](#场景-2-恶意软件家族识别)
- [场景 3: 加壳器检测与分析](#场景-3-加壳器检测与分析)
- [场景 4: .NET 程序初步分析](#场景-4-net-程序初步分析)
- [场景 5: IOC 提取](#场景-5-ioc-提取)
- [场景 6: 批量样本筛选](#场景-6-批量样本筛选)
- [场景 7: 导入表分析](#场景-7-导入表分析)
- [场景 8: 字符串分析](#场景-8-字符串分析)
- [场景 9: Frida 运行时 Instrumentation](#场景-9-frida-运行时 instrumentation)

## 场景 1: 快速威胁评估

**目标**: 在 5 分钟内评估未知样本的威胁等级

### 步骤 1: 摄入样本

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/tmp/suspicious.exe",
    "filename": "email_attachment.exe",
    "source": "phishing_email"
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "sample_id": "sha256:a1b2c3d4e5f6...",
    "size": 245760,
    "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows"
  }
}
```

### 步骤 2: 执行快速画像

```json
{
  "tool": "workflow.triage",
  "arguments": {
    "sample_id": "sha256:a1b2c3d4e5f6..."
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "summary": "高风险样本：检测到 Emotet 恶意软件特征，使用 UPX 加壳",
    "confidence": 0.92,
    "threat_level": "critical",
    "iocs": {
      "suspicious_imports": [
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory"
      ],
      "suspicious_strings": [
        "http://malicious-c2.com/gate.php",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
      ],
      "yara_matches": [
        "Emotet_Variant_2023",
        "UPX_Packer"
      ],
      "network_indicators": [
        "malicious-c2.com",
        "185.220.101.45"
      ]
    },
    "evidence": [
      "YARA 规则匹配 Emotet 恶意软件家族",
      "导入表包含进程注入相关 API",
      "字符串中发现 C2 服务器地址",
      "检测到 UPX 加壳器",
      "入口点位于非标准节区"
    ],
    "recommendation": "强烈建议在隔离环境进行深度分析，不要在生产环境执行"
  }
}
```

### 分析结论

- **威胁等级**: Critical（严重）
- **恶意软件家族**: Emotet
- **加壳器**: UPX
- **主要行为**: 进程注入、持久化、C2 通信
- **建议**: 立即隔离，进行深度分析

---

## 场景 2: 恶意软件家族识别

**目标**: 识别样本所属的恶意软件家族

### 步骤 1: 摄入样本

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/samples/ransomware.exe"
  }
}
```

### 步骤 2: YARA 扫描

```json
{
  "tool": "yara.scan",
  "arguments": {
    "sample_id": "sha256:b2c3d4e5f6g7...",
    "rule_set": "malware_families"
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "matches": [
      {
        "rule": "WannaCry_Ransomware",
        "tags": ["ransomware", "wannacry", "cryptor"],
        "meta": {
          "description": "WannaCry ransomware variant",
          "author": "Security Researcher",
          "date": "2023-05-15",
          "family": "WannaCry"
        },
        "strings": [
          {
            "offset": 12345,
            "identifier": "$str1",
            "data": "tasksche.exe"
          },
          {
            "offset": 23456,
            "identifier": "$str2",
            "data": ".WNCRY"
          }
        ]
      }
    ],
    "ruleset_version": "2024.01"
  }
}
```

### 步骤 3: 提取 IOC

```json
{
  "tool": "strings.extract",
  "arguments": {
    "sample_id": "sha256:b2c3d4e5f6g7...",
    "min_len": 8
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "strings": [
      {"value": "tasksche.exe", "offset": 12345, "encoding": "ascii"},
      {"value": ".WNCRY", "offset": 23456, "encoding": "ascii"},
      {"value": "msg/m_bulgarian.wnry", "offset": 34567, "encoding": "ascii"},
      {"value": "Ooops, your files have been encrypted!", "offset": 45678, "encoding": "ascii"}
    ],
    "count": 1247
  }
}
```

### 分析结论

- **恶意软件家族**: WannaCry Ransomware
- **特征字符串**: `tasksche.exe`, `.WNCRY`, 勒索信息
- **行为**: 文件加密、勒索
- **建议**: 隔离受感染系统，不要支付赎金

---

## 场景 3: 加壳器检测与分析

**目标**: 检测样本是否加壳，识别加壳器类型

### 步骤 1: 加壳器检测

```json
{
  "tool": "packer.detect",
  "arguments": {
    "sample_id": "sha256:c3d4e5f6g7h8..."
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "is_packed": true,
    "packers": [
      {
        "name": "Themida",
        "confidence": 0.95,
        "method": "yara"
      },
      {
        "name": "VMProtect",
        "confidence": 0.65,
        "method": "entropy"
      }
    ],
    "entropy": {
      "average": 7.2,
      "max": 7.8,
      "suspicious_sections": [
        {
          "name": ".vmp0",
          "entropy": 7.8
        },
        {
          "name": ".vmp1",
          "entropy": 7.6
        }
      ]
    },
    "entry_point": {
      "section": ".vmp0",
      "is_suspicious": true
    }
  }
}
```

### 步骤 2: PE 指纹分析

```json
{
  "tool": "pe.fingerprint",
  "arguments": {
    "sample_id": "sha256:c3d4e5f6g7h8...",
    "fast": false
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "sections": [
      {
        "name": ".text",
        "virtual_size": 102400,
        "raw_size": 102400,
        "entropy": 6.2
      },
      {
        "name": ".vmp0",
        "virtual_size": 524288,
        "raw_size": 524288,
        "entropy": 7.8
      },
      {
        "name": ".vmp1",
        "virtual_size": 262144,
        "raw_size": 262144,
        "entropy": 7.6
      }
    ]
  }
}
```

### 分析结论

- **加壳器**: Themida（高置信度）+ VMProtect（中等置信度）
- **特征**: 
  - 节区名称异常（`.vmp0`, `.vmp1`）
  - 高熵值（7.6-7.8）
  - 入口点在非标准节区
- **建议**: 需要脱壳后才能进行深度分析

---

## 场景 4: .NET 程序初步分析

**目标**: 快速识别 .NET 程序并提取基础信息

### 步骤 1: 运行时检测

```json
{
  "tool": "runtime.detect",
  "arguments": {
    "sample_id": "sha256:d4e5f6g7h8i9..."
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "is_dotnet": true,
    "dotnet_version": "v4.0.30319",
    "target_framework": ".NETFramework,Version=v4.5",
    "suspected": [
      {
        "runtime": "dotnet",
        "confidence": 1.0,
        "evidence": [
          "CLR header present",
          "mscoree.dll imported",
          ".NET metadata found"
        ]
      }
    ]
  }
}
```

### 步骤 2: 导入表分析

```json
{
  "tool": "pe.imports.extract",
  "arguments": {
    "sample_id": "sha256:d4e5f6g7h8i9...",
    "group_by_dll": true
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "mscoree.dll": ["_CorExeMain"],
    "kernel32.dll": ["GetProcAddress", "LoadLibraryA"]
  }
}
```

### 步骤 3: 字符串提取

```json
{
  "tool": "strings.extract",
  "arguments": {
    "sample_id": "sha256:d4e5f6g7h8i9...",
    "min_len": 10
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "strings": [
      {"value": "System.Windows.Forms", "encoding": "utf-16le"},
      {"value": "System.Net.Http", "encoding": "utf-16le"},
      {"value": "MyNamespace.MainForm", "encoding": "utf-16le"},
      {"value": "http://api.example.com/data", "encoding": "ascii"}
    ]
  }
}
```

### 分析结论

- **运行时**: .NET Framework 4.5
- **程序类型**: Windows Forms 应用
- **依赖**: System.Windows.Forms, System.Net.Http
- **网络活动**: 可能连接到 `api.example.com`
- **建议**: 使用 V0.3 的 .NET 专项工具进行深度分析

---

## 场景 5: IOC 提取

**目标**: 从样本中提取 IOC（Indicators of Compromise）

### 完整工作流

```json
// 1. 摄入样本
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/samples/trojan.exe"
  }
}

// 2. 执行快速画像
{
  "tool": "workflow.triage",
  "arguments": {
    "sample_id": "sha256:e5f6g7h8i9j0..."
  }
}
```

### 提取的 IOC

**响应**（IOC 部分）:
```json
{
  "iocs": {
    "suspicious_imports": [
      "InternetOpenA",
      "InternetConnectA",
      "HttpSendRequestA",
      "CreateProcessA",
      "RegSetValueExA"
    ],
    "suspicious_strings": [
      "http://185.220.101.45/update.php",
      "http://malware-c2.onion/gate",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "cmd.exe /c powershell -enc ...",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    ],
    "yara_matches": [
      "Generic_Trojan_Downloader",
      "Suspicious_Network_Activity"
    ],
    "network_indicators": [
      "185.220.101.45",
      "malware-c2.onion",
      "update.php",
      "gate"
    ]
  }
}
```

### IOC 分类

**网络 IOC**:
- IP: `185.220.101.45`
- 域名: `malware-c2.onion`
- URL: `http://185.220.101.45/update.php`

**文件系统 IOC**:
- 注册表键: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- 命令: `cmd.exe /c powershell -enc ...`

**行为 IOC**:
- 网络通信（HTTP）
- 进程创建
- 注册表修改（持久化）

---

## 场景 6: 批量样本筛选

**目标**: 快速筛选大量样本，识别高风险样本

### 批量摄入

```typescript
const samples = [
  "/samples/sample1.exe",
  "/samples/sample2.exe",
  "/samples/sample3.exe",
  // ... 100 个样本
]

// 并发摄入
const ingestResults = await Promise.all(
  samples.map(path => 
    callTool("sample.ingest", {path})
  )
)

const sampleIds = ingestResults.map(r => r.data.sample_id)
```

### 批量快速扫描

```typescript
// 仅使用 YARA 扫描进行快速筛选
const yaraResults = await Promise.all(
  sampleIds.map(id =>
    callTool("yara.scan", {
      sample_id: id,
      rule_set: "malware_families"
    })
  )
)

// 筛选出有匹配的样本
const maliciousSamples = yaraResults
  .filter(r => r.ok && r.data.matches.length > 0)
  .map((r, i) => ({
    sample_id: sampleIds[i],
    matches: r.data.matches.map(m => m.rule)
  }))

console.log(`发现 ${maliciousSamples.length} 个恶意样本`)
```

### 对高风险样本进行深度分析

```typescript
// 对匹配恶意家族规则的样本进行完整画像
const triageResults = await Promise.all(
  maliciousSamples.map(s =>
    callTool("workflow.triage", {
      sample_id: s.sample_id
    })
  )
)

// 生成汇总报告
const summary = triageResults.map((r, i) => ({
  sample_id: maliciousSamples[i].sample_id,
  threat_level: r.data.threat_level,
  family: r.data.yara_matches[0],
  iocs: r.data.iocs
}))
```

### 输出示例

```json
[
  {
    "sample_id": "sha256:abc123...",
    "threat_level": "critical",
    "family": "Emotet_Variant_2023",
    "iocs": {
      "network_indicators": ["malicious-c2.com"]
    }
  },
  {
    "sample_id": "sha256:def456...",
    "threat_level": "high",
    "family": "TrickBot_Loader",
    "iocs": {
      "network_indicators": ["185.220.101.45"]
    }
  }
]
```

---

## 场景 7: 导入表分析

**目标**: 分析程序的功能依赖和可疑 API 调用

### 提取导入表

```json
{
  "tool": "pe.imports.extract",
  "arguments": {
    "sample_id": "sha256:f6g7h8i9j0k1...",
    "group_by_dll": true
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "kernel32.dll": [
      "CreateFileA",
      "ReadFile",
      "WriteFile",
      "CreateProcessA",
      "VirtualAlloc",
      "VirtualProtect"
    ],
    "advapi32.dll": [
      "RegOpenKeyExA",
      "RegSetValueExA",
      "RegCloseKey"
    ],
    "ws2_32.dll": [
      "WSAStartup",
      "socket",
      "connect",
      "send",
      "recv"
    ],
    "user32.dll": [
      "MessageBoxA",
      "FindWindowA"
    ]
  }
}
```

### 可疑 API 分析

**文件操作**:
- `CreateFileA`, `ReadFile`, `WriteFile` - 文件读写

**进程操作**:
- `CreateProcessA` - 创建新进程（可能执行其他程序）
- `VirtualAlloc`, `VirtualProtect` - 内存分配和保护修改（可能用于代码注入）

**注册表操作**:
- `RegOpenKeyExA`, `RegSetValueExA` - 注册表修改（可能用于持久化）

**网络操作**:
- `WSAStartup`, `socket`, `connect`, `send`, `recv` - 网络通信

### 威胁评估

基于导入表，该样本可能具有以下行为:
1. 文件读写
2. 进程创建/注入
3. 注册表持久化
4. 网络通信

**风险等级**: High（高）

---

## 场景 8: 字符串分析

**目标**: 从字符串中发现敏感信息和行为线索

### 步骤 1: 提取基础字符串

```json
{
  "tool": "strings.extract",
  "arguments": {
    "sample_id": "sha256:g7h8i9j0k1l2...",
    "min_len": 6,
    "encoding": "all"
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "strings": [
      {"value": "http://malicious.com/payload.exe", "encoding": "ascii"},
      {"value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "encoding": "ascii"},
      {"value": "cmd.exe /c del /f /q %s", "encoding": "ascii"},
      {"value": "Mozilla/5.0 (Windows NT 10.0)", "encoding": "ascii"},
      {"value": "admin:password123", "encoding": "ascii"}
    ]
  }
}
```

### 步骤 2: FLOSS 解码（如果字符串较少）

```json
{
  "tool": "strings.floss.decode",
  "arguments": {
    "sample_id": "sha256:g7h8i9j0k1l2...",
    "timeout_sec": 60
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "decoded_strings": [
      {
        "value": "http://hidden-c2.com/gate.php",
        "method": "stack",
        "address": "0x401234"
      },
      {
        "value": "SecretKey123!@#",
        "method": "tight",
        "address": "0x402345"
      }
    ],
    "stack_strings": [
      {"value": "http://hidden-c2.com/gate.php", "address": "0x401234"}
    ]
  }
}
```

### 字符串分类

**网络相关**:
- `http://malicious.com/payload.exe` - 下载地址
- `http://hidden-c2.com/gate.php` - C2 服务器
- `Mozilla/5.0 (Windows NT 10.0)` - User-Agent

**持久化相关**:
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` - 自启动注册表键

**命令执行**:
- `cmd.exe /c del /f /q %s` - 删除文件命令

**凭据**:
- `admin:password123` - 硬编码凭据
- `SecretKey123!@#` - 加密密钥

### 威胁评估

- **网络活动**: 下载 payload，连接 C2 服务器
- **持久化**: 注册表自启动
- **反取证**: 删除文件
- **凭据泄露**: 硬编码凭据

**风险等级**: Critical（严重）

---

## 场景 9: Frida 运行时 Instrumentation

**目标**: 使用 Frida 对样本进行动态插桩，捕获运行时 API 调用和行为

### 前提条件

确保已安装 Frida：
```bash
pip install frida frida-tools
```

验证 Frida 可用性：
```json
{
  "tool": "system.health",
  "arguments": {}
}
```

### 步骤 1: 使用 spawn 模式启动样本并追踪 API

```json
{
  "tool": "frida.runtime.instrument",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "mode": "spawn",
    "trace_config": {
      "api_traces": true,
      "module_filter": ["kernel32.dll", "advapi32.dll", "ntdll.dll"],
      "function_patterns": ["Create*", "Open*", "Read*", "Write*", "Reg*"]
    },
    "capture_mode": "session",
    "timeout_sec": 30
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "session_id": "frida_session_abc123",
    "sample_id": "sha256:abc123...",
    "mode": "spawn",
    "pid": 12345,
    "status": "running",
    "messages_captured": 156,
    "traces": [
      {
        "type": "api_call",
        "function": "CreateFileA",
        "module": "kernel32.dll",
        "args": ["C:\\\\temp\\\\data.txt", "GENERIC_READ"],
        "timestamp": 1678901234567,
        "thread_id": 1
      },
      {
        "type": "api_call",
        "function": "RegOpenKeyExA",
        "module": "advapi32.dll",
        "args": ["HKEY_CURRENT_USER", "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"],
        "timestamp": 1678901234890,
        "thread_id": 1
      }
    ]
  }
}
```

### 步骤 2: 注入预定义脚本进行专项监控

#### 2.1: 文件和注册表监控

```json
{
  "tool": "frida.script.inject",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "pid": 12345,
    "script_name": "file_registry_monitor",
    "script_parameters": {
      "trackContent": false,
      "filePatterns": ["\\\\temp\\\\", "\\\\appdata\\\\", "\\\\startup\\\\"]
    },
    "timeout_sec": 30
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "session_id": "inject_session_def456",
    "pid": 12345,
    "script_name": "file_registry_monitor",
    "status": "completed",
    "messages_captured": 47,
    "results": [
      {
        "type": "file_create",
        "function": "CreateFileW",
        "path": "C:\\\\Users\\\\victim\\\\AppData\\\\Roaming\\\\malware.exe",
        "access": "GENERIC_WRITE",
        "creation": "CREATE_ALWAYS",
        "module": "kernel32.dll"
      },
      {
        "type": "reg_set",
        "function": "RegSetValueExA",
        "key": "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        "value": "UpdateTask",
        "type": "REG_SZ",
        "module": "advapi32.dll"
      }
    ]
  }
}
```

#### 2.2: 字符串解密监控

```json
{
  "tool": "frida.script.inject",
  "arguments": {
    "pid": 12345,
    "script_name": "string_decoder",
    "timeout_sec": 30
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "session_id": "inject_session_ghi789",
    "pid": 12345,
    "script_name": "string_decoder",
    "status": "completed",
    "messages_captured": 23,
    "results": [
      {
        "type": "string_decrypted",
        "function": "DecryptString",
        "address": "0x401234",
        "decrypted_value": "http://c2-server.evil/beacon",
        "encryption_method": "XOR"
      },
      {
        "type": "string_decrypted",
        "function": "DecryptString",
        "address": "0x401567",
        "decrypted_value": "cmd.exe /c powershell -enc base64...",
        "encryption_method": "RC4"
      }
    ]
  }
}
```

#### 2.3: 加密 API 监控

```json
{
  "tool": "frida.script.inject",
  "arguments": {
    "pid": 12345,
    "script_name": "crypto_finder",
    "timeout_sec": 30
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "session_id": "inject_session_jkl012",
    "pid": 12345,
    "script_name": "crypto_finder",
    "status": "completed",
    "messages_captured": 18,
    "results": [
      {
        "type": "crypto_api",
        "function": "CryptEncrypt",
        "module": "advapi32.dll",
        "algorithm": "CALG_AES_256",
        "data_size": 1024
      },
      {
        "type": "crypto_api",
        "function": "CryptDecrypt",
        "module": "advapi32.dll",
        "algorithm": "CALG_RSA_2048",
        "data_size": 256
      }
    ]
  }
}
```

### 步骤 3: 捕获和汇总 traces

```json
{
  "tool": "frida.trace.capture",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "session_id": "frida_session_abc123",
    "trace_format": "normalized",
    "filter": {
      "types": ["api_call", "file_create", "reg_set"],
      "modules": ["kernel32.dll", "advapi32.dll"]
    },
    "aggregate": true,
    "limit": 500
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "session_id": "frida_session_abc123",
    "sample_id": "sha256:abc123...",
    "captured_at": "2024-03-14T10:30:00Z",
    "trace_format": "normalized",
    "total_events": 1247,
    "filtered_events": 156,
    "events": [
      {
        "type": "api_call",
        "function": "CreateFileA",
        "module": "kernel32.dll"
      },
      {
        "type": "reg_set",
        "function": "RegSetValueExA",
        "module": "advapi32.dll"
      }
    ],
    "aggregation": {
      "by_type": {
        "api_call": 89,
        "file_create": 12,
        "file_write": 23,
        "reg_open": 15,
        "reg_set": 17
      },
      "by_module": {
        "kernel32.dll": 98,
        "advapi32.dll": 45,
        "ntdll.dll": 13
      },
      "by_function": {
        "CreateFileA": 45,
        "WriteFile": 23,
        "RegSetValueExA": 17
      }
    }
  }
}
```

### 步骤 4: 生成综合报告

```json
{
  "tool": "report.generate",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "format": "markdown",
    "evidence_scope": "all"
  }
}
```

**报告节选**:
```markdown
## 动态行为分析

### Frida 运行时证据

**会话 ID**: frida_session_abc123
**追踪事件**: 1247 total, 156 filtered

#### 检测到的行为

**文件操作**:
- 创建文件：C:\\Users\\victim\\AppData\\Roaming\\malware.exe
- 写入文件：23 次写操作

**注册表操作**:
- 设置自启动项：HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateTask
- 查询注册表：15 次查询操作

**网络行为**:
- 解密的 C2 地址：http://c2-server.evil/beacon
- User-Agent: Mozilla/5.0 (Windows NT 10.0)

**加密行为**:
- AES-256 加密：1 次
- RSA-2048 解密：1 次

#### 行为图谱
```

### 分析结论

- **持久化机制**: 通过注册表自启动项实现持久化
- **文件操作**: 在 AppData 目录创建恶意文件
- **C2 通信**: 使用硬编码 C2 地址进行通信
- **加密能力**: 使用 AES 和 RSA 加密算法
- **行为风险**: 高 - 具有典型的恶意软件行为特征

---

## Frida 故障排除

### 1. 架构不匹配问题

**症状**:
```
Error: Unable to inject: architecture mismatch
```

**原因**: Frida 架构与目标进程架构不匹配。

**解决方案**:
```powershell
# 检查目标进程架构
Get-Process | Select-Object Name, Id, Path

# 64 位进程 - 使用 64 位 Frida
frida -64 -n target.exe

# 32 位进程 - 使用 32 位 Frida
frida -32 -n target.exe

# 或者在 Python 中指定架构
import frida
device = frida.get_usb_device()
# 显式指定架构参数
```

**预防措施**:
- 在 64 位系统上，确保 Python 和 frida-tools 都是 64 位
- 对于 32 位目标，使用 `frida-get` 工具注入 32 位 Frida
- 使用 Speakeasy 模拟时，架构由模拟环境决定

---

### 2. 驱动程序签名问题

**症状**:
```
Frida was unable to load the driver
The system cannot find the file specified
```

**原因**: Windows 驱动程序签名强制阻止 Frida 驱动加载。

**解决方案**:

**方法 1: 临时禁用驱动签名强制**
```powershell
# 以管理员身份运行
bcdedit /set testsigning on
shutdown /r /t 0
```

**方法 2: 使用免驱动模式**
```bash
# 某些 Frida 版本支持无驱动模式
frida --no-driver -n target.exe
```

**方法 3: 签名 Frida 驱动**
```powershell
# 下载 Frida 驱动签名工具
# 参考：https://github.com/frida/frida-gum

# 使用测试证书签名
signtool sign /v /fd sha256 /t http://timestamp.digicert.com frida.sys
```

---

### 3. Frida 检测绕过

**症状**:
- 目标程序检测到 Frida 后立即退出
- 关键函数被 Hook 后触发反调试机制

**常见检测手法及绕过**:

| 检测手法 | 绕过方案 |
|----------|----------|
| 检查 Frida 进程名/窗口 | 使用 `frida-rename` 修改进程名 |
| 检查特定线程名 | 使用 `Stalker` 隐藏注入线程 |
| 检查内存特征 | 使用 `frida-unpack` 或自定义隐藏脚本 |
| 检查系统调用 | 使用 `Syscall` 直接调用绕过 Hook |
| 检查时间差异 | 在脚本中处理 `QueryPerformanceCounter` |

**示例 - 基础反检测脚本**:
```javascript
// anti_detect.js
Interceptor.replace(Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'),
    new NativeCallback(function() {
        return 0;
    }, 'int', []));

// 隐藏 Frida 线程
Process.enumerateThreads().forEach(thread => {
    if (thread.id !== Process.getCurrentThreadId()) {
        // 修改线程特征
    }
});
```

---

### 4. 常见错误消息及解决方案

| 错误消息 | 原因 | 解决方案 |
|----------|------|----------|
| `Frida server not running` | Frida server 未启动 | 手动启动或使用 spawn 模式 |
| `Process not found` | 目标进程不存在或已结束 | 检查进程名/使用 spawn 模式 |
| `Permission denied` | 权限不足 | 以管理员身份运行 |
| `Timeout waiting for script` | 脚本执行超时 | 增加 timeout 参数 |
| `Device lost` | USB 连接断开 | 检查设备连接 |
| `Invalid argument` | 参数格式错误 | 检查 API 调用参数 |
| `Out of memory` | 内存不足 | 减少跟踪范围或增加内存 |

---

### 5. Speakeasy 模拟限制

**已知问题**:

1. **不完全的 API 模拟**
   - 某些 Windows API 返回固定值
   - 文件系统模拟有限

2. **网络模拟**
   - 网络连接会被模拟但不会真实发出
   - DNS 解析返回模拟结果

3. **注册表模拟**
   - 注册表操作被记录但不持久化
   - 某些注册表键值可能不存在

**应对策略**:
```python
# 使用 memory_guided 模式进行真实环境分析
# 当 Speakeasy 无法准确模拟时使用真实沙箱
```

---

### 6. 性能优化

**减少跟踪数据量**:
```javascript
// 只跟踪特定模块
if (module_name === 'target.dll') {
    // 记录调用
}

// 采样模式 - 每 N 次记录一次
let counter = 0;
if (counter++ % 100 === 0) {
    // 采样记录
}

// 使用条件断点
if (arg1 === 'interesting_value') {
    // 只在条件满足时触发
}
```

**批处理日志输出**:
```javascript
// 累积日志批量输出
let logBuffer = [];
setInterval(() => {
    if (logBuffer.length > 0) {
        send({buffer: logBuffer});
        logBuffer = [];
    }
}, 1000);
```

---

### 7. 调试 Frida 脚本

**启用脚本调试**:
```bash
frida -n target.exe -l script.js --debug
# 然后使用 Chrome DevTools 连接
```

**脚本错误处理**:
```javascript
try {
    // Hook 代码
} catch (e) {
    console.error('Hook error: ' + e);
}
```

**逐步调试**:
```javascript
// 使用 console.log 输出中间状态
console.log('Function called with args:', args);

// 使用断点
debugger;  // 配合 --debug 参数使用
```

---

## 最佳实践

### 1. 分层分析策略

```
第一层（快速筛选）: YARA 扫描
    ↓ 匹配恶意规则
第二层（基础画像）: workflow.triage
    ↓ 威胁等级 High/Critical
第三层（深度分析）: 详细工具分析
```

### 2. 缓存利用

```typescript
// 第一次分析
const result1 = await callTool("pe.fingerprint", {sample_id: id})
// 耗时: 0.5s

// 第二次查询（缓存命中）
const result2 = await callTool("pe.fingerprint", {sample_id: id})
// 耗时: < 0.01s
```

### 3. 错误处理

```typescript
async function analyzeWithRetry(sampleId) {
  try {
    return await callTool("workflow.triage", {sample_id: sampleId})
  } catch (error) {
    if (error.code === "E_TIMEOUT") {
      // 超时重试
      return await callTool("workflow.triage", {
        sample_id: sampleId,
        timeout_ms: 600000  // 增加超时时间
      })
    }
    throw error
  }
}
```

### 4. 结果聚合

```typescript
async function comprehensiveAnalysis(sampleId) {
  const [fingerprint, imports, strings, yara, packer] = await Promise.all([
    callTool("pe.fingerprint", {sample_id: sampleId}),
    callTool("pe.imports.extract", {sample_id: sampleId}),
    callTool("strings.extract", {sample_id: sampleId}),
    callTool("yara.scan", {sample_id: sampleId, rule_set: "all"}),
    callTool("packer.detect", {sample_id: sampleId})
  ])
  
  return {
    fingerprint: fingerprint.data,
    imports: imports.data,
    strings: strings.data,
    yara: yara.data,
    packer: packer.data
  }
}
```

## 下一步

- 查看 [使用指南](USAGE.md) 了解工具详细说明
- 查看 [常见问题](FAQ.md) 解决常见问题
- 查看 [README.md](../README.md) 了解安装和配置
