# 常见问题解答 (FAQ)

本文档回答 Rikune 使用过程中的常见问题。

## 目录

- [安装和配置](#安装和配置)
- [使用问题](#使用问题)
- [性能问题](#性能问题)
- [错误处理](#错误处理)
- [安全问题](#安全问题)
- [高级话题](#高级话题)

## 安装和配置

### Q1: 支持哪些操作系统？

**A**: V0.1 支持以下操作系统:

- **Linux**: Ubuntu 20.04+, Debian 11+, CentOS 8+
- **macOS**: macOS 11+ (Big Sur 及以上)
- **Windows**: Windows 10/11, Windows Server 2019+

注意：Python Worker 需要在 Linux/macOS 上运行效果最佳，Windows 上部分功能可能受限。

---

### Q2: Python 依赖安装失败怎么办？

**A**: 常见解决方案:

**问题 1: pefile 安装失败**
```bash
# 升级 pip
pip install --upgrade pip

# 使用国内镜像
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pefile
```

**问题 2: LIEF 编译失败**
```bash
# 安装编译依赖（Ubuntu/Debian）
sudo apt-get install build-essential cmake

# 安装编译依赖（macOS）
brew install cmake

# 使用预编译二进制
pip install lief --prefer-binary
```

**问题 3: YARA 安装失败**
```bash
# Ubuntu/Debian
sudo apt-get install libyara-dev
pip install yara-python

# macOS
brew install yara
pip install yara-python
```

---

### Q3: 如何配置自定义 YARA 规则？

**A**: 将 YARA 规则文件放在 `workers/yara_rules/` 目录:

```bash
workers/yara_rules/
├── malware_families/
│   ├── emotet.yar
│   ├── trickbot.yar
│   └── wannacry.yar
├── packers/
│   ├── upx.yar
│   ├── themida.yar
│   └── vmprotect.yar
└── capabilities/
    ├── network.yar
    ├── persistence.yar
    └── injection.yar
```

规则集名称对应目录名（如 `malware_families`）。

---

### Q4: 数据库文件存储在哪里？

**A**: 默认位置:

- **数据库**: `./data/database.db`
- **Workspace**: `./workspaces/`
- **缓存**: `./cache/`
- **审计日志**: `./audit.log`

可通过配置文件或环境变量修改:

```bash
export DATABASE_PATH=/var/lib/mcp-server/database.db
export WORKSPACE_ROOT=/var/lib/mcp-server/workspaces
```

---

### Q5: 如何清理旧数据？

**A**: 使用内置清理脚本:

```bash
# 清理 30 天前的样本
npm run workspace:clean -- --days 30

# 清理特定样本
npm run workspace:clean -- --sample-id sha256:abc123...

# 清理所有缓存
npm run cache:clear
```

手动清理:

```bash
# 删除 workspace
rm -rf workspaces/

# 删除缓存
rm -rf cache/

# 重置数据库
rm data/database.db
npm run db:init
```

## 使用问题

### Q6: 样本摄入失败，提示 "File too large"

**A**: 样本大小超过限制（默认 500MB）。

**解决方案 1**: 修改配置文件

```json
{
  "workspace": {
    "maxSampleSize": 1073741824  // 1GB
  }
}
```

**解决方案 2**: 使用环境变量

```bash
export MAX_SAMPLE_SIZE=1073741824
```

**注意**: 大样本会占用更多磁盘空间和分析时间。

---

### Q7: YARA 扫描超时怎么办？

**A**: 增加超时时间:

```json
{
  "tool": "yara.scan",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "rule_set": "malware_families",
    "timeout_ms": 60000  // 增加到 60 秒
  }
}
```

或者使用更小的规则集:

```json
{
  "rule_set": "packers"  // 仅扫描加壳器规则
}
```

---

### Q8: 为什么 strings.floss.decode 很慢？

**A**: FLOSS 需要模拟执行来解码字符串，耗时较长（10-60 秒）。

**优化建议**:

1. **仅在必要时使用**: 先用 `strings.extract` 查看基础字符串
2. **调整超时**: 根据样本大小设置合理超时
3. **使用缓存**: 重复查询会直接返回缓存结果

```json
{
  "tool": "strings.floss.decode",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "timeout_sec": 30  // 小样本使用较短超时
  }
}
```

---

### Q9: 如何判断样本是否已分析过？

**A**: 使用 `sample.profile.get` 查看分析历史:

```json
{
  "tool": "sample.profile.get",
  "arguments": {
    "sample_id": "sha256:abc123..."
  }
}
```

响应中的 `analyses` 数组包含所有已完成的分析:

```json
{
  "analyses": [
    {
      "stage": "fingerprint",
      "status": "done",
      "finished_at": "2024-01-01T12:00:00Z"
    },
    {
      "stage": "yara",
      "status": "done",
      "finished_at": "2024-01-01T12:01:00Z"
    }
  ]
}
```

---

### Q10: 快速画像工作流包含哪些步骤？

**A**: `workflow.triage` 执行以下步骤:

1. **PE 指纹提取** (fast 模式) - 0.5s
2. **运行时检测** - 0.5s
3. **导入表提取** - 0.5s
4. **字符串提取** (min_len=6) - 2s
5. **YARA 扫描** (malware_families) - 5-30s
6. **加壳器检测** - 2-5s
7. **生成摘要** - 0.5s

**总耗时**: 通常 2-5 分钟，最多 5 分钟。

所有中间结果都会缓存，重复查询会更快。

## 性能问题

### Q11: 如何提高分析速度？

**A**: 性能优化建议:

**1. 使用缓存**
```typescript
// 所有工具结果自动缓存
// 重复查询同一样本时直接返回缓存
```

**2. 并发分析**
```typescript
// 批量分析时使用并发
const results = await Promise.all(
  sampleIds.map(id => callTool("workflow.triage", {sample_id: id}))
)
```

**3. 选择合适的模式**
```json
// 快速筛选：使用 fast 模式
{"fast": true}

// 深度分析：使用完整模式
{"fast": false}
```

**4. 调整超时**
```json
// 根据样本大小调整超时
{
  "timeout_ms": 10000  // 小样本
  "timeout_ms": 60000  // 大样本
}
```

---

### Q12: 系统资源占用过高怎么办？

**A**: 资源优化建议:

**CPU 占用高**:
- 减少并发分析数量
- 调整 YARA 扫描超时
- 使用 fast 模式

**内存占用高**:
- 定期清理缓存
- 减少内存缓存 TTL
- 限制样本大小

**磁盘占用高**:
- 定期清理旧样本
- 减少缓存 TTL
- 压缩 workspace

```bash
# 监控资源使用
npm run health-check

# 清理缓存
npm run cache:clear

# 清理旧样本
npm run workspace:clean -- --days 7
```

---

### Q13: 数据库查询变慢怎么办？

**A**: 数据库优化:

**1. 重建索引**
```bash
npm run db:reindex
```

**2. 清理旧记录**
```bash
npm run db:vacuum
```

**3. 迁移到 PostgreSQL**（V0.4 支持）
```json
{
  "database": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "mcp_server"
  }
}
```

## 错误处理

### Q14: 遇到 "E_PARSE_PE" 错误怎么办？

**A**: PE 文件解析失败，可能原因:

1. **文件损坏**: 文件不完整或损坏
2. **非 PE 文件**: 文件不是有效的 PE 格式
3. **畸形 PE**: 恶意构造的 PE 文件

**解决方案**:

```bash
# 验证文件完整性
file /path/to/sample.exe

# 使用备用解析器（自动尝试）
# 系统会自动尝试 LIEF 作为备用解析器
```

如果仍然失败，样本会被标记为 `malformed`，需要人工分析。

---

### Q15: 遇到 "E_WORKER_UNAVAILABLE" 错误怎么办？

**A**: Python Worker 不可用，可能原因:

1. **Python 环境未激活**
2. **依赖未安装**
3. **Worker 进程崩溃**

**解决方案**:

```bash
# 1. 检查 Python 环境
cd workers
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# 2. 验证依赖
pip list | grep pefile

# 3. 测试 Worker
python static_worker.py --test

# 4. 重启服务器
npm restart
```

---

### Q16: 遇到 "E_TIMEOUT" 错误怎么办？

**A**: 操作超时，可能原因:

1. **样本过大**
2. **系统资源不足**
3. **超时设置过短**

**解决方案**:

```json
// 增加超时时间
{
  "tool": "yara.scan",
  "arguments": {
    "sample_id": "sha256:abc123...",
    "timeout_ms": 120000  // 增加到 120 秒
  }
}
```

或者使用重试机制:

```typescript
async function retryWithBackoff(fn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn()
    } catch (error) {
      if (error.code !== "E_TIMEOUT" || i === maxRetries - 1) {
        throw error
      }
      await sleep(Math.pow(2, i) * 1000)
    }
  }
}
```

---

### Q17: 如何查看详细错误日志？

**A**: 启用调试日志:

```bash
# 设置日志级别
export LOG_LEVEL=debug

# 启动服务器
npm run dev
```

日志位置:
- **应用日志**: stdout/stderr
- **审计日志**: `./audit.log`
- **错误日志**: `./logs/error.log`（如果配置）

查看审计日志:

```bash
# 查看最近的操作
tail -f audit.log

# 搜索特定样本的日志
grep "sha256:abc123" audit.log

# 搜索错误
grep "level\":\"error" audit.log
```

## 安全问题

### Q18: 样本会自动执行吗？

**A**: **不会**。V0.1 仅进行静态分析，不会执行样本。

安全措施:
- ✅ 样本文件标记为不可执行
- ✅ 存储在隔离的 workspace 中
- ✅ 默认禁用动态执行
- ✅ 所有操作记录审计日志

V0.5 将支持可选的动态沙箱，但需要:
- 显式用户批准
- 隔离环境（VM/容器）
- 网络隔离
- 完整审计日志

---

### Q19: 如何确保分析环境安全？

**A**: 安全最佳实践:

**1. 隔离部署**
```bash
# 使用专用服务器或虚拟机
# 不要在生产环境部署
```

**2. 限制网络访问**
```bash
# 使用防火墙限制出站连接
sudo iptables -A OUTPUT -j DROP
```

**3. 定期审查日志**
```bash
# 检查审计日志
grep "level\":\"warning\|error\|critical" audit.log
```

**4. 限制文件系统访问**
```bash
# 使用专用用户运行
sudo useradd -r -s /bin/false mcp-server
sudo chown -R mcp-server:mcp-server /opt/mcp-server
```

**5. 启用 SELinux/AppArmor**（推荐）

---

### Q20: 审计日志包含哪些信息？

**A**: 审计日志记录所有操作:

```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "info",
  "operation": "sample.ingest",
  "sample_id": "sha256:abc123...",
  "size": 102400,
  "source": "upload",
  "user": "analyst@example.com",
  "ip": "192.168.1.100"
}
```

包含字段:
- `timestamp`: 操作时间
- `level`: 日志级别（info/warning/error/critical）
- `operation`: 操作类型
- `sample_id`: 样本 ID
- `decision`: 决策（allow/deny）
- `user`: 操作者（如果有认证）
- `ip`: 来源 IP（如果有）

---

### Q21: 如何防止数据泄露？

**A**: 数据保护措施:

**1. 禁用外部上传**（默认）
```json
{
  "policy": {
    "allowExternalUpload": false
  }
}
```

**2. 限制网络访问**（默认）
```json
{
  "policy": {
    "allowNetworkAccess": false
  }
}
```

**3. 加密存储**（可选）
```bash
# 使用加密文件系统
# 或配置数据库加密
```

**4. 定期清理**
```bash
# 自动清理旧样本
npm run workspace:clean -- --days 30
```

## 高级话题

### Q22: 如何扩展自定义工具？

**A**: V0.1 支持通过插件扩展工具。

**步骤 1**: 创建工具定义

```typescript
// src/tools/my-custom-tool.ts
export const myCustomToolDefinition: ToolDefinition = {
  name: "my.custom.tool",
  description: "My custom analysis tool",
  inputSchema: {
    type: "object",
    properties: {
      sample_id: {type: "string"}
    },
    required: ["sample_id"]
  }
}
```

**步骤 2**: 实现工具处理器

```typescript
export function createMyCustomToolHandler(
  workspace: WorkspaceManager,
  database: DatabaseManager
): ToolHandler {
  return async (args: unknown) => {
    // 实现自定义逻辑
    return {
      ok: true,
      data: {...}
    }
  }
}
```

**步骤 3**: 注册工具

```typescript
// src/index.ts
server.registerTool(
  myCustomToolDefinition,
  createMyCustomToolHandler(workspaceManager, database)
)
```

---

### Q23: 如何集成到 CI/CD 流程？

**A**: 示例 CI/CD 集成:

**GitHub Actions**:

```yaml
name: Malware Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup MCP Server
        run: |
          npm install
          cd workers && pip install -r requirements.txt
      
      - name: Scan Binaries
        run: |
          for file in dist/*.exe; do
            npm run scan -- --file "$file"
          done
```

**Jenkins**:

```groovy
pipeline {
  agent any
  stages {
    stage('Scan') {
      steps {
        sh 'npm run scan -- --file target/release/app.exe'
      }
    }
  }
}
```

---

### Q24: 如何与 SIEM 集成？

**A**: 审计日志可发送到 SIEM（V0.4 支持）。

**配置示例**:

```json
{
  "audit": {
    "siem": {
      "enabled": true,
      "type": "splunk",
      "endpoint": "https://splunk.example.com:8088",
      "token": "your-hec-token"
    }
  }
}
```

**手动集成**:

```bash
# 使用 Filebeat 转发日志
filebeat -e -c filebeat.yml
```

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /opt/mcp-server/audit.log
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

---

### Q25: V0.2 什么时候发布？

**A**: V0.2（反编译功能）预计发布时间:

- **开发周期**: 5-7 周
- **主要功能**:
  - Ghidra Headless 集成
  - 函数级反编译
  - 控制流图生成
  - 函数兴趣排序

**当前进度**: V0.1 已完成，V0.2 开发中

关注项目 [路线图](../README.md#路线图) 获取最新进展。

---

## 获取帮助

如果以上 FAQ 没有解决您的问题:

1. **查看文档**:
   - [使用指南](USAGE.md)
   - [使用示例](EXAMPLES.md)
   - [README](../README.md)

2. **搜索 Issues**:
   - [GitHub Issues](https://github.com/your-org/rikune/issues)

3. **提交 Issue**:
   - 提供详细的错误信息
   - 包含复现步骤
   - 附上日志文件

4. **联系支持**:
   - 邮件: security@your-org.com
   - 社区: [Discord/Slack]

---

**最后更新**: 2024-01-01
