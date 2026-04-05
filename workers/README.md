# Static Worker - Python 分析引擎

## 概述

Static Worker 是 Windows EXE 反编译 MCP Server 的 Python 分析引擎，负责执行静态分析任务，包括 PE 解析、字符串提取、YARA 扫描等。

## 架构

### 数据类

- **SampleInfo**: 样本信息（sample_id, path）
- **PolicyContext**: 策略上下文（allow_dynamic, allow_network）
- **WorkerContext**: Worker 上下文（request_time_utc, policy, versions）
- **WorkerRequest**: Worker 请求（job_id, tool, sample, args, context）
- **WorkerResponse**: Worker 响应（job_id, ok, warnings, errors, data, artifacts, metrics）
- **ArtifactRef**: 产物引用（id, type, path, sha256, mime）

### 通信协议

Worker 通过 stdin/stdout 与 Node.js 进程通信，使用 JSON Lines 格式：

1. Node.js 向 stdin 发送一行 JSON 请求
2. Worker 解析请求并执行分析
3. Worker 向 stdout 输出一行 JSON 响应
4. 循环处理直到 stdin 关闭

### 请求格式

```json
{
  "job_id": "job-123",
  "tool": "pe.fingerprint",
  "sample": {
    "sample_id": "sha256:abc123...",
    "path": "/path/to/sample.exe"
  },
  "args": {
    "fast": true
  },
  "context": {
    "request_time_utc": "2024-01-01T00:00:00Z",
    "policy": {
      "allow_dynamic": false,
      "allow_network": false
    },
    "versions": {
      "pefile": "2023.2.7",
      "lief": "0.14.0"
    }
  }
}
```

### 响应格式

```json
{
  "job_id": "job-123",
  "ok": true,
  "warnings": [],
  "errors": [],
  "data": {
    "sha256": "abc123...",
    "imphash": "def456...",
    "machine_type": "AMD64"
  },
  "artifacts": [],
  "metrics": {
    "elapsed_ms": 123.45,
    "tool": "pe.fingerprint"
  }
}
```

## 安装

### 依赖项

```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt
```

### 依赖包

- `pefile>=2023.2.7` - PE 文件解析
- `lief>=0.14.0` - 多格式二进制解析（备用解析器）
- `yara-python>=4.3.1` - YARA 规则引擎
- `floss>=3.0.0` - 字符串提取与去混淆
- `dnfile>=0.14.0` - .NET 元数据解析

## 使用

### 命令行模式

```bash
# 启动 Worker（从 stdin 读取请求）
python static_worker.py

# 发送测试请求
echo '{"job_id":"test","tool":"pe.fingerprint","sample":{"sample_id":"sha256:test","path":"/path/to/sample.exe"},"args":{},"context":{"request_time_utc":"2024-01-01T00:00:00Z","policy":{"allow_dynamic":false,"allow_network":false},"versions":{}}}' | python static_worker.py
```

### 编程接口

```python
from static_worker import StaticWorker, WorkerRequest, SampleInfo, PolicyContext, WorkerContext

# 创建 Worker
worker = StaticWorker()

# 构建请求
sample = SampleInfo(sample_id="sha256:abc123", path="/path/to/sample.exe")
policy = PolicyContext(allow_dynamic=False, allow_network=False)
context = WorkerContext(
    request_time_utc="2024-01-01T00:00:00Z",
    policy=policy,
    versions={"pefile": "2023.2.7"}
)

request = WorkerRequest(
    job_id="job-123",
    tool="pe.fingerprint",
    sample=sample,
    args={"fast": True},
    context=context
)

# 执行分析
response = worker.execute(request)

# 检查结果
if response.ok:
    print(f"Success: {response.data}")
else:
    print(f"Errors: {response.errors}")
```

## 测试

### 单元测试

```bash
# 运行所有单元测试
python -m pytest test_static_worker.py -v

# 运行特定测试类
python -m pytest test_static_worker.py::TestStaticWorker -v

# 运行特定测试
python -m pytest test_static_worker.py::TestStaticWorker::test_execute_successful -v
```

### 集成测试

```bash
# 运行集成测试
python test_integration.py
```

### 测试覆盖率

```bash
# 生成测试覆盖率报告
python -m pytest test_static_worker.py --cov=static_worker --cov-report=html
```

## 工具处理器

Worker 支持以下工具（将在后续任务中实现）：

- `pe.fingerprint` - PE 文件指纹提取
- `pe.imports.extract` - 导入表提取
- `pe.exports.extract` - 导出表提取
- `strings.extract` - 字符串提取
- `strings.floss.decode` - FLOSS 字符串解码
- `yara.scan` - YARA 规则扫描
- `runtime.detect` - 运行时检测
- `packer.detect` - 加壳器检测

## 错误处理

Worker 实现了完善的错误处理机制：

1. **未知工具**: 返回错误响应，包含 "Unknown tool" 消息
2. **JSON 解析错误**: 返回错误响应，包含 "JSON decode error" 消息
3. **缺少必需字段**: 返回错误响应，包含 "Missing required field" 消息
4. **工具执行异常**: 捕获异常并返回错误响应，包含异常消息

所有错误响应都包含：
- `ok: false`
- `errors: [...]` - 错误消息列表
- `metrics` - 执行指标（包括 elapsed_ms）

## 性能指标

Worker 自动收集以下性能指标：

- `elapsed_ms` - 执行耗时（毫秒）
- `tool` - 工具名称

后续将添加：
- `peak_rss_mb` - 内存峰值（MB）
- `cpu_percent` - CPU 使用率

## 开发指南

### 添加新工具

1. 在 `StaticWorker.__init__` 中注册工具处理器：

```python
def __init__(self):
    self.tool_handlers = {
        'pe.fingerprint': self.pe_fingerprint,
        'new.tool': self.new_tool,  # 添加新工具
    }
```

2. 实现工具处理器方法：

```python
def new_tool(self, sample_path: str, args: Dict[str, Any]) -> Any:
    """
    新工具实现
    
    Args:
        sample_path: 样本文件路径
        args: 工具参数
        
    Returns:
        分析结果
    """
    # 实现分析逻辑
    result = {"key": "value"}
    return result
```

3. 编写单元测试：

```python
def test_new_tool(self):
    worker = StaticWorker()
    
    # 添加测试处理器
    def test_handler(sample_path, args):
        return {"result": "success"}
    
    worker.tool_handlers["new.tool"] = test_handler
    
    # 构建请求并执行
    request = WorkerRequest(...)
    response = worker.execute(request)
    
    # 验证结果
    assert response.ok is True
    assert response.data["result"] == "success"
```

## 技术约束

- Python 版本: >= 3.9
- 通信协议: JSON Lines (stdin/stdout)
- 编码: UTF-8
- 换行符: \n
- 超时控制: 由 Node.js 端实现

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 相关文档

- [设计文档](../.kiro/specs/rikune/design.md)
- [需求文档](../.kiro/specs/rikune/requirements.md)
- [任务列表](../.kiro/specs/rikune/tasks.md)
