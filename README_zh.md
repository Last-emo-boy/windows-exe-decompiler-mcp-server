# Rikune

英文版：[`README.md`](./README.md)

这是一个面向 Windows 逆向分析的 MCP Server。它把 PE 初筛、Ghidra 辅助分析、DLL/COM 画像、运行时证据导入、Rust/.NET 恢复、源码风格重建，以及 LLM 参与的语义 review，统一暴露成可复用的 MCP 工具，供任意支持 tool calling 的 LLM 调用。

## 功能亮点

- 通用 Windows PE 覆盖：对 EXE、DLL、COM 风格库、Rust native 样本和 .NET 程序都提供了专门的画像或恢复路径。
- 以恢复为中心：当 Ghidra 函数提取为空或退化时，系统仍可继续走 `.pdata` 解析、函数边界恢复、符号恢复和函数定义导入。
- 可观测的 Ghidra 执行：高层输出会直接返回命令日志、运行日志、阶段进度、项目/日志根路径，以及解析后的 Java 异常摘要。
- 运行时证据可回灌：静态证据、trace 导入、内存快照和语义 review 产物都能继续反灌到 reconstruct 和 report。
- LLM 可深度介入：函数命名、函数解释、模块级重建 review 都已经是结构化 MCP workflow，而不是零散 prompt。
- 适合长任务编排：长耗时 workflow 会返回 `job_id`、进度和 `polling_guidance`，方便客户端按建议 sleep/wait，而不是高频轮询浪费 token。
- **分阶段非阻塞流水线**：分析按显式阶段组织（`fast_profile`、`enrich_static`、`function_map`、`reconstruct`、`dynamic_plan`、`dynamic_execute`、`summarize`），支持预览优先的工具合约和持久化运行状态。
- **HTTP 文件服务**：内嵌 HTTP API（端口 18080），支持样本上传、产物下载、上传会话管理，API Key 认证。
- **Web 实时监控面板**：`http://localhost:18080/dashboard` — 暗色主题，8 个标签页，展示工具、插件、样本、分析历史、报告查看器、配置、系统资源和 SSE 事件流。支持实时日志流显示。
- **SSE 实时事件**：`/api/v1/events` 实时推送分析进度、样本导入、服务器状态变更。
- **插件 SDK**：15 个内置插件，热加载/卸载，第三方自动发现。

## 本轮新增的静态初筛能力

这一轮在深度逆向前补了一层更强的静态初筛能力：

- `static.capability.triage`：用 `capa` 风格的能力识别回答“样本可能具备什么行为能力”，而不只是展示字符串或导入表。
- `pe.structure.analyze`：把 `pefile` 和 `LIEF` 风格的 PE 结构解析合并成一个统一输出，同时保留后端细节块。
- `compiler.packer.detect`：补上编译器、保护器和壳归因，并在 Detect It Easy 缺失时优雅降级成 setup guidance。
- `workflow.triage`、`report.summarize` 和 `report.generate` 现在会直接消费这三类结果，并支持 static artifact 的 provenance、scope 和 compare/baseline。

## 典型使用路径

### 快速初筛

1. `sample.ingest`
2. `static.capability.triage`
3. `pe.structure.analyze`
4. `compiler.packer.detect`
5. `workflow.triage`
6. `report.summarize`

### 困难 native 恢复

1. `ghidra.analyze`
2. `workflow.function_index_recover`
3. `workflow.reconstruct`

### LLM 辅助精修

1. `workflow.reconstruct`
2. `workflow.semantic_name_review`
3. `workflow.function_explanation_review`
4. `workflow.module_reconstruction_review`

## 这个项目适合做什么

它不是一组一次性的本地脚本，而是一层可组合、可复盘、可扩展的逆向分析能力。

适合的典型场景：

- 快速初筛 Windows PE 样本
- 查看导入、导出、字符串、壳线索、运行时类型和二进制角色
- 在有 Ghidra 时做反编译、CFG、搜索和函数重建
- 在 Ghidra 函数提取失败时继续恢复可用的函数索引
- 在 Java、Python 依赖或 Ghidra 缺失时返回结构化安装/配置指引
- 在分析失败时返回更详细的 Ghidra 诊断、日志路径和 remediation hints
- 关联静态证据、运行时 trace、内存快照和语义 review 产物
- 导出带可选 build / harness 验证的源码风格重建结果

## 核心能力

### 样本与静态分析

- `sample.ingest`
- `sample.profile.get`
- `static.capability.triage`
- `pe.structure.analyze`
- `compiler.packer.detect`
- `pe.fingerprint`
- `pe.imports.extract`
- `pe.exports.extract`
- `pe.pdata.extract`
- `dll.export.profile`
- `com.role.profile`
- `strings.extract`
- `strings.floss.decode`
- `yara.scan`
- `runtime.detect`
- `packer.detect`
- `binary.role.profile`
- `system.setup.guide`

### Ghidra 与函数分析

- `ghidra.health`
- `ghidra.analyze`
- `code.functions.list`
- `code.functions.rank`
- `code.functions.search`
- `code.function.decompile`
- `code.function.disassemble`
- `code.function.cfg`
- `code.functions.reconstruct`

### Rust 与困难 native 样本恢复

- `code.functions.smart_recover`
- `pe.symbols.recover`
- `code.functions.define`
- `rust_binary.analyze`
- `workflow.function_index_recover`

### .NET 与托管分析

- `dotnet.metadata.extract`
- `dotnet.types.list`
- `dotnet.reconstruct.export`

### 运行时证据与报告

- `dynamic.dependencies`
- `sandbox.execute`
- `dynamic.trace.import`
- `dynamic.memory.import`
- `dynamic.auto_hook` - 基于静态证据自动生成 Frida hook
- `dynamic.memory_dump` - 运行时内存转储与模式扫描
- `attack.map`
- `ioc.export`
- `report.summarize`
- `report.generate`
- `artifacts.list`
- `artifact.read`
- `artifacts.diff`
- `tool.help`

### Android / APK 分析

- `apk.structure.analyze` - APK 清单、权限、组件提取
- `apk.packer.detect` - APK 加壳/混淆检测
- `dex.decompile` - DEX 转 Java 反编译（jadx）
- `dex.classes.list` - DEX 类/方法枚举

### 符号执行与 CrackMe

- `symbolic.explore` - 基于 angr 的符号执行
- `keygen.verify` - 注册机/许可证验证（Qiling/angr）
- `constraint.solve` - Z3/angr 约束求解

### 恶意软件分析

- `malware.config.extract` - 恶意软件配置提取
- `malware.classify` - 家族分类（YARA + capa + 行为）
- `c2.extract` - C2 基础设施提取

### 跨平台与可视化

- `elf.macho.parse` - ELF/Mach-O 头部/段解析（Rizin）
- `rizin.diff` - 二进制差异比较（函数/基本块级别）
- `cfg.visualize` - 控制流图可视化（DOT/SVG/JSON）
- `timeline.correlate` - 多源事件时间线关联
- `cross_module.xref` - 跨模块交叉引用分析
- `kb.search` - 知识库语义搜索

### 语义 review 与重建

- `code.function.rename.prepare`（已废弃，使用 `llm.analyze`）
- `code.function.rename.review`（已废弃，使用 `llm.analyze`）
- `code.function.rename.apply`（已废弃，使用 `llm.analyze`）
- `code.function.explain.prepare`（已废弃，使用 `llm.analyze`）
- `code.function.explain.review`（已废弃，使用 `llm.analyze`）
- `code.function.explain.apply`（已废弃，使用 `llm.analyze`）
- `code.module.review.prepare`（已废弃，使用 `llm.analyze`）
- `code.module.review`（已废弃，使用 `llm.analyze`）
- `code.module.review.apply`（已废弃，使用 `llm.analyze`）
- `code.reconstruct.plan`
- `code.reconstruct.export`

### LLM 辅助分析

- `llm.analyze` - 统一 LLM 分析接口（替代已废弃的三步骤工具）
  - `task: 'summarize'` - 精简摘要
  - `task: 'explain'` - 清晰解释
  - `task: 'recommend'` - 可操作建议
  - `task: 'review'` - 代码审查

## 高层 Workflow

### `workflow.triage`

适合第一轮快速初筛，在深入恢复前先获得 PE 画像和分析方向。

### `workflow.deep_static`

长耗时静态分析流水线，适合更深入的函数排序和静态覆盖，支持异步 job 模式。

### `workflow.reconstruct`

这是当前最重要的高层重建入口。它可以：

- 执行 binary preflight
- 识别 Rust 倾向样本
- 识别 DLL 生命周期、导出分发、callback surface 和 COM activation 线索
- 在 Ghidra 函数索引缺失或退化时自动恢复函数索引
- 导出 native 或 .NET 的重建结果
- 可选执行 build 验证和 harness 验证
- 根据 DLL / COM / Rust 的角色画像自动调整导出策略
- 在环境不满足时返回结构化 setup guidance
- 在前台或后台 job 模式下返回阶段化进度信息
- 把 runtime / semantic provenance 和 diff 一起带到结果中
- 返回结构化 `ghidra_execution`，直接暴露项目路径、日志、阶段进度和 Java 异常摘要

### `workflow.function_index_recover`

困难 native 样本的高层恢复链：

1. `code.functions.smart_recover`
2. `pe.symbols.recover`
3. `code.functions.define`

当 Ghidra 已分析但函数提取为空或退化时，优先走这条链。

### `workflow.semantic_name_review`

供外部 LLM 执行函数命名 review 的高层 workflow。它可以准备证据、通过 MCP sampling 发起命名 review、应用结果，并可选刷新 `reconstruct/export`。当刷新 export 时，同样会返回 `ghidra_execution`。

### `workflow.function_explanation_review`

供外部 LLM 执行函数解释 review 的高层 workflow。它可以准备证据、请求结构化解释、应用结果，并可选重跑 `reconstruct/export`。当刷新 export 时，也会带上 `ghidra_execution`。

### `workflow.module_reconstruction_review`

供外部 LLM 执行模块级重建 review 的高层 workflow。它可以准备模块证据、请求结构化模块摘要和重写建议、应用结果，并可选刷新 `reconstruct/export`。当刷新 export 时，也会带上 `ghidra_execution`。

## 通用恢复模型

这个 Server 不假设 Ghidra 一定能正确提取函数。

对于 Rust、Go、重优化 native 或其他困难样本，推荐恢复链是：

1. `ghidra.analyze`
2. 如果 Ghidra post-script 提取失败，则走 `pe.pdata.extract`
3. 用 `code.functions.smart_recover` 恢复函数边界
4. 用 `pe.symbols.recover` 恢复命名线索
5. 用 `code.functions.define` 导入函数索引
6. 再继续使用 `code.functions.list`、`code.functions.rank`、`code.functions.reconstruct` 或 `workflow.reconstruct`

也就是说，系统会把：

- `function_index`
- `decompile`
- `cfg`

拆成不同的能力状态，而不是混成单一的“分析成功/失败”。

## Evidence Scope 与 Semantic Scope

多数高层工具支持显式作用域控制，避免历史证据污染当前结果。

运行时证据作用域：

- `evidence_scope=all`
- `evidence_scope=latest`
- `evidence_scope=session`，配合 `evidence_session_tag`

语义命名 / 函数解释 / 模块 review 作用域：

- `semantic_scope=all`
- `semantic_scope=latest`
- `semantic_scope=session`，配合 `semantic_session_tag`

也支持基线对比：

- `compare_evidence_scope`
- `compare_evidence_session_tag`
- `compare_semantic_scope`
- `compare_semantic_session_tag`

静态分析 artifact 也支持独立作用域：

- `static_scope=all`
- `static_scope=latest`
- `static_scope=session`，配合 `static_session_tag`

静态基线对比参数：

- `compare_static_scope`
- `compare_static_session_tag`

这样 MCP 客户端不只能够问“当前结果是什么”，还可以问“和上一轮证据或语义 review 相比变化了什么”。

## Ghidra 执行摘要

高层输出现在会显式返回 `ghidra_execution`，而不是把 Ghidra 行为隐藏在泛化的成功/失败状态后面。

它会告诉你：

- 当前使用的是哪一条分析记录
- 结果来自 `best_ready` 还是 `latest_attempt`
- project path、project root、log root
- command log 和 runtime log 路径
- function extraction 状态和所用脚本
- 阶段化 progress 信息
- 解析后的 Java exception 摘要

这层信息已经能在以下入口看到：

- `workflow.reconstruct`
- `workflow.semantic_name_review` 的 export refresh 结果
- `workflow.function_explanation_review` 的 export refresh 结果
- `workflow.module_reconstruction_review` 的 export refresh 结果
- `report.summarize`
- `report.generate`

## LLM 参与的 Review 层

当前已经支持三层结构化 review：

- 函数命名 review
- 函数解释 review
- 模块重建 review

统一流程是：

1. 准备结构化证据包
2. 在客户端支持 sampling 时发起受约束 review
3. 把接受的结果写回稳定 semantic artifact
4. 按显式 `semantic_scope` 重跑 `reconstruct/export/report`

## 异步 Job 模式

以下长任务支持排队执行和后台完成：

- `workflow.deep_static`
- `workflow.reconstruct`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`
- `workflow.module_reconstruction_review`

配套任务工具：

- `task.status`
- `task.cancel`
- `task.sweep`

排队后的 workflow 输出和 `task.status` 现在都会返回 `polling_guidance`。
当 Ghidra 或 reconstruct 这类长任务仍在排队或运行时，MCP 客户端应优先按
这个建议执行一次 sleep/wait，再查询下一次状态，而不是立即高频轮询。

## 环境 Bootstrap 与安装引导

如果用户一开始没有配好 Python 依赖、动态分析依赖或 Ghidra，可以使用：

- `system.health`
- `dynamic.dependencies`
- `ghidra.health`
- `system.setup.guide`

这些工具会返回结构化的：

- `setup_actions`
- `required_user_inputs`

方便 MCP 客户端显式要求用户执行：

- `python -m pip install ...`
- 设置 `JAVA_HOME`
- 提供 `GHIDRA_PATH` / `GHIDRA_INSTALL_DIR`
- 提供 `GHIDRA_PROJECT_ROOT` / `GHIDRA_LOG_ROOT`
- 提供 `CAPA_RULES_PATH`
- 提供 `DIE_PATH`
- 安装 Speakeasy / Frida 等可选动态分析依赖

### Frida 动态 Instrumentation（可选）

对于运行时 API 追踪和行为分析，安装 Frida：

```bash
pip install frida frida-tools
```

**环境变量**（可选 - 当 `frida` 在 PATH 中时自动检测）：

- `FRIDA_SERVER_PATH` - Frida server 二进制文件路径，用于 USB/远程设备分析
- `FRIDA_DEVICE` - 设备 ID 或 "usb" 用于 USB 设备选择（默认：本地 spawn）

**内置脚本** 位于 `frida_scripts/`：
- `api_trace.js` - Windows API 追踪与参数日志
- `string_decoder.js` - 运行时字符串解密
- `anti_debug_bypass.js` - 反调试检测中和
- `crypto_finder.js` - 加密 API 检测
- `file_registry_monitor.js` - 文件/注册表操作追踪

使用示例见 [`docs/EXAMPLES.md`](./docs/EXAMPLES.md#场景 -9-frida-运行时 instrumentation)。

## 当前开发进度

### 最新 Release: v1.0.0-beta.2

**稳定功能** (生产环境可用)：
- PE 初筛与静态分析 (`static.capability.triage`, `pe.structure.analyze`, `compiler.packer.detect`)
- Ghidra 辅助分析，完整执行可见性
- DLL/COM 画像 (`dll.export.profile`, `com.role.profile`)
- Rust 和 .NET 恢复路径
- 源码风格重建，支持 LLM 辅助 review 层
- 运行时证据导入与关联
- Android/APK 分析 (`apk.structure.analyze`, `dex.decompile`, `dex.classes.list`, `apk.packer.detect`)
- 符号执行与 CrackMe 工具 (`symbolic.explore`, `keygen.verify`, `constraint.solve`)
- 恶意软件分析 (`malware.config.extract`, `malware.classify`, `c2.extract`)
- 跨平台二进制解析 (`elf.macho.parse`, `rizin.diff`)
- 可视化与关联 (`cfg.visualize`, `timeline.correlate`, `cross_module.xref`, `kb.search`)
- Frida 动态 Instrumentation (`frida.runtime.instrument`, `frida.script.inject`, `frida.trace.capture`)
- HTTP 文件服务 REST API（端口 18080）— 样本上传、产物 CRUD、SSE 事件
- **Web 监控面板** (`http://localhost:18080/dashboard`) — 工具、插件、样本、分析历史、报告查看器（Markdown/JSON/HTML/SVG）、配置、系统实时监控，支持服务器日志流
- **插件 SDK**：15 个内置插件，热加载/卸载，第三方自动发现
- **生产基础设施**：限流、配置校验、分页、重试、批量分析、SBOM 生成
- **SSE 实时事件**：Server-Sent Events 实时推送分析进度

### 服务全景（Docker）

Docker 部署时（`docker-compose up -d`），容器暴露：

| 服务 | 访问方式 | 说明 |
|------|----------|------|
| MCP Server | stdio (`docker exec -i`) | 160 个工具、3 个 prompt、16 个 resource |
| HTTP API | `http://localhost:18080/api/v1/*` | 样本/产物/上传/健康检查 REST API |
| Web 面板 | `http://localhost:18080/dashboard` | 实时监控 SPA（8 标签页，暗色主题） |
| SSE 事件 | `http://localhost:18080/api/v1/events` | 分析事件实时推送 |
| 面板 API | `http://localhost:18080/api/v1/dashboard/*` | 12 个 JSON 端点 |

### 内置插件（15 个）

| 插件 | ID | 工具数 | 说明 |
|------|----|--------|------|
| Android / APK | `android` | 4 | APK 清单、DEX 反编译、加壳检测 |
| 恶意软件分析 | `malware` | 4 | C2 提取、配置解析、家族分类、沙箱报告 |
| CrackMe 自动化 | `crackme` | 4 | 验证定位、符号执行、补丁、注册机 |
| 动态分析 | `dynamic` | 3 | 自动 Frida hook、trace 归因、内存转储 |
| Frida Instrumentation | `frida` | 3 | 运行时 instrumentation、脚本注入、trace 采集 |
| Ghidra 集成 | `ghidra` | 2 | 无头 Ghidra 分析与健康检查 |
| 跨模块分析 | `cross-module` | 3 | 跨二进制比较、调用图、DLL 依赖树 |
| 可视化 | `visualization` | 3 | HTML 报告、行为时间线、数据流图 |
| 知识库 | `kb-collaboration` | 2 | 函数签名匹配、分析模板 |
| PE 分析 | `pe-analysis` | 6 | PE 结构、导入、导出、指纹、pdata、符号恢复 |
| 漏洞扫描 | `vuln-scanner` | 2 | 漏洞模式扫描与摘要 |
| 威胁情报 | `threat-intel` | 2 | ATT&CK 映射与 IOC 导出 |
| 调试会话 | `debug-session` | 6 | GDB/LLDB 调试会话管理 |
| 内存取证 | `memory-forensics` | 6 | 内存转储分析、volatility 集成 |
| 可观测性 | `observability` | 1 | 工具调用 hook 追踪与指标 |

插件通过 `PLUGINS` 环境变量控制（`*` = 全部, `android,malware` = 指定, `-dynamic` = 排除）。详见 [`docs/PLUGINS.md`](./docs/PLUGINS.md)。

### 开发中（beta 后续迭代）

对于新的静态初筛能力，最常见的可选依赖是：

- `flare-capa`
- `pefile`
- `lief`
- 通过 `CAPA_RULES_PATH` 指向的 capa rules bundle
- 通过 `DIE_PATH` 指向的 Detect It Easy CLI

对于 Ghidra 12.0.4，当前默认要求 Java 21+。如果 Java 缺失或版本过低，`ghidra.health`、`system.health` 和 `system.setup.guide` 都会返回明确的兼容性提示。

当 Ghidra 命令失败时，Server 现在会保留：

- command log
- Ghidra runtime log（如果可用）
- 解析后的 Java exception 摘要
- 结构化 remediation hints

而不是只返回一个笼统的 `exit code 1`。

内置的 `ghidra_scripts/` 目录现在会按安装包根目录或仓库根目录解析，
而不是按当前工作目录解析。这样即使用户从别的目录启动 Server，也不会
再因为找不到 `ExtractFunctions.py` / `ExtractFunctions.java` 而失败。

## 项目结构

```text
bin/                         npm CLI 入口
dist/                        编译后的 TypeScript 输出
ghidra_scripts/              Ghidra 辅助脚本
frida_scripts/               Frida instrumentation 脚本（同时作为 MCP resource）
helpers/DotNetMetadataProbe/ .NET 元数据辅助项目
src/                         MCP Server 源码
  index.ts                   入口（~90 行）
  server.ts                  MCPServer 类
  tool-registry.ts           集中式工具/prompt/resource 注册
  plugins.ts                 插件框架（15 个内置 + 自动发现）
  safe-command.ts            命令注入防护
  python-process-pool.ts     Python worker 并发池
  streaming-progress.ts      MCP 进度通知
  config-validator.ts        运行时配置校验
  logger.ts                  Pino 结构化日志
  tools/                     工具定义与处理器（~90 个文件）
  plugins/                   插件目录（15 个内置插件）
  api/
    file-server.ts           HTTP API（端口 18080）
    rate-limiter.ts          请求限流
    sse-events.ts            Server-Sent Events
    dashboard/index.html     Web 监控面板
    routes/
      dashboard-api.ts       面板 JSON API（12 个端点）
tests/                       单元与集成测试（207 个测试文件）
workers/                     Python worker、YARA 规则、动态分析辅助
packages/plugin-sdk/         独立 Plugin SDK npm 包
docs/                        文档
```

## 环境要求

必须：

- Node.js 18+
- npm 9+
- Python 3.9+

强烈建议：

- Ghidra，用于 native 反编译与 CFG
- Java 21+，供 Ghidra 12.0.4 使用
- .NET SDK，用于 `dotnet.metadata.extract`
- Clang，用于 reconstruct export 编译验证
- [`requirements.txt`](./requirements.txt) 中的 Python 依赖
- [`workers/requirements.txt`](./workers/requirements.txt) 中的 worker 依赖

## 本地开发

安装 JavaScript 依赖：

```bash
npm install
```

安装 Python worker 依赖：

```bash
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

构建：

```bash
npm run build
```

测试：

```bash
npm test
```

本地启动：

```bash
npm start
```

## MCP 客户端配置

### 通用 stdio 配置

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["/absolute/path/to/repo/dist/index.js"],
      "cwd": "/absolute/path/to/repo",
      "env": {
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

### 本地安装脚本

- Codex: [`install-to-codex.ps1`](./install-to-codex.ps1)
- Claude Code: [`install-to-claude.ps1`](./install-to-claude.ps1)
- GitHub Copilot: [`install-to-copilot.ps1`](./install-to-copilot.ps1)

相关文档：

- [`CODEX_INSTALLATION.md`](./CODEX_INSTALLATION.md)
- [`COPILOT_INSTALLATION.md`](./COPILOT_INSTALLATION.md)
- [`CLAUDE_INSTALLATION.md`](./CLAUDE_INSTALLATION.md)

## 持久化存储

默认情况下，运行时状态会写到用户目录和稳定系统目录，而不是跟随当前工作目录漂移：

- Windows workspace root: `%USERPROFILE%/.rikune/workspaces`
- SQLite database: `%USERPROFILE%/.rikune/data/database.db`
- File cache: `%USERPROFILE%/.rikune/cache`
- Audit log: `%USERPROFILE%/.rikune/audit.log`
- Ghidra project root: `%ProgramData%/.rikune/ghidra-projects`
- Ghidra log root: `%ProgramData%/.rikune/ghidra-logs`
- Ghidra 内置脚本目录：自动从安装包根目录解析

可以通过环境变量或用户配置文件覆盖：

- `%USERPROFILE%/.rikune/config.json`
- `WORKSPACE_ROOT`
- `DB_PATH`
- `CACHE_ROOT`
- `AUDIT_LOG_PATH`
- `GHIDRA_PROJECT_ROOT`
- `GHIDRA_LOG_ROOT`
- `CAPA_RULES_PATH`
- `DIE_PATH`

## 样本导入说明

对于 VS Code、Copilot 这类本地 IDE 客户端，优先使用本地文件路径：

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "E:/absolute/path/to/sample.exe"
  }
}
```

只有当客户端无法访问与 Server 相同的文件系统时，才使用 `bytes_b64`。

## 发布到 npm

发布包包含：

- 编译后的 `dist/`
- `bin/` 中的 CLI 入口
- Python workers 和 YARA 规则
- Ghidra 辅助脚本
- .NET metadata helper 源码
- MCP 客户端安装脚本

不包含：

- tests
- 本地 workspaces
- caches
- 生成的 reports
- 临时草稿和内部进度文档

发布前检查：

1. 更新 [`package.json`](./package.json) 中的版本号
2. 运行 `npm run release:check`
3. 检查 `npm run pack:dry-run`
4. 执行 `npm login`
5. 执行 `npm publish --access public`

仓库内置的 GitHub 自动化：

- [`ci.yml`](./.github/workflows/ci.yml)
- [`publish-npm.yml`](./.github/workflows/publish-npm.yml)
- [`dependabot.yml`](./.github/dependabot.yml)

如果通过 GitHub Actions 发布，请配置仓库级 `NPM_TOKEN` secret。

## 安全边界

这个项目面向分析工作流，而不是实时恶意行为操作。

当前强项：

- PE 初筛与分类支持
- 逆向证据抽取
- IOC 与 ATT&CK 导出
- 运行时证据导入与关联
- 源码风格重建与 review

当前非目标：

- 对复杂 native 二进制恢复原始源码
- 仅靠静态证据就高置信完成恶意家族归因
- 对所有壳实现完全自动脱壳
- 对重优化代码中的每个函数都完成高置信语义恢复

## 贡献与发布流程

- 贡献指南：[`CONTRIBUTING.md`](./CONTRIBUTING.md)
- 质量评估说明：[`docs/QUALITY_EVALUATION.md`](./docs/QUALITY_EVALUATION.md)
- 示例 benchmark corpus：[`examples/benchmark-corpus.example.json`](./examples/benchmark-corpus.example.json)
- 安全策略：[`SECURITY.md`](./SECURITY.md)

## 使用已发布的 npm 包

先启动 Docker runtime：

```powershell
docker compose up -d mcp-server
```

然后在 MCP 客户端中使用已发布的 npm launcher：

```json
{
  "mcpServers": {
    "rikune": {
      "command": "npx",
      "args": ["-y", "rikune", "docker-stdio"],
      "env": {
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

发布态的职责划分是：

- `npm/npx` 只负责启动 MCP launcher
- Docker Compose 容器负责真实分析 runtime

现有源码直跑方式和直接 `docker exec` 方式仍然可用。

## License

MIT 许可证，详见 [`LICENSE`](./LICENSE)。
