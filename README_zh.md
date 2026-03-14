# Windows EXE Decompiler MCP Server

English version: [`README.md`](./README.md)

这是一个面向 Windows 可执行文件、DLL、COM 组件和 .NET 程序的 MCP Server。它把 PE 初筛、Ghidra 辅助分析、运行时证据导入、Rust/.NET 恢复、源码风格重建，以及 LLM 参与的语义 review 暴露成统一的 MCP 工具，供任何支持 tool calling 的 LLM 调用。

## 这个项目适合做什么

它不是一堆一次性的本地脚本，而是一层可复用、可编排、可复盘的逆向分析能力。

它适合用来：

- 快速初筛 Windows PE 样本
- 查看导入、导出、字符串、壳特征、运行时类型和二进制角色
- 在有 Ghidra 时做反编译、CFG、函数搜索和重建
- 在 Ghidra 函数提取失败时继续恢复函数索引
- 关联静态证据、运行时 trace、内存快照和语义 review 产物
- 导出带可选 build / harness 验证的源码风格重建结果

## 核心能力

### 样本与静态分析

- `sample.ingest`
- `sample.profile.get`
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
- `attack.map`
- `ioc.export`
- `report.summarize`
- `report.generate`
- `artifacts.list`
- `artifact.read`
- `artifacts.diff`
- `tool.help`

### 语义 review 与重建

- `code.function.rename.prepare`
- `code.function.rename.review`
- `code.function.rename.apply`
- `code.function.explain.prepare`
- `code.function.explain.review`
- `code.function.explain.apply`
- `code.module.review.prepare`
- `code.module.review`
- `code.module.review.apply`
- `code.reconstruct.plan`
- `code.reconstruct.export`

## 高层 workflow

### `workflow.triage`

适合第一轮快速初筛，先给出样本画像和方向。

### `workflow.deep_static`

长耗时静态分析流水线，适合更深入的函数排序和静态覆盖，支持异步 job 模式。

### `workflow.reconstruct`

这是当前最重要的高层重建入口。它可以：

- 执行 binary preflight
- 识别 Rust 倾向样本
- 识别 DLL 生命周期、导出分发、callback surface 和 COM 激活线索
- 在 Ghidra 函数索引缺失或退化时自动恢复函数索引
- 导出 native 或 .NET 的重建结果
- 可选执行 build 验证和 harness 验证
- 把 runtime / semantic provenance 和 diff 一起带到结果中
- 根据 DLL / COM / Rust 的角色画像自动调整导出策略

### `workflow.function_index_recover`

这是困难 native 样本的高层恢复链：

1. `code.functions.smart_recover`
2. `pe.symbols.recover`
3. `code.functions.define`

当 Ghidra 已分析但函数提取为空或退化时，优先走这条链。

### `workflow.semantic_name_review`

给外部 LLM 做函数语义命名 review 的高层 workflow。它可以准备证据、通过 MCP sampling 发起命名 review、应用结果，并可选刷新 reconstruct/export。

### `workflow.function_explanation_review`

给外部 LLM 做函数解释 review 的高层 workflow。它可以准备证据、请求结构化解释、应用结果，并可选重跑 reconstruct/export。

### `workflow.module_reconstruction_review`

给外部 LLM 做模块级重建 review 的高层 workflow。它可以准备模块证据、请求结构化模块摘要和改写建议、应用结果，并可选刷新 reconstruct/export。

## 通用恢复模型

这个 Server 不假设 Ghidra 一定能正确提取函数。

对于 Rust、Go、重优化 native 或其他困难样本，推荐恢复链是：

1. `ghidra.analyze`
2. 如果 Ghidra post-script 提取失败，则走 `pe.pdata.extract`
3. 用 `code.functions.smart_recover` 恢复函数边界
4. 用 `pe.symbols.recover` 恢复函数命名线索
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

这样 MCP 客户端不止能问“当前结果是什么”，还可以问“和上一轮证据或语义 review 相比变化了什么”。

## LLM 参与的 review 层

当前已经支持三层结构化 review：

- 函数命名 review
- 函数解释 review
- 模块重建 review

统一流程是：

1. 准备结构化证据包
2. 在客户端支持 sampling 时发起受约束 review
3. 把接受的结果写回稳定 semantic artifact
4. 按显式 semantic scope 重跑 reconstruct/export/report

## 异步 job 模式

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

## 环境 bootstrap 与安装引导

如果用户一开始没有配 Python 依赖、动态分析依赖或 Ghidra，可以使用：

- `system.health`
- `dynamic.dependencies`
- `ghidra.health`
- `system.setup.guide`

这些工具会返回结构化的：

- `setup_actions`
- `required_user_inputs`

方便 MCP 客户端显式要求用户执行：

- `python -m pip install ...`
- 提供 `GHIDRA_PATH` / `GHIDRA_INSTALL_DIR`
- 安装 Speakeasy / Frida 等可选动态分析依赖

## 项目结构

```text
bin/                         npm CLI 入口
dist/                        TypeScript 编译输出
ghidra_scripts/              Ghidra 辅助脚本
helpers/DotNetMetadataProbe/ .NET 元数据辅助项目
src/                         MCP Server 源码
tests/                       单元与集成测试
workers/                     Python worker、YARA 规则、动态分析辅助
install-to-codex.ps1         Codex 本地安装脚本
install-to-copilot.ps1       GitHub Copilot 本地安装脚本
install-to-claude.ps1        Claude Code 本地安装脚本
docs/QUALITY_EVALUATION.md   回归与发布质量检查说明
```

## 环境要求

必需：

- Node.js 18+
- npm 9+
- Python 3.9+

强烈建议：

- Ghidra，用于 native 反编译与 CFG
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
    "windows-exe-decompiler": {
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

## 持久化目录

默认情况下，运行时状态会放在用户目录下，而不是当前工作目录：

- Windows workspace root: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/workspaces`
- SQLite database: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/data/database.db`
- file cache: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/cache`
- audit log: `%USERPROFILE%/.windows-exe-decompiler-mcp-server/audit.log`

也可以通过环境变量或用户配置文件覆盖：

- `%USERPROFILE%/.windows-exe-decompiler-mcp-server/config.json`

## 本地样本导入提示

对于本地 IDE 客户端，优先传绝对路径：

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "E:/absolute/path/to/sample.exe"
  }
}
```

只有当客户端和 Server 不共享同一文件系统时，才使用 `bytes_b64`。

## 发布到 npm

发布包包含：

- 编译后的 `dist/`
- `bin/` CLI 入口
- Python worker 与 YARA 规则
- Ghidra 辅助脚本
- .NET 元数据辅助源码
- MCP 客户端安装脚本

不包含：

- tests
- 本地 workspace
- cache
- 生成报告
- 草稿文档和内部进度记录

发布前检查：

1. 更新 [`package.json`](./package.json) 中的版本号。
2. 运行 `npm run release:check`。
3. 检查 `npm run pack:dry-run`。
4. 执行 `npm login`。
5. 执行 `npm publish --access public`。

仓库内置 GitHub 自动化：

- [`ci.yml`](./.github/workflows/ci.yml)
- [`publish-npm.yml`](./.github/workflows/publish-npm.yml)
- [`dependabot.yml`](./.github/dependabot.yml)

如果要用 GitHub Actions 自动发布，请配置仓库 secret：

- `NPM_TOKEN`

## 安全边界

这个项目用于分析工作流，不是实时恶意操作工具。

当前强项：

- PE 初筛与角色画像
- 逆向证据提取
- IOC 与 ATT&CK 导出
- 运行时证据导入与关联
- 源码风格重建与语义 review

当前非目标：

- 复杂 native 二进制的原始源码恢复
- 仅靠静态证据对家族归因给出绝对结论
- 对所有壳实现全自动脱壳
- 对所有重优化函数给出高置信的完整语义恢复

## 贡献与发布流程

- Contributor guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Quality evaluation notes: [`docs/QUALITY_EVALUATION.md`](./docs/QUALITY_EVALUATION.md)
- Example benchmark corpus: [`examples/benchmark-corpus.example.json`](./examples/benchmark-corpus.example.json)
- Security policy: [`SECURITY.md`](./SECURITY.md)

## 使用已发布的 npm 包

```json
{
  "mcpServers": {
    "windows-exe-decompiler": {
      "command": "npx",
      "args": ["-y", "windows-exe-decompiler-mcp-server"],
      "env": {
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

## License

MIT 协议，见 [`LICENSE`](./LICENSE)。
