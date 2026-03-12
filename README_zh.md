# Windows EXE Decompiler MCP Server

English version: [`README.md`](./README.md)

一个面向 Windows 二进制逆向分析的 MCP Server。

它把 PE 画像、native 与 .NET 分析、Ghidra 辅助反编译、运行时证据导入、重建工作流与报告生成统一暴露为 MCP tools，供任何支持 tool calling 的 LLM 调用。

## 项目用途

这个项目的目标不是提供一堆一次性的本地脚本，而是把逆向分析能力沉淀成可复用、可编排、可复盘的 MCP 工具面。

典型用途包括：

- Windows PE 样本快速画像
- 导入表、导出表、字符串、YARA 分析
- Ghidra 辅助反编译、CFG、函数搜索
- .NET 元数据与结构分析
- 运行时 trace 和内存快照导入
- 函数命名与解释 review 工作流
- 带验证 harness 的源码风格重建导出

## 当前能力

### 静态分析

- `sample.ingest`
- `sample.profile.get`
- `pe.fingerprint`
- `pe.imports.extract`
- `pe.exports.extract`
- `strings.extract`
- `strings.floss.decode`
- `yara.scan`
- `runtime.detect`
- `packer.detect`
- `binary.role.profile`

### Ghidra 与代码分析

- `ghidra.health`
- `ghidra.analyze`
- `code.functions.list`
- `code.functions.rank`
- `code.functions.search`
- `code.function.decompile`
- `code.function.disassemble`
- `code.function.cfg`
- `code.functions.reconstruct`

### 重建与 review 工作流

- `code.reconstruct.plan`
- `code.reconstruct.export`
- `dotnet.metadata.extract`
- `dotnet.types.list`
- `dotnet.reconstruct.export`
- `workflow.triage`
- `workflow.deep_static`
- `workflow.reconstruct`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`

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

## 目录结构

```text
bin/                         npm CLI 入口
dist/                        编译后的 TypeScript 输出
ghidra_scripts/              Ghidra 辅助脚本
helpers/DotNetMetadataProbe/ .NET 元数据辅助项目
src/                         TypeScript MCP server 源码
tests/                       单元与集成测试
workers/                     Python worker、YARA 规则、动态分析辅助
install-to-codex.ps1         本地 Codex 安装脚本
install-to-copilot.ps1       本地 GitHub Copilot 安装脚本
docs/QUALITY_EVALUATION.md   回归与发布质量评测清单
```

## 环境要求

必需：

- Node.js 18+
- npm 9+
- Python 3.9+

强烈建议：

- Ghidra，用于 native 反编译与 CFG 能力
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

编译：

```bash
npm run build
```

运行测试：

```bash
npm test
```

本地启动：

```bash
npm start
```

## MCP 客户端配置

### 通用 stdio 配置

大多数 MCP 客户端都可以用下面的方式启动：

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

仓库已经提供了本地安装脚本：

- Codex: [`install-to-codex.ps1`](./install-to-codex.ps1)
- Claude Code: [`install-to-claude.ps1`](./install-to-claude.ps1)
- GitHub Copilot: [`install-to-copilot.ps1`](./install-to-copilot.ps1)

配套文档：

- [`CODEX_INSTALLATION.md`](./CODEX_INSTALLATION.md)
- [`COPILOT_INSTALLATION.md`](./COPILOT_INSTALLATION.md)
- [`CLAUDE_INSTALLATION.md`](./CLAUDE_INSTALLATION.md)

## 样本导入说明

对于本地 IDE 客户端，例如 VS Code 或 Copilot，优先这样调用：

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "E:/absolute/path/to/sample.exe"
  }
}
```

只有当 MCP 客户端无法访问与 MCP Server 相同的文件系统时，才使用 `bytes_b64`。

## 发布到 npm

### npm 包包含什么

发布的 npm 包包含：

- 编译后的 `dist/`
- `bin/` 中的 CLI 入口
- Python workers 与 YARA 规则
- Ghidra 辅助脚本
- .NET 元数据辅助源码
- MCP 客户端安装脚本

不会包含：

- tests
- 本地 workspaces
- cache
- 生成的报告
- 草稿和阶段性内部文档

### 发布前检查

1. 确认 npm 包名可用。
2. 更新 [`package.json`](./package.json) 里的版本号。
3. 运行：

```bash
npm run release:check
```

4. 查看 dry-run 打包结果：

```bash
npm run pack:dry-run
```

5. 登录 npm：

```bash
npm login
```

6. 发布：

```bash
npm publish
```

### GitHub Actions

仓库当前已经包含：

- [`ci.yml`](./.github/workflows/ci.yml)：构建、Python 语法检查、关键单测、`npm pack --dry-run`
- [`publish-npm.yml`](./.github/workflows/publish-npm.yml)：在 `v*` tag 或手动触发时发布 npm，并创建附带 tarball 的 GitHub Release
- [`dependabot.yml`](./.github/dependabot.yml)：每周检查 npm 与 GitHub Actions 依赖更新

在使用 GitHub Actions 发 npm 之前，需要先配置仓库 secret：

- `NPM_TOKEN`

建议的发布流程：

```bash
npm version patch
git push origin main --follow-tags
```

推送 tag 后就会触发发布工作流。

## 贡献

本地开发、验证和发版流程见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)。

发布前的回归与评测建议见 [`docs/QUALITY_EVALUATION.md`](./docs/QUALITY_EVALUATION.md) 和
[`examples/benchmark-corpus.example.json`](./examples/benchmark-corpus.example.json)。

## 安全

漏洞披露和运行边界见 [`SECURITY.md`](./SECURITY.md)。

### 发布后如何使用

发布到 npm 后，MCP 客户端可以用 `npx`：

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

## 安全边界

这个项目是为分析工作流设计的，不是为真实恶意操作而设计。当前更擅长的是：

- 样本画像与初步分类
- 逆向证据提取
- IOC 与 ATT&CK 导出
- 运行时证据导入与关联
- 源码风格重建与 review

当前明确不承诺的能力：

- 复杂 native 二进制的原始源码恢复
- 仅靠静态证据就做高置信家族归因
- 对所有壳做全自动脱壳
- 对重优化代码中的每个函数都做高置信语义恢复

## 许可证

本项目使用 MIT 许可证，见 [`LICENSE`](./LICENSE)。
