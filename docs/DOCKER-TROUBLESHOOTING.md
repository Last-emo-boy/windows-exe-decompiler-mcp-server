# Docker 故障排除指南

本文档提供 Rikune Docker 部署的常见问题解决方案。

## 目录

- [构建问题](#构建问题)
- [运行时问题](#运行时问题)
- [MCP 通信问题](#mcp-通信问题)
- [Ghidra 问题](#ghidra 问题)
- [性能问题](#性能问题)
- [安全问题](#安全问题)

---

## 构建问题

### 问题 1: 构建过程中断

**症状**:
```
ERROR: failed to solve: failed to compute cache key: failed to calculate checksum of ref ...
```

**原因**:
- Docker BuildKit 缓存损坏
- 网络中断导致下载失败

**解决方案**:
```bash
# 清理构建缓存
docker builder prune -a

# 不使用缓存重新构建
docker build --no-cache -t rikune:latest .

# 禁用 BuildKit（备选）
DOCKER_BUILDKIT=0 docker build -t rikune:latest .
```

---

### 问题 2: Ghidra 下载失败

**症状**:
```
ERROR [3/4] RUN curl -L -o ghidra.zip ...
curl: (6) Could not resolve host: github.com
```

**原因**:
- 网络连接问题
- DNS 解析失败

**解决方案**:
```bash
# 使用国内镜像源下载 Ghidra
# 修改 Dockerfile:
RUN curl -L -o ghidra.zip \
    "https://ghidra-sre.org/ghidra_12.0.4_PUBLIC_20250910.zip" \
    || curl -L -o ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_BUILD/ghidra_12.0.4_PUBLIC_20250910.zip"

# 或手动下载 Ghidra 并放入构建上下文
wget https://github.com/.../ghidra_12.0.4_PUBLIC_20250910.zip -O ghidra.zip
docker build --build-arg GHIDRA_ZIP_PATH=./ghidra.zip .
```

---

### 问题 3: 磁盘空间不足

**症状**:
```
ERROR: failed to register layer: write /opt/ghidra/...: no space left on device
```

**原因**:
- Docker 镜像层累积占用大量空间
- 系统磁盘空间不足

**解决方案**:
```bash
# 清理未使用的 Docker 资源
docker system prune -a --volumes

# 查看 Docker 磁盘使用
docker system df

# 移动 Docker 数据目录（Linux）
# 编辑 /etc/docker/daemon.json:
{
  "data-root": "/path/to/larger/disk"
}
```

---

## 运行时问题

### 问题 1: 容器启动失败

**症状**:
```
Error: Environment variable GHIDRA_INSTALL_DIR is not set
```

**原因**:
- 环境变量未正确传递

**解决方案**:
```bash
# 显式设置环境变量
docker run --rm -i \
  -e GHIDRA_INSTALL_DIR=/opt/ghidra \
  -e JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
  rikune:latest

# 或使用 --env-file
docker run --rm -i \
  --env-file .env \
  rikune:latest
```

---

### 问题 2: 权限错误

**症状**:
```
Permission denied: /app/workspaces
chown: cannot change ownership: Operation not permitted
```

**原因**:
- 挂载卷的权限与容器内用户不匹配
- 使用了只读挂载但未正确配置

**解决方案**:
```bash
# 修复 Host 权限
sudo chown -R 1000:1000 ~/.rikune/

# 或在容器内修复
docker run --rm -it \
  -v ~/.rikune:/app \
  rikune:latest \
  bash

# 容器内执行
chown -R appuser:appuser /app
```

---

### 问题 3: 样本文件无法访问

**症状**:
```
Error: Sample file not found: /samples/malware.exe
```

**原因**:
- 挂载路径不正确
- 文件权限问题

**解决方案**:
```bash
# 检查挂载
docker run --rm -it \
  -v $(pwd)/samples:/samples:ro \
  rikune:latest \
  ls -la /samples/

# 确保样本文件存在
ls -la samples/

# 使用绝对路径
docker run --rm -i \
  -v /absolute/path/to/samples:/samples:ro \
  rikune:latest
```

---

## MCP 通信问题

### 问题 1: stdio 通信中断

**症状**:
```
Error: write EPIPE
Error: This socket has been ended by the other party
```

**原因**:
- 容器意外退出
- stdin/stdout 缓冲问题

**解决方案**:
```bash
# 使用 -i 保持 stdin 打开
docker run -i --rm ...

# 不要使用 -t（TTY）模式，会干扰 stdio
# 错误：docker run -it ...
# 正确：docker run -i ...

# 检查容器退出码
docker run -i --rm rikune:latest node dist/index.js
echo $?  # 应为 0
```

---

### 问题 2: MCP Client 无法连接

**症状**:
```
MCP Server connection failed
Timeout waiting for server response
```

**原因**:
- MCP Client 配置错误
- Docker 命令参数不正确

**解决方案**:
```json
// 检查 MCP Client 配置
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "run",
        "-i",        // 必需：保持 stdin 打开
        "--rm",      // 推荐：自动清理
        "rikune:latest"
      ]
    }
  }
}

// 测试配置
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  docker run -i --rm rikune:latest node dist/index.js
```

---

### 问题 3: 响应超时

**症状**:
```
Error: Request timed out
```

**原因**:
- 分析耗时过长
- 资源限制太严格

**解决方案**:
```bash
# 增加资源限制
docker run --rm -i \
  --memory=8g \
  --cpus=4 \
  ...

# 增加 MCP Client 超时
// claude_desktop_config.json
{
  "mcpServers": {
    "rikune": {
      "timeout": 300000  // 5 分钟
    }
  }
}
```

---

## Ghidra 问题

### 问题 1: Ghidra 分析失败

**症状**:
```
Error: Ghidra analysis failed with exit code 1
Java exception: java.lang.OutOfMemoryError
```

**原因**:
- Java 堆内存不足
- 样本文件过大

**解决方案**:
```bash
# 增加 Java 堆内存
docker run --rm -i \
  -e JAVA_TOOL_OPTIONS="-Xmx8g" \
  --memory=12g \
  rikune:latest

# 或修改 Dockerfile
ENV JAVA_TOOL_OPTIONS="-Xmx8g -XX:+UseG1GC"
```

---

### 问题 2: Ghidra 脚本未找到

**症状**:
```
Error: Ghidra script not found: ExtractFunctions.py
```

**原因**:
- ghidra_scripts 目录未正确复制到镜像

**解决方案**:
```bash
# 验证脚本存在
docker run --rm rikune:latest \
  ls -la /app/ghidra_scripts/

# 检查 Dockerfile 中的 COPY 指令
# COPY ghidra_scripts/ /app/ghidra_scripts/
```

---

### 问题 3: Java 版本不兼容

**症状**:
```
Error: UnsupportedClassVersionError
Java version: 11, required: 21
```

**原因**:
- Java 版本不正确

**解决方案**:
```bash
# 验证 Java 版本
docker run --rm rikune:latest \
  java -version

# 应显示：
# openjdk version "21.x.x"

# 检查 Dockerfile 使用正确的 JDK
# FROM eclipse-temurin:21-jdk AS ghidra-stage
```

---

## 性能问题

### 问题 1: 镜像拉取慢

**症状**:
- 下载速度低于 1MB/s
- 拉取时间超过 30 分钟

**解决方案**:
```bash
# 使用国内镜像加速器
# /etc/docker/daemon.json (Linux)
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1panel.live"
  ]
}

# 重启 Docker
sudo systemctl restart docker

# 或使用离线导入
# 在另一台机器导出
docker save rikune:latest | gzip > mcp-image.tar.gz

# 在本机导入
docker load < mcp-image.tar.gz
```

---

### 问题 2: 分析速度慢

**症状**:
- 单个样本分析超过 10 分钟
- CPU 使用率低

**解决方案**:
```bash
# 增加 CPU 配额
docker run --rm -i \
  --cpus=4 \
  --cpu-shares=2048 \
  rikune:latest

# 减少并发分析数（避免资源竞争）
// config.json
{
  "workers": {
    "ghidra": {
      "maxConcurrent": 2  // 默认 4
    }
  }
}
```

---

### 问题 3: 内存不足

**症状**:
```
Error: JavaScript heap out of memory
Killed
```

**解决方案**:
```bash
# 增加 Node.js 内存限制
docker run --rm -i \
  -e NODE_OPTIONS="--max-old-space-size=4096" \
  --memory=8g \
  rikune:latest

# 或修改 Dockerfile
ENV NODE_OPTIONS="--max-old-space-size=4096"
```

---

## 安全问题

### 问题 1: 容器逃逸风险

**症状**:
- 容器内进程访问 Host 文件系统
- 可疑网络连接

**解决方案**:
```bash
# 立即停止容器
docker stop <container-id>

# 使用更严格的安全配置
docker run --rm -i \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --security-opt no-new-privileges:true \
  --cap-drop=ALL \
  --userns=host \
  rikune:latest

# 审查容器日志
docker logs <container-id>
```

---

### 问题 2: 恶意样本持久化

**症状**:
- 工作空间出现可疑文件
- 数据库记录异常

**解决方案**:
```bash
# 清理工作空间
rm -rf ~/.rikune/workspaces/*

# 重置数据库
rm ~/.rikune/data/database.db

# 重新构建镜像（确保无污染）
docker build --no-cache -t rikune:latest .
```

---

## 收集诊断信息

运行以下命令收集完整诊断信息：

```bash
#!/bin/bash
# collect-diiagnostics.sh

echo "=== Docker Version ==="
docker --version

echo "=== Docker Info ==="
docker info

echo "=== Image Info ==="
docker images rikune

echo "=== Container Logs ==="
docker run --rm rikune:latest node dist/index.js 2>&1 | head -50

echo "=== Ghidra Check ==="
docker run --rm rikune:latest \
  /opt/ghidra/support/analyzeHeadless -version

echo "=== Java Version ==="
docker run --rm rikune:latest java -version

echo "=== Node Version ==="
docker run --rm rikune:latest node --version

echo "=== Python Version ==="
docker run --rm rikune:latest python3 --version

echo "=== Disk Usage ==="
df -h

echo "=== Memory Usage ==="
free -h
```

将输出保存到 `diagnostics.txt` 并附带到 Issue 中。

---

## 获取帮助

如果以上方案无法解决问题：

1. **查看已有 Issue**: https://github.com/Last-emo-boy/rikune/issues
2. **提交新 Issue**: 附上诊断信息和复现步骤
3. **查看讨论区**: https://github.com/Last-emo-boy/rikune/discussions
