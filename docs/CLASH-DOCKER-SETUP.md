# Clash 配置说明 - 允许容器访问代理

## 问题原因

Docker 容器内的网络请求无法通过宿主机的 `127.0.0.1:7890` 代理，因为：
- 宿主机的 `127.0.0.1` = 宿主机自己
- 容器内的 `127.0.0.1` = 容器自己
- 容器需要通过 `host.docker.internal:7890` 访问宿主机代理
- 但 Clash 默认只监听 `127.0.0.1`，不接受来自容器网络的连接

## 解决方案

### 方式 1: 修改 Clash 配置（推荐）

编辑 Clash 配置文件（通常是 `config.yaml`）：

```yaml
# 允许局域网连接（关键配置）
allow-lan: true

# 或者指定监听所有接口
bind-address: "*"

# 或者指定监听特定 IP（宿主机的局域网 IP）
# bind-address: 192.168.x.x
```

**重启 Clash** 后验证：

```powershell
# Windows PowerShell
netstat -an | findstr 7890

# 应该看到：
# TCP    0.0.0.0:7890          0.0.0.0:0          LISTENING
# 或
# TCP    *:7890                *:*                LISTENING
#
# 而不是：
# TCP    127.0.0.1:7890        0.0.0.0:0          LISTENING
```

### 方式 2: 使用 Clash for Windows 界面

1. 打开 Clash for Windows
2. 进入 **Settings** 或 **Profile**
3. 找到 **Allow LAN** 选项
4. 开启 **Allow LAN Connection**
5. 重启 Clash

### 方式 3: 临时使用代理模式

如果无法修改 Clash 配置，可以：

1. 在容器内配置 apt 使用国内镜像（不通过代理）
2. 仅让 GitHub 下载走代理

---

## Docker 构建配置

### 使用国内镜像源

修改 Dockerfile 使用国内 apt 镜像：

```dockerfile
# 在 FROM 之后立即配置
RUN sed -i 's|http://deb.debian.org/debian|https://mirrors.aliyun.com/debian|g' /etc/apt/sources.list && \
    sed -i 's|http://security.debian.org/debian-security|https://mirrors.aliyun.com/debian-security|g' /etc/apt/sources.list
```

### 构建命令

```powershell
# 如果 Clash 已配置 allow-lan: true
docker build `
  --build-arg HTTP_PROXY=http://host.docker.internal:7890 `
  --build-arg HTTPS_PROXY=http://host.docker.internal:7890 `
  -t rikune:latest .

# 或者不使用代理（推荐，如果国内镜像可用）
docker build `
  --build-arg USE_MIRROR=true `
  -t rikune:latest .
```

---

## 验证步骤

### 1. 检查 Clash 监听地址

```powershell
netstat -an | findstr 7890
```

✅ **正确**: `0.0.0.0:7890` 或 `*:7890`
❌ **错误**: `127.0.0.1:7890`

### 2. 测试容器内代理访问

```powershell
docker run --rm -it `
  -e HTTP_PROXY=http://host.docker.internal:7890 `
  -e HTTPS_PROXY=http://host.docker.internal:7890 `
  alpine `
  sh -c "apk add curl && curl -x http://host.docker.internal:7890 https://www.google.com"
```

### 3. 检查防火墙

确保 Windows 防火墙允许 Docker 访问 Clash：

```powershell
# 以管理员身份运行
netsh advfirewall firewall add rule name="Clash LAN" dir=in action=allow protocol=TCP localport=7890
```

---

## 常见问题

### Q: 修改配置后仍然无法连接

A: 检查 Windows 防火墙：
1. 打开"Windows Defender 防火墙"
2. 高级设置 → 入站规则
3. 确保 Clash 或端口 7890 允许连接

### Q: 容器可以连接代理但速度慢

A: 使用国内镜像源：
- Debian: `mirrors.aliyun.com` 或 `mirrors.tuna.tsinghua.edu.cn`
- Ubuntu: `mirrors.aliyun.com` 或 `mirrors.ustc.edu.cn`
- PyPI: `pypi.tuna.tsinghua.edu.cn`
- npm: `registry.npmmirror.com`

### Q: Docker Desktop 版本问题

A: 确保 Docker Desktop 是最新版本，旧版本可能有网络问题。

---

## 完整配置示例

### Clash 配置 (`config.yaml`)

```yaml
port: 7890
socks-port: 7891
allow-lan: true  # 关键配置
bind-address: "*"

mode: rule
log-level: info

external-controller: 127.0.0.1:9090

proxies:
  # 你的代理配置...

proxy-groups:
  # 你的代理组配置...

rules:
  # Debian/Ubuntu 镜像源直连（推荐）
  - DOMAIN-SUFFIX,aliyun.com,DIRECT
  - DOMAIN-SUFFIX,tsinghua.edu.cn,DIRECT
  - DOMAIN-SUFFIX,ustc.edu.cn,DIRECT
  
  # GitHub 走代理
  - DOMAIN-SUFFIX,github.com,PROXY
  - DOMAIN,github.com,PROXY
  - DOMAIN-SUFFIX,githubusercontent.com,PROXY
  
  # 其他规则
  - MATCH,PROXY
```

### Dockerfile 片段

```dockerfile
# 使用国内 apt 镜像
RUN sed -i 's|http://deb.debian.org/debian|https://mirrors.aliyun.com/debian|g' /etc/apt/sources.list && \
    sed -i 's|http://security.debian.org/debian-security|https://mirrors.aliyun.com/debian-security|g' /etc/apt/sources.list && \
    apt-get update

# pip 使用国内镜像
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# npm 使用国内镜像
RUN npm config set registry https://registry.npmmirror.com
```

---

## 快速修复步骤

1. **修改 Clash 配置**: `allow-lan: true`
2. **重启 Clash**
3. **验证监听**: `netstat -an | findstr 7890` 应该显示 `0.0.0.0:7890`
4. **运行安装脚本**: `.\install-docker.ps1 -DataRoot "D:\Docker\rikune" -UseProxy`

如果仍然有问题，请运行诊断命令并提供输出：

```powershell
# 诊断脚本
Write-Host "=== Clash 监听地址 ===" -ForegroundColor Cyan
netstat -an | findstr 7890

Write-Host "`n=== Docker 网络 ===" -ForegroundColor Cyan
docker network ls

Write-Host "`n=== 测试容器内代理 ===" -ForegroundColor Cyan
docker run --rm -e HTTP_PROXY=http://host.docker.internal:7890 alpine sh -c "wget -O- http://host.docker.internal:7890 2>&1 | head -5"
```
