# 发布与服务器安装

测试和生产服务器都在服务器本机执行适用于各自系统的安装脚本。仓库不保存服务器地址、
SSH 用户、私钥路径，也不提供远程 SSH 部署脚本。

## 正式发布

1. 确认工作区干净，并完成前端测试与构建、Go 全量测试、`go vet`、`go build`；涉及
   并发存储或状态采集时同时运行 `go test -race ./...`。
2. 提交并推送 `main`，按语义化版本创建并推送标签。
3. 运行 `GOCACHE=/private/tmp/wireguard-panel-go-cache ./scripts/build-release.sh`。
4. 校验生成的 `.sha256`，创建正式 GitHub Release，并上传安装包与校验文件。
5. 确认 Release 不是草稿或预发布版本，且远端资产摘要与本地一致。

不得从未提交的工作区构建生产包。

## 服务器本机安装

在 Alpine Linux AMD64 服务器上以 root 执行：

```sh
wget -qO- \
  https://raw.githubusercontent.com/pch18/wireguard-panel/main/install-alpine.sh \
  | sh
```

在以 systemd 启动的 Debian AMD64 服务器上以 root 执行：

```sh
wget -O install-debian.sh \
  https://raw.githubusercontent.com/pch18/wireguard-panel/main/install-debian.sh \
  && sh ./install-debian.sh
```

两种安装器均使用 GitHub Latest Release。

## 安装后验收

在 Alpine 服务器检查服务和默认端口的健康接口：

```sh
rc-service wireguard-panel status
rc-update show default | grep wireguard-panel
wget -qO- http://127.0.0.1:5555/api/health
```

在 Debian 服务器检查服务和默认端口的健康接口：

```sh
systemctl is-active wireguard-panel
systemctl is-enabled wireguard-panel
curl -fsS http://127.0.0.1:5555/api/health
```

在两种系统上都应使用 `wg show` 检查 WireGuard 状态，从服务器外部访问面板和健康接口，
并确认 `/etc/wireguard-panel` 权限为 `0700`、
`auth.json` 权限为 `0600`。首次登录后立即修改默认密码。
