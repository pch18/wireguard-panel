# 发布与服务器安装

项目只提供一个通用的 `install-alpine.sh`。测试和生产服务器都在服务器本机执行该脚本；
仓库不保存服务器地址、SSH 用户、私钥路径，也不提供远程 SSH 部署脚本。

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

安装器会使用 GitHub Latest Release。测试和生产服务器执行相同命令，不需要仓库中的
服务器配置或远程部署工具。

如果需要严格固定版本，应下载对应标签下的同一个安装器，并传入相同标签：

```sh
release_tag=vX.Y.Z
installer=/tmp/wireguard-panel-install.sh
wget -qO "$installer" \
  "https://raw.githubusercontent.com/pch18/wireguard-panel/${release_tag}/install-alpine.sh"
WIREGUARD_PANEL_RELEASE_TAG="$release_tag" sh "$installer"
rm -f "$installer"
```

## 安装后验收

在目标服务器执行：

```sh
rc-service wireguard-panel status
rc-update show default | grep wireguard-panel
wget -qO- http://127.0.0.1:5555/api/health
wg show
```

还应从服务器外部访问面板和健康接口，并确认 `/etc/wireguard-panel` 权限为 `0700`、
`auth.json` 权限为 `0600`。首次登录后立即修改默认密码。

## 回滚

安装器在新服务启动或健康检查失败时会自动恢复旧二进制、OpenRC 配置、运行状态和开机
启动状态。若新版本已成功运行但仍需人工回滚，在服务器本机重新执行上一正式标签的
`install-alpine.sh` 即可。
