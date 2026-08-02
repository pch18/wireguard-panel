# 发布与生产部署

生产部署使用 GitHub Release 中经过 SHA-256 校验的 Linux AMD64 安装包。部署目标和
SSH 私钥属于本机信息，不提交到公开仓库；它们保存在当前克隆仓库的本地 Git 配置中。

## 本机目标配置

首次使用时设置：

```sh
git config wireguard-panel.deployHost SERVER_IP
git config wireguard-panel.deployUser root
git config wireguard-panel.deployIdentity /absolute/path/to/ssh-private-key
git config wireguard-panel.deploySshPort 22
git config wireguard-panel.deployPanelPort 5555
```

也可以临时使用同名大写环境变量，例如
`WIREGUARD_PANEL_DEPLOY_HOST`、`WIREGUARD_PANEL_DEPLOY_IDENTITY`。

## 正式发布

1. 确认工作区干净，并完成前端测试与构建、Go 全量测试、`go vet`、`go build`；涉及
   并发存储或状态采集时同时运行 `go test -race ./...`。
2. 提交并推送 `main`。
3. 按语义化版本创建并推送标签。
4. 运行 `GOCACHE=/private/tmp/wireguard-panel-go-cache ./scripts/build-release.sh`。
5. 校验生成的 `.sha256`，创建正式 GitHub Release，并上传安装包与校验文件。
6. 从 GitHub API 确认该版本是非草稿、非预发布版本，且远端资产摘要与本地一致。

不得从未提交的工作区构建生产包，也不得使用可变的 `main` 安装器部署指定版本。

## 部署与验收

部署指定 Release：

```sh
./scripts/deploy-alpine.sh v0.1.2
```

省略版本时脚本部署 GitHub Latest Release：

```sh
./scripts/deploy-alpine.sh
```

只验证现有线上服务，不执行安装或重启：

```sh
./scripts/deploy-alpine.sh --check
```

脚本会完成以下工作：

- 通过已知主机密钥和 `BatchMode` SSH 登录，不关闭主机密钥校验；
- 核对 Alpine Linux AMD64，并补齐 `curl`、`wireguard-tools`、`iproute2`；
- 下载指定标签中的安装器，并将旧版安装器的 Latest URL 固定到目标标签，再下载、校验
  同版本 Release 资产；
- 安装或升级 OpenRC 服务；安装器会等待回环健康接口成功，启动失败或健康检查失败时恢复
  上一版二进制、服务定义、启动状态和开机自启状态；
- 不执行 `wg-quick down/up`，不主动中断现有 WireGuard Interface；
- 验证服务状态、开机自启、监听端口、服务器回环健康接口和客户端到服务器的健康接口。

首次部署后还应确认 `/etc/wireguard-panel` 为 `0700`、`auth.json` 为 `0600`，并通过
登录、会话及 Interface 列表接口完成一次应用层验收。默认密码必须从网页账户菜单修改。

## 回滚

新进程启动失败或未能通过回环健康检查时，安装器会自动恢复升级前的面板状态。若新版本
已成功启动但仍需人工回滚，
重新运行脚本并传入上一正式版本标签即可：

```sh
./scripts/deploy-alpine.sh v0.1.1
```
