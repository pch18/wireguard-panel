# WireGuard Panel

一个只使用原生 WireGuard 配置文件的数据面板。没有数据库、SSO、用户表、Redis，
也没有旁路业务配置文件。

## 架构边界

- 一个 Interface 对应标准目录中的一个 `/etc/wireguard/wg<ID>.conf`。
- 新建 Interface 时取现有最大 ID 加一，例如 `wg0.conf`、`wg1.conf`。
- Interface 和 Peer 的增删改都是单次原子文件事件。
- 文件使用 `0600` 权限，在同目录完成临时文件写入、`fsync` 与原子重命名。
- 只管理配置文件，不执行 `wg-quick up/down`，不会擅自改变运行中的接口。
- 登录只有一个来自环境变量的管理员；会话和运行状态都只保存在 Go 内存中。
- 给客户端的配置按需生成并下载，不会落成额外的服务端数据文件。

默认配置目录是 WireGuard 标准目录 `/etc/wireguard`。`WG_CONFIG_DIR` 只用于本地
开发或特殊部署时覆盖目录，必须是绝对路径。

## 配置文件中的面板元数据

WireGuard 会忽略注释，因此面板把非官方字段放在其所属配置段的注释中：

```ini
# Name = Tokyo Gateway
# ClientEndpoint = vpn.example.com:51820
# ClientDNS = 1.1.1.1
# ClientAllowedIPs = 0.0.0.0/0, ::/0

[Interface]
PrivateKey = ...
Address = 10.20.0.1/24
ListenPort = 51820

[Peer]
# ID = 12416d97-1b8c-4c36-bd4d-06dc4e458e4f
# Name = Alice MacBook
# PrivateKey = ...
# SystemGenerated = true
# ClientAddress = 10.20.0.2/24
# ClientPersistentKeepalive = 25
PublicKey = ...
AllowedIPs = 10.20.0.2/32
```

`# ID` 是 Peer 创建后不变的身份。后端按这个 ID 定位配置块，所以更换 PublicKey
不会把编辑操作错误地落到另一个 Peer。旧配置如果没有 ID，会先基于原公钥得到一个
稳定的兼容 ID，并在下一次写入时持久化到文件。

系统生成 Peer 密钥对时，私钥写入该 Peer 自己的 `# PrivateKey` 注释。这样同一个
原生配置文件包含生成客户端配置所需的全部数据。配置目录必须保持 `0700`，文件必须
保持 `0600`，备份也应按密钥材料处理。

> `SaveConfig = true` 会让 `wg-quick` 在接口停止时用运行状态重写文件，可能清除
> Peer ID、名称和客户端私钥等注释。面板完整支持这个官方字段，但在面板管理的环境
> 中强烈建议保持关闭。

## 支持字段

Interface 官方字段：

```text
PrivateKey
ListenPort
FwMark
Address
DNS
MTU
Table
PreUp
PostUp
PreDown
PostDown
SaveConfig
```

Peer 官方字段：

```text
PublicKey
PresharedKey
AllowedIPs
Endpoint
PersistentKeepalive
```

面板元数据还包括 Interface/Peer 名称、客户端 Endpoint/DNS/AllowedIPs/Address/
PersistentKeepalive、稳定 Peer ID 和系统生成的 Peer 私钥。

## 并发与原子事件

每次读取 Interface 都会返回 `revision`，它是当前配置文件原始字节的 SHA-256。
所有 PUT、DELETE 和 Peer 写操作必须通过 `If-Match` 发送该 revision。

后端处理一次事件时会：

1. 获取进程内配置锁；
2. 重新读取目标文件并核对 revision；
3. 按稳定 Peer ID 修改内存模型；
4. 再次完成字段、密钥、IP 和地址段冲突校验；
5. 原子替换原配置文件并返回新 revision。

旧页面写入时返回 `412 stale_revision`，前端载入最新版本并要求用户检查后重试，
不会静默覆盖其他客户端的修改。没有 revision 的写操作返回 `428`。

当前锁覆盖整个配置目录，保证同一进程内多个客户端的操作可以串行化。文件名 ID 的
分配也在同一把锁内完成。

## IP 地址规划

面板从 Interface `Address` 自动识别 IPv4/IPv6 子网，显示已占用地址，并为新 Peer
建议下一可用的：

- 客户端 `ClientAddress`，保留 Interface 的子网前缀；
- 服务端 Peer `AllowedIPs`，使用 `/32` 或 `/128` 主机路由。

保存前后端都会重新校验，阻止：

- Peer ClientAddress 与 Interface Address 相同；
- 两个 Peer 使用相同 ClientAddress；
- ClientAddress 不属于 Interface 任一子网；
- 不同 Peer 的 AllowedIPs 地址段重叠；
- 重复 Peer ID 或 PublicKey。

规划建议只是便捷输入；最终裁决始终由持锁后的服务端校验完成，因此两个页面同时选择
同一个建议地址时，只有先提交的一方会成功。

## 运行状态

服务每 2 秒执行一次 `wg show all dump`，并只在 Go 内存中维护：

- 最近握手时间和当前 Endpoint；
- 累计接收/发送流量；
- 当前接收/发送速度；
- 活跃或不活跃持续时间；
- 最近一小时、每分钟粒度的接收/发送流量。

重启后历史自然丢失。“活跃”表示最近 3 分钟内有过握手，是基于 WireGuard 数据的
推断，不代表传统意义上的长连接在线状态。读取失败不会影响配置管理，页面会明确显示
状态不可用。

## 身份与环境变量

默认账号密码为 `admin/admin`：

```bash
APP_PORT=8080
APP_USERNAME=admin
APP_PASSWORD=admin
WG_CONFIG_DIR=/etc/wireguard
APP_COOKIE_SECURE=false
```

账号、密码和会话都不写入磁盘。生产环境必须覆盖默认密码，并在 HTTPS 部署时设置
`APP_COOKIE_SECURE=true`。服务重启后，内存会话会自然失效。

## Docker

只管理配置文件时：

```bash
docker build -t wireguard-panel .
docker run --rm \
  -p 8080:8080 \
  -v /etc/wireguard:/etc/wireguard \
  -e APP_PASSWORD='replace-with-a-strong-password' \
  wireguard-panel
```

如需在 Linux 主机上读取宿主机运行中的 WireGuard 状态，容器还要与接口处于同一
网络命名空间，并有读取 WireGuard netlink 信息的权限：

```bash
docker run --rm \
  --network host \
  --cap-add NET_ADMIN \
  -v /etc/wireguard:/etc/wireguard \
  -e APP_PASSWORD='replace-with-a-strong-password' \
  wireguard-panel
```

镜像包含 `wireguard-tools`。默认以 root 运行，是为了访问宿主机通常由 root 持有且
权限为 `0700/0600` 的 WireGuard 目录；若目录权限已按其他 UID 调整，可在部署平台
指定对应用户。

## Alpine 一键安装

Release 提供静态链接的 Linux AMD64 安装包及 SHA-256 校验文件。在 Alpine
Linux AMD64 上以 root 执行：

```bash
curl -fsSL \
  https://raw.githubusercontent.com/pch18/wireguard-panel/main/install-alpine.sh \
  | sh
```

安装器会：

- 从 GitHub Latest Release 下载 `wireguard-panel_linux_amd64.tar.gz`；
- 校验同名 `.sha256` 文件；
- 安装二进制到 `/usr/local/bin/wireguard-panel`；
- 安装 `curl`、OpenRC 和 `wireguard-tools`；
- 创建权限为 `0600` 的 `/etc/conf.d/wireguard-panel`；
- 注册并启动 `wireguard-panel` OpenRC 服务；
- 保留升级前已经存在的环境配置。

首次安装可以直接设置管理员密码：

```bash
curl -fsSL \
  https://raw.githubusercontent.com/pch18/wireguard-panel/main/install-alpine.sh \
  | APP_PASSWORD='replace-with-a-strong-password' sh
```

默认仍为 `admin/admin`，生产环境务必修改
`/etc/conf.d/wireguard-panel` 中的 `APP_PASSWORD`。目前 Release 安装器只支持
Linux AMD64 Alpine。

私有仓库可以通过具有 Release 读取权限的 Token 安装：

```bash
curl -fsSL \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github.raw+json" \
  https://api.github.com/repos/pch18/wireguard-panel/contents/install-alpine.sh \
  | WIREGUARD_PANEL_GITHUB_TOKEN="${GITHUB_TOKEN}" sh
```

## 项目结构

```text
.
├── web/src/
│   ├── app/                    # 路由与 API 基础设施
│   ├── features/auth/          # 环境账号登录与会话
│   ├── features/wireguard/     # 配置、IP 规划、Peer 状态与流量图
│   ├── layouts/                # 响应式页面框架
│   ├── pages/                  # Interface 列表与编辑页
│   └── ui/                     # Modal、Toast、Icon
├── srv/
│   ├── internal/
│   │   ├── config/             # 环境变量
│   │   ├── httpapi/            # Gin 原子事件 API
│   │   ├── model/              # API 模型
│   │   ├── service/            # 本地身份与内存会话
│   │   ├── wgconfig/           # 解析、密钥、IP 校验、原子存储
│   │   └── wgstatus/           # wg dump 内存采集
│   ├── web/                    # 前端构建产物
│   └── main.go
└── Dockerfile
```

## 本地开发

需要 Go 1.23+、Node.js 22+、pnpm 10；状态采集还需要 `wg` 命令。开发时建议使用
临时目录：

```bash
cd srv
WG_CONFIG_DIR=/tmp/wireguard-panel go run .
```

另一个终端：

```bash
cd web
corepack pnpm install
corepack pnpm dev
```

打开 `http://localhost:5173`，Vite 会把 `/api` 代理到
`http://localhost:8080`。

## 构建与测试

```bash
cd web
corepack pnpm test
corepack pnpm build

cd ../srv
go test ./...
go vet ./...
go build -o app .
```

前端构建写入 `srv/web`，随后由 Go `embed` 打进同一个可执行文件。

## API

```text
GET    /api/health
POST   /api/v1/login
POST   /api/v1/logout
GET    /api/v1/session

GET    /api/v1/interfaces
POST   /api/v1/interfaces
GET    /api/v1/interfaces/:id
PUT    /api/v1/interfaces/:id
DELETE /api/v1/interfaces/:id

GET    /api/v1/interfaces/:id/ip-plan
GET    /api/v1/interfaces/:id/status
POST   /api/v1/interfaces/:id/peers
PUT    /api/v1/interfaces/:id/peers/:peerID
DELETE /api/v1/interfaces/:id/peers/:peerID
GET    /api/v1/interfaces/:id/peers/:peerID/client-config
```
