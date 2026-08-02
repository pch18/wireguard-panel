# WireGuard Panel

一个直接管理原生 WireGuard 配置文件的数据面板。没有数据库、SSO、用户表或 Redis；
管理员密码哈希单独保存在本机认证配置文件中。

## 架构边界

- 一个 Interface 对应标准目录中的一个 `/etc/wireguard/<name>.conf`。
- Interface 名称就是文件基础名，仅允许 1–15 位 ASCII 英文字母、数字、`-` 和 `_`。
- 普通配置编辑不包含名称；改名使用独立操作，运行中的 Interface 必须先手动停止，
  避免改名过程隐式中断隧道。
- Interface 和 Peer 的增删改按 Interface 串行执行。
- 文件使用 `0600` 权限，在同目录完成临时文件写入、`fsync` 与原子重命名。
- 创建会写入配置后启动隧道；运行中的 Interface 优先使用 `wg syncconf` 与 `ip` 命令
  热更新。DNS、从固定 MTU 切回自动计算，以及首次加入或移除默认路由等无法安全增量
  协调的变化必须先由用户二次确认，再由后端完成“预检新配置 → 使用旧文件停止 →
  原子写入新文件 → 启动并校验”的完整事务。
- 只要文件包含 `[Interface]` 就会进入面板；字段或语义问题作为可修复状态展示。原始
  配置可以在停用状态下原样保存，只有显式启动时才执行严格校验并调用 `wg-quick`。
- 删除会先确认隧道已停止，再删除配置文件。
- 后端在本次增量更新或启动完成后，会将 `wg-quick strip` 产生的目标配置与
  `wg showconf` 返回的实际配置逐项核对。只有文件、应用过程和校验全部成功时才返回；
  失败时恢复原文件及原运行状态。
  Peer Endpoint 会在认证流量到达后自动漫游，因此只作为初始目标应用，不参与后续静态一致性判断。
- 登录只有一个本机管理员；密码哈希持久化到受保护的配置文件，会话和流量历史只保存在
  Go 内存中。面板不保存第二份 WireGuard 运行快照或“待重启”状态。
- 给客户端的配置按需生成并以只读文本预览，不下载、也不会落成额外的服务端数据文件。

配置目录默认使用 WireGuard 标准目录 `/etc/wireguard`。开发或特殊部署可以通过
`APP_WIREGUARD_DIRECTORY` 指定绝对路径；后端会把该目录中的配置文件绝对路径直接交给
`wg-quick`，不会再回退到系统默认目录读取同名文件。

## 配置文件中的面板元数据

WireGuard 会忽略注释，因此面板把非官方字段放在其所属配置段的注释中：

```ini
# ClientEndpoint = vpn.example.com:51820
# ClientAllowedIPs = 10.0.0.0/8, fd00::/8

[Interface]
PrivateKey = ...
Address = 10.20.0.1/24
ListenPort = 51820

[Peer]
# Name = Alice MacBook
# PrivateKey = ...
PublicKey = ...
AllowedIPs = 10.20.0.2/32
```

PublicKey 是 Peer 的唯一标识。新增和导入时不允许重复 PublicKey；编辑时后端先用
请求路径中的原 PublicKey 定位配置块，再校验请求体中的新 PublicKey 未被其他
Peer 使用，因此可以安全换钥，也不会覆盖另一条 Peer。旧版面板写入的 `# ID`
注释会被兼容忽略，下一次保存时自动移除。

Peer 导入支持在同一份文本中连续粘贴多个 `[Peer]` 段。整批内容会在同一个后端事务中
完成解析、冲突校验和运行态同步；任意一段失败时不会导入其中任何 Peer。

Peer 私钥只要已知，就写入该 Peer 自己的 `# PrivateKey` 注释；无论它由系统生成还是
手动录入，后续处理完全相同。这样同一个原生配置文件包含生成客户端配置所需的全部
数据。配置目录必须保持 `0700`，文件必须保持 `0600`，备份也应按密钥材料处理。

## 支持字段

Interface 由面板管理并写回的字段：

```text
PrivateKey
ListenPort
Address
DNS
MTU
```

导入或读取旧配置时会兼容 `FwMark`、`Table`、`PreUp`、`PostUp`、
`PreDown`、`PostDown` 和 `SaveConfig`。面板不提供这些字段的结构化编辑，但会在保存时
原样保留，避免静默破坏已有的 wg-quick 行为。

Peer 官方字段：

```text
PublicKey
PresharedKey
AllowedIPs
Endpoint
PersistentKeepalive
```

面板元数据仅包括 Interface 的 Peer 默认 Endpoint、Peer 默认 AllowedIPs，以及 Peer
名称和已知私钥。
Interface 名称由 `.conf` 文件名推导，不再写入 `# Name` 注释。

生成客户端配置时，`[Interface] Address` 直接使用该 Peer `AllowedIPs` 的第一项，
`[Peer] Endpoint` 和 `[Peer] AllowedIPs` 使用 Interface 中配置的 Peer 默认参数，
`PersistentKeepalive` 固定写为 `25`，并且不写入 DNS。Interface PublicKey 始终根据
PrivateKey 实时计算，不写入配置文件。服务端 Interface 的 MTU 也不会写入客户端配置，
由客户端用户根据自身网络环境决定。

## MTU 探测

MTU 默认由管理员手动填写。Interface 表单也提供“探测”按钮：后端直接在 Go 进程中
使用带 DF 标志的 raw ICMP Echo 探测固定目标 `8.8.8.8`，不会调用 `ping` 或其他外部
命令。探测范围最高为 1500 字节，得到外层路径 MTU 后扣除 80 字节 WireGuard/IPv6
封装余量，并将建议值回填到 MTU 输入框；回填不会自动保存配置。

Linux、macOS 及主流 BSD 使用同一套 Go raw ICMP 实现；不调用系统 `ping`。raw ICMP
需要 root 或系统授予的 raw socket 权限（Linux 可使用 `CAP_NET_RAW`）。目标或中间网络禁止 ICMP、不同 WireGuard Peer
实际走不同路径时，探测可能失败或与该 Peer 的真实 PMTU 不同；此功能只提供当前主机到
固定目标路径的保守建议，失败时不会猜测或改写现有 MTU。

## 并发与原子事件

每次读取 Interface 都会返回 `revision`，它是当前配置文件原始字节的 SHA-256。
所有 PUT、DELETE 和 Peer 写操作必须通过 `If-Match` 发送该 revision。

后端处理一次事件时会：

1. 获取进程内配置锁；
2. 重新读取目标文件并核对 revision；
3. 按请求路径中的原 PublicKey 定位 Peer，并拒绝与其他 Peer 重复的新 PublicKey；
4. 再次完成字段、密钥、IP 和地址段冲突校验；
5. 对可增量处理的变化，先原子写入，再执行 `wg syncconf`、地址、路由或 MTU 热更新；
6. 对必须重建的变化，未携带明确确认时返回 `409 restart_required`；确认后先对候选文件
   执行 `wg-quick strip` 预检，再让 `wg-quick down` 使用尚未改写的旧文件完成停止，
   随后原子写入新文件并执行 `wg-quick up`；
7. 逐项核对本次目标 WireGuard 配置与 `wg showconf` 的结果；
8. 全部成功后才返回新 revision；任一步失败都会拒绝提交并尽力恢复原文件和原运行状态。

旧页面写入时返回 `412 stale_revision`，前端载入最新版本并要求用户检查后重试，
不会静默覆盖其他客户端的修改。没有 revision 的写操作返回 `428`。

同一 Interface 的文件与运行态操作会串行执行；创建、导入、改名和删除等会改变名称空间
的操作还会持有目录级锁。不同 Interface 的普通编辑可以并行，同名创建检查保持原子性。

## IP 地址规划

面板从 Interface `Address` 自动识别 IPv4/IPv6 子网，显示已占用地址，并为新 Peer
建议下一个可用的 Peer `AllowedIPs`，使用 `/32` 或 `/128` 主机路由。第一项同时用于
生成客户端 `[Interface] Address`。

Interface `ClientAllowedIPs` 是结构化地址选择器使用的路由范围约束，用于缩小候选项和
辅助规划；它不是 WireGuard 的访问控制，也不是后端保存或启动时的硬校验。已有配置、
原始配置导入以及其他合法 IP 族可以位于该范围之外。该字段只属于面板元数据，不属于
原生 WireGuard 运行配置：修改范围始终可以保存，不会停止或阻止 WireGuard 启动。

新增、导入或编辑 Peer 时，后端会重新校验并阻止：

- Peer 使用与 Interface 完全相同的主机地址；
- 同一或不同 Peer 出现规范化后完全相同的 AllowedIPs；
- 重复 PublicKey。

包含或相交但不完全相同的 Peer 前缀是 WireGuard 路由配置中的合法用法，不会被面板
擅自拒绝。路由范围约束仍会用于表单候选项，但最终可运行性由原生 WireGuard 配置校验
决定。

规划建议只是便捷输入；最终裁决始终由持锁后的服务端校验完成，因此两个页面同时选择
同一个建议地址时，只有先提交的一方会成功。

## 运行状态

服务只有一个 WireGuard 状态定时任务：每秒通过一个长期复用的 `wgctrl.Client` 读取一次
内核状态，一次采集同时覆盖所有 Interface 和 Peer，不再启动 `wg show` 子进程。HTTP 状态
查询只读取内存快照，也不会在后台比较配置文件与运行配置。面板自身不运行其他周期性
后台任务。
Peer 状态与流量使用两类独立 SSE 事件：Endpoint、握手、在线状态或 Interface 运行状态
发生变化后，在下一次 1 秒采集时立即推送；流量在后端按 5 秒窗口计算平均值并每 5 秒
推送一次。内存保留最近 1 小时的 5 秒速率采样，建立连接时先发送完整历史；折线图默认
展示最近 30 分钟。数据用于展示：

- 最近握手时间和当前 Endpoint；
- 累计接收/发送流量；
- 相邻采样之间的平均接收/发送速度及折线图；
- 活跃或不活跃持续时间。

外部停止的 Interface 会在下一次采样显示为已停用。面板允许原生 `wg`、`wg-quick` 或
其他系统工具同时存在，不尝试追踪某个 Interface 的启动来源，也不把外部文件编辑推断成
“待同步”状态。显式停止、删除和重启均直接使用当时的原生配置文件；面板发起的重启会先
完成配置解析、字段校验和 `wg-quick strip` 预检，预检失败时不会停止当前通道。

进程刚启动后的第一个 5 秒窗口完成前没有可计算的速率点，因此速度显示为零。
“活跃”表示最近 3 分钟内有过握手，是基于 WireGuard 数据的推断，不代表传统意义上的
长连接在线状态。读取失败不会影响配置管理，页面会明确显示状态不可用。

## 身份与密码配置

首次启动的默认账号密码为 `admin/admin5555`：

```bash
APP_PORT=5555
```

初始用户名和密码固定为 `admin/admin5555`，只在认证文件不存在时使用。认证文件格式为：

```json
{
  "version": 1,
  "username": "admin",
  "passwordHash": "$2a$..."
}
```

认证文件创建后，以文件中的用户名和 bcrypt 密码哈希为准。登录后可以从右上角账户菜单
直接修改密码，保存会立即写入认证文件并生效，同时注销除当前浏览器外的其他会话。认证
目录使用 `0700`、文件使用 `0600`，不会保存密码明文。

服务重启后内存会话会自然失效。当前面板按 HTTP 部署，Cookie 使用 HttpOnly 与
SameSite 保护，但不会设置 Secure 属性。

## 原生运行

项目发布为单个静态链接的 Linux AMD64 可执行文件，前端资源已经通过 Go `embed`
包含在二进制中，不需要额外的 Web 服务器或运行时。程序直接运行在 WireGuard 主机上：

- 默认读取和写入 `/etc/wireguard`，也可显式指定其他绝对目录；
- 通过 `wgctrl.Client` 读取 WireGuard 内核运行状态；
- 直接使用 raw ICMP 提供按需 MTU 探测，需要 root 或 `CAP_NET_RAW`；
- 默认监听 `0.0.0.0:5555` 并提供 HTTP 页面和 API；
- 需要拥有读写 WireGuard 配置及读取运行状态的权限，安装服务默认以 root 运行；
- 运行中 Interface 的结构化写操作会同步热更新；必须重建的字段会先二次确认，再自动
  调用 `wg-quick down/up`。停用 Interface 的写操作保持停用。运行中的 Interface 必须
  先停止才能改名。

当前正式安装方式是 Alpine Linux AMD64 + OpenRC。安装器只写入程序文件和 OpenRC
服务定义，不创建系统账户或数据库，服务始终以 root 运行。程序首次启动时会自行创建
受保护的认证文件，用于持久化网页中修改后的密码。升级只重启管理面板进程，不执行
`wg-quick down/up`，因此不会主动中断已经运行的 WireGuard Interface；若新面板进程
启动失败，安装器会恢复上一版二进制并尝试重新启动面板。

## Alpine 一键安装

Release 提供静态链接的 Linux AMD64 安装包及 SHA-256 校验文件。目标主机需要是
使用 OpenRC 的 Alpine Linux AMD64，并已安装 `curl`；安装器会自动补齐
`wireguard-tools` 和 `iproute2`。以 root 执行：

```bash
curl -fsSL \
  https://raw.githubusercontent.com/pch18/wireguard-panel/main/install-alpine.sh \
  | sh
```

安装器会：

- 安装缺失的 `wireguard-tools` 和 `iproute2`；
- 立即启用 IPv4 转发，并在内核支持 IPv6 时同时启用 IPv6 转发；转发设置写入
  `/etc/sysctl.d/99-wireguard-panel-forwarding.conf`，由 OpenRC 在启动时恢复；
- 从 GitHub Latest Release 下载 `wireguard-panel_linux_amd64.tar.gz`；
- 校验同名 `.sha256` 文件；
- 安装二进制到 `/usr/local/bin/wireguard-panel`；
- 写入 `/etc/init.d/wireguard-panel`，固定以 root 运行；
- 注册并启动 `wireguard-panel` OpenRC 服务；
- 启动或回环健康检查失败时回滚上一版面板二进制、服务定义和启动状态，不重启
  WireGuard Interface；
- 不创建系统账户，也不自动添加 NAT 或防火墙规则。

服务首次启动后，程序自行创建权限为 `0700` 的 `/etc/wireguard-panel` 和权限为
`0600` 的 `/etc/wireguard-panel/auth.json`。

初始账号密码是 `admin/admin5555`。首次登录后直接从右上角账户菜单修改密码。修改用户
名时先停止服务，编辑 `/etc/wireguard-panel/auth.json` 中的 `username`，然后重新启动。

如需修改监听端口，可创建可选的 `/etc/conf.d/wireguard-panel`：

```sh
printf '%s\n' \
  "export APP_PORT='5555'" \
  >/etc/conf.d/wireguard-panel
chmod 0600 /etc/conf.d/wireguard-panel
rc-service wireguard-panel restart
```

安装脚本本身不会创建这个可选环境文件。目前只支持 Alpine Linux AMD64。

维护者的 Release、生产部署、验收与回滚流程见 [DEPLOYMENT.md](DEPLOYMENT.md)。生产目标
和 SSH 私钥只保存在本地 Git 配置中，不进入公开仓库。

## 项目结构

```text
.
├── web/src/
│   ├── app/                    # 路由与 API 基础设施
│   ├── features/auth/          # 本地账号、密码修改与会话
│   ├── features/wireguard/     # 配置、导入、IP 规划与 Peer 状态
│   ├── layouts/                # 响应式页面框架
│   ├── pages/                  # Interface 列表与编辑页
│   └── ui/                     # Modal、Toast、Icon
├── srv/
│   ├── internal/
│   │   ├── config/             # 监听端口环境变量
│   │   ├── httpapi/            # Gin 原子事件 API
│   │   ├── model/              # API 模型
│   │   ├── mtuprobe/           # Go raw ICMP 路径 MTU 探测
│   │   ├── service/            # 密码文件、本地身份与内存会话
│   │   ├── wgconfig/           # 解析、密钥、IP 校验、原子存储
│   │   └── wgstatus/           # wg dump 内存采集
│   ├── web/                    # 前端构建产物
│   └── main.go
├── install-alpine.sh           # Alpine/OpenRC 一键安装
├── DEPLOYMENT.md               # Release、生产部署、验收与回滚
└── scripts/
    ├── build-release.sh        # 原生 AMD64 Release 构建
    └── deploy-alpine.sh        # 指定 Release 的生产部署与验收
```

## 本地开发

需要 Go 1.23+、Node.js 22+、pnpm 10。`system` 模式还需要 WireGuard 内核控制权限及
`wireguard-tools`；下面的本地开发方式使用 `file-only`，不会读取或控制系统真实接口：

```bash
mkdir -p /tmp/wireguard-panel-dev/wireguard
cd srv
APP_TUNNEL_MODE=file-only \
APP_WIREGUARD_DIRECTORY=/tmp/wireguard-panel-dev/wireguard \
APP_AUTHENTICATION_FILE=/tmp/wireguard-panel-dev/auth.json \
go run .
```

`file-only` 是本地开发模式：Interface 和 Peer 的增删改仍会原子写入
`APP_WIREGUARD_DIRECTORY`，但不会执行 `wg` 或 `wg-quick`，页面会明确显示“仅文件模式”，
手动启动 Interface 会返回明确错误。未设置这些环境变量时仍使用 `system`、
`/etc/wireguard` 和 `/etc/wireguard-panel/auth.json`，生产环境行为不变。

另一个终端：

```bash
cd web
corepack pnpm install
corepack pnpm dev
```

打开 `http://localhost:5173`，Vite 会把 `/api` 代理到
`http://localhost:5555`。

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
PUT    /api/v1/account/password
POST   /api/v1/wireguard/mtu-probe

GET    /api/v1/interfaces
POST   /api/v1/interfaces
GET    /api/v1/interfaces/:id
PUT    /api/v1/interfaces/:id
DELETE /api/v1/interfaces/:id
GET    /api/v1/interfaces/:id/raw-config
POST   /api/v1/interfaces/:id/start
POST   /api/v1/interfaces/:id/stop
POST   /api/v1/interfaces/:id/restart

GET    /api/v1/interfaces/:id/ip-plan
GET    /api/v1/interfaces/:id/status
POST   /api/v1/interfaces/:id/peers
PUT    /api/v1/interfaces/:id/peers/:publicKey
DELETE /api/v1/interfaces/:id/peers/:publicKey
GET    /api/v1/interfaces/:id/peers/:publicKey/config
GET    /api/v1/interfaces/:id/peers/:publicKey/client-config
```

Peer 路径中的 `:publicKey` 是将 WireGuard 标准 Base64 PublicKey 转换成的无填充
Base64URL 路径段；`PUT` 中它始终表示修改前的 PublicKey。

运行中 Interface 的写操作如果返回 `409 restart_required`，客户端应向用户明确说明会
短暂断联；用户确认后，以相同 revision 和请求体重试，并附加请求头
`X-WireGuard-Restart-Confirmed: true`。后端仍会重新读取文件、核对 revision 并重新分类，
不会仅凭该请求头跳过校验。
