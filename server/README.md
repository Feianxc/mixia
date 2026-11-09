# mixia-server

密匣 Mixia 的同步服务端。服务器被当作不可信方：它只保存信任账本、密文变更日志、设备封装的库密钥和加密附件，
不解密任何内容，也没有账户、密码或会话。每个请求都由设备密钥直接签名。

协议以 [`../docs/协议规范.md`](../docs/协议规范.md) 为准。

## 运行

```sh
go run ./cmd/mixia-server serve
```

| 子命令 | 作用 |
|---|---|
| `serve` | 运行服务 |
| `backup <dest.db>` | 用 `VACUUM INTO` 写一份一致的数据库副本，可与运行中的服务并发；目标已存在时拒绝 |
| `verify` | 重放账本并核对库表和附件文件，打印不含内容的摘要；不通过时退出码非 0 |

`backup` 只复制数据库，`blobs/` 目录要单独备份。先备份数据库、后备份 `blobs/`，可以保证数据库引用的文件都在副本里。

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `MIXIA_ADDR` | `127.0.0.1:8096` | 监听地址 |
| `MIXIA_DATA` | `./data` | 数据目录（`mixia.db`、`blobs/`） |
| `MIXIA_QUOTA_BYTES` | `4294967296` | 总存储配额，统计变更密文和附件的字节数 |
| `MIXIA_BOOTSTRAP_TOKEN_SHA256` | 未设置 | 引导令牌 UTF-8 字节的 SHA-256（hex）。未设置时 bootstrap 不可用 |
| `MIXIA_TRUST_CF` | 未设置 | 设为 `1` 时限流按 `CF-Connecting-IP` 计。经 Cloudflare Tunnel 部署时必须开启，否则所有客户端共用 127.0.0.1 的令牌桶 |
| `MIXIA_RATE_RPS` | `5` | 每 IP 令牌补充速率（个/秒） |
| `MIXIA_RATE_BURST` | `30` | 每 IP 令牌桶容量 |

生成引导令牌的哈希：

```sh
printf %s "$TOKEN" | sha256sum
```

集成测试会连续制造认证失败，令牌桶可能耗尽并返回 429。这时把 `MIXIA_RATE_RPS` 和 `MIXIA_RATE_BURST` 调大。

## 构建

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/mixia-server ./cmd/mixia-server
go build -o dist/mixia-server-test.exe ./cmd/mixia-server
```

第一条的产物是不依赖 libc 的静态二进制，第二条给本机集成测试用。

## 测试

```sh
go vet ./...
go test ./...
```

`internal/edtest` 是测试专用的 Ed25519 精确运算，用来构造正常签名器不会产生的签名，不进入二进制。

## 请求认证

每个需认证的请求带 `X-Mx-Device`、`X-Mx-Ts`、`X-Mx-Nonce`、`X-Mx-Body`、`X-Mx-Sig`。`X-Mx-Body` 是 body 的
SHA-256，小写 hex 64 字符，空 body 也要带。签名串：

```
MIXIA-REQ-1\n{METHOD}\n{PATH?QUERY}\n{TS}\n{NONCE}\n{X-Mx-Body 的值}
```

服务端的处理顺序是解析请求头 → 检查时间戳和 nonce 格式 → 查设备或 root → 验签 → 记录 nonce → 读 body →
比对哈希。认证失败不读 body，所以没有密钥的人无法让服务器缓冲大请求。验签通过后 nonce 即作废，body 对不上的
请求不能用同一个 nonce 重试。

| 接口 | body 上限 |
|---|---|
| 未认证接口（`POST /v1/bootstrap`、`POST /v1/pair/{id}/request`） | 64 KiB |
| 其余需认证接口 | 8 MiB |
| `PUT .../blobs/{id}` | 50 MiB |
| `POST .../rotate` | 96 MiB |

`deploy/mixia-server.service` 的 `MemoryMax=512M` 按 96 MiB 的 rotate 估算。接近上限的 rotate 实测峰值工作集约
200 MiB（一万条以上的变更），单个极大变更时约 330 MiB。这是单个请求的数字，多个大请求并发时会叠加。

## 账本校验

规则以规范第 2 节为准。客户端用 libsodium 重放账本，服务端接受而客户端拒绝的条目会让所有客户端永久无法重放，
所以服务端必须至少和客户端一样严：

- Ed25519 验签用 `ledger.StrictVerify`，语义与 `crypto_sign_verify_detached` 一致：在 `crypto/ed25519` 之外，
  拒绝小阶 R、小阶公钥和非规范公钥。`device_add` 的 `signPub`、`genesis` 和 `root_rotate` 的 `rootPub` 也拒绝这两类公钥。
- `keyCommit`、`snapshotHash` 必须是恰好 32 字节的 base64url，`snapshotCount` 为 0 时也一样。
- 条目 body 必须是合法 UTF-8。
- `vault_rotate` 的 data 必须带非负整数 `logHead`。
- 规范列出的 data 字段都必填，公钥长度固定，`authPub` 必须在曲线上，`vaultId` 要符合 id 正则。

`vault_rotate` 和 `root_rotate` 只能走各自的接口，走 `POST /v1/ledger` 或 bootstrap 返回 `ledger_invalid`。

已有数据库里如果存在不满足上述规则的条目（比如没有 `logHead` 的 `vault_rotate`），启动时重放会失败。

## 换钥和换根

`POST /v1/vaults/{id}/rotate` 在事务里比较 `logHead` 和当前库 head。不相等说明快照之后日志有变化，直接返回 409
`{"error":"stale_snapshot","head":N}`，什么都不改，客户端重新做快照。服务端还会核对 `snapshotHash`，并要求 `keys`
覆盖 `recovery` 和所有对该库有权限的活跃设备。

`POST /v1/root/rotate` 只接受 root 认证，body 为 `{entry:{body,sig}, keys:[{vaultId,gen,wrapped}]}`。`entry` 必须是
`root_rotate`；`keys` 必须恰好覆盖账本中每个库的当前代，每库一条，`deviceId` 隐含 `recovery`。一个事务内追加账本并
替换全部 recovery 封装，不满足时返回 400，什么都不改。

## 规范未定义、由实现确定的线上细节

错误响应为 `{"error":"<code>"}`，状态码如下：

| 状态 | 错误码 |
|---|---|
| 400 | `bad_request`、`ledger_invalid` |
| 401 | `unauthorized` |
| 403 | `forbidden` |
| 404 | `not_found` |
| 409 | `ledger_conflict`（附 `head`）、`stale_snapshot`（附 `head`）、`stale_gen`、`pair_used` |
| 410 | `gone`、`pair_expired` |
| 413 | `too_large`、`quota_exceeded` |
| 429 | `rate_limited` |
| 500 | `internal` |

`ledger_conflict` 的 `head` 是账本 seq，`stale_snapshot` 的 `head` 是该库的 head。

成功响应：

| 接口 | 响应 |
|---|---|
| `POST /v1/bootstrap`、`POST /v1/root/rotate` | `{"ok":true,"head":N}`（账本 seq） |
| `POST /v1/ledger` | `{"head":N}` |
| `PUT .../keys`、`PUT`/`DELETE .../blobs/{id}`、`POST /v1/pair`、`POST .../request`、`POST .../grant`、`DELETE /v1/pair/{id}` | `{"ok":true}` |
| `POST .../rotate` | `{"ok":true,"ledgerHead":N}` |

配对 `status` 取值为 `open`、`requested`、`granted`；尚未产生的 `grant`、`request` 字段为 `null`。
`offer`、`request`、`grant` 是非空的 base64url 字符串，服务端不解析内容。
`/v1/ledger` 的 `head` 是账本 seq，账本为空时为 `-1`；库的 `head` 从 0 开始，第一条变更 seq 为 1。
