# mixia-nmhost

把浏览器扩展接到已解锁的桌面客户端。Go + `golang.org/x/sys`，无 cgo，不需要管理员权限。同一个程序两种身份：

```
浏览器 ──stdio──▶ mixia-nmhost chrome-extension://<id>/
                       │ 命名管道 \\.\pipe\mixia-fill-<用户 SID>
                  mixia-nmhost --serve ──stdio──▶ Electron 主进程 ──IPC──▶ 渲染进程（库和判断）
```

管道放在 Go 里而不是 Node 里建：Node 建的管道默认 Everyone 可读，也拿不到对端进程。

## 身份

第一个参数决定身份，其他情况退出码 2。

| 参数 | 身份 |
|---|---|
| `chrome-extension://ikicghdoopckcolomkneepiooaengmep/` | native messaging host，浏览器启动 |
| `--serve` | 管道服务，Electron 启动，stdin 关闭时退出 |

扩展 ID 钉在三处，`TestExtensionIDPinned` 核对它们一致：`main.go` 的常量、`online.feian.mixia.json` 的
`allowed_origins`、`apps/extension/manifest.json` 公钥算出来的 ID。

## 协议

浏览器和 host 之间、host 和管道服务之间：4 字节小端长度 + JSON。请求严格串行，Windows 同步管道上读写不能并发。
管道服务和 Electron 之间：每行一个 JSON，`{"conn":连接号,"msg":{...}}`。

| op | 字段 | 成功回复 | 说明 |
|---|---|---|---|
| `status` | | `{state}`，`ready` 或 `locked` | |
| `list` | `origin` | `{items:[{ref,title,username}]}` | 匹配的云库条目，最多 50 条，没有密码 |
| `fill` | `origin, ref` | `{username,password}` | 桌面确认后给这一条。只接受云库条目 |
| `pick` | `origin` | `{username,password}` | 在桌面窗口选账号再确认，本地库条目只走这里 |

所有消息带 `id`。失败是 `{id,ok:false,error}`：

| error | 含义 |
|---|---|
| `bad_request` | 操作名或字段不对，请求没有进管道 |
| `locked` | 桌面端未解锁 |
| `no_match` | 条目不属于这个站点，或不存在 |
| `denied` | 用户拒绝或超时 |
| `busy` | 已有一个确认框在等 |
| `timeout` | 界面没有响应 |
| `desktop_unavailable` | host 生成：连不上管道 |
| `bad_reply` | host 生成：桌面的回复不符合这个操作的形状 |

## 这个程序负责什么

- `parseRequest`：操作和字段是固定的，多一个字段也拒绝。通过后转发的是重新编码的结构，不是收到的字节。管道服务那一侧再校验一遍。
- `filterReply`：按操作收紧回复，只有 `fill` 和 `pick` 能带密码。桌面端的 bug 不会让 `list` 把密码送进浏览器。
- 管道 DACL 只有当前用户，拒绝远程客户端，`FILE_FLAG_FIRST_PIPE_INSTANCE` 防止名字被抢。
- 两端用 `GetNamedPipeClientProcessId` / `GetNamedPipeServerProcessId` 核对对方跑的是这个程序本身。没通过的连接一个字节都不读。

这个程序不判断站点匹配，也不判断能不能给密码，那些都在 `packages/core/src/browserfill.ts`。

## 限制

- 身份核对的前提是安装目录普通用户改不了。安装程序会把安装目录收紧成只有管理员和 SYSTEM 能写，装到自定义目录也一样。
- 同用户恶意程序可以直接启动这个程序，身份核对挡不住。它能列出某个站点的云库标题和用户名，拿密码仍要用户在桌面确认。
- 没有 macOS 和 Linux 的传输，`pipe_other.go` 是占位。

## 构建与测试

```bash
go build -trimpath -ldflags "-s -w" -o dist/mixia-nmhost.exe .
go test -count=1 .
```

测试用真实命名管道，用 PowerShell 充当外部程序，验证外来客户端和冒充的服务端都过不了。
