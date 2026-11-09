# mixia-hwkey

密匣桌面端的 Windows 硬件密钥助手。Electron 把它作为长驻子进程启动，用它访问 TPM 里的
设备认证私钥（P-256）和封存设备秘密的 RSA 密钥。Go + `ncrypt.dll`，无 cgo，不需要管理员权限。

## 协议

stdin/stdout 每行一个 JSON，串行处理，stdin EOF 时以 0 退出。这是控制台程序，
Electron 里用 `spawn(path, { windowsHide: true })`。stderr 始终为空。

```
{"id":1,"cmd":"sign","args":{"name":"...","data":"..."}}
{"id":1,"ok":true,"result":{"sig":"..."}}
{"id":1,"ok":false,"error":"no_key","message":"NCryptOpenKey: SECURITY_STATUS 0x80090016"}
```

二进制字段都是无填充 base64url。`name` 须符合 `^[A-Za-z0-9_-]{1,64}$`，区分大小写。
无法解析的行以 `"id":null` 响应，单行上限 2 MiB，之后的请求不受影响。

| cmd | args | result | 说明 |
|---|---|---|---|
| `status` | | `{provider, available, level}` | `level` 为 `hardware` 或 `none` |
| `create` | `name` | `{authPub}` | 建 `Mixia-Auth-<name>`（ECDSA P-256）和 `Mixia-Seal-<name>`（RSA 2048），65 字节未压缩点 |
| `pub` | `name` | `{authPub}` | |
| `sign` | `name, data` | `{sig}` | 对 data 算 SHA-256 后签名，64 字节 `r\|\|s`。data 上限 1 MiB |
| `seal` | `name, data` | `{blob, alg}` | data 0 到 190 字节，blob 256 字节 |
| `unseal` | `name, blob, alg?` | `{data}` | 把 seal 返回的 `alg` 传回来；省略时依次试 SHA-256、SHA-1 |
| `delete` | `name` | `{auth, seal}` | 各表示这把密钥是否存在并已删除；两把都不存在时报 `no_key` |

| error | 含义 |
|---|---|
| `no_key` | 密钥不存在（`0x80090016` 等） |
| `exists` | 名字已被占用（`0x8009000F`），已有密钥不受影响 |
| `tpm_unavailable` | TPM 或 TBS 服务不可用、锁定、自检中，可稍后重试 |
| `failed` | 其他失败，包括 TPM 拒绝具体操作（如 blob 被篡改，`0x80280084`） |
| `bad_request` | 参数不合法，未触碰 TPM |

`create` 报 `exists` 而 `pub` 或 `seal` 报 `no_key`，说明上次 `create` 中途进程被杀，留下了半套
密钥。此时还没有任何数据被封存过，`delete` 后重新 `create` 即可。

`seal` 加密后会立刻用 TPM 解一次确认。公钥运算在软件里完成，TPM 不支持某个 hash 时加密照样
成功，不回读就可能封存一份永远解不开的设备秘密。代价是 `seal` 多一次 TPM 解密（约 300 ms）。

## 构建与测试

```
go build -trimpath -ldflags "-s -w" -o dist/mixia-hwkey.exe .

go test -count=1 -v -timeout 30m .                 # 真实 TPM，约 2 分钟；不可用时 Skip
MIXIA_HWKEY_BIN=<exe 绝对路径> go test -count=1 -v .  # 直接验证构建产物
MIXIA_HWKEY_SOAK=1500 go test -count=1 -v -timeout 30m -run FixedWidth .  # 签名定长压力测试
```

测试用随机 `name`，结束时删除，并比对前后的 PCP 密钥列表，有遗留则整体失败。

## 实测结论

2026-11-05，机械革命 CANGLONG，Windows 11 家庭版 26200，普通用户权限，
`TPM-Version:2.0 -Level:0-Revision:1.38-VendorID:'MSFT'-Firmware:393220.65936`。

**OAEP**：SHA-256 可用，`alg` 为 `oaep-sha256`。SHA-1 同样可用。`NCryptEncrypt` 在 PCP 上支持
OAEP，Go `rsa.EncryptOAEP` 产生的 blob 也能被 TPM 解开。Go 加密分支和 SHA-1 回退留给其他
TPM，已通过注入失败的 hash 在本机走通。

**不可导出**：`NCryptExportKey` 导出私钥全部失败，错误码都是 `0x8009000A`（NTE_BAD_TYPE），
大小查询和真实导出两步、`NCRYPT_SILENT_FLAG` 和 0 两种 flags 结果相同。

| 密钥 | 尝试的 blob 类型 |
|---|---|
| Auth | `ECCPRIVATEBLOB`、`PKCS8_PRIVATEKEY`、`PRIVATEBLOB` |
| Seal | `RSAPRIVATEBLOB`、`RSAFULLPRIVATEBLOB`、`PKCS8_PRIVATEKEY`、`PRIVATEBLOB` |

- 对照组：同一探测函数能从软件 KSP 的可导出密钥导出 `ECCPRIVATEBLOB`（104 字节）和
  `PKCS8_PRIVATEKEY`（165 字节），所以上面的失败不是探测函数的问题。
- `Export Policy` 读回为 0。设置它返回 `0x80090029`（NTE_NOT_SUPPORTED），finalize 之前
  和之后都一样，PCP 根本没有“允许导出”这个选项。
- TPM 对象属性（来自 PCP opaque blob 的公开区）：两把密钥都是 `fixedTPM`、`fixedParent`、
  `sensitiveDataOrigin`，即私钥在 TPM 内生成，TPM 拒绝复制。

| 密钥 | 类型 | objectAttributes | 用途 |
|---|---|---|---|
| Auth | ECC | `0x00040472` | 只能签名 |
| Seal | RSA | `0x00020472` | 只能解密 |

**耗时**（经 `dist/mixia-hwkey.exe` 的完整链路，各 10 次）：

| 操作 | 中位数 | 范围 |
|---|---|---|
| `sign` | 161 ms | 139 到 184 ms |
| `unseal` | 296 ms | 266 到 317 ms |
| `create` | | 2.8 到 7.9 s（RSA 生成，波动大） |

四轮测试的中位数：`sign` 161 到 187 ms，`unseal` 296 到 321 ms。每次请求都重新打开 key。
一次性测量显示，同一句柄上首次签名约 115 ms，第二次约 77 ms，如果以后要压延迟，可以缓存句柄。

**签名定长**：1500 次签名全部 64 字节且验签通过，其中 13 次 r 或 s 的高字节为 0。

**PCP 与文档或直觉不一致的地方**：

- `NCryptDeleteKey` 传 `NCRYPT_SILENT_FLAG` 返回 `0x80090009`（NTE_BAD_FLAGS），必须传 0。
- `NCryptExportKey` 导出 `OpaqueKeyBlob` 时同样不接受这个标志。
- `Impl Type` 属性只能在 provider 句柄上读，key 句柄返回 `0x80090029`。
- `NCRYPT_KEY_USAGE_PROPERTY` 设成仅解密不生效，RSA 密钥读回 `0x3` 且仍能签名。
  要用 `PCP_KEY_USAGE_POLICY`。
- 名字已存在时 `NCryptCreatePersistedKey` 立刻返回 `0x8009000F`，不生成密钥也不覆盖。

## 限制

- 密钥没有 PIN，TPM 对象的 authValue 为空。能以这个用户身份运行的程序都能调用 `sign` 和
  `unseal`。TPM 防的是私钥被带走，不防本机恶意软件当场使用，所以解锁还需要口令这个因子。
- 密钥绑定这颗 TPM。清除 TPM 或更换主板后密钥永久失效，只能走恢复码。
- 未实测：复制到另一台机器（没有第二颗 TPM，依据是上面的 `fixedTPM` 属性）、TPM 缺失或被
  禁用时的 `status` 和 `tpm_unavailable` 映射、TPM 清除后的错误码、Linux 和 macOS 上实际运行
  （已编译通过；stub 逻辑在 Windows 上测过）。
- 进程内对解封结果只做尽力清零。Go 的字符串和 JSON 编码会留下副本，不保证内存里没有残留。
