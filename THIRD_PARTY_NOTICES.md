# 第三方组件

密匣本身以 [MIT](LICENSE) 许可发布。下面是随源码或安装包一起分发的第三方组件。完整的依赖树以
`package-lock.json`、各 `go.mod` 和 Android 的 Gradle 配置为准，每个组件的许可证原文在其发行包里。

## 字体与字形

| 组件 | 用途 | 许可证 |
|---|---|---|
| Noto Serif SC（思源宋体），© 2017-2023 Adobe | 标题字体子集 `mixia-serif.woff2`；印章“云、本、冷、匣”的字形轮廓 | SIL OFL 1.1 |
| JetBrains Mono，© 2020 The JetBrains Mono Project Authors | 等宽字体 | SIL OFL 1.1 |

OFL 原文和版权声明见 [`packages/ui/public/fonts/OFL.txt`](packages/ui/public/fonts/OFL.txt)，它会随界面一起打进安装包。

## 界面与核心（JavaScript）

| 组件 | 许可证 |
|---|---|
| React、React DOM | MIT |
| libsodium.js（libsodium-wrappers-sumo） | ISC |
| @noble/curves、@noble/hashes、@scure/bip39 | MIT |
| lucide-react | ISC |
| qrcode-generator | MIT |
| jsQR | Apache-2.0 |
| @capacitor/core、@capacitor/android | MIT |

## 桌面端

| 组件 | 许可证 |
|---|---|
| Electron（含 Chromium、Node.js，许可证随安装包附带 `LICENSES.chromium.html`） | MIT 及其上游各自的许可证 |
| golang.org/x/sys | BSD-3-Clause |

## 服务端（Go）

| 组件 | 许可证 |
|---|---|
| modernc.org/sqlite 及 modernc.org/libc、mathutil、memory | BSD-3-Clause |
| github.com/google/uuid | BSD-3-Clause |
| github.com/remyoudompheng/bigfft | BSD-3-Clause |
| github.com/dustin/go-humanize、github.com/mattn/go-isatty、github.com/ncruces/go-strftime | MIT |
| golang.org/x/sys | BSD-3-Clause |

## Android

Capacitor 生成的 Android 工程依赖 AndroidX 等 Google 组件（Apache-2.0），版本见 `apps/mobile/android/variables.gradle`。
