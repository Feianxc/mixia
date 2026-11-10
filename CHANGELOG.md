# 更新记录

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
1.0 之前协议和存储格式都可能变化。

## [未发布]

### 变更

- 依赖升级：Capacitor 8.6.0、vite 8.3.6、TypeScript 7.0.2、vitest 5.1.0、lucide-react 1.70.0、
  @types/chrome 0.3.7、google-services 4.5.0。
- CI 使用 actions/checkout v7、setup-node v7、setup-go v7、setup-java v6。

### 暂缓

- @noble/curves、@noble/hashes、@scure/bip39 的 2.x：导入路径和接口都变了，要改代码并验证与已有数据兼容，单独做。
- Gradle 9：Capacitor 8 用的 Android Gradle 插件依赖一个 Gradle 9.6 删掉的内部接口，等 Android 插件升级后再升。

## [0.1.0] - 2026-11-09

第一个公开版本（预发布）。

### 新增

- 三类库：云同步日常库、重要本地库、离线冷库。
- 设备信任：TPM / Android Keystore 绑定的设备密钥，管理设备核对指纹后批准新设备，撤销后自动换钥。
- 同步服务端（Go + SQLite）：只存密文和签名账本，每个请求由设备签名，systemd 沙箱禁止外联。
- Windows 桌面端（Electron）、Android 手机端（Capacitor）、Chrome / Edge 扩展（经 native messaging 连桌面端）。
- Android 自动填充服务，浏览器网站来源白名单。
- 密钥与 API：服务商识别、环境变量导出、到期和轮换提醒。
- 导入导出：浏览器 CSV、密匣 JSON（带库名和文件夹路径）、加密 Pack 备份；离线恢复工具。
- 星空黑洞界面：WebGL 黑洞与虫洞转场，闲置自动停画。

### 已知限制

- 没有第三方安全审计，没有代码签名，没有自动更新。
- 只有 Windows 和 Android；iOS、macOS、Linux 未构建。

[0.1.0]: https://github.com/Feianxc/mixia/releases/tag/v0.1.0
