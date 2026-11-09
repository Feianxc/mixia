# 贡献指南

谢谢你愿意改进密匣。这是一个密码管理器，所以对“改了以后真的还安全”要求比一般项目高一些。

## 先说好的范围

密匣面向**一个所有者、几台自有设备**。下面这些方向目前不打算做，提之前可以先开 issue 讨论：

- 多人共享、团队、公开注册、网页版
- 服务器端解密、搜索或任何需要服务器读懂内容的功能
- 用软件密钥顶替缺失的 TPM / Keystore

安全问题不要提公开 issue，见 [SECURITY.md](SECURITY.md)。

## 开发环境

| 工具 | 版本 | 用于 |
|---|---|---|
| Node.js | 24 | 核心、界面、桌面、扩展 |
| Go | 1.27 | 服务端、TPM 助手、native host |
| JDK + Android SDK | 21 / compileSdk 见 `apps/mobile/android/variables.gradle` | Android |
| Windows 11 + TPM 2.0 | — | 桌面端真实验收 |

```bash
npm ci
cd server && go build -o dist/mixia-server-test.exe ./cmd/mixia-server && cd ..
npm -w @mixia/cli run build    # 端到端测试会调用离线恢复工具
npm test                       # 核心单元测试 + 真实服务端端到端
npm -w @mixia/ui run dev       # 界面开发预览，配合 node scripts/dev-server.mjs 起本地测试服务端（令牌 dev-token）
```

## 提交改动

1. 从 `main` 拉分支，一个 PR 只做一件事。
2. 跑通相关测试。CI 会跑类型检查、核心和扩展测试、Go 测试，以及 Windows 上的原生助手协议测试。
3. 改了协议、加密、认证、账本校验、填充来源判断或权限时：
   - 写能证明防护有效的测试，**最好是“破坏防护后测试会失败”的那种**；
   - 在 `scripts/mutate.py` 里加对应的变异项，或说明为什么不需要；
   - 同步更新 [协议规范](docs/协议规范.md) 或 [架构设计](docs/架构设计.md)。
4. 改了界面，附截图或录屏；动效相关的改动说明在手机上看过没有。
5. 只在测试里用**明显虚构**的数据。不要提交任何真实密码、密钥、令牌、服务器地址或个人数据，
   签名密钥和令牌放 `.secrets/`（已忽略）。

## 代码风格

- TypeScript 开 `strict`；Go 代码过 `go vet`。
- 注释和界面文案用简体中文，写“为什么”，不复述代码。界面文案站在用户一侧说话，同一个动作全流程同名。
- 不引入新的运行时依赖，除非理由充分；加密相关只用成熟库。

## 许可

提交 PR 即表示你同意你的贡献以 [MIT](LICENSE) 许可发布。
