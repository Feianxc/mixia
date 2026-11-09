# 安全策略

密匣是密码管理器，安全问题优先处理。

## 报告漏洞

**请不要在公开 issue、讨论区或 PR 里描述漏洞。**

在本仓库的 **Security → Report a vulnerability** 私下提交（GitHub 私密漏洞报告）。请尽量写清：

- 影响的组件和版本（核心库、服务端、桌面端、TPM 助手、native host、浏览器扩展、Android）
- 复现步骤或概念验证，以及攻击者需要的前提（能控制服务器？本机同用户进程？恶意网页？）
- 你认为的影响：泄露什么、伪造什么、绕过什么

项目由个人维护，会尽量在 7 天内确认收到，修复后在发布说明里致谢（你不希望署名的话请注明）。

## 支持的版本

| 版本 | 是否修复安全问题 |
|---|---|
| 0.1.x（最新） | 是 |
| 更早 | 否 |

## 范围

在范围内：

- 加密、密钥派生和封装（`packages/core`）
- 信任账本、请求认证、同步、换钥、配对和 Pack 格式（见 [协议规范](docs/协议规范.md)）
- 服务端对认证、配额和账本校验的实现（`server/`）
- 桌面端的 TPM 助手、浏览器桥和 Electron 主进程（`apps/desktop/`）
- 浏览器扩展的来源判断和填充流程（`apps/extension/`）
- Android 的 Keystore、自动填充、剪贴板和防截屏（`apps/mobile/`）

已经公开、经评估后接受的边界不算新漏洞，但如果你找到了比文档描述**更强**的利用方式，欢迎报告。
这些边界写在 [架构设计 · 已知边界](docs/架构设计.md#已知边界)，包括：

- 服务器与被撤销设备串通、对长期离线设备做全量隔离
- 本机同用户的恶意程序（应用已锁定或已解锁时）
- 备份文件可被伪造
- JS 无法可靠清零内存
- 匹配站点本身存在 XSS 时，填入的密码可被读取
- 没有代码签名证书

## 现状

- 没有经过第三方密码学审计。开发中做过一次 AI 辅助的对抗式审查，结果记在 [验收记录](docs/验收记录.md#独立安全审查)。
- 密码学原语来自 libsodium 和 @noble 系列库，协议是本项目自己设计的。
- 涉及安全的改动要求有测试，并用变异测试（`scripts/mutate.py`）确认破坏防护后测试会失败。

---

**English:** please report vulnerabilities privately via **Security → Report a vulnerability** on this repository.
Do not open public issues for security problems. Known, accepted limitations are listed in
[docs/架构设计.md](docs/架构设计.md#已知边界).
