/**
 * 验收脚本共用：只清理本次测试在 TPM 里建的设备密钥。
 *
 * 不能按“测试期间新出现的密钥”来删：用户真实安装的密匣可能恰好在测试运行时初始化、
 * 或者重新加入设备，新建的真实密钥会被一起删掉，只能靠恢复码找回。
 * 这里只认名字出现在本次测试数据目录里的密钥（设备 ID 原样写在 IndexedDB 的日志里）。
 * 测试结尾会擦除测试库，擦除后目录里可能找不到设备 ID，所以要在初始化完成后先 note() 记下。
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** TPM 里所有密匣密钥的全名，比如 Mixia-Auth-<设备 ID> */
export function tpmKeys() {
  try {
    const out = execFileSync('certutil', ['-user', '-csp', 'Microsoft Platform Crypto Provider', '-key'], { encoding: 'latin1' });
    return [...new Set(out.match(/Mixia-(Auth|Seal)-[A-Za-z0-9_-]+/g) ?? [])].sort();
  } catch {
    return [];
  }
}
const idOf = (k) => k.replace(/^Mixia-(Auth|Seal)-/, '');

/** 设备 ID：认证和封存两把密钥共用一个 */
export function tpmKeyNames() {
  return new Set(tpmKeys().map(idOf));
}

/** 目录里有没有哪个文件含这段文本 */
export function mentions(dir, text) {
  if (!existsSync(dir)) return false;
  for (const e of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (!e.isFile()) continue;
    try {
      if (readFileSync(join(e.parentPath, e.name)).toString('latin1').includes(text)) return true;
    } catch {
      /* 正在被占用的文件跳过 */
    }
  }
  return false;
}

/** 在启动应用之前调用 */
export function keyGuard(dataDir) {
  const before = tpmKeyNames();
  const ours = new Set();
  return {
    /** 记下本次测试建的密钥，返回已认出的个数 */
    note() {
      for (const n of tpmKeyNames()) if (!before.has(n) && mentions(dataDir, n)) ours.add(n);
      return ours.size;
    },
    /** 本次测试的设备 ID 里还留在 TPM 的 */
    remaining: () => [...tpmKeyNames()].filter((n) => ours.has(n)),
    /** 本次测试的密钥全名（认证、封存各一把） */
    oursFull: () => tpmKeys().filter((k) => ours.has(idOf(k))),
    /** 测试期间出现、但不属于本次测试的密钥（多半是用户真实安装的密匣建的），只报告，不碰 */
    foreign: () => [...tpmKeyNames()].filter((n) => !before.has(n) && !ours.has(n)),
    /** 必须在删除数据目录之前调用 */
    cleanup(hwkeyExe) {
      this.note();
      const names = this.remaining();
      if (!names.length) return;
      const lines = names.map((name, i) => `${JSON.stringify({ id: i + 1, cmd: 'delete', args: { name } })}\n`);
      execFileSync(hwkeyExe, { input: lines.join('') });
    },
  };
}
