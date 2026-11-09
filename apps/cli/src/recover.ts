/**
 * 离线恢复工具：没有服务器、没有客户端、项目停止维护时，也能读取备份。
 * 只依赖 Node，不联网。用法见 --help。
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import {
  VersionGraph,
  initCrypto,
  openPackWithBox,
  openPackWithCold,
  parseRecoveryCode,
  readPackHeader,
  rootKeysFrom,
  vaultRecoveryBox,
  type Snapshot,
} from '@mixia/core';

const USAGE = `密匣离线恢复工具

  mixia-recover info <文件>                 查看备份信息（不需要恢复码）
  mixia-recover verify <文件>               用恢复码解开并核对条目数，不输出内容
  mixia-recover export <文件> <输出.json>   解开并导出明文 JSON

恢复码和冷库口令在运行时询问，不要写在命令行里。导出的文件没有任何保护，用完请立即删除。`;

// 管道输入一次读完：readline 在没有等待者时收到的行会被丢弃
const piped = process.stdin.isTTY ? undefined : readFileSync(0, 'utf8').split(/\r?\n/);

async function ask(q: string): Promise<string> {
  if (piped) return (piped.shift() ?? '').trim();
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const a = await rl.question(q);
  rl.close();
  return a.trim();
}

async function open(bytes: Uint8Array): Promise<Snapshot> {
  const header = readPackHeader(bytes);
  const code = parseRecoveryCode(await ask('恢复码：'));
  if (header.slots.some((s) => s.t === 'pw')) {
    return openPackWithCold(bytes, await ask('冷库口令：'), code);
  }
  try {
    return openPackWithBox(bytes, vaultRecoveryBox(code));
  } catch {
    return openPackWithBox(bytes, rootKeysFrom(code).box);
  }
}

function currentItems(snap: Snapshot) {
  const g = new VersionGraph();
  for (const v of snap.versions) g.add(v);
  return g
    .objects('item')
    .map((id) => ({ id, r: g.resolve('item', id) }))
    .filter((x) => !x.r.deleted && x.r.current?.data)
    .map((x) => ({ id: x.id, conflict: x.r.conflict, ...x.r.current!.data }));
}

async function main() {
  const [cmd, file, out] = process.argv.slice(2);
  if (!cmd || !file) {
    console.error(USAGE);
    process.exit(2);
  }
  await initCrypto();
  const bytes = new Uint8Array(readFileSync(file));
  if (cmd === 'info') {
    const h = readPackHeader(bytes);
    console.log(JSON.stringify({ kind: h.kind, vaultId: h.vaultId, createdAt: new Date(h.createdAt).toISOString(), versions: h.count, slots: h.slots.map((s) => s.t) }, null, 2));
    return;
  }
  const snap = await open(bytes);
  const items = currentItems(snap);
  if (cmd === 'verify') {
    console.log(`可以恢复：${snap.name}，${items.length} 条，备份于 ${new Date(snap.exportedAt).toISOString()}`);
    return;
  }
  if (cmd === 'export' && out) {
    writeFileSync(out, JSON.stringify({ format: 'mixia-plain-v1', vault: snap.name, items }, null, 2), { mode: 0o600 });
    console.error(`已导出 ${items.length} 条到 ${out}。这个文件没有任何保护，用完请立即删除。`);
    return;
  }
  console.error(USAGE);
  process.exit(2);
}

main().catch((e: unknown) => {
  const code = (e as { code?: string }).code;
  console.error(`失败：${code ?? (e as Error).message}`);
  process.exit(1);
});
