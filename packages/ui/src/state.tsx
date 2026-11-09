import { createContext, useCallback, useContext, useEffect, useReducer, useRef, useState } from 'react';
import type { Mixia } from '@mixia/core';
import { IntegrityAlarm, MixiaError } from '@mixia/core';
import type { Bridge } from './bridge';

export interface Ctx {
  m: Mixia;
  bridge: Bridge;
  toast(text: string, kind?: 'ok' | 'err'): void;
}

export const AppCtx = createContext<Ctx>(null as unknown as Ctx);

/** 正在被编辑的库：暂缓短超时锁定。 */
export const editing = { vaults: new Set<string>() };
export const useApp = () => useContext(AppCtx);

/** 核心状态变化时重新渲染。 */
export function useMixia(m: Mixia): void {
  const [, bump] = useReducer((x: number) => x + 1, 0);
  useEffect(() => m.onChange(bump), [m]);
}

const MESSAGES: Record<string, string> = {
  wrong_passphrase: '口令不对',
  device_binding_failed: '这台设备的硬件密钥不匹配。数据可能是从别的设备复制来的，或硬件已被重置',
  bad_recovery_code: '恢复码不对，请核对每一组。校验位没有通过',
  bad_pair_code: '配对码应为 24 位，请核对',
  bad_code: '编码里有无法识别的字符',
  network: '连不上服务器，请检查网络',
  unauthorized: '服务器不认这台设备。它可能已被撤销',
  forbidden: '这台设备没有这个权限',
  gone: '这台服务器已经初始化过了，不能再次初始化',
  rate_limited: '操作太频繁，请稍后再试',
  admin_required: '只有管理设备才能这样做',
  hardware_required: '这台设备没有硬件级保护，不能存放重要库',
  vault_read_only: '这是只读快照，请在主写设备上修改',
  vault_locked: '这个库还没解锁',
  folder_cycle: '不能把文件夹移到它自己里面',
  csv_unrecognized: '认不出这个 CSV 的表头，至少要有“名称/用户名/密码”之一',
  json_unrecognized: '认不出这个 JSON 文件的格式',
  bitwarden_encrypted: '这是 Bitwarden 的加密导出，请改用未加密 JSON',
  not_a_pack: '这不是密匣的备份文件',
  pack_wrong_key: '恢复码或口令不对，打不开这个文件',
  pack_corrupt: '文件已损坏或被改动过',
  pack_truncated: '文件不完整',
  pair_expired: '配对码已过期，请重新生成',
  pair_used: '这个配对码已经用过了',
  not_found: '服务器上还没有：配对码不对，或附件还在从另一台设备上传',
  upload_needs_confirmation: '把重要内容移入云库需要你明确确认',
  bad_totp: '两步验证密钥格式不对',
  no_server: '这台设备没有连接服务器',
  quick_unavailable: '这台设备不支持快捷解锁',
  rotation_incomplete: '设备已撤销，但有库没能换钥。旧设备手里的密钥对这些库仍然有效，请到“设备”页重试',
  alarm_active: '完整性告警还没处理，现在不能批准新设备',
  no_backup_key: '这个库没有备份密钥。只读快照请回到主写设备备份',
  attachment_too_big: '附件不能超过 10 MB。密匣适合放证书和密钥文件，不适合放大文件',
  attachment_unavailable: '这个附件不在本机，服务器上也没有',
};

export function errorText(e: unknown): string {
  if (e instanceof IntegrityAlarm) return `完整性校验未通过（${e.code}），已停止同步`;
  if (e instanceof MixiaError) return MESSAGES[e.code] ?? `操作失败（${e.code}）`;
  return '操作失败，请重试';
}

export const ALARM_TEXT: Record<string, string> = {
  ledger_rollback: '服务器返回的信任账本比本机已确认的版本更旧。',
  ledger_fork: '服务器返回的信任账本和本机记录分叉了。',
  ledger_tampered: '服务器返回的信任账本没有通过签名校验。',
  ledger_withheld: '其他设备的变更显示账本有更新的记录，但服务器没有给这台设备。它可能在隐瞒撤销操作。',
  malformed_response: '服务器的响应格式不对。',
  malformed_change: '服务器日志里有一条无法解析的记录。',
  push_not_accepted: '服务器没有确认收到上传的内容。',
  genesis_mismatch: '服务器的信任根和本机钉住的不一致。',
  log_rollback: '服务器的变更日志比本机已确认的更旧。',
  log_truncated: '服务器的变更日志缺了一段。',
  gen_rollback: '服务器试图退回旧的库密钥代数。',
  change_withheld: '服务器隐瞒了部分变更。',
  change_replayed: '服务器重放了旧变更。',
  change_bad_signature: '有一条变更的签名不对。',
  change_unknown_author: '有一条变更来自账本中不存在的设备。',
  change_from_revoked: '有一条变更来自已撤销的设备。',
  key_commit_mismatch: '服务器给的库密钥和账本里的承诺值不一致。',
  snapshot_tampered: '换钥快照没有通过校验。',
};

export function useAsync() {
  const { toast } = useApp();
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>, ok?: string): Promise<T | undefined> => {
      setBusy(true);
      try {
        const r = await fn();
        if (ok) toast(ok);
        return r;
      } catch (e) {
        toast(errorText(e), 'err');
        return undefined;
      } finally {
        if (alive.current) setBusy(false);
      }
    },
    [toast],
  );
  return { busy, run };
}

export function timeAgo(ts: number): string {
  if (!ts) return '从未';
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return '刚刚';
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)} 天前`;
  return new Date(ts).toLocaleDateString('zh-CN');
}

export const fullTime = (ts: number): string =>
  ts ? new Date(ts).toLocaleString('zh-CN', { hour12: false }) : '—';
