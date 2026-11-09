/**
 * 服务器 API 客户端。每个请求都由设备硬件密钥签名，没有登录，没有令牌。
 * 底层 Transport 由平台外壳提供：界面层自身没有联网能力。
 */
import { b64e, hex, randomBytes, sha256, utf8d, utf8e } from './crypto';
import { MixiaError } from './errors';
import type { LedgerEntry } from './ledger';
import type { ChangeRecord, Vault } from './vault';

export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array;
}
export interface HttpResponse {
  status: number;
  body: Uint8Array;
}
export type Transport = (req: HttpRequest) => Promise<HttpResponse>;

export interface RequestSigner {
  /** 设备 ID，或字面量 root。 */
  id: string;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

export class ApiError extends MixiaError {
  constructor(
    code: string,
    readonly status: number,
    readonly detail?: Record<string, unknown>,
  ) {
    super(code);
    this.name = 'ApiError';
  }
}

export interface WrappedKey {
  deviceId: string;
  gen: number;
  wrapped: string;
}

export interface ChangesPage {
  changes: ChangeRecord[];
  head: number;
  base: number;
  gen: number;
}

export class ServerApi {
  /** 服务器时间 - 本机时间，避免手机时钟漂移导致签名过期。 */
  private clockOffset = 0;

  constructor(
    readonly baseUrl: string,
    private transport: Transport,
    public signer?: RequestSigner,
  ) {}

  private async send(
    method: string,
    path: string,
    opts: { json?: unknown; raw?: Uint8Array; headers?: Record<string, string>; signed?: boolean } = {},
  ): Promise<Uint8Array> {
    const body =
      opts.raw ?? (opts.json !== undefined ? utf8e(JSON.stringify(opts.json)) : new Uint8Array());
    const headers: Record<string, string> = { ...opts.headers };
    if (opts.json !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.raw) headers['Content-Type'] = 'application/octet-stream';
    if (opts.signed !== false) {
      if (!this.signer) throw new MixiaError('no_signer');
      const ts = String(Date.now() + this.clockOffset);
      const nonce = b64e(randomBytes(16));
      // 哈希放进请求头：服务端验完签才读 body，匿名请求没法让它缓冲大文件
      const bodyHash = hex(sha256(body));
      const msg = utf8e(`MIXIA-REQ-1\n${method}\n${path}\n${ts}\n${nonce}\n${bodyHash}`);
      const sig = await this.signer.sign(msg);
      headers['X-Mx-Body'] = bodyHash;
      headers['X-Mx-Device'] = this.signer.id;
      headers['X-Mx-Ts'] = ts;
      headers['X-Mx-Nonce'] = nonce;
      headers['X-Mx-Sig'] = b64e(sig);
    }
    let res: HttpResponse;
    try {
      res = await this.transport({
        method,
        url: this.baseUrl.replace(/\/+$/, '') + path,
        headers,
        ...(body.length ? { body } : {}),
      });
    } catch {
      throw new MixiaError('network');
    }
    if (res.status >= 200 && res.status < 300) return res.body;
    let detail: Record<string, unknown> = {};
    try {
      detail = JSON.parse(utf8d(res.body)) as Record<string, unknown>;
    } catch {
      /* 可能是 Cloudflare 的 HTML 错误页 */
    }
    throw new ApiError(
      typeof detail.error === 'string' ? detail.error : `http_${res.status}`,
      res.status,
      detail,
    );
  }

  private async json<T>(
    method: string,
    path: string,
    opts: Parameters<ServerApi['send']>[2] = {},
  ): Promise<T> {
    const b = await this.send(method, path, opts);
    return JSON.parse(utf8d(b)) as T;
  }

  async info(): Promise<{ proto: number; time: number; bootstrapped: boolean }> {
    const r = await this.json<{ proto: number; time: number; bootstrapped: boolean }>(
      'GET',
      '/v1/info',
      { signed: false },
    );
    this.clockOffset = r.time - Date.now();
    return r;
  }

  bootstrap(
    token: string,
    entries: LedgerEntry[],
    keys: (WrappedKey & { vaultId: string })[],
  ): Promise<unknown> {
    return this.json('POST', '/v1/bootstrap', { json: { token, entries, keys }, signed: false });
  }

  getLedger(from: number): Promise<{ entries: LedgerEntry[]; head: number }> {
    return this.json('GET', `/v1/ledger?from=${from}`);
  }

  postLedger(entries: LedgerEntry[]): Promise<{ head: number }> {
    return this.json('POST', '/v1/ledger', { json: { entries } });
  }

  getChanges(vaultId: string, after: number, limit = 500): Promise<ChangesPage> {
    return this.json('GET', `/v1/vaults/${vaultId}/changes?after=${after}&limit=${limit}`);
  }

  /**
   * 第二道闸：这个函数只接受云库对象。本地库和冷库即使被代码错误地传进来也发不出去。
   * 第一道闸是同步模块根本拿不到它们；第三道闸是界面层 CSP。
   */
  pushChanges(
    vault: Vault,
    changes: { id: string; gen: number; blob: string }[],
  ): Promise<{ accepted: { id: string; seq: number }[]; head: number }> {
    if (vault.policy !== 'cloud') throw new MixiaError('policy_blocks_upload');
    return this.json('POST', `/v1/vaults/${vault.id}/changes`, { json: { changes } });
  }

  getKeys(vaultId: string): Promise<{ keys: { gen: number; wrapped: string }[] }> {
    return this.json('GET', `/v1/vaults/${vaultId}/keys`);
  }

  putKeys(vaultId: string, keys: WrappedKey[]): Promise<unknown> {
    return this.json('PUT', `/v1/vaults/${vaultId}/keys`, { json: { keys } });
  }

  rotate(
    vaultId: string,
    entry: LedgerEntry,
    keys: WrappedKey[],
    changes: { id: string; gen: number; blob: string }[],
  ): Promise<unknown> {
    return this.json('POST', `/v1/vaults/${vaultId}/rotate`, { json: { entry, keys, changes } });
  }

  /** 换根和替换全部恢复封装在服务端一个事务里完成，中途失败不会失去根。 */
  rootRotate(entry: LedgerEntry, keys: { vaultId: string; gen: number; wrapped: string }[]): Promise<unknown> {
    return this.json('POST', '/v1/root/rotate', { json: { entry, keys } });
  }

  putBlob(vault: Vault, blobId: string, bytes: Uint8Array): Promise<Uint8Array> {
    if (vault.policy !== 'cloud') throw new MixiaError('policy_blocks_upload');
    return this.send('PUT', `/v1/vaults/${vault.id}/blobs/${blobId}`, { raw: bytes });
  }

  getBlob(vault: Vault, blobId: string): Promise<Uint8Array> {
    // 读取也要过闸：请求本身会把本地库 ID 带到服务器
    if (vault.policy !== 'cloud') throw new MixiaError('policy_blocks_upload');
    return this.send('GET', `/v1/vaults/${vault.id}/blobs/${blobId}`);
  }

  deleteBlob(vaultId: string, blobId: string): Promise<Uint8Array> {
    return this.send('DELETE', `/v1/vaults/${vaultId}/blobs/${blobId}`);
  }

  audit(limit = 100): Promise<{
    events: { ts: number; device: string; action: string; detail: string }[];
  }> {
    return this.json('GET', `/v1/audit?limit=${limit}`);
  }

  // —— 配对 ——

  pairOpen(p: { pairId: string; tokenHash: string; expiresAt: number; offer: string }): Promise<unknown> {
    return this.json('POST', '/v1/pair', { json: p });
  }

  pairGet(
    pairId: string,
    token: string,
  ): Promise<{ offer: string; status: string; grant?: string | null }> {
    return this.json('GET', `/v1/pair/${pairId}`, {
      signed: false,
      headers: { 'X-Mx-Pair-Token': token },
    });
  }

  pairRequest(pairId: string, token: string, request: string): Promise<unknown> {
    return this.json('POST', `/v1/pair/${pairId}/request`, {
      json: { request },
      signed: false,
      headers: { 'X-Mx-Pair-Token': token },
    });
  }

  pairAdmin(pairId: string): Promise<{ status: string; request?: string | null }> {
    return this.json('GET', `/v1/pair/${pairId}/admin`);
  }

  pairGrant(pairId: string, grant: string): Promise<unknown> {
    return this.json('POST', `/v1/pair/${pairId}/grant`, { json: { grant } });
  }

  pairClose(pairId: string): Promise<Uint8Array> {
    return this.send('DELETE', `/v1/pair/${pairId}`);
  }
}
