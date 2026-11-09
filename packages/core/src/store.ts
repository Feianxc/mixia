/**
 * 键值存储接口。数据在写入前已经加密，这里只要求原子批量写。
 * 每个保险库持有自己的 KV 实例：同步模块拿不到本地库的句柄，
 * 这是“本地库没有上云路径”的结构性保证之一。
 */
export type KVOp = { t: 'put'; k: string; v: Uint8Array } | { t: 'del'; k: string };

export interface KV {
  get(key: string): Promise<Uint8Array | undefined>;
  /** 按键升序返回前缀下所有键值。 */
  scan(prefix: string): Promise<[string, Uint8Array][]>;
  /** 全部成功或全部不生效。 */
  batch(ops: KVOp[]): Promise<void>;
  /** 删除底层存储（销毁保险库或擦除设备时用）。 */
  destroy(): Promise<void>;
}

export class MemoryKV implements KV {
  private m = new Map<string, Uint8Array>();

  async get(key: string) {
    const v = this.m.get(key);
    return v ? v.slice() : undefined;
  }

  async scan(prefix: string) {
    const out: [string, Uint8Array][] = [];
    for (const [k, v] of this.m) if (k.startsWith(prefix)) out.push([k, v.slice()]);
    return out.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  }

  async batch(ops: KVOp[]) {
    for (const o of ops) {
      if (o.t === 'put') this.m.set(o.k, o.v.slice());
      else this.m.delete(o.k);
    }
  }

  async destroy() {
    this.m.clear();
  }

  /** 测试用：全部已存字节，便于检查是否有明文落盘。 */
  dump(): Uint8Array[] {
    return [...this.m.values()];
  }
}

/** 浏览器 / WebView / Electron 渲染进程使用的 IndexedDB 实现。 */
export class IdbKV implements KV {
  private static cache = new Map<string, IdbKV>();
  private dbp: Promise<IDBDatabase> | undefined;

  private constructor(private name: string) {}

  /** 同名共用一个实例：deleteDatabase 会被任何未关闭的连接挡住，永远不返回。 */
  static open(name: string): IdbKV {
    let kv = IdbKV.cache.get(name);
    if (!kv) IdbKV.cache.set(name, (kv = new IdbKV(name)));
    return kv;
  }

  private db(): Promise<IDBDatabase> {
    this.dbp ??= new Promise((resolve, reject) => {
      const r = indexedDB.open(this.name, 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    return this.dbp;
  }

  async get(key: string) {
    const db = await this.db();
    return new Promise<Uint8Array | undefined>((resolve, reject) => {
      const q = db.transaction('kv').objectStore('kv').get(key);
      q.onsuccess = () => resolve(q.result as Uint8Array | undefined);
      q.onerror = () => reject(q.error);
    });
  }

  async scan(prefix: string) {
    const db = await this.db();
    return new Promise<[string, Uint8Array][]>((resolve, reject) => {
      const range = IDBKeyRange.bound(prefix, prefix + "\uffff");
      const st = db.transaction('kv').objectStore('kv');
      const kq = st.getAllKeys(range);
      const vq = st.getAll(range);
      vq.onsuccess = () => {
        const keys = kq.result as string[];
        const vals = vq.result as Uint8Array[];
        resolve(keys.map((k, i) => [k, vals[i]!] as [string, Uint8Array]));
      };
      vq.onerror = () => reject(vq.error);
    });
  }

  async batch(ops: KVOp[]) {
    const db = await this.db();
    return new Promise<void>((resolve, reject) => {
      // strict：提交前强制落盘，断电时不丢已确认的写入
      const tx = db.transaction('kv', 'readwrite', { durability: 'strict' });
      const st = tx.objectStore('kv');
      for (const o of ops) {
        if (o.t === 'put') st.put(o.v, o.k);
        else st.delete(o.k);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  }

  async destroy() {
    const db = await this.db();
    db.close();
    this.dbp = undefined;
    return new Promise<void>((resolve, reject) => {
      const r = indexedDB.deleteDatabase(this.name);
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error);
    });
  }
}

export const jsonBytes = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));
export const fromJson = <T>(b: Uint8Array): T => JSON.parse(new TextDecoder().decode(b)) as T;
