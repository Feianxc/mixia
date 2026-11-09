import { describe, expect, it } from 'vitest';
import { detectAndImport, exportJson, importMixiaJson, markDuplicates, newItem, type ItemView } from '../src';

const view = (vaultId: string, data: ItemView['data']): ItemView => ({ id: `i-${data.title}`, vaultId, data }) as ItemView;

describe('密匣 JSON 导入', () => {
  it('导出再导入：类型、机密字段、服务商和文件夹路径都保留', () => {
    const key = newItem('api', 'DeepSeek');
    key.fields = [
      { name: 'Endpoint', value: 'https://api.deepseek.com' },
      { name: 'API Key', value: 'sk-test', secret: true, envName: 'DEEPSEEK_API_KEY' },
    ];
    key.provider = 'DeepSeek';
    key.env = 'production';
    key.tags = ['大模型'];
    key.rotateDays = 90;
    const login = newItem('login', 'github.com');
    login.username = 'me';
    login.password = 'pw';
    login.urls = ['https://github.com/login'];
    login.favorite = true;
    const text = exportJson(
      [view('v1', key), view('v1', login)],
      () => '日常',
      (i) => (i.data.type === 'api' ? '密钥与 API/大模型' : '开发与云服务'),
    );

    const p = detectAndImport('导出.json', text);
    expect(p.format).toBe('密匣 JSON');
    expect(p.skipped).toBe(0);
    expect(p.rows.map((r) => r.folderPath)).toEqual(['密钥与 API/大模型', '开发与云服务']);
    expect(p.rows[0]!.data).toMatchObject({ type: 'api', title: 'DeepSeek', provider: 'DeepSeek', env: 'production', tags: ['大模型'], rotateDays: 90 });
    expect(p.rows[0]!.data.fields).toEqual(key.fields);
    expect(p.rows[1]!.data).toMatchObject({ type: 'login', username: 'me', password: 'pw', urls: ['https://github.com/login'], favorite: true });
    // 导出里的 id、所在库、文件夹 id 不会被带进来
    expect(p.rows[0]!.data).not.toHaveProperty('id');
    expect(p.rows[0]!.data).not.toHaveProperty('vault');
    expect(p.rows[0]!.data.folder).toBeUndefined();
    // 所有条目都来自同一个库：导入对话框会预选它
    expect(p.suggestedVault).toBe('日常');
  });

  it('条目来自不同的库时不预选', () => {
    const p = importMixiaJson({ items: [{ type: 'note', title: 'a', vault: '日常' }, { type: 'note', title: 'b', vault: '重要' }] });
    expect(p.suggestedVault).toBeUndefined();
    const q = importMixiaJson({ items: [{ type: 'note', title: 'a' }] });
    expect(q.suggestedVault).toBeUndefined();
  });

  it('不认识的类型、没有标题、回收站里的条目跳过并提示', () => {
    const p = importMixiaJson({
      items: [
        { type: 'spaceship', title: 'x' },
        { type: 'login', title: '  ' },
        { type: 'login', title: '已删除', trashedAt: 1 },
        null,
        { type: 'ssh', title: '服务器私钥', fields: [{ name: '私钥', value: '-----BEGIN-----', secret: true }] },
      ],
    });
    expect(p.rows).toHaveLength(1);
    expect(p.skipped).toBe(4);
    expect(p.warnings[0]).toContain('4');
    expect(p.rows[0]!.data.type).toBe('ssh');
  });

  it('字段只收字符串；secret 只认 true；不合规的环境变量名丢掉', () => {
    const p = importMixiaJson({
      items: [
        {
          type: 'token',
          title: 'T',
          fields: [
            { name: 'Token', value: 'abc', secret: 'yes', envName: 'BAD NAME' },
            { name: 'n', value: 5 },
            { name: 'ok', value: 'v', secret: true, envName: 'OK_1' },
          ],
          urls: ['https://a', 3, ''],
          tags: 'not-a-list',
        },
      ],
    });
    expect(p.rows[0]!.data.fields).toEqual([
      { name: 'Token', value: 'abc' },
      { name: 'ok', value: 'v', secret: true, envName: 'OK_1' },
    ]);
    expect(p.rows[0]!.data.urls).toEqual(['https://a']);
    expect(p.rows[0]!.data.tags).toBeUndefined();
  });

  it('文件夹路径规整：反斜杠、首尾斜杠、空段', () => {
    const p = importMixiaJson({ items: [{ type: 'note', title: 'n', folderPath: '\\\\公司\\ /项目甲// ' }] });
    expect(p.rows[0]!.folderPath).toBe('公司/项目甲');
  });

  it('没有 format 的 JSON 仍按 Bitwarden 处理', () => {
    const p = detectAndImport('bw.json', JSON.stringify({ items: [{ type: 1, name: 'A', login: { username: 'u', password: 'p' } }] }));
    expect(p.format).toBe('Bitwarden JSON');
    expect(p.rows[0]!.data.username).toBe('u');
  });

  it('同一个文件里重复的条目只导入一次', () => {
    const one = { type: 'login', title: 'a.com', username: 'u', password: 'p', urls: ['https://a.com'] };
    const p = importMixiaJson({ items: [one, { ...one }] });
    const { fresh, dupes } = markDuplicates(p.rows, []);
    expect(fresh).toHaveLength(1);
    expect(dupes).toHaveLength(1);
  });
});
