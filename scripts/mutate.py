"""变异测试：逐条破坏客户端的安全防护，确认测试能发现。任何一条存活都说明测试有盲区。
用法：python scripts/mutate.py [名称关键词...]；加 --e2e 跑真机组（要先关掉正在运行的密匣）。"""
import pathlib, subprocess, sys
root = pathlib.Path(__file__).resolve().parent.parent
src = root / "packages/core/src"
M = [
 ("ledger.ts", "if (!edVerify(b64d(dev.signPub), msg, sig)) fail('bad_signature');", "", "设备签名不校验"),
 ("ledger.ts", "if (!isStr(rootPub) || !edVerify(b64d(rootPub), msg, sig)) fail('bad_root_signature');", "", "根签名不校验"),
 ("ledger.ts", "if (dev.revokedSeq !== undefined) fail('signer_revoked');", "", "已撤销设备仍可签名"),
 ("ledger.ts", "if (dev.role !== 'admin') fail('signer_not_admin');", "", "普通设备可签管理条目"),
 ("ledger.ts", "if (body.seq !== this.seq + 1) fail('bad_seq');", "", "序号不校验"),
 ("ledger.ts", "if (body.prev !== (this.seq < 0 ? '' : this.headHash)) fail('bad_prev');", "", "前序哈希不校验"),
 ("ledger.ts", "if (deviceIdFromAuthPub(b64d(d.authPub as string)) !== d.deviceId) fail('device_id_mismatch');", "", "设备ID不绑定公钥"),
 ("ledger.ts", "if (dev.role === 'admin' && this.activeAdmins.length <= 1) fail('last_admin');", "", "可撤销最后管理设备"),
 ("ledger.ts", "if (d.gen !== v.gen + 1 || !isStr(d.keyCommit)) fail('bad_gen');", "", "代数可跳"),
 ("ledger.ts", "if (body.type === 'root_rotate' && body.signer !== 'root') fail('root_only');", "", "非根可换根"),
 ("sync.ts", "if (keyCommit(vk, info.vaultId, info.gen) !== info.keyCommit) {\n      throw new IntegrityAlarm('key_commit_mismatch');\n    }", "", "不校验库密钥承诺"),
 ("sync.ts", "if (res.head < from) throw new IntegrityAlarm('ledger_rollback');", "", "不检测账本回退(head)"),
 ("sync.ts", "if (!first) throw new IntegrityAlarm('ledger_rollback');", "if (!first) return 0;", "空响应当作无更新"),
 ("sync.ts", "if (entryHash(first) !== this.state.headHash) throw new IntegrityAlarm('ledger_fork');", "", "不检测账本分叉"),
 ("sync.ts", "if (!verifyBlob(o, b64d(dev.signPub))) throw new IntegrityAlarm('change_bad_signature');", "", "变更签名不校验"),
 ("sync.ts", "if (!dev) throw new IntegrityAlarm('change_unknown_author');", "if (!dev) return;", "未知作者放行"),
 ("sync.ts", "if (snapshotHash(snapshot) !== info.snapshotHash) throw new IntegrityAlarm('snapshot_tampered');", "", "不校验快照哈希"),
 ("sync.ts", "if (info.gen < v.gen) throw new IntegrityAlarm('gen_rollback');", "", "不检测代数回退"),
 ("vault.ts", "if (h.counter !== last + 1) throw new IntegrityAlarm('change_withheld');", "", "不检测隐瞒变更"),
 ("vault.ts", "if (h.counter <= last) throw new IntegrityAlarm('change_replayed');", "", "不检测重放"),
 ("vault.ts", "h.device !== c.device ||", "", "不核对作者"),
 ("vault.ts", "if (versions.length === 0) return;\n    if (this.meta.readOnly) throw new MixiaError('vault_read_only');", "if (versions.length === 0) return;", "只读库可写"),
 ("api.ts", "if (vault.policy !== 'cloud') throw new MixiaError('policy_blocks_upload');\n    return this.json('POST'", "return this.json('POST'", "本地库可上传变更"),
 ("api.ts", "if (vault.policy !== 'cloud') throw new MixiaError('policy_blocks_upload');\n    return this.send('PUT'", "return this.send('PUT'", "本地库可上传附件"),
 ("mixia.ts", "if (st.genesisHash !== j.genesisHash) throw new IntegrityAlarm('genesis_mismatch');", "", "不校验信任根"),
 ("mixia.ts", "if (st.rootPub !== b64e(root.sign.pub)) throw new IntegrityAlarm('root_mismatch');", "", "恢复时不比对根"),
 ("mixia.ts", "if (src.policy !== 'cloud' && dst.policy === 'cloud' && !opts.confirmUpload) {\n      throw new MixiaError('upload_needs_confirmation');\n    }", "", "本地到云不需确认"),
 ("mixia.ts", "if (src.policy === 'cloud') data.cloudExposed = true;", "", "不标记曾上云"),
 ("mixia.ts", "if (this.level === 'software') throw new MixiaError('hardware_required');", "", "软件设备可建本地库"),
 ("device.ts", "throw new MixiaError('device_binding_failed');", "secret = new Uint8Array(32);", "设备绑定失败时继续"),
 ("sync.ts", "if (highest > this.book.state.seq) throw new IntegrityAlarm('ledger_withheld');", "", "不检测账本被隐瞒"),
 ("sync.ts", "if (!batch.every((p) => got.has(p.id))) throw new IntegrityAlarm('push_not_accepted');", "", "不核对服务器是否接受"),
 ("vault.ts", "for (const v of this.graph.allHeads()) if (!fresh.has(v.id)) carry.set(v.id, v);", "", "换钥丢弃快照外的本机版本"),
 ("vault.ts", "const v: Version = { ...original, device: this.author.deviceId };", "const v: Version = original;", "转发版本不改作者"),
 ("vault.ts", "this.key.fill(0);\n  }\n\n  private assertOpen(): void {\n    if (this.closed) throw new MixiaError('vault_locked');", "this.key.fill(0);\n  }\n\n  private assertOpen(): void {", "锁定后仍可写"),
 ("vault.ts", "const purged = [...heads].every((id) => this.versions.get(id)?.del);", "const purged = false;", "永久删除保留历史"),
 ("mixia.ts", "if (!seen || entryHash(seen) !== grant.headHash) throw new IntegrityAlarm('ledger_withheld');", "", "新设备不核对批准时的账本"),
 ("mixia.ts", "if (mine.signPub !== b64e(s.sign.pub) || mine.boxPub !== b64e(s.box.pub)) {\n      throw new IntegrityAlarm('device_keys_swapped');\n    }", "", "不核对账本里的本机公钥"),
 ("mixia.ts", "if (this.ledger.vaultsNeedingRotation().length > 0) throw new MixiaError('rotation_incomplete');", "", "换钥不全仍报成功"),
 ("mixia.ts", "if (await this.kv.get('alarm')) throw new MixiaError('alarm_active');", "", "告警期可批准设备"),
 ("mixia.ts", "if (this.session !== s) {\n        this.status = { ...this.status, state: 'idle' };\n        return;\n      }", "", "锁定竞态留下错误状态"),
 ("mixia.ts", "const vaults = opts.role === 'admin' ? [...st.vaults.keys()] : opts.vaults;", "const vaults = opts.vaults;", "管理设备不持有全部库"),
 ("api.ts", "if (vault.policy !== 'cloud') throw new MixiaError('policy_blocks_upload');\n    return this.send('GET'", "return this.send('GET'", "本地库附件可向服务器请求"),
 ("keys.ts", "r.value.replace(/'/g, `'\\\\''`)", "r.value", "Bash 导出不转义单引号"),
 ("keys.ts", "r.value.replace(/'/g, \"''\")", "r.value", "PowerShell 导出不转义单引号"),
 ("keys.ts", "const ok = rows.filter((r) => isEnvName(r.name));", "const ok = rows;", "非法变量名可进入命令"),
 ("keys.ts", "if (d.expiresAt <= now) return { state: 'expired', label: '已过期' };", "", "过期不报警"),
 ("keys.ts", "cloudProduction: keys.filter((i) => i.data.env === 'production' && isCloud(i.vaultId)),", "cloudProduction: [],", "不提示云库里的生产密钥"),
 ("keys.ts", "while (rows.has(name)) name = `${base}_${++n}`;", "", "导出时同名变量互相覆盖"),
 ("keys.ts", "return n ? `${n} 个变量` : '';", "", "变量组露出值的末 4 位"),
 ("transfer.ts", "...(d.fields ?? []).filter((f) => f.secret).map((f) => `${f.name}\\0${f.value}`),", "", "同名的不同密钥导入时被当成重复"),
 ("tools.ts", "(f.secret ? [f.name, f.envName] : [f.name, f.value, f.envName])", "[f.name, f.value, f.envName]", "搜索能匹配机密值"),
 ("model.ts", "if (!f.secret || !f.value) continue;\n    if (data.fields?.find", "if (!f.value) continue;\n    if (data.fields?.find", "非机密字段进入历史"),
 ("crypto.ts", "    p.ops < KDF_FLOOR.ops ||\n    p.mem < KDF_FLOOR.mem ||", "", "允许降级口令派生"),
 ("pack.ts", "const { n, c } = aeadSeal(packKey, utf8e(JSON.stringify(snap)), hb);", "const { n, c } = aeadSeal(packKey, utf8e(JSON.stringify(snap)), new Uint8Array());", "Pack 头部不认证(写)"),
]

# —— 浏览器填充 ——
CORE = ("npx -w @mixia/core vitest run test/autofill.test.ts --bail 1", ".")
EXT = ("npx -w @mixia/extension vitest run --bail 1", ".")
GO = ("go test -count=1 .", "apps/desktop/native/nmhost")
AF = "packages/core/src/autofill.ts"
BF = "packages/core/src/browserfill.ts"
PF = "packages/core/src/phonefill.ts"
# 手机推荐改用核心规则之前的写法：反向匹配父域、接受非网页协议、不看端口和公共后缀
PHONE_OLD = ("match: origin && (item.data.urls ?? []).some((u) => { let h = ''; try { h = new URL(u.includes('://') ? u : `https://${u}`)"
             ".hostname.replace(/^www\\./, '').toLowerCase(); } catch { h = ''; } const p = req.target.replace(/^www\\./, '').toLowerCase();"
             " return !!h && (h === p || p.endsWith(`.${h}`) || h.endsWith(`.${p}`)); }) ? 'exact' : null")
PO ="apps/extension/src/policy.ts"
CT = "apps/extension/src/controller.ts"
PR = "apps/desktop/native/nmhost/protocol.go"
HO = "apps/desktop/native/nmhost/host.go"
SV = "apps/desktop/native/nmhost/serve.go"
PW = "apps/desktop/native/nmhost/pipe_windows.go"
MN = "apps/desktop/native/nmhost/main.go"
B = [
 (AF, "if (page.scheme === 'http:' && item.scheme !== 'http:') return null;", "", "https 账号给明文页面", CORE),
 (AF, "if (page.port !== (item.explicitPort ? item.port : DEFAULT_PORT[page.scheme])) return null;", "", "站点不比较端口", CORE),
 (AF, "if (page.scheme === 'http:') return null;\n  if (!allowsSubdomains", "if (!allowsSubdomains", "明文页面做子域匹配", CORE),
 (AF, "if (!allowsSubdomains(item.host)) return null;", "", "公共后缀也做子域匹配", CORE),
 (AF, "return page.host.endsWith(`.${item.host}`) ? 'subdomain' : null;", "return page.host.includes(item.host) ? 'subdomain' : null;", "主机名子串匹配", CORE),
 (AF, "return page.host.endsWith(`.${item.host}`) ? 'subdomain' : null;", "return page.host.endsWith(item.host) ? 'subdomain' : null;", "子域匹配不带点", CORE),
 (AF, "return page.host.endsWith(`.${item.host}`) ? 'subdomain' : null;", "return page.host.endsWith(`.${item.host}`) || item.host.endsWith(`.${page.host}`) ? 'subdomain' : null;", "反向匹配父域", CORE),
 (AF, "if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;\n  if (!u.hostname)", "if (!u.hostname)", "接受非网页协议", CORE),
 (AF, "return u.origin === origin ? siteOf(u) : null;", "return siteOf(u);", "接受非规范 origin", CORE),
 (AF, "if (!host.includes('.')) return false;", "", "单段主机做子域匹配", CORE),
 (AF, "if (/^(com|net|org|gov|edu|ac|co)\\.[a-z]{2}$/.test(host)) return false;", "", "二级公共后缀做子域匹配", CORE),
 (AF, "return !SHARED_HOSTS.has(host);", "return true;", "多租户后缀做子域匹配", CORE),
 (AF, "return keys === 'op' ? { op: 'status' } : null;", "return { op: 'status' };", "status 接受多余字段", CORE),
 (AF, "return keys === 'op,origin' && origin ? { op: r.op, origin } : null;", "return origin ? { op: r.op, origin } : null;", "list 接受多余字段", CORE),
 (AF, "return keys === 'op,origin,ref' && origin && typeof r.ref === 'string' && REF.test(r.ref)", "return origin && typeof r.ref === 'string' && REF.test(r.ref)", "fill 接受多余字段", CORE),
 (AF, "typeof r.ref === 'string' && REF.test(r.ref)", "typeof r.ref === 'string'", "ref 不校验格式", CORE),
 (AF, "const origin = typeof r.origin === 'string' && parseOrigin(r.origin) ? r.origin : undefined;", "const origin = typeof r.origin === 'string' ? r.origin : undefined;", "请求 origin 不校验", CORE),
 (BF, "if (v.policy === 'cold') continue;", "", "冷库参与填充", CORE),
 (BF, ".filter((c) => c.policy === 'cloud')\n", "\n", "本地库条目进扩展列表", CORE),
 (BF, "if (!match) continue;", "", "不匹配的条目进候选", CORE),
 (BF, "if (!item.data.password) continue;", "", "没有密码的条目进候选", CORE),
 (BF, ".slice(0, LIST_LIMIT)\n", "\n", "列表没有上限", CORE),
 (BF, "if (!this.unlocked) return fail('locked');\n    if (req.op === 'list') {", "if (req.op === 'list') {", "未解锁仍处理请求", CORE),
 (BF, "if (this.busy) return fail('busy');", "", "可同时弹多个确认框", CORE),
 (BF, "this.busy = false;\n    }\n  }\n\n  private choice", "}\n  }\n\n  private choice", "确认框占用不释放", CORE),
 (BF, "if (req.op === 'fill' && chosen.policy !== 'cloud') return fail('no_match');", "", "扩展能直接点本地库条目", CORE),
 (BF, "if (!(await this.ui.confirm(origin, this.choice(chosen)))) return fail('denied');", "await this.ui.confirm(origin, this.choice(chosen));", "不看用户确认结果", CORE),
 (BF, "if (!this.unlocked) return fail('locked');\n      const now", "const now", "确认后不复查锁定", CORE),
 (BF, "const now = this.candidates(origin).find((c) => c.ref === ref);\n      if (!now) return fail('no_match');", "const now = this.candidates(origin).find((c) => c.ref === ref) ?? chosen;", "确认后不复查站点", CORE),
 (BF, "password: now.item.data.password ?? ''", "password: chosen.item.data.password ?? ''", "确认后给旧密码", CORE),
 (AF, "return u.hostname === host ? u.origin : null;", "return u.origin;", "手机域名不校验格式", CORE),
 (PF, "if (v.policy === 'cold') continue;", "", "手机冷库参与填充", CORE),
 (PF, "if (!item.data.password) continue;", "", "手机没有密码的条目进候选", CORE),
 (PF, "const origin = req.kind === 'web' ? phoneOrigin(req.target) : null;", "const origin = phoneOrigin(req.target);", "手机按 App 自报的域名推荐", CORE),
 (PF, "return { items, suggested: items.filter((e) => e.match) };", "return { items, suggested: items };", "手机不匹配的条目也推荐", CORE),
 (PF, "match: origin ? bestMatch(item.data.urls, origin) : null", "match: origin ? (bestMatch(item.data.urls, origin) ?? ((item.data.urls ?? []).some((u) => u.endsWith(`.${req.target}`)) ? 'subdomain' : null)) : null", "手机反向匹配父域", CORE),
 (PF, "match: origin ? bestMatch(item.data.urls, origin) : null", PHONE_OLD, "手机退回旧的宽匹配", CORE),

 (PO, "if (senderOrigin !== origin) return deny('cross_origin_frame');", "", "不看浏览器报告的框架来源", EXT),
 (PO, "if (webOrigin(f.url) !== origin) return deny('cross_origin_ancestor');", "", "不检查祖先框架", EXT),
 (PO, "if (!documentId || self.documentId !== documentId) return deny('stale_document');", "", "不核对文档", EXT),
 (PO, "if (!origin) return deny('top_not_web');", "", "顶层不是网页也放行", EXT),
 (PO, "if (!f || seen.has(f.frameId)) return deny('broken_chain');", "if (!f || seen.has(f.frameId)) return { ok: true, origin };", "框架断链放行", EXT),
 (PO, "return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null;", "return u.origin;", "非网页页面算网页", EXT),
 (PO, "return s.id === extensionId && s.tab?.id !== undefined && typeof s.frameId === 'number';", "return s.tab?.id !== undefined && typeof s.frameId === 'number';", "内容脚本不核对扩展 ID", EXT),
 (PO, "return s.id === extensionId && s.tab === undefined &&", "return s.tab === undefined &&", "弹窗不核对扩展 ID", EXT),
 (PO, "return s.id === extensionId && s.tab === undefined &&", "return s.id === extensionId &&", "标签页里的 popup.html 算弹窗", EXT),
 (PO, "s.tab === undefined && s.url === `chrome-extension://${extensionId}/popup.html`;", "s.tab === undefined;", "扩展其他页面算弹窗", EXT),
 (CT, "if (!(await this.stillThere(s))) return this.finish(s, 'page_changed');", "", "确认后不核对页面", EXT),
 (CT, "return v.ok && v.origin === s.origin && frames.find((f) => f.frameId === 0)?.documentId === s.topDocumentId;", "return v.ok && v.origin === s.origin;", "不核对顶层文档", EXT),
 (CT, "return v.ok && v.origin === s.origin && frames.find((f) => f.frameId === 0)?.documentId === s.topDocumentId;", "return frames.find((f) => f.frameId === 0)?.documentId === s.topDocumentId;", "不核对框架文档", EXT),
 (CT, "this.current = undefined;\n    try {", "try {", "会话可重复使用", EXT),
 (CT, "if (this.filling) return { error: 'busy' };", "", "可并发填充", EXT),
 (CT, "this.current = armed && (await this.stillThere(armed)) ? armed : await this.probe(tabId);", "this.current = armed ?? (await this.probe(tabId));", "旧的 arm 不作废", EXT),
 (CT, "if (!v.ok) return { error: v.reason };", "", "框架判断失败仍登记", EXT),
 (CT, "} else if (isPopup(sender, this.extensionId)) {", "} else {", "来路不明的消息当弹窗", EXT),
 (CT, "if (isContent(sender, this.extensionId)) {", "if (sender.tab || t === 'arm') {", "弹窗能调内容脚本操作", EXT),
 (CT, "if (!r.ok) return this.finish(s, r.error ?? 'failed');", "", "桌面拒绝仍往下走", EXT),
 (CT, "if (typeof r.password !== 'string') return this.finish(s, 'bad_reply');", "", "回复没有密码仍发给页面", EXT),
 (CT, ".send(s.tabId, s.documentId, { t: 'fill'", ".send(s.tabId, s.topDocumentId, { t: 'fill'", "密码发给顶层而不是发起框架", EXT),

 (PR, "\tdefault:\n\t\treturn request{}, errBadMessage\n\t}\n\tif needOrigin !=", "\t}\n\tif needOrigin !=", "未知操作放行", GO),
 (PR, "\td.DisallowUnknownFields()\n", "", "接受未知字段", GO),
 (PR, "\tif needOrigin != (r.Origin != \"\") || needRef != (r.Ref != \"\") {\n\t\treturn request{}, errBadMessage\n\t}\n", "", "字段和操作不对应", GO),
 (PR, "if needOrigin && !originRE.MatchString(r.Origin) {", "if false {", "host 不校验 origin 格式", GO),
 (PR, "if needRef && !refRE.MatchString(r.Ref) {", "if false {", "host 不校验 ref 格式", GO),
 (PR, "if r.ID != req.ID {", "if false {", "回复 ID 不核对", GO),
 (PR, "if r.State != \"\" || r.Items == nil || hasCred || !validItems(*r.Items) {", "if r.State != \"\" || r.Items == nil || !validItems(*r.Items) {", "list 回复可带密码", GO),
 (PR, "if (r.State != \"ready\" && r.State != \"locked\") || r.Items != nil || hasCred {", "if (r.State != \"ready\" && r.State != \"locked\") || r.Items != nil {", "status 回复可带密码", GO),
 (PR, "if !replyErrors[r.Error] || r.State != \"\" || r.Items != nil || hasCred {", "if !replyErrors[r.Error] {", "错误回复可带密码", GO),
 (PR, "if !replyErrors[r.Error] || r.State", "if r.State", "错误码不限定", GO),
 (PR, "if !refRE.MatchString(it.Ref) || len(it.Title)", "if len(it.Title)", "列表 ref 不校验", GO),
 (PR, "if len(items) > maxListItems {", "if false {", "列表条数不限", GO),
 (PR, "len(*r.Password) > maxPasswordLen", "false", "密码长度不限", GO),
 (PR, "if n > uint32(limit) {", "if false {", "超长帧继续读", GO),
 (HO, "\t\tif err != nil {\n\t\t\tdata = failure(requestID(f.raw), \"bad_request\")\n\t\t} else {\n\t\t\tdata = h.exchange(req)\n\t\t}", "\t\t_ = err\n\t\tdata = h.exchange(req)", "坏请求也进管道", GO),
 (HO, "\tdata, err := filterReply(req, raw)\n\tif err != nil {\n\t\treturn failure(req.ID, codeBadReply)\n\t}\n\treturn data", "\treturn raw", "回复不过滤", GO),
 (SV, "\t\treq, err := parseRequest(raw)\n\t\tif err != nil {\n\t\t\tif writeFrame(c, failure(requestID(raw), \"bad_request\"), maxReplyFrame) != nil {\n\t\t\t\treturn\n\t\t\t}\n\t\t\tcontinue\n\t\t}\n\t\tmsg, err := json.Marshal(req)\n\t\tif err != nil || h.send(id, msg) != nil {", "\t\tif h.send(id, raw) != nil {", "管道服务不校验请求", GO),
 (PW, "return \"D:P(A;;GA;;;\" + sid + \")\"", "return \"D:P(A;;GA;;;\" + sid + \")(A;;GR;;;WD)\"", "管道对 Everyone 开放", GO),
 (PW, "if verify(h) != nil {\n\t\t\t_ = windows.DisconnectNamedPipe(h)", "if false {\n\t\t\t_ = windows.DisconnectNamedPipe(h)", "服务端不核对客户端", GO),
 (PW, "\t\tif err := verify(h); err != nil {\n\t\t\twindows.CloseHandle(h)\n\t\t\treturn nil, err\n\t\t}\n\t\treturn &pipeFile{h}, nil", "\t\treturn &pipeFile{h}, nil", "客户端不核对服务端", GO),
 (PW, "if !strings.EqualFold(self, peer) {", "if !strings.EqualFold(self, self) && peer != \"\" {", "对端镜像不比较", GO),
 (PW, "l.next, err = l.create(windows.FILE_FLAG_FIRST_PIPE_INSTANCE)", "l.next, err = l.create(0)", "管道名可被共用", GO),
 (MN, "\tcase extensionOrigin:\n\t\treturn \"host\"\n\t}\n\treturn \"\"", "\t}\n\treturn \"host\"", "任何参数都当 host", GO),
]

# 真机组：破坏防护后，整条真实链路必须失败。每项要重新构建并跑一遍 e2e，只在 --e2e 时运行
BUILD = "npm -w @mixia/ui run build && cd apps\\desktop && node build.mjs && cd ..\\extension && node build.mjs"
REAL = ("set MIXIA_E2E_FAST=1&& node e2e.mjs", "apps/extension", BUILD)
SLOW = ("set MIXIA_E2E_LIFE=1&& node e2e.mjs", "apps/extension", BUILD)
E = [
 (PO, "if (webOrigin(f.url) !== origin) return deny('cross_origin_ancestor');", "", "真机:不检查祖先框架", REAL),
 (AF, "if (page.host === item.host) return 'exact';", "return 'exact';", "真机:站点不匹配也给", REAL),
 # 跳转后不泄露靠三层：发送前核对、按 documentId 发送、新文档的内容脚本没有目标字段。去掉一层不会泄露（实测存活），要三层一起去掉
 (CT, "if (!(await this.stillThere(s))) return this.finish(s, 'page_changed');", "", "真机:跳转防护三层全去", REAL + ([
   ("apps/extension/src/background.ts", "chrome.tabs.sendMessage(tabId, msg, { documentId })", "chrome.tabs.sendMessage(tabId, msg)"),
   ("apps/extension/src/content.ts", "  const t = target;\n", "  const t = target ?? findFields();\n"),
 ],)),
 ("apps/extension/src/content.ts", "if (!t || !visible(t.password)) return", "if (!t) return", "真机:填隐藏字段", REAL),
 # 这项存活就说明生命周期测试里 Service Worker 根本没被回收，那段测试是空的
 ("apps/extension/src/popup.ts", "setInterval(() => void chrome.runtime.sendMessage({ t: 'ping' }), 20_000);", "", "真机:弹窗不保活", SLOW),
]

survived = []
args = sys.argv[1:]
real = "--e2e" in args
only = [a for a in args if a != "--e2e"]
FULL = ("npx -w @mixia/core vitest run --bail 1", ".")
ALL = E if real else [(f"packages/core/src/{m[0]}", m[1], m[2], m[3], FULL) for m in M] + B
if only:
    ALL = [m for m in ALL if any(k in m[3] for k in only)]
sh = dict(shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
for rel, old, new, name, run in ALL:
    p = root / rel
    orig = p.read_text(encoding="utf-8")
    if old not in orig:
        print("!! 未命中:", name); survived.append("未命中:"+name); continue
    # 真机组可以同时改几处：run 的第 4 项是额外的 (文件, 原文, 替换)
    extras = [(root / e[0], e[1], e[2]) for e in (run[3] if len(run) > 3 else [])]
    saved = [(f, f.read_text(encoding="utf-8")) for f, _, _ in extras]
    if any(o not in t for (_, o, _), (_, t) in zip(extras, saved)):
        print("!! 未命中:", name); survived.append("未命中:"+name); continue
    p.write_text(orig.replace(old, new, 1), encoding="utf-8", newline="\n")
    for (f, o, n), (_, t) in zip(extras, saved):
        f.write_text(t.replace(o, n, 1), encoding="utf-8", newline="\n")
    invalid = False
    killed = False
    r = None
    try:
        # 构建失败或编译不过不算抓到：那只说明变异写错了或环境有问题
        if len(run) > 2 and subprocess.run(run[2], cwd=root, **sh).returncode != 0:
            invalid = True
        else:
            r = subprocess.run(run[0], cwd=root / run[1], timeout=900 if real else 240, **sh)
            killed = r.returncode != 0
            invalid = "[build failed]" in r.stdout + r.stderr
            # 退出码不是 0 却没有一条 FAIL：是进程自己出了问题，不是测试发现了什么
            if real and killed and "FAIL" not in r.stdout:
                invalid = True
    except subprocess.TimeoutExpired:
        # 真机组超时说明测试挂住了，没有证明防护失效时测试会报错
        killed = not real
        invalid = real
    finally:
        p.write_text(orig, encoding="utf-8", newline="\n")
        for f, t in saved:
            f.write_text(t, encoding="utf-8", newline="\n")
    if invalid:
        print("!! 无效变异:", name, flush=True); survived.append("无效:"+name); continue
    print(("抓到" if killed else "存活!"), name, flush=True)
    # 真机组要看清是哪一项失败的，环境问题造成的失败不算数
    if real and r:
        for line in [l for l in r.stdout.splitlines() if l.startswith("FAIL")][:4]:
            print("   ", line[:150], flush=True)
    if not killed: survived.append(name)
print(f"\n共 {len(ALL)} 项，存活 {len(survived)}：{survived}")
if real:
    print("重新构建干净的产物")
    subprocess.run(BUILD, cwd=root, **sh)
