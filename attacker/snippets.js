// ============================================================================
// attacker/snippets.js  ―  ラボ画面右ペインに出す「脆弱 / 対策」の最小コード片
// ----------------------------------------------------------------------------
// target/app.ts から要点の行だけを抜き出したもの。attacker コンテナからは
// target のソースが見えないため手で持つが、target/tests/snippets.test.ts が
// 「各行が app.ts にそのまま存在すること」を検査するので、app.ts を変えたのに
// ここを直し忘れると CI が落ちる。`//` で始まる行と空行は注記扱いで検査対象外。
// ============================================================================
window.LAB_SNIPPETS = {
  clickjacking: {
    where: "app.use('/sns/widget', …)",
    point: 'フレーム化禁止ヘッダを返すだけ。iframe に重ねられなくなる。',
    vuln: [
      "app.use('/sns/widget', async (c, next) => {",
      '  await next();',
      '  // ★ フレーム化を禁止するヘッダを何も付けていない',
      '});',
    ],
    defense: [
      "app.use('/sns/widget', async (c, next) => {",
      '  await next();',
      "  c.header('X-Frame-Options', 'DENY');",
      "  c.header('Content-Security-Policy', \"frame-ancestors 'none'\");",
      '});',
    ],
  },
  xss: {
    where: 'GET /sns/search',
    point: '出力前に HTML エスケープ。入力は「文字列」として表示される。',
    vuln: [
      "const raw = c.req.query('q') ?? '';",
      'q = raw;',
      '// ↓ そのまま HTML に埋め込む',
      '<p>「${q}」に一致する投稿は見つかりませんでした。</p>',
    ],
    defense: [
      "const raw = c.req.query('q') ?? '';",
      'q = escapeHtml(raw);',
      '// ↓ < > " \' & はエンティティ化済み',
      '<p>「${q}」に一致する投稿は見つかりませんでした。</p>',
    ],
  },
  sqli: {
    where: 'POST /sns/login',
    point: '文字列連結をやめ、値はプレースホルダ (?) で別渡しにする。',
    vuln: [
      "sql = `SELECT * FROM members WHERE username = '${username}' AND password = '${password}'`;",
      'run = () => db.prepare(sql).get() as Member | undefined;',
    ],
    defense: [
      "sql = 'SELECT * FROM members WHERE username = ? AND password = ?';",
      'run = () => db.prepare(sql).get(username, password) as Member | undefined;',
    ],
  },
  oscmd: {
    where: 'GET /admin/net/ping',
    point: '許可リストで入力検証し、シェルを介さない execFile で引数配列として渡す。',
    vuln: ['cmd = `ping -c 1 ${host}`;', 'run = () => execAsync(cmd, { timeout: 5000 });'],
    defense: [
      'if (!/^[A-Za-z0-9.-]+$/.test(host)) {',
      "  return c.json({ ok: false, mode, error: 'invalid host' }, 400);",
      '}',
      "run = () => execFileAsync('ping', ['-c', '1', host], { timeout: 5000 });",
    ],
  },
  pathtrav: {
    where: 'GET /sns/files',
    point: '正規化後のパスが公開ディレクトリの内側かを検証し、外なら拒否。',
    vuln: ['target = join(UPLOAD_DIR, name);', "const content = await readFile(target, 'utf8');"],
    defense: [
      'target = resolve(UPLOAD_DIR, name);',
      'const rel = relative(UPLOAD_DIR, target);',
      "if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {",
      "  return c.json({ ok: false, mode, requested: name, error: 'invalid path' }, 400);",
      '}',
      "const content = await readFile(target, 'utf8');",
    ],
  },
  csrf: {
    where: 'POST /account/email',
    point: '送信元 (Origin / Referer) が自サイトでなければ拒否。不明も拒否 (fail closed)。',
    vuln: [
      "app.post('/account/email', async (c) => {",
      '  // ★ 送信元を確認せずに状態を変える',
      '  const body = await c.req.parseBody();',
      '  accountEmail = email;',
    ],
    defense: [
      "app.post('/account/email', async (c) => {",
      '  if (isDefended(c) && !isSameOriginRequest(c)) {',
      "    return c.json({ ok: false, mode: 'defended', error: 'cross-site request rejected' }, 403);",
      '  }',
      '  const body = await c.req.parseBody();',
      '  accountEmail = email;',
      '',
      '// isSameOriginRequest の中身',
      "const src = c.req.header('origin') ?? c.req.header('referer');",
      "if (!src || src === 'null') return false;",
      'return SELF_HOSTS.has(new URL(src).host);',
    ],
  },
  authz: {
    where: 'GET /api/messages/:id',
    point: '取得したリソースが本人のものかを、毎回サーバ側で確認する。',
    vuln: [
      'const msg = messages.find((m) => m.id === id);',
      "if (!msg) return c.json({ ok: false, mode, error: 'not found' }, 404);",
      'return c.json({ ok: true, mode, requestedBy: currentUser(c), message: msg });',
    ],
    defense: [
      'const msg = messages.find((m) => m.id === id);',
      "if (!msg) return c.json({ ok: false, mode, error: 'not found' }, 404);",
      "if (mode === 'defended' && msg.owner !== currentUser(c)) {",
      "  return c.json({ ok: false, mode, error: 'forbidden' }, 403);",
      '}',
      'return c.json({ ok: true, mode, requestedBy: currentUser(c), message: msg });',
    ],
  },
};
