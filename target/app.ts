// ============================================================================
// target/app.ts  ―  やられ役Webアプリの本体 (Hono + TypeScript)
// ----------------------------------------------------------------------------
// ※ 教育目的の「意図的に脆弱な」アプリです。本番・公開サーバには置かないこと。
//   ローカル隔離 (127.0.0.1) のラボ内でのみ動かす前提です。
//
// ルート定義とアプリ本体(`app`)をここに置き、起動(listen)は server.ts が行う。
// こうすることで、Vitest から `app.request(...)` を直接叩いて脆弱性を検証できる
// (サーバを listen せずに fetch ハンドラをテストできる)。
//
// このモジュールの脆弱性: クリックジャッキング / ライクジャッキング (Clickjacking)
//   /sns/widget（埋め込み用「いいね」ボタン）がフレーム化を禁止するヘッダを
//   返さないため、任意の外部サイトが <iframe> で透明に重ねられてしまう。
// ============================================================================

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { Hono } from 'hono';

const execAsync = promisify(exec);

export const app = new Hono();

// ---------------------------------------------------------------------------
// ★ 脆弱ポイントの核心 ★
//   本来ここで、全レスポンス (少なくとも /sns/widget) にフレーム化禁止ヘッダを
//   付ければクリックジャッキングは防げる。このラボでは「あえて付けていない」。
//
//   == 対策 (どちらか一方を有効化すれば攻撃は成立しなくなる) ==
//   下の app.use(...) のコメントを外して再起動し、同じ攻撃が失敗することを確認せよ。
// ---------------------------------------------------------------------------
//
// app.use('*', async (c, next) => {
//   await next();
//   // 対策A: 古くからある専用ヘッダ。iframe 埋め込みを全面拒否。
//   c.header('X-Frame-Options', 'DENY');
//   // 対策B: 現代的な方法。frame-ancestors 'none' で祖先フレームを一切許可しない。
//   c.header('Content-Security-Policy', "frame-ancestors 'none'");
// });

// トップ: SNSホームへの入口
app.get('/', (c) => {
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>つなぐ (target)</title></head>
<body style="font-family:sans-serif;padding:24px">
  <h1>つなぐ (target)</h1>
  <p>これは教育用のやられ役SNSです。</p>
  <p><a href="/sns">タイムラインへ</a></p>
</body></html>`);
});

// ===========================================================================
// シナリオ: ライクジャッキング (Likejacking) ― 架空SNS「つなぐ」
// ---------------------------------------------------------------------------
// 2010年に Facebook で流行した「いいね！」ボタン乗っ取りの再現。
//   - /sns/widget は、外部サイトに貼り付ける「いいね」ボタン(埋め込みウィジェット)。
//     Facebook の Like プラグインに相当する。
//   - このウィジェットもフレーム化禁止ヘッダを返さないため、攻撃者が透明で重ねられる。
//   - 「ログイン中の本人」としていいねが成立し、本人のフィードに流れる(=友達に拡散)。
//
//   ※ 本物の Facebook は別ドメイン(cross-site)なので、現代ブラウザのサードパーティ
//      Cookie ブロックや SameSite が効く。このラボは localhost 同士(same-site)なので
//      セッションを使わずとも「ログイン中の本人の操作」を単純なサーバ状態で再現する。
// ===========================================================================

// 「ログイン中ユーザー」とその『いいね』フィード (DB代わりのメモリ状態)
const snsUser = 'あなた (@you)';
let likedFeed: string[] = [];

// SNSホーム: 誰としてログイン中か、これまで何に「いいね」したか(=友達に流れた内容)。
app.get('/sns', (c) => {
  const feedHtml = likedFeed.length
    ? likedFeed
        .map(
          (t) =>
            `<li>👍 <strong>${t}</strong> <span style="color:#888">— あなたがいいねしました(友達のフィードに表示)</span></li>`,
        )
        .join('')
    : '<li style="color:#888">まだ何もいいねしていません</li>';
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>つなぐ (SNS)</title>
<style>
  body { font-family: sans-serif; padding:24px; max-width:640px; }
  .me { background:#eef3ff; border-radius:10px; padding:12px 16px; }
  li { margin:8px 0; }
</style></head>
<body>
  <h1>つなぐ <span style="font-size:14px;color:#888">架空SNS (target)</span></h1>
  <p class="me">ログイン中: <strong>${snsUser}</strong></p>
  <h2>あなたがいいねした投稿 (タイムライン)</h2>
  <ul>${feedHtml}</ul>
</body></html>`);
});

// 埋め込み用「いいね」ウィジェット。外部サイトに iframe で貼る想定。
//   ?title=... で対象の投稿タイトルを受け取る。★フレーム化禁止ヘッダは無し(脆弱点)。
app.get('/sns/widget', (c) => {
  const title = c.req.query('title') ?? 'おすすめの投稿';
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>いいねウィジェット</title>
<style>
  body { font-family: sans-serif; margin:0; padding:10px; }
  .card { border:1px solid #d9d9d9; border-radius:10px; padding:12px 14px; max-width:320px; }
  .ttl { font-size:14px; margin:0 0 10px; }
  .like { background:#1877f2; color:#fff; border:none; border-radius:6px;
          font-size:16px; font-weight:bold; padding:10px 22px; cursor:pointer; }
</style></head>
<body>
  <div class="card">
    <p class="ttl">【つなぐ】${title}</p>
    <!-- ログイン中の本人として、ワンクリックで「いいね」が確定する -->
    <form method="POST" action="/sns/like">
      <input type="hidden" name="title" value="${title}">
      <button class="like" type="submit">👍 いいね！</button>
    </form>
  </div>
</body></html>`);
});

// 「いいね」の実体。確認なしでフィードに追加される(=友達に拡散される)。
app.post('/sns/like', async (c) => {
  const body = await c.req.parseBody();
  const title = typeof body.title === 'string' ? body.title : 'おすすめの投稿';
  likedFeed.push(title);
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>いいね完了</title></head>
<body style="font-family:sans-serif;padding:16px">
  <p>👍 「${title}」にいいねしました。</p>
  <p><a href="/sns">タイムラインを見る</a></p>
</body></html>`);
});

// SNSシナリオのリセット
app.post('/sns/reset', (c) => {
  likedFeed = [];
  return c.json({ ok: true, likedFeed });
});

// ===========================================================================
// モジュール2: XSS (クロスサイトスクリプティング) ― 蓄積型 + 反射型
// ---------------------------------------------------------------------------
// 実在事例: 2005年 MySpace の「Samy ワーム」(Samy Kamkar)。
//   プロフィールの自由記述に JavaScript を仕込める蓄積型XSSを悪用し、
//   「but most of all, samy is my hero」を他人のプロフィールへ勝手に追記 + その
//   スクリプト自体を閲覧者のプロフィールへ複製し、約20時間で100万人超へ自己増殖した。
//
// 架空シナリオ (つなぐ):
//   攻撃者「サミー(@samy)」が自分のプロフィールの『ひとこと』に <script> を仕込む。
//   その profile を見た利用者のブラウザで script が動き、
//     (1) 利用者として拡散投稿に「いいね」し (POST /sns/like)、
//     (2) 同じ script を利用者自身の『ひとこと』にも複製する (POST /sns/profile)。
//   見た人がまた増殖源になり、MySpace の Samy ワームと同じ構図で広がる。
//
// 脆弱点:
//   - 蓄積型: /sns/users/:name が profile.bio を「無エスケープ」で HTML に埋め込む。
//   - 反射型: /sns/search が ?q をそのまま結果ページに反射する。
// ===========================================================================

// --- 対策(出力時の HTML エスケープ)。これを使って埋め込めば XSS は成立しない ---
// function escapeHtml(s: string): string {
//   return s
//     .replaceAll('&', '&amp;')
//     .replaceAll('<', '&lt;')
//     .replaceAll('>', '&gt;')
//     .replaceAll('"', '&quot;')
//     .replaceAll("'", '&#39;');
// }
// さらに Content-Security-Policy: script-src 'self' などを併用すると多層防御になる。

type Profile = { handle: string; display: string; bio: string };
const defaultProfiles = (): Record<string, Profile> => ({
  you: { handle: 'you', display: 'あなた (@you)', bio: 'はじめまして！よろしくお願いします。' },
  samy: {
    handle: 'samy',
    display: 'サミー (@samy)',
    // 攻撃者が仕込んだ蓄積型XSSペイロード(Samyワームの再現)。
    // 閲覧者のブラウザで動き、いいね拡散 + 自分のプロフィールへ複製して自己増殖する。
    bio: "みんなよろしく！<img src=x onerror=\"fetch('/sns/like',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:'title=サミーは俺のヒーロー'});\">",
  },
});
let profiles: Record<string, Profile> = defaultProfiles();

// プロフィール表示。★ bio を無エスケープで埋め込む(蓄積型XSSのシンク)。
app.get('/sns/users/:name', (c) => {
  const name = c.req.param('name');
  const p = profiles[name];
  if (!p) return c.notFound();
  // 脆弱: 本来は escapeHtml(p.bio) すべきところを、そのまま展開している。
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>${p.display} | つなぐ</title>
<style>
  body { font-family: sans-serif; padding:24px; max-width:640px; }
  .bio { background:#f6f8fa; border:1px solid #e1e4e8; border-radius:10px; padding:14px 16px; }
</style></head>
<body>
  <h1>${p.display}</h1>
  <h2>ひとこと</h2>
  <div class="bio">${p.bio}</div>
  <p><a href="/sns/users/you">自分のプロフィール</a> / <a href="/sns">タイムライン</a></p>
</body></html>`);
});

// 『ひとこと』の更新(ログイン中の本人 = you)。蓄積型XSSの投入口。
app.post('/sns/profile', async (c) => {
  const body = await c.req.parseBody();
  const bio = typeof body.bio === 'string' ? body.bio : '';
  profiles.you.bio = bio;
  return c.json({ ok: true, bio });
});

// 検索。★ ?q をそのまま結果ページへ反射する(反射型XSSのシンク)。
app.get('/sns/search', (c) => {
  const q = c.req.query('q') ?? '';
  // 脆弱: 本来は escapeHtml(q) すべきところを、そのまま展開している。
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>「${q}」の検索結果 | つなぐ</title>
<style>body { font-family: sans-serif; padding:24px; max-width:640px; }</style></head>
<body>
  <h1>検索結果</h1>
  <p>「${q}」に一致する投稿は見つかりませんでした。</p>
  <form method="GET" action="/sns/search">
    <input name="q" value="${q}" placeholder="キーワード">
    <button type="submit">検索</button>
  </form>
</body></html>`);
});

// XSSシナリオのリセット(プロフィールを初期状態へ)。
app.post('/sns/profile/reset', (c) => {
  profiles = defaultProfiles();
  return c.json({ ok: true });
});

// ===========================================================================
// モジュール3: SQLインジェクション ― ログインバイパス + UNION によるデータ窃取
// ---------------------------------------------------------------------------
// 実在事例: 2011年 Sony Pictures の情報漏えい(LulzSec)。SQLインジェクションで
//   会員DBが抜かれ、約100万件のアカウントが流出。しかもパスワードが平文保存で、
//   そのまま使える状態だった、と報じられた。古典の `' OR '1'='1` ログインバイパスも
//   同じ原理(入力をSQL文字列にそのまま連結する)で成立する。
//
// 架空シナリオ (つなぐ):
//   会員ログインと会員検索が、入力値を SQL にそのまま文字列連結している。
//     (1) ログイン: username に `admin'--` を入れるとパスワード照合を無効化して成りすまし。
//     (2) 会員検索: `' UNION SELECT ... --` で平文パスワードや秘密メモを丸ごと吸い出す。
//
// 脆弱点: プレースホルダ(パラメータバインド)を使わず、`'${input}'` と連結している。
// ===========================================================================

// やられ役の会員DB(メモリ上の SQLite)。※ パスワード平文保存も「やられ」仕様。
const db = new Database(':memory:');
db.exec(`
  CREATE TABLE members (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email    TEXT NOT NULL,
    secret   TEXT NOT NULL
  );
  INSERT INTO members (username, password, email, secret) VALUES
    ('you',   'password123', 'you@tsunagu.example',   '下書き: 退職願'),
    ('samy',  'hero2005',    'samy@tsunagu.example',  'DM下書き'),
    ('admin', 'S0ny-pwn3d!', 'admin@tsunagu.example', '管理者用バックアップ鍵: ABCD-1234');
`);

// --- 対策(プレースホルダ/パラメータバインド)。これなら注入は成立しない ---
//   const row = db.prepare(
//     'SELECT * FROM members WHERE username = ? AND password = ?',
//   ).get(username, password);
//   会員検索も db.prepare('... WHERE username = ?').all(name) とする。

type Member = { id: number; username: string; password: string; email: string; secret: string };

// 会員ログイン。★ 入力を SQL にそのまま連結(脆弱)。
//   username = admin'--  → パスワード条件がコメントアウトされ成りすまし。
//   username = ' OR '1'='1  → 全件ヒットの先頭として最初のユーザーでログイン。
app.post('/sns/login', async (c) => {
  const body = await c.req.parseBody();
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const sql = `SELECT * FROM members WHERE username = '${username}' AND password = '${password}'`;
  try {
    const row = db.prepare(sql).get() as Member | undefined;
    if (row) {
      return c.json({ ok: true, loggedInAs: row.username, sql });
    }
    return c.json({ ok: false, sql }, 401);
  } catch (e) {
    // 注入で構文エラーになった場合でも、学習用に実行SQLとエラーを見せる。
    return c.json({ ok: false, sql, error: String(e) }, 400);
  }
});

// 会員検索。★ ?name を SQL にそのまま連結(脆弱)。UNION でカラムを揃えて窃取できる。
//   name = ' UNION SELECT id, username || ':' || password, email, secret FROM members --
app.get('/sns/members', (c) => {
  const name = c.req.query('name') ?? '';
  const sql = `SELECT id, username, email, secret FROM members WHERE username = '${name}'`;
  try {
    const rows = db.prepare(sql).all();
    return c.json({ ok: true, sql, rows });
  } catch (e) {
    return c.json({ ok: false, sql, error: String(e) }, 400);
  }
});

// ===========================================================================
// モジュール4: OSコマンドインジェクション ― 管理者向けネットワーク診断(ping)ツール
// ---------------------------------------------------------------------------
// 実在事例: 2014年「Shellshock」(CVE-2014-6271)。bash の環境変数処理の欠陥を突いて、
//   CGI 経由などで Web サーバ上に任意の OS コマンドを実行され、多数のサーバが乗っ取られた。
//   「Web からの入力が最終的にシェルに渡る」典型例で、管理画面の ping/traceroute 診断
//   機能に ; や && を混ぜてコマンドを連結する古典的な注入も同じ原理で成立する。
//
// 架空シナリオ (つなぐ):
//   運営の管理画面に「サーバ疎通確認(ping)」ツールがある。入力ホスト名をそのまま
//   `ping -c 1 <host>` のコマンド文字列に連結してシェル実行しているため、
//     host = 127.0.0.1; cat /etc/passwd   のように書くと任意コマンドが動く。
//
// 脆弱点: ユーザー入力をシェルコマンド文字列へ連結し、`exec`(シェル経由)で実行している。
// ===========================================================================

// --- 対策(シェルを介さない + 入力検証)。これなら注入は成立しない ---
//   import { execFile } from 'node:child_process';
//   // 1) ホスト名として妥当な文字だけ許可(英数字・ドット・ハイフン)。
//   if (!/^[A-Za-z0-9.-]+$/.test(host)) return c.json({ ok:false, error:'invalid host' }, 400);
//   // 2) シェルを使わず引数配列で渡す(; や && がメタ文字として解釈されない)。
//   const { stdout } = await execFileAsync('ping', ['-c', '1', host]);

// 管理者向け ping 診断。★ 入力を ping コマンド文字列へ連結して exec(脆弱)。
//   host = 127.0.0.1; echo PWNED  →  ping のあとに echo も実行される。
app.get('/admin/net/ping', async (c) => {
  const host = c.req.query('host') ?? '127.0.0.1';
  const cmd = `ping -c 1 ${host}`;
  try {
    // シェル経由で実行するため ; && | ` などのメタ文字が効いてしまう。
    const { stdout, stderr } = await execAsync(cmd, { timeout: 5000 });
    return c.json({ ok: true, cmd, output: stdout + stderr });
  } catch (e) {
    // 実行自体が失敗(ping 不在や非ゼロ終了)でも、連結したコマンドの出力は得られる。
    const err = e as { stdout?: string; stderr?: string; message?: string };
    return c.json({
      ok: false,
      cmd,
      output: (err.stdout ?? '') + (err.stderr ?? ''),
      error: err.message ?? String(e),
    });
  }
});
