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

import { exec, execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { type Context, Hono } from 'hono';
import { cors } from 'hono/cors';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

export const app = new Hono();

// ---------------------------------------------------------------------------
// CORS ― 各攻撃デモ(attacker/*.html)を「ブラウザから」体験可能にするための配線
//   攻撃デモは別オリジン http://localhost:9090 から配信され、この標的
//   http://localhost:8080 の応答を fetch で読み取る(例: /admin/net/ping,
//   /sns/files, /account, /api/messages)。標的がCORS応答を返さないと、
//   サーバは正常に処理していてもブラウザが結果の読み取りをブロックし、画面には
//   "TypeError: Failed to fetch" だけが出てデモが成立しない。
//   そこで全ルートに許可応答を付ける。これは各モジュールの脆弱性(所有者チェック
//   欠落・OSコマンド注入・パストラバーサル等)とは別問題で、緩いCORSは現実のAPIでも
//   珍しくない。脆弱性の本体はあくまで各ハンドラ側にあり、CORSはそれを
//   ブラウザ越しに観測できるようにするだけ。
//   ※ ナビゲーション主体のデモ(フォーム送信=CSRF、iframe=クリックジャッキング、
//     直接URL=SQLi/XSS)はCORS無しでも成立する。これは fetch で応答を読む
//     デモ(OSコマンド/パストラバーサル/IDOR、CSRFの検証表示)向けの配線。
// ---------------------------------------------------------------------------
app.use('*', cors({ origin: '*', allowHeaders: ['X-User', 'Content-Type'] }));

// ---------------------------------------------------------------------------
// 対策フラグ(全モジュール共通): `?defense=1` を付けたリクエストだけ「対策済み」の
//   実装で処理する。同じペイロードを 脆弱/対策済み で撃ち比べるための学習用スイッチ。
//   フラグなし(既定)は常に脆弱版。フォーム送信・iframe・直接URLのデモでも使えるよう、
//   ヘッダではなくクエリで受け取る。各ハンドラ内で 脆弱版(★) と 対策版(✅) を並べてある。
// ---------------------------------------------------------------------------
const isDefended = (c: Context) => c.req.query('defense') === '1';
const modeOf = (c: Context) => (isDefended(c) ? 'defended' : 'vulnerable');

// ---------------------------------------------------------------------------
// ★ 脆弱ポイントの核心 ★
//   本来ここで、全レスポンス (少なくとも /sns/widget) にフレーム化禁止ヘッダを
//   付ければクリックジャッキングは防げる。このラボでは「あえて付けていない」。
//
//   == 対策 (どちらか一方を返せば攻撃は成立しなくなる) ==
//   `?defense=1` 付きのリクエストにだけ、下のミドルウェアがフレーム化禁止ヘッダを付ける。
//   (本番なら条件なしで全レスポンスに付けるべきもの。このラボでは XSS デモが標的ページを
//    iframe で表示するため、対象をクリックジャッキングの標的 /sns/widget に絞っている)
// ---------------------------------------------------------------------------
app.use('/sns/widget', async (c, next) => {
  await next();
  if (!isDefended(c)) return; // ★ 脆弱: 既定ではヘッダを付けない
  // ✅ 対策A: 古くからある専用ヘッダ。iframe 埋め込みを全面拒否。
  c.header('X-Frame-Options', 'DENY');
  // ✅ 対策B: 現代的な方法。frame-ancestors 'none' で祖先フレームを一切許可しない。
  c.header('Content-Security-Policy', "frame-ancestors 'none'");
});

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

// 対策(出力時の HTML エスケープ)。これを通して埋め込めば XSS は成立しない。
//   `?defense=1` のときだけ使う。さらに Content-Security-Policy: script-src 'self' などを
//   併用すると多層防御になる。
function escapeHtml(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

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

// プロフィール表示。
//   脆弱: bio を無エスケープで埋め込む(蓄積型XSSのシンク)。
//   対策: escapeHtml で文字列として埋め込む。
app.get('/sns/users/:name', (c) => {
  const name = c.req.param('name');
  const p = profiles[name];
  if (!p) return c.notFound();
  // ★ 脆弱: そのまま展開 / ✅ 対策: escapeHtml してから展開
  const out = isDefended(c) ? escapeHtml : (v: string) => v;
  const display = out(p.display);
  const bio = out(p.bio);
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>${display} | つなぐ</title>
<style>
  body { font-family: sans-serif; padding:24px; max-width:640px; }
  .bio { background:#f6f8fa; border:1px solid #e1e4e8; border-radius:10px; padding:14px 16px; }
</style></head>
<body>
  <h1>${display}</h1>
  <h2>ひとこと</h2>
  <div class="bio">${bio}</div>
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

// 検索。
//   脆弱: ?q をそのまま結果ページへ反射する(反射型XSSのシンク)。
//   対策: escapeHtml で文字列として埋め込む。
app.get('/sns/search', (c) => {
  const raw = c.req.query('q') ?? '';
  const defended = isDefended(c);
  let q: string;
  if (defended) {
    // ✅ 対策: 出力前に HTML エスケープ。<script> はただの文字列になる。
    q = escapeHtml(raw);
  } else {
    // ★ 脆弱: 入力をそのまま HTML に埋め込む。
    q = raw;
  }
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>「${q}」の検索結果 | つなぐ</title>
<style>body { font-family: sans-serif; padding:24px; max-width:640px; }</style></head>
<body>
  <h1>検索結果</h1>
  <p>「${q}」に一致する投稿は見つかりませんでした。</p>
  <form method="GET" action="/sns/search">
    <input name="q" value="${q}" placeholder="キーワード">
    ${defended ? '<input type="hidden" name="defense" value="1">' : ''}
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
// 対策の確認: 各エンドポイントに `?defense=1` を付けると対策済み実装に切り替わる。
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

type Member = { id: number; username: string; password: string; email: string; secret: string };

// 会員ログイン。
//   脆弱: 入力を SQL にそのまま連結。
//     username = admin'--  → パスワード条件がコメントアウトされ成りすまし。
//     username = ' OR '1'='1' --  → 全件ヒットの先頭として最初のユーザーでログイン。
//   対策: プレースホルダ(パラメータバインド)。入力は常に「データ」として扱われる。
app.post('/sns/login', async (c) => {
  const body = await c.req.parseBody();
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const mode = modeOf(c);

  let sql: string;
  let run: () => Member | undefined;
  if (mode === 'defended') {
    // ✅ 対策: 値は ? で別渡し。SQL 文の構造は入力で変わらない。
    sql = 'SELECT * FROM members WHERE username = ? AND password = ?';
    run = () => db.prepare(sql).get(username, password) as Member | undefined;
  } else {
    // ★ 脆弱: 入力をそのまま連結。入力次第で SQL 文の構造が書き換わる。
    sql = `SELECT * FROM members WHERE username = '${username}' AND password = '${password}'`;
    run = () => db.prepare(sql).get() as Member | undefined;
  }

  try {
    const row = run();
    if (row) {
      return c.json({ ok: true, mode, loggedInAs: row.username, sql });
    }
    return c.json({ ok: false, mode, sql }, 401);
  } catch (e) {
    // 注入で構文エラーになった場合でも、学習用に実行SQLとエラーを見せる。
    return c.json({ ok: false, mode, sql, error: String(e) }, 400);
  }
});

// 会員検索。
//   脆弱: ?name を SQL にそのまま連結。UNION でカラムを揃えて窃取できる。
//     name = ' UNION SELECT id, username || ':' || password, email, secret FROM members --
//   対策: プレースホルダ。上の name は「そういう名前の会員」として検索され 0 件になる。
app.get('/sns/members', (c) => {
  const name = c.req.query('name') ?? '';
  const mode = modeOf(c);

  let sql: string;
  let run: () => unknown[];
  if (mode === 'defended') {
    // ✅ 対策
    sql = 'SELECT id, username, email, secret FROM members WHERE username = ?';
    run = () => db.prepare(sql).all(name);
  } else {
    // ★ 脆弱
    sql = `SELECT id, username, email, secret FROM members WHERE username = '${name}'`;
    run = () => db.prepare(sql).all();
  }

  try {
    return c.json({ ok: true, mode, sql, rows: run() });
  } catch (e) {
    return c.json({ ok: false, mode, sql, error: String(e) }, 400);
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

// 管理者向け ping 診断。
//   脆弱: 入力を ping コマンド文字列へ連結して exec(シェル経由)。
//     host = 127.0.0.1; echo PWNED  →  ping のあとに echo も実行される。
//   対策: (1) ホスト名として妥当な文字だけ許可 (2) シェルを介さず execFile で引数配列として渡す。
app.get('/admin/net/ping', async (c) => {
  const host = c.req.query('host') ?? '127.0.0.1';
  const mode = modeOf(c);

  let cmd: string;
  let run: () => Promise<{ stdout: string; stderr: string }>;
  if (mode === 'defended') {
    // ✅ 対策1: 英数字・ドット・ハイフン以外を含む入力は拒否(許可リスト方式の入力検証)。
    if (!/^[A-Za-z0-9.-]+$/.test(host)) {
      return c.json({ ok: false, mode, error: 'invalid host' }, 400);
    }
    // ✅ 対策2: シェルを使わず引数配列で渡す。; や && はメタ文字として解釈されない。
    cmd = `execFile('ping', ['-c', '1', ${JSON.stringify(host)}])`;
    run = () => execFileAsync('ping', ['-c', '1', host], { timeout: 5000 });
  } else {
    // ★ 脆弱: シェル経由で実行するため ; && | ` などのメタ文字が効いてしまう。
    cmd = `ping -c 1 ${host}`;
    run = () => execAsync(cmd, { timeout: 5000 });
  }

  try {
    const { stdout, stderr } = await run();
    return c.json({ ok: true, mode, cmd, output: stdout + stderr });
  } catch (e) {
    // 実行自体が失敗(ping 不在や非ゼロ終了)でも、連結したコマンドの出力は得られる。
    const err = e as { stdout?: string; stderr?: string; message?: string };
    return c.json({
      ok: false,
      mode,
      cmd,
      output: (err.stdout ?? '') + (err.stderr ?? ''),
      error: err.message ?? String(e),
    });
  }
});

// ===========================================================================
// モジュール5: パストラバーサル (ディレクトリトラバーサル) ― 添付ファイル閲覧
// ---------------------------------------------------------------------------
// 実在事例: 2021年「CVE-2021-41773」(Apache HTTP Server 2.4.49)。URL の正規化不備で
//   `..%2f` を使ったパストラバーサルが可能になり、ドキュメントルート外のファイル閲覧や
//   (条件次第で)リモートコード実行まで引き起こした。古典の `../../etc/passwd` と同原理。
//
// 架空シナリオ (つなぐ):
//   投稿の「添付ファイル」を名前で取り出す機能が、公開ディレクトリ(uploads)に対して
//   入力ファイル名を join するだけで中身を返す。name = ../../../../etc/passwd のように
//   `../` を重ねると、公開ディレクトリの外のファイル(サーバの秘密)まで読めてしまう。
//
// 脆弱点: 入力ファイル名を検証せず join(UPLOAD_DIR, name) し、公開範囲の外へ出られる。
// ===========================================================================

// 公開してよい添付ファイルの置き場(ここ「だけ」を見せるつもりの設計)。
const UPLOAD_DIR = join(import.meta.dirname, 'uploads');

// 添付ファイル取得。
//   脆弱: 入力ファイル名を検証せず join するだけ。
//     name = welcome.txt            → 正常に添付を返す
//     name = ../../../../etc/passwd → 公開ディレクトリ外まで読めてしまう
//   対策: resolve 後のパスが公開ディレクトリ内に収まっているかを検証し、外なら拒否。
//     (あわせて name から '..' やパス区切りを弾くと多層防御になる)
app.get('/sns/files', async (c) => {
  const name = c.req.query('name') ?? 'welcome.txt';
  const mode = modeOf(c);
  let target: string;
  if (mode === 'defended') {
    // ✅ 対策: 正規化した最終パスが UPLOAD_DIR の内側かを確認する。
    target = resolve(UPLOAD_DIR, name);
    const rel = relative(UPLOAD_DIR, target);
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
      return c.json({ ok: false, mode, requested: name, error: 'invalid path' }, 400);
    }
  } else {
    // ★ 脆弱: 範囲チェックをしていないため `../` で外へ出られる。
    target = join(UPLOAD_DIR, name);
  }
  try {
    const content = await readFile(target, 'utf8');
    return c.text(content);
  } catch {
    return c.json({ ok: false, mode, requested: name, resolved: target, error: 'not found' }, 404);
  }
});

// ===========================================================================
// モジュール6: CSRF (クロスサイトリクエストフォージェリ) ― メールアドレス変更
// ---------------------------------------------------------------------------
// 実在事例: 2006年 Netflix の CSRF。ログイン中の利用者が攻撃者ページを開くだけで、
//   本人の意思と無関係に「配送先住所の変更」「レンタル希望リストへの追加」などが
//   勝手に実行された。状態を変える操作に CSRF 対策(トークン等)が無いために成立する。
//
// 架空シナリオ (つなぐ):
//   アカウントのメールアドレス変更が、ログイン状態だけを頼りに POST を受け付ける。
//   CSRFトークンも Origin/Referer 検査も無いため、攻撃者ページが用意した
//   自動送信フォームで「ログイン中の本人」のメールを攻撃者のものに書き換えられる。
//   メールを奪えればパスワード再設定からアカウント乗っ取りに繋がる。
//
// 脆弱点: 状態変更 POST に CSRF 対策(同期トークン / Origin 検査 / SameSite)が一切無い。
// ===========================================================================

// ログイン中ユーザーのアカウント状態(DB代わりのメモリ)。
let accountEmail = 'you@tsunagu.example';

// 対策の選択肢:
//   1) フォーム表示時に発行した同期トークンを照合する(未提示・不一致は必ず拒否)。
//      ※ この最小ラボはセッション/トークン発行を実装していないので、ここでは採用しない。
//        未発行どうしの `undefined !== undefined` で素通り(fail open)にならないよう注意。
//   2) Origin(無ければ Referer)が自分のサイトかを検査する。← `?defense=1` で有効になるのはこれ。
//   3) 併せて Cookie を SameSite=Lax/Strict にすると多層防御になる。
const SELF_HOSTS = new Set(['localhost:8080', '127.0.0.1:8080']);
const isSameOriginRequest = (c: Context): boolean => {
  const src = c.req.header('origin') ?? c.req.header('referer');
  // 送信元が分からないリクエストは拒否する(fail closed)。
  if (!src || src === 'null') return false;
  try {
    return SELF_HOSTS.has(new URL(src).host);
  } catch {
    return false;
  }
};

// アカウント設定の表示(現在のメールアドレス)。
app.get('/account', (c) => {
  return c.json({ loggedInAs: 'you', email: accountEmail });
});

// メールアドレス変更。
//   脆弱: CSRF トークンも Origin 検査も無い。他サイトの自動送信フォームからでも
//     ログイン中の本人として変更が通ってしまう。
//   対策: Origin/Referer が自サイトでなければ 403 で拒否。
app.post('/account/email', async (c) => {
  // ★ 脆弱: 既定では送信元を確認しない / ✅ 対策: 他サイト発のリクエストを拒否
  if (isDefended(c) && !isSameOriginRequest(c)) {
    return c.json({ ok: false, mode: 'defended', error: 'cross-site request rejected' }, 403);
  }
  const body = await c.req.parseBody();
  const email = typeof body.email === 'string' ? body.email : '';
  accountEmail = email;
  return c.html(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>メール変更完了</title></head>
<body style="font-family:sans-serif;padding:16px">
  <p>✅ 登録メールアドレスを <strong>${email}</strong> に変更しました。</p>
  <p><a href="/account">アカウント設定</a></p>
</body></html>`);
});

// CSRFシナリオのリセット。
app.post('/account/reset', (c) => {
  accountEmail = 'you@tsunagu.example';
  return c.json({ ok: true, email: accountEmail });
});

// ===========================================================================
// モジュール7: 認可制御の欠落 (IDOR / BOLA) ― ダイレクトメッセージ閲覧
// ---------------------------------------------------------------------------
// 実在事例: 2019年 First American Financial の情報漏えい。書類URLが連番IDで、
//   ログインも所有者チェックも無かったため、ID を増減するだけで他人の
//   不動産取引書類(社会保障番号や銀行口座など)約8.85億件が誰でも閲覧できた。
//   「本人のものかを確認し忘れた(認可制御の欠落 / IDOR・BOLA)」典型例。
//
// 架空シナリオ (つなぐ):
//   ダイレクトメッセージ(DM)が連番IDで取得でき、取得時に「そのDMが本当に
//   リクエスト元ユーザーのものか」を確認していない。ID を 1,2,3... と変えるだけで
//   他人の非公開DM(口座番号や管理者パスワード等)が読めてしまう。
//
//   ※ ログイン中ユーザーは学習用に X-User ヘッダで表現する(既定 you)。
// 脆弱点: 一覧は owner で絞っているのに、個別取得が owner 照合を忘れている。
// ===========================================================================

type DirectMessage = { id: number; owner: string; peer: string; body: string };
const messages: DirectMessage[] = [
  { id: 1, owner: 'you', peer: 'samy', body: '明日の打ち合わせ、10時で大丈夫です' },
  { id: 2, owner: 'samy', peer: 'admin', body: '例のサーバの鍵は kagi-7788。内緒で' },
  { id: 3, owner: 'admin', peer: 'ceo', body: '管理者パスワードの一時値: Adm!n-tmp-0001' },
  { id: 4, owner: 'you', peer: 'admin', body: '経費精算、提出しました' },
];

// リクエスト元(ログイン中)ユーザー。学習用に X-User ヘッダで切り替える(既定 you)。
const currentUser = (c: { req: { header: (k: string) => string | undefined } }): string =>
  c.req.header('x-user') ?? 'you';

// 自分のDM一覧。こちらは owner で正しく絞っている(対比用)。
app.get('/api/messages', (c) => {
  const me = currentUser(c);
  const mine = messages.filter((m) => m.owner === me);
  return c.json({ ok: true, user: me, messages: mine });
});

// DM 個別取得。
//   脆弱: owner 照合を忘れている(認可制御の欠落 = IDOR/BOLA)。
//     X-User: you のまま id=2,3 を叩くと、他人の非公開DMが読めてしまう。
//   対策: 取得したDMの owner がリクエスト元ユーザーと一致するかを毎回サーバ側で確認する。
app.get('/api/messages/:id', (c) => {
  const id = Number(c.req.param('id'));
  const mode = modeOf(c);
  const msg = messages.find((m) => m.id === id);
  if (!msg) return c.json({ ok: false, mode, error: 'not found' }, 404);
  // ★ 脆弱: 既定では所有者を確認しない / ✅ 対策: 本人のもの以外は拒否
  if (mode === 'defended' && msg.owner !== currentUser(c)) {
    return c.json({ ok: false, mode, error: 'forbidden' }, 403);
  }
  return c.json({ ok: true, mode, requestedBy: currentUser(c), message: msg });
});
