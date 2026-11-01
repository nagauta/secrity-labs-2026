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

import { Hono } from 'hono';

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
