// ============================================================================
// クリックジャッキング / ライクジャッキング モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」をテストで固定する。つまり /sns/widget がフレーム化禁止
// ヘッダ(X-Frame-Options / CSP frame-ancestors)を返さないことを確認する。
// 対策(app.ts 冒頭の app.use(...) 有効化)を入れるとこのテストは落ちる想定で、
// 「対策すると攻撃が成立しなくなる」= テストが脆弱性の有無のセンサーになる。
// ============================================================================

import { describe, expect, it } from 'vitest';
import { app } from '../app';

describe('clickjacking / likejacking', () => {
  it('/sns/widget はフレーム化禁止ヘッダを返さない(=任意サイトが iframe で重ねられる脆弱性)', async () => {
    const res = await app.request('/sns/widget?title=test');
    expect(res.status).toBe(200);
    // 脆弱点: これらのヘッダが「無い」ことが攻撃成立の条件。
    expect(res.headers.get('x-frame-options')).toBeNull();
    expect(res.headers.get('content-security-policy')).toBeNull();
  });

  it('/sns/widget は ?title をそのまま埋め込みウィジェットに表示する', async () => {
    const res = await app.request('/sns/widget?title=%E6%8B%A1%E6%95%A3%E6%8A%95%E7%A8%BF');
    const html = await res.text();
    expect(html).toContain('拡散投稿');
    expect(html).toContain('いいね！');
  });

  it('/sns/like は確認なしでいいねを記録し、本人のタイムラインに流れる', async () => {
    await app.request('/sns/reset', { method: 'POST' });

    const res = await app.request('/sns/like', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ title: '【拡散中】絶対見て！衝撃映像' }).toString(),
    });
    expect(res.status).toBe(200);

    const sns = await app.request('/sns');
    const html = await sns.text();
    expect(html).toContain('【拡散中】絶対見て！衝撃映像');
  });

  it('/sns/reset でタイムラインを初期化できる', async () => {
    await app.request('/sns/like', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ title: 'ゴミ' }).toString(),
    });
    const res = await app.request('/sns/reset', { method: 'POST' });
    const json = (await res.json()) as { ok: boolean; likedFeed: string[] };
    expect(json.ok).toBe(true);
    expect(json.likedFeed).toEqual([]);
  });
});
