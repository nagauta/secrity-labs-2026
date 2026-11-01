// ============================================================================
// CSRF (クロスサイトリクエストフォージェリ) モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」= 状態変更 POST に CSRF 対策が無いため、トークン無し・他サイト
// Origin の偽造リクエストでもメール変更が通ることを固定する。対策を入れると落ちる想定。
// 実在事例: 2006年 Netflix の CSRF(アカウント設定の勝手な変更)。
// ============================================================================

import { describe, expect, it } from 'vitest';
import { app } from '../app';

const formPost = (
  path: string,
  data: Record<string, string>,
  headers: Record<string, string> = {},
) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(data).toString(),
  });

describe('CSRF (/account/email)', () => {
  it('CSRFトークン無しのフォーム POST でメールアドレスが変更できてしまう(脆弱性)', async () => {
    await app.request('/account/reset', { method: 'POST' });
    const res = await formPost('/account/email', { email: 'attacker@evil.example' });
    expect(res.status).toBe(200);

    const account = (await (await app.request('/account')).json()) as { email: string };
    expect(account.email).toBe('attacker@evil.example');
  });

  it('攻撃者サイトの Origin から送られても拒否されない(Origin 検査が無い)', async () => {
    await app.request('/account/reset', { method: 'POST' });
    const res = await formPost(
      '/account/email',
      { email: 'takeover@evil.example' },
      { origin: 'http://evil.example', referer: 'http://evil.example/evil-csrf.html' },
    );
    expect(res.status).toBe(200);

    const account = (await (await app.request('/account')).json()) as { email: string };
    // 他サイト由来でも変更が通る = CSRF 脆弱。
    expect(account.email).toBe('takeover@evil.example');
  });

  it('/account/reset で既定メールへ戻る', async () => {
    await formPost('/account/email', { email: 'temp@evil.example' });
    const res = await app.request('/account/reset', { method: 'POST' });
    const json = (await res.json()) as { ok: boolean; email: string };
    expect(json.ok).toBe(true);
    expect(json.email).toBe('you@tsunagu.example');
  });
});
