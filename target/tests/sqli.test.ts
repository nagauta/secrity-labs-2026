// ============================================================================
// SQLインジェクション モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」= 入力を SQL に連結しているため、認証バイパスと UNION による
// データ窃取が成立することを固定する。あわせて `?defense=1`(対策済み実装)では
// 同じペイロードが無効化されることも確認する。
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

describe('SQLi - 対策済み(?defense=1)', () => {
  it('正しい資格情報なら対策済みでもログインできる', async () => {
    const res = await app.request(
      '/sns/login?defense=1',
      form({ username: 'you', password: 'password123' }),
    );
    const json = (await res.json()) as { ok: boolean; mode: string; loggedInAs?: string };
    expect(res.status).toBe(200);
    expect(json.mode).toBe('defended');
    expect(json.loggedInAs).toBe('you');
  });

  it.each(["admin'--", "' OR '1'='1' --"])('%s では認証バイパスできない', async (username) => {
    const res = await app.request('/sns/login?defense=1', form({ username, password: 'nope' }));
    const json = (await res.json()) as { ok: boolean; mode: string; sql: string };
    expect(res.status).toBe(401);
    expect(json.ok).toBe(false);
    expect(json.mode).toBe('defended');
    // 実行 SQL に入力値は埋め込まれていない(プレースホルダのまま)。
    expect(json.sql).toContain('?');
    expect(json.sql).not.toContain(username);
  });

  it('UNION を注入しても何も漏れない(ただの名前として検索され 0 件)', async () => {
    const payload = "' UNION SELECT id, username || ':' || password, email, secret FROM members --";
    const res = await app.request(`/sns/members?defense=1&name=${encodeURIComponent(payload)}`);
    const json = (await res.json()) as { ok: boolean; mode: string; rows: unknown[] };
    expect(res.status).toBe(200);
    expect(json.mode).toBe('defended');
    expect(json.rows).toHaveLength(0);
    const text = JSON.stringify(json);
    expect(text).not.toContain('password123');
    expect(text).not.toContain('S0ny-pwn3d!');
  });

  it('通常の検索は対策済みでも同じ結果を返す', async () => {
    const res = await app.request('/sns/members?defense=1&name=you');
    const json = (await res.json()) as { rows: Array<{ username: string }> };
    expect(json.rows).toHaveLength(1);
    expect(json.rows[0].username).toBe('you');
  });
});
