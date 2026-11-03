// ============================================================================
// OSコマンドインジェクション モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」= 入力をシェルコマンドに連結しているため、ping 以外の任意コマンドが
// 実行されることを固定する。対策(execFile + 入力検証)を入れると落ちる想定。
// 実在事例: 2014年 Shellshock(Web入力が最終的にシェルへ渡る典型)。
// ============================================================================

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { app } from '../app';

describe('OSコマンドインジェクション (/admin/net/ping)', () => {
  it('; で連結した echo が実行され、出力に現れる(任意コマンド実行=脆弱)', async () => {
    const host = '127.0.0.1; echo PWNED-OSCMD-INJECTION';
    const res = await app.request(`/admin/net/ping?host=${encodeURIComponent(host)}`);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { cmd: string; output: string };
    // ping の成否に関係なく、連結した echo の出力が得られてしまう。
    expect(json.output).toContain('PWNED-OSCMD-INJECTION');
  });

  it('算術展開 $((...)) が効く = シェルが入力を解釈している', async () => {
    // ; で連結(ping の成否に依存しない)。算術展開が効けば 42321 が出る。
    const host = '127.0.0.1; echo MARKER-$((40000+2000+300+21))';
    const res = await app.request(`/admin/net/ping?host=${encodeURIComponent(host)}`);
    const json = (await res.json()) as { output: string };
    expect(json.output).toContain('MARKER-42321');
  });

  it('機密ファイルの読み出し(; cat)も通ってしまう', async () => {
    // テスト用の擬似機密として、確実に存在する /etc/hostname を読む。
    const expected = readFileSync('/etc/hostname', 'utf8').trim();
    const host = '127.0.0.1; cat /etc/hostname';
    const res = await app.request(`/admin/net/ping?host=${encodeURIComponent(host)}`);
    const json = (await res.json()) as { output: string };
    // cat が実行され、/etc/hostname の中身が応答に漏れている。
    expect(json.output).toContain(expected);
  });

  it('組み立てたコマンド文字列に入力がそのまま連結されている', async () => {
    const res = await app.request('/admin/net/ping?host=127.0.0.1');
    const json = (await res.json()) as { cmd: string };
    expect(json.cmd).toBe('ping -c 1 127.0.0.1');
  });
});

describe('OSコマンドインジェクション - 対策済み(?defense=1)', () => {
  it.each([
    '127.0.0.1; echo PWNED-OSCMD-INJECTION',
    '127.0.0.1 && echo PWNED',
    '127.0.0.1 | id',
    '$(id)',
    '`id`',
  ])('%s は入力検証で拒否され、コマンドは実行されない', async (host) => {
    const res = await app.request(`/admin/net/ping?defense=1&host=${encodeURIComponent(host)}`);
    expect(res.status).toBe(400);
    const json = (await res.json()) as { ok: boolean; mode: string; output?: string };
    expect(json.ok).toBe(false);
    expect(json.mode).toBe('defended');
    expect(json.output).toBeUndefined();
  });

  it('正しいホスト名はシェルを介さず execFile で実行される', async () => {
    const res = await app.request('/admin/net/ping?defense=1&host=127.0.0.1');
    const json = (await res.json()) as { mode: string; cmd: string };
    expect(json.mode).toBe('defended');
    expect(json.cmd).toBe(`execFile('ping', ['-c', '1', "127.0.0.1"])`);
  });
});
