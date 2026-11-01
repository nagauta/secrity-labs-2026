// ============================================================================
// パストラバーサル (ディレクトリトラバーサル) モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」= 入力ファイル名を検証せず join するため、公開ディレクトリの外の
// ファイルまで読めることを固定する。対策(resolve 後の範囲チェック)で落ちる想定。
// 実在事例: 2021年 CVE-2021-41773 (Apache HTTP Server のパストラバーサル)。
// ============================================================================

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { app } from '../app';

describe('パストラバーサル (/sns/files)', () => {
  it('公開ディレクトリ内の添付は正常に取得できる(正常系)', async () => {
    const res = await app.request('/sns/files?name=welcome.txt');
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('つなぐへようこそ');
  });

  it('../ を重ねると公開ディレクトリ外の /etc/hostname が読める(脆弱性)', async () => {
    const expected = readFileSync('/etc/hostname', 'utf8').trim();
    // `../` はルートで頭打ちになる(それ以上は無視される)ので、作業ディレクトリの
    // 深さに依存しないよう十分な数を重ねて確実にルートまで遡る。
    const res = await app.request(`/sns/files?name=${'../'.repeat(12)}etc/hostname`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain(expected);
  });

  it('アプリ自身の package.json も公開範囲外から読み出せてしまう', async () => {
    // uploads の 1つ上(= target/)の package.json を読む。
    const res = await app.request('/sns/files?name=../package.json');
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('"better-sqlite3"');
  });

  it('存在しないファイルは 404', async () => {
    const res = await app.request('/sns/files?name=no-such-file.txt');
    expect(res.status).toBe(404);
  });
});
