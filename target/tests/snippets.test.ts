// ============================================================================
// ラボ画面右ペインのコード片(attacker/snippets.js)が target/app.ts とずれていないかの検査
// ----------------------------------------------------------------------------
// snippets.js は app.ts から要点の行を手で抜き出したもの。ここでは
//   「コード片の各行(前後の空白を除く)が app.ts のどこかの行と完全一致すること」
// を確認する。app.ts だけ直してコード片を直し忘れると、このテストが落ちる。
// `//` で始まる行と空行は注記扱いで検査しない。
// ============================================================================

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';

type Snippet = { where: string; point: string; vuln: string[]; defense: string[] };

const root = join(import.meta.dirname, '..', '..');
const appLines = new Set(
  readFileSync(join(root, 'target', 'app.ts'), 'utf8')
    .split('\n')
    .map((l) => l.trim()),
);
const sandbox: { window: { LAB_SNIPPETS?: Record<string, Snippet> } } = { window: {} };
runInNewContext(readFileSync(join(root, 'attacker', 'snippets.js'), 'utf8'), sandbox);
const snippets = sandbox.window.LAB_SNIPPETS ?? {};

// ラボ画面(index.html)の MODULES の id と揃っていること。
const moduleIds = [
  ...readFileSync(join(root, 'attacker', 'index.html'), 'utf8').matchAll(/\{ id: '([a-z]+)'/g),
].map((m) => m[1]);

const codeLines = (lines: string[]) =>
  lines.map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('//'));

describe('attacker/snippets.js', () => {
  it('ラボ画面の全モジュール分のコード片がある', () => {
    expect(moduleIds.length).toBeGreaterThan(0);
    expect(Object.keys(snippets).sort()).toEqual([...moduleIds].sort());
  });

  for (const [id, s] of Object.entries(snippets)) {
    for (const side of ['vuln', 'defense'] as const) {
      it(`${id} の ${side} の各行が app.ts にそのまま存在する`, () => {
        const lines = codeLines(s[side]);
        expect(lines.length).toBeGreaterThan(0);
        const missing = lines.filter((l) => !appLines.has(l));
        expect(missing).toEqual([]);
      });
    }
  }
});
