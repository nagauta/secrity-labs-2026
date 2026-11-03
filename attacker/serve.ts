// ============================================================================
// attacker/serve.ts  ―  ラボ配信サーバ (TypeScript / 外部依存なし)
// ----------------------------------------------------------------------------
// ラボのシェル(index.html)と各攻撃デモの .html を静的配信する最小サーバ。
// Node標準モジュール + tsx のみ。※ 教育目的。ローカル隔離ラボ内でのみ使用。
// ============================================================================

import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const port = 9090;

// 同ディレクトリの .html と .js(ラボ画面のコード片 snippets.js 等)だけを配信する。
//   新しい攻撃デモは .html を置くだけで増やせる。
//   "/" は index.html(サイドバー付きシェル)。パストラバーサルはファイル名検査で防ぐ。
const TYPES: Record<string, string> = {
  html: 'text/html; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
};

const server = createServer(async (req, res) => {
  try {
    const path = (req.url ?? '/').split('?')[0];
    const name = path === '/' ? 'index.html' : path.replace(/^\/+/, '');
    // 許可するのは「英数字・ハイフン・アンダースコアの .html / .js」単一ファイル名のみ。
    const m = /^[A-Za-z0-9_-]+\.(html|js)$/.exec(name);
    if (!m) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('not found');
      return;
    }
    const body = await readFile(join(__dirname, name));
    res.writeHead(200, { 'Content-Type': TYPES[m[1]] });
    res.end(body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found');
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`[attacker] listening on http://0.0.0.0:${port}`);
});
