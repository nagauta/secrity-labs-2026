// ============================================================================
// attacker/serve.ts  ―  ラボ配信サーバ (TypeScript / 外部依存なし)
// ----------------------------------------------------------------------------
// ラボのシェル(index.html)と各攻撃デモの .html を静的配信する最小サーバ。
// Node標準モジュール + tsx のみ。※ 教育目的。ローカル隔離ラボ内でのみ使用。
// ============================================================================

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const port = 9090;

// 同ディレクトリの .html だけを配信する。新しい攻撃デモは .html を置くだけで増やせる。
//   "/" は index.html(サイドバー付きシェル)。パストラバーサルはファイル名検査で防ぐ。
const server = createServer(async (req, res) => {
  try {
    const path = (req.url ?? '/').split('?')[0];
    const name = path === '/' ? 'index.html' : path.replace(/^\/+/, '');
    // 許可するのは「英数字・ハイフン・アンダースコアの .html」単一ファイル名のみ。
    if (!/^[A-Za-z0-9_-]+\.html$/.test(name)) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('not found');
      return;
    }
    const html = await readFile(join(__dirname, name));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found');
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`[attacker] listening on http://0.0.0.0:${port}`);
});
