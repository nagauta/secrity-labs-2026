// ============================================================================
// attacker/serve.ts  ―  おとりページ配信サーバ (TypeScript / 外部依存なし)
// ----------------------------------------------------------------------------
// evil.html を静的配信するだけの最小サーバ。Node標準モジュール + tsx のみ。
// ※ 教育目的。ローカル隔離ラボ内でのみ使用すること。
// ============================================================================

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const port = 9090;

// パスごとに配信するおとりページ (パストラバーサル回避のため既知ファイルのみ許可)
const routes: Record<string, string> = {
  '/': 'evil.html',                 // クリックジャッキング(銀行)シナリオ
  '/evil.html': 'evil.html',
  '/sns': 'evil-sns.html',          // ライクジャッキング(架空SNS)シナリオ
  '/evil-sns.html': 'evil-sns.html',
};

const server = createServer(async (req, res) => {
  try {
    const path = (req.url ?? '/').split('?')[0];
    const file = routes[path] ?? 'evil.html';
    const html = await readFile(join(__dirname, file));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('server error: ' + message);
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`[attacker] listening on http://0.0.0.0:${port}`);
});
