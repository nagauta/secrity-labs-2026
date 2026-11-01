// ============================================================================
// target/server.ts  ―  やられ役Webアプリの起動エントリ
// ----------------------------------------------------------------------------
// アプリ本体(ルート定義)は app.ts にある。ここでは listen するだけ。
// Vitest からは app.ts の `app` を直接 import してテストする(listen 不要)。
// ============================================================================

import { serve } from '@hono/node-server';
import { app } from './app';

const port = Number(process.env.PORT ?? 8080);
serve({ fetch: app.fetch, port, hostname: '0.0.0.0' }, (info) => {
  // コンテナ内は 0.0.0.0 で待受。外部公開は docker-compose 側で 127.0.0.1 に限定する。
  console.log(`[target] listening on http://0.0.0.0:${info.port}`);
});
