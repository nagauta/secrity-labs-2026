// ============================================================================
// 認可制御の欠落 (IDOR / BOLA) モジュールのテスト
// ----------------------------------------------------------------------------
// 「脆弱であること」= DM 個別取得が所有者チェックを欠くため、連番IDを変えるだけで
// 他人の非公開DMが読めることを固定する。対策(owner 照合)を入れると落ちる想定。
// 実在事例: 2019年 First American Financial(連番IDで他人の書類が無認可閲覧)。
// ============================================================================

import { describe, expect, it } from 'vitest';
import { app } from '../app';

// ログイン中ユーザー you として取得する。
const asYou = (path: string) => app.request(path, { headers: { 'x-user': 'you' } });

describe('認可制御の欠落 (/api/messages/:id)', () => {
  it('自分のDMは取得できる(正常系)', async () => {
    const res = await asYou('/api/messages/1');
    expect(res.status).toBe(200);
    const json = (await res.json()) as { message: { owner: string; body: string } };
    expect(json.message.owner).toBe('you');
    expect(json.message.body).toContain('打ち合わせ');
  });

  it('一覧 API は owner で正しく絞られている(対比: ここは認可できている)', async () => {
    const res = await asYou('/api/messages');
    const json = (await res.json()) as { messages: Array<{ owner: string }> };
    // you のDM(id=1,4)だけが返る。
    expect(json.messages.every((m) => m.owner === 'you')).toBe(true);
    expect(json.messages).toHaveLength(2);
  });

  it('id を変えるだけで他人(samy)の非公開DMが読める(IDOR 脆弱性)', async () => {
    const res = await asYou('/api/messages/2');
    expect(res.status).toBe(200);
    const json = (await res.json()) as { message: { owner: string; body: string } };
    // 本来 you は見られないはずの samy のDMが漏れている。
    expect(json.message.owner).toBe('samy');
    expect(json.message.body).toContain('kagi-7788');
  });

  it('連番の総当たりで全ユーザーの非公開DMを収集できる', async () => {
    const leaked: string[] = [];
    for (let id = 1; id <= 4; id++) {
      const res = await asYou(`/api/messages/${id}`);
      if (res.status === 200) {
        const json = (await res.json()) as { message: { owner: string; body: string } };
        if (json.message.owner !== 'you') leaked.push(json.message.body);
      }
    }
    // 他人(samy, admin)のDMが you の手で収集できてしまう。
    expect(leaked.join('\n')).toContain('kagi-7788');
    expect(leaked.join('\n')).toContain('Adm!n-tmp-0001');
  });

  it('存在しない id は 404', async () => {
    const res = await asYou('/api/messages/999');
    expect(res.status).toBe(404);
  });

  // DMビューアは別オリジン(9090)から 8080 の API を fetch する。CORS応答が無いと
  // ブラウザが結果の読み取りをブロックし "TypeError: Failed to fetch" になる。
  // ここでCORS応答を固定し、ブラウザからの体験が壊れない(= 回帰しない)ことを担保する。
  it('API応答にCORS許可ヘッダが付く(別オリジンのブラウザから読める)', async () => {
    const res = await asYou('/api/messages/2');
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('プリフライト(OPTIONS)に X-User を許可して応答する', async () => {
    const res = await app.request('/api/messages/2', {
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:9090',
        'access-control-request-method': 'GET',
        'access-control-request-headers': 'x-user',
      },
    });
    expect(res.status).toBeLessThan(300);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect((res.headers.get('access-control-allow-headers') ?? '').toLowerCase()).toContain(
      'x-user',
    );
  });
});
