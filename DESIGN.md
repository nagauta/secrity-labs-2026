# セキュリティ学習ラボ 設計ドキュメント (secrity-labs-2026)

## 1. 目的

IPA「安全なウェブサイトの作り方」で解説される主要な脆弱性を、
**インターネットから隔離された Docker 環境** で再現する。
攻撃の仕組みを手を動かして理解し、同時に「どう直すか」も学ぶための教材。

参考: https://www.ipa.go.jp/security/vuln/websecurity/about.html

## 2. 安全のための大前提

- **ローカル隔離**: 公開ポートは `127.0.0.1` のみにバインドし、外部ネットワークへ出さない。
- **教育目的のみ**: 意図的に脆弱なアプリ。本番や公開サーバには絶対に置かない。
- **自分の環境だけが対象**: ラボ内の自分のコンテナ以外を攻撃する用途には使わない。
- DVWA / OWASP WebGoat / Juice Shop と同じカテゴリの、定番の学習用やられアプリ。

## 3. 設計方針: とにかく簡単に

- 実装は **Node.js + Hono**（target）。コードを読めば脆弱性がすぐ分かる素朴な書き方。
- コンテナは **2つ**: `target`（やられ役Web）と `attacker`（攻撃用ページを配信）。
- 対策は **コード内コメント + README** で提示する（脆弱コードはそのまま残す）。
- 可能なモジュールでは **`?defense=1` で対策済み実装に切り替え**られるようにし、同じペイロードを
  脆弱/対策済みで撃ち比べられるようにする（脆弱版と対策版は同じハンドラ内に並べて読み比べやすくする）。
  既定（フラグなし）は常に脆弱版。全モジュールで実装済み。各攻撃デモの「🛡 対策を有効化」トグルが
  このフラグを付け外しする。
- 1つの脆弱性ずつ、動くものを作ってから次へ進む。

## 4. 実装順（決定事項）

いずれも実在事例を名指しで引き、そこから架空SNS「つなぐ」のシナリオを作る方針。

0. **CI / Lint / テスト基盤** ← 実装済み
   - GitHub Actions（`.github/workflows/ci.yml`）で Biome（lint/format）と Vitest を実行。
   - 各モジュールは Vitest で「脆弱であること」を固定し、テストが通ったらマージする。
1. **クリックジャッキング（ライクジャッキング）** ← 実装済み（Facebook ライクジャッキング 2010）
   - 「いいね」ボタンを透明で重ねて乗っ取る（`/sns/widget` + `evil-sns.html`）
2. **XSS** ← 実装済み（MySpace Samy ワーム 2005）: `/sns/users/:name`・`/sns/search` + `evil-xss.html`
3. **SQLインジェクション** ← 実装済み（Sony Pictures 2011）: `/sns/login`・`/sns/members` + `evil-sqli.html`
4. **OSコマンドインジェクション** ← 実装済み（Shellshock 2014）: `/admin/net/ping` + `evil-oscmd.html`
5. **パストラバーサル** ← 実装済み（Apache CVE-2021-41773）: `/sns/files` + `evil-pathtrav.html`
6. **CSRF** ← 実装済み（Netflix 2006）: `/account/email` + `evil-csrf.html`
7. **認可制御の欠落（IDOR/BOLA）** ← 実装済み（First American Financial 2019）: `/api/messages/:id` + `evil-authz.html`

## 5. モジュール1: クリックジャッキング（ライクジャッキング）

### 攻撃の筋書き
攻撃者のおとりページ（「衝撃映像」の餌）が、標的SNSの **いいねボタンを透明な iframe** で
「▶ 再生する」ボタンの裏に重ねる。利用者は再生を押したつもりで、実際には
**ログイン中の本人として拡散投稿に「いいね」** してしまい、それが本人のタイムラインに
流れて友達へ拡散する。2010年に Facebook で流行したライクジャッキングの再現。

### アーキテクチャ
```
       ┌──────────────── 利用者のブラウザ ─────────────────┐
       │   http://localhost:9090/  (attacker のおとりページ)  │
       │     └ 透明 iframe → http://localhost:8080/sns/widget  │
       └─────────────────────────────────────────────────────┘
            │                              │
   ┌────────▼──────────┐        ┌──────────▼──────────────────┐
   │ attacker:9090     │        │ target:8080 (Hono)           │
   │ evil-sns.html 配信│        │ /sns/widget に「いいね」ボタン │
   └───────────────────┘        │ ★フレーム化禁止ヘッダ無し     │
                                └──────────────────────────────┘
       どちらも 127.0.0.1 のみ公開 / docker network: labnet
```

### 脆弱ポイント
`target` の `/sns/widget` が `X-Frame-Options` も `Content-Security-Policy: frame-ancestors` も返さない
→ 任意のサイトから iframe 埋め込み可能。

### 対策（`?defense=1` で有効化 / README・コメントで解説）
次のどちらかを付与すると iframe 埋め込みを拒否でき、攻撃が成立しなくなる:
- `X-Frame-Options: DENY`
- `Content-Security-Policy: frame-ancestors 'none'`

## 6. ディレクトリ構成

```
secrity-labs-2026/
├── DESIGN.md
├── README.md
├── docker-compose.yml
├── target/            ← Hono製の脆弱Webアプリ（TypeScript / tsx 実行）
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   └── server.ts
└── attacker/          ← ラボ配信（Node標準モジュールのみ / tsx 実行）
    ├── Dockerfile
    ├── package.json
    ├── tsconfig.json
    ├── serve.ts       ← 同ディレクトリの .html を配信（"/" は index.html）
    ├── index.html     ← ラボのシェル。左サイドバーから攻撃の種類を選ぶ
    └── evil-sns.html  ← ライクジャッキング（架空SNS「つなぐ」）。トグルで可視化＋狙い解説
```

※ 新しい攻撃デモは `attacker/<name>.html` を置き、`index.html` の `MODULES` 配列に
   `{ status:'ready', src:'<name>.html' }` を追加するだけでサイドバーに載る。

※ 実装言語は TypeScript。target は Hono、attacker は依存ライブラリなしの
   Node 標準モジュールで、どちらも `tsx` で TS を直接実行する。

## 7. 学習フロー（ライクジャッキング）

1. `docker compose up` で両方起動。
2. ブラウザで `http://localhost:9090/` を開く → おとりページ（「衝撃映像」の餌）。
3. 「▶ 再生する」を押す → 実は標的SNSの「いいね」が本人として実行される。
4. `http://localhost:8080/sns` で、押した覚えのない投稿がいいね済みなことを確認する。
5. `target/app.ts` の `/sns/widget` を読み、ヘッダが無いことを確認する。
6. 「🛡 対策を有効化」をオン（`?defense=1`）→ 同じ攻撃が失敗することを確認する。

---
（クリックジャッキング／ライクジャッキングを実装済み。以降のモジュールはこの枠組みを踏襲して追加）
