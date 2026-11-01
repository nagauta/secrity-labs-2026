FROM node:22-slim

WORKDIR /app

# ネットワーク診断(ping)ツールのデモ用に iputils-ping を入れておく
# (OSコマンドインジェクションのモジュールで使用)。
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
  && rm -rf /var/lib/apt/lists/*

# better-sqlite3(ネイティブモジュール)のプリビルドバイナリが glibc 前提のため、
# alpine(musl)ではなく slim(Debian/glibc)を使う。これでビルド工具なしで入る。

# 依存だけ先に入れてレイヤキャッシュを効かせる (tsx でTSを直接実行するため全依存を入れる)
COPY package.json ./
RUN npm install

COPY tsconfig.json server.ts app.ts ./
# 添付ファイル機能(パストラバーサルのモジュール)の公開ディレクトリ。
COPY uploads ./uploads

EXPOSE 8080
CMD ["npm", "start"]
