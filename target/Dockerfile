FROM node:22-slim

WORKDIR /app

# better-sqlite3(ネイティブモジュール)のプリビルドバイナリが glibc 前提のため、
# alpine(musl)ではなく slim(Debian/glibc)を使う。これでビルド工具なしで入る。

# 依存だけ先に入れてレイヤキャッシュを効かせる (tsx でTSを直接実行するため全依存を入れる)
COPY package.json ./
RUN npm install

COPY tsconfig.json server.ts app.ts ./

EXPOSE 8080
CMD ["npm", "start"]
