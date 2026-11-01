FROM node:22-alpine

WORKDIR /app

# tsx でTSを直接実行するため依存を入れる
COPY package.json ./
RUN npm install

COPY tsconfig.json serve.ts evil-sns.html ./

EXPOSE 9090
CMD ["npm", "start"]
