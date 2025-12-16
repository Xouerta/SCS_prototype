# 使用轻量级 Node 镜像
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 安装 nodemon 实现热更新 (全局安装)
RUN npm install -g nodemon

# 先复制 package.json (利用 Docker 缓存机制加速构建)
COPY package.json package-lock.json* ./

# 安装依赖
RUN npm install

# 复制其余代码 (虽然会被 docker-compose 的 volume 覆盖，但这是标准做法)
COPY . .

# 暴露端口
EXPOSE 3000

# 启动命令 (会被 docker-compose 覆盖，这里只是兜底)
CMD ["npm", "run", "dev"]
