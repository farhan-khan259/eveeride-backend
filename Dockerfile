FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN npm ci --omit=dev --workspace backend && mkdir -p /app/backend/uploads && chown -R node:node /app
COPY --chown=node:node backend/src backend/src
USER node
WORKDIR /app/backend
ENV NODE_ENV=production PORT=4000 UPLOAD_DIR=/app/backend/uploads
EXPOSE 4000
CMD ["node", "src/server.js"]
