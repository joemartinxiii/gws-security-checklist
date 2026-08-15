FROM node:24-slim AS builder

WORKDIR /app

ENV NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_LOGLEVEL=error

COPY package*.json ./
COPY backend/package*.json ./backend/
COPY frontend/package*.json ./frontend/

RUN npm install

COPY . .

ENV VITE_USE_MSW=false
RUN npm run build

FROM node:24-slim

WORKDIR /app

ENV NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_LOGLEVEL=error

COPY --from=builder /app/frontend/dist ./frontend/dist
COPY --from=builder /app/backend/dist ./backend/dist
COPY --from=builder /app/backend/package.json ./backend/

RUN cd backend && npm install --omit=dev --legacy-peer-deps

RUN groupadd --gid 1001 nodejs && \
    useradd --uid 1001 --gid nodejs --no-create-home nodejs

RUN chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 8080
ENV NODE_ENV=production
ENV PORT=8080

CMD ["node", "backend/dist/index.js"]
