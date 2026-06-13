# ─── RAXC WebSocket Server Dockerfile ──────────────────────────────────────────
# Build: docker build -t raxc-ws-server .
# Run:   docker run -p 3001:3001 --env-file .env raxc-ws-server

FROM oven/bun:1-alpine AS base
WORKDIR /app

# ─── Dependencies layer (cached unless package.json changes) ──────────────────
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# ─── Source layer ─────────────────────────────────────────────────────────────
COPY tsconfig.json ./
COPY src/ ./src/

# ─── Runtime ──────────────────────────────────────────────────────────────────
ENV NODE_ENV=production
ENV WS_PORT=3001

EXPOSE 3001

# Use bun to run TypeScript directly (no build step needed)
CMD ["bun", "run", "src/bin/ws-server.ts"]
