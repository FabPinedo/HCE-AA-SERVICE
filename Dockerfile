# Dockerfile — auth-pruebas-auth (Auth Service)
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS production
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S nestjs && adduser -S nestjs -G nestjs
COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist
EXPOSE 10101
USER nestjs
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:10101/auth/health || exit 1
CMD ["node", "dist/main"]
