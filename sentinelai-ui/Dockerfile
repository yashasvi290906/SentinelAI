FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Build
COPY . .
RUN npm run build

# Production stage - serve static export with npx serve
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Install serve globally
RUN npm install -g serve

# Copy built static export
COPY --from=builder /app/out ./out

EXPOSE 3000

CMD ["serve", "-s", "out", "-l", "3000"]
