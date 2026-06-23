#!/usr/bin/env bash
# Render build script for SentinelAI
set -euo pipefail

echo "=== SentinelAI Build ==="

# ── 1. Build Frontend (Next.js static export) ──
echo "→ Building frontend..."
cd sentinelai-ui
npm ci
npm run build
cd ..

# ── 2. Copy static export into backend's static dir ──
echo "→ Copying frontend build to backend..."
mkdir -p app/static
rm -rf app/static/*
cp -r sentinelai-ui/out/* app/static/

echo "=== Build complete ==="
