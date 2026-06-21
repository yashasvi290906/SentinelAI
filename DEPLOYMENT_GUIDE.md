# SentinelAI Deployment Guide

This guide covers deploying SentinelAI to production environments.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Frontend Deployment (Vercel)](#frontend-deployment-vercel)
3. [Backend Deployment (Render)](#backend-deployment-render)
4. [Backend Deployment (Railway)](#backend-deployment-railway)
5. [Database Setup](#database-setup)
6. [Environment Variables Reference](#environment-variables-reference)
7. [Domain Configuration](#domain-configuration)
8. [SSL/HTTPS Setup](#sslhttps-setup)
9. [Post-Deployment Checklist](#post-deployment-checklist)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- GitHub account with the SentinelAI repository
- Vercel account (free tier available)
- Render or Railway account
- Google Gemini API key
- Domain name (optional, for custom domains)

---

## Frontend Deployment (Vercel)

### Step 1: Connect Repository

1. Log in to [Vercel](https://vercel.com)
2. Click **"Add New Project"**
3. Import your GitHub repository
4. Select the repository root as the root directory

### Step 2: Configure Build Settings

Vercel auto-detects Next.js. Verify these settings:

| Setting | Value |
|---------|-------|
| Framework Preset | Next.js |
| Root Directory | `./` |
| Build Command | `npm run build` |
| Output Directory | `.next` |
| Install Command | `npm install` |

### Step 3: Set Environment Variables

Add the following in the Vercel dashboard under **Settings → Environment Variables**:

| Variable | Value |
|----------|-------|
| `NEXT_PUBLIC_API_URL` | `https://your-backend-url.onrender.com` |

> **Note:** Set this for **Production**, **Preview**, and **Development** environments.

### Step 4: Deploy

1. Click **"Deploy"**
2. Wait for the build to complete (typically 1–2 minutes)
3. Vercel provides a preview URL (e.g., `sentinelai.vercel.app`)
4. Every push to `main` triggers automatic deployment

### Step 5: Custom Domain (Optional)

1. Go to **Settings → Domains**
2. Add your custom domain
3. Configure DNS records as instructed by Vercel:
   - **A Record:** `76.76.21.21`
   - **CNAME Record:** `cname.vercel-dns.com`

Vercel provisions SSL certificates automatically.

---

## Backend Deployment (Render)

### Step 1: Create Web Service

1. Log in to [Render](https://render.com)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure the service:

| Setting | Value |
|---------|-------|
| Name | `sentinelai-backend` |
| Region | Oregon (or closest to your users) |
| Branch | `main` |
| Runtime | Python 3 |
| Build Command | `cd app && pip install -r requirements.txt` |
| Start Command | `cd app && uvicorn main:app --host 0.0.0.0 --port $PORT` |

### Step 2: Set Environment Variables

Go to **Environment** tab and add:

| Variable | Value |
|----------|-------|
| `SECRET_KEY` | A secure random string (generate with `python -c "import secrets; print(secrets.token_hex(32))"`) |
| `DATABASE_URL` | Your database connection string (see [Database Setup](#database-setup)) |
| `GEMINI_API_KEY` | Your Google Gemini API key |
| `CORS_ORIGINS` | `https://your-frontend.vercel.app,http://localhost:3000` |
| `PYTHON_VERSION` | `3.11.0` |

### Step 3: Deploy

1. Click **"Create Web Service"**
2. Render automatically builds and deploys
3. Your API will be available at `https://sentinelai-backend.onrender.com`

### Step 4: Health Check

Verify the deployment:

```bash
curl https://sentinelai-backend.onrender.com/health
```

Expected response:

```json
{"status": "healthy", "version": "1.0.0"}
```

---

## Backend Deployment (Railway)

Railway is an alternative to Render with a simpler setup process.

### Step 1: Create Project

1. Log in to [Railway](https://railway.app)
2. Click **"New Project"** → **"Deploy from GitHub Repo"**
3. Select your SentinelAI repository

### Step 2: Configure Service

Railway auto-detects the Python app. Add a **Start Command**:

```bash
cd app && uvicorn main:app --host 0.0.0.0 --port $PORT
```

### Step 3: Set Environment Variables

Go to the **Variables** tab:

| Variable | Value |
|----------|-------|
| `SECRET_KEY` | Secure random string |
| `DATABASE_URL` | Database connection string |
| `GEMINI_API_KEY` | Your Gemini API key |
| `CORS_ORIGINS` | Frontend URL |
| `PORT` | `8000` (Railway assigns ports dynamically) |

### Step 4: Deploy

1. Railway auto-deploys on push
2. Access your service at the generated `.up.railway.app` URL

---

## Database Setup

### Option A: Neon PostgreSQL (Recommended for Production)

1. Create account at [Neon](https://neon.tech)
2. Create a new project
3. Copy the connection string from the dashboard
4. Update `DATABASE_URL` in your backend environment variables:

```
DATABASE_URL=postgresql://user:password@ep-xxx.us-east-2.aws.neon.tech/sentinelai?sslmode=require
```

5. Run migrations on first deploy:

```bash
cd app
python -c "from database import engine, Base; Base.metadata.create_all(bind=engine)"
```

### Option B: SQLite (Development / Small Deployments)

SQLite is the default and requires no external setup:

```
DATABASE_URL=sqlite:///./sentinelai.db
```

> **Warning:** SQLite is not recommended for production with concurrent users. Use PostgreSQL for any serious deployment.

### Option C: Render PostgreSQL

1. In Render dashboard, click **"New +"** → **"PostgreSQL"**
2. Create the database
3. Copy the **Internal Database URL**
4. Set as `DATABASE_URL` in your web service environment

### Running Migrations

After setting up the database, run the initial migration:

```bash
# Local
cd app
python -c "
from database import engine, Base
from models import user, alert, threat
Base.metadata.create_all(bind=engine)
print('Tables created successfully')
"

# Or if using Alembic
alembic upgrade head
```

---

## Environment Variables Reference

### Frontend

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `NEXT_PUBLIC_API_URL` | Yes | Backend API base URL | `https://sentinelai-api.onrender.com` |

### Backend

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `SECRET_KEY` | Yes | JWT signing secret (min 32 chars) | `a1b2c3d4e5...` |
| `DATABASE_URL` | Yes | Database connection string | `postgresql://user:pass@host/db` |
| `GEMINI_API_KEY` | Yes | Google Gemini API key | `AIzaSy...` |
| `CORS_ORIGINS` | Yes | Comma-separated allowed origins | `https://app.com,http://localhost:3000` |

### Generating a Secure Secret Key

```bash
# Python
python -c "import secrets; print(secrets.token_hex(32))"

# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# OpenSSL
openssl rand -hex 32
```

---

## Domain Configuration

### Custom Domain Setup

#### Frontend (Vercel)

1. Purchase a domain (e.g., `sentinelai.com`)
2. In Vercel, go to **Settings → Domains**
3. Add `sentinelai.com` and `www.sentinelai.com`
4. Configure DNS:

```
Type    Name    Value
A       @       76.76.21.21
CNAME   www     cname.vercel-dns.com
```

5. Wait for DNS propagation (up to 48 hours, usually < 1 hour)
6. Vercel auto-provisions SSL

#### Backend (Render)

1. In Render, go to **Settings → Custom Domains**
2. Add your API domain (e.g., `api.sentinelai.com`)
3. Configure DNS:

```
Type    Name    Value
CNAME   api     sentinelai-backend.onrender.com
```

4. Render auto-provisions SSL for custom domains

### Updating CORS

After setting up custom domains, update the backend `CORS_ORIGINS`:

```
CORS_ORIGINS=https://sentinelai.com,https://www.sentinelai.com,http://localhost:3000
```

---

## SSL/HTTPS Setup

### Vercel (Automatic)

Vercel automatically provisions and renews SSL certificates for all deployments and custom domains. No manual configuration required.

### Render (Automatic)

Render provides automatic SSL for:
- All `.onrender.com` subdomains
- Custom domains added through the dashboard

Certificates are issued via Let's Encrypt and auto-renew.

### Manual SSL (Self-Hosted)

If hosting elsewhere, use Certbot with Let's Encrypt:

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d sentinelai.com -d www.sentinelai.com

# Auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

### Enforcing HTTPS

Add this to your Next.js `next.config.js`:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
```

---

## Post-Deployment Checklist

- [ ] Frontend deployed and accessible
- [ ] Backend deployed and `/health` endpoint responds
- [ ] Database connected and tables created
- [ ] Environment variables set correctly
- [ ] CORS configured for production frontend URL
- [ ] Custom domain configured (if applicable)
- [ ] SSL/HTTPS working
- [ ] Authentication flow tested end-to-end
- [ ] API rate limiting enabled
- [ ] Error monitoring configured (Sentry, etc.)
- [ ] Logging configured and accessible
- [ ] Backup strategy in place

---

## Troubleshooting

### Common Issues

#### "CORS Error" in Browser Console

**Cause:** Backend CORS_ORIGINS doesn't include the frontend URL.

**Fix:** Update `CORS_ORIGINS` to include your exact frontend URL (including `https://`).

#### "Application failed to respond" on Render

**Cause:** The start command isn't finding the correct directory.

**Fix:** Ensure the build and start commands include `cd app &&`:

```
Build: cd app && pip install -r requirements.txt
Start: cd app && uvicorn main:app --host 0.0.0.0 --port $PORT
```

#### "DATABASE_URL" Connection Error

**Cause:** Database connection string is incorrect or database is sleeping (free tiers).

**Fix:**
- Verify the connection string format
- For Neon free tier, check if the compute is paused and wake it
- Ensure SSL mode is set (`?sslmode=require` for PostgreSQL)

#### Vercel Build Fails

**Cause:** Missing dependencies or incorrect build configuration.

**Fix:**
- Check build logs in Vercel dashboard
- Ensure `package.json` has all required dependencies
- Verify `next.config.js` syntax

#### Slow Cold Starts on Render

**Cause:** Free tier Render services spin down after inactivity.

**Fix:**
- Upgrade to a paid plan for always-on service
- Or use a cron job to ping the service every 10 minutes

### Checking Logs

**Vercel:**
1. Go to your project → **Logs** tab
2. Filter by function or deployment

**Render:**
1. Go to your service → **Logs** tab
2. View real-time logs or download logs

**Railway:**
1. Go to your service → **Deployments**
2. Click on a deployment to view logs

---

## Cost Estimation

### Free Tier (Development/Testing)

| Service | Cost |
|---------|------|
| Vercel | $0/month (Hobby plan) |
| Render | $0/month (free tier) |
| Neon | $0/month (free tier) |
| **Total** | **$0/month** |

### Production Tier

| Service | Cost |
|---------|------|
| Vercel | $20/month (Pro plan) |
| Render | $7–25/month (Starter plans) |
| Neon | $19/month (Launch plan) |
| **Total** | **$46–64/month** |

---

## Quick Deploy Commands

### One-Line Deploy (Vercel)

```bash
npx vercel --prod -e NEXT_PUBLIC_API_URL=https://your-backend.onrender.com
```

### One-Line Deploy (Render)

Connect your repo on Render dashboard — auto-deploys on push.

---

For additional help, open an issue on [GitHub](https://github.com/your-org/sentinelai/issues).
