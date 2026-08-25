# 🚀 Deployment Guide

This guide explains how to deploy CyberSure and set up automatic deployments on every push.

---

## Quick Deploy (Render)

### Step 1: Create Render Account

1. Go to [render.com](https://render.com)
2. Sign up with your GitHub account
3. Verify your email

### Step 2: Create Web Service

1. Click **"New +"** → **"Web Service"**
2. Connect your GitHub repo: `cybershanti6-scshackathon/Scshackathon-all-mem`
3. Configure:
   - **Name:** `cybersure`
   - **Runtime:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn msme_auditor.api.server:app --host 0.0.0.0 --port $PORT`
4. Click **"Create Web Service"**

### Step 3: Get Your API Credentials

After deployment, go to your service → **Settings** → **API Keys**

1. Create a new **API Key** → Copy it
2. Note your **Service ID** (shown in the URL)

---

## Set Up Automatic Deployments

### Step 4: Add GitHub Secrets

1. Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **"New repository secret"**
3. Add these two secrets:

| Secret Name | Value |
|-------------|-------|
| `RENDER_API_KEY` | Your Render API key (from Step 3) |
| `RENDER_SERVICE_ID` | Your Render Service ID (from Step 3) |

### Step 5: Push & Deploy

Now every time you push to `main`, GitHub Actions will:

1. ✅ Run tests
2. 🚀 Deploy to Render automatically

```bash
# Make changes, then:
git add .
git commit -m "Your changes"
git push origin main
# → Auto-deploys in ~2 minutes!
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    PUSH TO GITHUB                           │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   GITHUB ACTIONS                            │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Run Tests     │  │  Deploy to      │                  │
│  │   (Python)      │──│  Render         │                  │
│  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     RENDER.COM                              │
│  • Builds your app                                          │
│  • Installs dependencies                                    │
│  • Starts FastAPI server                                    │
│  • Provides live URL                                        │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    YOUR LIVE APP                            │
│  https://cybersure.onrender.com                             │
│                                                             │
│  • Dashboard: /dashboard.html                               │
│  • API Docs: /docs                                          │
│  • Scanners: RPP, NES, Web Security                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Environment Variables (Optional)

If you add environment variables to Render, they'll be available in your app:

| Variable | Description | Example |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API for AI assistant | `AIza...` |
| `SECRET_KEY` | JWT secret for auth | `your-secret-key` |

Add them in Render Dashboard → **Environment** tab.

---

## Troubleshooting

### Deployment fails?

1. Check Render logs: **Logs** tab in your service
2. Check GitHub Actions: **Actions** tab in your repo
3. Common issues:
   - Missing `requirements.txt` → Already fixed ✅
   - Import errors → Check `msme_auditor/` structure

### App not loading?

1. Render takes 2-3 min to start on first deploy
2. Check if the service is **"Live"** (green dot)
3. Visit `/docs` to see if API is running

### Changes not deploying?

1. Ensure you pushed to `main` branch
2. Check GitHub Actions logs for errors
3. Verify `RENDER_API_KEY` and `RENDER_SERVICE_ID` secrets are set

---

## Manual Deploy (Without GitHub Actions)

If you prefer manual deploys:

1. Go to Render Dashboard
2. Click **"Manual Deploy"** → **"Deploy latest commit"**

---

## Cost

**Render Free Tier:**
- ✅ 750 hours/month (enough for 24/7)
- ✅ Auto-sleeps after 15 min of inactivity
- ✅ Wakes up automatically when accessed
- ⚠️ First request after sleep takes ~30 sec

**GitHub Actions Free Tier:**
- ✅ 2,000 minutes/month
- ✅ Your usage: ~10 min/push (very minimal)

---

## Your Live URL

After deployment: **https://cybersure.onrender.com**

| Page | URL |
|------|-----|
| Home | https://cybersure.onrender.com |
| Dashboard | https://cybersure.onrender.com/dashboard.html |
| API Docs | https://cybersure.onrender.com/docs |

---

## Next Steps

After deployment, you can:
1. Add custom domain
2. Set up monitoring
3. Add authentication
4. Configure AI assistant with Gemini API key
