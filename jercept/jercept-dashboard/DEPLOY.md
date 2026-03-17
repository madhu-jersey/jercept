# Deploying Jercept Dashboard

## Quickstart — Railway (recommended, free tier)

```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. From the jercept-dashboard/ directory
cd jercept-dashboard
railway login
railway init
railway up

# 3. Set required environment variables
railway variables set JERCEPT_ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
railway variables set ALLOWED_ORIGINS="https://app.jercept.com,https://jercept.com"
railway variables set DATABASE_URL="postgresql+asyncpg://..."  # Railway auto-provisions this
```

Your dashboard is live at `https://your-project.up.railway.app` in under 2 minutes.

---

## Environment variables

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `DATABASE_URL` | ✅ | `sqlite+aiosqlite:///jercept.db` | PostgreSQL: `postgresql+asyncpg://user:pass@host/db` |
| `JERCEPT_ENCRYPTION_KEY` | ✅ for prod | none | Fernet key for webhook URL encryption. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `ALLOWED_ORIGINS` | ✅ for prod | `http://localhost:3000` | Comma-separated list of allowed CORS origins |
| `PORT` | auto | `8000` | Set automatically by Railway |

---

## Database migrations

Run migrations before starting the server for the first time on an existing database:

```bash
# Show status
python backend/migrations/run.py --status

# Apply all pending
python backend/migrations/run.py

# Dry run (preview SQL without applying)
python backend/migrations/run.py --dry-run
```

Migrations are idempotent — safe to run on every deploy.

---

## Docker

```bash
# Build
docker build -t jercept-dashboard .

# Run locally (SQLite)
docker run -p 8000:8000 \
  -e JERCEPT_ENCRYPTION_KEY="your-key-here" \
  jercept-dashboard

# Run with PostgreSQL
docker run -p 8000:8000 \
  -e DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/jercept" \
  -e JERCEPT_ENCRYPTION_KEY="your-key-here" \
  -e ALLOWED_ORIGINS="https://app.jercept.com" \
  jercept-dashboard
```

---

## Verify deployment

```bash
curl https://api.jercept.com/health
# {"status":"ok","version":"1.2.0","api_version":"v1","service":"jercept-dashboard"}
```

---

## SDK → Dashboard connection

Once deployed, users connect with their API key:

```python
from jercept import protect_agent

agent = protect_agent(
    my_agent,
    telemetry_key="jercept_live_xxxx",   # get free at jercept.com
)
result = await agent.run("check billing for customer 123")
```

Every `agent.run()` sends events to `/v1/events`. The dashboard at `/dashboard` shows:
- Real-time blocked attacks
- Per-session scope visualizer (what each request unlocked)
- Extraction tier (cache / regex / LLM) and confidence
- Webhook alerts when attacks are detected

---

## Custom domain

```
Railway → your project → Settings → Domains → Add custom domain
```

DNS records:
```
CNAME  app    your-project.up.railway.app
CNAME  api    your-project.up.railway.app
```
