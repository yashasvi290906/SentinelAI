# SentinelAI — Cyber Threat Intelligence Platform

> AI-powered security operations center with real-time threat detection, predictive analytics, and intelligent response recommendations.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Frontend                       │
│         Next.js 16 + Tailwind v4                │
│    ┌──────┬──────┬──────┬──────┬──────┐        │
│    │Dash- │Predic│Analy-│Kill  │Net-  │        │
│    │board │tions │tics  │Chain │work  │        │
│    └──────┴──────┴──────┴──────┴──────┘        │
│         │ State: Zustand  │ Charts: Recharts    │
│         │ Animations: Framer Motion             │
└─────────────────┬───────────────────────────────┘
                  │ REST API + WebSocket
┌─────────────────┴───────────────────────────────┐
│                   Backend                        │
│            FastAPI + Python 3.11                 │
│    ┌──────┬──────┬──────┬──────┬──────┐        │
│    │Predic│Auth  │Copilot│Graph │Drift │        │
│    │tion  │      │      │      │      │        │
│    └──────┴──────┴──────┴──────┴──────┘        │
│         │ SQLite + DeterministicModel           │
│         │ Markov Chain + Attack Weighting       │
└─────────────────────────────────────────────────┘
```

## Features

### Core Analytics
- **10-Card SOC Dashboard** — Threat score, model agreement, prediction volume, drift detection
- **Predictions Module** — Interactive attack sequence builder with chain analysis
- **Analytics Dashboard** — Attack distribution, drift timeline, threat heatmap
- **Network Graph** — Visual attack path mapping with React Flow
- **Kill Chain** — 7-stage cyber kill chain visualization
- **Drift Analytics** — Model performance monitoring and drift detection

### Intelligence
- **AI Copilot** — Context-aware threat analysis assistant
- **Threat Intelligence** — Real-time threat feed with event correlation
- **World Attack Map** — Geographic attack visualization with d3-geo
- **Threat Radar** — Rotating radar display of active threats
- **Explainability Engine** — Model decision transparency

### Operations
- **Simulation Lab** — Attack scenario testing environment
- **Reports Module** — Dynamic PDF-ready threat reports
- **Live Activity Ticker** — Real-time event stream via WebSocket
- **System Health** — Infrastructure monitoring dashboard

### Security
- **JWT Authentication** — Access + refresh token architecture
- **OTP Verification** — 6-digit email verification with rate limiting
- **Role-Based Access** — Admin and analyst role support
- **Security Headers** — CSP, HSTS, X-Frame-Options, and more
- **Rate Limiting** — Per-endpoint request throttling

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS v4 |
| State | Zustand, React Query patterns |
| Animations | Framer Motion, CSS @keyframes |
| Charts | Recharts, D3-geo, React Flow |
| Backend | FastAPI, Python 3.11, Uvicorn |
| Database | SQLite (WAL mode), bcrypt |
| Auth | JWT (python-jose), bcrypt |
| Deployment | Docker, Docker Compose, Render |

## Installation

### Prerequisites
- Node.js 18+
- Python 3.11+
- npm or yarn

### Frontend
```bash
cd sentinelai-ui
npm install
cp .env.example .env.local
# Edit .env.local with your backend URL
npm run dev
```

### Backend
```bash
cd app
pip install -r requirements.txt
cp .env.example .env
# Edit .env with SECRET_KEY and optional GEMINI_API_KEY
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### Docker
```bash
docker-compose up --build
```

## Environment Variables

### Frontend (.env.local)
| Variable | Required | Description |
|----------|----------|-------------|
| NEXT_PUBLIC_API_URL | Yes | Backend API URL |
| NEXT_PUBLIC_GEMINI_API_KEY | No | Gemini AI API key |
| NEXT_PUBLIC_APP_NAME | No | Application name |

### Backend (.env)
| Variable | Required | Description |
|----------|----------|-------------|
| SECRET_KEY | Yes | JWT signing secret (min 32 chars) |
| GEMINI_API_KEY | No | Gemini AI key for copilot |
| CORS_ORIGINS | No | Allowed origins (comma-separated) |
| DATABASE_PATH | No | SQLite database path |
| SMTP_HOST | No | SMTP server for OTP emails |
| SMTP_PORT | No | SMTP port (default: 587) |
| SMTP_USER | No | SMTP username |
| SMTP_PASSWORD | No | SMTP password |

## API Endpoints

### Public
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/signup | Register new account |
| POST | /auth/login | Login with email/password |
| POST | /auth/send-otp | Send OTP verification |
| POST | /auth/verify-otp | Verify OTP code |
| GET | /health | Health check |

### Protected (JWT Required)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /predict | Predict next attack |
| POST | /compare | Compare ML vs Markov |
| GET | /stats | Dashboard statistics |
| GET | /drift | Drift detection data |
| POST | /explain | Model explanation |
| GET | /graph | Network graph data |
| GET | /killchain | Kill chain analysis |
| GET | /recommendations | Response recommendations |
| GET | /reports | Generate reports |
| WS | /ws | Real-time event stream |

## Project Structure

```
SentinelAI/
├── app/                          # Backend
│   ├── app.py                   # FastAPI application (all endpoints)
│   ├── auth.py                  # JWT + OTP authentication
│   ├── database.py              # SQLite database manager
│   ├── model_loader.py          # DeterministicModel + MarkovChain
│   ├── predict.py               # Prediction logic
│   ├── services/
│   │   └── email_service.py     # SMTP email service
│   ├── Dockerfile               # Backend Docker config
│   ├── requirements.txt         # Python dependencies
│   └── render.yaml              # Render deployment
├── sentinelai-ui/               # Frontend
│   ├── app/
│   │   ├── page.tsx             # SPA router (18 modules)
│   │   ├── layout.tsx           # Root layout
│   │   ├── login/page.tsx       # Login page
│   │   ├── signup/page.tsx      # Signup page
│   │   ├── not-found.tsx        # 404 page
│   │   ├── error.tsx            # Error boundary
│   │   └── loading.tsx          # Loading skeleton
│   ├── components/
│   │   ├── layout/              # Shell, sidebar, command bar
│   │   ├── copilot/             # AI copilot widget
│   │   └── ui/                  # Reusable UI components
│   ├── modules/                 # Feature modules (18)
│   ├── stores/                  # Zustand state stores
│   ├── hooks/                   # Custom React hooks
│   ├── services/                # Audio, logger, system monitor
│   ├── lib/                     # Config, types, API client
│   └── Dockerfile               # Frontend Docker config
├── docker-compose.yml           # Multi-container setup
├── .gitignore                   # Git ignore rules
├── .env.example                 # Root env template
└── README.md                    # This file
```

## Deployment

### Vercel (Frontend)
1. Push to GitHub
2. Import repository in Vercel
3. Set `NEXT_PUBLIC_API_URL` to your backend URL
4. Deploy

### Render (Backend)
1. Connect GitHub repository
2. Use `render.yaml` blueprint
3. Set `SECRET_KEY` environment variable
4. Deploy

### Docker
```bash
# Build and start
docker-compose up --build -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Security

- JWT tokens stored in httpOnly cookies (production) or localStorage (development)
- Passwords hashed with bcrypt (12 salt rounds)
- OTP codes hashed with SHA-256, never stored in plain text
- Rate limiting on auth endpoints (3-5 requests/minute)
- CSP headers prevent XSS attacks
- CORS restricted to known origins
- No secrets committed to repository
- SQL injection prevented via parameterized queries

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

Built as a cybersecurity intelligence platform combining machine learning predictions with operational security analytics.
