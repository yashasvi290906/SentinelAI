# SentinelAI

> Enterprise AI-Powered Cyber Threat Intelligence Platform

SentinelAI is a comprehensive threat intelligence platform that leverages artificial intelligence to detect, analyze, and respond to cybersecurity threats in real-time. Built with modern web technologies and powered by Google Gemini AI, it provides security teams with actionable insights and automated response capabilities.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Next.js Frontend                       │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │ Dashboard │ │ Alerts   │ │ Reports  │ │ Settings │   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        API LAYER                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  FastAPI Backend                         │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │   Auth   │ │  Threat  │ │ Analytics│ │  Reports │   │   │
│  │  │ Endpoints│ │ Endpoints│ │ Endpoints│ │ Endpoints│   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SERVICE LAYER                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Gemini   │ │ Threat   │ │  Email   │ │  Background      │   │
│  │   AI     │ │ Intel    │ │ Service  │ │  Tasks (Celery)  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DATA LAYER                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ SQLite/  │ │  Redis   │ │   S3     │ │  Elasticsearch   │   │
│  │PostgreSQL│ │  Cache   │ │ Storage  │ │     (Optional)   │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Core Capabilities
- **Real-time Threat Monitoring** — Live dashboard with threat feeds and alerts
- **AI-Powered Analysis** — Google Gemini integration for intelligent threat assessment
- **Automated Alert System** — Configurable alerts with severity levels and notifications
- **Threat Intelligence Feeds** — Aggregation from multiple open-source intelligence sources
- **Incident Response** — Workflow automation for threat mitigation
- **Comprehensive Reporting** — Generate detailed security reports and analytics

### Dashboard & Analytics
- Interactive threat visualization charts
- Historical trend analysis
- Geographic threat mapping
- Severity distribution analytics
- Custom date range filtering
- Real-time metric updates

### Security Features
- JWT-based authentication
- Role-based access control (RBAC)
- API rate limiting
- CORS protection
- Input validation and sanitization
- Audit logging

### Integrations
- Google Gemini AI for threat analysis
- Email notifications (SMTP)
- Webhook support for external integrations
- RESTful API for third-party connections

---

## Tech Stack

### Frontend
| Technology | Purpose |
|------------|---------|
| Next.js 14 | React framework with App Router |
| TypeScript | Type-safe development |
| Tailwind CSS | Utility-first styling |
| Shadcn/UI | Component library |
| Recharts | Data visualization |
| React Query | Server state management |
| Zustand | Client state management |
| Lucide Icons | Icon library |

### Backend
| Technology | Purpose |
|------------|---------|
| FastAPI | High-performance Python API framework |
| SQLAlchemy | ORM and database toolkit |
| Pydantic | Data validation and serialization |
| Google Gemini AI | Threat analysis and natural language processing |
| Celery | Distributed task queue |
| Redis | Caching and message broker |
| JWT | Authentication tokens |

### DevOps & Deployment
| Technology | Purpose |
|------------|---------|
| Vercel | Frontend hosting and CI/CD |
| Render | Backend hosting |
| Neon | Serverless PostgreSQL |
| Docker | Containerization |
| GitHub Actions | CI/CD pipelines |

---

## Prerequisites

- **Node.js** 18.0 or higher
- **Python** 3.10 or higher
- **npm** or **yarn** or **pnpm**
- **pip** or **poetry**
- **Git**

---

## Installation

### Clone the Repository

```bash
git clone https://github.com/your-org/sentinelai.git
cd sentinelai
```

### Frontend Setup

```bash
# Install dependencies
npm install

# Copy environment variables
cp .env.example .env.local

# Start development server
npm run dev
```

The frontend will be available at [http://localhost:3000](http://localhost:3000).

### Backend Setup

```bash
# Navigate to backend directory
cd app

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env

# Start the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The backend API will be available at [http://localhost:8000](http://localhost:8000).

---

## Environment Variables

### Frontend (`.env.local`)

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXT_PUBLIC_API_URL` | Backend API base URL | `http://localhost:8000` |

### Backend (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing secret | — (required) |
| `DATABASE_URL` | Database connection string | `sqlite:///./sentinelai.db` |
| `GEMINI_API_KEY` | Google Gemini API key | — (required) |
| `CORS_ORIGINS` | Allowed CORS origins | `http://localhost:3000` |

---

## Running Locally

### Development Mode

```bash
# Terminal 1 — Frontend
npm run dev

# Terminal 2 — Backend
cd app
venv\Scripts\activate  # or source venv/bin/activate
uvicorn main:app --reload --port 8000
```

### Production Build

```bash
# Build frontend
npm run build

# Start frontend production server
npm start

# Start backend production server
cd app
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## Deployment

### Frontend (Vercel)

1. Push your repository to GitHub
2. Import the project on [Vercel](https://vercel.com)
3. Set environment variables in the Vercel dashboard
4. Deploy — Vercel auto-detects Next.js

```bash
# Or deploy via CLI
npm i -g vercel
vercel --prod
```

### Backend (Render)

1. Create a new **Web Service** on [Render](https://render.com)
2. Connect your GitHub repository
3. Configure the service:
   - **Build Command:** `cd app && pip install -r requirements.txt`
   - **Start Command:** `cd app && uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add environment variables in the Render dashboard
5. Deploy

See [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) for detailed instructions.

---

## Project Structure

```
sentinelai/
├── app/                          # Backend application
│   ├── __init__.py
│   ├── main.py                   # FastAPI application entry point
│   ├── config.py                 # Configuration management
│   ├── database.py               # Database connection setup
│   ├── models/                   # SQLAlchemy ORM models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── alert.py
│   │   └── threat.py
│   ├── schemas/                  # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── alert.py
│   │   └── threat.py
│   ├── routers/                  # API route handlers
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── alerts.py
│   │   ├── threats.py
│   │   ├── dashboard.py
│   │   └── reports.py
│   ├── services/                 # Business logic
│   │   ├── __init__.py
│   │   ├── gemini_service.py
│   │   ├── threat_intel.py
│   │   └── email_service.py
│   ├── middleware/               # Custom middleware
│   │   ├── __init__.py
│   │   └── auth.py
│   ├── utils/                    # Utility functions
│   │   ├── __init__.py
│   │   └── helpers.py
│   ├── requirements.txt          # Python dependencies
│   └── .env.example              # Backend env template
├── src/                          # Frontend application
│   ├── app/                      # Next.js App Router
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   ├── dashboard/
│   │   ├── alerts/
│   │   ├── reports/
│   │   └── settings/
│   ├── components/               # Reusable UI components
│   │   ├── ui/                   # Shadcn/UI components
│   │   ├── dashboard/
│   │   ├── alerts/
│   │   └── shared/
│   ├── lib/                      # Utility functions
│   │   ├── api.ts
│   │   └── utils.ts
│   ├── hooks/                    # Custom React hooks
│   ├── stores/                   # Zustand state stores
│   └── types/                    # TypeScript type definitions
├── public/                       # Static assets
├── .env.example                  # Frontend env template
├── .gitignore
├── next.config.js
├── tailwind.config.ts
├── tsconfig.json
├── package.json
├── LICENSE
├── README.md
├── DEPLOYMENT_GUIDE.md
└── CHANGELOG.md
```

---

## API Documentation

Once the backend is running, access the interactive API docs:

- **Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc:** [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.

---

## Support

For support and questions:

- **Issues:** [GitHub Issues](https://github.com/your-org/sentinelai/issues)
- **Documentation:** [Project Wiki](https://github.com/your-org/sentinelai/wiki)

---

<p align="center">Built with care by the SentinelAI team</p>
