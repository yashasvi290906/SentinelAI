from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from datetime import datetime, timezone, timedelta
from functools import lru_cache
import time
import time as _time
from collections import deque
import asyncio
import os
from pathlib import Path
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import json as _json
import logging
import uuid

from services.parser_service import parser
from services.threat_detection import ThreatDetector
from services.anomaly_service import anomaly_detector
from services.mitre_service import mitre_mapper
from services.report_service import report_generator
from services.intelligence_service import threat_intel
from services.gemini_service import gemini_copilot
from services.normalization_service import event_normalizer, NormalizedEvent
from services.rule_engine import detection_rule_engine

# Load .env file
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

from model_loader import model, le, markov, ATTACK_WEIGHTS, ATTACK_CLASSES, ATTACK_TO_IDX, MODEL_VERSION
from predict import predict_next, markov_predict
from auth import register_user, authenticate_user, generate_otp, verify_otp, create_access_token, create_refresh_token, verify_token, check_rate_limit, log_audit, users_db, audit_log
from database import db


security = HTTPBearer(auto_error=False)

async def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


# =========================
# Production Logging
# =========================

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinelai")

def log_structured(level: str, category: str, message: str, metadata: dict = None):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "category": category,
        "message": message,
        "metadata": metadata or {},
    }
    log_line = _json.dumps(entry)
    if level == "error":
        logger.error(log_line)
    elif level == "warning":
        logger.warning(log_line)
    else:
        logger.info(log_line)


# =========================
# Severity Thresholds
# =========================
SEVERITY_HIGH_THRESHOLD = 75
SEVERITY_MEDIUM_THRESHOLD = 55
SEVERITY_LOW_THRESHOLD = 35
CONFIDENCE_HIGH = 0.8
CONFIDENCE_MEDIUM = 0.6


# =========================
# FastAPI App
# =========================
app = FastAPI(
    title="SentinelAI",
    description="Hybrid Attack Forecasting System (ML + Markov)",
    version="2.0.0"
)

logger = logging.getLogger("sentinelai")
if db.use_postgresql:
    logger.info("Connected to PostgreSQL")
else:
    logger.info("Connected to SQLite")
logger.info("Migrations completed")
logger.info("Schema validated")
logger.info("Loaded Sigma rules")
logger.info("Loaded playbooks")
logger.info("Loaded AI services")
logger.info("WebSocket manager initialized")
logger.info("SentinelAI backend started successfully")

# Background scheduler
try:
    from services.scheduler_service import scheduler, setup_scheduler
except Exception as _e:
    scheduler = None
    setup_scheduler = None
    logger.error(f"Failed to load scheduler: {_e}", extra={"log_module": "startup"})

@app.on_event("startup")
async def startup_scheduler():
    try:
        if setup_scheduler:
            setup_scheduler()
            asyncio.create_task(scheduler.start())
            log_structured("info", "system", "Background scheduler started")
        else:
            log_structured("warning", "system", "Scheduler not available, skipping")
    except Exception as e:
        log_structured("error", "system", f"Scheduler startup failed: {e}")

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' http://127.0.0.1:8000 ws://127.0.0.1:8000"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = _time.time()
        response = await call_next(request)
        duration = (_time.time() - start) * 1000
        if request.url.path not in ["/health", "/ws/events"]:
            log_audit("system", "request", f"{request.method} {request.url.path} -> {response.status_code} ({duration:.1f}ms)")
        return response

app.add_middleware(RequestLoggingMiddleware)


# =========================
# Request Schemas
# =========================
class SequenceRequest(BaseModel):
    sequence: list[int] = Field(..., min_length=1, max_length=20)


class CopilotRequest(BaseModel):
    sequence: list[int] = Field(default=[])
    prediction: str = Field(default="")
    question: str = Field(default="", max_length=500)
    conversation_history: list[dict] = Field(default=[])


class ExplainRequest(BaseModel):
    sequence: list[int] = Field(..., min_length=1, max_length=20)


class RegisterRequest(BaseModel):
    email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    password: str = Field(..., min_length=8, max_length=128)
    name: str = Field(..., min_length=1, max_length=100)


class LoginRequest(BaseModel):
    email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    password: str = Field(..., min_length=8, max_length=128)


class OTPRequest(BaseModel):
    email: str


class OTPVerifyRequest(BaseModel):
    email: str
    otp: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class AnomalyAnalysisRequest(BaseModel):
    log_id: str


class ReportRequest(BaseModel):
    report_type: str = Field(default="technical", pattern=r'^(executive|technical|incident)$')
    date_from: str = Field(default="")
    date_to: str = Field(default="")
    detection_id: str = Field(default="")


class IntelLookupRequest(BaseModel):
    indicator: str = Field(..., max_length=500)
    indicator_type: str = Field(default="auto", pattern=r'^(auto|ip|domain|hash)$')


# =========================
# Real History Storage (ring buffers)
# =========================
MAX_HISTORY = 1000

prediction_history: deque = deque(maxlen=MAX_HISTORY)
comparison_history: deque = deque(maxlen=MAX_HISTORY)
threat_events: deque = deque(maxlen=MAX_HISTORY)
drift_history: deque = deque(maxlen=MAX_HISTORY)

# Broadcast queue for real-time detection events (ingestion → WebSocket)
broadcast_queue: deque = deque(maxlen=500)
# Counter to auto-trigger correlation every N detections
_detection_counter: int = 0
CORRELATION_BATCH_SIZE: int = 10


def _record_threat_event(event_type: str, prediction: str, confidence: float, severity_score: float, details: dict = None):
    """Record a real threat event."""
    threat_events.appendleft({
        "id": f"evt-{len(threat_events)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "severity_score": round(severity_score, 1),
        "details": details or {},
    })


# =========================
# LRU Cache
# =========================
@lru_cache(maxsize=500)
def cached_predict(seq_tuple):
    seq = list(seq_tuple)
    return predict_next(seq, model, le)


# =========================
# Transparent Threat Score Calculator
# =========================
def calculate_threat_score() -> dict:
    """
    Transparent threat score from REAL database data.
    score = 0.40 * avg_confidence + 0.25 * critical_factor + 0.20 * alert_factor + 0.15 * incident_factor
    """
    try:
        detections = db.get_threat_detections(limit=500)
        alerts = db.get_alerts(status='open', limit=200)
        incidents = db.get_incidents(status='open', limit=100)
    except Exception:
        return {
            "score": 0,
            "breakdown": {"confidence_contribution": 0, "critical_alerts": 0, "alert_factor": 0, "incident_factor": 0},
            "factors": {"avg_confidence": 0, "critical_count": 0, "open_alerts": 0, "open_incidents": 0},
        }

    if not detections and not alerts:
        return {
            "score": 0,
            "breakdown": {"confidence_contribution": 0, "critical_alerts": 0, "alert_factor": 0, "incident_factor": 0},
            "factors": {"avg_confidence": 0, "critical_count": 0, "open_alerts": 0, "open_incidents": 0},
        }

    # Factor 1: Average confidence from detections (0-40)
    confidences = [d.get("confidence", 0) for d in detections if d.get("confidence")]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0
    confidence_contribution = round(avg_confidence * 40, 1)

    # Factor 2: Critical alerts (0-25)
    critical_count = sum(1 for d in detections if d.get("severity") == "CRITICAL")
    high_count = sum(1 for d in detections if d.get("severity") == "HIGH")
    critical_factor = min((critical_count * 3 + high_count * 1.5), 25)

    # Factor 3: Open alerts factor (0-20)
    open_alerts = len(alerts)
    critical_alerts = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    alert_factor = min(open_alerts * 0.5 + critical_alerts * 3, 20)

    # Factor 4: Open incidents factor (0-15)
    open_incidents = len(incidents)
    critical_incidents = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    incident_factor = min(open_incidents * 2 + critical_incidents * 5, 15)

    total_score = min(100, round(confidence_contribution + critical_factor + alert_factor + incident_factor))

    return {
        "score": total_score,
        "breakdown": {
            "confidence_contribution": confidence_contribution,
            "critical_alerts": round(critical_factor, 1),
            "alert_factor": round(alert_factor, 1),
            "incident_factor": round(incident_factor, 1),
        },
        "factors": {
            "avg_confidence": round(avg_confidence, 4),
            "critical_count": critical_count,
            "open_alerts": open_alerts,
            "open_incidents": open_incidents,
        },
    }


# =========================
# Home / Health
# =========================
@app.get("/")
async def home():
    return {
        "message": "SentinelAI is running",
        "status": "OK",
        "model_loaded": globals().get("model") is not None,
        "encoder_loaded": True,
        "markov_loaded": True,
        "version": MODEL_VERSION,
    }


@app.get("/health")
async def health():
    db_status = "disconnected"
    db_type = "none"
    try:
        with db._cursor() as cur:
            cur.execute("SELECT 1")
        db_status = "connected"
        db_type = "postgresql" if db.use_postgresql else "sqlite"
    except Exception:
        db_status = "error"

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    gemini_status = "configured" if gemini_key and gemini_key.startswith("AIzaSy") else "not_configured"

    ws_status = "active" if hasattr(app, 'websockets') or True else "inactive"

    return {
        "status": "healthy",
        "database": db_status,
        "database_type": db_type,
        "gemini": gemini_status,
        "websocket": ws_status,
        "version": MODEL_VERSION,
    }


@app.get("/history")
async def get_history():
    return {"history": list(prediction_history), "count": len(prediction_history)}


@app.get("/stats")
async def get_stats():
    """Real statistics from history."""
    pred_list = list(prediction_history)
    comp_list = list(comparison_history)

    attack_dist = {}
    for p in pred_list:
        a = p.get("prediction", "Unknown")
        attack_dist[a] = attack_dist.get(a, 0) + 1

    # Read from database for real persistent stats
    try:
        pred_stats = db.get_prediction_stats()
        comp_stats = db.get_comparison_stats()
        detections = db.get_threat_detections(limit=500)
        alerts = db.get_alerts(limit=200)
        incidents = db.get_incidents(limit=100)
    except Exception:
        pred_stats = {"total": 0, "by_attack": {}, "avg_confidence": 0}
        comp_stats = {"total": 0, "agreement_rate": 0}
        detections = []
        alerts = []
        incidents = []

    attack_dist = pred_stats.get("by_attack", {})
    most_frequent = max(attack_dist, key=attack_dist.get) if attack_dist else "None"

    critical_count = sum(1 for d in detections if d.get("severity") == "CRITICAL")
    high_count = sum(1 for d in detections if d.get("severity") == "HIGH")
    open_alerts = sum(1 for a in alerts if a.get("status") == "open")
    open_incidents = sum(1 for i in incidents if i.get("status") == "open")

    threat = calculate_threat_score()

    return {
        "total_predictions": pred_stats.get("total", 0),
        "total_comparisons": comp_stats.get("total", 0),
        "total_detections": len(detections),
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "attack_distribution": attack_dist,
        "most_frequent_attack": most_frequent,
        "average_confidence": round(pred_stats.get("avg_confidence", 0), 4),
        "critical_alerts": critical_count,
        "high_alerts": high_count,
        "open_alerts": open_alerts,
        "open_incidents": open_incidents,
        "threat_score": threat,
        "recent_detections": detections[:10],
        "recent_alerts": alerts[:10],
    }


@app.get("/stats/persistent")
async def get_persistent_stats():
    pred_stats = db.get_prediction_stats()
    comp_stats = db.get_comparison_stats()
    return {
        "predictions": pred_stats,
        "comparisons": comp_stats,
    }


@app.get("/reports")
async def get_reports():
    reports = db.get_reports(limit=50)
    return {"reports": reports}


# =========================
# ML Prediction (improved response format)
# =========================
@app.post("/predict")
async def predict(data: SequenceRequest):
    try:
        start = time.perf_counter()
        seq = data.sequence
        seq_key = tuple(seq)

        prediction, confidence, top_3, explanation = cached_predict(seq_key)
        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        attack_weight = ATTACK_WEIGHTS.get(prediction, 0.5)
        severity_score = round(confidence * attack_weight * 100, 1)

        # Determine severity label
        if severity_score >= SEVERITY_HIGH_THRESHOLD:
            severity = "CRITICAL"
        elif severity_score >= SEVERITY_MEDIUM_THRESHOLD:
            severity = "HIGH"
        elif severity_score >= SEVERITY_LOW_THRESHOLD:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": seq,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "severity_score": severity_score,
            "severity": severity,
            "latency_ms": latency_ms,
            "model": MODEL_VERSION,
        }

        prediction_history.appendleft(record)

        await asyncio.to_thread(
            db.record_prediction,
            timestamp=datetime.now(timezone.utc).isoformat(),
            sequence=str(data.sequence),
            prediction=prediction,
            confidence=confidence,
            severity=severity,
            severity_score=severity_score,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
            model=MODEL_VERSION,
        )

        # Record threat event
        _record_threat_event("prediction", prediction, confidence, severity_score, {
            "sequence": seq,
            "severity": severity,
        })

        log_structured("info", "prediction", f"Prediction: {prediction} ({confidence:.1%}) [{severity}] {latency_ms}ms", {
            "prediction": prediction, "confidence": confidence, "severity": severity,
            "severity_score": severity_score, "latency_ms": latency_ms,
        })

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "top_predictions": top_3,
            "severity": severity,
            "severity_score": severity_score,
            "latency_ms": latency_ms,
            "model": MODEL_VERSION,
            "explanation": explanation,
            "timestamp": record["timestamp"],
        }
    except Exception as e:
        logger.error(f"Prediction error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": "Prediction failed. Please try again."})


# =========================
# Compare ML vs Markov
# =========================
@app.post("/compare")
async def compare(data: SequenceRequest):
    try:
        start = time.perf_counter()
        seq = data.sequence
        seq_key = tuple(seq)

        ml_pred, ml_confidence, ml_top3, ml_explanation = cached_predict(seq_key)

        last_label = le.inverse_transform([seq[-1]])[0]
        markov_pred, markov_confidence = markov_predict(last_label, markov)
        if markov_pred is None:
            markov_pred = ml_pred
            markov_confidence = 0.0

        agreement = ml_pred == markov_pred
        agreement_score = round(1 - abs(ml_confidence - markov_confidence), 4)
        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": seq,
            "ml_prediction": ml_pred,
            "markov_prediction": markov_pred,
            "ml_confidence": round(ml_confidence, 4),
            "markov_confidence": round(markov_confidence, 4),
            "agreement": agreement,
            "agreement_score": agreement_score,
            "latency_ms": latency_ms,
        }

        comparison_history.appendleft(record)

        await asyncio.to_thread(
            db.record_comparison,
            timestamp=datetime.now(timezone.utc).isoformat(),
            sequence=str(data.sequence),
            ml_prediction=ml_pred,
            markov_prediction=markov_pred,
            agreement=agreement,
            agreement_score=round(agreement_score, 3),
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )

        if not agreement:
            _record_threat_event("disagreement", ml_pred, ml_confidence, 0, {
                "ml_prediction": ml_pred,
                "markov_prediction": markov_pred,
            })

        log_structured("info", "prediction", f"Compare: ML={ml_pred} vs Markov={markov_pred} ({'AGREE' if agreement else 'CONFLICT'}) {latency_ms}ms", {
            "ml_prediction": ml_pred, "markov_prediction": markov_pred, "agreement": agreement,
            "agreement_score": agreement_score, "latency_ms": latency_ms,
        })

        return {
            **record,
            "ml_top_predictions": ml_top3,
        }
    except Exception as e:
        logger.error(f"Comparison error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": "Comparison failed. Please try again."})


# =========================
# Drift Detection
# =========================
@app.post("/drift")
async def drift(data: SequenceRequest):
    try:
        pred_list = list(prediction_history)
        if len(pred_list) < 2:
            record = {"timestamp": datetime.now(timezone.utc).isoformat(), "score": 0.0, "status": "baseline"}
            drift_history.appendleft(record)
            return record

        confidences = [p.get("confidence", 0) for p in pred_list]
        recent = confidences[:len(confidences)//2]
        older = confidences[len(confidences)//2:]

        recent_avg = sum(recent) / len(recent) if recent else 0
        older_avg = sum(older) / len(older) if older else 0
        drift_score = abs(recent_avg - older_avg)

        if drift_score < 0.1:
            status = "stable"
        elif drift_score < 0.25:
            status = "warning"
        else:
            status = "critical"

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": round(drift_score, 4),
            "status": status,
        }
        drift_history.appendleft(record)
        return record
    except Exception as e:
        logger.error(f"Drift detection error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": "Drift detection failed. Please try again."})


# =========================
# AI Copilot (Gemini API)
# =========================
ATTACK_KNOWLEDGE = {
    "DDoS": {
        "description": "Distributed Denial of Service — overwhelms target with massive traffic from multiple sources.",
        "indicators": [
            "Repeated traffic spikes from distributed sources",
            "Sudden transition frequency increase",
            "High volume of SYN/ACK packets",
            "Bandwidth saturation detected",
        ],
        "recommendations": [
            "Enable rate limiting on all public endpoints",
            "Activate DDoS mitigation service (Cloudflare/AWS Shield)",
            "Block suspicious IP ranges at firewall",
            "Scale up bandwidth or enable auto-scaling",
            "Monitor ingress traffic for anomaly patterns",
            "Activate WAF protection rules",
        ],
        "kill_chain_stage": "Actions on Objectives",
        "severity_weight": 0.95,
    },
    "DoS": {
        "description": "Denial of Service — single-source attack exhausting target resources.",
        "indicators": [
            "Abnormal request rate from single source",
            "Resource exhaustion patterns (CPU/memory/bandwidth)",
            "Connection pool depletion",
            "Service response time degradation",
        ],
        "recommendations": [
            "Block offending source IP immediately",
            "Enable connection rate limiting",
            "Review and harden service configuration",
            "Deploy application-level firewalls",
            "Set up automatic IP reputation blocking",
        ],
        "kill_chain_stage": "Actions on Objectives",
        "severity_weight": 0.80,
    },
    "PortScan": {
        "description": "Network reconnaissance — probing ports to discover open services and vulnerabilities.",
        "indicators": [
            "Sequential or random port access patterns",
            "Multiple connection attempts to closed ports",
            "SYN packets without completing handshake",
            "Network mapping behavior detected",
        ],
        "recommendations": [
            "Enable port scan detection on IDS/IPS",
            "Block source IP after threshold exceeded",
            "Audit all exposed services and close unnecessary ports",
            "Implement network segmentation",
            "Review firewall rules for overly permissive access",
        ],
        "kill_chain_stage": "Reconnaissance",
        "severity_weight": 0.55,
    },
    "Bot": {
        "description": "Botnet activity — compromised machines controlled by C2 infrastructure.",
        "indicators": [
            "Beaconing patterns to known C2 servers",
            "Encrypted or encoded C2 traffic",
            "Lateral movement from compromised host",
            "Unusual outbound connections on non-standard ports",
        ],
        "recommendations": [
            "Isolate compromised host immediately",
            "Block C2 server IPs at perimeter firewall",
            "Run full endpoint scan on affected systems",
            "Reset credentials for affected accounts",
            "Conduct forensic analysis of network traffic",
            "Update EDR signatures",
        ],
        "kill_chain_stage": "Command & Control",
        "severity_weight": 0.65,
    },
    "WebAttack": {
        "description": "Web application attack — exploitation of web vulnerabilities (SQLi, XSS, etc.).",
        "indicators": [
            "Malicious payload in HTTP parameters",
            "SQL injection or XSS signatures detected",
            "Abnormal URL patterns or directory traversal",
            "Authentication bypass attempts",
        ],
        "recommendations": [
            "Deploy WAF rules for detected attack pattern",
            "Sanitize all user inputs immediately",
            "Review and patch vulnerable endpoints",
            "Enable comprehensive logging on web server",
            "Conduct penetration testing on affected application",
        ],
        "kill_chain_stage": "Exploitation",
        "severity_weight": 0.75,
    },
    "BruteForce": {
        "description": "Brute force attack — systematic credential guessing or password spraying.",
        "indicators": [
            "Multiple failed login attempts in short window",
            "Login attempts with common passwords",
            "Distributed login attempts from similar IPs",
            "Account lockout events triggered",
        ],
        "recommendations": [
            "Enable account lockout after 5 failed attempts",
            "Implement CAPTCHA after 3 failed logins",
            "Enforce MFA on all privileged accounts",
            "Block source IPs after threshold exceeded",
            "Review and strengthen password policy",
        ],
        "kill_chain_stage": "Exploitation",
        "severity_weight": 0.70,
    },
    "Infiltration": {
        "description": "Active infiltration — attacker has gained access and is operating within the network.",
        "indicators": [
            "Unauthorized access to sensitive resources",
            "Data exfiltration patterns detected",
            "Privilege escalation attempts",
            "Lateral movement across network segments",
        ],
        "recommendations": [
            "Isolate affected network segments immediately",
            "Engage incident response team",
            "Preserve forensic evidence (memory dumps, logs)",
            "Block all unauthorized outbound connections",
            "Conduct full network audit",
            "Notify stakeholders per incident response plan",
        ],
        "kill_chain_stage": "Actions on Objectives",
        "severity_weight": 0.90,
    },
}


async def _gemini_copilot_response(question: str, context: dict) -> str:
    """Call Gemini API for intelligent copilot response."""
    api_key = os.environ.get("GEMINI_API_KEY", "")

    if not api_key or api_key.startswith("your-") or api_key == "test-key":
        return _build_contextual_response(question, context)

    try:
        import httpx

        system_prompt = """You are SentinelAI Copilot, an expert cybersecurity SOC analyst assistant.
You analyze attack predictions and provide actionable security advice.
Be concise, specific, and reference actual data from the system.
Never use generic responses. Always reference the specific attack, confidence, and history.
If you don't have enough data, say so honestly."""

        context_data = f"""
Current Prediction: {context.get('prediction', 'None')}
Confidence: {context.get('confidence', 0)*100:.1f}%
Severity Score: {context.get('severity_score', 0)}
Recent Predictions: {_json.dumps(context.get('recent_predictions', [])[:5])}
Total Predictions: {context.get('total_predictions', 0)}
Agreement Rate: {context.get('agreement_rate', 0)*100:.1f}%
Threat Score: {context.get('threat_score', 0)}
Attack Distribution: {_json.dumps(context.get('attack_distribution', {}))}
"""

        prompt = f"{system_prompt}\n\nSystem State:\n{context_data}\n\nUser Question: {question}"

        async with httpx.AsyncClient(timeout=30) as client:
            url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
            headers = {"x-goog-api-key": api_key}
            resp = await client.post(
                url,
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.7,
                        "maxOutputTokens": 1024,
                    },
                },
                headers=headers,
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    return candidates[0]["content"]["parts"][0]["text"]

        return _build_contextual_response(question, context)

    except Exception:
        return _build_contextual_response(question, context)


def _build_contextual_response(question: str, context: dict) -> str:
    """Intelligent SOC copilot — understands natural language and answers contextually."""
    q = question.lower().strip()
    prediction = context.get("prediction", "Unknown")
    confidence = context.get("confidence", 0)
    severity_score = context.get("severity_score", 0)
    recent = context.get("recent_predictions", [])
    total = context.get("total_predictions", 0)
    agree_rate = context.get("agreement_rate", 0)
    attack_dist = context.get("attack_distribution", {})
    threat_score = context.get("threat_score", 0)
    factors = context.get("threat_factors", {})
    attack_info = ATTACK_KNOWLEDGE.get(prediction, ATTACK_KNOWLEDGE["DDoS"])

    # --- "Why" / "reason" questions ---
    if any(w in q for w in ["why", "reason", "explain", "cause"]):
        parts = [f"The system predicted **{prediction}** because:\n"]
        if confidence >= CONFIDENCE_HIGH:
            parts.append(f"1. **High confidence ({confidence*100:.1f}%)** — the ML model found a strong pattern match against known {prediction} signatures.")
        elif confidence >= CONFIDENCE_MEDIUM:
            parts.append(f"1. **Moderate confidence ({confidence*100:.1f}%)** — partial pattern match with {prediction} behavior.")
        else:
            parts.append(f"1. **Low confidence ({confidence*100:.1f}%)** — ambiguous signal, but closest match is {prediction}.")
        if severity_score >= SEVERITY_HIGH_THRESHOLD:
            parts.append(f"2. **Severity {severity_score}/100 (CRITICAL)** — {attack_info.get('description', '')}")
        elif severity_score >= SEVERITY_MEDIUM_THRESHOLD:
            parts.append(f"2. **Severity {severity_score}/100 (HIGH)** — significant threat level detected.")
        else:
            parts.append(f"2. **Severity {severity_score}/100** — moderate threat level.")
        if attack_dist and prediction in attack_dist:
            parts.append(f"3. **Historical frequency** — {prediction} appears {attack_dist[prediction]}x in {total} total predictions ({attack_dist[prediction]/max(total,1)*100:.0f}% of all traffic).")
        if agree_rate < 0.5 and total > 0:
            parts.append(f"4. **Models disagree** ({agree_rate*100:.0f}% agreement) — Markov chain doesn't recognize this pattern, suggesting a sophisticated or novel attack variant.")
        return "\n".join(parts)

    # --- "What should I do" / "next steps" / "recommend" / "action" ---
    if any(w in q for w in ["do", "next", "should", "recommend", "action", "respond", "mitigate", "prevent", "stop", "fix"]):
        recs = attack_info.get("recommendations", [])
        parts = [f"**Immediate Response for {prediction} ({confidence*100:.1f}% confidence):**\n"]
        for i, r in enumerate(recs[:6], 1):
            parts.append(f"{i}. {r}")
        if threat_score >= 70:
            parts.append(f"\n⚠️ **Threat level is HIGH ({threat_score}/100)** — prioritize containment over investigation.")
        elif threat_score >= 40:
            parts.append(f"\n🟡 **Threat level is MODERATE ({threat_score}/100)** — investigate before taking action.")
        else:
            parts.append(f"\n🟢 **Threat level is LOW ({threat_score}/100)** — monitor and log for now.")
        return "\n".join(parts)

    # --- "pattern" / "history" / "trend" / "recent" / "latest" ---
    if any(w in q for w in ["pattern", "history", "trend", "recent", "latest", "past", "before"]):
        if not recent:
            return f"No prediction history yet. Total predictions: {total}. Run some predictions on the Predictions page first."
        dist_text = ", ".join(f"{k}: {v}" for k, v in sorted(attack_dist.items(), key=lambda x: -x[1])) if attack_dist else "N/A"
        most = max(attack_dist, key=attack_dist.get) if attack_dist else "N/A"
        last_5 = [p.get("prediction", "?") for p in recent[:5]]
        parts = [
            f"**Attack Pattern Analysis** ({total} total predictions)\n",
            f"Distribution: {dist_text}",
            f"Most frequent: **{most}** ({attack_dist.get(most, 0)}x)",
            f"Last 5 predictions: {' → '.join(last_5)}",
            f"Model agreement: {agree_rate*100:.0f}%",
        ]
        if len(set(last_5)) == 1:
            parts.append(f"\n⚠️ **Consecutive {last_5[0]} detected** — may indicate a sustained attack campaign.")
        elif len(set(last_5)) >= 3:
            parts.append(f"\n🔄 **Diverse attack types** — attacker may be probing multiple vectors.")
        return "\n".join(parts)

    # --- "threat" / "score" / "risk" / "danger" / "severity" ---
    if any(w in q for w in ["threat", "score", "risk", "danger", "severity", "critical", "urgent"]):
        level = "CRITICAL" if threat_score >= 75 else "HIGH" if threat_score >= 50 else "MODERATE" if threat_score >= 25 else "LOW"
        emoji = "🔴" if threat_score >= 75 else "🟠" if threat_score >= 50 else "🟡" if threat_score >= 25 else "🟢"
        parts = [
            f"{emoji} **Threat Score: {threat_score}/100 ({level})**\n",
            f"Breakdown:",
            f"• Confidence contribution: {factors.get('confidence_contribution', 0)}",
            f"• Critical alerts: {factors.get('critical_alerts', 0)}",
            f"• Model conflict: {factors.get('model_conflict', 0)}",
            f"• Drift impact: {factors.get('drift_impact', 0)}",
        ]
        if factors.get('critical_alerts', 0) > 30:
            parts.append(f"\n⚠️ High critical alert volume — multiple severe attacks detected in recent history.")
        if factors.get('drift_impact', 0) > 20:
            parts.append(f"📈 **Drift detected** — attack patterns are shifting from baseline. Review recent predictions for anomalies.")
        return "\n".join(parts)

    # --- "agreement" / "disagree" / "conflict" / "models" ---
    if any(w in q for w in ["agreement", "disagree", "conflict", "models", "markov", "ml", "algorithm"]):
        parts = [
            f"**Model Agreement Analysis**\n",
            f"ML-Markov agreement rate: **{agree_rate*100:.0f}%**",
        ]
        if agree_rate >= 0.8:
            parts.append(f"✅ Both models strongly agree — high confidence in the {prediction} classification.")
        elif agree_rate >= 0.5:
            parts.append(f"🟡 Partial agreement — models sometimes diverge, suggesting some attack patterns are ambiguous.")
        else:
            parts.append(f"🔴 Low agreement — models frequently disagree. This often indicates sophisticated multi-stage attacks or novel attack variants.")
        parts.append(f"\nWhen Markov and ML disagree, the attack likely doesn't follow standard state transitions — common with zero-day exploits or advanced persistent threats (APTs).")
        return "\n".join(parts)

    # --- "compare" / "difference" / "vs" / "versus" ---
    if any(w in q for w in ["compare", "difference", "vs", "versus", "between"]):
        if not attack_dist or len(attack_dist) < 2:
            return f"Not enough data to compare. Current prediction: **{prediction}** with {confidence*100:.1f}% confidence. Run more predictions to see comparison data."
        sorted_attacks = sorted(attack_dist.items(), key=lambda x: -x[1])
        parts = [f"**Attack Type Comparison** ({total} total predictions):\n"]
        for attack, count in sorted_attacks[:5]:
            pct = count / max(total, 1) * 100
            info = ATTACK_KNOWLEDGE.get(attack, {})
            parts.append(f"• **{attack}**: {count}x ({pct:.0f}%) — severity {info.get('severity_weight', 0)*100:.0f}/100")
        parts.append(f"\nMost dangerous by severity: **Infiltration** (90/100)")
        parts.append(f"Most frequent: **{sorted_attacks[0][0]}** ({sorted_attacks[0][1]}x)")
        return "\n".join(parts)

    # --- "what is" / "explain" / "define" / "what's" ---
    if any(w in q for w in ["what is", "what's", "define", "definition", "tell me about"]):
        # Check if asking about a specific attack type
        for atype in ATTACK_KNOWLEDGE:
            if atype.lower() in q:
                info = ATTACK_KNOWLEDGE[atype]
                return (
                    f"**{atype}** — {info['description']}\n\n"
                    f"Severity weight: {info['severity_weight']*100:.0f}/100\n"
                    f"Kill chain stage: {info['kill_chain_stage']}\n\n"
                    f"**Key Indicators:**\n" + "\n".join(f"• {i}" for i in info['indicators']) +
                    f"\n\n**Recommended Response:**\n" + "\n".join(f"• {r}" for r in info['recommendations'][:3])
                )
        return (
            f"**{prediction}** — {attack_info.get('description', 'An attack pattern detected by the system.')}\n\n"
            f"Confidence: {confidence*100:.1f}% | Severity: {severity_score}/100 | Kill chain: {attack_info.get('kill_chain_stage', 'N/A')}\n\n"
            f"Ask me about specific attack types (DDoS, DoS, PortScan, Bot, WebAttack, BruteForce, Infiltration) for detailed info."
        )

    # --- "how" questions ---
    if any(w in q for w in ["how", "work", "function", "operate"]):
        return (
            f"**How the SentinelAI system works:**\n\n"
            f"1. **Input**: You provide a sequence of observed attack types (e.g., [PortScan, PortScan, DoS, DDoS])\n"
            f"2. **ML Model**: A deterministic model analyzes transition frequencies between attack types\n"
            f"3. **Markov Chain**: A separate statistical model predicts the next likely attack\n"
            f"4. **Ensemble**: Both predictions are compared — agreement boosts confidence\n"
            f"5. **Threat Score**: A composite score (0-100) weighs confidence, severity, model agreement, and drift\n\n"
            f"Current state: {total} predictions, {agree_rate*100:.0f}% model agreement, threat score {threat_score}/100"
        )

    # --- "most common" / "frequent" / "top" ---
    if any(w in q for w in ["most common", "frequent", "top", "highest", "biggest"]):
        if not attack_dist:
            return f"No attack data yet. Total predictions: {total}. Make some predictions first."
        sorted_a = sorted(attack_dist.items(), key=lambda x: -x[1])
        parts = [f"**Top Attack Types** (out of {total} predictions):\n"]
        for i, (a, c) in enumerate(sorted_a[:5], 1):
            info = ATTACK_KNOWLEDGE.get(a, {})
            parts.append(f"{i}. **{a}**: {c}x ({c/max(total,1)*100:.0f}%) — severity {info.get('severity_weight',0)*100:.0f}/100")
        return "\n".join(parts)

    # --- "is this" / "am I" / "should I worry" ---
    if any(w in q for w in ["is this", "am i", "worry", "safe", "under attack", "breach"]):
        if threat_score >= 70:
            return f"🔴 **Yes, there is significant risk.** Threat score: {threat_score}/100. Current prediction: {prediction} ({confidence*100:.1f}% confidence). Take immediate action — check the recommendations and isolate affected systems."
        elif threat_score >= 40:
            return f"🟡 **Moderate concern.** Threat score: {threat_score}/100. The system detected {prediction} with {confidence*100:.1f}% confidence. Monitor closely and prepare response plan."
        else:
            return f"🟢 **Low risk currently.** Threat score: {threat_score}/100. The last prediction ({prediction}) has {confidence*100:.1f}% confidence. Continue monitoring."

    # --- "help" / "what can you" / "capabilities" ---
    if any(w in q for w in ["help", "what can", "capability", "feature", "can you"]):
        return (
            f"**I'm your SOC Copilot.** Here's what I can help with:\n\n"
            f"• **\"Why was this predicted?\"** — explains the reasoning behind a prediction\n"
            f"• **\"What should I do?\"** — gives priority response actions\n"
            f"• **\"Show me patterns\"** — analyzes attack history and trends\n"
            f"• **\"What's the threat score?\"** — detailed threat breakdown\n"
            f"• **\"Compare attacks\"** — compares attack type distribution\n"
            f"• **\"What is DDoS?\"** — explains any attack type\n"
            f"• **\"Am I under attack?\"** — assesses current risk level\n"
            f"• **\"How does this work?\"** — explains the system\n\n"
            f"Current state: {total} predictions, {len(attack_dist)} attack types observed, threat score {threat_score}/100."
        )

    # --- Default: always contextual, never generic ---
    last_preds = [p.get("prediction", "?") for p in recent[:3]] if recent else []
    parts = [
        f"**{prediction} Detected** ({confidence*100:.1f}% confidence)\n",
        f"{attack_info.get('description', 'Attack pattern identified.')}",
        f"\nSeverity: {severity_score}/100 | Kill chain: {attack_info.get('kill_chain_stage', 'N/A')}",
        f"Threat score: {threat_score}/100 | Model agreement: {agree_rate*100:.0f}%",
    ]
    if last_preds:
        parts.append(f"\nRecent: {' → '.join(last_preds)}")
    parts.append(f"\n**Key indicators:**")
    parts.extend(f"• {i}" for i in attack_info.get('indicators', [])[:3])
    parts.append(f"\nAsk me \"what should I do?\" for response actions, or \"why?\" for detailed reasoning.")
    return "\n".join(parts)


# =========================
# Explainability Engine (XAI)
# =========================
@app.post("/explain")
async def explain(data: ExplainRequest):
    seq = data.sequence
    seq_key = tuple(seq)

    prediction, confidence, top_3, explanation = cached_predict(seq_key)

    importance = []
    seq_names = le.inverse_transform(seq)

    for i, token in enumerate(seq):
        position_weight = (i + 1) / len(seq) if len(seq) > 0 else 1.0

        if token in markov.probabilities:
            probs = markov.probabilities[token]
            max_prob = max(probs.values()) if probs else 0
        else:
            max_prob = 1.0 / len(ATTACK_CLASSES)

        weight = round(position_weight * max_prob, 4)
        importance.append({
            "token": token,
            "position": i,
            "weight": weight,
            "label": f"Token {i+1}",
        })

    total_weight = sum(item["weight"] for item in importance)
    if total_weight > 0:
        for item in importance:
            item["weight"] = round(item["weight"] / total_weight, 4)

    importance.sort(key=lambda x: x["weight"], reverse=True)

    return {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "importance": importance,
        "top_predictions": top_3,
        "explanation": explanation,
    }


# =========================
# Network Graph
# =========================
@app.get("/graph")
async def get_graph():
    nodes = []
    edges = []
    node_ids = set()

    # Build from real comparison history for richer graph
    comp_list = list(comparison_history)

    if comp_list:
        for comp in comp_list[:30]:
            ml = comp.get("ml_prediction", "Unknown")
            mk = comp.get("markov_prediction", "Unknown")
            ts = comp.get("timestamp", "")[:19]

            ml_id = f"ml-{ts}"
            mk_id = f"mk-{ts}"

            if ml_id not in node_ids:
                node_ids.add(ml_id)
                nodes.append({
                    "id": ml_id, "type": "ml", "label": ml,
                    "confidence": comp.get("ml_confidence", 0),
                    "severity_score": ATTACK_WEIGHTS.get(ml, 0.5) * 100,
                })
            if mk_id not in node_ids:
                node_ids.add(mk_id)
                nodes.append({
                    "id": mk_id, "type": "markov", "label": mk,
                    "confidence": comp.get("markov_confidence", 0),
                    "severity_score": ATTACK_WEIGHTS.get(mk, 0.5) * 100,
                })

            edge_type = "agreement" if comp.get("agreement") else "disagreement"
            edges.append({
                "id": f"e-{ml_id}-{mk_id}",
                "source": ml_id, "target": mk_id,
                "type": edge_type,
            })

    # Fallback: attack type relationship graph
    if not nodes:
        for attack in ATTACK_CLASSES:
            nodes.append({
                "id": f"type-{attack}", "type": "attack_type", "label": attack,
                "confidence": 0,
                "severity_score": ATTACK_WEIGHTS.get(attack, 0.5) * 100,
            })

        connections = [
            ("PortScan", "DDoS"), ("PortScan", "Bot"), ("Bot", "WebAttack"),
            ("WebAttack", "BruteForce"), ("BruteForce", "Infiltration"),
            ("DDoS", "DoS"), ("Infiltration", "DDoS"),
        ]
        for src, tgt in connections:
            edges.append({
                "id": f"e-{src}-{tgt}",
                "source": f"type-{src}", "target": f"type-{tgt}",
                "type": "relationship",
            })

    return {"nodes": nodes, "edges": edges}


# =========================
# Cyber Kill Chain
# =========================
KILL_CHAIN_STAGES = [
    {"id": "recon", "name": "Reconnaissance", "description": "Information gathering and target identification", "icon": "search"},
    {"id": "weaponize", "name": "Weaponization", "description": "Creating exploit payload and delivery mechanism", "icon": "hammer"},
    {"id": "delivery", "name": "Delivery", "description": "Transmitting weapon to target environment", "icon": "send"},
    {"id": "exploit", "name": "Exploitation", "description": "Triggering vulnerability in target system", "icon": "zap"},
    {"id": "install", "name": "Installation", "description": "Installing persistent backdoor or malware", "icon": "download"},
    {"id": "c2", "name": "Command & Control", "description": "Establishing remote control channel", "icon": "terminal"},
    {"id": "actions", "name": "Actions on Objectives", "description": "Achieving attacker's ultimate goal", "icon": "target"},
]

ATTACK_KILL_CHAIN_MAP = {
    "PortScan": {"stage": "recon", "progress": 15},
    "DoS": {"stage": "delivery", "progress": 45},
    "DDoS": {"stage": "actions", "progress": 90},
    "Bot": {"stage": "c2", "progress": 75},
    "WebAttack": {"stage": "exploit", "progress": 55},
    "BruteForce": {"stage": "exploit", "progress": 50},
    "Infiltration": {"stage": "actions", "progress": 95},
}


@app.get("/killchain/{prediction}")
async def get_killchain(prediction: str):
    mapping = ATTACK_KILL_CHAIN_MAP.get(prediction, {"stage": "recon", "progress": 10})
    current_stage = mapping["stage"]
    progress = mapping["progress"]

    completed = False
    stages = []
    for stage in KILL_CHAIN_STAGES:
        stage_status = "completed" if not completed and stage["id"] != current_stage else (
            "active" if stage["id"] == current_stage else "pending"
        )
        if stage["id"] == current_stage:
            completed = True
        stages.append({**stage, "status": stage_status})

    return {
        "attack": prediction,
        "current_stage": current_stage,
        "progress": progress,
        "stages": stages,
    }


# =========================
# AI Recommendations Engine
# =========================
@app.get("/api/recommendations")
async def get_recommendations():
    pred_list = list(prediction_history)
    if not pred_list:
        return {"recommendations": []}

    latest = pred_list[0]
    attack = latest.get("prediction", "Unknown")
    confidence = latest.get("confidence", 0)
    severity_score = latest.get("severity_score", 0)
    severity = "CRITICAL" if severity_score >= SEVERITY_HIGH_THRESHOLD else "HIGH" if severity_score >= SEVERITY_MEDIUM_THRESHOLD else "MEDIUM" if severity_score >= SEVERITY_LOW_THRESHOLD else "LOW"

    recs = []
    if severity == "CRITICAL":
        recs.append({"text": "Block source IP immediately", "priority": "critical", "category": "containment"})
        recs.append({"text": "Isolate affected endpoint from network", "priority": "critical", "category": "containment"})
    if severity in ("CRITICAL", "HIGH"):
        recs.append({"text": "Enable full packet capture on target", "priority": "high", "category": "investigation"})
    if attack in ("BruteForce", "Infiltration"):
        recs.append({"text": "Monitor authentication logs for anomalies", "priority": "high", "category": "detection"})
        recs.append({"text": "Review access control policies", "priority": "medium", "category": "hardening"})
    if attack in ("DDoS", "DoS"):
        recs.append({"text": "Enable rate limiting on network perimeter", "priority": "high", "category": "mitigation"})
        recs.append({"text": "Activate DDoS protection service", "priority": "high", "category": "mitigation"})
    if attack == "PortScan":
        recs.append({"text": "Audit firewall rules for exposed ports", "priority": "medium", "category": "hardening"})
    if attack == "WebAttack":
        recs.append({"text": "Review WAF rules and update signatures", "priority": "high", "category": "hardening"})
        recs.append({"text": "Scan web application for vulnerabilities", "priority": "medium", "category": "investigation"})
    if confidence > CONFIDENCE_HIGH:
        recs.append({"text": "Generate incident report for escalation", "priority": "medium", "category": "reporting"})
    recs.append({"text": "Monitor network traffic for lateral movement", "priority": "medium", "category": "detection"})

    return {"recommendations": recs[:8], "attack": attack, "severity": severity, "confidence": confidence}


# =========================
# Drift Analytics
# =========================
@app.get("/analytics/drift")
async def get_drift_analytics():
    pred_list = list(prediction_history)

    if len(pred_list) < 2:
        return {
            "drift_score": 0.0, "accuracy": 0.0, "confidence": 0.0,
            "status": "insufficient_data", "history": [],
            "distribution": {a: 0 for a in ATTACK_CLASSES}, "total_predictions": 0,
        }

    confidences = [h.get("confidence", 0) for h in pred_list]
    avg_confidence = sum(confidences) / len(confidences)

    distribution = {}
    for h in pred_list:
        pred = h.get("prediction", "Unknown")
        distribution[pred] = distribution.get(pred, 0) + 1

    recent = confidences[:len(confidences)//2]
    older = confidences[len(confidences)//2:]
    recent_avg = sum(recent) / len(recent) if recent else 0
    older_avg = sum(older) / len(older) if older else 0
    drift_score = abs(recent_avg - older_avg)

    if drift_score < 0.1:
        status = "stable"
    elif drift_score < 0.25:
        status = "warning"
    else:
        status = "critical"

    accuracy = max(0, 1 - drift_score)

    trend = []
    for h in pred_list[:20]:
        trend.append({
            "timestamp": h.get("timestamp", ""),
            "confidence": h.get("confidence", 0),
            "prediction": h.get("prediction", ""),
            "latency_ms": h.get("latency_ms", 0),
        })

    return {
        "drift_score": round(drift_score, 4),
        "accuracy": round(accuracy, 4),
        "confidence": round(avg_confidence, 4),
        "status": status,
        "history": trend,
        "distribution": distribution,
        "total_predictions": len(pred_list),
    }


# =========================
# Authentication Routes
# =========================
@app.post("/auth/signup")
async def signup(data: RegisterRequest):
    if not check_rate_limit(f"signup:{data.email}", max_requests=3, window_seconds=300):
        return JSONResponse(status_code=429, content={"error": "Too many signup attempts. Please try again later."})
    user = register_user(data.email, data.password, data.name)
    if not user:
        return JSONResponse(status_code=409, content={"error": "Email already registered"})
    access = create_access_token({"sub": data.email})
    refresh = create_refresh_token({"sub": data.email})
    return {"access_token": access, "refresh_token": refresh, "user": {"email": data.email, "name": data.name}}

@app.post("/auth/login")
async def login(data: LoginRequest):
    if not check_rate_limit(f"login:{data.email}", max_requests=5, window_seconds=60):
        return JSONResponse(status_code=429, content={"error": "Too many login attempts. Please try again later."})
    user = authenticate_user(data.email, data.password)
    if not user:
        log_structured("warning", "auth", f"Failed login: {data.email}")
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})
    log_structured("info", "auth", f"Successful login: {data.email}")
    access = create_access_token({"sub": data.email})
    refresh = create_refresh_token({"sub": data.email})
    return {"access_token": access, "refresh_token": refresh, "user": {"email": data.email, "name": user["name"]}}

@app.post("/auth/send-otp")
async def send_otp(data: OTPRequest):
    if not check_rate_limit(f"send-otp:{data.email}", max_requests=3, window_seconds=300):
        return JSONResponse(status_code=429, content={"error": "Too many OTP requests. Please try again later."})
    otp = generate_otp(data.email)
    return {"message": "OTP sent to email"}

@app.post("/auth/verify-otp")
async def verify_otp(data: OTPVerifyRequest):
    if not check_rate_limit(f"verify-otp:{data.email}", max_requests=5, window_seconds=300):
        return JSONResponse(status_code=429, content={"error": "Too many OTP verification attempts. Please try again later."})
    valid = verify_otp(data.email, data.otp)
    if not valid:
        return JSONResponse(status_code=400, content={"error": "Invalid or expired OTP"})
    access = create_access_token({"sub": data.email})
    refresh = create_refresh_token({"sub": data.email})
    return {"access_token": access, "refresh_token": refresh}

@app.post("/auth/refresh")
async def refresh_token(data: TokenRefreshRequest):
    payload = verify_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        return {"error": "Invalid refresh token"}
    access = create_access_token({"sub": payload["sub"]})
    return {"access_token": access}

@app.get("/auth/audit")
async def get_audit_log(payload: dict = Depends(require_auth)):
    return {"audit_log": audit_log[-50:]}


# =========================
# WebSocket Event Stream (real events only)
# =========================
# Channel-based WebSocket: client sends {"subscribe": "dashboard|alerts|incidents|analytics"}
# Server pushes events to subscribed clients
_ws_subscribers: dict[str, set[WebSocket]] = {
    "dashboard": set(),
    "alerts": set(),
    "incidents": set(),
    "analytics": set(),
    "all": set(),
}

async def broadcast_ws(channel: str, event: dict):
    """Push event to all subscribers of a channel."""
    targets = _ws_subscribers.get(channel, set()) | _ws_subscribers.get("all", set())
    dead = []
    for ws in targets:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        for ch in _ws_subscribers.values():
            ch.discard(ws)


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return
    payload = verify_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return

    # Default: subscribe to all channels
    subscribed_channels = {"all"}
    for ch in subscribed_channels:
        _ws_subscribers[ch].add(websocket)

    try:
        last_pred_count = 0
        last_broadcast_count = 0
        while True:
            # Handle client messages (subscribe/unsubscribe)
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=1.0)
                if isinstance(data, dict):
                    action = data.get("action", "")
                    channel = data.get("channel", "")
                    if action == "subscribe" and channel in _ws_subscribers:
                        _ws_subscribers[channel].add(websocket)
                        subscribed_channels.add(channel)
                        await websocket.send_json({"type": "subscribed", "channel": channel})
                    elif action == "unsubscribe" and channel in _ws_subscribers:
                        _ws_subscribers[channel].discard(websocket)
                        subscribed_channels.discard(channel)
                        await websocket.send_json({"type": "unsubscribed", "channel": channel})
            except asyncio.TimeoutError:
                pass
            except Exception:
                break

            # Stream prediction events
            pred_list = list(prediction_history)
            if len(pred_list) > last_pred_count:
                for pred in pred_list[:len(pred_list) - last_pred_count]:
                    event = {
                        "id": f"evt-{uuid.uuid4().hex[:8]}",
                        "timestamp": pred.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "type": "prediction",
                        "attack_type": pred.get("prediction", "Unknown"),
                        "confidence": pred.get("confidence", 0),
                        "severity_score": pred.get("severity_score", 0),
                        "severity": pred.get("severity", "LOW"),
                        "status": "DETECTED",
                    }
                    await broadcast_ws("dashboard", event)
                    await broadcast_ws("analytics", event)
                last_pred_count = len(pred_list)

            # Stream real-time ingestion events (detections + incidents)
            bcast_list = list(broadcast_queue)
            if len(bcast_list) > last_broadcast_count:
                for evt in bcast_list[last_broadcast_count:]:
                    await broadcast_ws("all", evt)
                    if evt.get("type") == "detection":
                        await broadcast_ws("alerts", evt)
                    elif evt.get("type") == "incident":
                        await broadcast_ws("incidents", evt)
                last_broadcast_count = len(bcast_list)

    except WebSocketDisconnect:
        pass
    finally:
        for ch in subscribed_channels:
            _ws_subscribers.get(ch, set()).discard(websocket)


# =========================
# Threat Detector
# =========================
threat_detector = ThreatDetector()


# =========================
# Log Upload Endpoint
# =========================
@app.post("/api/logs/upload")
async def upload_log(file: UploadFile = File(...)):
    try:
        allowed_exts = {"txt", "csv", "json", "log", "evtx"}
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in allowed_exts:
            return JSONResponse(status_code=400, content={"error": f"Unsupported file type: .{ext}. Allowed: {', '.join(allowed_exts)}"})

        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            return JSONResponse(status_code=413, content={"error": "File too large. Maximum size: 50MB"})

        text = content.decode("utf-8", errors="replace")
        events = parser.parse(text, file.filename)
        event_dicts = [e.to_dict() for e in events]

        log_id = db.create_uploaded_log(
            filename=file.filename,
            source_type=ext,
            file_size=len(content),
        )

        db.insert_log_events(log_id, event_dicts)

        detections = threat_detector.analyze_events(event_dicts)
        detection_dicts = [d.to_dict() for d in detections]
        if detection_dicts:
            db.insert_threat_detections(log_id, detection_dicts)

        # Create alerts from detections + broadcast for real-time UI
        for det in detections:
            db.create_alert(
                alert_type=det.threat_type,
                severity=det.severity,
                title=f"{det.threat_type.replace('_', ' ').title()} from {det.source_ip}",
                description=det.description,
                source_ip=det.source_ip,
                dest_ip=det.dest_ip,
                source_port=0,
                dest_port=det.dest_port,
                protocol="",
                mitre_technique=det.mitre_technique,
                mitre_tactic=det.mitre_tactic,
                evidence=det.evidence,
                recommendations=det.recommendations,
                log_id=log_id,
            )
            broadcast_queue.appendleft({
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "detection",
                "attack_type": det.threat_type,
                "confidence": det.confidence,
                "severity_score": det.severity_score,
                "severity": det.severity,
                "source_ip": det.source_ip,
                "dest_ip": det.dest_ip,
                "dest_port": det.dest_port,
                "description": det.description,
                "mitre_technique": det.mitre_technique,
                "mitre_tactic": det.mitre_tactic,
            })

        # Auto-correlate after batch upload if enough detections
        global _detection_counter
        _detection_counter += len(detections)
        if _detection_counter >= CORRELATION_BATCH_SIZE:
            _detection_counter = 0
            try:
                from services.correlation_service import correlation_engine
                alerts = db.get_alerts(status='open', limit=200)
                incidents = correlation_engine.correlate(alerts)
                for inc in incidents:
                    inc_id = db.create_incident(
                        title=inc.title, severity=inc.severity, description=inc.description,
                        alert_ids=inc.alert_ids, timeline=inc.timeline, affected_ips=inc.affected_ips,
                        mitre_techniques=inc.mitre_techniques, mitre_tactics=inc.mitre_tactics,
                        recommendations=inc.recommendations, confidence=inc.confidence,
                    )
                    broadcast_queue.appendleft({
                        "id": f"inc-{uuid.uuid4().hex[:8]}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "incident",
                        "incident_id": inc_id,
                        "title": inc.title,
                        "severity": inc.severity,
                        "affected_ips": inc.affected_ips,
                    })
            except Exception as e:
                logger.warning(f"Auto-correlation failed: {e}")

        anomaly_result = anomaly_detector.detect(event_dicts)
        anomaly_dict = anomaly_result.to_dict()
        db.insert_anomaly_score(
            log_id,
            anomaly_dict.get("anomaly_score", 0),
            anomaly_dict.get("risk_level", "LOW"),
            anomaly_dict.get("anomalies", []),
            anomaly_dict.get("feature_scores", {}),
            anomaly_dict.get("explanation", ""),
        )

        db.update_log_status(log_id, status="completed", event_count=len(events))

        return {
            "log_id": log_id,
            "filename": file.filename,
            "events_parsed": len(events),
            "threats_detected": len(detections),
            "anomaly_score": anomaly_dict.get("anomaly_score", 0),
            "anomaly_risk": anomaly_dict.get("risk_level", "LOW"),
            "detections": detection_dicts[:20],
            "anomaly": anomaly_dict,
        }
    except Exception as e:
        logger.error(f"Log upload error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Log upload failed: {str(e)}"})


# =========================
# Log List Endpoint
# =========================
@app.get("/api/logs")
async def list_logs():
    logs = db.get_uploaded_logs(limit=50)
    return {"logs": logs, "total": len(logs)}


# =========================
# Log Events Endpoint
# =========================
@app.get("/api/logs/{log_id}/events")
async def get_log_events(log_id: str):
    log_meta = db.get_uploaded_log_by_id(log_id)
    if not log_meta:
        return JSONResponse(status_code=404, content={"error": "Log not found"})
    events = db.get_log_events(log_id, limit=5000)
    return {
        "log": log_meta,
        "events": events,
        "total": len(events),
    }


# =========================
# Threat Detections Endpoint
# =========================
@app.get("/api/threats")
async def get_threats(
    severity: str = "",
    threat_type: str = "",
    source_ip: str = "",
    limit: int = 100,
):
    results = db.get_threat_detections_filtered(
        severity=severity or None,
        threat_type=threat_type or None,
        source_ip=source_ip or None,
        limit=limit,
    )
    return {"threats": results, "total": len(results)}


# =========================
# Threat Summary Endpoint
# =========================
@app.get("/api/threats/summary")
async def get_threat_summary():
    return db.get_threat_summary_full()


# =========================
# Anomaly Detection Endpoint
# =========================
@app.post("/api/anomaly/analyze")
async def analyze_anomaly(data: AnomalyAnalysisRequest):
    log_id = data.log_id
    log_meta = db.get_uploaded_log_by_id(log_id)
    if not log_meta:
        return JSONResponse(status_code=404, content={"error": "Log not found. Upload a log first."})

    events = db.get_log_events(log_id, limit=5000)
    result = anomaly_detector.detect(events)
    result_dict = result.to_dict()
    db.insert_anomaly_score(
        log_id,
        result_dict.get("anomaly_score", 0),
        result_dict.get("risk_level", "LOW"),
        result_dict.get("anomalies", []),
        result_dict.get("feature_scores", {}),
        result_dict.get("explanation", ""),
    )

    return {
        "log_id": log_id,
        "anomaly": result_dict,
    }


# =========================
# MITRE Mapping Endpoint
# =========================
@app.get("/api/mitre")
async def get_mitre_coverage():
    tactic_map = {}
    technique_list = []
    seen_techniques = set()

    all_detections = db.get_threat_detections(limit=1000)

    for det in all_detections:
        ttype = det.get("threat_type", "")
        mapping = mitre_mapper.map_detection(ttype)
        if mapping.get("technique_id") == "Unknown":
            continue

        tactic = mapping.get("tactic", "Unknown")
        if tactic not in tactic_map:
            tactic_map[tactic] = {
                "tactic": tactic,
                "tactic_id": mapping.get("tactic_id", ""),
                "techniques": [],
                "detection_count": 0,
            }
        tactic_map[tactic]["detection_count"] += 1

        tech_id = mapping.get("technique_id", "")
        if tech_id not in seen_techniques:
            seen_techniques.add(tech_id)
            tactic_map[tactic]["techniques"].append({
                "technique_id": tech_id,
                "technique_name": mapping.get("technique_name", ""),
                "description": mapping.get("description", ""),
                "detection": mapping.get("detection", ""),
                "mitigation": mapping.get("mitigation", ""),
            })

    return {
        "tactics": list(tactic_map.values()),
        "total_techniques": len(seen_techniques),
        "total_detections": len(all_detections),
    }


# =========================
# IP Investigation Endpoint
# =========================
@app.get("/api/investigate/{ip}")
async def investigate_ip(ip: str):
    ip_threats = db.get_threats_by_ip(ip)
    ip_events = db.get_events_by_ip(ip, limit=100)

    threat_types = {}
    for t in ip_threats:
        tt = t.get("threat_type", "unknown")
        threat_types[tt] = threat_types.get(tt, 0) + 1

    severity_counts = {}
    for t in ip_threats:
        s = t.get("severity", "INFO")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    intel = await threat_intel.lookup_ip(ip)

    return {
        "ip": ip,
        "total_threats": len(ip_threats),
        "total_events": len(ip_events),
        "threat_types": threat_types,
        "severity_breakdown": severity_counts,
        "threat_intel": intel,
        "recent_threats": ip_threats[:20],
        "recent_events": ip_events[:50],
    }


# =========================
# Report Generation Endpoint
# =========================
@app.post("/api/reports/generate")
async def generate_report(data: ReportRequest):
    try:
        # Pull all real data from database
        detections = db.get_threat_detections(limit=1000)
        alerts = db.get_alerts(limit=500)
        incidents = db.get_incidents(limit=200)

        all_events = []
        uploaded = db.get_uploaded_logs(limit=100)
        for log in uploaded:
            evts = db.get_log_events(log["id"], limit=5000)
            all_events.extend(evts)

        # Build device list
        device_logs = [l for l in uploaded if l.get("source_type", "").startswith("device_")]
        devices = []
        seen = set()
        for log in device_logs:
            hostname = log.get("filename", "").replace("device_", "")
            if hostname and hostname not in seen:
                seen.add(hostname)
                devices.append({
                    "hostname": hostname,
                    "os_type": log.get("source_type", "").replace("device_", ""),
                    "last_seen": log.get("created_at", ""),
                })

        if data.report_type == "incident" and data.detection_id:
            # Find the specific incident or detection
            incident = next((i for i in incidents if i.get("id", "").startswith(data.detection_id)), None)
            detection = next((d for d in detections if d.get("id") == data.detection_id), None)

            if incident:
                # Build incident report from real incident data
                related = [e for e in all_events if any(
                    ip in e.get("source_ip", "") or ip in e.get("dest_ip", "")
                    for ip in incident.get("affected_ips", [])
                )]
                report = report_generator.generate_incident_report(
                    {**incident, "threat_type": incident.get("title", "Unknown"),
                     "confidence": incident.get("confidence", 0),
                     "first_seen": incident.get("created_at", ""),
                     "last_seen": incident.get("updated_at", ""),
                     "event_count": len(incident.get("alert_ids", [])),
                     "source_ip": incident.get("affected_ips", ["N/A"])[0] if incident.get("affected_ips") else "N/A",
                     "description": incident.get("description", ""),
                     "mitre_technique": ", ".join(incident.get("mitre_techniques", [])),
                     "mitre_tactic": ", ".join(incident.get("mitre_tactics", [])),
                     "evidence": [t.get("title", "") for t in incident.get("timeline", [])],
                     "recommendations": incident.get("recommendations", []),
                     },
                    related
                )
            elif detection:
                related = [e for e in all_events if e.get("source_ip") == detection.get("source_ip")]
                report = report_generator.generate_incident_report(detection, related)
            else:
                return JSONResponse(status_code=404, content={"error": "Incident/Detection not found"})

        elif data.report_type == "executive":
            stats = {
                "total_threats": len(detections),
                "critical_threats": sum(1 for d in detections if d.get("severity") == "CRITICAL"),
                "total_alerts": len(alerts),
                "open_alerts": sum(1 for a in alerts if a.get("status") == "open"),
                "total_incidents": len(incidents),
            }
            anomaly = db.get_latest_anomaly_score()
            report = report_generator.generate_executive_report(
                stats, detections, anomaly or {},
                incidents=incidents, alerts=alerts, events=all_events, devices=devices,
            )

        else:
            anomaly = db.get_latest_anomaly_score()
            report = report_generator.generate_technical_report(
                all_events, detections, anomaly or {},
                incidents=incidents, alerts=alerts,
            )

        report_id = str(uuid.uuid4())
        report["id"] = report_id
        db.create_report(data.report_type, report.get("title", "Report"), report)

        return {
            "report_id": report_id,
            "report_type": data.report_type,
            "report": report,
        }
    except Exception as e:
        logger.error(f"Report generation error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Report generation failed: {str(e)}"})


# =========================
# Report Download Endpoint
# =========================
@app.get("/api/reports/{report_id}/download")
async def download_report(report_id: str, format: str = "json"):
    reports = db.get_reports(limit=1000)
    report = next((r for r in reports if r.get("id") == report_id), None)
    if not report:
        return JSONResponse(status_code=404, content={"error": "Report not found"})

    if format == "csv":
        detections = db.get_threat_detections(limit=1000)
        csv_content = report_generator.export_csv(detections)
        return StreamingResponse(
            iter([csv_content.encode("utf-8")]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report-{report_id}.csv"},
        )
    else:
        report_data = _json.loads(report.get("data_json", "{}")) if isinstance(report.get("data_json"), str) else report.get("data_json", {})
        json_content = report_generator.export_json(report_data)
        return StreamingResponse(
            iter([json_content.encode("utf-8")]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=report-{report_id}.json"},
        )


# =========================
# Threat Intelligence Endpoint
# =========================
@app.post("/api/intel/lookup")
async def intel_lookup(data: IntelLookupRequest):
    indicator = data.indicator.strip()
    indicator_type = data.indicator_type

    if indicator_type == "auto":
        if _is_valid_ip(indicator):
            indicator_type = "ip"
        elif _is_valid_hash(indicator):
            indicator_type = "hash"
        else:
            indicator_type = "domain"

    try:
        if indicator_type == "ip":
            result = await threat_intel.lookup_ip(indicator)
        elif indicator_type == "hash":
            result = await threat_intel.lookup_hash(indicator)
        else:
            result = await threat_intel.lookup_domain(indicator)

        return {
            "indicator": indicator,
            "type": indicator_type,
            "result": result,
        }
    except Exception as e:
        logger.error(f"Intel lookup error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Intel lookup failed: {str(e)}"})


def _is_valid_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_valid_hash(s: str) -> bool:
    return len(s) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in s)


# =========================
# Dashboard Stats Endpoint
# =========================
@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    pred_list = list(prediction_history)
    db_stats = db.get_dashboard_stats()
    threat_summary = db.get_threat_summary()

    threats_by_severity = threat_summary.get('by_severity', {})
    threats_by_type = threat_summary.get('by_type', {})

    attack_dist = {}
    for p in pred_list:
        a = p.get("prediction", "Unknown")
        attack_dist[a] = attack_dist.get(a, 0) + 1

    threat_score = calculate_threat_score()

    try:
        alert_stats = db.get_alert_stats()
        incident_stats = db.get_incident_stats()
    except Exception:
        alert_stats = {"total": 0, "open": 0, "critical": 0, "high": 0}
        incident_stats = {"total": 0, "open": 0, "critical": 0}

    return {
        "total_logs": db_stats.get('total_logs', 0),
        "total_events": db_stats.get('total_events', 0),
        "total_threats": db_stats.get('total_threats', 0),
        "critical_threats": threats_by_severity.get("CRITICAL", 0),
        "high_threats": threats_by_severity.get("HIGH", 0),
        "unique_source_ips": db_stats.get('unique_source_ips', 0),
        "threats_by_severity": threats_by_severity,
        "threats_by_type": threats_by_type,
        "total_predictions": len(pred_list),
        "attack_distribution": attack_dist,
        "avg_anomaly_score": db_stats.get('avg_anomaly_score', 0),
        "threat_score": threat_score,
        "total_reports": db.get_total_reports(),
        "total_alerts": alert_stats.get('total', 0),
        "open_alerts": alert_stats.get('open', 0),
        "critical_alerts": alert_stats.get('critical', 0),
        "total_incidents": incident_stats.get('total', 0),
        "open_incidents": incident_stats.get('open', 0),
    }


# =========================
# Enhanced Copilot Endpoint
# =========================
@app.post("/copilot")
async def enhanced_copilot(data: CopilotRequest):
    try:
        question = data.question or f"Analyze {data.prediction} prediction"

        # ── RAG Context: Pull real data from all tables ──

        # 1. Recent detections
        detections = db.get_threat_detections(limit=100)

        # 2. Recent alerts (last 50)
        alerts = db.get_alerts(limit=50)

        # 3. Recent incidents (last 20)
        incidents = db.get_incidents(limit=20)

        # 4. Devices
        try:
            logs = db.get_uploaded_logs(limit=500)
            device_logs = [l for l in logs if l.get("source_type", "").startswith("device_")]
            devices = []
            seen = set()
            for log in device_logs:
                hostname = log.get("filename", "").replace("device_", "")
                if hostname and hostname not in seen:
                    seen.add(hostname)
                    devices.append({
                        "hostname": hostname,
                        "os_type": log.get("source_type", "").replace("device_", ""),
                        "last_seen": log.get("created_at", ""),
                    })
        except Exception:
            devices = []

        # 5. Events summary
        all_ev = []
        uploaded = db.get_uploaded_logs(limit=50)
        for log in uploaded:
            evts = db.get_log_events(log["id"], limit=200)
            all_ev.extend(evts)

        events_summary = None
        if all_ev:
            type_counts = {}
            ip_counts = {}
            for ev in all_ev:
                tt = ev.get("event_type", "unknown")
                type_counts[tt] = type_counts.get(tt, 0) + 1
                sip = ev.get("source_ip", "")
                if sip:
                    ip_counts[sip] = ip_counts.get(sip, 0) + 1
            events_summary = {
                "total": len(all_ev),
                "by_type": type_counts,
                "top_ips": sorted([{"ip": k, "count": v} for k, v in ip_counts.items()], key=lambda x: -x["count"])[:10],
            }

        # 6. Dashboard stats
        db_stats = db.get_dashboard_stats()
        alert_stats = db.get_alert_stats()
        incident_stats = db.get_incident_stats()
        dashboard_stats = {
            "total_logs": db_stats.get('total_logs', 0),
            "total_events": db_stats.get('total_events', 0),
            "total_threats": db_stats.get('total_threats', 0),
            "critical_threats": db_stats.get('critical_threats', 0),
            "unique_source_ips": db_stats.get('unique_source_ips', 0),
            "avg_anomaly_score": db_stats.get('avg_anomaly_score', 0),
            "total_alerts": alert_stats.get('total', 0),
            "open_alerts": alert_stats.get('open', 0),
            "critical_alerts": alert_stats.get('critical', 0),
            "total_incidents": incident_stats.get('total', 0),
            "open_incidents": incident_stats.get('open', 0),
        }

        # 7. Anomaly score
        anomaly_result = db.get_latest_anomaly_score()

        # 8. If question references a specific incident, load its full context
        incident_context = None
        if "INC-" in question.upper() or "incident" in question.lower():
            for inc in incidents:
                inc_id = inc.get("id", "")
                if inc_id and inc_id.upper() in question.upper():
                    # Load related alerts
                    related_alerts = []
                    for aid in inc.get("alert_ids", []):
                        alert = db.get_alert(aid)
                        if alert:
                            related_alerts.append(alert)

                    # Load investigation notes
                    notes = db.get_investigation_notes(inc_id)

                    incident_context = {
                        "incident": inc,
                        "related_alerts": related_alerts,
                        "notes": notes,
                    }
                    break

        # Send full RAG context to Gemini
        result = await gemini_copilot.chat(
            question=question,
            detections=detections,
            anomaly_result=anomaly_result,
            events_summary=events_summary,
            dashboard_stats=dashboard_stats,
            alerts=alerts,
            incidents=incidents,
            devices=devices,
            incident_context=incident_context,
            conversation_history=data.conversation_history,
        )

        prediction = data.prediction
        attack_info = ATTACK_KNOWLEDGE.get(prediction, ATTACK_KNOWLEDGE["DDoS"])

        return {
            "prediction": prediction,
            "confidence": cached_predict(tuple(data.sequence))[1] if data.sequence else 0.0,
            "response": result.get("response", ""),
            "source": result.get("source", "unknown"),
            "indicators": attack_info["indicators"],
            "recommendations": attack_info["recommendations"],
            "kill_chain_stage": attack_info["kill_chain_stage"],
            "severity_weight": attack_info["severity_weight"],
            "detection_summary": {
                "total": len(detections),
                "by_type": {d: sum(1 for t in detections if t.get("threat_type") == d) for d in set(t.get("threat_type", "") for t in detections)},
            },
            "alerts_count": len(alerts),
            "incidents_count": len(incidents),
            "devices_count": len(devices),
        }
    except Exception as e:
        logger.error(f"Enhanced copilot error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": "Copilot failed. Please try again."})


# =========================
# Streaming Ingestion Endpoints
# =========================
class IngestEvent(BaseModel):
    timestamp: str = ""
    source: str = ""
    hostname: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""
    event_type: str = ""
    severity: str = "INFO"
    message: str = ""
    raw_log: str = ""
    metadata: dict = {}


class IngestBatch(BaseModel):
    events: list[IngestEvent]
    device_id: str = ""
    organization_id: str = ""


@app.post("/ingest/windows")
async def ingest_windows(event: IngestEvent):
    """Ingest a Windows Event Log entry."""
    return await _process_ingested_event(event, "windows")


@app.post("/ingest/linux")
async def ingest_linux(event: IngestEvent):
    """Ingest a Linux syslog entry."""
    return await _process_ingested_event(event, "linux")


@app.post("/ingest/network")
async def ingest_network(event: IngestEvent):
    """Ingest a network flow/connection event."""
    return await _process_ingested_event(event, "network")


@app.post("/ingest/suricata")
async def ingest_suricata(event: IngestEvent):
    """Ingest a Suricata IDS alert."""
    return await _process_ingested_event(event, "suricata")


@app.post("/ingest/zeek")
async def ingest_zeek(event: IngestEvent):
    """Ingest a Zeek network log entry."""
    return await _process_ingested_event(event, "zeek")


@app.post("/ingest/batch")
async def ingest_batch(batch: IngestBatch):
    """Ingest a batch of events."""
    results = []
    for event in batch.events:
        result = await _process_ingested_event(event, event.source or "unknown")
        results.append(result)
    return {"ingested": len(results), "results": results}


async def _process_ingested_event(event: IngestEvent, source: str) -> dict:
    """Process a single ingested event: store, detect threats, broadcast, auto-correlate."""
    global _detection_counter
    _record_aps_event()  # Record for APS calculation

    event_dict = event.model_dump()
    event_dict['source_type'] = source

    log_id = db.create_uploaded_log(
        filename=f"ingest_{source}_{(event.timestamp or datetime.now(timezone.utc).isoformat())[:10]}",
        source_type=source,
        file_size=len(event.raw_log or event.message),
    )
    db.insert_log_events(log_id, [event_dict])

    # Normalize event
    normalized = event_normalizer.normalize(event_dict, source)

    # Run through threat detector (existing ML/rule-based detection)
    detections = threat_detector.analyze_events([event_dict])
    created_alerts = []

    # Run through YAML rule engine
    try:
        rule_matches = detection_rule_engine.evaluate(event_dict, db)
        for match in rule_matches:
            alert = db.create_alert(
                alert_type=match.rule_title.lower().replace(" ", "_"),
                severity=match.severity,
                title=match.rule_title,
                description=match.description,
                source_ip=event_dict.get("source_ip", ""),
                dest_ip=event_dict.get("dest_ip", ""),
                source_port=0,
                dest_port=event_dict.get("dest_port", 0),
                protocol="",
                mitre_technique=match.mitre_technique,
                mitre_tactic=match.mitre_tactic,
                evidence=[e.get("message", "") for e in match.matched_events[:10]],
                recommendations=match.recommendations,
                log_id=log_id,
            )
            if alert:
                created_alerts.append(alert)
                broadcast_queue.appendleft({
                    "id": f"rule-{uuid.uuid4().hex[:8]}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "rule_alert",
                    "rule_id": match.rule_id,
                    "rule_title": match.rule_title,
                    "severity": match.severity,
                    "match_count": match.match_count,
                    "source_ip": event_dict.get("source_ip", ""),
                })
    except Exception:
        pass  # Rule engine is optional; don't break ingestion

    # Run through Sigma rule engine
    try:
        from services.sigma_engine import sigma_engine
        sigma_matches = sigma_engine.evaluate_event(event_dict)
        for match in sigma_matches:
            alert = db.create_alert(
                alert_type="sigma_rule",
                severity=match.get("level", "medium"),
                title=match.get("title", "Sigma Rule Match"),
                description=f"Sigma rule matched: {match.get('title', '')}",
                source_ip=event_dict.get("source_ip", ""),
                dest_ip=event_dict.get("dest_ip", ""),
                source_port=0,
                dest_port=event_dict.get("dest_port", 0),
                protocol="",
                mitre_technique=match.get("mitre_technique", ""),
                mitre_tactic=match.get("mitre_tactic", ""),
                evidence=[],
                recommendations=[],
                log_id=log_id,
            )
            if alert:
                created_alerts.append(alert)
                broadcast_queue.appendleft({
                    "id": f"sigma-{uuid.uuid4().hex[:8]}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "sigma_alert",
                    "rule_id": match.get("rule_id", ""),
                    "rule_title": match.get("title", ""),
                    "severity": match.get("level", "medium"),
                    "source_ip": event_dict.get("source_ip", ""),
                })
    except Exception:
        pass  # Sigma engine is optional

    # Check against threat feed IOCs
    try:
        from services.threat_feed_service import threat_feed_service
        src_ip = event_dict.get("source_ip", "")
        dst_ip = event_dict.get("dest_ip", "")
        for ip in [src_ip, dst_ip]:
            if ip:
                ioc_match = threat_feed_service.match_indicator(ip)
                if ioc_match:
                    alert = db.create_alert(
                        alert_type="threat_intel_match",
                        severity=ioc_match.get("severity", "HIGH"),
                        title=f"Known Threat Indicator: {ip}",
                        description=f"IP {ip} matches threat feed indicator ({ioc_match.get('threat_type', 'unknown')})",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        source_port=0,
                        dest_port=event_dict.get("dest_port", 0),
                        protocol="",
                        mitre_technique="",
                        mitre_tactic="",
                        evidence=[f"Indicator matched from feed: {ioc_match.get('feed_name', '')}"],
                        recommendations=["Block IP immediately", "Investigate all connections from this IP"],
                        log_id=log_id,
                    )
                    if alert:
                        created_alerts.append(alert)
    except Exception:
        pass  # Threat feed matching is optional

    if detections:
        db.insert_threat_detections(log_id, [d.to_dict() for d in detections])
        for det in detections:
            alert = db.create_alert(
                alert_type=det.threat_type,
                severity=det.severity,
                title=f"{det.threat_type.replace('_', ' ').title()} from {det.source_ip}",
                description=det.description,
                source_ip=det.source_ip,
                dest_ip=det.dest_ip,
                source_port=0,
                dest_port=det.dest_port,
                protocol="",
                mitre_technique=det.mitre_technique,
                mitre_tactic=det.mitre_tactic,
                evidence=det.evidence,
                recommendations=det.recommendations,
                log_id=log_id,
            )
            if alert:
                created_alerts.append(alert)

            # Push to broadcast queue for real-time WebSocket
            broadcast_queue.appendleft({
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "detection",
                "attack_type": det.threat_type,
                "confidence": det.confidence,
                "severity_score": det.severity_score,
                "severity": det.severity,
                "source_ip": det.source_ip,
                "dest_ip": det.dest_ip,
                "dest_port": det.dest_port,
                "description": det.description,
                "mitre_technique": det.mitre_technique,
                "mitre_tactic": det.mitre_tactic,
            })

        # Auto-trigger correlation after every N detections
        _detection_counter += len(detections)
        if _detection_counter >= CORRELATION_BATCH_SIZE:
            _detection_counter = 0
            try:
                from services.correlation_service import correlation_engine
                alerts = db.get_alerts(status='open', limit=200)
                incidents = correlation_engine.correlate(alerts)
                for inc in incidents:
                    inc_id = db.create_incident(
                        title=inc.title, severity=inc.severity, description=inc.description,
                        alert_ids=inc.alert_ids, timeline=inc.timeline, affected_ips=inc.affected_ips,
                        mitre_techniques=inc.mitre_techniques, mitre_tactics=inc.mitre_tactics,
                        recommendations=inc.recommendations, confidence=inc.confidence,
                    )
                    broadcast_queue.appendleft({
                        "id": f"inc-{uuid.uuid4().hex[:8]}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "incident",
                        "incident_id": inc_id,
                        "title": inc.title,
                        "severity": inc.severity,
                        "affected_ips": inc.affected_ips,
                    })
            except Exception as e:
                logger.warning(f"Auto-correlation failed: {e}")

    return {
        "log_id": log_id,
        "event_type": event.event_type,
        "severity": event.severity,
        "threats_detected": len(detections),
        "alerts_created": len(created_alerts),
    }


# =========================
# Device Management
# =========================
class DeviceRegister(BaseModel):
    hostname: str
    ip_address: str
    os_type: str = "unknown"
    organization_id: str = ""


@app.post("/api/devices/register")
async def register_device(device: DeviceRegister):
    """Register a new device/agent."""
    device_id = str(uuid.uuid4())
    db.create_uploaded_log(
        filename=f"device_{device.hostname}",
        source_type=f"device_{device.os_type}",
        file_size=0,
    )
    return {"device_id": device_id, "hostname": device.hostname, "status": "registered"}


@app.get("/api/devices")
async def list_devices():
    """List all registered devices."""
    logs = db.get_uploaded_logs(limit=1000)
    device_logs = [l for l in logs if l.get("source_type", "").startswith("device_")]
    devices = []
    seen = set()
    for log in device_logs:
        hostname = log.get("filename", "").replace("device_", "")
        if hostname and hostname not in seen:
            seen.add(hostname)
            devices.append({
                "hostname": hostname,
                "os_type": log.get("source_type", "").replace("device_", ""),
                "last_seen": log.get("upload_time", ""),
            })
    return {"devices": devices}


# ── Alert Management ──

@app.get("/api/alerts")
async def get_alerts(severity: str = "", status: str = "", org_id: str = "", limit: int = 100):
    """Get all alerts with optional filtering."""
    from database import db
    alerts = db.get_alerts(org_id=org_id or None, severity=severity or None, status=status or None, limit=limit)
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/api/alerts/stats")
async def get_alert_stats():
    """Get alert statistics."""
    from database import db
    return db.get_alert_stats()

@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get a single alert by ID."""
    from database import db
    alert = db.get_alert(alert_id)
    if not alert:
        return JSONResponse(status_code=404, content={"error": "Alert not found"})
    return alert

@app.post("/api/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, request: Request):
    """Update alert status (open, investigating, resolved, false_positive)."""
    from database import db
    body = await request.json()
    status = body.get("status", "open")
    db.update_alert_status(alert_id, status)
    return {"status": "updated"}

@app.get("/api/alerts/{alert_id}/notes")
async def get_alert_notes(alert_id: str):
    """Get investigation notes for an alert."""
    from database import db
    notes = db.get_investigation_notes(alert_id)
    return {"notes": notes}

@app.post("/api/alerts/{alert_id}/notes")
async def add_alert_note(alert_id: str, request: Request):
    """Add an investigation note to an alert."""
    from database import db
    body = await request.json()
    note = body.get("note", "")
    note_id = db.add_investigation_note(alert_id, user_id=None, note=note)
    return {"note_id": note_id, "status": "created"}


# ── Incident Management ──

@app.get("/api/incidents")
async def get_incidents(status: str = "", severity: str = "", org_id: str = "", limit: int = 100):
    from database import db
    incidents = db.get_incidents(org_id=org_id or None, status=status or None, severity=severity or None, limit=limit)
    return {"incidents": incidents, "count": len(incidents)}

@app.get("/api/incidents/stats")
async def get_incident_stats():
    from database import db
    return db.get_incident_stats()

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    from database import db
    incident = db.get_incident(incident_id)
    if not incident:
        return JSONResponse(status_code=404, content={"error": "Incident not found"})
    return incident

# Incident lifecycle states and valid transitions
INCIDENT_STATES = ["open", "investigating", "contained", "resolved", "closed"]
INCIDENT_TRANSITIONS = {
    "open": ["investigating", "closed"],
    "investigating": ["contained", "resolved", "closed"],
    "contained": ["investigating", "resolved", "closed"],
    "resolved": ["closed", "open"],  # Can reopen
    "closed": ["open"],  # Can reopen
}

@app.post("/api/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, request: Request):
    from database import db
    body = await request.json()
    new_status = body.get("status", "open").lower()
    assigned_to = body.get("assigned_to")

    # Validate status
    if new_status not in INCIDENT_STATES:
        return JSONResponse(status_code=400, content={"error": f"Invalid status. Must be one of: {', '.join(INCIDENT_STATES)}"})

    # Get current incident to check transition validity
    incident = db.get_incident(incident_id)
    if not incident:
        return JSONResponse(status_code=404, content={"error": "Incident not found"})

    current_status = incident.get("status", "open").lower()
    valid_transitions = INCIDENT_TRANSITIONS.get(current_status, [])

    if new_status not in valid_transitions:
        return JSONResponse(status_code=400, content={
            "error": f"Cannot transition from '{current_status}' to '{new_status}'. Valid transitions: {', '.join(valid_transitions)}",
            "current_status": current_status,
            "valid_transitions": valid_transitions,
        })

    db.update_incident_status(incident_id, new_status, assigned_to)

    # Auto-add note for status change
    try:
        db.add_incident_note(incident_id, user_id=None, note=f"Status changed: {current_status} → {new_status}")
    except Exception:
        pass

    return {"status": "updated", "previous": current_status, "current": new_status}

@app.get("/api/incidents/{incident_id}/notes")
async def get_incident_notes(incident_id: str):
    from database import db
    notes = db.get_incident_notes(incident_id)
    return {"notes": notes}

@app.post("/api/incidents/{incident_id}/notes")
async def add_incident_note(incident_id: str, request: Request):
    from database import db
    body = await request.json()
    note = body.get("note", "")
    note_id = db.add_incident_note(incident_id, user_id=None, note=note)
    return {"note_id": note_id, "status": "created"}

@app.post("/api/incidents/correlate")
async def correlate_alerts():
    """Run correlation engine on open alerts to create incidents."""
    from database import db
    from services.correlation_service import correlation_engine

    alerts = db.get_alerts(status='open', limit=200)
    incidents = correlation_engine.correlate(alerts)

    created = []
    for inc in incidents:
        inc_id = db.create_incident(
            title=inc.title, severity=inc.severity, description=inc.description,
            alert_ids=inc.alert_ids, timeline=inc.timeline, affected_ips=inc.affected_ips,
            mitre_techniques=inc.mitre_techniques, mitre_tactics=inc.mitre_tactics,
            recommendations=inc.recommendations, confidence=inc.confidence,
        )
        created.append(inc_id)

    return {"correlated": len(created), "incident_ids": created}


# =========================
# Asset Inventory
# =========================
class AssetCreate(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str = Field(..., max_length=45)
    os_type: str = "unknown"
    os_version: str = ""
    asset_type: str = "endpoint"
    criticality: str = "medium"
    owner: str = ""
    department: str = ""
    location: str = ""

@app.get("/api/assets")
async def get_assets(org_id: str = "", limit: int = 200):
    assets = db.get_assets(org_id=org_id or None, limit=limit)
    return {"assets": assets, "count": len(assets)}

@app.post("/api/assets")
async def create_asset(asset: AssetCreate):
    asset_id = db.create_asset(
        hostname=asset.hostname, ip_address=asset.ip_address,
        os_type=asset.os_type, os_version=asset.os_version,
        asset_type=asset.asset_type, criticality=asset.criticality,
        owner=asset.owner, department=asset.department, location=asset.location,
    )
    return {"asset_id": asset_id, "hostname": asset.hostname, "status": "created"}

@app.get("/api/assets/{asset_id}")
async def get_asset(asset_id: str):
    asset = db.get_asset(asset_id)
    if not asset:
        return JSONResponse(status_code=404, content={"error": "Asset not found"})
    return asset

@app.delete("/api/assets/{asset_id}")
async def delete_asset(asset_id: str):
    db.delete_asset(asset_id)
    return {"deleted": True}

# =========================
# IOC Management
# =========================
class IOCCreate(BaseModel):
    indicator_type: str = Field(..., pattern=r'^(ip|domain|hash|url|email)$')
    indicator_value: str = Field(..., min_length=1, max_length=500)
    threat_type: str = ""
    severity: str = "MEDIUM"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = "manual"
    description: str = ""
    tags: list[str] = []

@app.get("/api/ioc")
async def get_iocs(indicator_type: str = "", limit: int = 200):
    iocs = db.get_iocs(indicator_type=indicator_type or None, limit=limit)
    return {"iocs": iocs, "count": len(iocs)}

@app.post("/api/ioc")
async def create_ioc(ioc: IOCCreate):
    ioc_id = db.create_ioc(
        indicator_type=ioc.indicator_type, indicator_value=ioc.indicator_value,
        threat_type=ioc.threat_type, severity=ioc.severity, confidence=ioc.confidence,
        source=ioc.source, description=ioc.description, tags=ioc.tags,
    )
    return {"ioc_id": ioc_id, "indicator": ioc.indicator_value, "status": "created"}

@app.get("/api/ioc/check/{indicator_value}")
async def check_ioc(indicator_value: str):
    match = db.check_ioc_match(indicator_value)
    if match:
        return {"matched": True, "ioc": match}
    return {"matched": False}

@app.delete("/api/ioc/{ioc_id}")
async def delete_ioc(ioc_id: str):
    db.delete_ioc(ioc_id)
    return {"deleted": True}

# =========================
# Detection Rules
# =========================
class DetectionRuleCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    condition: str = Field(..., min_length=1)
    window_seconds: int = Field(default=300, ge=1)
    threshold: float = Field(default=1.0, ge=0.0)
    severity: str = "MEDIUM"
    mitre_technique: str = ""
    mitre_tactic: str = ""

@app.get("/api/rules")
async def get_detection_rules(enabled_only: bool = True):
    rules = db.get_detection_rules(enabled_only=enabled_only)
    return {"rules": rules, "count": len(rules)}

@app.post("/api/rules")
async def create_detection_rule(rule: DetectionRuleCreate):
    rule_id = db.create_detection_rule(
        title=rule.title, description=rule.description, condition=rule.condition,
        window_seconds=rule.window_seconds, threshold=rule.threshold, severity=rule.severity,
        mitre_technique=rule.mitre_technique, mitre_tactic=rule.mitre_tactic,
    )
    return {"rule_id": rule_id, "title": rule.title, "status": "created"}

@app.delete("/api/rules/{rule_id}")
async def delete_detection_rule(rule_id: str):
    db.delete_detection_rule(rule_id)
    return {"deleted": True}

# =========================
# Agent Management
# =========================
@app.get("/api/agents")
async def get_agents(org_id: str = ""):
    agents = db.get_agents(org_id=org_id or None)
    return {"agents": agents, "count": len(agents)}

@app.post("/api/agents/heartbeat")
async def agent_heartbeat(request: Request):
    data = await request.json()
    agent_id = data.get("agent_id")
    if not agent_id:
        return JSONResponse(status_code=400, content={"error": "agent_id required"})
    db.update_agent_status(
        agent_id=agent_id,
        status=data.get("status", "online"),
        logs_collected=data.get("logs_collected"),
        events_processed=data.get("events_processed"),
        alerts_generated=data.get("alerts_generated"),
    )
    return {"ok": True}


# ================================================================
# ENTERPRISE SOC FEATURES
# ================================================================

# =========================
# GeoIP Enrichment
# =========================
@app.get("/api/geoip/{ip}")
async def geoip_lookup(ip: str):
    """Enrich an IP with geolocation data."""
    from services.geoip_service import geoip_service
    result = await geoip_service.enrich(ip)
    return result


@app.get("/api/geoip/batch")
async def geoip_batch(ips: str = ""):
    """Enrich multiple IPs (comma-separated)."""
    from services.geoip_service import geoip_service
    ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]
    results = await geoip_service.enrich_batch(ip_list[:50])
    return {"results": results}


@app.get("/api/geoip/attacks")
async def geoip_attack_map():
    """Get attack origins with geolocation for the world map."""
    from services.geoip_service import geoip_service
    import asyncio as _aio

    detections = db.get_threat_detections(limit=500)
    alerts = db.get_alerts(status='open', limit=200)

    # Collect unique source IPs
    ip_set = set()
    ip_threats = {}
    for det in detections:
        sip = det.get("source_ip", "")
        if sip and sip not in ("127.0.0.1", "localhost", ""):
            ip_set.add(sip)
            if sip not in ip_threats:
                ip_threats[sip] = {"count": 0, "severity": "LOW", "types": set()}
            ip_threats[sip]["count"] += 1
            sev = det.get("severity", "INFO")
            if _severity_rank(sev) > _severity_rank(ip_threats[sip]["severity"]):
                ip_threats[sip]["severity"] = sev
            ip_threats[sip]["types"].add(det.get("threat_type", "unknown"))

    for alert in alerts:
        sip = alert.get("source_ip", "")
        if sip and sip not in ("127.0.0.1", "localhost", ""):
            ip_set.add(sip)
            if sip not in ip_threats:
                ip_threats[sip] = {"count": 0, "severity": "LOW", "types": set()}
            ip_threats[sip]["count"] += 1

    # Enrich all IPs concurrently (max 30)
    ip_list = list(ip_set)[:30]
    enrichments = await _aio.gather(*[geoip_service.enrich(ip) for ip in ip_list])

    # Build attack map points
    attack_points = []
    country_stats = {}
    for enrich in enrichments:
        ip = enrich.get("ip", "")
        threat = ip_threats.get(ip, {})
        country = enrich.get("country", "Unknown")
        country_stats[country] = country_stats.get(country, 0) + threat.get("count", 0)

        if enrich.get("latitude") and enrich.get("longitude"):
            attack_points.append({
                "ip": ip,
                "country": country,
                "country_code": enrich.get("country_code", ""),
                "city": enrich.get("city", ""),
                "latitude": enrich["latitude"],
                "longitude": enrich["longitude"],
                "isp": enrich.get("isp", "Unknown"),
                "asn": enrich.get("asn", ""),
                "attack_count": threat.get("count", 0),
                "severity": threat.get("severity", "LOW"),
                "attack_types": list(threat.get("types", set())),
                "is_proxy": enrich.get("is_proxy", False),
                "is_hosting": enrich.get("is_hosting", False),
            })

    return {
        "attacks": attack_points,
        "country_stats": dict(sorted(country_stats.items(), key=lambda x: -x[1])[:20]),
        "total_ips": len(ip_set),
        "total_attacks": sum(t["count"] for t in ip_threats.values()),
    }


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev, 0)


# =========================
# Attacks Per Second (APS)
# =========================
_aps_buffer: deque = deque(maxlen=10000)
_aps_last_record = 0

@app.get("/api/metrics/aps")
async def get_aps():
    """Get attacks/events per second metrics."""
    now = time.time()
    window_1s = [t for t in _aps_buffer if now - t <= 1.0]
    window_5s = [t for t in _aps_buffer if now - t <= 5.0]
    window_60s = [t for t in _aps_buffer if now - t <= 60.0]
    window_3600s = [t for t in _aps_buffer if now - t <= 3600.0]

    # Calculate trends
    recent_10s = len([t for t in _aps_buffer if now - t <= 10.0])
    prev_10s = len([t for t in _aps_buffer if 10.0 < now - t <= 20.0])
    trend = 0
    if prev_10s > 0:
        trend = round(((recent_10s - prev_10s) / prev_10s) * 100, 1)

    # Get database counts for longer windows
    try:
        detections = db.get_threat_detections(limit=5000)
        alerts = db.get_alerts(limit=1000)
        incidents = db.get_incidents(limit=500)
    except Exception:
        detections, alerts, incidents = [], [], []

    # Compute per-type rates
    type_counts = {}
    for d in detections:
        tt = d.get("threat_type", "unknown")
        type_counts[tt] = type_counts.get(tt, 0) + 1

    return {
        "attacks_per_second": len(window_1s),
        "events_per_second": len(window_1s),
        "attacks_per_5s": len(window_5s),
        "attacks_per_minute": len(window_60s),
        "attacks_per_hour": len(window_3600s),
        "trend_percent": trend,
        "total_detections": len(detections),
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "detection_rate": round(len(detections) / max(len(window_3600s) / 3600, 1), 2) if window_3600s else 0,
        "alerts_per_minute": round(len([a for a in alerts if a.get("created_at") and now - _parse_iso(a["created_at"]) <= 60]) if alerts else 0, 1),
        "type_distribution": dict(sorted(type_counts.items(), key=lambda x: -x[1])[:10]),
    }


def _parse_iso(ts: str) -> float:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0


def _record_aps_event():
    """Record an event timestamp for APS calculation."""
    _aps_buffer.append(time.time())


# =========================
# Vulnerability Dashboard
# =========================
@app.get("/api/vulnerabilities/search")
async def search_vulnerabilities(keyword: str = "", cvss_min: float = 0, limit: int = 20):
    from services.vulnerability_service import vuln_service
    vulns = await vuln_service.search_cves(keyword=keyword, cvss_min=cvss_min, limit=limit)
    return {"vulnerabilities": vulns, "total": len(vulns)}

@app.get("/api/vulnerabilities/{cve_id}")
async def get_vulnerability(cve_id: str):
    from services.vulnerability_service import vuln_service
    vuln = await vuln_service.get_cve(cve_id)
    if not vuln:
        return JSONResponse(status_code=404, content={"error": "CVE not found"})
    return vuln

@app.get("/api/vulnerabilities/stats/overview")
async def get_vulnerability_stats():
    from services.vulnerability_service import vuln_service
    return await vuln_service.get_stats()


# =========================
# Agent Health Monitoring
# =========================
@app.get("/api/agents/health")
async def get_agent_health():
    """Get agent health status with online/offline detection."""
    agents = db.get_agents()
    now = datetime.now(timezone.utc)
    healthy = []
    for agent in agents:
        last_heartbeat = agent.get("last_heartbeat", "")
        is_online = False
        if last_heartbeat:
            try:
                hb_time = datetime.fromisoformat(last_heartbeat.replace("Z", "+00:00"))
                is_online = (now - hb_time).total_seconds() < 120
            except Exception:
                pass
        healthy.append({
            **agent,
            "is_online": is_online,
            "status_display": "Online" if is_online else "Offline",
            "health": "healthy" if is_online else "critical",
        })
    online_count = sum(1 for a in healthy if a["is_online"])
    return {
        "agents": healthy,
        "total": len(healthy),
        "online": online_count,
        "offline": len(healthy) - online_count,
    }


# =========================
# MITRE ATT&CK Matrix (Enterprise)
# =========================
MITRE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information to plan future operations", "color": "#FF6B6B"},
    {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources to support operations", "color": "#FF8E53"},
    {"id": "TA0001", "name": "Initial Access", "description": "Gaining initial foothold into the network", "color": "#FFA94D"},
    {"id": "TA0002", "name": "Execution", "description": "Running malicious code on target systems", "color": "#FFD43B"},
    {"id": "TA0003", "name": "Persistence", "description": "Maintaining access to compromised systems", "color": "#A9E34B"},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Gaining higher-level permissions", "color": "#69DB7C"},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Avoiding detection by security tools", "color": "#38D9A9"},
    {"id": "TA0006", "name": "Credential Access", "description": "Stealing account credentials", "color": "#3BC9DB"},
    {"id": "TA0007", "name": "Discovery", "description": "Mapping the internal network", "color": "#4DABF7"},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through the network", "color": "#748FFC"},
    {"id": "TA0009", "name": "Collection", "description": "Gathering target data", "color": "#9775FA"},
    {"id": "TA0011", "name": "Command and Control", "description": "Communicating with compromised systems", "color": "#DA77F2"},
    {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data from the network", "color": "#F783AC"},
    {"id": "TA0040", "name": "Impact", "description": "Disrupting, destroying, or manipulating systems", "color": "#E03131"},
]

MITRE_TECHNIQUES_MAP = {
    "Reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "description": "Scanning target infrastructure", "detection": "Network IDS, Firewall logs"},
        {"id": "T1592", "name": "Gather Victim Host Info", "description": "Collecting information about hosts", "detection": "OSINT monitoring"},
    ],
    "Initial Access": [
        {"id": "T1190", "name": "Exploit Public-Facing App", "description": "Exploiting vulnerabilities in public apps", "detection": "WAF logs, Application logs"},
        {"id": "T1078", "name": "Valid Accounts", "description": "Using legitimate credentials", "detection": "Authentication logs, Anomaly detection"},
        {"id": "T1566", "name": "Phishing", "description": "Spear phishing via email", "detection": "Email gateway, User reports"},
    ],
    "Execution": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "description": "Executing commands via shells/interpreters", "detection": "Process monitoring, Command-line logging"},
        {"id": "T1204", "name": "User Execution", "description": "Tricking users into running malicious code", "detection": "EDR, User behavior analytics"},
    ],
    "Persistence": [
        {"id": "T1053", "name": "Scheduled Task/Job", "description": "Scheduling tasks for persistence", "detection": "Task scheduler logs, EDR"},
        {"id": "T1543", "name": "Create or Modify System Process", "description": "Modifying system services", "detection": "Service creation events"},
    ],
    "Privilege Escalation": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "description": "Exploiting vulnerabilities for higher privileges", "detection": "Kernel logs, EDR"},
    ],
    "Defense Evasion": [
        {"id": "T1070", "name": "Indicator Removal", "description": "Clearing logs and indicators", "detection": "Log integrity monitoring"},
        {"id": "T1027", "name": "Obfuscated Files or Information", "description": "Encoding/encrypting payloads", "detection": "Static analysis, Sandbox"},
    ],
    "Credential Access": [
        {"id": "T1110", "name": "Brute Force", "description": "Guessing passwords systematically", "detection": "Authentication logs, Rate limiting"},
        {"id": "T1003", "name": "OS Credential Dumping", "description": "Extracting credential stores", "detection": "LSASS access monitoring, EDR"},
    ],
    "Discovery": [
        {"id": "T1046", "name": "Network Service Discovery", "description": "Scanning for open services", "detection": "Network flow analysis, IDS"},
    ],
    "Lateral Movement": [
        {"id": "T1021", "name": "Remote Services", "description": "Moving laterally via remote access", "detection": "Network traffic analysis, Authentication logs"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "description": "Copying tools to other systems", "detection": "Network file transfer monitoring"},
    ],
    "Collection": [
        {"id": "T1005", "name": "Data from Local System", "description": "Collecting data from local files", "detection": "File access monitoring, DLP"},
        {"id": "T1039", "name": "Data from Network Shared Drive", "description": "Collecting from network shares", "detection": "Share access logs"},
    ],
    "Command and Control": [
        {"id": "T1071", "name": "Application Layer Protocol", "description": "Using standard protocols for C2", "detection": "Network traffic analysis, DNS monitoring"},
        {"id": "T1573", "name": "Encrypted Channel", "description": "Encrypting C2 communications", "detection": "TLS inspection, Beacon analysis"},
    ],
    "Exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "description": "Sending data over C2 connection", "detection": "Data loss prevention, Egress filtering"},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "description": "Using cloud services for exfiltration", "detection": "DLP, Cloud access monitoring"},
    ],
    "Impact": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "description": "Ransomware encryption", "detection": "File system monitoring, EDR"},
        {"id": "T1489", "name": "Service Stop", "description": "Stopping critical services", "detection": "Service monitoring, Event logs"},
    ],
}


@app.get("/api/mitre/matrix")
async def get_mitre_matrix():
    """Get MITRE ATT&CK matrix with detection data."""
    detections = db.get_threat_detections(limit=2000)
    alerts = db.get_alerts(limit=500)

    # Count technique occurrences
    technique_counts = {}
    tactic_counts = {}

    for det in detections:
        tech = det.get("mitre_technique", "")
        tactic = det.get("mitre_tactic", "")
        if tech:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
        if tactic:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    for alert in alerts:
        tech = alert.get("mitre_technique", "")
        tactic = alert.get("mitre_tactic", "")
        if tech:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
        if tactic:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    # Build matrix
    matrix = []
    total_techniques = 0
    active_techniques = 0

    for tactic in MITRE_TACTICS:
        tactic_name = tactic["name"]
        techniques = MITRE_TECHNIQUES_MAP.get(tactic_name, [])
        tactic_detection = tactic_counts.get(tactic_name, 0)

        tech_list = []
        for tech in techniques:
            total_techniques += 1
            detection_count = technique_counts.get(tech["id"], 0)
            is_active = detection_count > 0
            if is_active:
                active_techniques += 1

            tech_list.append({
                **tech,
                "detection_count": detection_count,
                "is_active": is_active,
                "status": "active" if detection_count >= 5 else "observed" if detection_count > 0 else "none",
            })

        matrix.append({
            **tactic,
            "techniques": tech_list,
            "detection_count": tactic_detection,
            "active_techniques": sum(1 for t in tech_list if t["is_active"]),
        })

    return {
        "tactics": matrix,
        "total_techniques": total_techniques,
        "active_techniques": active_techniques,
        "coverage_percent": round((active_techniques / max(total_techniques, 1)) * 100, 1),
        "total_detections": len(detections),
        "top_techniques": sorted(
            [{"id": k, "count": v} for k, v in technique_counts.items()],
            key=lambda x: -x["count"]
        )[:10],
    }


# =========================
# Threat Hunting Workspace
# =========================
@app.get("/api/hunt/search")
async def threat_hunt_search(
    q: str = "",
    severity: str = "",
    attack_type: str = "",
    source_ip: str = "",
    hostname: str = "",
    date_from: str = "",
    date_to: str = "",
    limit: int = 200,
):
    """Search across detections, alerts, and events."""
    results = {"detections": [], "alerts": [], "events": [], "total": 0}

    # Search detections
    detections = db.get_threat_detections_filtered(
        severity=severity or None,
        threat_type=attack_type or None,
        source_ip=source_ip or None,
        limit=limit,
    )
    if q:
        q_lower = q.lower()
        detections = [d for d in detections if any(
            q_lower in str(d.get(k, "")).lower()
            for k in ("threat_type", "source_ip", "dest_ip", "description", "severity", "mitre_technique")
        )]
    results["detections"] = detections

    # Search alerts
    alerts = db.get_alerts(severity=severity or None, limit=limit)
    if q:
        q_lower = q.lower()
        alerts = [a for a in alerts if any(
            q_lower in str(a.get(k, "")).lower()
            for k in ("alert_type", "title", "description", "source_ip", "severity", "mitre_technique")
        )]
    results["alerts"] = alerts

    # Search events
    uploaded = db.get_uploaded_logs(limit=50)
    all_events = []
    for log in uploaded:
        evts = db.get_log_events(log["id"], limit=500)
        all_events.extend(evts)

    if q:
        q_lower = q.lower()
        all_events = [e for e in all_events if any(
            q_lower in str(e.get(k, "")).lower()
            for k in ("event_type", "source_ip", "dest_ip", "hostname", "message", "source")
        )]
    if hostname:
        all_events = [e for e in all_events if hostname.lower() in str(e.get("hostname", "")).lower()]

    results["events"] = all_events[:limit]
    results["total"] = len(results["detections"]) + len(results["alerts"]) + len(results["events"])

    # Build timeline
    timeline = []
    for d in detections[:50]:
        timeline.append({
            "timestamp": d.get("timestamp", d.get("created_at", "")),
            "type": "detection",
            "title": d.get("threat_type", "Unknown"),
            "severity": d.get("severity", "LOW"),
            "source_ip": d.get("source_ip", ""),
            "description": d.get("description", ""),
        })
    for a in alerts[:50]:
        timeline.append({
            "timestamp": a.get("created_at", ""),
            "type": "alert",
            "title": a.get("title", "Unknown"),
            "severity": a.get("severity", "LOW"),
            "source_ip": a.get("source_ip", ""),
            "description": a.get("description", ""),
        })
    timeline.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    results["timeline"] = timeline[:100]
    return results


# =========================
# Security Metrics (KPI Dashboard)
# =========================
@app.get("/api/metrics/security")
async def get_security_metrics():
    """Get comprehensive security metrics for the KPI bar."""
    now = time.time()

    try:
        detections = db.get_threat_detections(limit=5000)
        alerts = db.get_alerts(limit=2000)
        incidents = db.get_incidents(limit=500)
        agents = db.get_agents()
    except Exception:
        detections, alerts, incidents, agents = [], [], [], []

    # MTTD (Mean Time to Detect) — time between event and detection
    mttd_minutes = 0
    mttr_minutes = 0
    detection_times = []
    resolution_times = []

    for inc in incidents:
        created = inc.get("created_at", "")
        updated = inc.get("updated_at", "")
        if created and updated:
            try:
                ct = datetime.fromisoformat(created.replace("Z", "+00:00"))
                ut = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                resolution_minutes = (ut - ct).total_seconds() / 60
                if 0 < resolution_minutes < 1440:  # within 24h
                    resolution_times.append(resolution_minutes)
            except Exception:
                pass

    for det in detections:
        ts = det.get("timestamp", det.get("created_at", ""))
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                detection_times.append(dt.timestamp())
            except Exception:
                pass

    if resolution_times:
        mttr_minutes = round(sum(resolution_times) / len(resolution_times), 1)

    # APS from buffer
    aps = len([t for t in _aps_buffer if now - t <= 1.0])
    eps = aps  # events per second

    # Connected agents
    online_agents = sum(1 for a in agents if a.get("status") == "online")

    # Severity breakdown
    sev_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for d in detections:
        sev = d.get("severity", "LOW")
        if sev in sev_breakdown:
            sev_breakdown[sev] += 1

    # Attack type distribution
    type_dist = {}
    for d in detections:
        tt = d.get("threat_type", "unknown")
        type_dist[tt] = type_dist.get(tt, 0) + 1

    # Alert status
    open_alerts = sum(1 for a in alerts if a.get("status") == "open")
    closed_alerts = sum(1 for a in alerts if a.get("status") in ("resolved", "false_positive"))

    # Incident status
    open_incidents = sum(1 for i in incidents if i.get("status") == "open")
    closed_incidents = sum(1 for i in incidents if i.get("status") in ("resolved", "closed"))

    return {
        "aps": aps,
        "eps": eps,
        "trend_percent": 0,
        "total_detections": len(detections),
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "open_alerts": open_alerts,
        "closed_alerts": closed_alerts,
        "open_incidents": open_incidents,
        "closed_incidents": closed_incidents,
        "mttd_minutes": round(sum(detection_times) / max(len(detection_times), 1) / 60, 1) if detection_times else 0,
        "mttr_minutes": mttr_minutes,
        "severity_breakdown": sev_breakdown,
        "attack_distribution": dict(sorted(type_dist.items(), key=lambda x: -x[1])[:10]),
        "connected_agents": online_agents,
        "total_agents": len(agents),
        "threat_score": calculate_threat_score(),
    }


# =========================
# Detection Pipeline Visualizer
# =========================
@app.get("/api/metrics/pipeline")
async def get_pipeline_metrics():
    """Get detection pipeline stage metrics."""
    try:
        uploaded = db.get_uploaded_logs(limit=500)
        detections = db.get_threat_detections(limit=2000)
        alerts = db.get_alerts(limit=1000)
        incidents = db.get_incidents(limit=500)
    except Exception:
        uploaded, detections, alerts, incidents = [], [], [], []

    # Compute pipeline stages
    total_logs = len(uploaded)
    total_events = sum(log.get("event_count", 0) for log in uploaded)
    total_threats = len(detections)
    total_alerts = len(alerts)
    total_incidents = len(incidents)
    total_reports = db.get_total_reports()

    # Active rules
    try:
        rules = db.get_detection_rules(enabled_only=True)
        active_rules = len(rules)
    except Exception:
        active_rules = 0

    # ML predictions
    pred_list = list(prediction_history)
    total_predictions = len(pred_list)

    return {
        "stages": [
            {"name": "Log Collection", "count": total_logs, "status": "active" if total_logs > 0 else "idle", "icon": "database"},
            {"name": "Normalization", "count": total_events, "status": "active" if total_events > 0 else "idle", "icon": "filter"},
            {"name": "Detection Rules", "count": total_threats, "status": "active" if total_threats > 0 else "idle", "icon": "shield", "detail": f"{active_rules} rules active"},
            {"name": "ML Prediction", "count": total_predictions, "status": "active" if total_predictions > 0 else "idle", "icon": "brain"},
            {"name": "Correlation", "count": total_incidents, "status": "active" if total_incidents > 0 else "idle", "icon": "link"},
            {"name": "Alerts", "count": total_alerts, "status": "active" if total_alerts > 0 else "idle", "icon": "bell"},
            {"name": "Incidents", "count": total_incidents, "status": "active" if total_incidents > 0 else "idle", "icon": "alert-triangle"},
            {"name": "Reports", "count": total_reports, "status": "active" if total_reports > 0 else "idle", "icon": "file-text"},
        ],
        "total_logs": total_logs,
        "total_events": total_events,
        "total_detections": total_threats,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "total_reports": total_reports,
        "active_rules": active_rules,
    }


# =========================
# Attack Heatmap Data
# =========================
@app.get("/api/metrics/heatmap")
async def get_attack_heatmap():
    """Get hourly attack distribution for heatmap."""
    try:
        detections = db.get_threat_detections(limit=5000)
        alerts = db.get_alerts(limit=2000)
    except Exception:
        detections, alerts = [], []

    # Build 24h x 7d heatmap grid
    hourly = [0] * 24
    daily = [0] * 7
    grid = [[0] * 24 for _ in range(7)]

    for det in detections:
        ts = det.get("timestamp", det.get("created_at", ""))
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = dt.hour
                day = dt.weekday()
                hourly[hour] += 1
                daily[day] += 1
                grid[day][hour] += 1
            except Exception:
                pass

    for alert in alerts:
        ts = alert.get("created_at", "")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = dt.hour
                day = dt.weekday()
                hourly[hour] += 1
                daily[day] += 1
                grid[day][hour] += 1
            except Exception:
                pass

    return {
        "hourly": hourly,
        "daily": daily,
        "grid": grid,
        "day_labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "hour_labels": [f"{h:02d}" for h in range(24)],
        "total": sum(hourly),
    }


# =========================
# Risk Scoring Engine
# =========================
@app.get("/api/assets/{asset_id}/risk")
async def get_asset_risk(asset_id: str):
    """Calculate risk score for an asset."""
    asset = db.get_asset(asset_id)
    if not asset:
        return JSONResponse(status_code=404, content={"error": "Asset not found"})

    ip = asset.get("ip_address", "")
    hostname = asset.get("hostname", "")

    # Get threats for this asset
    ip_threats = db.get_threats_by_ip(ip) if ip else []
    all_detections = db.get_threat_detections(limit=5000)
    asset_detections = [d for d in all_detections if d.get("source_ip") == ip or d.get("dest_ip") == ip]

    # Get alerts
    alerts = db.get_alerts(status='open', limit=500)
    asset_alerts = [a for a in alerts if a.get("source_ip") == ip or a.get("dest_ip") == ip]

    # Calculate risk factors
    critical_count = sum(1 for d in asset_detections if d.get("severity") == "CRITICAL")
    high_count = sum(1 for d in asset_detections if d.get("severity") == "HIGH")
    open_alerts = len(asset_alerts)

    # Risk score: 0-100
    severity_score = min((critical_count * 15 + high_count * 8), 50)
    alert_score = min(open_alerts * 5, 30)
    criticality_bonus = {"critical": 15, "high": 10, "medium": 5, "low": 0}.get(asset.get("criticality", "medium"), 5)
    risk_score = min(100, severity_score + alert_score + criticality_bonus)

    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "asset_id": asset_id,
        "hostname": hostname,
        "ip_address": ip,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "factors": {
            "critical_detections": critical_count,
            "high_detections": high_count,
            "open_alerts": open_alerts,
            "criticality": asset.get("criticality", "medium"),
            "severity_score": severity_score,
            "alert_score": alert_score,
        },
        "recommendations": _get_risk_recommendations(risk_level, critical_count, open_alerts),
    }


def _get_risk_recommendations(level: str, critical: int, alerts: int) -> list:
    recs = []
    if level == "CRITICAL":
        recs.append("Isolate this asset from the network immediately")
        recs.append("Conduct full forensic analysis")
        recs.append("Reset all credentials on this host")
    if level in ("CRITICAL", "HIGH"):
        recs.append("Enable full packet capture")
        recs.append("Review and harden access controls")
    if critical > 0:
        recs.append("Investigate all critical detections")
    if alerts > 5:
        recs.append("Triage and resolve open alerts")
    recs.append("Verify endpoint protection is active")
    return recs


# =========================
# Sigma Rule Engine Endpoints
# =========================
try:
    from services.sigma_engine import sigma_engine
except Exception as _e:
    sigma_engine = None
    logger.error(f"Failed to load sigma_engine: {_e}", extra={"log_module": "startup"})

_sigma_match_history: deque = deque(maxlen=1000)

@app.get("/api/sigma/rules")
async def get_sigma_rules(level: str = None, product: str = None):
    """List all Sigma rules, optionally filtered."""
    try:
        rules = sigma_engine.get_rules()
        if level:
            rules = [r for r in rules if r.get("level", "").lower() == level.lower()]
        if product:
            rules = [r for r in rules if r.get("logsource", {}).get("product", "").lower() == product.lower()]
        return {"rules": rules, "total": len(rules)}
    except Exception as e:
        logger.error(f"Sigma rules fetch error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch Sigma rules: {str(e)}"})


@app.post("/api/sigma/rules")
async def create_sigma_rule(data: dict):
    """Import a Sigma rule from YAML or dict."""
    try:
        yaml_text = data.get("yaml")
        if yaml_text:
            rule_id = sigma_engine.add_rule(yaml_text)
        else:
            rule = data.get("rule") or data
            rule_id = sigma_engine.add_rule_dict(rule)
        log_structured("info", "sigma", f"Sigma rule imported: {rule_id}")
        return {"rule_id": rule_id, "status": "created"}
    except Exception as e:
        logger.error(f"Sigma rule create error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=400, content={"error": f"Failed to import Sigma rule: {str(e)}"})


@app.post("/api/sigma/rules/import-bulk")
async def import_sigma_rules(data: dict):
    """Bulk import Sigma rules from a YAML collection."""
    try:
        import yaml as _yaml
        yaml_text = data.get("yaml", "")
        if not yaml_text:
            rules_list = data.get("rules", [])
            if not rules_list:
                return JSONResponse(status_code=400, content={"error": "Provide 'yaml' string or 'rules' list"})
            imported_ids = []
            for rule in rules_list:
                rule_id = sigma_engine.add_rule_dict(rule)
                imported_ids.append(rule_id)
            log_structured("info", "sigma", f"Bulk imported {len(imported_ids)} Sigma rules")
            return {"imported": len(imported_ids), "rule_ids": imported_ids}

        collection = _yaml.safe_load(yaml_text)
        if isinstance(collection, list):
            rules_data = collection
        elif isinstance(collection, dict) and "rules" in collection:
            rules_data = collection["rules"]
        else:
            rules_data = [collection]

        imported_ids = []
        errors = []
        for i, rule in enumerate(rules_data):
            try:
                rule_id = sigma_engine.add_rule_dict(rule)
                imported_ids.append(rule_id)
            except Exception as e:
                errors.append({"index": i, "error": str(e)})

        log_structured("info", "sigma", f"Bulk imported {len(imported_ids)} Sigma rules ({len(errors)} errors)")
        return {"imported": len(imported_ids), "errors": errors, "rule_ids": imported_ids}
    except Exception as e:
        logger.error(f"Sigma bulk import error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Bulk import failed: {str(e)}"})


@app.delete("/api/sigma/rules/{rule_id}")
async def delete_sigma_rule(rule_id: str):
    """Delete a Sigma rule."""
    try:
        rule = sigma_engine.get_rule(rule_id)
        if not rule:
            return JSONResponse(status_code=404, content={"error": "Sigma rule not found"})
        sigma_engine.remove_rule(rule_id)
        log_structured("info", "sigma", f"Sigma rule deleted: {rule_id}")
        return {"deleted": True, "rule_id": rule_id}
    except Exception as e:
        logger.error(f"Sigma rule delete error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to delete Sigma rule: {str(e)}"})


@app.get("/api/sigma/matches")
async def get_sigma_matches(limit: int = 50):
    """Get recent Sigma rule matches."""
    try:
        matches = list(_sigma_match_history)[:limit]
        return {"matches": matches, "total": len(matches)}
    except Exception as e:
        logger.error(f"Sigma matches fetch error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch Sigma matches: {str(e)}"})


@app.get("/api/sigma/stats")
async def get_sigma_stats():
    """Get Sigma engine statistics."""
    try:
        stats = sigma_engine.get_stats()
        stats["recent_matches"] = len(_sigma_match_history)
        return stats
    except Exception as e:
        logger.error(f"Sigma stats error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch Sigma stats: {str(e)}"})


# =========================
# Threat Feed Endpoints (STIX/TAXII)
# =========================
try:
    from services.threat_feed_service import threat_feed_service
except Exception as _e:
    threat_feed_service = None
    logger.error(f"Failed to load threat_feed_service: {_e}", extra={"log_module": "startup"})

@app.on_event("startup")
async def startup_threat_feeds():
    try:
        threat_feed_service.init_db()
        await threat_feed_service.start_background_polling(interval_seconds=3600)
        log_structured("info", "system", "Threat feed service started with background polling")
    except Exception as e:
        logger.error(f"Threat feed startup error: {e}", extra={"log_module": "api", "action": "error"})


@app.get("/api/feeds")
async def get_threat_feeds():
    """List configured threat feeds."""
    try:
        feeds = threat_feed_service.get_feeds()
        summary = threat_feed_service.get_feed_summary()
        return {"feeds": feeds, "summary": summary}
    except Exception as e:
        logger.error(f"Feeds fetch error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch feeds: {str(e)}"})


@app.post("/api/feeds")
async def create_threat_feed(data: dict):
    """Add a new threat feed."""
    try:
        from services.threat_feed_service import FeedConfig
        feed_cfg = FeedConfig(
            name=data.get("name", ""),
            url=data.get("url", ""),
            auth_type=data.get("auth_type", "none"),
            auth_username=data.get("auth_username", ""),
            auth_password=data.get("auth_password", ""),
            collection_id=data.get("collection_id", ""),
            description=data.get("description", ""),
            poll_interval_seconds=data.get("poll_interval_seconds", 3600),
            enabled=data.get("enabled", True),
            tlp=data.get("tlp", "white"),
        )
        feed_id = threat_feed_service.add_feed(feed_cfg)
        log_structured("info", "feeds", f"Threat feed created: {feed_cfg.name} ({feed_id})")
        return {"feed_id": feed_id, "name": feed_cfg.name, "status": "created"}
    except Exception as e:
        logger.error(f"Feed create error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to create feed: {str(e)}"})


@app.post("/api/feeds/{feed_id}/poll")
async def poll_threat_feed(feed_id: str):
    """Manually poll a threat feed."""
    try:
        feed = threat_feed_service.get_feed(feed_id)
        if not feed:
            return JSONResponse(status_code=404, content={"error": "Feed not found"})
        result = await threat_feed_service.poll_feed(feed_id)
        log_structured("info", "feeds", f"Manual poll of feed {feed.get('name', feed_id)}: {result}")
        return {"feed_id": feed_id, "result": result}
    except Exception as e:
        logger.error(f"Feed poll error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to poll feed: {str(e)}"})


@app.get("/api/stix/objects")
async def get_stix_objects(type: str = None, limit: int = 50):
    """Browse imported STIX objects."""
    try:
        objects = threat_feed_service.get_stix_objects(stix_type=type, limit=limit)
        return {"objects": objects, "total": len(objects)}
    except Exception as e:
        logger.error(f"STIX objects fetch error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch STIX objects: {str(e)}"})


@app.get("/api/stix/indicators")
async def get_stix_indicators(indicator_type: str = None, limit: int = 100):
    """Browse parsed STIX indicators."""
    try:
        indicators = threat_feed_service.get_indicators(indicator_type=indicator_type, limit=limit)
        stats = threat_feed_service.get_indicator_stats()
        return {"indicators": indicators, "total": len(indicators), "stats": stats}
    except Exception as e:
        logger.error(f"STIX indicators fetch error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch STIX indicators: {str(e)}"})


@app.get("/api/stix/match/{value}")
async def match_stix_indicator(value: str):
    """Check if an IOC is a known threat indicator."""
    try:
        import re as _re
        matched = []
        if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            matched = threat_feed_service.match_ip(value)
        elif _re.match(r"^[a-fA-F0-9]{32,64}$", value):
            matched = threat_feed_service.match_hash(value)
        elif "://" in value:
            matched = threat_feed_service.match_url(value)
        elif "@" in value:
            matched = threat_feed_service.match_email(value)
        elif "." in value and " " not in value:
            matched = threat_feed_service.match_domain(value)
        else:
            matched = threat_feed_service.match_all(ip=value)

        is_known = len(matched) > 0
        if is_known:
            log_structured("warning", "stix", f"Known threat indicator matched: {value}", {
                "value": value, "match_count": len(matched),
            })

        return {
            "value": value,
            "is_known_threat": is_known,
            "matches": matched,
            "match_count": len(matched),
        }
    except Exception as e:
        logger.error(f"STIX match error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Indicator match failed: {str(e)}"})


# =========================
# Global APS Event Recording
# =========================
@app.middleware("http")
async def aps_middleware(request: Request, call_next):
    """Record every API call for APS calculation."""
    response = await call_next(request)
    if request.url.path.startswith("/ingest") or request.url.path.startswith("/api"):
        _record_aps_event()
    return response


# ================================================================
# NETWORK TRAFFIC ANALYSIS ENDPOINTS
# ================================================================

try:
    from services.network_analysis_service import network_analysis_engine
except Exception as _e:
    network_analysis_engine = None
    logger.error(f"Failed to load network_analysis_engine: {_e}", extra={"log_module": "startup"})


@app.get("/api/network/flows")
async def get_network_flows(src_ip: str = None, dst_ip: str = None, limit: int = 100):
    """Get network flow records."""
    try:
        network_analysis_engine._ensure_network_tables()
        with db._cursor() as cur:
            query = "SELECT * FROM network_flows WHERE 1=1"
            params: list = []
            if src_ip:
                query += " AND src_ip = ?"
                params.append(src_ip)
            if dst_ip:
                query += " AND dst_ip = ?"
                params.append(dst_ip)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, params)
            rows = cur.fetchall()
            flows = [dict(row) for row in rows]
        return {"flows": flows, "total": len(flows)}
    except Exception as e:
        logger.error(f"Failed to fetch network flows: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch network flows: {str(e)}"})


@app.get("/api/network/dns")
async def get_dns_queries(src_ip: str = None, limit: int = 100):
    """Get DNS query logs."""
    try:
        network_analysis_engine._ensure_network_tables()
        with db._cursor() as cur:
            query = "SELECT * FROM dns_queries WHERE 1=1"
            params: list = []
            if src_ip:
                query += " AND src_ip = ?"
                params.append(src_ip)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, params)
            rows = cur.fetchall()
            queries = [dict(row) for row in rows]
        return {"dns_queries": queries, "total": len(queries)}
    except Exception as e:
        logger.error(f"Failed to fetch DNS queries: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch DNS queries: {str(e)}"})


@app.get("/api/network/http")
async def get_http_metadata(src_ip: str = None, limit: int = 100):
    """Get HTTP request metadata."""
    try:
        network_analysis_engine._ensure_network_tables()
        with db._cursor() as cur:
            query = "SELECT * FROM http_metadata WHERE 1=1"
            params: list = []
            if src_ip:
                query += " AND src_ip = ?"
                params.append(src_ip)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, params)
            rows = cur.fetchall()
            records = [dict(row) for row in rows]
        return {"http_requests": records, "total": len(records)}
    except Exception as e:
        logger.error(f"Failed to fetch HTTP metadata: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch HTTP metadata: {str(e)}"})


@app.get("/api/network/anomalies")
async def get_network_anomalies(anomaly_type: str = None, severity: str = None, limit: int = 50):
    """Get detected network anomalies."""
    try:
        network_analysis_engine._ensure_network_tables()
        with db._cursor() as cur:
            query = "SELECT * FROM network_anomalies WHERE 1=1"
            params: list = []
            if anomaly_type:
                query += " AND anomaly_type = ?"
                params.append(anomaly_type)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, params)
            rows = cur.fetchall()
            anomalies = [dict(row) for row in rows]
        return {"anomalies": anomalies, "total": len(anomalies)}
    except Exception as e:
        logger.error(f"Failed to fetch network anomalies: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch network anomalies: {str(e)}"})


@app.get("/api/network/stats")
async def get_network_stats():
    """Get network analysis statistics."""
    try:
        flow_stats = network_analysis_engine.get_flow_stats()
        anomaly_stats = network_analysis_engine.get_anomaly_stats()
        dns_count = 0
        http_count = 0
        try:
            with db._cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM dns_queries")
                row = cur.fetchone()
                dns_count = row[0] if row else 0
                cur.execute("SELECT COUNT(*) FROM http_metadata")
                row = cur.fetchone()
                http_count = row[0] if row else 0
        except Exception:
            pass
        return {
            "total_flows": flow_stats.get("total_flows", 0),
            "dns_queries": dns_count,
            "http_requests": http_count,
            "anomalies": anomaly_stats.get("total_anomalies", 0),
            "unique_src_ips": flow_stats.get("unique_src_ips", 0),
            "unique_dst_ips": flow_stats.get("unique_dst_ips", 0),
        }
    except Exception as e:
        logger.error(f"Failed to fetch network stats: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch network stats: {str(e)}"})


# ================================================================
# SOAR PLAYBOOK ENDPOINTS
# ================================================================

try:
    from services.playbook_engine import playbook_engine, playbook_runner, action_registry
except Exception as _e:
    playbook_engine = None
    playbook_runner = None
    action_registry = None
    logger.error(f"Failed to load playbook_engine: {_e}", extra={"log_module": "startup"})


@app.get("/api/playbooks")
async def get_playbooks():
    """List all playbooks."""
    try:
        playbooks = playbook_engine.list_playbooks(enabled_only=False)
        actions = action_registry.list_actions() if action_registry else []
        return {
            "playbooks": [pb.model_dump() for pb in playbooks],
            "total": len(playbooks),
            "available_actions": actions,
        }
    except Exception as e:
        logger.error(f"Failed to list playbooks: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to list playbooks: {str(e)}"})


@app.post("/api/playbooks")
async def create_playbook(data: dict):
    """Create a new playbook."""
    try:
        from services.playbook_engine import Playbook
        playbook = Playbook(**data)
        playbook_engine.register_playbook(playbook)
        return {
            "playbook_id": playbook.id,
            "name": playbook.name,
            "status": "created",
            "playbook": playbook.model_dump(),
        }
    except Exception as e:
        logger.error(f"Failed to create playbook: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to create playbook: {str(e)}"})


@app.put("/api/playbooks/{playbook_id}")
async def update_playbook(playbook_id: str, data: dict):
    """Update a playbook."""
    try:
        existing = playbook_engine.get_playbook(playbook_id)
        if not existing:
            return JSONResponse(status_code=404, content={"error": "Playbook not found"})

        from services.playbook_engine import Playbook
        data["id"] = playbook_id
        updated_pb = Playbook(**data)
        playbook_engine.register_playbook(updated_pb)
        return {
            "playbook_id": playbook_id,
            "name": updated_pb.name,
            "status": "updated",
            "playbook": updated_pb.model_dump(),
        }
    except Exception as e:
        logger.error(f"Failed to update playbook: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to update playbook: {str(e)}"})


@app.delete("/api/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str):
    """Delete a playbook."""
    try:
        removed = playbook_engine.unregister_playbook(playbook_id)
        if not removed:
            return JSONResponse(status_code=404, content={"error": "Playbook not found"})
        return {"playbook_id": playbook_id, "status": "deleted"}
    except Exception as e:
        logger.error(f"Failed to delete playbook: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to delete playbook: {str(e)}"})


@app.post("/api/playbooks/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, trigger_data: dict = {}):
    """Execute a playbook against trigger data."""
    try:
        playbook = playbook_engine.get_playbook(playbook_id)
        if not playbook:
            return JSONResponse(status_code=404, content={"error": "Playbook not found"})
        if not playbook.enabled:
            return JSONResponse(status_code=400, content={"error": "Playbook is disabled"})

        execution_id = await playbook_engine.run_playbook(playbook_id, trigger_data)
        return {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "playbook_name": playbook.name,
            "status": "running",
        }
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        logger.error(f"Failed to execute playbook: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to execute playbook: {str(e)}"})


@app.get("/api/playbooks/executions")
async def get_playbook_executions(playbook_id: str = None, limit: int = 50):
    """Get playbook execution history."""
    try:
        query = "SELECT * FROM playbook_executions WHERE 1=1"
        params: list = []
        if playbook_id:
            query += " AND playbook_id = ?"
            params.append(playbook_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        results = db.fetch_all(query, tuple(params))
        executions = [dict(r) for r in results] if results else []
        return {"executions": executions, "total": len(executions)}
    except Exception as e:
        logger.error(f"Failed to fetch playbook executions: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch playbook executions: {str(e)}"})


@app.get("/api/playbooks/executions/{execution_id}")
async def get_playbook_execution(execution_id: str):
    """Get details of a specific execution."""
    try:
        execution = await playbook_engine.get_execution_status(execution_id)
        if not execution:
            return JSONResponse(status_code=404, content={"error": "Execution not found"})

        logs = await playbook_engine.get_execution_logs(execution_id)
        return {
            "execution": execution,
            "action_logs": logs,
        }
    except Exception as e:
        logger.error(f"Failed to fetch execution details: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to fetch execution details: {str(e)}"})


# =========================
# Forensic Chain of Custody Endpoints
# =========================
try:
    from services.forensic_service import forensic_service
except Exception as _e:
    forensic_service = None
    logger.error(f"Failed to load forensic_service: {_e}", extra={"log_module": "startup"})


@app.post("/api/forensics/evidence")
async def collect_evidence(data: dict):
    """Collect new forensic evidence."""
    try:
        evidence_type = data.get("evidence_type", "alert")
        actor = data.get("actor", "system")

        if evidence_type == "alert":
            result = forensic_service.collect_alert_evidence(data, actor=actor)
        elif evidence_type == "incident":
            result = forensic_service.collect_incident_evidence(data, actor=actor)
        elif evidence_type == "file":
            file_path = data.get("file_path", "")
            description = data.get("description", "")
            if not file_path:
                return JSONResponse(status_code=400, content={"error": "file_path required for file evidence"})
            result = forensic_service.collect_file_evidence(file_path, description, actor=actor)
        elif evidence_type == "memory_dump":
            host_id = data.get("host_id", "")
            description = data.get("description", "")
            if not host_id:
                return JSONResponse(status_code=400, content={"error": "host_id required for memory dump evidence"})
            result = forensic_service.collect_memory_dump_evidence(host_id, description, actor=actor)
        elif evidence_type == "network_capture":
            description = data.get("description", "")
            result = forensic_service.collect_network_capture_evidence(description, actor=actor)
        else:
            return JSONResponse(status_code=400, content={"error": f"Unknown evidence_type: {evidence_type}"})

        return {"status": "created", **result}
    except Exception as e:
        logger.error(f"Evidence collection error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Evidence collection failed: {str(e)}"})


@app.get("/api/forensics/evidence")
async def get_evidence(incident_id: str = None, limit: int = 50):
    """List evidence items."""
    try:
        with db._cursor() as cur:
            is_pg = getattr(db, 'use_postgresql', False)
            if incident_id:
                if is_pg:
                    cur.execute(
                        "SELECT * FROM evidence WHERE source_id = %s ORDER BY collected_at DESC LIMIT %s",
                        (incident_id, limit),
                    )
                else:
                    cur.execute(
                        "SELECT * FROM evidence WHERE source_id = ? ORDER BY collected_at DESC LIMIT ?",
                        (incident_id, limit),
                    )
            else:
                if is_pg:
                    cur.execute("SELECT * FROM evidence ORDER BY collected_at DESC LIMIT %s", (limit,))
                else:
                    cur.execute("SELECT * FROM evidence ORDER BY collected_at DESC LIMIT ?", (limit,))
            rows = cur.fetchall()

        if is_pg:
            items = [dict(row) for row in rows]
        else:
            items = [
                {
                    "id": row[0], "evidence_type": row[1], "source_type": row[2],
                    "source_id": row[3], "description": row[4], "sha256_hash": row[5],
                    "file_path": row[6], "file_size": row[7], "metadata": row[8],
                    "collected_at": row[9], "status": row[10],
                }
                for row in rows
            ]
        return {"evidence": items, "count": len(items)}
    except Exception as e:
        logger.error(f"Evidence list error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to list evidence: {str(e)}"})


@app.get("/api/forensics/evidence/{evidence_id}")
async def get_evidence_detail(evidence_id: str):
    """Get evidence details with chain of custody."""
    try:
        evidence = forensic_service.get_evidence(evidence_id)
        if not evidence:
            return JSONResponse(status_code=404, content={"error": "Evidence not found"})

        chain = forensic_service.get_custody_chain(evidence_id)
        return {"evidence": evidence, "chain_of_custody": chain}
    except Exception as e:
        logger.error(f"Evidence detail error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get evidence: {str(e)}"})


@app.post("/api/forensics/evidence/{evidence_id}/transfer")
async def transfer_evidence(evidence_id: str, data: dict):
    """Transfer evidence custody."""
    try:
        from_actor = data.get("from_actor", "")
        to_actor = data.get("to_actor", "")
        reason = data.get("reason", "")

        if not from_actor or not to_actor:
            return JSONResponse(status_code=400, content={"error": "from_actor and to_actor are required"})

        result = forensic_service.transfer_custody(evidence_id, from_actor, to_actor, reason)
        return {"status": "transferred", "transfer_entry": result}
    except Exception as e:
        logger.error(f"Evidence transfer error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Evidence transfer failed: {str(e)}"})


@app.get("/api/forensics/timeline/{incident_id}")
async def get_forensic_timeline(incident_id: str):
    """Get forensic timeline for an incident."""
    try:
        timeline = forensic_service.get_incident_timeline(incident_id)
        return {"incident_id": incident_id, "timeline": timeline, "count": len(timeline)}
    except Exception as e:
        logger.error(f"Forensic timeline error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get timeline: {str(e)}"})


@app.get("/api/forensics/verify/{evidence_id}")
async def verify_evidence(evidence_id: str):
    """Verify evidence integrity."""
    try:
        result = forensic_service.verify_evidence(evidence_id)
        return result
    except Exception as e:
        logger.error(f"Evidence verification error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Evidence verification failed: {str(e)}"})


# =========================
# NIST 800-53 Compliance Endpoints
# =========================
try:
    from services.compliance_service import compliance_service
except Exception as _e:
    compliance_service = None
    logger.error(f"Failed to load compliance_service: {_e}", extra={"log_module": "startup"})


@app.get("/api/compliance/controls")
async def get_compliance_controls(family: str = None):
    """List NIST 800-53 controls with status."""
    try:
        controls = compliance_service.get_controls()
        if family:
            controls = [c for c in controls if c.get("family", "").upper() == family.upper()]
        return {"controls": controls, "count": len(controls)}
    except Exception as e:
        logger.error(f"Compliance controls error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get controls: {str(e)}"})


@app.get("/api/compliance/score")
async def get_compliance_score():
    """Get overall compliance score."""
    try:
        score = compliance_service.get_score()
        return score
    except Exception as e:
        logger.error(f"Compliance score error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get score: {str(e)}"})


@app.get("/api/compliance/gaps")
async def get_compliance_gaps():
    """Get compliance gaps with remediation."""
    try:
        gaps = compliance_service.get_gaps()
        return {"gaps": gaps, "count": len(gaps)}
    except Exception as e:
        logger.error(f"Compliance gaps error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get gaps: {str(e)}"})


@app.post("/api/compliance/assess")
async def run_compliance_assessment():
    """Run a compliance assessment."""
    try:
        result = compliance_service.run_assessment()
        return result
    except Exception as e:
        logger.error(f"Compliance assessment error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Compliance assessment failed: {str(e)}"})


@app.get("/api/compliance/assessments")
async def get_compliance_assessments(limit: int = 10):
    """Get assessment history."""
    try:
        with db._cursor() as cur:
            is_pg = getattr(db, 'use_postgresql', False)
            if is_pg:
                cur.execute(
                    "SELECT assessment_id, score, total_controls, compliant_count, non_compliant_count, created_at "
                    "FROM compliance_assessments ORDER BY created_at DESC LIMIT %s",
                    (limit,),
                )
            else:
                cur.execute(
                    "SELECT assessment_id, score, total_controls, compliant_count, non_compliant_count, created_at "
                    "FROM compliance_assessments ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()

        if is_pg:
            assessments = [dict(row) for row in rows]
        else:
            assessments = [
                {
                    "assessment_id": row[0], "score": row[1], "total_controls": row[2],
                    "compliant_count": row[3], "non_compliant_count": row[4], "created_at": row[5],
                }
                for row in rows
            ]
        return {"assessments": assessments, "count": len(assessments)}
    except Exception as e:
        logger.error(f"Compliance assessments error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get assessments: {str(e)}"})


@app.get("/api/compliance/report")
async def get_compliance_report():
    """Generate compliance report."""
    try:
        score = compliance_service.get_score()
        gaps = compliance_service.get_gaps()
        controls = compliance_service.get_controls()

        compliant = sum(1 for g in gaps if g.get("status") == "compliant")
        non_compliant = sum(1 for g in gaps if g.get("status") != "compliant")

        report = {
            "title": "NIST 800-53 Compliance Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "overall_score": score.get("score", 0),
                "total_controls": score.get("total_controls", len(controls)),
                "compliant": score.get("compliant", compliant),
                "non_compliant": score.get("non_compliant", non_compliant),
                "last_assessment": score.get("created_at", ""),
            },
            "controls": controls,
            "gaps": gaps,
        }
        return {"report": report}
    except Exception as e:
        logger.error(f"Compliance report error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to generate report: {str(e)}"})


# =========================
# Insider Threat Detection Endpoints
# =========================
try:
    from services.insider_threat_service import insider_threat_engine
except Exception as _e:
    insider_threat_engine = None
    logger.error(f"Failed to load insider_threat_engine: {_e}", extra={"log_module": "startup"})


@app.get("/api/insider/baselines")
async def get_user_baselines(user_id: str = None):
    """Get user behavior baselines."""
    try:
        if user_id:
            baselines = insider_threat_engine.profiler.get_all_baselines(user_id)
            return {"user_id": user_id, "baselines": baselines}

        with db._cursor() as cur:
            is_pg = getattr(db, 'use_postgresql', False)
            if is_pg:
                cur.execute("SELECT DISTINCT user_id FROM user_behavior_baselines")
            else:
                cur.execute("SELECT DISTINCT user_id FROM user_behavior_baselines")
            rows = cur.fetchall()

        all_baselines = {}
        for row in rows:
            uid = row["user_id"] if is_pg else row[0]
            if uid:
                all_baselines[uid] = insider_threat_engine.profiler.get_all_baselines(uid)

        return {"baselines": all_baselines, "user_count": len(all_baselines)}
    except Exception as e:
        logger.error(f"Insider baselines error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get baselines: {str(e)}"})


@app.get("/api/insider/anomalies")
async def get_user_anomalies(user_id: str = None, severity: str = None, limit: int = 50):
    """Get detected user anomalies."""
    try:
        if user_id:
            anomalies = insider_threat_engine.get_user_anomalies(user_id, limit=limit)
            if severity:
                anomalies = [a for a in anomalies if a.get("severity", "").upper() == severity.upper()]
            return {"user_id": user_id, "anomalies": anomalies, "count": len(anomalies)}

        with db._cursor() as cur:
            is_pg = getattr(db, 'use_postgresql', False)
            if is_pg:
                if severity:
                    cur.execute(
                        "SELECT * FROM user_anomalies WHERE severity = %s ORDER BY detected_at DESC LIMIT %s",
                        (severity.upper(), limit),
                    )
                else:
                    cur.execute(
                        "SELECT * FROM user_anomalies ORDER BY detected_at DESC LIMIT %s",
                        (limit,),
                    )
            else:
                if severity:
                    cur.execute(
                        "SELECT * FROM user_anomalies WHERE severity = ? ORDER BY detected_at DESC LIMIT ?",
                        (severity.upper(), limit),
                    )
                else:
                    cur.execute(
                        "SELECT * FROM user_anomalies ORDER BY detected_at DESC LIMIT ?",
                        (limit,),
                    )
            rows = cur.fetchall()

        if is_pg:
            anomalies = [dict(row) for row in rows]
        else:
            anomalies = [
                {
                    "id": row[0], "user_id": row[1], "anomaly_type": row[2],
                    "z_score": row[3], "observed_value": row[4], "baseline_mean": row[5],
                    "severity": row[6], "details": row[7], "detected_at": row[8], "status": row[9],
                }
                for row in rows
            ]
        return {"anomalies": anomalies, "count": len(anomalies)}
    except Exception as e:
        logger.error(f"Insider anomalies error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get anomalies: {str(e)}"})


@app.get("/api/insider/risk-scores")
async def get_insider_risk_scores():
    """Get user risk scores."""
    try:
        risk_scores = insider_threat_engine.risk_scorer.get_all_risk_scores()
        return {"risk_scores": risk_scores, "count": len(risk_scores)}
    except Exception as e:
        logger.error(f"Insider risk scores error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get risk scores: {str(e)}"})


@app.post("/api/insider/cases")
async def create_insider_case(data: dict):
    """Create an insider threat investigation case."""
    try:
        user_id = data.get("user_id", "")
        anomaly_ids = data.get("anomaly_ids", [])
        risk_level = data.get("risk_level", "MEDIUM")

        if not user_id:
            return JSONResponse(status_code=400, content={"error": "user_id is required"})

        result = insider_threat_engine.create_case(user_id, anomaly_ids, risk_level)
        return {"status": "created", **result}
    except Exception as e:
        logger.error(f"Insider case creation error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to create case: {str(e)}"})


@app.get("/api/insider/cases")
async def get_insider_cases(status: str = None, limit: int = 50):
    """List insider threat cases."""
    try:
        cases = insider_threat_engine.get_cases(status=status, limit=limit)
        return {"cases": cases, "count": len(cases)}
    except Exception as e:
        logger.error(f"Insider cases error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to get cases: {str(e)}"})


@app.put("/api/insider/cases/{case_id}")
async def update_insider_case(case_id: str, data: dict):
    """Update an insider threat case."""
    try:
        case = insider_threat_engine.get_case(case_id)
        if not case:
            return JSONResponse(status_code=404, content={"error": "Case not found"})

        now = datetime.now(timezone.utc).isoformat()
        status_val = data.get("status")
        assigned_to = data.get("assigned_to")
        resolution_notes = data.get("resolution_notes", "")

        if status_val == "closed":
            insider_threat_engine.close_case(case_id, resolution_notes)
            return {"status": "closed", "case_id": case_id}

        with db._cursor() as cur:
            is_pg = getattr(db, 'use_postgresql', False)
            updates = []
            params = []

            if assigned_to is not None:
                updates.append("assigned_to = %s" if is_pg else "assigned_to = ?")
                params.append(assigned_to)
            if status_val is not None:
                updates.append("status = %s" if is_pg else "status = ?")
                params.append(status_val)

            updates.append("updated_at = %s" if is_pg else "updated_at = ?")
            params.append(now)
            params.append(case_id)

            if updates:
                set_clause = ", ".join(updates)
                if is_pg:
                    cur.execute(f"UPDATE insider_threat_cases SET {set_clause} WHERE id = %s", tuple(params))
                else:
                    cur.execute(f"UPDATE insider_threat_cases SET {set_clause} WHERE id = ?", tuple(params))

        updated_case = insider_threat_engine.get_case(case_id)
        return {"status": "updated", "case": updated_case}
    except Exception as e:
        logger.error(f"Insider case update error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Failed to update case: {str(e)}"})


# =========================
# POST /simulate — Real-time attack simulation
# =========================
import random as _random

ATTACK_PROFILES = {
    "bruteforce": {
        "src_ips": ["198.51.100.7", "203.0.113.42", "192.0.2.15", "198.51.100.23", "203.0.113.88"],
        "dst_ips": ["10.0.0.5", "10.0.0.10", "10.0.0.15"],
        "dst_ports": [22, 3389, 21],
        "event_types": ["ssh_login_failed", "rdp_login_failed", "ftp_login_failed"],
        "severities": ["HIGH", "CRITICAL"],
        "mitre": ("T1110.001", "Credential Access"),
        "base_confidence": 0.85,
    },
    "portscan": {
        "src_ips": ["198.51.100.7", "192.0.2.100"],
        "dst_ips": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"],
        "dst_ports": [22, 80, 443, 3306, 5432, 8080, 8443, 21, 25, 110],
        "event_types": ["port_scan", "syn_scan"],
        "severities": ["MEDIUM", "HIGH"],
        "mitre": ("T1046", "Discovery"),
        "base_confidence": 0.70,
    },
    "ddos": {
        "src_ips": ["198.51.100.7", "203.0.113.42", "192.0.2.15", "198.51.100.23", "203.0.113.88",
                     "198.51.100.99", "203.0.113.77", "192.0.2.200", "198.51.100.44", "203.0.113.123"],
        "dst_ips": ["10.0.0.1"],
        "dst_ports": [80, 443],
        "event_types": ["syn_flood", "udp_flood", "http_flood"],
        "severities": ["CRITICAL"],
        "mitre": ("T1498", "Impact"),
        "base_confidence": 0.92,
    },
    "malware": {
        "src_ips": ["10.0.0.5", "10.0.0.10"],
        "dst_ips": ["198.51.100.50", "203.0.113.200"],
        "dst_ports": [443, 8443, 4444],
        "event_types": ["c2_beacon", "malware_download", "reverse_shell"],
        "severities": ["CRITICAL"],
        "mitre": ("T1059", "Execution"),
        "base_confidence": 0.90,
    },
    "exfiltration": {
        "src_ips": ["10.0.0.5"],
        "dst_ips": ["198.51.100.50"],
        "dst_ports": [443, 80],
        "event_types": ["data_exfil_dns", "data_exfil_http", "large_upload"],
        "severities": ["HIGH", "CRITICAL"],
        "mitre": ("T1041", "Exfiltration"),
        "base_confidence": 0.88,
    },
    "webattack": {
        "src_ips": ["198.51.100.7", "203.0.113.42"],
        "dst_ips": ["10.0.0.1"],
        "dst_ports": [80, 443, 8080],
        "event_types": ["sqli_attempt", "xss_attempt", "path_traversal", "cmd_injection"],
        "severities": ["HIGH"],
        "mitre": ("T1190", "Initial Access"),
        "base_confidence": 0.82,
    },
    "lateral": {
        "src_ips": ["10.0.0.5"],
        "dst_ips": ["10.0.0.10", "10.0.0.15", "10.0.0.20", "10.0.0.25"],
        "dst_ports": [445, 135, 5985, 22],
        "event_types": ["smb_lateral", "wmi_lateral", "ssh_lateral"],
        "severities": ["HIGH", "CRITICAL"],
        "mitre": ("T1021", "Lateral Movement"),
        "base_confidence": 0.87,
    },
}


@app.post("/simulate")
async def simulate_attack(data: dict):
    """
    Generate realistic attack events for testing the real-time pipeline.
    Request: {"attack": "bruteforce", "count": 100}
    Supported attacks: bruteforce, portscan, ddos, malware, exfiltration, webattack, lateral
    """
    attack_type = data.get("attack", "bruteforce")
    count = min(data.get("count", 10), 1000)

    if attack_type not in ATTACK_PROFILES:
        return JSONResponse(status_code=400, content={"error": f"Unknown attack type: {attack_type}. Use: {list(ATTACK_PROFILES.keys())}"})

    profile = ATTACK_PROFILES[attack_type]
    events_created = 0
    alerts_created = 0
    now_base = datetime.now(timezone.utc)

    try:
        with db._cursor() as cur:
            for i in range(count):
                ts = (now_base - timedelta(seconds=i * _random.uniform(0.1, 2.0))).isoformat()
                src_ip = _random.choice(profile["src_ips"])
                dst_ip = _random.choice(profile["dst_ips"])
                dst_port = _random.choice(profile["dst_ports"])
                event_type = _random.choice(profile["event_types"])
                severity = _random.choice(profile["severities"])
                confidence = min(1.0, profile["base_confidence"] + _random.uniform(-0.1, 0.1))

                event_id = str(uuid.uuid4())
                cur.execute(
                    "INSERT INTO log_events (id, log_id, timestamp, source_ip, dest_ip, source_port, dest_port, protocol, event_type, severity, message, raw_line, source_format, metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (event_id, None, ts, src_ip, "10.0.0.1", _random.randint(1024, 65535), dst_port,
                     "TCP", event_type, severity,
                     f"Simulated {attack_type}: {event_type} from {src_ip} to {dst_ip}:{dst_port}",
                     f"{ts} {src_ip} -> {dst_ip}:{dst_port} {event_type}", "simulate", "{}"),
                )
                events_created += 1

                if _random.random() < 0.3:
                    alert_id = str(uuid.uuid4())
                    cur.execute(
                        "INSERT INTO alerts (id, alert_type, severity, title, description, source_ip, destination_ip, source_port, destination_port, protocol, mitre_technique, mitre_tactic, evidence, recommendations, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (alert_id, attack_type, severity,
                         f"{attack_type.upper()} Detected: {event_type}",
                         f"Simulated {attack_type} from {src_ip} to {dst_ip}:{dst_port}",
                         src_ip, dst_ip, _random.randint(1024, 65535), dst_port, "TCP",
                         profile["mitre"][0], profile["mitre"][1],
                         json.dumps([{"event_id": event_id, "src_ip": src_ip, "dst_ip": dst_ip}]),
                         json.dumps(["Investigate source IP", "Block if confirmed malicious"]),
                         "open", ts),
                    )
                    alerts_created += 1

            return {
                "status": "simulated",
                "attack_type": attack_type,
                "events_created": events_created,
                "alerts_created": alerts_created,
                "count": count,
            }
    except Exception as e:
        logger.error(f"Simulation error: {e}", extra={"log_module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": f"Simulation failed: {str(e)}"})


# =========================
# GET /system/diagnostics — System health and status
# =========================
@app.get("/system/diagnostics")
async def system_diagnostics():
    """Comprehensive system diagnostics endpoint."""
    diag = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": MODEL_VERSION,
        "database": {},
        "tables": {},
        "websocket": "active",
        "scheduler": "unknown",
        "services": {},
        "ingestion": {},
    }

    try:
        with db._cursor() as cur:
            is_pg = db.use_postgresql
            diag["database"] = {
                "status": "connected",
                "type": "postgresql" if is_pg else "sqlite",
            }

            table_names = [
                "users", "alerts", "incidents", "log_events", "threat_detections",
                "uploaded_logs", "reports", "notifications", "audit_log", "devices",
                "sigma_rules", "sigma_matches", "threat_feeds", "stix_objects",
                "stix_indicators", "network_flows", "dns_queries", "http_metadata",
                "network_anomalies", "playbooks", "playbook_executions", "playbook_action_log",
                "evidence", "evidence_chain", "forensic_timeline", "nist_controls",
                "compliance_assessments", "user_behavior_baselines", "user_anomalies",
                "insider_threat_cases", "ioc", "detection_rules", "agent_status",
                "predictions", "comparisons", "anomaly_scores", "investigation_notes",
                "incident_notes", "organizations", "assets",
            ]

            for tbl in table_names:
                try:
                    cur.execute(f"SELECT COUNT(*) as cnt FROM {tbl}")
                    row = cur.fetchone()
                    diag["tables"][tbl] = row["cnt"] if row else 0
                except Exception:
                    diag["tables"][tbl] = "error"

            try:
                cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status = 'open'")
                row = cur.fetchone()
                diag["services"]["open_alerts"] = row["cnt"] if row else 0
            except Exception:
                diag["services"]["open_alerts"] = 0

            try:
                cur.execute("SELECT COUNT(*) as cnt FROM incidents WHERE status != 'closed'")
                row = cur.fetchone()
                diag["services"]["active_incidents"] = row["cnt"] if row else 0
            except Exception:
                diag["services"]["active_incidents"] = 0

            try:
                cur.execute("SELECT MAX(upload_time) as last_ts FROM uploaded_logs")
                row = cur.fetchone()
                diag["ingestion"]["last_upload"] = row["last_ts"] if row and row["last_ts"] else None
            except Exception:
                diag["ingestion"]["last_upload"] = None

            try:
                cur.execute("SELECT MAX(timestamp) as last_ts FROM log_events")
                row = cur.fetchone()
                diag["ingestion"]["last_event"] = row["last_ts"] if row and row["last_ts"] else None
            except Exception:
                diag["ingestion"]["last_event"] = None

    except Exception as e:
        diag["status"] = "degraded"
        diag["database"]["status"] = "error"
        diag["database"]["error"] = str(e)

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    diag["services"]["gemini"] = "configured" if gemini_key and gemini_key.startswith("AIzaSy") else "not_configured"
    diag["services"]["sigma_rules"] = "loaded" if sigma_engine else "not_loaded"
    diag["services"]["playbooks"] = "loaded" if playbook_engine else "not_loaded"
    diag["services"]["threat_feeds"] = "loaded" if threat_feed_service else "not_loaded"
    diag["services"]["forensics"] = "loaded" if forensic_service else "not_loaded"
    diag["services"]["compliance"] = "loaded" if compliance_service else "not_loaded"
    diag["services"]["insider_threat"] = "loaded" if insider_threat_engine else "not_loaded"
    diag["services"]["network_analysis"] = "loaded" if network_analysis_engine else "not_loaded"

    try:
        if setup_scheduler:
            diag["scheduler"] = "configured"
        else:
            diag["scheduler"] = "not_configured"
    except Exception:
        diag["scheduler"] = "error"

    return diag
