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
    Transparent threat score from real historical data.
    score = 0.40 * avg_confidence + 0.25 * critical_factor + 0.20 * disagreement_factor + 0.15 * drift_factor
    """
    pred_list = list(prediction_history)
    comp_list = list(comparison_history)

    if not pred_list:
        return {
            "score": 0,
            "breakdown": {
                "confidence_contribution": 0,
                "critical_alerts": 0,
                "model_conflict": 0,
                "drift_impact": 0,
            },
            "factors": {
                "avg_confidence": 0,
                "critical_count": 0,
                "disagreement_rate": 0,
                "drift_score": 0,
            },
        }

    # Factor 1: Average confidence (0-100)
    confidences = [p.get("confidence", 0) for p in pred_list]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0
    confidence_contribution = round(avg_confidence * 40, 1)

    # Factor 2: Critical alert count (capped at 10)
    critical_count = sum(1 for p in pred_list if p.get("severity_score", 0) >= SEVERITY_HIGH_THRESHOLD)
    critical_factor = min(critical_count * 2.5, 25)

    # Factor 3: Model disagreement rate (0-20)
    if comp_list:
        disagreements = sum(1 for c in comp_list if not c.get("agreement", True))
        disagreement_rate = disagreements / len(comp_list) if comp_list else 0
    else:
        disagreement_rate = 0
    disagreement_factor = round(disagreement_rate * 20, 1)

    # Factor 4: Drift impact (0-15)
    drift_list = list(drift_history)
    if drift_list:
        recent_drift = drift_list[0].get("score", 0)
    else:
        recent_drift = 0
    drift_factor = round(min(recent_drift * 15, 15), 1)

    total_score = min(100, round(
        confidence_contribution + critical_factor + disagreement_factor + drift_factor
    ))

    return {
        "score": total_score,
        "breakdown": {
            "confidence_contribution": confidence_contribution,
            "critical_alerts": round(critical_factor, 1),
            "model_conflict": round(disagreement_factor, 1),
            "drift_impact": drift_factor,
        },
        "factors": {
            "avg_confidence": round(avg_confidence, 4),
            "critical_count": critical_count,
            "disagreement_rate": round(disagreement_rate, 4),
            "drift_score": round(recent_drift, 4),
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
    return {"status": "healthy", "version": MODEL_VERSION}


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

    most_frequent = max(attack_dist, key=attack_dist.get) if attack_dist else "None"

    total_conf = sum(p.get("confidence", 0) for p in pred_list)
    avg_conf = total_conf / len(pred_list) if pred_list else 0

    total_lat = sum(p.get("latency_ms", 0) for p in pred_list)
    avg_lat = total_lat / len(pred_list) if pred_list else 0

    total_sev = sum(p.get("severity_score", 0) for p in pred_list)
    avg_sev = total_sev / len(pred_list) if pred_list else 0

    agree_count = sum(1 for c in comp_list if c.get("agreement", True))
    agree_rate = agree_count / len(comp_list) if comp_list else 0

    critical_count = sum(1 for p in pred_list if p.get("severity_score", 0) >= SEVERITY_HIGH_THRESHOLD)
    high_count = sum(1 for p in pred_list if SEVERITY_MEDIUM_THRESHOLD <= p.get("severity_score", 0) < SEVERITY_HIGH_THRESHOLD)

    threat = calculate_threat_score()

    return {
        "total_predictions": len(pred_list),
        "total_comparisons": len(comp_list),
        "total_simulations": 0,
        "attack_distribution": attack_dist,
        "most_frequent_attack": most_frequent,
        "average_confidence": round(avg_conf, 4),
        "average_latency": round(avg_lat, 2),
        "average_severity": round(avg_sev, 1),
        "agreement_rate": round(agree_rate, 4),
        "critical_alerts": critical_count,
        "high_alerts": high_count,
        "threat_score": threat,
        "recent_predictions": pred_list[:10],
        "recent_comparisons": comp_list[:10],
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
        logger.error(f"Prediction error: {e}", extra={"module": "api", "action": "error"})
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
        logger.error(f"Comparison error: {e}", extra={"module": "api", "action": "error"})
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
        logger.error(f"Drift detection error: {e}", extra={"module": "api", "action": "error"})
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
    try:
        last_event_count = 0
        while True:
            pred_list = list(prediction_history)
            threat_list = list(threat_events)
            current_count = len(pred_list) + len(threat_list)

            if current_count > last_event_count and pred_list:
                pred = pred_list[0]
                event = {
                    "id": f"evt-{uuid.uuid4().hex[:8]}",
                    "timestamp": pred.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "attack_type": pred.get("prediction", "Unknown"),
                    "confidence": pred.get("confidence", 0),
                    "severity_score": pred.get("severity_score", 0),
                    "severity": pred.get("severity", "LOW"),
                    "status": "DETECTED",
                }
                await websocket.send_json(event)
                last_event_count = current_count

            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass


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

        # Create alerts from detections
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
        logger.error(f"Log upload error: {e}", extra={"module": "api", "action": "error"})
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
        detections = db.get_threat_detections(limit=1000)
        all_events = []
        uploaded = db.get_uploaded_logs(limit=100)
        for log in uploaded:
            evts = db.get_log_events(log["id"], limit=5000)
            all_events.extend(evts)

        if data.report_type == "incident" and data.detection_id:
            detection = next((d for d in detections if d.get("id") == data.detection_id), None)
            if not detection:
                return JSONResponse(status_code=404, content={"error": "Detection not found"})
            related = [e for e in all_events if e.get("source_ip") == detection.get("source_ip")]
            report = report_generator.generate_incident_report(detection, related)
        elif data.report_type == "executive":
            stats = {
                "total_threats": len(detections),
                "critical_threats": sum(1 for d in detections if d.get("severity") == "CRITICAL"),
            }
            anomaly = db.get_latest_anomaly_score()
            report = report_generator.generate_executive_report(stats, detections, anomaly or {})
        else:
            anomaly = db.get_latest_anomaly_score()
            report = report_generator.generate_technical_report(all_events, detections, anomaly or {})

        report_id = str(uuid.uuid4())
        report["id"] = report_id
        db.create_report(data.report_type, report.get("title", "Report"), report)

        return {
            "report_id": report_id,
            "report_type": data.report_type,
            "report": report,
        }
    except Exception as e:
        logger.error(f"Report generation error: {e}", extra={"module": "api", "action": "error"})
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
        logger.error(f"Intel lookup error: {e}", extra={"module": "api", "action": "error"})
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
    }


# =========================
# Enhanced Copilot Endpoint
# =========================
@app.post("/copilot")
async def enhanced_copilot(data: CopilotRequest):
    try:
        question = data.question or f"Analyze {data.prediction} prediction"
        detections = db.get_threat_detections(limit=1000)

        all_ev = []
        uploaded = db.get_uploaded_logs(limit=100)
        for log in uploaded:
            evts = db.get_log_events(log["id"], limit=5000)
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

        db_stats = db.get_dashboard_stats()
        dashboard_stats = {
            "total_logs": db_stats.get('total_logs', 0),
            "total_events": db_stats.get('total_events', 0),
            "total_threats": db_stats.get('total_threats', 0),
            "critical_threats": db_stats.get('critical_threats', 0),
            "unique_source_ips": db_stats.get('unique_source_ips', 0),
            "avg_anomaly_score": db_stats.get('avg_anomaly_score', 0),
        }

        anomaly_result = db.get_latest_anomaly_score()

        result = await gemini_copilot.chat(
            question=question,
            detections=detections,
            anomaly_result=anomaly_result,
            events_summary=events_summary,
            dashboard_stats=dashboard_stats,
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
        }
    except Exception as e:
        logger.error(f"Enhanced copilot error: {e}", extra={"module": "api", "action": "error"})
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
    """Process a single ingested event: store, detect threats, return result."""
    event_dict = event.model_dump()
    event_dict['source_type'] = source

    log_id = db.create_uploaded_log(
        filename=f"ingest_{source}_{(event.timestamp or datetime.now(timezone.utc).isoformat())[:10]}",
        source_type=source,
        file_size=len(event.raw_log or event.message),
    )
    db.insert_log_events(log_id, [event_dict])

    detector = ThreatDetector()
    detections = detector.analyze_events([event_dict])
    if detections:
        db.insert_threat_detections(log_id, [d.to_dict() for d in detections])

    return {
        "log_id": log_id,
        "event_type": event.event_type,
        "severity": event.severity,
        "threats_detected": len(detections),
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
async def get_alerts(severity: str = "", status: str = "", limit: int = 100):
    """Get all alerts with optional filtering."""
    from database import db
    alerts = db.get_alerts(severity=severity or None, status=status or None, limit=limit)
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
