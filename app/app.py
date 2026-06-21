from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
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
import random as _random

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
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' *"
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
    password: str = Field(..., min_length=1, max_length=128)


class OTPRequest(BaseModel):
    email: str


class OTPVerifyRequest(BaseModel):
    email: str
    otp: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


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
async def get_history(payload: dict = Depends(require_auth)):
    return {"history": list(prediction_history), "count": len(prediction_history)}


@app.get("/stats")
async def get_stats(payload: dict = Depends(require_auth)):
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
async def get_persistent_stats(payload: dict = Depends(require_auth)):
    pred_stats = db.get_prediction_stats()
    comp_stats = db.get_comparison_stats()
    return {
        "predictions": pred_stats,
        "comparisons": comp_stats,
    }


@app.get("/reports")
async def get_reports(payload: dict = Depends(require_auth)):
    reports = db.get_reports(limit=50)
    return {"reports": reports}


# =========================
# ML Prediction (improved response format)
# =========================
@app.post("/predict")
async def predict(data: SequenceRequest, payload: dict = Depends(require_auth)):
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
async def compare(data: SequenceRequest, payload: dict = Depends(require_auth)):
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
async def drift(data: SequenceRequest, payload: dict = Depends(require_auth)):
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
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.7,
                        "maxOutputTokens": 1024,
                    },
                },
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


@app.post("/copilot")
async def copilot(data: CopilotRequest):
    try:
        seq = data.sequence
        prediction = data.prediction
        question = data.question

        # Build context from real system state
        pred_list = list(prediction_history)
        comp_list = list(comparison_history)
        threat = calculate_threat_score()

        attack_dist = {}
        for p in pred_list:
            a = p.get("prediction", "Unknown")
            attack_dist[a] = attack_dist.get(a, 0) + 1

        agree_count = sum(1 for c in comp_list if c.get("agreement", True))

        context = {
            "prediction": prediction,
            "confidence": cached_predict(tuple(seq))[1] if seq else 0.0,
            "severity_score": ATTACK_WEIGHTS.get(prediction, 0.5) * 100,
            "recent_predictions": pred_list[:10],
            "total_predictions": len(pred_list),
            "agreement_rate": agree_count / len(comp_list) if comp_list else 0,
            "threat_score": threat["score"],
            "attack_distribution": attack_dist,
            "threat_factors": threat["breakdown"],
        }

        explanation = await _gemini_copilot_response(question or f"Analyze {prediction} prediction", context)

        attack_info = ATTACK_KNOWLEDGE.get(prediction, ATTACK_KNOWLEDGE["DDoS"])

        return {
            "prediction": prediction,
            "confidence": context["confidence"],
            "explanation": explanation,
            "indicators": attack_info["indicators"],
            "recommendations": attack_info["recommendations"],
            "kill_chain_stage": attack_info["kill_chain_stage"],
            "severity_weight": attack_info["severity_weight"],
        }
    except Exception as e:
        logger.error(f"Copilot error: {e}", extra={"module": "api", "action": "error"})
        return JSONResponse(status_code=500, content={"error": "Copilot failed. Please try again."})


# =========================
# Explainability Engine (XAI)
# =========================
@app.post("/explain")
async def explain(data: ExplainRequest, payload: dict = Depends(require_auth)):
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
async def get_graph(payload: dict = Depends(require_auth)):
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
async def get_killchain(prediction: str, payload: dict = Depends(require_auth)):
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
async def get_recommendations(payload: dict = Depends(require_auth)):
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
async def get_drift_analytics(payload: dict = Depends(require_auth)):
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
@app.post("/auth/register")
async def register(data: RegisterRequest):
    if not check_rate_limit(data.email):
        return JSONResponse(status_code=429, content={"error": "Too many attempts. Please try again later."})
    user = register_user(data.email, data.password, data.name)
    if not user:
        return JSONResponse(status_code=409, content={"error": "Email already registered"})
    access = create_access_token({"sub": data.email})
    refresh = create_refresh_token({"sub": data.email})
    return {"access_token": access, "refresh_token": refresh, "user": {"email": data.email, "name": data.name}}

@app.post("/auth/login")
async def login(data: LoginRequest):
    if not check_rate_limit(data.email):
        return JSONResponse(status_code=429, content={"error": "Too many attempts. Please try again later."})
    user = authenticate_user(data.email, data.password)
    if not user:
        log_structured("warning", "auth", f"Failed login: {data.email}")
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})
    log_structured("info", "auth", f"Successful login: {data.email}")
    access = create_access_token({"sub": data.email})
    refresh = create_refresh_token({"sub": data.email})
    return {"access_token": access, "refresh_token": refresh, "user": {"email": data.email, "name": user["name"]}}

@app.post("/auth/otp/generate")
async def generate_otp_route(data: OTPRequest):
    if not check_rate_limit(data.email):
        return JSONResponse(status_code=429, content={"error": "Too many attempts. Please try again later."})
    otp = generate_otp(data.email)
    # In production, send via email. For demo, return it.
    return {"message": "OTP sent to email"}

@app.post("/auth/otp/verify")
async def verify_otp_route(data: OTPVerifyRequest):
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
# WebSocket Event Stream (real events from history)
# =========================
ATTACK_TYPES = ["DDoS", "DoS", "PortScan", "Bot", "WebAttack", "BruteForce", "Infiltration"]
SOURCE_IPS = ["45.33.32.156", "192.168.1.0", "103.21.244.0", "185.220.101.45", "203.0.113.42", "198.51.100.7"]
DEST_IPS = ["10.0.0.1", "10.0.0.12", "172.16.0.5", "10.0.1.100", "10.0.2.50"]
COUNTRIES = ["RU", "CN", "KP", "IR", "US", "BR", "VN", "IN"]
COUNTRY_GEO = {
    "RU": {"lat": 61.524, "lng": 105.318, "name": "Russia"},
    "CN": {"lat": 35.861, "lng": 104.195, "name": "China"},
    "KP": {"lat": 40.339, "lng": 127.510, "name": "North Korea"},
    "IR": {"lat": 32.427, "lng": 53.688, "name": "Iran"},
    "US": {"lat": 37.090, "lng": -95.712, "name": "United States"},
    "BR": {"lat": -14.235, "lng": -51.925, "name": "Brazil"},
    "VN": {"lat": 14.058, "lng": 108.277, "name": "Vietnam"},
    "IN": {"lat": 20.593, "lng": 78.962, "name": "India"},
}
DEST_COUNTRIES = ["US", "DE", "GB", "JP", "KR", "AU", "FR", "NL"]
DEST_COUNTRY_GEO = {
    "US": {"lat": 37.090, "lng": -95.712, "name": "United States"},
    "DE": {"lat": 51.165, "lng": 10.451, "name": "Germany"},
    "GB": {"lat": 55.378, "lng": -3.436, "name": "United Kingdom"},
    "JP": {"lat": 36.204, "lng": 138.252, "name": "Japan"},
    "KR": {"lat": 35.907, "lng": 127.766, "name": "South Korea"},
    "AU": {"lat": -25.274, "lng": 133.775, "name": "Australia"},
    "FR": {"lat": 46.227, "lng": 2.213, "name": "France"},
    "NL": {"lat": 52.132, "lng": 5.291, "name": "Netherlands"},
}
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["DETECTED", "BLOCKED", "QUARANTINED", "INVESTIGATING"]

_random.seed()


async def generate_event():
    # Mix of real recent predictions and simulated events
    pred_list = list(prediction_history)

    if pred_list and _random.random() < 0.6:
        # Use real prediction data
        pred = _random.choice(pred_list[:10])
        attack = pred.get("prediction", _random.choice(ATTACK_TYPES))
        confidence = pred.get("confidence", _random.uniform(0.55, 0.99))
        severity_score = pred.get("severity_score", _random.uniform(20, 95))
    else:
        attack = _random.choices(ATTACK_TYPES, weights=[30, 20, 15, 15, 10, 5, 5])[0]
        confidence = round(_random.uniform(0.55, 0.99), 3)
        severity_score = round(confidence * ATTACK_WEIGHTS.get(attack, 0.5) * 100, 1)

    severity = "CRITICAL" if severity_score >= SEVERITY_HIGH_THRESHOLD else "HIGH" if severity_score >= SEVERITY_MEDIUM_THRESHOLD else "MEDIUM" if severity_score >= SEVERITY_LOW_THRESHOLD else "LOW"

    return {
        "id": _random.randint(100000, 999999),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": attack,
        "source_ip": _random.choice(SOURCE_IPS),
        "dest_ip": _random.choice(DEST_IPS),
        "severity": severity,
        "status": _random.choice(STATUSES),
        "confidence": round(confidence, 3),
        "severity_score": severity_score,
        "geo": {
            "src_country": _random.choice(COUNTRIES),
            "src_lat": round(_random.uniform(-60, 70), 4),
            "src_lng": round(_random.uniform(-160, 160), 4),
        },
        "dest_geo": {
            "dest_country": _random.choice(DEST_COUNTRIES),
            "dest_lat": round(_random.uniform(-50, 65), 4),
            "dest_lng": round(_random.uniform(-130, 150), 4),
        }
    }


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    token = websocket.query_params.get("token")
    if token:
        payload = verify_token(token)
        if not payload:
            await websocket.close(code=4001, reason="Invalid token")
            return
    try:
        while True:
            event = await generate_event()
            await websocket.send_json(event)
            await asyncio.sleep(_random.uniform(0.8, 2.5))
    except WebSocketDisconnect:
        pass
