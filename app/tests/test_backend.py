"""
Automated tests for SentinelAI backend.
Tests database, auth, services, and API endpoints.
"""
import os
import sys
import json
import time
import pytest

# Ensure app directory is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-ci")
os.environ.setdefault("DATABASE_PATH", ":memory:")


# ── Database Tests ──

class TestDatabase:
    """Test database operations."""

    def test_database_initializes(self):
        from database import db
        assert db is not None
        assert db.conn is not None

    def test_cursor_context_manager(self):
        from database import db
        with db._cursor() as cur:
            cur.execute("SELECT 1 as val")
            row = cur.fetchone()
            assert row is not None

    def test_user_creation_and_retrieval(self):
        from database import db
        import uuid
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"
        result = db.create_user(email, "hashed_password", "Test User")
        assert result is not None
        user = db.get_user_by_email(email)
        assert user is not None
        assert user["email"] == email
        assert user["name"] == "Test User"

    def test_threat_detection_insert(self):
        from database import db
        import uuid
        log_id = str(uuid.uuid4())
        # Create a log entry first
        try:
            db.insert_uploaded_log(log_id, "test.txt", "test_user")
        except Exception:
            pass
        detections = [{
            "threat_type": "brute_force",
            "severity": "HIGH",
            "confidence": 0.85,
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "dest_port": 22,
            "description": "Test brute force detection",
        }]
        inserted = db.insert_threat_detections(log_id, detections)
        assert inserted >= 0

    def test_alert_creation(self):
        from database import db
        alert_id = db.create_alert(
            alert_type="test_alert",
            severity="MEDIUM",
            title="Test Alert",
            description="Automated test alert",
            source_ip="10.0.0.1",
        )
        assert alert_id is not None
        alerts = db.get_alerts(limit=10)
        assert any(a.get("id") == alert_id for a in alerts)

    def test_audit_log(self):
        from database import db
        db.log_audit(user_id="test_user", action="test_action", details="test details")
        # If no exception, it passed


# ── Auth Tests ──

class TestAuth:
    """Test authentication system."""

    def test_password_hashing(self):
        from auth import hash_password, verify_password
        password = "TestPassword123!"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("WrongPassword", hashed)

    def test_jwt_tokens(self):
        from auth import create_access_token, create_refresh_token, verify_token
        data = {"sub": "test@example.com", "role": "analyst"}
        access = create_access_token(data)
        refresh = create_refresh_token(data)
        assert access is not None
        assert refresh is not None
        payload = verify_token(access)
        assert payload is not None
        assert payload["sub"] == "test@example.com"
        assert payload["role"] == "analyst"

    def test_otp_generation_and_verification(self):
        from auth import generate_otp, verify_otp
        email = "otp_test@example.com"
        generate_otp(email)
        # Wrong OTP should fail
        assert not verify_otp(email, "000000")
        # Correct OTP - we need to get it from DB
        from database import db
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("SELECT hash FROM otp_store WHERE email = %s", (email,))
            else:
                cur.execute("SELECT hash FROM otp_store WHERE email = ?", (email,))
            row = cur.fetchone()
        assert row is not None

    def test_rate_limiting(self):
        from auth import check_rate_limit
        key = f"test_rate_{int(time.time())}"
        # First request should pass
        assert check_rate_limit(key, max_requests=3, window_seconds=60)
        assert check_rate_limit(key, max_requests=3, window_seconds=60)
        assert check_rate_limit(key, max_requests=3, window_seconds=60)
        # Fourth should be rate limited
        assert not check_rate_limit(key, max_requests=3, window_seconds=60)

    def test_rbac(self):
        from auth import check_permission, require_role, ROLES
        assert check_permission("admin", "delete")
        assert check_permission("admin", "manage_users")
        assert not check_permission("viewer", "delete")
        assert not check_permission("viewer", "write")
        check = require_role("analyst")
        assert check("analyst")
        assert check("admin")
        assert not check("viewer")


# ── Service Tests ──

class TestServices:
    """Test backend services."""

    def test_parser_service(self):
        from services.parser_service import parser
        assert parser is not None

    def test_threat_detector(self):
        from services.threat_detection import ThreatDetector
        detector = ThreatDetector()
        assert detector is not None
        # Test with empty events
        detections = detector.analyze_events([])
        assert isinstance(detections, list)

    def test_anomaly_detector(self):
        from services.anomaly_service import anomaly_detector
        assert anomaly_detector is not None

    def test_mitre_mapper(self):
        from services.mitre_service import mitre_mapper
        assert mitre_mapper is not None

    def test_correlation_engine(self):
        from services.correlation_service import correlation_engine
        assert correlation_engine is not None

    def test_rule_engine(self):
        from services.rule_engine import detection_rule_engine
        assert detection_rule_engine is not None

    def test_geoip_service(self):
        from services.geoip_service import geoip_service
        assert geoip_service is not None

    def test_cache_service(self):
        from services.cache_service import cache_get, cache_set
        cache_set("test_key", {"data": "test"}, ttl=10)
        val = cache_get("test_key")
        # May be None if Redis not available, that's OK
        assert val is None or val == {"data": "test"}

    def test_model_loader(self):
        from model_loader import model, ATTACK_CLASSES, MODEL_VERSION
        assert model is not None
        assert len(ATTACK_CLASSES) == 7
        assert "DDoS" in ATTACK_CLASSES
        assert "rule-based" in MODEL_VERSION

    def test_report_service(self):
        from services.report_service import report_generator
        assert report_generator is not None
        # Test JSON export
        data = {"test": "data", "number": 42}
        json_out = report_generator.export_json(data)
        assert json.loads(json_out) == data

    def test_sigma_engine(self):
        from services.sigma_engine import sigma_engine
        assert sigma_engine is not None
        stats = sigma_engine.get_stats()
        assert "total_rules" in stats

    def test_playbook_engine(self):
        from services.playbook_engine import playbook_engine
        assert playbook_engine is not None

    def test_email_service(self):
        from services.email_service import send_otp_email
        assert callable(send_otp_email)


# ── API Endpoint Tests ──

class TestAPIEndpoints:
    """Test API endpoint definitions using httpx AsyncClient + ASGITransport."""

    @pytest.mark.anyio
    async def test_app_loads(self):
        import app
        assert app.app is not None

    @pytest.mark.anyio
    async def test_health_endpoint_exists(self):
        import httpx
        import app as app_module
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert "status" in data

    @pytest.mark.anyio
    async def test_stats_endpoint_exists(self):
        import httpx
        import app as app_module
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/stats")
            assert response.status_code == 200

    @pytest.mark.anyio
    async def test_login_endpoint_exists(self):
        import httpx
        import app as app_module
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/auth/login", json={"email": "test@test.com", "password": "wrong"})
            assert response.status_code in [400, 401, 404, 422]

    @pytest.mark.anyio
    async def test_events_search_endpoint(self):
        import httpx
        import app as app_module
        from auth import create_access_token
        token = create_access_token({"sub": "test@test.com", "role": "analyst", "org_id": "test-org"})
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/events/search", json={"q": "test", "limit": 10}, headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200

    @pytest.mark.anyio
    async def test_rule_packs_endpoint(self):
        import httpx
        import app as app_module
        from auth import create_access_token
        token = create_access_token({"sub": "test@test.com", "role": "analyst", "org_id": "test-org"})
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/rule-packs", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200
            data = response.json()
            assert "packs" in data
            assert data["total_packs"] > 0

    @pytest.mark.anyio
    async def test_sigma_rules_endpoint(self):
        import httpx
        import app as app_module
        from auth import create_access_token
        token = create_access_token({"sub": "test@test.com", "role": "analyst", "org_id": "test-org"})
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/sigma/rules", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200

    @pytest.mark.anyio
    async def test_threats_endpoint(self):
        import httpx
        import app as app_module
        from auth import create_access_token
        token = create_access_token({"sub": "test@test.com", "role": "analyst", "org_id": "test-org"})
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/threats", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
