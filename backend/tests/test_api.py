import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database import init_db

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()

@pytest.mark.asyncio
async def test_health_check_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "docker_sandbox_active" in data

@pytest.mark.asyncio
async def test_create_scan_validation_rejection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Loopback rejection without flag
        resp = await client.post("/api/scans", json={"target": "http://127.0.0.1:9090"})
        assert resp.status_code == 400
        assert "Blocked SSRF" in resp.json()["detail"] or "blocked" in resp.json()["detail"]
