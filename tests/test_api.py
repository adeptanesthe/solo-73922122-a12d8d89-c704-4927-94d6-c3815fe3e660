"""API 层测试：FastAPI 路由、校验与示例端点。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.example import EXAMPLE
from app.main import app

client = TestClient(app)


def rule(src="10.0.0.0/24", dst="192.168.1.0/24", pl=80, ph=80, action="allow"):
    return {
        "src_cidr": src,
        "dst_cidr": dst,
        "port_low": pl,
        "port_high": ph,
        "action": action,
    }


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_index_page_served():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "防火墙规则变更核对工具" in resp.text


def test_example_endpoint_matches_embedded():
    resp = client.get("/api/example")
    assert resp.status_code == 200
    assert resp.json() == EXAMPLE
    assert len(resp.json()["old_rules"]) <= 20
    assert len(resp.json()["new_rules"]) <= 20


def test_analyze_happy_path():
    payload = {
        "old_rules": [rule(action="deny", pl=0, ph=65535, src="0.0.0.0/0", dst="0.0.0.0/0")],
        "new_rules": [
            rule(),
            rule(action="deny", pl=0, ph=65535, src="0.0.0.0/0", dst="0.0.0.0/0"),
        ],
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["newly_allowed"]) == 1
    assert data["newly_allowed"][0]["port_segment"]["label"] == "80"
    assert data["newly_blocked"] == []


def test_analyze_rejects_bad_cidr():
    payload = {
        "old_rules": [rule(src="10.0.0.1/24")],
        "new_rules": [rule()],
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 400
    assert "CIDR" in resp.json()["detail"]


def test_analyze_rejects_bad_action():
    bad = rule()
    bad["action"] = "permit"
    resp = client.post("/api/analyze", json={"old_rules": [bad], "new_rules": [rule()]})
    assert resp.status_code == 422


def test_analyze_rejects_port_out_of_range():
    bad = rule(ph=70000)
    resp = client.post("/api/analyze", json={"old_rules": [bad], "new_rules": [rule()]})
    assert resp.status_code == 422


def test_analyze_rejects_more_than_20_rules():
    payload = {
        "old_rules": [rule() for _ in range(21)],
        "new_rules": [rule()],
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 422


def test_analyze_accepts_empty_rule_lists_as_default_deny():
    # 空规则表合法：两侧均为全默认拒绝，结果无差异
    resp = client.post("/api/analyze", json={"old_rules": [], "new_rules": []})
    assert resp.status_code == 200
    data = resp.json()
    assert data["newly_allowed"] == []
    assert data["newly_blocked"] == []


def test_example_runs_through_full_pipeline():
    resp = client.post("/api/analyze", json=EXAMPLE)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # 示例同时包含新增放行（3306）与新增阻断（80）
    allowed_ports = {r["port_segment"]["low"] for r in data["newly_allowed"]}
    blocked_ports = {r["port_segment"]["low"] for r in data["newly_blocked"]}
    assert 3306 in allowed_ports
    assert 80 in blocked_ports
