"""证书轮换单元/接口测试：材料校验、SQLite CAS、持久化、并发与页面接入。"""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.cert_material import (
    CertificateValidationError,
    generate_material,
    validate_material,
)
from app.certstore import CertStore, VersionConflict
from app.main import create_app
from app.settings import Settings


def _material(key_bits=1024):
    return generate_material(key_bits=key_bits)


def _custom_rsa_cert(*, ca=False, san_dns=("localhost",), not_before=None, not_after=None, key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=1024)
    now = datetime.now(timezone.utc)
    not_before = not_before or now - timedelta(days=1)
    not_after = not_after or now + timedelta(days=365)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    names = [x509.DNSName(name) for name in san_dns]
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


# --------------------------------------------------------------------------- #
# 材料校验
# --------------------------------------------------------------------------- #
def test_valid_generated_material_passes():
    cert_pem, key_pem, info = _material()
    validated = validate_material(cert_pem, key_pem)
    assert validated.info.fingerprint_sha256 == info.fingerprint_sha256
    assert "localhost" in [name.lower() for name in validated.info.san_dns]
    assert validated.cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert validated.key_pem.startswith("-----BEGIN PRIVATE KEY-----")


def test_cert_and_key_mismatch_rejected():
    cert_a, _, _ = _material()
    _, key_b, _ = _material()
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_a, key_b)
    assert "不匹配" in str(excinfo.value)


def test_missing_localhost_dns_san_rejected():
    cert_pem, key_pem = _custom_rsa_cert(san_dns=("example.com",))
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_pem, key_pem)
    assert "localhost" in str(excinfo.value)


def test_no_san_extension_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_pem, key_pem)
    assert "SubjectAlternativeName" in str(excinfo.value)


def test_expired_cert_rejected():
    cert_pem, key_pem = _custom_rsa_cert(
        not_before=datetime.now(timezone.utc) - timedelta(days=10),
        not_after=datetime.now(timezone.utc) - timedelta(days=1),
    )
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_pem, key_pem)
    assert "过期" in str(excinfo.value)


def test_not_yet_valid_cert_rejected():
    cert_pem, key_pem = _custom_rsa_cert(
        not_before=datetime.now(timezone.utc) + timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
    )
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_pem, key_pem)
    assert "尚未生效" in str(excinfo.value)


def test_ca_true_rejected():
    cert_pem, key_pem = _custom_rsa_cert(ca=True)
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_pem, key_pem)
    assert "CA" in str(excinfo.value)


def test_missing_basic_constraints_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem)
    assert "BasicConstraints" in str(excinfo.value)


def test_encrypted_private_key_rejected():
    cert_pem, key_pem, _ = _material()
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    encrypted = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    ).decode()
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_pem, encrypted)
    assert "加密" in str(excinfo.value)


def test_multiple_certificates_rejected():
    cert_a, key_a, _ = _material()
    cert_b, _, _ = _material()
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert_a + cert_b, key_a)
    assert "只包含一张" in str(excinfo.value)


def test_non_rsa_certificate_rejected():
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with pytest.raises(CertificateValidationError) as excinfo:
        validate_material(cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem)
    assert "RSA" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# SQLite 仓库：初始化、持久化、CAS 与并发
# --------------------------------------------------------------------------- #
def _store(tmp_path, name="certs.db", key_bits=1024):
    store = CertStore(str(tmp_path / name), rsa_key_bits=key_bits)
    store.ensure_initialized()
    return store


def test_first_start_generates_demo_cert_and_samples(tmp_path):
    store = _store(tmp_path)
    snapshot = store.snapshot()
    assert snapshot.version == 1
    assert snapshot.origin == "demo-generated"
    assert snapshot.cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert snapshot.key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    # 演示证书能通过同一套严格校验
    validated = validate_material(snapshot.cert_pem, snapshot.key_pem)
    assert validated.info.fingerprint_sha256 == snapshot.fingerprint_sha256
    assert len(store.samples()) == 2


def test_activation_increments_version_and_persists_after_reopen(tmp_path):
    store = _store(tmp_path)
    sample = store.samples()[0]
    validated = validate_material(sample["cert_pem"], sample["key_pem"])
    result = store.activate(
        cert_pem=validated.cert_pem,
        key_pem=validated.key_pem,
        info=validated.info,
        expected_version=1,
    )
    assert result["previous_version"] == 1
    assert result["version"] == 2

    reopened = CertStore(str(tmp_path / "certs.db"), rsa_key_bits=1024)
    reopened.ensure_initialized()
    snapshot = reopened.snapshot()
    assert snapshot.version == 2
    assert snapshot.fingerprint_sha256 == validated.info.fingerprint_sha256
    assert snapshot.cert_pem == validated.cert_pem
    assert snapshot.key_pem == validated.key_pem


def test_version_mismatch_keeps_original(tmp_path):
    store = _store(tmp_path)
    sample = store.samples()[0]
    validated = validate_material(sample["cert_pem"], sample["key_pem"])
    original = store.snapshot()
    with pytest.raises(VersionConflict) as excinfo:
        store.activate(
            cert_pem=validated.cert_pem,
            key_pem=validated.key_pem,
            info=validated.info,
            expected_version=99,
        )
    assert excinfo.value.current_version == 1
    assert store.snapshot() == original


def test_concurrent_activation_same_expected_version_only_one_succeeds(tmp_path):
    path = str(tmp_path / "certs.db")
    stores = [CertStore(path, rsa_key_bits=1024) for _ in range(8)]
    for store in stores:
        store.ensure_initialized()
    sample = stores[0].samples()[0]
    validated = validate_material(sample["cert_pem"], sample["key_pem"])
    expected = stores[0].current_version()

    def attempt(store):
        try:
            return store.activate(
                cert_pem=validated.cert_pem,
                key_pem=validated.key_pem,
                info=validated.info,
                expected_version=expected,
            )
        except VersionConflict as exc:
            return exc

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        results = list(pool.map(attempt, stores))

    successes = [r for r in results if isinstance(r, dict)]
    conflicts = [r for r in results if isinstance(r, VersionConflict)]
    assert len(successes) == 1
    assert len(conflicts) == len(stores) - 1
    final = stores[0].snapshot()
    assert final.version == expected + 1
    assert final.fingerprint_sha256 == validated.info.fingerprint_sha256


# --------------------------------------------------------------------------- #
# HTTP API / 页面
# --------------------------------------------------------------------------- #
def _client(tmp_path):
    store = _store(tmp_path, key_bits=1024)
    settings = Settings(
        worker_name="test-worker",
        db_path=str(tmp_path / "certs.db"),
        probe_targets=(),
    )
    return TestClient(create_app(store=store, settings=settings)), store


def test_rotate_page_is_served_and_linked_from_index(tmp_path):
    client, _ = _client(tmp_path)
    rotate_page = client.get("/rotate")
    assert rotate_page.status_code == 200
    assert "HTTPS 证书轮换" in rotate_page.text
    index = client.get("/")
    assert 'href="/rotate"' in index.text


def test_state_and_samples_endpoints(tmp_path):
    client, _ = _client(tmp_path)
    state = client.get("/api/rotate/state").json()
    assert state["version"] == 1
    assert state["worker"] == "test-worker"
    assert len(state["fingerprint_sha256"]) == 64
    assert "key_pem" not in state
    samples = client.get("/api/rotate/samples").json()["samples"]
    assert [sample["key"] for sample in samples] == ["sample-a", "sample-b"]
    assert all(sample["cert_pem"] and sample["key_pem"] for sample in samples)


def test_activate_json_and_version_conflict(tmp_path):
    client, store = _client(tmp_path)
    sample = store.samples()[0]
    payload = {
        "cert_pem": sample["cert_pem"],
        "key_pem": sample["key_pem"],
        "expected_version": 1,
    }
    response = client.post("/api/rotate/activate", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2

    conflict = client.post("/api/rotate/activate", json=payload)
    assert conflict.status_code == 409
    assert conflict.json()["current_version"] == 2
    assert store.snapshot().version == 2


def test_activate_multipart_supported(tmp_path):
    client, store = _client(tmp_path)
    sample = store.samples()[1]
    response = client.post(
        "/api/rotate/activate",
        data={"expected_version": "1"},
        files={
            "cert_pem": ("new-cert.pem", sample["cert_pem"], "text/plain"),
            "key_pem": ("new-key.pem", sample["key_pem"], "text/plain"),
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2


def test_validation_failure_keeps_original(tmp_path):
    client, store = _client(tmp_path)
    sample_a = store.samples()[0]
    sample_b = store.samples()[1]
    payload = {
        "cert_pem": sample_a["cert_pem"],
        "key_pem": sample_b["key_pem"],  # 不匹配
        "expected_version": 1,
    }
    response = client.post("/api/rotate/activate", json=payload)
    assert response.status_code == 400
    assert "不匹配" in response.json()["detail"]
    assert store.snapshot().version == 1


def test_activate_missing_expected_version_rejected(tmp_path):
    client, store = _client(tmp_path)
    sample = store.samples()[0]
    response = client.post(
        "/api/rotate/activate",
        json={"cert_pem": sample["cert_pem"], "key_pem": sample["key_pem"]},
    )
    assert response.status_code == 400
    assert "expected_version" in response.json()["detail"]
