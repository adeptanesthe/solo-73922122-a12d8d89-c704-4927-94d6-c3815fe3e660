"""真实 HTTPS/TLS 集成测试。

覆盖需求中最关键的行为：

- 轮换前后新握手的证书指纹切换；
- 轮换前建立的 TLS 连接在轮换后仍可继续服务；
- 每次新连接使用独立 SSLContext，TLS 会话不可恢复。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import ssl
import time

import uvicorn

from app.cert_material import validate_material
from app.certstore import CertStore
from app.main import create_app
from app.settings import ProbeTarget, Settings
from app.tlsproxy import TlsProxy


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"端口 {port} 未在 {timeout}s 内就绪")


def _client_socket(port: int) -> ssl.SSLSocket:
    context = ssl._create_unverified_context()
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    return context.wrap_socket(raw, server_hostname="localhost")


def _fingerprint(sock: ssl.SSLSocket) -> str:
    return hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()


def _http_request(
    sock: ssl.SSLSocket, path: str = "/api/rotate/state", connection: str = "keep-alive"
) -> tuple[int, bytes]:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
        f"Connection: {connection}\r\n\r\n"
    ).encode()
    sock.sendall(request)

    data = b""
    while b"\r\n\r\n" not in data:
        data += sock.recv(4096)
    head, body = data.split(b"\r\n\r\n", 1)
    headers: dict[bytes, bytes] = {}
    for line in head.split(b"\r\n")[1:]:
        key, value = line.split(b":", 1)
        headers[key.strip().lower()] = value.strip()
    content_length = int(headers.get(b"content-length", b"0"))
    while len(body) < content_length:
        body += sock.recv(content_length - len(body))
    status = int(head.split(b" ")[1])
    return status, body


async def _run_scenario(tmp_path) -> None:
    https_port = _free_port()
    internal_port = _free_port()
    store = CertStore(str(tmp_path / "certs.db"), rsa_key_bits=2048)
    store.ensure_initialized()
    first_snapshot = store.snapshot()

    settings = Settings(
        worker_name="tls-test-worker",
        db_path=str(tmp_path / "certs.db"),
        https_port=https_port,
        internal_port=internal_port,
        bind_host="127.0.0.1",
        probe_targets=(),
    )
    application = create_app(store=store, settings=settings)
    config = uvicorn.Config(
        application,
        host="127.0.0.1",
        port=internal_port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    proxy = TlsProxy(store, settings)
    await proxy.start()
    server_task = asyncio.create_task(server.serve())

    try:
        await asyncio.to_thread(_wait_port, internal_port)
        await asyncio.to_thread(_wait_port, https_port)

        # 轮换前的既有连接
        existing = await asyncio.to_thread(_client_socket, https_port)
        old_fingerprint = await asyncio.to_thread(_fingerprint, existing)
        assert old_fingerprint == first_snapshot.fingerprint_sha256
        status, body = await asyncio.to_thread(_http_request, existing)
        assert status == 200
        assert json.loads(body)["version"] == 1

        # 轮换到样例 A
        sample = store.samples()[0]
        validated = validate_material(sample["cert_pem"], sample["key_pem"])
        result = await asyncio.to_thread(
            store.activate,
            cert_pem=validated.cert_pem,
            key_pem=validated.key_pem,
            info=validated.info,
            expected_version=1,
        )
        assert result["version"] == 2

        # 既有连接继续服务（仍使用旧 TLS 会话），并能看到新活动版本
        status, body = await asyncio.to_thread(
            _http_request, existing, "/api/rotate/state", "close"
        )
        assert status == 200
        assert json.loads(body)["version"] == 2
        existing.close()

        # 新握手必须使用新证书
        fresh = await asyncio.to_thread(_client_socket, https_port)
        new_fingerprint = await asyncio.to_thread(_fingerprint, fresh)
        assert new_fingerprint == validated.info.fingerprint_sha256
        status, _ = await asyncio.to_thread(
            _http_request, fresh, "/health", "close"
        )
        assert status == 200
        fresh.close()

        # 会话恢复必须不可用：拿第一次握手的 session 去复用会得到完整握手
        def session_reuse_probe() -> bool | None:
            context = ssl._create_unverified_context()
            first = context.wrap_socket(
                socket.create_connection(("127.0.0.1", https_port), timeout=5),
                server_hostname="localhost",
            )
            session = first.session
            first.close()
            if session is None:
                return None
            second = context.wrap_socket(
                socket.create_connection(("127.0.0.1", https_port), timeout=5),
                server_hostname="localhost",
                session=session,
            )
            try:
                return bool(getattr(second, "session_reused", False))
            finally:
                second.close()

        reused = await asyncio.to_thread(session_reuse_probe)
        assert reused is not True
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(server_task, timeout=10)
        except asyncio.TimeoutError:  # pragma: no cover
            server_task.cancel()
        await proxy.stop()


def test_tls_rotation_new_handshake_and_existing_connection(tmp_path):
    asyncio.run(_run_scenario(tmp_path))
