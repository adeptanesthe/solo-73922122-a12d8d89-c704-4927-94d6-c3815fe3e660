"""从服务端实际发起 TLS 握手，探测两个工作进程当前使用的证书。

探测方式：

- 客户端建立真正的 HTTPS/TLS 连接（演示证书为自签名，所以关闭链校验，但仍然
  完整执行 TLS 握手）；
- 从握手的 SSL 对象读取对端叶子证书 DER，计算 SHA-256；
- 在同一条 TLS 连接上请求 ``/api/rotate/state``，取得对端进程报告的活动版本；
- 比对“握手看到的指纹”和“对端状态中的指纹”，验证二者一致。
"""

from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from .cert_material import fingerprint_display
from .settings import ProbeTarget


def _ssl_client_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:  # pragma: no cover
        pass
    return ctx


def _failed(target: ProbeTarget, started: float, exc: BaseException) -> dict:
    return {
        "name": target.name,
        "url": target.url,
        "display_url": target.display_url or target.url,
        "ok": False,
        "fingerprint_sha256": None,
        "fingerprint_display": None,
        "handshake_certificate_sha256": None,
        "handshake_fingerprint_display": None,
        "version": None,
        "worker": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "tls_version": None,
        "cipher": None,
        "state_matches_handshake": None,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "error": f"{type(exc).__name__}: {exc}",
    }


def probe_target(target: ProbeTarget, *, timeout: float = 6.0) -> dict:
    """对单个目标执行一次真实 TLS 握手并读取其活动证书指纹。"""

    started = time.perf_counter()
    parsed = urlparse(target.url)
    if parsed.scheme != "https" or not parsed.hostname:
        return _failed(
            target,
            started,
            ValueError(f"探测目标必须是 https:// URL: {target.url!r}"),
        )

    host = parsed.hostname
    port = parsed.port or 443
    context = _ssl_client_context()
    connection: http.client.HTTPSConnection | None = None

    try:
        connection = http.client.HTTPSConnection(
            host, port, context=context, timeout=timeout
        )
        # 先完成 TLS 握手并立即读取对端证书；HTTP 响应结束后连接可能已被
        # http.client 关闭（Connection: close），届时 sock 会变成 None。
        connection.connect()
        sock = connection.sock
        if sock is None:
            raise RuntimeError("TLS 连接已建立但无法取得套接字")
        der = sock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("TLS 握手未返回对端证书")
        handshake_fp = hashlib.sha256(der).hexdigest()
        handshake_display = fingerprint_display(handshake_fp)
        tls_version = getattr(sock, "version", lambda: None)()
        cipher_info = getattr(sock, "cipher", lambda: None)()
        cipher = cipher_info[0] if cipher_info else None

        connection.request(
            "GET",
            "/api/rotate/state",
            headers={"Accept": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        raw_body = response.read()
        if response.status != 200:
            raise RuntimeError(f"对端返回 HTTP {response.status}: {raw_body[:200]!r}")

        try:
            state = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError(f"对端状态不是合法 JSON: {exc}") from exc

        return {
            "name": target.name,
            "url": target.url,
            "display_url": target.display_url or target.url,
            "ok": True,
            "fingerprint_sha256": handshake_fp,
            "fingerprint_display": handshake_display,
            "handshake_certificate_sha256": handshake_fp,
            "handshake_fingerprint_display": handshake_display,
            "version": state.get("version"),
            "worker": state.get("worker"),
            "subject": state.get("subject"),
            "not_before": state.get("not_before"),
            "not_after": state.get("not_after"),
            "tls_version": tls_version,
            "cipher": cipher,
            "state_matches_handshake": (
                state.get("fingerprint_sha256") == handshake_fp
            ),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - 探测失败要作为结果返回而不是 500
        return _failed(target, started, exc)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:  # pragma: no cover
                pass


def probe_all(targets: tuple[ProbeTarget, ...] | list[ProbeTarget], *, timeout: float = 6.0) -> list[dict]:
    target_list = list(targets)
    if not target_list:
        return []
    with ThreadPoolExecutor(max_workers=min(len(target_list), 8)) as pool:
        return list(
            pool.map(lambda target: probe_target(target, timeout=timeout), target_list)
        )
