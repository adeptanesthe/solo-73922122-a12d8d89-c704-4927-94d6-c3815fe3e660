"""HTTPS 工作进程的 TLS 前置层。

每个新 TCP 连接都会：

1. 从 SQLite 用 **一条 SELECT** 读取活动证书的完整快照（版本 + 证书 + 私钥）；
2. 在进程临时目录中按 ``(version, fingerprint)`` 缓存该版材料文件；
3. 为本连接新建一个 ``SSLContext``（因此不会跨连接复用会话/票据）；
4. 完成 TLS 握手；
5. 把解密后的字节流转发给本机回环地址上的 uvicorn（FastAPI 应用）。

已建立连接在使用旧 SSLContext，不会受后续轮换影响；新连接在握手中读取新的
单行快照，因此不会出现证书/私钥混配。``OP_NO_TICKET`` 与 ``num_tickets = 0``
进一步禁用 TLS 会话恢复。
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import ssl
import tempfile

from .certstore import ActiveCertificate, CertStore
from .settings import Settings

logger = logging.getLogger("cert_rotation.tls")


class TlsProxy:
    def __init__(self, store: CertStore, settings: Settings):
        self.store = store
        self.settings = settings
        self._server: asyncio.AbstractServer | None = None
        self._temp_dir = tempfile.mkdtemp(
            prefix=f"fwcheck-tls-{settings.worker_name}-{os.getpid()}-"
        )
        self._material_files: dict[tuple[int, str], tuple[str, str]] = {}

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.settings.bind_host,
            port=self.settings.https_port,
            backlog=256,
            reuse_address=True,
        )
        sockets = self._server.sockets or []
        addresses = ", ".join(str(sock.getsockname()) for sock in sockets)
        logger.info(
            "worker %s: HTTPS TLS 前置层监听 %s (upstream %s:%s)",
            self.settings.worker_name,
            addresses,
            self.settings.internal_host,
            self.settings.internal_port,
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # pragma: no cover
                pass
            self._server = None
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------ #
    # 单连接处理
    # ------------------------------------------------------------------ #
    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            # 关键：在握手前读取一次单行原子快照。
            snapshot = self.store.snapshot()
            cert_path, key_path = self._material_paths(snapshot)
            context = self._build_context(cert_path, key_path)

            await writer.start_tls(
                context, ssl_handshake_timeout=self.settings.handshake_timeout
            )

            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.settings.internal_host, self.settings.internal_port
            )
            results = await asyncio.gather(
                self._pipe(reader, upstream_writer),
                self._pipe(upstream_reader, writer),
                return_exceptions=True,
            )
            for result in results:
                if isinstance(result, BaseException):
                    logger.debug("worker %s: 连接转发结束: %r", self.settings.worker_name, result)
        except asyncio.CancelledError:
            raise
        except (ssl.SSLError, ssl.SSLEOFError, ConnectionError, OSError) as exc:
            logger.debug("worker %s: TLS/连接错误: %s", self.settings.worker_name, exc)
        except Exception:  # noqa: BLE001
            logger.exception("worker %s: 处理连接时出现未预期错误", self.settings.worker_name)
        finally:
            self._safe_close(writer)
            if upstream_writer is not None:
                self._safe_close(upstream_writer)

    @staticmethod
    async def _pipe(
        source: asyncio.StreamReader, destination: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await source.read(65536)
                if not data:
                    break
                destination.write(data)
                await destination.drain()
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            TlsProxy._safe_close(destination)

    @staticmethod
    def _safe_close(writer: asyncio.StreamWriter | None) -> None:
        if writer is None:
            return
        try:
            writer.close()
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------ #
    # 材料文件与 SSLContext
    # ------------------------------------------------------------------ #
    def _material_paths(self, snapshot: ActiveCertificate) -> tuple[str, str]:
        """按 (version, fingerprint) 缓存 PEM 文件，写入使用临时文件 + rename。"""

        cache_key = (snapshot.version, snapshot.fingerprint_sha256)
        cached = self._material_files.get(cache_key)
        if cached is not None:
            return cached

        version_dir = os.path.join(self._temp_dir, f"v{snapshot.version}")
        os.makedirs(version_dir, mode=0o700, exist_ok=True)
        cert_path = os.path.join(version_dir, "cert.pem")
        key_path = os.path.join(version_dir, "key.pem")
        self._atomic_write(cert_path, snapshot.cert_pem.encode("utf-8"), 0o600)
        self._atomic_write(key_path, snapshot.key_pem.encode("utf-8"), 0o600)
        self._material_files[cache_key] = (cert_path, key_path)
        return cert_path, key_path

    @staticmethod
    def _atomic_write(path: str, content: bytes, mode: int) -> None:
        temp_path = f"{path}.tmp.{os.getpid()}"
        with open(temp_path, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)

    def _build_context(self, cert_path: str, key_path: str) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # 需求只要求 RSA，没有限定密钥长度。OpenSSL 3 默认安全级别 2 会在
        # load_cert_chain 阶段拒绝 1024 位 RSA；降到级别 1 以兼容这类演示证书，
        # 同时 2048 位及以上证书行为不变。
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:  # pragma: no cover - 某些 OpenSSL 构建不支持
            pass

        # 禁用 TLS 会话票据；每个连接还使用全新的 SSLContext，因此也不存在
        # 服务端会话缓存跨连接复用的问题。
        if hasattr(ssl, "OP_NO_TICKET"):
            context.options |= ssl.OP_NO_TICKET
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            context.options |= ssl.OP_NO_COMPRESSION
        if hasattr(ssl, "OP_NO_RENEGOTIATION"):
            context.options |= ssl.OP_NO_RENEGOTIATION
        if hasattr(context, "num_tickets"):
            context.num_tickets = 0

        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        try:
            context.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:  # pragma: no cover
            pass
        return context
