"""HTTPS 工作进程入口。

进程结构：

- 一个 uvicorn/FastAPI 实例只监听 ``127.0.0.1`` 上的内部明文端口；
- 对外只暴露 :class:`TlsProxy` 的 HTTPS 端口；
- 每个新 TLS 连接在握手前读取 SQLite 中的单行活动证书快照。

Docker Compose 启动两个这样的独立进程（worker1 / worker2），二者共享同一个
SQLite 卷，因此轮换在任意一个进程生效后，两个进程的后续握手都会自动使用新证书。
"""

from __future__ import annotations

import asyncio
import logging

import uvicorn

from .certstore import CertStore
from .main import create_app
from .settings import Settings
from .tlsproxy import TlsProxy


async def serve(settings: Settings, store: CertStore) -> None:
    application = create_app(store=store, settings=settings)

    config = uvicorn.Config(
        application,
        host=settings.internal_host,
        port=settings.internal_port,
        log_level=settings.log_level,
        access_log=False,
        lifespan="on",
    )
    server = uvicorn.Server(config)
    proxy = TlsProxy(store, settings)

    await proxy.start()
    logging.getLogger("cert_rotation").info(
        "worker %s 已启动：HTTPS 端口 %s，内部端口 %s",
        settings.worker_name,
        settings.https_port,
        settings.internal_port,
    )
    try:
        await server.serve()
    finally:
        await proxy.stop()


def main() -> None:
    settings = Settings.from_env()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    store = CertStore(settings.db_path, rsa_key_bits=settings.rsa_key_bits)
    # 首次启动在这里生成持久化演示证书与两套轮换样例；两个进程并发启动由
    # SQLite 事务 + 文件锁串行化。
    store.ensure_initialized()

    try:
        asyncio.run(serve(settings, store))
    except KeyboardInterrupt:  # pragma: no cover - 交互式停止
        pass


if __name__ == "__main__":
    main()
