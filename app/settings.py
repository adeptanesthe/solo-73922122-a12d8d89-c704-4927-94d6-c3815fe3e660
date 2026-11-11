"""运行配置。

所有配置都可以通过环境变量覆盖，Docker Compose 会为两个 worker 分别设置。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProbeTarget:
    """一个需要实际探测的 HTTPS 工作进程。"""

    name: str
    url: str
    display_url: str = ""

    def public_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "display_url": self.display_url or self.url,
        }


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"环境变量 {name} 必须是整数: {raw!r}") from exc


def _parse_probe_targets(raw: str, default_https_port: int) -> tuple[ProbeTarget, ...]:
    """解析 ``name|url|display_url,name|url|display_url`` 形式的探测目标。"""

    targets: list[ProbeTarget] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        parts = [p.strip() for p in item.split("|")]
        if len(parts) >= 2 and parts[0] and parts[1]:
            name, url = parts[0], parts[1]
            display = parts[2] if len(parts) >= 3 and parts[2] else url
        elif "=" in item:
            name, url = (p.strip() for p in item.split("=", 1))
            display = url
        else:
            raise ValueError(
                f"PROBE_TARGETS 条目格式应为 name|url|display_url: {item!r}"
            )
        targets.append(ProbeTarget(name=name, url=url, display_url=display))

    if targets:
        return tuple(targets)

    # 本地直接运行时的默认值：两个 worker 分别监听 8443/8444。
    return (
        ProbeTarget(
            name="worker1",
            url=f"https://localhost:{default_https_port}",
            display_url=f"https://localhost:{default_https_port}",
        ),
        ProbeTarget(
            name="worker2",
            url=f"https://localhost:{default_https_port + 1}",
            display_url=f"https://localhost:{default_https_port + 1}",
        ),
    )


@dataclass(frozen=True)
class Settings:
    worker_name: str = "worker1"
    db_path: str = "data/certs.db"
    https_port: int = 8443
    internal_port: int = 18080
    bind_host: str = "0.0.0.0"
    internal_host: str = "127.0.0.1"
    probe_targets: tuple[ProbeTarget, ...] = field(default_factory=tuple)
    rsa_key_bits: int = 2048
    handshake_timeout: float = 15.0
    log_level: str = "info"
    probe_timeout: float = 6.0

    @classmethod
    def from_env(cls) -> "Settings":
        https_port = _env_int("HTTPS_PORT", 8443)
        raw_targets = os.environ.get("PROBE_TARGETS", "").strip()
        targets = _parse_probe_targets(raw_targets, https_port)
        return cls(
            worker_name=os.environ.get("WORKER_NAME", "worker1").strip() or "worker1",
            db_path=os.environ.get("CERT_DB_PATH", "data/certs.db").strip()
            or "data/certs.db",
            https_port=https_port,
            internal_port=_env_int("INTERNAL_PORT", 18080),
            bind_host=os.environ.get("BIND_HOST", "0.0.0.0").strip() or "0.0.0.0",
            internal_host=os.environ.get("INTERNAL_HOST", "127.0.0.1").strip()
            or "127.0.0.1",
            probe_targets=targets,
            rsa_key_bits=_env_int("RSA_KEY_BITS", 2048),
            handshake_timeout=float(os.environ.get("TLS_HANDSHAKE_TIMEOUT", "15")),
            log_level=os.environ.get("LOG_LEVEL", "info").strip() or "info",
            probe_timeout=float(os.environ.get("PROBE_TIMEOUT", "6")),
        )

    def probe_targets_public(self) -> list[dict]:
        return [target.public_dict() for target in self.probe_targets]
