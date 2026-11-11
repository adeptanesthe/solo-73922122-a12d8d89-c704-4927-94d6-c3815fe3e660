"""SQLite 证书材料仓库。

设计要点：

- ``active_cert`` 只有一行（``id=1``），把 **活动版本 + 证书 PEM + 私钥 PEM +
  指纹 + 有效期** 放在同一行。激活时用一条 UPDATE 原子替换整行，因此任何读取者
  拿到的都是同一版本、互相匹配的完整材料，不可能读到“新证书配旧私钥”。
- 激活使用 ``BEGIN IMMEDIATE`` + “期望版本”比较（CAS）：并发请求中只有一个能
  看到匹配的版本并提交；其余在锁释放后会看到已递增的版本，从而返回版本冲突。
- 演示证书和两套轮换样例只在数据库为空时生成一次，保存在同一个 SQLite 文件中，
  容器重启后继续使用。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .cert_material import CertificateInfo, fingerprint_display, generate_material

try:  # Linux/Docker 下用于跨进程串行化首次初始化
    import fcntl
except ImportError:  # pragma: no cover - 非 POSIX 平台
    fcntl = None  # type: ignore[assignment]


SCHEMA = """
CREATE TABLE IF NOT EXISTS active_cert (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    subject TEXT NOT NULL,
    san_dns TEXT NOT NULL,
    san_ip TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    origin TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cert_history (
    version INTEGER PRIMARY KEY,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    subject TEXT NOT NULL,
    san_dns TEXT NOT NULL,
    san_ip TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    origin TEXT NOT NULL,
    expected_version INTEGER
);

CREATE TABLE IF NOT EXISTS rotation_samples (
    sample_key TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    subject TEXT NOT NULL,
    san_dns TEXT NOT NULL,
    san_ip TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    created_at TEXT NOT NULL,
    note TEXT NOT NULL
);
"""

SAMPLE_DEFINITIONS = (
    {
        "sample_key": "sample-a",
        "label": "轮换样例 A",
        "organization": "Rotation Sample A",
        "note": "本地生成的 RSA 演示证书 A，含 DNS SAN localhost、CA=false。",
    },
    {
        "sample_key": "sample-b",
        "label": "轮换样例 B",
        "organization": "Rotation Sample B",
        "note": "本地生成的 RSA 演示证书 B，与样例 A 密钥和指纹均不同。",
    },
)


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class ActiveCertificate:
    """一次原子读取得到的活动证书完整快照。"""

    version: int
    cert_pem: str
    key_pem: str
    fingerprint_sha256: str
    subject: str
    san_dns: list[str]
    san_ip: list[str]
    not_before: str
    not_after: str
    activated_at: str
    origin: str

    @property
    def fingerprint_display(self) -> str:
        return fingerprint_display(self.fingerprint_sha256)


class VersionConflict(Exception):
    """期望版本与当前活动版本不一致；未做任何修改。"""

    def __init__(self, expected_version: int, current_version: int):
        self.expected_version = expected_version
        self.current_version = current_version
        super().__init__(
            f"版本不符：当前活动版本为 {current_version}，预期为 {expected_version}；"
            "未做任何更改"
        )


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def _columns_from_info(info: CertificateInfo) -> dict:
    return {
        "fingerprint_sha256": info.fingerprint_sha256,
        "subject": info.subject,
        "san_dns": json.dumps(info.san_dns, ensure_ascii=False),
        "san_ip": json.dumps(info.san_ip, ensure_ascii=False),
        "not_before": info.not_before,
        "not_after": info.not_after,
    }


class CertStore:
    """线程/进程安全的证书材料仓库。每次操作使用独立连接（内存模式除外）。"""

    def __init__(self, db_path: str | Path, *, rsa_key_bits: int = 2048):
        self.db_path = str(db_path)
        self.rsa_key_bits = rsa_key_bits
        self._lock = threading.RLock()
        self._initialized = False
        self._memory_conn: sqlite3.Connection | None = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(
                ":memory:", check_same_thread=False, isolation_level=None
            )
            self._memory_conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------ #
    # 连接与初始化
    # ------------------------------------------------------------------ #
    def _make_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._memory_conn is not None:
            with self._lock:
                yield self._memory_conn
            return
        conn = self._make_connection()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _init_file_lock(self) -> Iterator[None]:
        if self._memory_conn is not None:
            yield
            return
        lock_path = Path(self.db_path + ".init.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock_path, "a+")
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    def ensure_initialized(self) -> None:
        """幂等初始化：建表，首次启动生成演示证书与两套样例。"""

        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            if self._memory_conn is None:
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with self._init_file_lock():
                with self._connection() as conn:
                    try:
                        if self._memory_conn is None:
                            conn.execute("PRAGMA journal_mode=WAL")
                    except sqlite3.OperationalError:
                        # 某些共享文件系统不支持 WAL；单行 UPDATE 的原子性仍然成立。
                        pass
                    conn.executescript(SCHEMA)
                    self._seed_if_empty(conn)
            self._initialized = True

    def _seed_if_empty(self, conn: sqlite3.Connection) -> None:
        active = conn.execute("SELECT version FROM active_cert WHERE id=1").fetchone()
        sample_keys = {
            row["sample_key"]
            for row in conn.execute("SELECT sample_key FROM rotation_samples").fetchall()
        }
        required_keys = {definition["sample_key"] for definition in SAMPLE_DEFINITIONS}
        if active is not None and required_keys <= sample_keys:
            return

        conn.execute("BEGIN IMMEDIATE")
        try:
            active = conn.execute(
                "SELECT version FROM active_cert WHERE id=1"
            ).fetchone()
            if active is None:
                self._insert_demo_cert(conn)

            # 在写事务内重新读取，避免并发首次启动时使用过期判断。
            existing_samples = {
                row["sample_key"]
                for row in conn.execute(
                    "SELECT sample_key FROM rotation_samples"
                ).fetchall()
            }
            for definition in SAMPLE_DEFINITIONS:
                if definition["sample_key"] in existing_samples:
                    continue
                self._insert_sample(conn, definition)
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def _insert_demo_cert(self, conn: sqlite3.Connection) -> None:
        cert_pem, key_pem, info = generate_material(
            common_name="localhost",
            organization="Firewall Rule Checker Demo",
            organizational_unit="First-start persistent demo certificate",
            days=3650,
            key_bits=self.rsa_key_bits,
        )
        activated_at = utc_now_iso()
        columns = _columns_from_info(info)
        conn.execute(
            """
            INSERT INTO active_cert
                (id, version, cert_pem, key_pem, fingerprint_sha256, subject,
                 san_dns, san_ip, not_before, not_after, activated_at, origin)
            VALUES
                (1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert_pem,
                key_pem,
                columns["fingerprint_sha256"],
                columns["subject"],
                columns["san_dns"],
                columns["san_ip"],
                columns["not_before"],
                columns["not_after"],
                activated_at,
                "demo-generated",
            ),
        )
        self._insert_history(
            conn,
            version=1,
            cert_pem=cert_pem,
            key_pem=key_pem,
            info=info,
            activated_at=activated_at,
            origin="demo-generated",
            expected_version=None,
        )

    def _insert_sample(self, conn: sqlite3.Connection, definition: dict) -> None:
        cert_pem, key_pem, info = generate_material(
            common_name="localhost",
            organization=definition["organization"],
            organizational_unit="Local rotation sample",
            days=1825,
            key_bits=self.rsa_key_bits,
        )
        columns = _columns_from_info(info)
        conn.execute(
            """
            INSERT INTO rotation_samples
                (sample_key, label, cert_pem, key_pem, fingerprint_sha256, subject,
                 san_dns, san_ip, not_before, not_after, created_at, note)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                definition["sample_key"],
                definition["label"],
                cert_pem,
                key_pem,
                columns["fingerprint_sha256"],
                columns["subject"],
                columns["san_dns"],
                columns["san_ip"],
                columns["not_before"],
                columns["not_after"],
                utc_now_iso(),
                definition["note"],
            ),
        )

    def _insert_history(
        self,
        conn: sqlite3.Connection,
        *,
        version: int,
        cert_pem: str,
        key_pem: str,
        info: CertificateInfo,
        activated_at: str,
        origin: str,
        expected_version: int | None,
    ) -> None:
        columns = _columns_from_info(info)
        conn.execute(
            """
            INSERT INTO cert_history
                (version, cert_pem, key_pem, fingerprint_sha256, subject,
                 san_dns, san_ip, not_before, not_after, activated_at, origin,
                 expected_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                version,
                cert_pem,
                key_pem,
                columns["fingerprint_sha256"],
                columns["subject"],
                columns["san_dns"],
                columns["san_ip"],
                columns["not_before"],
                columns["not_after"],
                activated_at,
                origin,
                expected_version,
            ),
        )

    # ------------------------------------------------------------------ #
    # 读取
    # ------------------------------------------------------------------ #
    def snapshot(self) -> ActiveCertificate:
        """读取活动证书的完整、原子快照（单行 SELECT）。"""

        self.ensure_initialized()
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT version, cert_pem, key_pem, fingerprint_sha256, subject,
                       san_dns, san_ip, not_before, not_after, activated_at, origin
                FROM active_cert
                WHERE id = 1
                """
            ).fetchone()
        if row is None:
            raise RuntimeError("证书数据库尚未初始化")
        return ActiveCertificate(
            version=int(row["version"]),
            cert_pem=row["cert_pem"],
            key_pem=row["key_pem"],
            fingerprint_sha256=row["fingerprint_sha256"],
            subject=row["subject"],
            san_dns=_json_list(row["san_dns"]),
            san_ip=_json_list(row["san_ip"]),
            not_before=row["not_before"],
            not_after=row["not_after"],
            activated_at=row["activated_at"],
            origin=row["origin"],
        )

    def current_version(self) -> int:
        return self.snapshot().version

    def samples(self) -> list[dict]:
        self.ensure_initialized()
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT sample_key, label, cert_pem, key_pem, fingerprint_sha256,
                       subject, san_dns, san_ip, not_before, not_after, created_at, note
                FROM rotation_samples
                ORDER BY sample_key
                """
            ).fetchall()
        return [
            {
                "key": row["sample_key"],
                "label": row["label"],
                "cert_pem": row["cert_pem"],
                "key_pem": row["key_pem"],
                "fingerprint_sha256": row["fingerprint_sha256"],
                "fingerprint_display": fingerprint_display(row["fingerprint_sha256"]),
                "subject": row["subject"],
                "san_dns": _json_list(row["san_dns"]),
                "san_ip": _json_list(row["san_ip"]),
                "not_before": row["not_before"],
                "not_after": row["not_after"],
                "created_at": row["created_at"],
                "note": row["note"],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------ #
    # 原子激活
    # ------------------------------------------------------------------ #
    def activate(
        self,
        *,
        cert_pem: str,
        key_pem: str,
        info: CertificateInfo,
        expected_version: int,
        origin: str = "upload",
    ) -> dict:
        """比较并交换：仅当活动版本等于 ``expected_version`` 时原子启用新证书。

        返回新版本信息。版本不符抛 :class:`VersionConflict`。任何失败都不会修改
        活动证书。
        """

        self.ensure_initialized()
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT version FROM active_cert WHERE id=1"
                ).fetchone()
                if row is None:
                    raise RuntimeError("证书数据库尚未初始化")
                current_version = int(row["version"])
                if current_version != int(expected_version):
                    conn.execute("ROLLBACK")
                    raise VersionConflict(int(expected_version), current_version)

                new_version = current_version + 1
                activated_at = utc_now_iso()
                columns = _columns_from_info(info)
                conn.execute(
                    """
                    UPDATE active_cert
                    SET version = ?, cert_pem = ?, key_pem = ?,
                        fingerprint_sha256 = ?, subject = ?, san_dns = ?,
                        san_ip = ?, not_before = ?, not_after = ?,
                        activated_at = ?, origin = ?
                    WHERE id = 1
                    """,
                    (
                        new_version,
                        cert_pem,
                        key_pem,
                        columns["fingerprint_sha256"],
                        columns["subject"],
                        columns["san_dns"],
                        columns["san_ip"],
                        columns["not_before"],
                        columns["not_after"],
                        activated_at,
                        origin,
                    ),
                )
                self._insert_history(
                    conn,
                    version=new_version,
                    cert_pem=cert_pem,
                    key_pem=key_pem,
                    info=info,
                    activated_at=activated_at,
                    origin=origin,
                    expected_version=current_version,
                )
                conn.execute("COMMIT")
            except VersionConflict:
                raise
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

        return {
            "previous_version": current_version,
            "version": new_version,
            "fingerprint_sha256": info.fingerprint_sha256,
            "fingerprint_display": info.fingerprint_display,
            "subject": info.subject,
            "activated_at": activated_at,
            "origin": origin,
        }
