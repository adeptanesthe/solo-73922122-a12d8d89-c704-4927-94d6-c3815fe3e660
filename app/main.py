"""FastAPI 入口：原防火墙规则核对功能 + 证书轮换页面/API。"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from . import engine
from .cert_material import (
    CertificateValidationError,
    fingerprint_display,
    validate_material,
)
from .certstore import CertStore, VersionConflict, utc_now_iso
from .example import EXAMPLE
from .probe import probe_all
from .schemas import AnalyzeRequest
from .settings import Settings

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


class ActivationPayloadError(ValueError):
    pass


def _pick(mapping: dict, aliases: tuple[str, ...]):
    for alias in aliases:
        value = mapping.get(alias)
        if value is not None and value != "":
            return value
    return None


async def _as_pem_text(value, field: str) -> str:
    if hasattr(value, "read"):
        try:
            value = await value.read()
        except Exception as exc:  # noqa: BLE001
            raise ActivationPayloadError(f"无法读取上传的{field}: {exc}") from exc
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ActivationPayloadError(f"{field}不是 UTF-8 文本 PEM") from exc
    if not isinstance(value, str):
        raise ActivationPayloadError(f"{field}必须是 PEM 文本")
    return value


def _as_expected_version(value) -> int:
    if value is None:
        raise ActivationPayloadError("缺少 expected_version（预期当前版本）")
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, float):
        if not value.is_integer():
            raise ActivationPayloadError("expected_version 必须是整数")
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ActivationPayloadError("expected_version 必须是整数") from exc


async def _parse_activation_payload(request: Request) -> tuple[str, str, int]:
    content_type = (
        request.headers.get("content-type", "").split(";")[0].strip().lower()
    )

    if content_type in ("multipart/form-data", "application/x-www-form-urlencoded"):
        try:
            form = await request.form()
        except Exception as exc:  # noqa: BLE001
            raise ActivationPayloadError(f"无法解析表单请求体: {exc}") from exc
        mapping = dict(form)
    else:
        try:
            data = await request.json()
        except Exception as exc:  # noqa: BLE001
            raise ActivationPayloadError(
                "请求体必须是 JSON 对象或 multipart/form-data"
            ) from exc
        if not isinstance(data, dict):
            raise ActivationPayloadError("请求体必须是 JSON 对象")
        mapping = data

    cert_value = _pick(
        mapping,
        (
            "cert_pem",
            "certificate_pem",
            "certificate",
            "cert",
            "cert_file",
            "certificate_file",
        ),
    )
    key_value = _pick(
        mapping,
        (
            "key_pem",
            "private_key_pem",
            "private_key",
            "key",
            "key_file",
            "private_key_file",
        ),
    )
    expected_value = _pick(
        mapping,
        ("expected_version", "expected_current_version", "current_version", "version"),
    )

    if cert_value is None:
        raise ActivationPayloadError("缺少证书 PEM（字段 cert_pem / certificate）")
    if key_value is None:
        raise ActivationPayloadError("缺少私钥 PEM（字段 key_pem / private_key）")

    return (
        await _as_pem_text(cert_value, "证书"),
        await _as_pem_text(key_value, "私钥"),
        _as_expected_version(expected_value),
    )


def _state_dict(store: CertStore, settings: Settings) -> dict:
    snapshot = store.snapshot()
    return {
        "worker": settings.worker_name,
        "version": snapshot.version,
        "fingerprint_sha256": snapshot.fingerprint_sha256,
        "fingerprint_display": snapshot.fingerprint_display,
        "subject": snapshot.subject,
        "san_dns": snapshot.san_dns,
        "san_ip": snapshot.san_ip,
        "not_before": snapshot.not_before,
        "not_after": snapshot.not_after,
        "activated_at": snapshot.activated_at,
        "origin": snapshot.origin,
        "targets": settings.probe_targets_public(),
        "session_resumption": "disabled",
        "snapshot_policy": "per-connection-single-row-atomic",
    }


def create_app(
    store: CertStore | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or CertStore(settings.db_path, rsa_key_bits=settings.rsa_key_bits)

    application = FastAPI(
        title="防火墙规则变更核对 / HTTPS 证书轮换",
        description=(
            "比对变更前后两份有序规则，计算新增放行与新增阻断的完整区域；"
            "并提供零停机、原子生效的 HTTPS 证书轮换。"
        ),
        version="2.0.0",
    )
    application.state.store = store
    application.state.settings = settings

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # ------------------------------------------------------------------ #
    # 原功能
    # ------------------------------------------------------------------ #
    @application.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @application.get("/rotate", include_in_schema=False)
    @application.get("/rotate/", include_in_schema=False)
    def rotate_page() -> FileResponse:
        return FileResponse(STATIC_DIR / "rotate.html")

    @application.get("/api/example")
    def get_example() -> dict:
        """返回可编辑示例数据，供页面一键填充。"""
        return EXAMPLE

    @application.post("/api/analyze")
    def analyze(request: AnalyzeRequest) -> JSONResponse:
        """执行差异核对。输入校验错误由 FastAPI 自动返回 422。"""
        try:
            result = engine.analyze(
                [rule.model_dump() for rule in request.old_rules],
                [rule.model_dump() for rule in request.new_rules],
            )
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"detail": str(exc)})
        return JSONResponse(content=result)

    @application.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    # ------------------------------------------------------------------ #
    # 证书轮换
    # ------------------------------------------------------------------ #
    @application.get("/api/rotate/state")
    def rotate_state() -> dict:
        """返回当前活动版本与公开证书信息（绝不返回私钥）。"""
        store.ensure_initialized()
        return _state_dict(store, settings)

    @application.get("/api/rotate/samples")
    def rotate_samples() -> dict:
        """返回两套本地轮换样例，供页面载入后直接提交。"""
        store.ensure_initialized()
        return {
            "worker": settings.worker_name,
            "samples": store.samples(),
        }

    @application.post("/api/rotate/activate")
    async def rotate_activate(request: Request) -> JSONResponse:
        """校验并原子启用新证书；版本不符或校验失败保留原证书。"""

        try:
            cert_pem, key_pem, expected_version = await _parse_activation_payload(
                request
            )
        except ActivationPayloadError as exc:
            return JSONResponse(
                status_code=400,
                content={"detail": str(exc), "errors": [str(exc)]},
            )

        try:
            validated = await run_in_threadpool(validate_material, cert_pem, key_pem)
        except CertificateValidationError as exc:
            return JSONResponse(
                status_code=400,
                content={"detail": str(exc), "errors": exc.errors},
            )
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                status_code=400,
                content={
                    "detail": f"证书校验失败：{exc}",
                    "errors": [f"证书校验失败：{exc}"],
                },
            )

        try:
            result = await run_in_threadpool(
                store.activate,
                cert_pem=validated.cert_pem,
                key_pem=validated.key_pem,
                info=validated.info,
                expected_version=expected_version,
                origin="upload",
            )
        except VersionConflict as exc:
            return JSONResponse(
                status_code=409,
                content={
                    "detail": str(exc),
                    "current_version": exc.current_version,
                    "expected_version": exc.expected_version,
                },
            )

        current_version = result["version"]
        result.update(
            {
                "ok": True,
                "worker": settings.worker_name,
                "fingerprint_display": fingerprint_display(
                    result["fingerprint_sha256"]
                ),
                "message": (
                    f"全部校验通过，已原子启用新证书（版本 {result['previous_version']}"
                    f" → {current_version}）。既有连接继续使用旧 TLS 会话；"
                    "此后开始的完整 TLS 握手使用新证书。"
                ),
            }
        )
        return JSONResponse(status_code=200, content=result)

    @application.get("/api/rotate/probe")
    def rotate_probe() -> dict:
        """实际连接两个 HTTPS 工作进程，返回握手证书 SHA-256 指纹。"""
        store.ensure_initialized()
        return {
            "worker": settings.worker_name,
            "probed_at": utc_now_iso(),
            "targets": probe_all(
                settings.probe_targets, timeout=settings.probe_timeout
            ),
        }

    return application


app = create_app()
