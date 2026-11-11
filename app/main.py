"""FastAPI 入口：页面 + 核对 API。"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import engine
from .example import EXAMPLE
from .schemas import AnalyzeRequest

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="防火墙规则变更核对工具",
    description="比对变更前后两份有序规则，计算新增放行与新增阻断的完整区域",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/example")
def get_example() -> dict:
    """返回可编辑示例数据，供页面一键填充。"""
    return EXAMPLE


@app.post("/api/analyze")
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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
