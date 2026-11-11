"""Pydantic 请求/响应模型（校验层）。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RuleInput(BaseModel):
    src_cidr: str = Field(..., description="源 IPv4 CIDR，例如 10.0.0.0/8")
    dst_cidr: str = Field(..., description="目标 IPv4 CIDR，例如 192.168.1.0/24")
    port_low: int = Field(..., ge=0, le=65535, description="TCP 目标端口闭区间下限")
    port_high: int = Field(..., ge=0, le=65535, description="TCP 目标端口闭区间上限")
    action: Literal["allow", "deny"] = Field(..., description="允许或拒绝")


class AnalyzeRequest(BaseModel):
    old_rules: list[RuleInput] = Field(..., max_length=20, description="变更前的有序规则（首条命中生效）")
    new_rules: list[RuleInput] = Field(..., max_length=20, description="变更后的有序规则（首条命中生效）")


class ErrorResponse(BaseModel):
    detail: str
