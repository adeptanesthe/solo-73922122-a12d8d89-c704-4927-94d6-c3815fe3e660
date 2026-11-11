"""防火墙有序规则差异核对引擎。

核心思路（纯区间运算，不逐个枚举 IP）：

1. 取旧、新两份规则在源 CIDR、目标 CIDR、端口区间三个维度上的全部边界点，
   把整个连接空间 (IPv4 源 × IPv4 目标 × TCP 端口 0..65535) 切割成一组
   互不重叠的“基本区间”。每个基本区间内，任意规则对它的包含关系恒定。
2. 对每个三维基本单元 (源区间 i, 目标区间 j, 端口区间 k)，分别按旧规则表、
   新规则表做“首条命中”求值（未命中记为默认拒绝）。
3. 比较两侧判定，仅保留动作发生变化的单元（deny -> allow 为新增放行，
   allow -> deny 为新增阻断）。
4. 用贪心矩形合并把相邻且判定一致的单元合并成互不重叠的长方体区域，
   每个区域即 (源地址段, 目标地址段, 端口段) 的一个组合，完整覆盖全部差异。

地址段以闭区间表示，并进一步分解为最小 CIDR 列表展示。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

PORT_MIN = 0
PORT_MAX = 65535
IP_MIN = 0
IP_MAX = (1 << 32) - 1
SENTINEL = 0  # decisions 数组中的默认拒绝标记（规则命中存 rule.index）


# --------------------------------------------------------------------------- #
# 规则模型与输入解析
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    """一条有序防火墙规则（index 从 1 开始，代表规则表中的顺序）。"""

    index: int
    src_lo: int
    src_hi: int
    dst_lo: int
    dst_hi: int
    port_lo: int
    port_hi: int
    action: str  # "allow" | "deny"
    src_cidr: str
    dst_cidr: str


def parse_cidr(value: str, field: str) -> tuple[int, int]:
    """严格解析 IPv4 CIDR，拒绝 IPv6、主机位非零等不规范输入，返回闭区间。"""
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValueError(f"{field} 不是合法的 IPv4 CIDR（需带掩码且主机位为 0）: {value!r}") from exc
    if network.version != 4:
        raise ValueError(f"{field} 仅支持 IPv4 CIDR: {value!r}")
    return int(network.network_address), int(network.broadcast_address)


def build_rule(raw: dict, index: int) -> Rule:
    """把 API 输入的一条规则字典转换为引擎内部的 Rule。"""
    src_lo, src_hi = parse_cidr(raw["src_cidr"], "源 CIDR")
    dst_lo, dst_hi = parse_cidr(raw["dst_cidr"], "目标 CIDR")

    try:
        port_lo = int(raw["port_low"])
        port_hi = int(raw["port_high"])
    except (TypeError, ValueError) as exc:
        raise ValueError("端口必须是整数") from exc
    if not (PORT_MIN <= port_lo <= PORT_MAX and PORT_MIN <= port_hi <= PORT_MAX):
        raise ValueError(f"TCP 端口必须在 {PORT_MIN}..{PORT_MAX} 之间")
    if port_lo > port_hi:
        raise ValueError("端口区间下限不能大于上限")

    action = str(raw["action"]).lower()
    if action not in ("allow", "deny"):
        raise ValueError("动作只允许是 allow 或 deny")

    return Rule(
        index=index,
        src_lo=src_lo,
        src_hi=src_hi,
        dst_lo=dst_lo,
        dst_hi=dst_hi,
        port_lo=port_lo,
        port_hi=port_hi,
        action=action,
        src_cidr=raw["src_cidr"].strip(),
        dst_cidr=raw["dst_cidr"].strip(),
    )


# --------------------------------------------------------------------------- #
# 第一步：边界点 -> 基本区间
# --------------------------------------------------------------------------- #
def build_cuts(rules: list[Rule], lo_attr: str, hi_attr: str, universe_lo: int, universe_hi: int) -> list[tuple[int, int]]:
    """收集某一维度上的所有边界点，生成互不重叠且覆盖全空间的闭区间列表。"""
    points = {universe_lo, universe_hi + 1}
    for rule in rules:
        points.add(getattr(rule, lo_attr))
        points.add(getattr(rule, hi_attr) + 1)
    ordered = sorted(points)
    return [(ordered[i], ordered[i + 1] - 1) for i in range(len(ordered) - 1)]


def memberships(rules: list[Rule], cuts: list[tuple[int, int]], lo_attr: str, hi_attr: str) -> list[frozenset[int]]:
    """每条规则在该维度上覆盖了哪些基本区间（区间索引集合）。"""
    result: list[frozenset[int]] = []
    for rule in rules:
        lo = getattr(rule, lo_attr)
        hi = getattr(rule, hi_attr)
        covered = {i for i, (a, b) in enumerate(cuts) if a >= lo and b <= hi}
        result.append(frozenset(covered))
    return result


# --------------------------------------------------------------------------- #
# 第二步：对全部基本单元做两侧“首条命中”求值
# --------------------------------------------------------------------------- #
def compute_decisions(rules: list[Rule], cuts: list[list[tuple[int, int]]]) -> tuple[bytearray, bytearray]:
    """返回两个一维数组（按源、目标、端口行优先排列）：

    - hits: 命中规则的 index（未命中为 SENTINEL，代表默认拒绝）
    - verdicts: 实际动作，1=allow，0=deny（SENTINEL 单元也是 deny）
    """
    src_cuts, dst_cuts, port_cuts = cuts
    ns, nd, np_ = len(src_cuts), len(dst_cuts), len(port_cuts)
    total = ns * nd * np_
    hits = bytearray(total)  # 初值全部为 SENTINEL（默认拒绝）
    verdicts = bytearray(total)  # 默认拒绝对应 0

    src_mem = memberships(rules, src_cuts, "src_lo", "src_hi")
    dst_mem = memberships(rules, dst_cuts, "dst_lo", "dst_hi")
    port_mem = memberships(rules, port_cuts, "port_lo", "port_hi")
    prepared = [
        (src_mem[r], dst_mem[r], port_mem[r], rules[r].index, 1 if rules[r].action == "allow" else 0)
        for r in range(len(rules))
    ]

    for i in range(ns):
        for j in range(nd):
            # 预过滤：源、目标都命中的规则才可能命中该 (i,j) 柱上的端口单元
            candidates = [p for p in prepared if i in p[0] and j in p[1]]
            if not candidates:
                continue
            base = (i * nd + j) * np_
            for k in range(np_):
                for sm, dm, pm, rule_index, verdict in candidates:
                    if k in pm:
                        hits[base + k] = rule_index
                        verdicts[base + k] = verdict
                        break  # 首条命中：规则按输入顺序求值
    return hits, verdicts


# --------------------------------------------------------------------------- #
# 第三步 + 第四步：差异筛选与贪心矩形合并
# --------------------------------------------------------------------------- #
def coalesce_regions(
    changed: set[int],
    new_verdicts: bytearray,
    ns: int,
    nd: int,
    np_: int,
) -> list[tuple[int, int, int, int, int, int]]:
    """把差异单元合并为互不重叠的长方体 (i0,j0,k0,i1,j1,k1)，闭区间索引。

    合并顺序：先沿端口轴延伸，再沿目标地址轴，最后沿源地址轴。
    每个单元只会被一个区域消费，因此输出区域天然互不重叠且完整覆盖差异。
    """

    def flat(i: int, j: int, k: int) -> int:
        return (i * nd + j) * np_ + k

    regions: list[tuple[int, int, int, int, int, int]] = []
    while changed:
        seed = min(changed)
        i0, rem = divmod(seed, nd * np_)
        j0, k0 = divmod(rem, np_)
        verdict = new_verdicts[seed]

        # 端口轴延伸
        k1 = k0
        while k1 + 1 < np_:
            pos = flat(i0, j0, k1 + 1)
            if pos in changed and new_verdicts[pos] == verdict:
                k1 += 1
            else:
                break

        # 目标地址轴延伸（要求整条端口边一致）
        j1 = j0
        while j1 + 1 < nd:
            ok = True
            for k in range(k0, k1 + 1):
                pos = flat(i0, j1 + 1, k)
                if pos not in changed or new_verdicts[pos] != verdict:
                    ok = False
                    break
            if ok:
                j1 += 1
            else:
                break

        # 源地址轴延伸（要求整个 j×k 面一致）
        i1 = i0
        while i1 + 1 < ns:
            ok = True
            for j in range(j0, j1 + 1):
                for k in range(k0, k1 + 1):
                    pos = flat(i1 + 1, j, k)
                    if pos not in changed or new_verdicts[pos] != verdict:
                        ok = False
                        break
                if not ok:
                    break
            if ok:
                i1 += 1
            else:
                break

        for i in range(i0, i1 + 1):
            for j in range(j0, j1 + 1):
                for k in range(k0, k1 + 1):
                    changed.discard(flat(i, j, k))
        regions.append((i0, j0, k0, i1, j1, k1))

    return regions


# --------------------------------------------------------------------------- #
# 展示层：区间 -> IP / CIDR / 端口视图
# --------------------------------------------------------------------------- #
def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def range_to_cidrs(lo: int, hi: int) -> list[str]:
    """把一个对齐于切割边界的 IPv4 闭区间分解为最少的 CIDR 列表。"""
    cidrs: list[str] = []
    cur = lo
    while cur <= hi:
        if cur == 0:
            max_aligned_size = 32
        else:
            # cur 的二进制末尾零数即当前地址能对齐的最大 CIDR 块位数
            max_aligned_size = (cur & -cur).bit_length() - 1
        # 剩余空间能容纳的最大块位数
        max_fitting_size = (hi - cur + 1).bit_length() - 1
        size = min(max_aligned_size, max_fitting_size, 32)
        cidrs.append(f"{int_to_ip(cur)}/{32 - size}")
        cur += 1 << size
    return cidrs


def ip_interval_view(lo: int, hi: int) -> dict:
    cidrs = range_to_cidrs(lo, hi)
    if lo == hi:
        label = int_to_ip(lo)
    else:
        label = f"{int_to_ip(lo)} – {int_to_ip(hi)}"
    return {"start": int_to_ip(lo), "end": int_to_ip(hi), "cidrs": cidrs, "label": label}


def port_interval_view(lo: int, hi: int) -> dict:
    return {"low": lo, "high": hi, "label": str(lo) if lo == hi else f"{lo}-{hi}"}


def hit_view(rule_index: int, rules_by_index: dict[int, Rule]) -> dict:
    if rule_index == SENTINEL:
        return {"kind": "default_deny", "label": "默认拒绝（未命中任何规则）", "rule": None}
    rule = rules_by_index[rule_index]
    return {
        "kind": "rule",
        "label": (
            f"#{rule.index} {rule.action} {rule.src_cidr} → "
            f"{rule.dst_cidr} 端口 {rule.port_lo}-{rule.port_hi}"
        ),
        "rule": {
            "index": rule.index,
            "action": rule.action,
            "src_cidr": rule.src_cidr,
            "dst_cidr": rule.dst_cidr,
            "port_low": rule.port_lo,
            "port_high": rule.port_hi,
        },
    }


# --------------------------------------------------------------------------- #
# 顶层分析
# --------------------------------------------------------------------------- #
def analyze(raw_old: list[dict], raw_new: list[dict]) -> dict:
    if len(raw_old) > 20 or len(raw_new) > 20:
        raise ValueError("每份规则表最多 20 条")

    old_rules = [build_rule(raw, i + 1) for i, raw in enumerate(raw_old)]
    new_rules = [build_rule(raw, i + 1) for i, raw in enumerate(raw_new)]

    # 两侧规则一起切割，保证单元划分一致、可逐单元比较
    all_rules = old_rules + new_rules
    src_cuts = build_cuts(all_rules, "src_lo", "src_hi", IP_MIN, IP_MAX)
    dst_cuts = build_cuts(all_rules, "dst_lo", "dst_hi", IP_MIN, IP_MAX)
    port_cuts = build_cuts(all_rules, "port_lo", "port_hi", PORT_MIN, PORT_MAX)
    cuts = [src_cuts, dst_cuts, port_cuts]

    old_hits, old_verdicts = compute_decisions(old_rules, cuts)
    new_hits, new_verdicts = compute_decisions(new_rules, cuts)
    ns, nd, np_ = len(src_cuts), len(dst_cuts), len(port_cuts)

    old_by_index = {r.index: r for r in old_rules}
    new_by_index = {r.index: r for r in new_rules}

    # 仅当实际动作（allow/deny，默认拒绝视为 deny）发生变化时才算差异
    changed: set[int] = {
        pos for pos in range(len(old_verdicts)) if old_verdicts[pos] != new_verdicts[pos]
    }
    region_indexes = coalesce_regions(changed, new_verdicts, ns, nd, np_)

    newly_allowed: list[dict] = []
    newly_blocked: list[dict] = []

    for order, (i0, j0, k0, i1, j1, k1) in enumerate(region_indexes, start=1):
        seed = (i0 * nd + j0) * np_ + k0
        new_hit = new_hits[seed]
        old_hit = old_hits[seed]
        category = "newly_allowed" if new_verdicts[seed] == 1 else "newly_blocked"

        src_lo = src_cuts[i0][0]
        src_hi = src_cuts[i1][1]
        dst_lo = dst_cuts[j0][0]
        dst_hi = dst_cuts[j1][1]
        port_lo = port_cuts[k0][0]
        port_hi = port_cuts[k1][1]

        connection_count = (src_hi - src_lo + 1) * (dst_hi - dst_lo + 1) * (port_hi - port_lo + 1)

        region = {
            "id": order,
            "category": category,
            "src_segment": ip_interval_view(src_lo, src_hi),
            "dst_segment": ip_interval_view(dst_lo, dst_hi),
            "port_segment": port_interval_view(port_lo, port_hi),
            "connection_count": connection_count,
            "sample_connection": {
                "src_ip": int_to_ip(src_lo),
                "dst_ip": int_to_ip(dst_lo),
                "dst_port": port_lo,
                "label": f"{int_to_ip(src_lo)}:{port_lo} → {int_to_ip(dst_lo)}:{port_lo} (TCP)",
            },
            "old_side": hit_view(old_hit, old_by_index),
            "new_side": hit_view(new_hit, new_by_index),
        }
        if category == "newly_allowed":
            newly_allowed.append(region)
        else:
            newly_blocked.append(region)

    return {
        "old_rules": [_rule_public(r) for r in old_rules],
        "new_rules": [_rule_public(r) for r in new_rules],
        "newly_allowed": newly_allowed,
        "newly_blocked": newly_blocked,
        "stats": {
            "grid_cells": ns * nd * np_,
            "src_segments": ns,
            "dst_segments": nd,
            "port_segments": np_,
            "allowed_region_count": len(newly_allowed),
            "blocked_region_count": len(newly_blocked),
            "allowed_connection_count": sum(r["connection_count"] for r in newly_allowed),
            "blocked_connection_count": sum(r["connection_count"] for r in newly_blocked),
        },
    }


def _rule_public(rule: Rule) -> dict:
    return {
        "index": rule.index,
        "action": rule.action,
        "src_cidr": rule.src_cidr,
        "dst_cidr": rule.dst_cidr,
        "port_low": rule.port_lo,
        "port_high": rule.port_hi,
    }
