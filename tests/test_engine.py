"""引擎层测试：区间切割、首条命中、默认拒绝、区域合并与边界校验。"""

from __future__ import annotations

import pytest

from app import engine


def rule(src, dst, pl, ph, action):
    return {
        "src_cidr": src,
        "dst_cidr": dst,
        "port_low": pl,
        "port_high": ph,
        "action": action,
    }


# --------------------------------------------------------------------------- #
# CIDR 与区间分解
# --------------------------------------------------------------------------- #
def test_range_to_cidrs_full_space():
    assert engine.range_to_cidrs(0, (1 << 32) - 1) == ["0.0.0.0/0"]


def test_range_to_cidrs_single_host():
    assert engine.range_to_cidrs(0x0A000001, 0x0A000001) == ["10.0.0.1/32"]


def test_range_to_cidrs_multi_block():
    # 10.0.0.0 – 10.0.1.255 恰好是一个对齐的 /23
    lo = int("0A000000", 16)
    hi = int("0A0001FF", 16)
    assert engine.range_to_cidrs(lo, hi) == ["10.0.0.0/23"]


def test_range_to_cidrs_non_aligned_pair():
    # 两个不连续对齐边界的 /24：10.0.1.0 – 10.0.2.255 需要拆成多个 CIDR
    lo = int("0A000100", 16)
    hi = int("0A0002FF", 16)
    assert engine.range_to_cidrs(lo, hi) == ["10.0.1.0/24", "10.0.2.0/24"]


def test_range_to_cidrs_odd_start():
    # 10.0.0.1 – 10.0.0.3 拆为 /32 + /31
    lo = int("0A000001", 16)
    hi = int("0A000003", 16)
    assert engine.range_to_cidrs(lo, hi) == ["10.0.0.1/32", "10.0.0.2/31"]


def test_strict_cidr_rejects_host_bits():
    with pytest.raises(ValueError):
        engine.parse_cidr("10.0.0.1/24", "源 CIDR")


def test_strict_cidr_rejects_ipv6():
    with pytest.raises(ValueError):
        engine.parse_cidr("2001:db8::/32", "源 CIDR")


def test_port_order_validation():
    with pytest.raises(ValueError):
        engine.build_rule(rule("10.0.0.0/24", "10.0.0.0/24", 100, 80, "allow"), 1)


def test_port_range_validation():
    with pytest.raises(ValueError):
        engine.build_rule(rule("10.0.0.0/24", "10.0.0.0/24", 0, 70000, "allow"), 1)


# --------------------------------------------------------------------------- #
# 端到端分析
# --------------------------------------------------------------------------- #
def test_new_allow_against_default_deny():
    old = [rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny")]
    new = [
        rule("10.0.0.0/8", "192.168.1.0/24", 80, 80, "allow"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    result = engine.analyze(old, new)

    assert len(result["newly_blocked"]) == 0
    assert len(result["newly_allowed"]) == 1
    region = result["newly_allowed"][0]
    assert region["src_segment"]["cidrs"] == ["10.0.0.0/8"]
    assert region["dst_segment"]["cidrs"] == ["192.168.1.0/24"]
    assert region["port_segment"] == {"low": 80, "high": 80, "label": "80"}
    assert region["connection_count"] == (2 ** 24) * (2 ** 8) * 1
    assert region["old_side"]["kind"] == "rule"
    assert region["old_side"]["rule"]["index"] == 1
    assert region["new_side"]["rule"]["index"] == 1
    assert region["sample_connection"]["src_ip"] == "10.0.0.0"
    assert region["sample_connection"]["dst_ip"] == "192.168.1.0"


def test_new_block_with_old_default_deny_shown_as_default():
    # 旧表无任何规则：未命中即默认拒绝；新表显式 deny 同一范围，动作未变化，不应产生区域
    old = []
    new = [rule("10.0.0.0/8", "10.0.0.0/8", 0, 65535, "deny")]
    result = engine.analyze(old, new)
    assert result["newly_allowed"] == []
    assert result["newly_blocked"] == []


def test_new_block_replaces_allow():
    old = [rule("10.0.0.0/8", "172.16.0.0/16", 0, 65535, "allow")]
    new = [
        rule("10.0.0.0/8", "172.16.0.0/16", 22, 22, "deny"),
        rule("10.0.0.0/8", "172.16.0.0/16", 0, 65535, "allow"),
    ]
    result = engine.analyze(old, new)
    assert len(result["newly_allowed"]) == 0
    assert len(result["newly_blocked"]) == 1
    region = result["newly_blocked"][0]
    assert region["port_segment"]["label"] == "22"
    assert region["old_side"]["rule"]["action"] == "allow"
    assert region["new_side"]["rule"]["action"] == "deny"
    # 其余连接仍被放行，不出现在差异里
    assert result["stats"]["blocked_connection_count"] == (2 ** 24) * (2 ** 16)


def test_first_match_wins():
    # 第一条 deny 优先于后面的 allow
    old = [
        rule("10.1.0.0/16", "0.0.0.0/0", 0, 65535, "deny"),
        rule("10.1.2.0/24", "0.0.0.0/0", 0, 65535, "allow"),
    ]
    new = [
        rule("10.1.2.0/24", "0.0.0.0/0", 0, 65535, "allow"),
        rule("10.1.0.0/16", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    result = engine.analyze(old, new)
    # 仅 10.1.2.0/24 从“被首条 deny 命中”变为 allow
    assert len(result["newly_allowed"]) == 1
    region = result["newly_allowed"][0]
    assert region["src_segment"]["cidrs"] == ["10.1.2.0/24"]
    assert region["old_side"]["rule"]["index"] == 1
    assert region["new_side"]["rule"]["index"] == 1


def test_regions_are_disjoint_and_complete():
    old = [rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "allow")]
    new = [
        rule("10.0.0.0/8", "192.168.0.0/16", 22, 22, "deny"),
        rule("10.0.0.0/8", "192.168.0.0/16", 80, 443, "deny"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "allow"),
    ]
    result = engine.analyze(old, new)

    # 阻断连接总量必须等于两段端口 × 源 × 目标，且端口段被拆为 22 与 80-443 两个区域
    blocked = result["newly_blocked"]
    assert len(blocked) == 2
    total = sum(r["connection_count"] for r in blocked)
    expected = (2 ** 24) * (2 ** 16) * (1 + (443 - 80 + 1))
    assert total == expected

    # 端口段互不重叠
    port_ranges = sorted((r["port_segment"]["low"], r["port_segment"]["high"]) for r in blocked)
    assert port_ranges == [(22, 22), (80, 443)]

    # 每个区域两侧命中规则都齐全
    for r in blocked:
        assert r["old_side"]["rule"]["action"] == "allow"
        assert r["new_side"]["rule"]["action"] == "deny"
        assert r["sample_connection"]["dst_port"] == r["port_segment"]["low"]


def test_default_deny_label_when_no_rule_matches():
    old = [rule("10.0.0.0/8", "10.0.0.0/8", 443, 443, "allow")]
    new = [
        rule("10.0.0.0/8", "10.0.0.0/8", 443, 443, "allow"),
        rule("10.0.0.0/8", "10.0.0.0/8", 80, 80, "allow"),
    ]
    result = engine.analyze(old, new)
    region = result["newly_allowed"][0]
    assert region["old_side"]["kind"] == "default_deny"
    assert "默认拒绝" in region["old_side"]["label"]
    assert region["new_side"]["kind"] == "rule"


def test_no_change_returns_empty_regions():
    rules = [
        rule("10.0.0.0/8", "0.0.0.0/0", 0, 1024, "allow"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    result = engine.analyze(rules, [dict(r) for r in rules])
    assert result["newly_allowed"] == []
    assert result["newly_blocked"] == []
    assert result["stats"]["allowed_connection_count"] == 0


def test_max_20_rules_enforced():
    many = [rule("10.0.0.0/24", "10.0.0.0/24", 0, 65535, "deny") for _ in range(21)]
    with pytest.raises(ValueError):
        engine.analyze(many, many[:1])


def test_merged_interval_rendered_as_range_and_cidrs():
    # 两个相邻且可聚合的 /24 被同一动作覆盖：区间合并，最少 CIDR 分解为一个 /23
    old = [rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny")]
    new = [
        rule("192.168.0.0/24", "10.0.0.0/24", 80, 80, "allow"),
        rule("192.168.1.0/24", "10.0.0.0/24", 80, 80, "allow"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    result = engine.analyze(old, new)
    assert len(result["newly_allowed"]) == 1
    seg = result["newly_allowed"][0]["src_segment"]
    assert seg["start"] == "192.168.0.0"
    assert seg["end"] == "192.168.1.255"
    assert seg["cidrs"] == ["192.168.0.0/23"]


def test_merged_non_aligned_interval_renders_multiple_cidrs():
    # 192.168.1.0/24 与 192.168.2.0/24 合并后的区间无法用单个 CIDR 表示
    old = [rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny")]
    new = [
        rule("192.168.1.0/24", "10.0.0.0/24", 80, 80, "allow"),
        rule("192.168.2.0/24", "10.0.0.0/24", 80, 80, "allow"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    result = engine.analyze(old, new)
    seg = result["newly_allowed"][0]["src_segment"]
    assert seg["label"] == "192.168.1.0 – 192.168.2.255"
    assert seg["cidrs"] == ["192.168.1.0/24", "192.168.2.0/24"]
