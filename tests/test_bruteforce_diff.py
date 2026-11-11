"""差分测试：在小空间上暴力枚举每个连接的判定，核对区域输出完整且互不重叠。

注意：暴力部分只存在于测试里，且作用于 /30、/29 这类微型 CIDR；
生产引擎本身始终按区间计算，不枚举 IP。
"""

from __future__ import annotations

import ipaddress
import itertools

from app import engine


def rule(src, dst, pl, ph, action):
    return {
        "src_cidr": src,
        "dst_cidr": dst,
        "port_low": pl,
        "port_high": ph,
        "action": action,
    }


def brute_force_verdict(rules, src_ip, dst_ip, port):
    for raw in rules:
        net_s = ipaddress.ip_network(raw["src_cidr"])
        net_d = ipaddress.ip_network(raw["dst_cidr"])
        if (
            ipaddress.IPv4Address(src_ip) in net_s
            and ipaddress.IPv4Address(dst_ip) in net_d
            and raw["port_low"] <= port <= raw["port_high"]
        ):
            return 1 if raw["action"] == "allow" else 0
    return 0  # 默认拒绝


def region_contains(region, src_ip, dst_ip, port):
    s = int(ipaddress.IPv4Address(src_ip))
    d = int(ipaddress.IPv4Address(dst_ip))
    src_lo = int(ipaddress.IPv4Address(region["src_segment"]["start"]))
    src_hi = int(ipaddress.IPv4Address(region["src_segment"]["end"]))
    dst_lo = int(ipaddress.IPv4Address(region["dst_segment"]["start"]))
    dst_hi = int(ipaddress.IPv4Address(region["dst_segment"]["end"]))
    return (
        src_lo <= s <= src_hi
        and dst_lo <= d <= dst_hi
        and region["port_segment"]["low"] <= port <= region["port_segment"]["high"]
    )


def assert_matches_bruteforce(old_rules, new_rules, universe_src, universe_dst, ports):
    result = engine.analyze(old_rules, new_rules)
    all_regions = result["newly_allowed"] + result["newly_blocked"]

    expected_allowed = 0
    expected_blocked = 0
    for src_ip, dst_ip, port in itertools.product(universe_src, universe_dst, ports):
        old_v = brute_force_verdict(old_rules, src_ip, dst_ip, port)
        new_v = brute_force_verdict(new_rules, src_ip, dst_ip, port)
        if old_v == new_v:
            expected_owner = None
        elif new_v == 1:
            expected_owner = "newly_allowed"
            expected_allowed += 1
        else:
            expected_owner = "newly_blocked"
            expected_blocked += 1

        if expected_owner is None:
            assert not any(region_contains(r, src_ip, dst_ip, port) for r in all_regions), (
                f"未变化的连接 {src_ip}->{dst_ip}:{port} 被错误纳入区域"
            )
        else:
            owners = [r for r in all_regions if region_contains(r, src_ip, dst_ip, port)]
            assert len(owners) == 1, f"变化连接必须恰好属于一个区域，实际 {len(owners)} 个"
            assert owners[0]["category"] == expected_owner

    assert sum(r["connection_count"] for r in result["newly_allowed"]) == expected_allowed
    assert sum(r["connection_count"] for r in result["newly_blocked"]) == expected_blocked


def test_disjoint_complex_mix():
    old_rules = [
        rule("10.0.0.0/30", "192.168.0.0/30", 0, 100, "allow"),
        rule("10.0.0.0/30", "192.168.0.0/30", 101, 200, "deny"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    new_rules = [
        rule("10.0.0.0/30", "192.168.0.0/30", 50, 150, "deny"),
        rule("10.0.0.0/30", "192.168.0.0/30", 0, 200, "allow"),
        rule("10.0.0.0/30", "192.168.1.0/30", 200, 300, "allow"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    universe_src = [str(ip) for ip in ipaddress.ip_network("10.0.0.0/30")]
    universe_dst = [
        str(ip)
        for net in ("192.168.0.0/30", "192.168.1.0/30")
        for ip in ipaddress.ip_network(net)
    ]
    ports = list(range(0, 302))
    assert_matches_bruteforce(old_rules, new_rules, universe_src, universe_dst, ports)


def test_disjoint_multi_src_dst_split():
    old_rules = [
        rule("172.16.0.0/30", "10.1.0.0/30", 10, 20, "allow"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    new_rules = [
        rule("172.16.0.0/31", "10.1.0.0/31", 10, 15, "allow"),
        rule("172.16.0.2/31", "10.1.0.2/31", 16, 20, "deny"),
        rule("0.0.0.0/0", "0.0.0.0/0", 0, 65535, "deny"),
    ]
    universe_src = [str(ip) for ip in ipaddress.ip_network("172.16.0.0/30")]
    universe_dst = [str(ip) for ip in ipaddress.ip_network("10.1.0.0/30")]
    ports = list(range(9, 22))
    assert_matches_bruteforce(old_rules, new_rules, universe_src, universe_dst, ports)


def test_default_deny_to_allow_full_universe():
    old_rules = []
    new_rules = [
        rule("10.0.0.0/30", "192.168.9.0/31", 443, 443, "allow"),
    ]
    universe_src = [str(ip) for ip in ipaddress.ip_network("10.0.0.0/30")]
    universe_dst = [str(ip) for ip in ipaddress.ip_network("192.168.9.0/31")]
    ports = [80, 443, 8080]
    assert_matches_bruteforce(old_rules, new_rules, universe_src, universe_dst, ports)
