"""页面首次加载时使用的可编辑示例（同时演示新增放行、新增阻断与默认拒绝）。"""

EXAMPLE = {
    "old_rules": [
        # 办公网只允许访问测试区的 80/443
        {
            "src_cidr": "10.10.0.0/16",
            "dst_cidr": "172.16.5.0/24",
            "port_low": 80,
            "port_high": 443,
            "action": "allow",
        },
        # 其余全部拒绝
        {
            "src_cidr": "0.0.0.0/0",
            "dst_cidr": "0.0.0.0/0",
            "port_low": 0,
            "port_high": 65535,
            "action": "deny",
        },
    ],
    "new_rules": [
        # 新增：办公网可访问测试区数据库 3306（新增放行）
        {
            "src_cidr": "10.10.0.0/16",
            "dst_cidr": "172.16.5.0/24",
            "port_low": 3306,
            "port_high": 3306,
            "action": "allow",
        },
        # 收紧：办公网到测试区的 80 端口被显式拒绝（新增阻断，443 仍放行）
        {
            "src_cidr": "10.10.0.0/16",
            "dst_cidr": "172.16.5.0/24",
            "port_low": 80,
            "port_high": 80,
            "action": "deny",
        },
        # 保留的 81-443 放行
        {
            "src_cidr": "10.10.0.0/16",
            "dst_cidr": "172.16.5.0/24",
            "port_low": 81,
            "port_high": 443,
            "action": "allow",
        },
        # 其余全部拒绝
        {
            "src_cidr": "0.0.0.0/0",
            "dst_cidr": "0.0.0.0/0",
            "port_low": 0,
            "port_high": 65535,
            "action": "deny",
        },
    ],
}
