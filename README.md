# 防火墙规则变更核对工具

网络运维人员上线防火墙变更前，用本工具核对两份有序规则（变更前 / 变更后）之间
**哪些连接被意外开放（新增放行）或阻断（新增阻断）**。

- 后端：FastAPI + 纯 Python 区间计算引擎（不逐个枚举 IP）
- 前端：原生 HTML / CSS / JavaScript，无构建步骤
- 部署：Docker Compose 一键启动
- 规则模型：源 IPv4 CIDR、目标 IPv4 CIDR、TCP 目标端口闭区间、允许（allow）/ 拒绝（deny）
- 匹配语义：**首条命中生效，未命中默认拒绝**；每份规则表最多 20 条

## 快速开始（Docker Compose）

```bash
docker compose up --build
```

打开浏览器访问 <http://localhost:8000> 。页面打开时会自动载入一份可编辑示例，
可直接点“开始核对”，也可在表格中增删、上移/下移（调整规则顺序）、修改任意字段后再核对。

停止：

```bash
docker compose down
```

## 本地直接运行（不用 Docker）

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 页面功能

- 两张可编辑规则表：旧规则（变更前）、新规则（变更后），各最多 20 条
- 每行可编辑源/目标 IPv4 CIDR、端口下限/上限（闭区间，0–65535）、动作
- ↑ / ↓ 按钮调整规则顺序（顺序即匹配优先级），可删除、添加规则
- 核对结果分两栏展示：
  - **新增放行区域**：旧侧拒绝（含默认拒绝）→ 新侧允许
  - **新增阻断区域**：旧侧允许 → 新侧拒绝
- 每个区域以**互不重叠的源地址段 × 目标地址段 × 端口段**组合表示，完整覆盖全部差异连接：
  - 地址段显示为 `起始 IP – 结束 IP`，并附最少 CIDR 分解（单个 CIDR 时只显示 CIDR）
  - 端口段为闭区间，单端口只显示一个数字
  - 区域连接总数 = 源 IP 数 × 目标 IP 数 × 端口数
  - 附一条**示例连接**（取各段最小值），以及该连接在**旧规则侧、新规则侧分别命中的规则编号与内容**；
    未命中任何规则时明确标注“默认拒绝”
- 顶部汇总：空间切分单元数、两类区域数量与覆盖连接总数

## 计算原理（按区间，不枚举 IP）

整个连接空间是三维笛卡尔积：`IPv4 源地址 × IPv4 目标地址 × TCP 端口 0..65535`。

1. **边界切分**：收集旧、新两份规则在三个维度上的所有区间边界，把全空间切成一组
   互不重叠的基本区间。每个基本区间内，任意规则对它的“包含/不包含”关系恒定。
2. **首条命中求值**：对每个三维基本单元，分别按旧表、新表从上到下做首条命中求值，
   未命中记为默认拒绝（deny）。比较的是单元的**实际动作**（allow/deny），
   因此“旧表 #3 deny、新表 #5 deny”这类规则编号变化但动作不变的情况不会误报。
3. **差异筛选**：仅保留动作翻转的单元（deny→allow 为新增放行，allow→deny 为新增阻断）。
4. **贪心矩形合并**：按端口轴 → 目标地址轴 → 源地址轴的顺序，把相邻且判定一致的
   单元合并成长方体。每个单元只被一个区域消费，所以输出区域**互不重叠且完整覆盖**
   全部差异连接。
5. **地址段展示**：区间基于 CIDR 边界切分，必然可以精确分解为 CIDR；分解取最少 CIDR 集合
   （例如 `192.168.0.0 – 192.168.1.255` 显示为单个 `192.168.0.0/23`）。

整个过程只对“区间”做集合运算，从不逐个枚举 IP 地址。最坏情况（两侧各 20 条、
边界高度交错）约产生数十万级基本单元，常规硬件数秒内完成。

## HTTP API

### `POST /api/analyze`

请求体：

```json
{
  "old_rules": [
    {"src_cidr": "10.10.0.0/16", "dst_cidr": "172.16.5.0/24",
     "port_low": 80, "port_high": 443, "action": "allow"},
    {"src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
     "port_low": 0, "port_high": 65535, "action": "deny"}
  ],
  "new_rules": [
    {"src_cidr": "10.10.0.0/16", "dst_cidr": "172.16.5.0/24",
     "port_low": 3306, "port_high": 3306, "action": "allow"},
    {"src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
     "port_low": 0, "port_high": 65535, "action": "deny"}
  ]
}
```

响应（节选）：

```json
{
  "newly_allowed": [
    {
      "id": 1,
      "category": "newly_allowed",
      "src_segment": {"start": "10.10.0.0", "end": "10.10.255.255",
                      "cidrs": ["10.10.0.0/16"], "label": "10.10.0.0/16"},
      "dst_segment": {"start": "172.16.5.0", "end": "172.16.5.255",
                      "cidrs": ["172.16.5.0/24"], "label": "172.16.5.0/24"},
      "port_segment": {"low": 3306, "high": 3306, "label": "3306"},
      "connection_count": 4194304,
      "sample_connection": {"src_ip": "10.10.0.0", "dst_ip": "172.16.5.0",
                            "dst_port": 3306,
                            "label": "10.10.0.0:3306 → 172.16.5.0:3306 (TCP)"},
      "old_side": {"kind": "rule",
                   "label": "#2 deny 0.0.0.0/0 → 0.0.0.0/0 端口 0-65535",
                   "rule": {"index": 2, "action": "deny", "...": "..."}},
      "new_side": {"kind": "rule",
                   "label": "#1 allow 10.10.0.0/16 → 172.16.5.0/24 端口 3306-3306",
                   "rule": {"index": 1, "action": "allow", "...": "..."}}
    }
  ],
  "newly_blocked": [],
  "stats": {"grid_cells": 27, "src_segments": 3, "dst_segments": 3,
            "port_segments": 3, "allowed_region_count": 1, "blocked_region_count": 0,
            "allowed_connection_count": 4194304, "blocked_connection_count": 0}
}
```

未命中规则时 `old_side` / `new_side` 的 `kind` 为 `default_deny`，
`label` 为“默认拒绝（未命中任何规则）”，`rule` 为 `null`。

其他端点：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 核对页面 |
| GET | `/api/example` | 内置可编辑示例数据 |
| GET | `/health` | 健康检查（Compose 健康探测使用） |
| GET | `/docs` | FastAPI 自动生成的 Swagger 文档 |

错误约定：请求体结构/字段非法返回 `422`；CIDR 不合法（如主机位非零、IPv6）等
语义错误返回 `400`，响应均为 `{"detail": "..."}`。

## 测试

```bash
pip install -r requirements.txt pytest httpx
python -m pytest tests/ -q
```

测试包含三类：

1. 引擎单元测试：CIDR 区间分解、严格校验、首条命中、默认拒绝、区域合并不重叠等
2. API 测试：路由、状态码、校验错误、示例端到端
3. **差分测试**（`tests/test_bruteforce_diff.py`）：在微型 CIDR 空间上暴力枚举每个
   连接的两侧判定，断言引擎输出的每个变化连接恰好属于一个区域、未变化连接不属于任何区域、
   连接总数与暴力结果一致（暴力枚举仅存在于测试中）

## 目录结构

```
.
├── app/
│   ├── main.py              # FastAPI 入口与路由
│   ├── engine.py            # 区间化差异核对引擎
│   ├── schemas.py           # Pydantic 请求模型与校验
│   ├── example.py           # 页面内置示例
│   └── static/              # 前端页面（index.html / styles.css / app.js）
├── tests/                   # pytest 测试（含暴力差分测试）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 边界与约束

- 仅支持 IPv4；CIDR 使用严格解析（`10.0.0.1/24` 这类主机位非零写法会被拒绝）
- 端口为 TCP 目标端口闭区间，范围 0–65535
- 规则按输入顺序匹配，首条命中生效；全部未命中时默认拒绝
- 每份规则表最多 20 条；空规则表是合法输入（等价于“全默认拒绝”）
