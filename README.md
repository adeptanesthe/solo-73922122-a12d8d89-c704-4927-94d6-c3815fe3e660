# 防火墙规则变更核对工具 + 零停机 HTTPS 证书轮换

本服务包含两部分能力：

1. **防火墙规则变更核对**：网络运维人员上线防火墙变更前，核对两份有序规则
   （变更前 / 变更后）之间哪些连接被意外开放（新增放行）或阻断（新增阻断）。
2. **零停机 HTTPS 证书轮换**：运维人员上传新证书与私钥，服务在**不重启进程**的前提下
   原子启用新证书；启用后开始的完整 TLS 握手使用新证书，已建立的连接继续服务，
   且禁用 TLS 会话恢复。

- 后端：FastAPI + 纯 Python 区间计算引擎（不逐个枚举 IP）
- 证书：`cryptography` 严格校验 RSA 证书/私钥材料，SQLite 持久化活动版本与完整材料
- 部署：Docker Compose 启动 **两个独立 HTTPS 工作进程**，共享同一个 SQLite 卷
- 前端：原生 HTML / CSS / JavaScript，无构建步骤
- 规则模型：源 IPv4 CIDR、目标 IPv4 CIDR、TCP 目标端口闭区间、允许（allow）/ 拒绝（deny）
- 匹配语义：**首条命中生效，未命中默认拒绝**；每份规则表最多 20 条

## 快速开始（Docker Compose）

```bash
docker compose up --build
```

启动后有两个独立 HTTPS 工作进程：

| 进程 | 浏览器入口（首页） | 证书轮换页 |
| --- | --- | --- |
| worker1 | <https://localhost:8443/> | <https://localhost:8443/rotate> |
| worker2 | <https://localhost:8444/> | <https://localhost:8444/rotate> |

首次启动会在共享卷中生成一张**自签名演示证书**（RSA、DNS SAN `localhost`、
`CA=false`、当前有效），并持久化在 SQLite 中。浏览器会提示证书不受信任（因为没有
受信任 CA 签发），选择“继续访问”即可。两个进程默认使用同一张活动证书。

停止：

```bash
docker compose down       # 保留证书卷
docker compose down -v    # 同时删除证书卷，下次启动重新生成演示证书
```

## HTTPS 证书轮换（浏览器操作）

打开 <https://localhost:8443/rotate>：

1. 页面顶部显示当前活动版本、握手证书 SHA-256 指纹、主题、DNS SAN、有效期、来源与时间。
2. 在“预期当前版本”中填入页面显示的版本（载入样例时会自动填入）。
3. 通过文件选择或直接粘贴：
   - **单张 RSA 证书 PEM**；
   - **未加密 RSA 私钥 PEM**；
   - 页面还提供“载入样例 A / 载入样例 B”按钮，分别载入两套本地轮换样例。
4. 点击“校验并原子启用（版本 +1）”。

只有以下校验全部通过才会原子启用并把活动版本 +1：

- 证书 PEM 必须且只能包含一张证书，且证书公钥为 **RSA**；
- 私钥必须是一个**未加密的 RSA 私钥**；
- **证书与私钥公钥参数匹配**；
- 证书含 **DNS SAN `localhost`**；
- 证书**当前有效**（按 UTC 判断 `not_before <= now <= not_after`）；
- 证书 BasicConstraints 存在且 **`CA=false`**。

任一校验失败或“预期当前版本”与实际活动版本不符时，**原证书与版本完全保留**。
版本不符返回 HTTP 409；材料校验失败返回 HTTP 400。

激活成功后：

- 每个工作进程的**新 TCP 连接**在 TLS 握手前读取 SQLite 中的活动证书行，
  因此此后开始的完整 TLS 握手使用新证书；
- **已建立的 TLS 连接继续使用旧会话服务**，不中断；
- 每个连接使用独立 `SSLContext`，并设置 `OP_NO_TICKET`、`num_tickets=0`，
  **禁用 TLS 会话票据/恢复**；
- 活动版本、证书、私钥、指纹在**同一行**内一次性更新和读取，不会出现混配材料；
- 激活使用 `BEGIN IMMEDIATE` + “期望版本”比较并交换（CAS）。**多个进程并发启用
  同一预期版本时只有一个成功**，其余返回 409。

页面底部的“双进程握手探测”会由服务端分别对 worker1、worker2 发起**真实 TLS 握手**，
读取握手叶子证书并显示其 **SHA-256 指纹**，同时显示对端进程报告的活动版本、TLS 版本
与耗时；若某进程不可达会显示错误原因。

## 架构与关键实现

```
                    host port 8443                         host port 8444
                         │                                      │
              ┌──────────▼──────────┐               ┌───────────▼─────────┐
              │ worker1 容器/进程    │               │ worker2 容器/进程     │
              │  TlsProxy (HTTPS)    │               │  TlsProxy (HTTPS)    │
              │      │ 解密字节流     │               │      │               │
              │  uvicorn/FastAPI     │               │  uvicorn/FastAPI     │
              │  127.0.0.1:18080     │               │  127.0.0.1:18080     │
              └──────────┬──────────┘               └───────────┬─────────┘
                         │      共享 named volume /data          │
                         └──────────────┬───────────────────────┘
                                        ▼
                              SQLite: /data/certs.db
                              active_cert（单行：版本 + 证书 + 私钥 + 指纹）
                              cert_history（历史版本审计）
                              rotation_samples（两套本地样例）
```

- **对外只有 HTTPS**：每个容器内的 uvicorn 只监听 `127.0.0.1` 的内部明文端口，
  `TlsProxy` 负责真正的 TLS 终止。
- **每连接 SSLContext**：代理在每个新连接读取活动证书快照后新建 `SSLContext` 并
  `load_cert_chain`，因此新连接不会复用旧会话，也不会跨版本混用材料。
- **单行原子快照**：`active_cert` 只有 `id=1` 一行，包含 `version/cert_pem/key_pem/
  fingerprint/...`；一次 `SELECT` 或一次激活 `UPDATE` 都在同一行内完成。
- **跨进程一致性**：两个容器读写同一个 SQLite 文件（WAL + `busy_timeout`）；
  首次初始化用文件锁串行化，避免两个进程同时生成演示证书或样例。
- **首次启动持久化**：若 `active_cert` 为空则生成演示证书（版本 1）；两套轮换样例也
  只在缺失时生成。重启后继续使用数据库中的活动版本。
- **既有连接**：轮换只更新数据库行，不关闭代理监听，也不关闭任何已建立的连接。

## HTTP API

### 原核对功能

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 规则核对页面 |
| GET | `/rotate` | HTTPS 证书轮换页面 |
| GET | `/api/example` | 内置可编辑示例数据 |
| POST | `/api/analyze` | 执行规则差异核对 |
| GET | `/health` | 健康检查（Compose 健康探测使用） |
| GET | `/docs` | FastAPI 自动生成的 Swagger 文档 |

`POST /api/analyze` 请求/响应与之前一致；错误约定：请求体结构/字段非法返回 `422`；
CIDR 不合法等语义错误返回 `400`，响应均为 `{"detail": "..."}`。

### 证书轮换

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/rotate/state` | 当前活动版本、公开证书信息、探测目标 |
| GET | `/api/rotate/samples` | 两套本地轮换样例（含演示用私钥） |
| POST | `/api/rotate/activate` | 校验并原子启用，版本 +1 |
| GET | `/api/rotate/probe` | 实际探测两个 HTTPS 进程的握手证书指纹 |

`POST /api/rotate/activate` 支持两种请求体：

**JSON**（轮换页使用）：

```json
{
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "expected_version": 1
}
```

**multipart/form-data**（文件上传）：

```bash
curl -k -X POST https://localhost:8443/api/rotate/activate \
  -F "cert_pem=@new-cert.pem" \
  -F "key_pem=@new-key.pem" \
  -F "expected_version=1"
```

成功响应（节选）：

```json
{
  "ok": true,
  "worker": "worker1",
  "previous_version": 1,
  "version": 2,
  "fingerprint_sha256": "…",
  "fingerprint_display": "AA:BB:…",
  "message": "全部校验通过，已原子启用新证书（版本 1 → 2）…"
}
```

版本冲突返回 `409`：

```json
{"detail": "版本不符：当前活动版本为 2，预期为 1；未做任何更改",
 "current_version": 2, "expected_version": 1}
```

材料校验失败返回 `400`，`detail` 为原因汇总，`errors` 为逐条原因：

```json
{"detail": "证书与私钥不匹配；证书的 DNS SAN 必须包含 localhost",
 "errors": ["证书与私钥不匹配", "证书的 DNS SAN 必须包含 localhost"]}
```

探测接口响应（节选）：

```json
{
  "worker": "worker1",
  "probed_at": "2026-11-11T…Z",
  "targets": [
    {
      "name": "worker1",
      "display_url": "https://localhost:8443",
      "ok": true,
      "fingerprint_sha256": "…",
      "fingerprint_display": "AA:BB:…",
      "version": 2,
      "worker": "worker1",
      "tls_version": "TLSv1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "state_matches_handshake": true,
      "elapsed_ms": 3.1,
      "error": null
    }
  ]
}
```

## 本地直接运行（不用 Docker）

每个 worker 是一个独立进程。先准备两个终端，共享同一个 SQLite 文件：

```bash
pip install -r requirements.txt

# 终端 1
CERT_DB_PATH=./data/certs.db WORKER_NAME=worker1 HTTPS_PORT=8443 \
INTERNAL_PORT=18080 \
PROBE_TARGETS="worker1|https://localhost:8443|https://localhost:8443,worker2|https://localhost:8444|https://localhost:8444" \
python -m app.worker

# 终端 2
CERT_DB_PATH=./data/certs.db WORKER_NAME=worker2 HTTPS_PORT=8444 \
INTERNAL_PORT=18081 \
PROBE_TARGETS="worker1|https://localhost:8443|https://localhost:8443,worker2|https://localhost:8444|https://localhost:8444" \
python -m app.worker
```

然后访问 <https://localhost:8443/> 或 <https://localhost:8444/>。

> 直接运行 `uvicorn app.main:app` 只会启动内部明文应用，不会自动提供 HTTPS 终止；
> HTTPS 入口请使用 `python -m app.worker` 或 Docker Compose。

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WORKER_NAME` | `worker1` | 进程名称（页面/探测展示） |
| `CERT_DB_PATH` | `data/certs.db` | 共享 SQLite 路径；Compose 中为 `/data/certs.db` |
| `HTTPS_PORT` | `8443` | 对外 HTTPS 端口 |
| `INTERNAL_PORT` | `18080` | 内部 uvicorn 明文端口（仅回环） |
| `BIND_HOST` | `0.0.0.0` | HTTPS 监听地址 |
| `PROBE_TARGETS` | 本地 8443/8444 | `name\|url\|display_url,...` 形式的探测目标 |
| `RSA_KEY_BITS` | `2048` | 首次生成的演示证书/样例密钥位数 |
| `PROBE_TIMEOUT` | `6` | 单个探测超时（秒） |

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

## 页面功能（规则核对）

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
- 首页右上角提供“HTTPS 证书轮换”入口

## 测试

```bash
pip install -r requirements.txt pytest httpx
python -m pytest tests/ -q
```

测试包含：

1. 引擎单元测试：CIDR 区间分解、严格校验、首条命中、默认拒绝、区域合并不重叠等
2. API 测试：路由、状态码、校验错误、示例端到端
3. **差分测试**（`tests/test_bruteforce_diff.py`）：在微型 CIDR 空间上暴力枚举每个
   连接的两侧判定，断言引擎输出的每个变化连接恰好属于一个区域、未变化连接不属于任何区域、
   连接总数与暴力结果一致（暴力枚举仅存在于测试中）
4. 证书轮换测试：材料校验、版本 CAS、并发激活、SQLite 持久化、两个进程的 TLS
   握手指纹与“新旧连接分离”行为

## 目录结构

```
.
├── app/
│   ├── main.py              # FastAPI 入口与路由（核对 + 轮换）
│   ├── engine.py            # 区间化差异核对引擎
│   ├── schemas.py           # Pydantic 请求模型与校验
│   ├── example.py           # 页面内置示例
│   ├── cert_material.py     # 证书/私钥校验、指纹、演示材料生成
│   ├── certstore.py         # SQLite 单行原子快照与版本 CAS
│   ├── tlsproxy.py          # 每连接 SSLContext 的 HTTPS 终止层
│   ├── probe.py             # 真实 TLS 握手探测与 SHA-256 指纹
│   ├── settings.py          # 环境变量配置
│   ├── worker.py            # HTTPS 工作进程入口
│   ├── healthcheck.py       # 容器健康探测
│   └── static/              # index / rotate 页面与样式、脚本
├── tests/                   # pytest（含暴力差分与证书轮换测试）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 边界与约束

- 规则核对仅支持 IPv4；CIDR 使用严格解析（`10.0.0.1/24` 这类主机位非零写法会被拒绝）
- 端口为 TCP 目标端口闭区间，范围 0–65535
- 规则按输入顺序匹配，首条命中生效；全部未命中时默认拒绝
- 每份规则表最多 20 条；空规则表是合法输入（等价于“全默认拒绝”）
- 证书轮换仅接受**单张 RSA 证书** + **未加密 RSA 私钥**，并要求 DNS SAN 含 `localhost`、
  当前有效、`CA=false`
- 演示环境使用自签名证书，浏览器需手动信任/继续；生产部署应使用正式 CA 签发证书，
  并避免在共享卷中长期明文保存私钥
