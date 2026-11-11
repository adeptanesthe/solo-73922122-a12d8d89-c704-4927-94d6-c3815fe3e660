"""容器健康探测：通过 HTTPS 访问 /health。

演示证书是自签名叶证书，因此这里只验证 TLS 连接可用、HTTP 返回 200，不校验证书链
（与真实的证书轮换无关；轮换材料本身由服务端严格校验）。
"""

from __future__ import annotations

import os
import ssl
import sys
import urllib.request


def main() -> int:
    port = int(os.environ.get("HTTPS_PORT", "8443"))
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(
            f"https://127.0.0.1:{port}/health",
            context=context,
            timeout=4,
        ) as response:
            if response.status != 200:
                return 1
    except Exception as exc:  # noqa: BLE001
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
