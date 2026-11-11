"""X.509 证书材料校验、指纹与演示证书生成。

本模块只负责“材料是否可信/可用”，不接触 SQLite，也不启动 TLS：

- 证书必须是单张 RSA 证书 PEM；
- 私钥必须是未加密的 RSA 私钥 PEM；
- 证书公钥与私钥必须匹配；
- 证书必须含 DNS SAN ``localhost``；
- 证书必须处于有效期内（按 UTC 当前时间判断）；
- 证书 BasicConstraints 必须存在且 ``CA=false``。
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CERT_BLOCK_RE = re.compile(r"-----BEGIN CERTIFICATE-----")
_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (ENCRYPTED PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|PRIVATE KEY)-----"
)


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CertificateInfo:
    """从证书中提取的、可安全展示的公开信息。"""

    fingerprint_sha256: str
    fingerprint_display: str
    subject: str
    common_name: str | None
    san_dns: list[str]
    san_ip: list[str]
    not_before: str
    not_after: str
    serial_number: str

    def as_dict(self) -> dict:
        return {
            "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_display": self.fingerprint_display,
            "subject": self.subject,
            "common_name": self.common_name,
            "san_dns": list(self.san_dns),
            "san_ip": list(self.san_ip),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial_number": self.serial_number,
        }


@dataclass(frozen=True)
class ValidatedMaterial:
    """校验通过后的规范化材料（PEM 已经重新编码，便于直接落库/加载）。"""

    cert_pem: str
    key_pem: str
    info: CertificateInfo
    certificate: x509.Certificate


class CertificateValidationError(ValueError):
    """证书或私钥不满足启用条件。``errors`` 保存全部原因。"""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("；".join(self.errors))


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def fingerprint_display(fingerprint_sha256: str) -> str:
    """把 64 位十六进制指纹格式化为 ``AA:BB:...`` 便于人工核对。"""

    hex_text = fingerprint_sha256.upper()
    return ":".join(hex_text[i : i + 2] for i in range(0, len(hex_text), 2))


def sha256_fingerprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _cert_validity(cert: x509.Certificate) -> tuple[datetime, datetime]:
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = _utc(cert.not_valid_before)
    if not_after is None:
        not_after = _utc(cert.not_valid_after)
    return not_before, not_after


def _decode_pem(value: str | bytes, field: str, errors: list[str]) -> str | None:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8").lstrip("﻿")
        except UnicodeDecodeError:
            errors.append(f"{field}不是 UTF-8 文本 PEM")
            return None
    if not isinstance(value, str):
        errors.append(f"{field}必须是 PEM 文本")
        return None
    return value.lstrip("﻿")


def certificate_info(cert: x509.Certificate) -> CertificateInfo:
    """提取公开信息；调用方应保证证书可解析。"""

    san_dns: list[str] = []
    san_ip: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_dns = [str(name) for name in san.get_values_for_type(x509.DNSName)]
        san_ip = [str(name) for name in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        common_name = None

    fp = sha256_fingerprint(cert)
    nb, na = _cert_validity(cert)
    return CertificateInfo(
        fingerprint_sha256=fp,
        fingerprint_display=fingerprint_display(fp),
        subject=cert.subject.rfc4514_string(),
        common_name=common_name,
        san_dns=san_dns,
        san_ip=san_ip,
        not_before=_iso(nb),
        not_after=_iso(na),
        serial_number=format(cert.serial_number, "x"),
    )


# --------------------------------------------------------------------------- #
# 校验
# --------------------------------------------------------------------------- #
def validate_material(
    cert_pem: str | bytes,
    key_pem: str | bytes,
    *,
    now: datetime | None = None,
) -> ValidatedMaterial:
    """校验证书 + 私钥。全部通过时返回可持久化的规范化材料。

    失败时抛 :class:`CertificateValidationError`，其中 ``errors`` 收集所有问题，
    便于页面一次展示。
    """

    errors: list[str] = []
    now = _utc(now or datetime.now(timezone.utc))

    cert_text = _decode_pem(cert_pem, "证书", errors)
    key_text = _decode_pem(key_pem, "私钥", errors)

    if cert_text is not None:
        cert_blocks = len(_CERT_BLOCK_RE.findall(cert_text))
        if cert_blocks == 0:
            errors.append("证书 PEM 中未找到 CERTIFICATE 块")
        elif cert_blocks > 1:
            errors.append(f"证书 PEM 必须只包含一张证书，实际包含 {cert_blocks} 张")

    if key_text is not None:
        key_blocks = _KEY_BLOCK_RE.findall(key_text)
        if not key_blocks:
            errors.append("私钥 PEM 中未找到 PRIVATE KEY 块")
        elif len(key_blocks) > 1:
            errors.append(f"私钥 PEM 必须只包含一个私钥，实际包含 {len(key_blocks)} 个")
        elif key_blocks[0] == "ENCRYPTED PRIVATE KEY":
            errors.append("私钥不能加密，必须是未加密的 RSA 私钥")

    cert: x509.Certificate | None = None
    if cert_text is not None and len(_CERT_BLOCK_RE.findall(cert_text)) == 1:
        try:
            cert = x509.load_pem_x509_certificate(cert_text.encode("utf-8"))
        except ValueError as exc:
            errors.append(f"无法解析证书 PEM：{exc}")

    private_key = None
    if (
        key_text is not None
        and len(_KEY_BLOCK_RE.findall(key_text)) == 1
        and "ENCRYPTED PRIVATE KEY" not in _KEY_BLOCK_RE.findall(key_text)
    ):
        try:
            private_key = serialization.load_pem_private_key(
                key_text.encode("utf-8"), password=None
            )
        except TypeError:
            errors.append("私钥不能加密，必须提供未加密的 RSA 私钥")
        except ValueError as exc:
            errors.append(f"无法解析私钥 PEM：{exc}")

    public_key = None
    if cert is not None:
        try:
            public_key = cert.public_key()
        except Exception:  # noqa: BLE001 - 未知/不支持的密钥算法
            errors.append("无法读取证书公钥")
        if public_key is not None and not isinstance(public_key, rsa.RSAPublicKey):
            errors.append("证书公钥不是 RSA，仅支持 RSA 证书")

        # DNS SAN 必须包含 localhost
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            dns_names = [str(name).lower() for name in san.get_values_for_type(x509.DNSName)]
            if "localhost" not in dns_names:
                errors.append("证书的 DNS SAN 必须包含 localhost")
        except x509.ExtensionNotFound:
            errors.append("证书缺少 SubjectAlternativeName（DNS SAN localhost）扩展")

        # 有效期
        not_before, not_after = _cert_validity(cert)
        if now < not_before:
            errors.append(f"证书尚未生效（not_before={_iso(not_before)}）")
        if now > not_after:
            errors.append(f"证书已过期（not_after={_iso(not_after)}）")

        # CA=false
        try:
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if basic.ca:
                errors.append("证书 BasicConstraints 的 CA 必须为 false")
        except x509.ExtensionNotFound:
            errors.append("证书缺少 BasicConstraints 扩展（要求 CA=false）")

    if private_key is not None and not isinstance(private_key, rsa.RSAPrivateKey):
        errors.append("私钥不是 RSA 私钥，仅支持未加密的 RSA 私钥")

    # 证书与私钥匹配（仅两者都是 RSA 时才可比较）
    if (
        cert is not None
        and private_key is not None
        and isinstance(private_key, rsa.RSAPrivateKey)
        and isinstance(public_key, rsa.RSAPublicKey)
    ):
        if public_key.public_numbers() != private_key.public_key().public_numbers():
            errors.append("证书与私钥不匹配")

    if errors or cert is None or private_key is None:
        if not errors:
            errors.append("证书或私钥无效")
        raise CertificateValidationError(errors)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CertificateValidationError(["私钥不是 RSA 私钥"])

    # 统一重编码：证书只保留单张 PEM，私钥统一为未加密 PKCS#8。
    normalized_cert = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    normalized_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return ValidatedMaterial(
        cert_pem=normalized_cert,
        key_pem=normalized_key,
        info=certificate_info(cert),
        certificate=cert,
    )


# --------------------------------------------------------------------------- #
# 生成演示/样例材料
# --------------------------------------------------------------------------- #
def generate_material(
    *,
    common_name: str = "localhost",
    organization: str = "Firewall Rule Checker Demo",
    organizational_unit: str = "Certificate Rotation Demo",
    days: int = 3650,
    not_before_days_ago: int = 1,
    key_bits: int = 2048,
    san_dns: tuple[str, ...] = ("localhost",),
    san_ips: tuple[str, ...] = ("127.0.0.1",),
) -> tuple[str, str, CertificateInfo]:
    """生成一张自签名 RSA 叶证书（CA=false、含 localhost DNS SAN、当前有效）。

    返回 ``(cert_pem, key_pem, info)``。仅用于首次启动的演示证书与本地轮换样例。
    生成后仍会经过与用户上传完全相同的校验流程（调用方按需复验）。
    """

    now = datetime.now(timezone.utc)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=not_before_days_ago))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
    )

    names: list[x509.GeneralName] = [x509.DNSName(name) for name in san_dns]
    names.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips)
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        )

    cert = builder.sign(private_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return cert_pem, key_pem, certificate_info(cert)
