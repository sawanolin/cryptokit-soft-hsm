"""X.509 checks and encoding helpers for UKey challenge-response login."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography import x509


SM2_CURVE_OID = "1.2.156.10197.1.301"
SM2_WITH_SM3_OID = "1.2.156.10197.1.501"
EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"


class UKeyCertificateError(ValueError):
    pass


def decode_certificate(value: str) -> bytes:
    try:
        compact = "".join(value.split())
        raw = base64.b64decode(compact, validate=True)
    except (ValueError, TypeError) as error:
        raise UKeyCertificateError("证书不是有效的 Base64 数据") from error
    if not raw or len(raw) > 64 * 1024:
        raise UKeyCertificateError("证书长度无效")
    return raw


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
        return base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
    except (UnicodeEncodeError, ValueError) as error:
        raise UKeyCertificateError("数据不是有效的 Base64URL") from error


def _tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    if offset >= len(data):
        raise UKeyCertificateError("证书 DER 结构不完整")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise UKeyCertificateError("证书 DER 长度不完整")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise UKeyCertificateError("证书 DER 长度无效")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise UKeyCertificateError("证书 DER 内容被截断")
    return tag, offset, end, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    result: list[tuple[int, int, int]] = []
    cursor = start
    while cursor < end:
        tag, value_start, value_end, cursor = _tlv(data, cursor)
        result.append((tag, value_start, value_end))
    if cursor != end:
        raise UKeyCertificateError("证书 DER 子结构长度无效")
    return result


def _decode_oid(value: bytes) -> str:
    if not value:
        raise UKeyCertificateError("证书算法 OID 为空")
    first = value[0]
    parts = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(current)
            current = 0
    if current:
        raise UKeyCertificateError("证书算法 OID 不完整")
    return ".".join(str(part) for part in parts)


def sm2_public_point(der: bytes) -> tuple[bytes, bytes]:
    # Locate SubjectPublicKeyInfo inside TBSCertificate without asking OpenSSL to
    # instantiate the SM2 curve, which is not enabled in all cryptography builds.
    tag, cert_start, cert_end, next_offset = _tlv(der, 0)
    if tag != 0x30 or next_offset != len(der):
        raise UKeyCertificateError("证书结构无效")
    cert_children = _children(der, cert_start, cert_end)
    if len(cert_children) != 3 or cert_children[0][0] != 0x30:
        raise UKeyCertificateError("证书结构无效")
    _, tbs_start, tbs_end = cert_children[0]
    tbs_children = _children(der, tbs_start, tbs_end)
    if not tbs_children:
        raise UKeyCertificateError("证书主体结构无效")
    spki_index = 6 if tbs_children[0][0] == 0xA0 else 5
    if len(tbs_children) <= spki_index or tbs_children[spki_index][0] != 0x30:
        raise UKeyCertificateError("证书缺少公钥信息")
    _, spki_start, spki_end = tbs_children[spki_index]
    spki_children = _children(der, spki_start, spki_end)
    if len(spki_children) != 2 or spki_children[0][0] != 0x30 or spki_children[1][0] != 0x03:
        raise UKeyCertificateError("证书公钥结构无效")
    _, alg_start, alg_end = spki_children[0]
    alg_children = _children(der, alg_start, alg_end)
    if len(alg_children) < 2 or alg_children[0][0] != 0x06 or alg_children[1][0] != 0x06:
        raise UKeyCertificateError("证书公钥算法参数缺失")
    algorithm = _decode_oid(der[alg_children[0][1]:alg_children[0][2]])
    curve = _decode_oid(der[alg_children[1][1]:alg_children[1][2]])
    if algorithm != EC_PUBLIC_KEY_OID or curve != SM2_CURVE_OID:
        raise UKeyCertificateError("用户证书必须使用 sm2p256v1 公钥")
    _, point_start, point_end = spki_children[1]
    point = der[point_start:point_end]
    if len(point) != 66 or point[0] != 0 or point[1] != 0x04:
        raise UKeyCertificateError("证书 SM2 公钥点格式无效")
    return point[2:34], point[34:66]


def der_signature_to_raw(signature: bytes) -> bytes:
    tag, start, end, next_offset = _tlv(signature, 0)
    if tag != 0x30 or next_offset != len(signature):
        raise UKeyCertificateError("SM2 签名 DER 结构无效")
    values = _children(signature, start, end)
    if len(values) != 2 or any(item[0] != 0x02 for item in values):
        raise UKeyCertificateError("SM2 签名必须包含 r、s 两个整数")
    raw = bytearray()
    for _, value_start, value_end in values:
        integer = signature[value_start:value_end]
        if integer and integer[0] == 0:
            integer = integer[1:]
        if not integer or len(integer) > 32:
            raise UKeyCertificateError("SM2 签名整数长度无效")
        raw.extend(b"\0" * (32 - len(integer)) + integer)
    return bytes(raw)


def _extension(cert: x509.Certificate, extension_type: type[Any]) -> Any | None:
    try:
        return cert.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def _summary(cert: x509.Certificate, der: bytes) -> dict[str, Any]:
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "public_key_algorithm_oid": cert.public_key_algorithm_oid.dotted_string,
        "curve_oid": SM2_CURVE_OID,
        "sha256_fingerprint": hashlib.sha256(der).hexdigest().upper(),
    }


def validate_certificate_binding(
    user_der: bytes,
    ca_der: bytes,
    digest_and_verify: Callable[[bytes, bytes, bytes, bytes], bool],
) -> dict[str, Any]:
    try:
        user = x509.load_der_x509_certificate(user_der)
        ca = x509.load_der_x509_certificate(ca_der)
    except (ValueError, TypeError) as error:
        raise UKeyCertificateError("证书不是有效的 X.509 DER") from error

    now = datetime.now(timezone.utc)
    for cert, label in ((user, "用户证书"), (ca, "CA 证书")):
        if cert.not_valid_before_utc > now:
            raise UKeyCertificateError(f"{label}尚未生效")
        if cert.not_valid_after_utc < now:
            raise UKeyCertificateError(f"{label}已经过期")
        if cert.signature_algorithm_oid.dotted_string != SM2_WITH_SM3_OID:
            raise UKeyCertificateError(f"{label}必须使用 SM2-with-SM3 签名")
        sm2_public_point(user_der if cert is user else ca_der)

    if user.issuer != ca.subject:
        raise UKeyCertificateError("用户证书的颁发者与上传的 CA 证书主题不匹配")

    user_basic = _extension(user, x509.BasicConstraints)
    if user_basic is not None and user_basic.ca:
        raise UKeyCertificateError("用户签名证书不能是 CA 证书")
    ca_basic = _extension(ca, x509.BasicConstraints)
    if ca_basic is None or not ca_basic.ca:
        raise UKeyCertificateError("上传的 CA 证书缺少 CA=true 基本约束")

    user_usage = _extension(user, x509.KeyUsage)
    if user_usage is None or not user_usage.digital_signature:
        raise UKeyCertificateError("用户证书 KeyUsage 必须包含 digitalSignature")
    ca_usage = _extension(ca, x509.KeyUsage)
    if ca_usage is None or not ca_usage.key_cert_sign:
        raise UKeyCertificateError("CA 证书 KeyUsage 必须包含 keyCertSign")

    user_aki = _extension(user, x509.AuthorityKeyIdentifier)
    ca_ski = _extension(ca, x509.SubjectKeyIdentifier)
    if user_aki and user_aki.key_identifier and ca_ski:
        if user_aki.key_identifier != ca_ski.digest:
            raise UKeyCertificateError("用户证书 AKI 与 CA 证书 SKI 不匹配")

    ca_x, ca_y = sm2_public_point(ca_der)
    certificate_signature = der_signature_to_raw(user.signature)
    if not digest_and_verify(ca_x, ca_y, user.tbs_certificate_bytes, certificate_signature):
        raise UKeyCertificateError("用户证书签名或证书链校验失败")

    user_summary = _summary(user, user_der)
    ca_summary = _summary(ca, ca_der)
    user_summary.update({
        "digital_signature": True,
    })
    ca_summary.update({"ca": True, "key_cert_sign": True})
    return {"user_certificate": user_summary, "ca_certificate": ca_summary, "chain_valid": True}
