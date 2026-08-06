#!/usr/bin/env python3
"""Apple App Attest validation helpers for the Pairling relay."""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier


APP_ATTEST_NONCE_OID = ObjectIdentifier("1.2.840.113635.100.8.2")
APP_ATTEST_PRODUCTION_AAGUID = b"appattest" + (b"\x00" * 7)
APP_ATTEST_DEVELOPMENT_AAGUID = b"appattestdevelop"


class AppAttestValidationError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ParsedAuthData:
    rp_id_hash: bytes
    flags: int
    counter: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None


class AppleAppAttestValidator:
    def __init__(self, *, root_cert_pem: str | None = None, root_cert_path: str | Path | None = None):
        pem = root_cert_pem
        if pem is None and root_cert_path is not None:
            pem = Path(root_cert_path).read_text(encoding="utf-8")
        if pem is None:
            env_path = os.environ.get("PAIRLING_APP_ATTEST_ROOT_CERT")
            if env_path:
                pem = Path(env_path).read_text(encoding="utf-8")
        if not pem:
            raise AppAttestValidationError(
                "app_attest_root_unconfigured",
                "Apple App Attest root certificate is not configured",
            )
        self.root_cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))

    def validate_attestation(
        self,
        *,
        attestation: dict[str, Any],
        challenge: str,
        key_id: str,
        bundle_id: str,
        team_id: str | None,
        app_id_hash: str | None = None,
        environment: str,
    ) -> dict[str, Any]:
        del app_id_hash
        if not team_id:
            raise AppAttestValidationError("app_attest_missing_team_id", "team id is required")
        expected_challenge_hash = _sha256_b64(challenge)
        if attestation.get("challenge_hash_base64") != expected_challenge_hash:
            raise AppAttestValidationError("app_attest_challenge_hash_mismatch", "challenge hash mismatch")
        key_id_bytes = _decode_key_id(key_id)
        decoded = _decode_cbor_b64(str(attestation.get("attestation_object_base64") or ""))
        if not isinstance(decoded, dict):
            raise AppAttestValidationError("app_attest_object_invalid", "attestation object must be a CBOR map")
        if decoded.get("fmt") != "apple-appattest":
            raise AppAttestValidationError("app_attest_format_invalid", "attestation format is not apple-appattest")
        auth_data = decoded.get("authData")
        att_stmt = decoded.get("attStmt")
        if not isinstance(auth_data, bytes) or not isinstance(att_stmt, dict):
            raise AppAttestValidationError("app_attest_object_invalid", "attestation object fields are invalid")
        chain = att_stmt.get("x5c")
        if not isinstance(chain, list) or len(chain) < 2 or not all(isinstance(item, bytes) for item in chain):
            raise AppAttestValidationError("app_attest_chain_missing", "attestation certificate chain is missing")
        credential_cert = x509.load_der_x509_certificate(chain[0])
        intermediate_cert = x509.load_der_x509_certificate(chain[1])
        _verify_chain(credential_cert, intermediate_cert, self.root_cert)
        parsed = _parse_attestation_auth_data(auth_data)
        expected_rp_id = hashlib.sha256(f"{team_id}.{bundle_id}".encode("utf-8")).digest()
        if parsed.rp_id_hash != expected_rp_id:
            raise AppAttestValidationError("app_attest_rp_id_mismatch", "RP ID hash mismatch")
        if parsed.counter != 0:
            raise AppAttestValidationError("app_attest_counter_nonzero", "attestation counter must be zero")
        expected_aaguid = _expected_aaguid(environment)
        if parsed.aaguid != expected_aaguid:
            raise AppAttestValidationError("app_attest_aaguid_mismatch", "App Attest environment AAGUID mismatch")
        if parsed.credential_id != key_id_bytes:
            raise AppAttestValidationError("app_attest_credential_id_mismatch", "credential id does not match key id")
        public_key = credential_cert.public_key()
        public_point = _public_key_uncompressed_point(public_key)
        if hashlib.sha256(public_point).digest() != key_id_bytes:
            raise AppAttestValidationError("app_attest_key_id_mismatch", "key id does not match public key")
        nonce = hashlib.sha256(auth_data + hashlib.sha256(challenge.encode("utf-8")).digest()).digest()
        cert_nonce = _certificate_nonce(credential_cert)
        if cert_nonce != nonce:
            raise AppAttestValidationError("app_attest_nonce_mismatch", "attestation nonce mismatch")
        public_key_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        receipt = att_stmt.get("receipt")
        receipt_hash = hashlib.sha256(receipt).hexdigest() if isinstance(receipt, bytes) else ""
        return {
            "ok": True,
            "mode": "apple_app_attest",
            "public_key_pem": public_key_pem,
            "public_key_sha256": hashlib.sha256(public_point).hexdigest(),
            "receipt_hash": receipt_hash,
            "counter": parsed.counter,
        }

    def validate_assertion(
        self,
        *,
        assertion: dict[str, Any],
        canonical: str,
        device: dict[str, Any],
    ) -> dict[str, Any]:
        key_id = str(assertion.get("key_id") or "")
        if key_id and key_id != str(device.get("app_attest_key_id") or key_id):
            raise AppAttestValidationError("app_attest_assertion_key_mismatch", "assertion key id mismatch")
        expected_hash = _sha256_b64(canonical)
        if assertion.get("challenge_hash_base64") != expected_hash:
            raise AppAttestValidationError("app_attest_assertion_hash_mismatch", "assertion hash mismatch")
        decoded = _decode_cbor_b64(str(assertion.get("assertion_object_base64") or ""))
        if not isinstance(decoded, dict):
            raise AppAttestValidationError("app_attest_assertion_invalid", "assertion object must be a CBOR map")
        auth_data = decoded.get("authenticatorData")
        signature = decoded.get("signature")
        if not isinstance(auth_data, bytes) or not isinstance(signature, bytes):
            raise AppAttestValidationError("app_attest_assertion_invalid", "assertion fields are invalid")
        parsed = _parse_assertion_auth_data(auth_data)
        team_id = str(device.get("team_id") or "")
        bundle_id = str(device.get("bundle_id") or "")
        expected_rp_id = hashlib.sha256(f"{team_id}.{bundle_id}".encode("utf-8")).digest()
        if parsed.rp_id_hash != expected_rp_id:
            raise AppAttestValidationError("app_attest_assertion_rp_id_mismatch", "assertion RP ID mismatch")
        previous_counter = int(device.get("last_assertion_counter") or 0)
        if parsed.counter <= previous_counter:
            raise AppAttestValidationError("app_attest_counter_replayed", "assertion counter did not increase")
        public_key_pem = str(device.get("app_attest_public_key_pem") or "")
        if not public_key_pem:
            raise AppAttestValidationError("app_attest_public_key_missing", "stored App Attest public key is missing")
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        nonce = hashlib.sha256(auth_data + hashlib.sha256(canonical.encode("utf-8")).digest()).digest()
        _verify_signature(public_key, signature, nonce)
        return {
            "ok": True,
            "counter": parsed.counter,
        }


def _sha256_b64(value: str) -> str:
    return base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")


def _decode_key_id(value: str) -> bytes:
    text = value.strip()
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        padded = text + ("=" * ((4 - len(text) % 4) % 4))
        try:
            return base64.urlsafe_b64decode(padded)
        except Exception as exc:
            raise AppAttestValidationError("app_attest_key_id_invalid", "key id is not valid base64") from exc


def _decode_cbor_b64(value: str) -> Any:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise AppAttestValidationError("app_attest_base64_invalid", "object is not valid base64") from exc
    return _CborReader(raw).read_single()


def _verify_chain(leaf: x509.Certificate, intermediate: x509.Certificate, root: x509.Certificate) -> None:
    now = time.time()
    for cert in [leaf, intermediate, root]:
        if not (_cert_not_before(cert) <= now <= _cert_not_after(cert)):
            raise AppAttestValidationError("app_attest_certificate_expired", "certificate is outside validity period")
    if leaf.issuer != intermediate.subject or intermediate.issuer != root.subject:
        raise AppAttestValidationError("app_attest_chain_invalid", "certificate issuer chain mismatch")
    _require_ca(intermediate, "app_attest_intermediate_not_ca")
    _require_ca(root, "app_attest_root_not_ca")
    _verify_cert_signature(leaf, intermediate)
    _verify_cert_signature(intermediate, root)
    _verify_cert_signature(root, root)


def _cert_not_before(cert: x509.Certificate) -> float:
    value = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    if value.tzinfo is None:
        value = value.replace(tzinfo=__import__("datetime").timezone.utc)
    return value.timestamp()


def _cert_not_after(cert: x509.Certificate) -> float:
    value = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if value.tzinfo is None:
        value = value.replace(tzinfo=__import__("datetime").timezone.utc)
    return value.timestamp()


def _require_ca(cert: x509.Certificate, code: str) -> None:
    try:
        constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound as exc:
        raise AppAttestValidationError(code, "CA certificate lacks basic constraints") from exc
    if not constraints.ca:
        raise AppAttestValidationError(code, "certificate is not a CA")


def _verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    try:
        _verify_signature(issuer.public_key(), cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
    except InvalidSignature as exc:
        raise AppAttestValidationError("app_attest_chain_signature_invalid", "certificate signature invalid") from exc


def _verify_signature(public_key: Any, signature: bytes, payload: bytes, algorithm: hashes.HashAlgorithm | None = None) -> None:
    digest = algorithm or hashes.SHA256()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, payload, ec.ECDSA(digest))
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, payload, padding.PKCS1v15(), digest)
        return
    raise AppAttestValidationError("app_attest_public_key_unsupported", "unsupported public key type")


def _parse_attestation_auth_data(auth_data: bytes) -> ParsedAuthData:
    if len(auth_data) < 55:
        raise AppAttestValidationError("app_attest_auth_data_invalid", "attestation auth data is too short")
    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    counter = int.from_bytes(auth_data[33:37], "big")
    aaguid = auth_data[37:53]
    credential_length = int.from_bytes(auth_data[53:55], "big")
    start = 55
    end = start + credential_length
    if len(auth_data) < end:
        raise AppAttestValidationError("app_attest_auth_data_invalid", "credential id is truncated")
    return ParsedAuthData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        counter=counter,
        aaguid=aaguid,
        credential_id=auth_data[start:end],
    )


def _parse_assertion_auth_data(auth_data: bytes) -> ParsedAuthData:
    if len(auth_data) < 37:
        raise AppAttestValidationError("app_attest_assertion_auth_data_invalid", "assertion auth data is too short")
    return ParsedAuthData(
        rp_id_hash=auth_data[:32],
        flags=auth_data[32],
        counter=int.from_bytes(auth_data[33:37], "big"),
    )


def _expected_aaguid(environment: str) -> bytes:
    if environment == "production":
        return APP_ATTEST_PRODUCTION_AAGUID
    if environment in {"development", "sandbox"}:
        return APP_ATTEST_DEVELOPMENT_AAGUID
    raise AppAttestValidationError("app_attest_environment_invalid", "unsupported App Attest environment")


def _public_key_uncompressed_point(public_key: Any) -> bytes:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise AppAttestValidationError("app_attest_public_key_unsupported", "App Attest public key must be EC")
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _certificate_nonce(cert: x509.Certificate) -> bytes:
    try:
        extension = cert.extensions.get_extension_for_oid(APP_ATTEST_NONCE_OID).value
    except x509.ExtensionNotFound as exc:
        raise AppAttestValidationError("app_attest_nonce_missing", "App Attest nonce extension missing") from exc
    if not isinstance(extension, x509.UnrecognizedExtension):
        raise AppAttestValidationError("app_attest_nonce_invalid", "App Attest nonce extension has unexpected type")
    return _decode_der_sequence_octet_string(extension.value)


def _decode_der_sequence_octet_string(data: bytes) -> bytes:
    reader = _DerReader(data)
    if data[:1] == b"\x04":
        value = reader.read_tlv(0x04)
        reader.ensure_done()
        return value
    sequence = reader.read_tlv(0x30)
    reader.ensure_done()
    inner = _DerReader(sequence)
    if inner.peek_tag() == 0x04:
        value = inner.read_tlv(0x04)
    elif inner.peek_tag() in {0xA0, 0xA1}:
        tagged = inner.read_tlv(inner.peek_tag())
        tagged_inner = _DerReader(tagged)
        value = tagged_inner.read_tlv(0x04)
        tagged_inner.ensure_done()
    else:
        raise AppAttestValidationError("app_attest_der_invalid", "unexpected DER tag")
    inner.ensure_done()
    return value


class _DerReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_tlv(self, expected_tag: int) -> bytes:
        if self.pos >= len(self.data) or self.data[self.pos] != expected_tag:
            raise AppAttestValidationError("app_attest_der_invalid", "unexpected DER tag")
        self.pos += 1
        length = self._read_length()
        end = self.pos + length
        if end > len(self.data):
            raise AppAttestValidationError("app_attest_der_invalid", "DER value is truncated")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def _read_length(self) -> int:
        if self.pos >= len(self.data):
            raise AppAttestValidationError("app_attest_der_invalid", "DER length is missing")
        first = self.data[self.pos]
        self.pos += 1
        if first < 0x80:
            return first
        count = first & 0x7F
        if count == 0 or count > 4 or self.pos + count > len(self.data):
            raise AppAttestValidationError("app_attest_der_invalid", "DER length is invalid")
        value = int.from_bytes(self.data[self.pos:self.pos + count], "big")
        self.pos += count
        return value

    def peek_tag(self) -> int | None:
        if self.pos >= len(self.data):
            return None
        return self.data[self.pos]

    def ensure_done(self) -> None:
        if self.pos != len(self.data):
            raise AppAttestValidationError("app_attest_der_invalid", "DER has trailing bytes")


class _CborReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_single(self) -> Any:
        value = self.read()
        if self.pos != len(self.data):
            raise AppAttestValidationError("app_attest_cbor_invalid", "CBOR has trailing data")
        return value

    def read(self) -> Any:
        if self.pos >= len(self.data):
            raise AppAttestValidationError("app_attest_cbor_invalid", "unexpected end of CBOR")
        initial = self.data[self.pos]
        self.pos += 1
        major = initial >> 5
        additional = initial & 0x1F
        length = self._read_length(additional)
        if major == 0:
            return length
        if major == 2:
            return self._read_bytes(length)
        if major == 3:
            return self._read_bytes(length).decode("utf-8")
        if major == 4:
            return [self.read() for _ in range(length)]
        if major == 5:
            result = {}
            for _ in range(length):
                key = self.read()
                result[key] = self.read()
            return result
        raise AppAttestValidationError("app_attest_cbor_invalid", "unsupported CBOR type")

    def _read_length(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            return int.from_bytes(self._read_bytes(1), "big")
        if additional == 25:
            return int.from_bytes(self._read_bytes(2), "big")
        if additional == 26:
            return int.from_bytes(self._read_bytes(4), "big")
        if additional == 27:
            return int.from_bytes(self._read_bytes(8), "big")
        raise AppAttestValidationError("app_attest_cbor_invalid", "indefinite CBOR is not supported")

    def _read_bytes(self, length: int) -> bytes:
        end = self.pos + length
        if end > len(self.data):
            raise AppAttestValidationError("app_attest_cbor_invalid", "CBOR item is truncated")
        value = self.data[self.pos:end]
        self.pos = end
        return value
