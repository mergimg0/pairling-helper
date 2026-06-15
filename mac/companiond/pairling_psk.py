#!/usr/bin/env python3
"""WS3: PSK-authenticated ECDH for pairing — the byte-exact reference.

The 192-bit pairing secret is a pre-shared key delivered out-of-band (QR / paste);
it is NEVER transmitted. The claim becomes an authenticated P-256 ECDH whose key
schedule mixes in the secret, so only a holder of the secret can derive the keys.

Native primitives only (cryptography: ECDH + HKDF + HMAC + AES-GCM). The Swift
side (PairingPSK.swift) mirrors every byte of this; SPEC-ws3-psk-authenticated-ecdh.md
and the shared vectors in test_psk_vectors.py / PairingPSKTests.swift pin the agreement.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
)

# Frozen protocol constants — must match PairingPSK.swift exactly.
PSK_INFO_PREFIX = b"pairling.psk.v1"
PSK_SALT = hashlib.sha256(b"pairling.psk.salt.v1").digest()
CONFIRM_PHONE = b"pairling.psk.confirm.phone.v1"
CONFIRM_MAC = b"pairling.psk.confirm.mac.v1"
_CURVE = ec.SECP256R1()


def mac_keygen() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Per-invitation Mac ephemeral key. Returns (private, A_pub X9.63 65 bytes)."""
    priv = ec.generate_private_key(_CURVE)
    return priv, public_x963(priv)


def private_from_scalar(scalar: int) -> ec.EllipticCurvePrivateKey:
    """Deterministic key for test vectors."""
    return ec.derive_private_key(scalar, _CURVE)


def public_x963(priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def public_from_x963(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, data)


def dump_private(priv: ec.EllipticCurvePrivateKey) -> bytes:
    """PKCS8 DER, for storing the per-invitation key in the (mode-600) pair record."""
    return priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())


def load_private(der: bytes) -> ec.EllipticCurvePrivateKey:
    return load_der_private_key(der, password=None)


def shared_secret(priv: ec.EllipticCurvePrivateKey, peer_pub_x963: bytes) -> bytes:
    """SEC1 X-coordinate (32 bytes) — the standard ECDH output both libraries return."""
    peer = public_from_x963(peer_pub_x963)
    return priv.exchange(ec.ECDH(), peer)


def transcript(pair_id: str, a_pub_x963: bytes, b_pub_x963: bytes) -> bytes:
    return PSK_INFO_PREFIX + pair_id.encode("utf-8") + a_pub_x963 + b_pub_x963


def derive_keys(*, pair_id: str, a_pub: bytes, b_pub: bytes, z: bytes, secret: str) -> tuple[bytes, bytes]:
    """Returns (K_confirm, K_token), each 32 bytes."""
    info = transcript(pair_id, a_pub, b_pub)
    okm = HKDF(algorithm=SHA256(), length=64, salt=PSK_SALT, info=info).derive(z + secret.encode("utf-8"))
    return okm[:32], okm[32:]


def confirm_tag(k_confirm: bytes, domain: bytes, pair_id: str, a_pub: bytes, b_pub: bytes) -> bytes:
    return hmac.new(k_confirm, domain + transcript(pair_id, a_pub, b_pub), hashlib.sha256).digest()


def verify_confirm(k_confirm: bytes, domain: bytes, pair_id: str, a_pub: bytes, b_pub: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(confirm_tag(k_confirm, domain, pair_id, a_pub, b_pub), tag or b"")


def seal_token(k_token: bytes, token: str, *, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM. Returns (nonce(12), ciphertext+tag). Random nonce → not deterministic."""
    import os
    nonce = os.urandom(12)
    ct = AESGCM(k_token).encrypt(nonce, token.encode("utf-8"), aad)
    return nonce, ct


def open_token(k_token: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes) -> str:
    return AESGCM(k_token).decrypt(nonce, ciphertext, aad).decode("utf-8")
