"""Pairling session-control principals, P-256 authority signing, and pinning."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import platform
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


_AUTHORITY_APPLICATION_TAG = b"dev.pairling.session-control-authority.v1"
_AUTHORITY_KEY_ID_PREFIX = "pairling.control_authority."
_PROOF_JWS_TYPE = "pairling-proof+jws"
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


class SessionControlTrustError(RuntimeError):
    pass


class P256SigningBackend(Protocol):
    @property
    def public_key_x963(self) -> bytes: ...

    @property
    def hardware_backed(self) -> bool: ...

    def sign_der(self, message: bytes) -> bytes: ...


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str, *, maximum: int = 16 * 1024) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SessionControlTrustError("base64url value is invalid")
    if "=" in value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise SessionControlTrustError("base64url value is not canonical")
    try:
        decoded = base64.b64decode(
            value + ("=" * ((4 - len(value) % 4) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise SessionControlTrustError("base64url value is invalid") from exc
    if _b64url(decoded) != value:
        raise SessionControlTrustError("base64url value is not canonical")
    return decoded


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SessionControlTrustError(
            "trust payload is not canonical restricted JSON"
        ) from exc


def derive_device_principal(mac_install_id: str, device_id: str) -> str:
    install = str(mac_install_id or "")
    device = str(device_id or "")
    if (
        not install
        or not device
        or len(install) > 512
        or len(device) > 512
        or any(character in install + device for character in "\r\n\0")
    ):
        raise SessionControlTrustError(
            "authenticated device identity is incomplete"
        )
    digest = hashlib.sha256(
        install.encode("utf-8") + b"\0" + device.encode("utf-8")
    ).hexdigest()
    return f"pairling.device:sha256:{digest}"


def authority_key_id(public_key_x963: bytes) -> str:
    _validate_public_key(public_key_x963)
    digest = hashlib.sha256(public_key_x963).hexdigest()
    return _AUTHORITY_KEY_ID_PREFIX + digest


def _validate_public_key(value: bytes) -> ec.EllipticCurvePublicKey:
    if not isinstance(value, bytes) or len(value) != 65 or value[0] != 4:
        raise SessionControlTrustError("P-256 public key is not X9.63 encoded")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            value,
        )
    except ValueError as exc:
        raise SessionControlTrustError("P-256 public key is invalid") from exc
    if key.curve.name != "secp256r1":
        raise SessionControlTrustError("authority public key is not P-256")
    return key


def _der_to_raw(signature_der: bytes) -> bytes:
    try:
        r, s = utils.decode_dss_signature(signature_der)
    except ValueError as exc:
        raise SessionControlTrustError("P-256 signature is invalid") from exc
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        raise SessionControlTrustError("P-256 signature scalar is invalid")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_to_der(signature_raw: bytes) -> bytes:
    if not isinstance(signature_raw, bytes) or len(signature_raw) != 64:
        raise SessionControlTrustError("P-256 signature must be 64 raw bytes")
    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        raise SessionControlTrustError("P-256 signature scalar is invalid")
    return utils.encode_dss_signature(r, s)


@dataclass(frozen=True)
class AuthorityPublicKey:
    key_id: str
    algorithm: str
    public_key_format: str
    public_key: str
    hardware_backed: bool

    @classmethod
    def from_x963(
        cls,
        public_key_x963: bytes,
        *,
        hardware_backed: bool,
    ) -> "AuthorityPublicKey":
        return cls(
            key_id=authority_key_id(public_key_x963),
            algorithm="p256-sha256",
            public_key_format="x963-base64url",
            public_key=_b64url(public_key_x963),
            hardware_backed=bool(hardware_backed),
        )

    def x963_bytes(self) -> bytes:
        if self.algorithm != "p256-sha256":
            raise SessionControlTrustError("authority algorithm is unsupported")
        if self.public_key_format != "x963-base64url":
            raise SessionControlTrustError("authority public-key format is unsupported")
        value = _b64url_decode(self.public_key, maximum=256)
        if authority_key_id(value) != self.key_id:
            raise SessionControlTrustError("authority key ID does not match its key")
        return value

    def to_payload(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_format": self.public_key_format,
            "public_key": self.public_key,
            "hardware_backed": self.hardware_backed,
        }


class CryptographyP256Backend:
    """Explicit in-memory backend for deterministic boundary tests only."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise SessionControlTrustError("test authority key is invalid")
        if private_key.curve.name != "secp256r1":
            raise SessionControlTrustError("test authority key is not P-256")
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "CryptographyP256Backend":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @property
    def public_key_x963(self) -> bytes:
        numbers = self._private_key.public_key().public_numbers()
        return (
            b"\x04"
            + numbers.x.to_bytes(32, "big")
            + numbers.y.to_bytes(32, "big")
        )

    @property
    def hardware_backed(self) -> bool:
        return False

    def sign_der(self, message: bytes) -> bytes:
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))


class _CFDictionaryKeyCallBacks(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_long),
        ("retain", ctypes.c_void_p),
        ("release", ctypes.c_void_p),
        ("copyDescription", ctypes.c_void_p),
        ("equal", ctypes.c_void_p),
        ("hash", ctypes.c_void_p),
    ]


class _CFDictionaryValueCallBacks(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_long),
        ("retain", ctypes.c_void_p),
        ("release", ctypes.c_void_p),
        ("copyDescription", ctypes.c_void_p),
        ("equal", ctypes.c_void_p),
    ]


class _SecurityBindings:
    _UTF8 = 0x08000100
    _NUMBER_SINT32 = 3
    _PRIVATE_KEY_USAGE = 1 << 30
    _ITEM_NOT_FOUND = -25300

    def __init__(self) -> None:
        if platform.system() != "Darwin":
            raise SessionControlTrustError(
                "Keychain authority signing requires macOS"
            )
        self.cf = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self.security = ctypes.CDLL(
            "/System/Library/Frameworks/Security.framework/Security"
        )
        self._configure()
        self._key_callbacks = _CFDictionaryKeyCallBacks.in_dll(
            self.cf,
            "kCFTypeDictionaryKeyCallBacks",
        )
        self._value_callbacks = _CFDictionaryValueCallBacks.in_dll(
            self.cf,
            "kCFTypeDictionaryValueCallBacks",
        )

    def _configure(self) -> None:
        void = ctypes.c_void_p
        self.cf.CFRelease.argtypes = [void]
        self.cf.CFRelease.restype = None
        self.cf.CFDictionaryCreateMutable.argtypes = [
            void,
            ctypes.c_long,
            ctypes.POINTER(_CFDictionaryKeyCallBacks),
            ctypes.POINTER(_CFDictionaryValueCallBacks),
        ]
        self.cf.CFDictionaryCreateMutable.restype = void
        self.cf.CFDictionarySetValue.argtypes = [void, void, void]
        self.cf.CFDictionarySetValue.restype = None
        self.cf.CFDictionaryGetValue.argtypes = [void, void]
        self.cf.CFDictionaryGetValue.restype = void
        self.cf.CFDataCreate.argtypes = [
            void,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_long,
        ]
        self.cf.CFDataCreate.restype = void
        self.cf.CFDataGetLength.argtypes = [void]
        self.cf.CFDataGetLength.restype = ctypes.c_long
        self.cf.CFDataGetBytePtr.argtypes = [void]
        self.cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
        self.cf.CFNumberCreate.argtypes = [void, ctypes.c_int, void]
        self.cf.CFNumberCreate.restype = void
        self.cf.CFEqual.argtypes = [void, void]
        self.cf.CFEqual.restype = ctypes.c_ubyte
        self.cf.CFStringGetLength.argtypes = [void]
        self.cf.CFStringGetLength.restype = ctypes.c_long
        self.cf.CFStringGetMaximumSizeForEncoding.argtypes = [
            ctypes.c_long,
            ctypes.c_uint32,
        ]
        self.cf.CFStringGetMaximumSizeForEncoding.restype = ctypes.c_long
        self.cf.CFStringGetCString.argtypes = [
            void,
            ctypes.c_char_p,
            ctypes.c_long,
            ctypes.c_uint32,
        ]
        self.cf.CFStringGetCString.restype = ctypes.c_ubyte

        self.security.SecItemCopyMatching.argtypes = [void, ctypes.POINTER(void)]
        self.security.SecItemCopyMatching.restype = ctypes.c_int32
        self.security.SecKeyCreateRandomKey.argtypes = [void, ctypes.POINTER(void)]
        self.security.SecKeyCreateRandomKey.restype = void
        self.security.SecKeyCopyPublicKey.argtypes = [void]
        self.security.SecKeyCopyPublicKey.restype = void
        self.security.SecKeyCopyExternalRepresentation.argtypes = [
            void,
            ctypes.POINTER(void),
        ]
        self.security.SecKeyCopyExternalRepresentation.restype = void
        self.security.SecKeyCreateSignature.argtypes = [
            void,
            void,
            void,
            ctypes.POINTER(void),
        ]
        self.security.SecKeyCreateSignature.restype = void
        self.security.SecKeyCopyAttributes.argtypes = [void]
        self.security.SecKeyCopyAttributes.restype = void
        self.security.SecAccessControlCreateWithFlags.argtypes = [
            void,
            void,
            ctypes.c_ulong,
            ctypes.POINTER(void),
        ]
        self.security.SecAccessControlCreateWithFlags.restype = void
        self.cf.CFErrorCopyDescription.argtypes = [void]
        self.cf.CFErrorCopyDescription.restype = void

    @staticmethod
    def constant(library: ctypes.CDLL, name: str) -> int:
        value = ctypes.c_void_p.in_dll(library, name).value
        if not value:
            raise SessionControlTrustError(f"Security constant {name} is absent")
        return int(value)

    def dictionary(self, values: Mapping[int, int]) -> int:
        result = self.cf.CFDictionaryCreateMutable(
            None,
            0,
            ctypes.byref(self._key_callbacks),
            ctypes.byref(self._value_callbacks),
        )
        if not result:
            raise SessionControlTrustError("could not allocate Security attributes")
        for key, value in values.items():
            self.cf.CFDictionarySetValue(
                ctypes.c_void_p(result),
                ctypes.c_void_p(key),
                ctypes.c_void_p(value),
            )
        return int(result)

    def data(self, value: bytes) -> int:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        result = self.cf.CFDataCreate(None, buffer, len(value))
        if not result:
            raise SessionControlTrustError("could not allocate Security data")
        return int(result)

    def number(self, value: int) -> int:
        raw = ctypes.c_int32(value)
        result = self.cf.CFNumberCreate(
            None,
            self._NUMBER_SINT32,
            ctypes.byref(raw),
        )
        if not result:
            raise SessionControlTrustError("could not allocate Security number")
        return int(result)

    def data_bytes(self, value: int) -> bytes:
        length = int(self.cf.CFDataGetLength(ctypes.c_void_p(value)))
        pointer = self.cf.CFDataGetBytePtr(ctypes.c_void_p(value))
        if length < 0 or (length and not pointer):
            raise SessionControlTrustError("Security data is invalid")
        return ctypes.string_at(pointer, length)

    def error_text(self, error: int | None) -> str:
        if not error:
            return "unknown Security.framework error"
        description = self.cf.CFErrorCopyDescription(ctypes.c_void_p(error))
        try:
            if not description:
                return "Security.framework operation failed"
            length = self.cf.CFStringGetLength(ctypes.c_void_p(description))
            maximum = self.cf.CFStringGetMaximumSizeForEncoding(
                length,
                self._UTF8,
            ) + 1
            buffer = ctypes.create_string_buffer(maximum)
            if self.cf.CFStringGetCString(
                ctypes.c_void_p(description),
                buffer,
                maximum,
                self._UTF8,
            ):
                return buffer.value.decode("utf-8", errors="replace")[:500]
            return "Security.framework operation failed"
        finally:
            if description:
                self.cf.CFRelease(ctypes.c_void_p(description))
            self.cf.CFRelease(ctypes.c_void_p(error))

    def release(self, value: int | None) -> None:
        if value:
            self.cf.CFRelease(ctypes.c_void_p(value))


class MacOSKeychainP256Backend:
    """Non-exportable P-256 key in Keychain, Secure Enclave when available."""

    def __init__(self, key: int, *, bindings: _SecurityBindings) -> None:
        self._bindings = bindings
        self._key = int(key)
        self._lock = threading.RLock()
        self._public_key_x963 = self._copy_public_key()
        self._hardware_backed = self._read_hardware_backing()

    @classmethod
    def load_or_create(
        cls,
        *,
        application_tag: bytes = _AUTHORITY_APPLICATION_TAG,
    ) -> "MacOSKeychainP256Backend":
        bindings = _SecurityBindings()
        tag = bindings.data(application_tag)
        try:
            key = cls._load(bindings, tag)
            if key is None:
                key = cls._create(bindings, tag, secure_enclave=True)
            if key is None:
                key = cls._create(bindings, tag, secure_enclave=False)
            if key is None:
                raise SessionControlTrustError(
                    "could not create a Keychain-backed P-256 authority key"
                )
            return cls(key, bindings=bindings)
        finally:
            bindings.release(tag)

    @staticmethod
    def _load(bindings: _SecurityBindings, tag: int) -> int | None:
        security = bindings.security
        key_type = bindings.constant(security, "kSecAttrKeyType")
        key_class = bindings.constant(security, "kSecAttrKeyClass")
        query = bindings.dictionary({
            bindings.constant(security, "kSecClass"):
                bindings.constant(security, "kSecClassKey"),
            bindings.constant(security, "kSecAttrApplicationTag"): tag,
            key_type: bindings.constant(
                security,
                "kSecAttrKeyTypeECSECPrimeRandom",
            ),
            key_class: bindings.constant(security, "kSecAttrKeyClassPrivate"),
            bindings.constant(security, "kSecReturnRef"):
                bindings.constant(bindings.cf, "kCFBooleanTrue"),
            bindings.constant(security, "kSecMatchLimit"):
                bindings.constant(security, "kSecMatchLimitOne"),
        })
        try:
            result = ctypes.c_void_p()
            status = bindings.security.SecItemCopyMatching(
                ctypes.c_void_p(query),
                ctypes.byref(result),
            )
            if status == bindings._ITEM_NOT_FOUND:
                return None
            if status != 0 or not result.value:
                raise SessionControlTrustError(
                    f"Keychain authority lookup failed with OSStatus {status}"
                )
            return int(result.value)
        finally:
            bindings.release(query)

    @staticmethod
    def _create(
        bindings: _SecurityBindings,
        tag: int,
        *,
        secure_enclave: bool,
    ) -> int | None:
        security = bindings.security
        true_value = bindings.constant(bindings.cf, "kCFBooleanTrue")
        bits = bindings.number(256)
        access_control = None
        error = ctypes.c_void_p()
        private_values = {
            bindings.constant(security, "kSecAttrIsPermanent"): true_value,
            bindings.constant(security, "kSecAttrApplicationTag"): tag,
        }
        if secure_enclave:
            access_control = security.SecAccessControlCreateWithFlags(
                None,
                ctypes.c_void_p(bindings.constant(
                    security,
                    "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
                )),
                bindings._PRIVATE_KEY_USAGE,
                ctypes.byref(error),
            )
            if not access_control:
                if error.value:
                    bindings.error_text(int(error.value))
                bindings.release(bits)
                return None
            private_values[
                bindings.constant(security, "kSecAttrAccessControl")
            ] = int(access_control)
        else:
            private_values[
                bindings.constant(security, "kSecAttrAccessible")
            ] = bindings.constant(
                security,
                "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
            )
        private_attributes = bindings.dictionary(private_values)
        attributes = {
            bindings.constant(security, "kSecAttrKeyType"):
                bindings.constant(
                    security,
                    "kSecAttrKeyTypeECSECPrimeRandom",
                ),
            bindings.constant(security, "kSecAttrKeySizeInBits"): bits,
            bindings.constant(security, "kSecPrivateKeyAttrs"): private_attributes,
        }
        if secure_enclave:
            attributes[bindings.constant(security, "kSecAttrTokenID")] = (
                bindings.constant(security, "kSecAttrTokenIDSecureEnclave")
            )
        key_attributes = bindings.dictionary(attributes)
        try:
            error = ctypes.c_void_p()
            key = security.SecKeyCreateRandomKey(
                ctypes.c_void_p(key_attributes),
                ctypes.byref(error),
            )
            if not key:
                if error.value:
                    bindings.error_text(int(error.value))
                return None
            return int(key)
        finally:
            bindings.release(key_attributes)
            bindings.release(private_attributes)
            bindings.release(int(access_control) if access_control else None)
            bindings.release(bits)

    def _copy_public_key(self) -> bytes:
        public_key = self._bindings.security.SecKeyCopyPublicKey(
            ctypes.c_void_p(self._key)
        )
        if not public_key:
            raise SessionControlTrustError("authority public key is unavailable")
        try:
            error = ctypes.c_void_p()
            external = self._bindings.security.SecKeyCopyExternalRepresentation(
                ctypes.c_void_p(public_key),
                ctypes.byref(error),
            )
            if not external:
                message = self._bindings.error_text(
                    int(error.value) if error.value else None
                )
                raise SessionControlTrustError(
                    f"authority public key export failed: {message}"
                )
            try:
                value = self._bindings.data_bytes(int(external))
                _validate_public_key(value)
                return value
            finally:
                self._bindings.release(int(external))
        finally:
            self._bindings.release(int(public_key))

    def _read_hardware_backing(self) -> bool:
        attributes = self._bindings.security.SecKeyCopyAttributes(
            ctypes.c_void_p(self._key)
        )
        if not attributes:
            return False
        try:
            token = self._bindings.cf.CFDictionaryGetValue(
                ctypes.c_void_p(attributes),
                ctypes.c_void_p(self._bindings.constant(
                    self._bindings.security,
                    "kSecAttrTokenID",
                )),
            )
            secure_enclave = self._bindings.constant(
                self._bindings.security,
                "kSecAttrTokenIDSecureEnclave",
            )
            return bool(
                token
                and self._bindings.cf.CFEqual(
                    ctypes.c_void_p(token),
                    ctypes.c_void_p(secure_enclave),
                )
            )
        finally:
            self._bindings.release(int(attributes))

    @property
    def public_key_x963(self) -> bytes:
        return self._public_key_x963

    @property
    def hardware_backed(self) -> bool:
        return self._hardware_backed

    def sign_der(self, message: bytes) -> bytes:
        if not isinstance(message, bytes) or not message:
            raise SessionControlTrustError("authority signing input is empty")
        data = self._bindings.data(message)
        try:
            error = ctypes.c_void_p()
            signature = self._bindings.security.SecKeyCreateSignature(
                ctypes.c_void_p(self._key),
                ctypes.c_void_p(self._bindings.constant(
                    self._bindings.security,
                    "kSecKeyAlgorithmECDSASignatureMessageX962SHA256",
                )),
                ctypes.c_void_p(data),
                ctypes.byref(error),
            )
            if not signature:
                detail = self._bindings.error_text(
                    int(error.value) if error.value else None
                )
                raise SessionControlTrustError(
                    f"authority signature failed: {detail}"
                )
            try:
                return self._bindings.data_bytes(int(signature))
            finally:
                self._bindings.release(int(signature))
        finally:
            self._bindings.release(data)

    def close(self) -> None:
        with self._lock:
            if self._key:
                self._bindings.release(self._key)
                self._key = 0

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class SessionControlAuthority:
    def __init__(self, backend: P256SigningBackend) -> None:
        public_key = bytes(backend.public_key_x963)
        _validate_public_key(public_key)
        self._backend = backend
        self._public_key = AuthorityPublicKey.from_x963(
            public_key,
            hardware_backed=backend.hardware_backed,
        )
        self._lock = threading.RLock()

    @classmethod
    def load_or_create(cls) -> "SessionControlAuthority":
        return cls(MacOSKeychainP256Backend.load_or_create())

    @classmethod
    def ephemeral_for_tests(cls) -> "SessionControlAuthority":
        return cls(CryptographyP256Backend.generate())

    @property
    def public_key(self) -> AuthorityPublicKey:
        return self._public_key

    @property
    def key_id(self) -> str:
        return self._public_key.key_id

    def _sign_raw(self, message: bytes) -> bytes:
        with self._lock:
            signature = _der_to_raw(self._backend.sign_der(message))
        public_key = _validate_public_key(self._backend.public_key_x963)
        try:
            public_key.verify(
                _raw_to_der(signature),
                message,
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature as exc:
            raise SessionControlTrustError(
                "authority produced an unverifiable signature"
            ) from exc
        return signature

    def envelope_signature(self, canonical_unsigned_message: bytes) -> dict[str, str]:
        if not isinstance(canonical_unsigned_message, bytes):
            raise SessionControlTrustError("envelope signing input must be bytes")
        return {
            "algorithm": "p256-sha256",
            "key_id": self.key_id,
            "value": _b64url(self._sign_raw(canonical_unsigned_message)),
        }

    def proof_token(self, canonical_proof_without_token: bytes) -> dict[str, str]:
        if not isinstance(canonical_proof_without_token, bytes):
            raise SessionControlTrustError("proof signing input must be bytes")
        header = _canonical_json({
            "alg": "ES256",
            "kid": self.key_id,
            "typ": _PROOF_JWS_TYPE,
        })
        signing_input = (
            _b64url(header) + "." + _b64url(canonical_proof_without_token)
        ).encode("ascii")
        compact = (
            signing_input.decode("ascii")
            + "."
            + _b64url(self._sign_raw(signing_input))
        )
        return {"format": "jws", "value": compact}


class PinnedP256TrustStore:
    def __init__(self, roots: list[AuthorityPublicKey | Mapping[str, Any]]) -> None:
        self._keys: dict[str, ec.EllipticCurvePublicKey] = {}
        self._records: dict[str, AuthorityPublicKey] = {}
        for value in roots:
            if isinstance(value, AuthorityPublicKey):
                record = value
            elif isinstance(value, Mapping) and set(value) == {
                "key_id",
                "algorithm",
                "public_key_format",
                "public_key",
                "hardware_backed",
            }:
                record = AuthorityPublicKey(
                    key_id=str(value["key_id"]),
                    algorithm=str(value["algorithm"]),
                    public_key_format=str(value["public_key_format"]),
                    public_key=str(value["public_key"]),
                    hardware_backed=bool(value["hardware_backed"]),
                )
            else:
                raise SessionControlTrustError("authority trust root is invalid")
            public_key = _validate_public_key(record.x963_bytes())
            if record.key_id in self._keys:
                raise SessionControlTrustError("authority trust root is duplicated")
            self._keys[record.key_id] = public_key
            self._records[record.key_id] = record
        if not self._keys:
            raise SessionControlTrustError("at least one authority trust root is required")

    def _verify_raw(self, key_id: str, message: bytes, signature: bytes) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(
                _raw_to_der(signature),
                message,
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except (InvalidSignature, SessionControlTrustError, ValueError):
            return False

    def verify_envelope_signature(
        self,
        canonical_unsigned_message: bytes,
        signature: Mapping[str, Any],
    ) -> bool:
        try:
            if not isinstance(signature, Mapping) or set(signature) != {
                "algorithm",
                "key_id",
                "value",
            }:
                return False
            if signature["algorithm"] != "p256-sha256":
                return False
            key_id = str(signature["key_id"])
            raw = _b64url_decode(str(signature["value"]), maximum=512)
            return self._verify_raw(key_id, canonical_unsigned_message, raw)
        except (SessionControlTrustError, TypeError, ValueError):
            return False

    def verify_proof_token(
        self,
        canonical_proof_without_token: bytes,
        token: Mapping[str, Any],
    ) -> bool:
        try:
            if not isinstance(token, Mapping) or set(token) != {"format", "value"}:
                return False
            if token["format"] != "jws":
                return False
            compact = str(token["value"])
            parts = compact.split(".")
            if len(parts) != 3:
                return False
            header_bytes = _b64url_decode(parts[0], maximum=2048)
            payload = _b64url_decode(parts[1], maximum=16 * 1024)
            signature = _b64url_decode(parts[2], maximum=512)
            header = json.loads(header_bytes.decode("utf-8"))
            if not isinstance(header, dict) or set(header) != {"alg", "kid", "typ"}:
                return False
            if header.get("alg") != "ES256" or header.get("typ") != _PROOF_JWS_TYPE:
                return False
            if _canonical_json(header) != header_bytes:
                return False
            if payload != canonical_proof_without_token:
                return False
            signing_input = (parts[0] + "." + parts[1]).encode("ascii")
            return self._verify_raw(str(header.get("kid") or ""), signing_input, signature)
        except (
            SessionControlTrustError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            return False
