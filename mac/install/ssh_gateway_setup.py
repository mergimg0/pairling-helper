#!/usr/bin/env python3
"""SPEC-p5 §2.3 — SSH gateway setup helper.

Generates the hardened `authorized_keys` line, computes host-key
fingerprints, and toggles the connectd SSH-gateway launchd env. The
forced-options line is the security surface the §5 review closes: it must
confine the Pairling key to forwarding the single SSH-gateway port and
nothing else. This lives in Python (not shell) so it can be unit-tested.
"""

from __future__ import annotations

import base64
import hashlib

# The one loopback target the tunnel may open: connectd's SSH gateway.
# NOT the daemon (7773) and NOT connectd's status server (7774).
SSH_GATEWAY_TARGET = "127.0.0.1:7775"

# restrict is the modern umbrella (disables pty, agent/X11/port forwarding,
# then we re-enable ONLY local port-forwarding to the gateway). command=""
# forces an empty command so the key can never open a shell even if the
# client requests one. The explicit no-* options are belt-and-suspenders
# for older sshd that predates `restrict`.
_FORCED_OPTIONS = (
    "restrict",
    'command=""',
    "port-forwarding",
    f'permitopen="{SSH_GATEWAY_TARGET}"',
    "no-pty",
    "no-agent-forwarding",
    "no-X11-forwarding",
    "no-user-rc",
)


def _validate_public_key(public_key: str) -> str:
    key = (public_key or "").strip()
    if not key or "\n" in key or "\r" in key:
        raise ValueError("public key must be a single non-empty line")
    parts = key.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-")):
        raise ValueError("not an OpenSSH public key line")
    return key


def authorized_keys_line(public_key: str) -> str:
    """Return the full authorized_keys line: forced options + the public key.

    The key is confined to opening a local forward to the SSH gateway port
    and nothing else — no shell, no pty, no agent, no X11.
    """
    key = _validate_public_key(public_key)
    return ",".join(_FORCED_OPTIONS) + " " + key


def host_key_fingerprint(host_key: str) -> str:
    """SHA256 fingerprint of an OpenSSH public host key, in `ssh-keygen -lf`
    shape (`SHA256:<base64-no-padding>`)."""
    parts = (host_key or "").strip().split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-")):
        raise ValueError("not an OpenSSH public key line")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except Exception as exc:  # noqa: BLE001 - re-raise as ValueError for callers
        raise ValueError("public key body is not valid base64") from exc
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _read_first_host_key() -> str | None:
    """The Mac's ed25519 host public key, preferred; falls back to ECDSA.
    Used to show the operator the fingerprint the phone will pin."""
    for name in ("ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub"):
        path = f"/etc/ssh/{name}"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                line = fh.read().strip()
                if line:
                    return line
        except OSError:
            continue
    return None


def main(argv: list[str]) -> int:
    # SPEC-p5 §6: --ssh-print-key re-displays the public key line and the
    # host fingerprint without re-running setup. `public-key <file>` prints
    # the hardened authorized_keys line for a given public key.
    if not argv:
        print("usage: ssh_gateway_setup.py {print-authorized-keys <pubkey-file> | host-fingerprint}", flush=True)
        return 2
    cmd = argv[0]
    if cmd == "print-authorized-keys":
        if len(argv) < 2:
            print("error: public key file required", flush=True)
            return 2
        with open(argv[1], "r", encoding="utf-8") as fh:
            pub = fh.read().strip()
        try:
            print(authorized_keys_line(pub), flush=True)
        except ValueError as exc:
            print(f"error: {exc}", flush=True)
            return 1
        return 0
    if cmd == "host-fingerprint":
        host_key = _read_first_host_key()
        if host_key is None:
            print("error: no OpenSSH host key found under /etc/ssh", flush=True)
            return 1
        print(host_key_fingerprint(host_key), flush=True)
        return 0
    print(f"error: unknown command {cmd!r}", flush=True)
    return 2


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
