#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Pairling PSK pairing import dependencies.")
    parser.add_argument("companiond_path")
    parser.add_argument("--label", default="dependency check")
    args = parser.parse_args()

    companiond = Path(args.companiond_path).resolve()
    sys.path.insert(0, str(companiond))
    os.environ.pop("PAIRLING_PSK_REQUIRED", None)

    try:
        import cryptography  # noqa: F401
        import pairling_psk  # noqa: F401
        import pairling_pairing  # noqa: F401
    except Exception as exc:
        print(
            "PSK pairing dependency check failed during "
            f"{args.label}: companiond_path={companiond}; Python must import "
            "cryptography, pairling_psk, and pairling_pairing while "
            "PAIRLING_PSK_REQUIRED is default-on; otherwise PSK pairing is "
            "unavailable/fail-closed and daemon liveness alone is insufficient "
            "(pairing endpoints may return pairing_unavailable). "
            f"Cause: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
