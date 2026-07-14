#!/usr/bin/env python3
"""Scan, extract, and verify a prebuilt Pairling Python archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path, PurePosixPath


UNSAFE_MODE_BITS = 0o7022
MAX_MEMBERS = 200_000
MAX_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
FORBIDDEN_PAX_PREFIXES = (
    "GNU.sparse",
    "LIBARCHIVE.xattr",
    "RHT.security",
    "SCHILY.acl",
    "SCHILY.xattr",
)
INPUTS_FILENAME = "python-runtime-inputs.json"
BUILD_METADATA_FILENAME = "PAIRLING-BUILD.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    pass


def sha256_stream(handle) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def safe_member_path(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or name.startswith("/"):
        raise VerificationError(f"unsafe archive path: {name!r}")
    path = PurePosixPath(name)
    parts = tuple(part for part in path.parts if part != "")
    if not parts or parts[0] != "python" or any(part in (".", "..") for part in parts):
        raise VerificationError(f"archive entry is outside python/: {name!r}")
    if "__pycache__" in parts or parts[-1].endswith(".pyc"):
        raise VerificationError(f"archive contains forbidden Python bytecode: {name}")
    return parts


def validate_mode(member: tarfile.TarInfo, relative: str) -> int:
    mode = member.mode & 0o7777
    if mode & UNSAFE_MODE_BITS:
        raise VerificationError(f"archive entry has unsafe permissions: {relative}")
    if not mode & stat.S_IRUSR:
        raise VerificationError(f"archive entry is not owner-readable: {relative}")
    if member.isdir() and not mode & stat.S_IXUSR:
        raise VerificationError(f"archive directory is not owner-searchable: {relative}")
    if member.isfile() and mode & 0o111 and not mode & stat.S_IXUSR:
        raise VerificationError(f"archive executable is not owner-executable: {relative}")
    return mode


def scan_archive(archive: tarfile.TarFile) -> list[tuple[tarfile.TarInfo, tuple[str, ...], int]]:
    entries: list[tuple[tarfile.TarInfo, tuple[str, ...], int]] = []
    seen: set[str] = set()
    total_bytes = 0
    for member in archive:
        if len(entries) >= MAX_MEMBERS:
            raise VerificationError("archive contains too many entries")
        parts = safe_member_path(member.name)
        relative = "/".join(parts)
        if relative in seen:
            raise VerificationError(f"archive contains a duplicate path: {relative}")
        seen.add(relative)
        if not (member.isdir() or member.isfile()):
            raise VerificationError(f"archive entry is not a regular file or directory: {relative}")
        for key in member.pax_headers:
            if key.startswith(FORBIDDEN_PAX_PREFIXES):
                raise VerificationError(f"archive entry has forbidden metadata {key}: {relative}")
        total_bytes += member.size
        if total_bytes > MAX_EXPANDED_BYTES:
            raise VerificationError("archive expands beyond the Pairling package limit")
        entries.append((member, parts, validate_mode(member, relative)))
    if not entries or "python/bin/python3" not in seen:
        raise VerificationError("archive is missing python/bin/python3")
    return entries


def prepare_destination(destination: Path) -> None:
    if destination.is_symlink():
        raise VerificationError(f"destination must not be a symlink: {destination}")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = destination.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise VerificationError(f"destination is not a same-user directory: {destination}")
    if any(destination.iterdir()):
        raise VerificationError(f"destination must be empty: {destination}")
    destination.chmod(0o700)


def extract_entries(
    archive: tarfile.TarFile,
    destination: Path,
    entries: list[tuple[tarfile.TarInfo, tuple[str, ...], int]],
) -> Path:
    directory_modes: list[tuple[Path, int]] = []
    for member, parts, mode in sorted(entries, key=lambda item: (len(item[1]), item[1])):
        target = destination.joinpath(*parts)
        if member.isdir():
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory_modes.append((target, mode))
            continue
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise VerificationError(f"cannot read archive entry: {'/'.join(parts)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, mode)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
            source.close()
    for path, mode in sorted(directory_modes, key=lambda item: len(item[0].parts), reverse=True):
        path.chmod(mode)
    return destination / "python"


def command_output(command: list[str], label: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip() or f"exit {result.returncode}"
        raise VerificationError(f"{label} failed: {detail}")
    return result.stdout + result.stderr


def developer_id_requirement(team_id: str) -> str:
    return (
        "anchor apple generic and "
        f'certificate leaf[subject.OU] = "{team_id}" and '
        "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )


def codesign_fields(path: Path) -> dict[str, str]:
    output = command_output(["/usr/bin/codesign", "-dvv", str(path)], f"identity inspection for {path}")
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    return fields


def is_macho(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(4) in MACHO_MAGICS


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    paths = [root, *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())]
    for path in paths:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if stat.S_ISDIR(metadata.st_mode):
            record = f"{relative}\0D\0{mode}\n"
        elif stat.S_ISREG(metadata.st_mode):
            file_digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    file_digest.update(chunk)
            record = f"{relative}\0F\0{mode}\0{file_digest.hexdigest()}\n"
        else:
            raise VerificationError(f"unsupported entry in Python tree: {relative}")
        digest.update(record.encode("utf-8"))
    return digest.hexdigest()


def verify_python_tree(root: Path, arch: str, team_id: str, identifier: str) -> tuple[Path, int]:
    python = root / "bin" / "python3"
    if python.is_symlink() or not python.is_file() or not os.access(python, os.X_OK):
        raise VerificationError("python/bin/python3 is not a real executable")
    expected_arch = "x86_64" if arch == "x64" else "arm64"
    macho_paths = [path for path in sorted(root.rglob("*")) if path.is_file() and is_macho(path)]
    if python not in macho_paths:
        raise VerificationError("python/bin/python3 is not a Mach-O executable")
    for path in macho_paths:
        command_output(
            ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)],
            f"code signature verification for {path}",
        )
        if team_id != "-":
            command_output(
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--strict",
                    "--verbose=2",
                    f"-R={developer_id_requirement(team_id)}",
                    str(path),
                ],
                f"Developer ID certificate verification for {path}",
            )
        fields = codesign_fields(path)
        if team_id != "-" and fields.get("TeamIdentifier") != team_id:
            raise VerificationError(f"TeamIdentifier mismatch for {path}")
        architectures = command_output(
            ["/usr/bin/lipo", "-archs", str(path)],
            f"architecture inspection for {path}",
        ).strip().split()
        architecture_set = set(architectures)
        if (
            expected_arch not in architecture_set
            or not architecture_set.issubset({"arm64", "x86_64"})
            or (path == python and architectures != [expected_arch])
        ):
            raise VerificationError(f"architecture mismatch for {path}: {architectures}")
    if codesign_fields(python).get("Identifier") != identifier:
        raise VerificationError(f"python identifier is not {identifier}")
    return python, len(macho_paths)


def strict_json(path: Path, label: str) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} must be a real file: {path}")
    raw = path.read_bytes()
    seen_duplicate = False

    def object_hook(pairs):
        nonlocal seen_duplicate
        result = {}
        for key, value in pairs:
            if key in result:
                seen_duplicate = True
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=object_hook)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not valid JSON: {exc}") from exc
    if seen_duplicate or not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object without duplicate keys")
    return value, raw


def expected_build_metadata(inputs_path: Path, arch: str) -> dict:
    inputs, raw = strict_json(inputs_path, "Python runtime inputs")
    if set(inputs) != {"schema_version", "python_version", "python_build_standalone", "wheels"}:
        raise VerificationError("Python runtime inputs have unexpected top-level keys")
    if inputs.get("schema_version") != 1:
        raise VerificationError("Python runtime inputs use an unsupported schema")
    pbs = inputs.get("python_build_standalone")
    wheels = inputs.get("wheels")
    if (
        not isinstance(inputs.get("python_version"), str)
        or not isinstance(pbs, dict)
        or set(pbs) != {"tag", "assets"}
        or not isinstance(pbs.get("assets"), dict)
        or set(pbs["assets"]) != {"arm64", "x64"}
        or not isinstance(wheels, dict)
        or set(wheels) != {"cryptography", "cffi", "pycparser"}
    ):
        raise VerificationError("Python runtime inputs are incomplete")
    asset = pbs["assets"].get(arch)
    if not isinstance(asset, dict) or set(asset) != {"filename", "sha256"}:
        raise VerificationError(f"Python build asset inputs are incomplete for {arch}")
    selected_wheels = {}
    for name, row in sorted(wheels.items()):
        if not isinstance(row, dict) or set(row) != {"version", "arm64", "x64"}:
            raise VerificationError(f"Python wheel inputs are incomplete for {name}")
        selected = row.get(arch)
        if (
            not isinstance(row.get("version"), str)
            or not isinstance(selected, dict)
            or set(selected) != {"filename", "sha256"}
        ):
            raise VerificationError(f"Python wheel asset inputs are incomplete for {name}.{arch}")
        selected_wheels[name] = {"version": row["version"], **selected}
    digests = [asset.get("sha256"), *(row.get("sha256") for row in selected_wheels.values())]
    if any(not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) for digest in digests):
        raise VerificationError("Python runtime inputs contain an invalid digest")
    return {
        "schema_version": 1,
        "architecture": arch,
        "inputs_sha256": hashlib.sha256(raw).hexdigest(),
        "python_version": inputs["python_version"],
        "python_build_standalone": {"tag": pbs["tag"], **asset},
        "wheels": selected_wheels,
    }


def verify_build_metadata(root: Path, arch: str, inputs_path: Path) -> dict:
    actual, _ = strict_json(root / BUILD_METADATA_FILENAME, "vendored Python build metadata")
    expected = expected_build_metadata(inputs_path, arch)
    if actual != expected:
        raise VerificationError("vendored Python build metadata does not match pinned runtime inputs")
    return expected


def smoke_python(python: Path, arch: str, build_metadata: dict) -> None:
    smoke_code = (
        "import cffi,cryptography,hashlib,hmac,json,platform,plistlib,pty,pycparser,"
        "select,socket,sqlite3,ssl,struct,subprocess,termios,fcntl,urllib.request;"
        "actual='arm64' if platform.machine() in ('arm64','aarch64') else "
        "'x64' if platform.machine() == 'x86_64' else platform.machine();"
        "print(json.dumps({'architecture':actual,'python_version':platform.python_version(),"
        "'wheels':{'cffi':cffi.__version__,'cryptography':cryptography.__version__,"
        "'pycparser':pycparser.__version__}},sort_keys=True))"
    )
    probe = [
        str(python),
        "-I",
        "-B",
        "-c",
        smoke_code,
    ]
    machine = platform.machine().lower()
    if arch == "x64" and machine == "arm64":
        probe = ["/usr/bin/arch", "-x86_64", *probe]
    elif arch == "arm64" and machine not in ("arm64", "aarch64"):
        raise VerificationError("cannot smoke-test an arm64 Python on this host")
    output = command_output(probe, "vendored Python runtime smoke test")
    try:
        result = json.loads(output.strip())
    except json.JSONDecodeError as exc:
        raise VerificationError(f"vendored Python returned invalid smoke output: {exc}") from exc
    expected = {
        "architecture": arch,
        "python_version": build_metadata["python_version"],
        "wheels": {
            name: build_metadata["wheels"][name]["version"]
            for name in ("cffi", "cryptography", "pycparser")
        },
    }
    if result != expected:
        raise VerificationError(f"vendored Python smoke test failed: {result!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--expected-sha256", default="")
    parser.add_argument("--arch", required=True, choices=("arm64", "x64"))
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--identifier", default="dev.pairling.python")
    parser.add_argument(
        "--inputs",
        type=Path,
        default=Path(__file__).resolve().with_name(INPUTS_FILENAME),
    )
    args = parser.parse_args()

    cleanup_destination = False
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(args.archive, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise VerificationError("prebuilt Python archive is not a regular file")
            with os.fdopen(os.dup(descriptor), "rb") as digest_handle:
                digest = sha256_stream(digest_handle)
            if args.expected_sha256 and digest != args.expected_sha256.lower():
                raise VerificationError("prebuilt Python archive sha256 does not match release evidence")
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(os.dup(descriptor), "rb") as archive_handle:
                with tarfile.open(fileobj=archive_handle, mode="r:gz") as archive:
                    entries = scan_archive(archive)
                prepare_destination(args.destination)
                cleanup_destination = True
                archive_handle.seek(0)
                with tarfile.open(fileobj=archive_handle, mode="r:gz") as archive:
                    python_root = extract_entries(archive, args.destination, entries)
        finally:
            os.close(descriptor)

        python, macho_count = verify_python_tree(
            python_root,
            args.arch,
            args.team_id,
            args.identifier,
        )
        build_metadata = verify_build_metadata(python_root, args.arch, args.inputs)
        smoke_python(python, args.arch, build_metadata)
    except Exception:
        if cleanup_destination:
            shutil.rmtree(args.destination, ignore_errors=True)
        raise
    cleanup_destination = False
    print(json.dumps({
        "ok": True,
        "archive_sha256": digest,
        "architecture": args.arch,
        "macho_count": macho_count,
        "python": str(python),
        "inputs_sha256": build_metadata["inputs_sha256"],
        "tree_sha256": tree_sha256(python_root),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, tarfile.TarError, VerificationError) as exc:
        print(f"prebuilt Python verification failed: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
