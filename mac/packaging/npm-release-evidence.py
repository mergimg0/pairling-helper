#!/usr/bin/env python3
"""Create and verify the evidence that binds Pairling npm release assets."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


SCHEMA_VERSION = 6
PRODUCT_REPOSITORY_SHA256 = "59d2705328edc11607151f8602e184148bb2f90dd12a55ace53f96ccaf1da0cf"
EXPECTED_TEAM_ID = "965AVD34A3"
ARCHES = ("arm64", "x64")
MIRROR_SOURCE_EXCLUDED_ROOTS = {".git", "dist"}
MIRROR_SOURCE_EVIDENCE = "RELEASE-BINARIES.json"
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
SHA = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
SUBMISSION_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class EvidenceError(RuntimeError):
    pass


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular_file(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"{label} must be a real file: {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"{label} must be a real file: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def sha256_regular_file(path: Path, label: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"{label} must be a real file: {path}: {exc}") from exc
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"{label} must be a real file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def read_json(path: Path) -> tuple[dict, bytes]:
    raw = read_regular_file(path, "evidence")
    try:
        value = json.loads(raw, object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot parse release evidence: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError("release evidence must be a JSON object")
    return value, raw


def require_keys(value: dict, expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise EvidenceError(f"{label} keys do not match schema; missing={missing}, unknown={unknown}")


def sha256_file(path: Path) -> str:
    return sha256_regular_file(path, "release asset")

def tree_sha256(path: Path, label: str) -> str:
    path = Path(path)
    try:
        root_metadata = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"{label} is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceError(f"{label} must be a real directory: {path}")
    digest = hashlib.sha256()
    for entry in [path, *sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix())]:
        metadata = entry.lstat()
        relative = "." if entry == path else entry.relative_to(path).as_posix()
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if stat.S_ISDIR(metadata.st_mode):
            record = f"{relative}\0D\0{mode}\n"
        elif stat.S_ISREG(metadata.st_mode):
            record = f"{relative}\0F\0{mode}\0{sha256_regular_file(entry, label)}\n"
        else:
            raise EvidenceError(f"{label} contains an unsupported entry: {relative}")
        digest.update(record.encode("utf-8"))
    return digest.hexdigest()


def mirror_source_sha256(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise EvidenceError(f"mirror source root must be a real directory: {root}")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if relative.parts[0] in MIRROR_SOURCE_EXCLUDED_ROOTS:
            continue
        if relative.as_posix() == MIRROR_SOURCE_EVIDENCE:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"mirror source contains a symlink: {relative.as_posix()}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"mirror source contains an unsupported entry: {relative.as_posix()}")
        executable = "x" if metadata.st_mode & 0o111 else "-"
        file_sha256 = sha256_regular_file(path, "mirror source file")
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(executable.encode("ascii"))
        digest.update(b"\0")
        digest.update(file_sha256.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def validate_build_info(value: object, *, version: str, revision: str, arch: str) -> None:
    if not isinstance(value, dict):
        raise EvidenceError(f"connectd {arch} build_info is not an object")
    require_keys(
        value,
        {"schema_version", "version", "source_revision", "source_dirty"},
        f"connectd {arch} build_info",
    )
    if value != {
        "schema_version": 1,
        "version": version,
        "source_revision": revision,
        "source_dirty": False,
    }:
        raise EvidenceError(f"connectd {arch} build_info does not prove the clean product release")


def validate_evidence(value: dict, *, version: str, source_revision: str) -> None:
    require_keys(
        value,
        {
            "schema_version",
            "tag",
            "version",
            "source_revision",
            "source_dirty",
            "product_repository_sha256",
            "mirror_source_sha256",
            "notarization_receipts_sha256",
            "binaries",
            "python",
            "automation",
        },
        "release evidence",
    )
    if value.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"release evidence schema must be {SCHEMA_VERSION}")
    if not SEMVER.fullmatch(version) or value.get("version") != version or value.get("tag") != f"v{version}":
        raise EvidenceError("release evidence version or tag does not match the requested release")
    if not REVISION.fullmatch(source_revision) or value.get("source_revision") != source_revision:
        raise EvidenceError("release evidence source revision does not match the requested release")
    if value.get("source_dirty") is not False:
        raise EvidenceError("release evidence must prove source_dirty=false")
    if value.get("product_repository_sha256") != PRODUCT_REPOSITORY_SHA256:
        raise EvidenceError("release evidence product repository is not allowlisted")
    if not isinstance(value.get("mirror_source_sha256"), str) or not SHA.fullmatch(value["mirror_source_sha256"]):
        raise EvidenceError("release evidence mirror source digest is invalid")
    if (
        not isinstance(value.get("notarization_receipts_sha256"), str)
        or not SHA.fullmatch(value["notarization_receipts_sha256"])
    ):
        raise EvidenceError("release evidence notarization receipt digest is invalid")
    for section in ("binaries", "python", "automation"):
        rows = value.get(section)
        if not isinstance(rows, dict):
            raise EvidenceError(f"release evidence {section} is not an object")
        require_keys(rows, set(ARCHES), f"release evidence {section}")
        for arch in ARCHES:
            row = rows[arch]
            expected_keys = {"sha256", "team_id", "identifier", "architecture", "notarization"}
            if section == "binaries":
                expected_keys.add("build_info")
            elif section == "automation":
                expected_keys.update({"tree_sha256", "notarization_tree_sha256"})
            if not isinstance(row, dict):
                raise EvidenceError(f"release evidence {section}.{arch} is not an object")
            require_keys(row, expected_keys, f"release evidence {section}.{arch}")
            if not isinstance(row.get("sha256"), str) or not SHA.fullmatch(row["sha256"]):
                raise EvidenceError(f"release evidence {section}.{arch} has an invalid sha256")
            if section == "automation":
                for field in ("tree_sha256", "notarization_tree_sha256"):
                    if not isinstance(row.get(field), str) or not SHA.fullmatch(row[field]):
                        raise EvidenceError(f"release evidence automation.{arch} has an invalid {field}")
            if row.get("architecture") != arch:
                raise EvidenceError(f"release evidence {section}.{arch} architecture does not match")
            expected_identifier = {
                "binaries": "dev.pairling.connectd",
                "python": "dev.pairling.python",
                "automation": "dev.pairling.automation",
            }[section]
            if row.get("identifier") != expected_identifier or row.get("team_id") != EXPECTED_TEAM_ID:
                raise EvidenceError(f"release evidence {section}.{arch} code identity is invalid")
            notarization = row.get("notarization")
            if not isinstance(notarization, dict):
                raise EvidenceError(f"release evidence {section}.{arch} notarization is invalid")
            require_keys(
                notarization,
                {"status", "submission_id", "subject_kind", "subject_sha256", "submitted_sha256"},
                f"release evidence {section}.{arch} notarization",
            )
            expected_kind = "file-sha256" if section == "binaries" else "tree-sha256"
            if (
                notarization.get("status") != "Accepted"
                or notarization.get("subject_kind") != expected_kind
                or not isinstance(notarization.get("submission_id"), str)
                or not SUBMISSION_ID.fullmatch(notarization["submission_id"])
                or not isinstance(notarization.get("subject_sha256"), str)
                or not SHA.fullmatch(notarization["subject_sha256"])
                or not isinstance(notarization.get("submitted_sha256"), str)
                or not SHA.fullmatch(notarization["submitted_sha256"])
            ):
                raise EvidenceError(f"release evidence {section}.{arch} notarization is invalid")
            if section == "binaries" and notarization["subject_sha256"] != row["sha256"]:
                raise EvidenceError(f"release evidence binaries.{arch} notarization does not bind the binary")
            if section == "automation" and notarization["subject_sha256"] != row["notarization_tree_sha256"]:
                raise EvidenceError(f"release evidence automation.{arch} notarization does not bind its submitted app tree")
            if section == "binaries":
                validate_build_info(row.get("build_info"), version=version, revision=source_revision, arch=arch)


def command_output(command: list[str], label: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip() or f"exit {result.returncode}"
        raise EvidenceError(f"{label} failed: {detail}")
    return result.stdout + result.stderr


def code_fields(path: Path) -> dict[str, str]:
    output = command_output(["/usr/bin/codesign", "-dvv", str(path)], f"identity inspection for {path}")
    fields = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    return fields


def developer_id_requirement(team_id: str) -> str:
    return (
        "anchor apple generic and "
        f'certificate leaf[subject.OU] = "{team_id}" and '
        "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )


def connectd_build_info(path: Path, arch: str, team_id: str) -> dict:
    command_output(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)],
        f"connectd {arch} code signature verification",
    )
    command_output(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            "--verbose=2",
            f"-R={developer_id_requirement(team_id)}",
            str(path),
        ],
        f"connectd {arch} Developer ID certificate verification",
    )
    fields = code_fields(path)
    if fields.get("Identifier") != "dev.pairling.connectd" or fields.get("TeamIdentifier") != team_id:
        raise EvidenceError(f"connectd {arch} code identity does not match release policy")
    expected_mach_arch = "x86_64" if arch == "x64" else "arm64"
    actual_arches = command_output(
        ["/usr/bin/lipo", "-archs", str(path)],
        f"connectd {arch} architecture inspection",
    ).strip().split()
    if actual_arches != [expected_mach_arch]:
        raise EvidenceError(f"connectd {arch} has wrong architectures: {actual_arches}")
    command = [str(path), "--build-info-json"]
    if arch == "x64" and platform.machine().lower() == "arm64":
        command = ["/usr/bin/arch", "-x86_64", *command]
    output = command_output(command, f"connectd {arch} build-info smoke test")
    try:
        value = json.loads(output, object_pairs_hook=strict_object)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"connectd {arch} returned invalid build info: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"connectd {arch} build info is not an object")
    return value


def verify_python_archive(path: Path, arch: str, team_id: str, mirror_source_root: Path) -> dict:
    verifier = Path(__file__).resolve().with_name("verify-prebuilt-python-archive.py")
    inputs = mirror_source_root / "mac" / "packaging" / "python-runtime-inputs.json"
    with tempfile.TemporaryDirectory(prefix=f"pairling-evidence-python-{arch}-") as tmp:
        output = command_output(
            [
                os.sys.executable,
                str(verifier),
                "--archive",
                str(path),
                "--destination",
                tmp,
                "--arch",
                arch,
                "--team-id",
                team_id,
                "--identifier",
                "dev.pairling.python",
                "--inputs",
                str(inputs),
            ],
            f"Python {arch} release archive verification",
        )
    try:
        result = json.loads(output, object_pairs_hook=strict_object)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"Python {arch} verifier returned invalid JSON: {exc}") from exc
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise EvidenceError(f"Python {arch} verifier did not return success")
    return result

def automation_helper_lifecycle_module():
    module_path = Path(__file__).resolve().parents[1] / "install" / "automation_helper_lifecycle.py"
    spec = importlib.util.spec_from_file_location("pairling_automation_helper_lifecycle", module_path)
    if spec is None or spec.loader is None:
        raise EvidenceError("automation helper lifecycle verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise EvidenceError("automation helper lifecycle verifier could not load") from exc
    return module


def verify_automation_archive(path: Path, arch: str) -> dict:
    archive_sha256 = sha256_file(path)
    lifecycle = automation_helper_lifecycle_module()
    expected_arch = "x86_64" if arch == "x64" else arch
    try:
        with tempfile.TemporaryDirectory(prefix=f"pairling-evidence-automation-{arch}-") as tmp:
            app = lifecycle.extract_bundle_archive(
                path,
                Path(tmp) / "extracted",
                expected_sha256=archive_sha256,
            )
            lifecycle.verify_signed_bundle(app, architecture=expected_arch)
            return {
                "sha256": archive_sha256,
                "tree_sha256": tree_sha256(app, "automation helper app bundle"),
            }
    except Exception as exc:
        raise EvidenceError(f"automation helper {arch} archive verification failed") from exc

def load_notarization_receipts(path: Path, *, version: str, revision: str) -> tuple[dict, bytes]:
    raw = read_regular_file(path, "notarization receipt set")
    try:
        value = json.loads(raw, object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot parse notarization receipt set: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError("notarization receipt set must be an object")
    require_keys(value, {"schema_version", "version", "source_revision", "assets"}, "notarization receipt set")
    if value["schema_version"] != 1 or value["version"] != version or value["source_revision"] != revision:
        raise EvidenceError("notarization receipt set does not match this release")
    expected_labels = {
        "pairling-connectd-arm64",
        "pairling-connectd-x64",
        "pairling-python-arm64",
        "pairling-python-x64",
        "pairling-automation-arm64",
        "pairling-automation-x64",
    }
    assets = value.get("assets")
    if not isinstance(assets, dict) or set(assets) != expected_labels:
        raise EvidenceError("notarization receipt set does not contain the six exact release assets")
    for label, row in assets.items():
        if not isinstance(row, dict):
            raise EvidenceError(f"notarization receipt is not an object: {label}")
        require_keys(
            row,
            {"status", "submission_id", "subject_kind", "subject_sha256", "submitted_sha256"},
            f"notarization receipt {label}",
        )
        if (
            row.get("status") != "Accepted"
            or not isinstance(row.get("submission_id"), str)
            or not SUBMISSION_ID.fullmatch(row["submission_id"])
            or not isinstance(row.get("subject_sha256"), str)
            or not SHA.fullmatch(row["subject_sha256"])
            or not isinstance(row.get("submitted_sha256"), str)
            or not SHA.fullmatch(row["submitted_sha256"])
        ):
            raise EvidenceError(f"notarization receipt is invalid: {label}")
        expected_kind = "file-sha256" if "connectd" in label else "tree-sha256"
        if row.get("subject_kind") != expected_kind:
            raise EvidenceError(f"notarization receipt subject kind is invalid: {label}")
    return assets, raw


def artifact_paths(args) -> dict[str, dict[str, Path]]:
    return {
        "binaries": {
            "arm64": args.connectd_arm64,
            "x64": args.connectd_x64,
        },
        "python": {
            "arm64": args.python_arm64,
            "x64": args.python_x64,
        },
        "automation": {
            "arm64": args.automation_arm64,
            "x64": args.automation_x64,
        },
    }


def verify_command(args) -> dict:
    value, raw = read_json(args.evidence)
    source_revision = args.source_revision or value.get("source_revision")
    if not isinstance(source_revision, str):
        raise EvidenceError("release evidence source revision is missing")
    validate_evidence(value, version=args.version, source_revision=source_revision)
    if mirror_source_sha256(args.mirror_source_root) != value["mirror_source_sha256"]:
        raise EvidenceError("mirror source sha256 does not match release evidence")
    if args.notarization_receipts is not None:
        receipt_rows, receipt_raw = load_notarization_receipts(
            args.notarization_receipts,
            version=args.version,
            revision=source_revision,
        )
        if hashlib.sha256(receipt_raw).hexdigest() != value["notarization_receipts_sha256"]:
            raise EvidenceError("notarization receipt set sha256 does not match release evidence")
        for section, label_prefix in (
            ("binaries", "pairling-connectd"),
            ("python", "pairling-python"),
            ("automation", "pairling-automation"),
        ):
            for arch in ARCHES:
                if value[section][arch]["notarization"] != receipt_rows[f"{label_prefix}-{arch}"]:
                    raise EvidenceError(f"{section}.{arch} notarization does not match retained receipts")
    paths = artifact_paths(args)
    for section, rows in paths.items():
        for arch, path in rows.items():
            if path is None:
                continue
            if sha256_file(path) != value[section][arch]["sha256"]:
                raise EvidenceError(f"{section}.{arch} sha256 does not match release evidence")
    return {
        "ok": True,
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "source_revision": value["source_revision"],
        "version": value["version"],
        "mirror_source_sha256": value["mirror_source_sha256"],
        "notarization_receipts_sha256": value["notarization_receipts_sha256"],
        "asset_sha256": {
            section: {arch: value[section][arch]["sha256"] for arch in ARCHES}
            for section in ("binaries", "python", "automation")
        },
    }


def create_command(args) -> dict:
    if args.source_dirty:
        raise EvidenceError("release evidence cannot be created from dirty source")
    if not SEMVER.fullmatch(args.version) or not REVISION.fullmatch(args.source_revision):
        raise EvidenceError("release version or source revision is invalid")
    if args.team_id != EXPECTED_TEAM_ID:
        raise EvidenceError("release evidence Team ID is not allowlisted")
    paths = artifact_paths(args)
    if any(path is None for rows in paths.values() for path in rows.values()):
        raise EvidenceError("all six release assets are required to create evidence")
    receipts, receipt_raw = load_notarization_receipts(
        args.notarization_receipts,
        version=args.version,
        revision=args.source_revision,
    )
    build_info = {
        arch: connectd_build_info(paths["binaries"][arch], arch, args.team_id)
        for arch in ARCHES
    }
    python_verification = {}
    automation_verification = {}
    for arch in ARCHES:
        validate_build_info(build_info[arch], version=args.version, revision=args.source_revision, arch=arch)
        python_verification[arch] = verify_python_archive(
            paths["python"][arch], arch, args.team_id, args.mirror_source_root
        )
        automation_verification[arch] = verify_automation_archive(paths["automation"][arch], arch)
        binary_receipt = receipts[f"pairling-connectd-{arch}"]
        if binary_receipt["subject_sha256"] != sha256_file(paths["binaries"][arch]):
            raise EvidenceError(f"connectd {arch} notarization receipt does not bind the selected binary")
        python_receipt = receipts[f"pairling-python-{arch}"]
        if python_receipt["subject_sha256"] != python_verification[arch].get("tree_sha256"):
            raise EvidenceError(f"Python {arch} notarization receipt does not bind the verified archive tree")
    value = {
        "schema_version": SCHEMA_VERSION,
        "tag": f"v{args.version}",
        "version": args.version,
        "source_revision": args.source_revision,
        "source_dirty": False,
        "product_repository_sha256": PRODUCT_REPOSITORY_SHA256,
        "mirror_source_sha256": mirror_source_sha256(args.mirror_source_root),
        "notarization_receipts_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "binaries": {
            arch: {
                "sha256": sha256_file(paths["binaries"][arch]),
                "team_id": args.team_id,
                "identifier": "dev.pairling.connectd",
                "architecture": arch,
                "build_info": build_info[arch],
                "notarization": receipts[f"pairling-connectd-{arch}"],
            }
            for arch in ARCHES
        },
        "python": {
            arch: {
                "sha256": sha256_file(paths["python"][arch]),
                "team_id": args.team_id,
                "identifier": "dev.pairling.python",
                "architecture": arch,
                "notarization": receipts[f"pairling-python-{arch}"],
            }
            for arch in ARCHES
        },
        "automation": {
            arch: {
                "sha256": automation_verification[arch]["sha256"],
                "tree_sha256": automation_verification[arch]["tree_sha256"],
                "notarization_tree_sha256": receipts[f"pairling-automation-{arch}"]["subject_sha256"],
                "team_id": args.team_id,
                "identifier": "dev.pairling.automation",
                "architecture": arch,
                "notarization": receipts[f"pairling-automation-{arch}"],
            }
            for arch in ARCHES
        },
    }
    validate_evidence(value, version=args.version, source_revision=args.source_revision)
    if args.output.is_symlink():
        raise EvidenceError(f"evidence output must not be a symlink: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, args.output)
    return verify_command(argparse.Namespace(
        evidence=args.output,
        version=args.version,
        source_revision=args.source_revision,
        connectd_arm64=paths["binaries"]["arm64"],
        connectd_x64=paths["binaries"]["x64"],
        python_arm64=paths["python"]["arm64"],
        python_x64=paths["python"]["x64"],
        automation_arm64=paths["automation"]["arm64"],
        automation_x64=paths["automation"]["x64"],
        mirror_source_root=args.mirror_source_root,
        notarization_receipts=args.notarization_receipts,
    ))


def add_artifact_arguments(parser) -> None:
    parser.add_argument("--connectd-arm64", type=Path)
    parser.add_argument("--connectd-x64", type=Path)
    parser.add_argument("--python-arm64", type=Path)
    parser.add_argument("--python-x64", type=Path)
    parser.add_argument("--automation-arm64", type=Path)
    parser.add_argument("--automation-x64", type=Path)


def add_mirror_source_argument(parser) -> None:
    parser.add_argument("--mirror-source-root", required=True, type=Path)


def add_notarization_receipts_argument(parser, *, required: bool) -> None:
    parser.add_argument("--notarization-receipts", required=required, type=Path)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--evidence", required=True, type=Path)
    verify.add_argument("--version", required=True)
    verify.add_argument("--source-revision", default="")
    add_artifact_arguments(verify)
    add_mirror_source_argument(verify)
    add_notarization_receipts_argument(verify, required=False)
    create = subparsers.add_parser("create")
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--version", required=True)
    create.add_argument("--source-revision", required=True)
    create.add_argument("--source-dirty", action="store_true")
    create.add_argument("--team-id", required=True)
    add_artifact_arguments(create)
    add_mirror_source_argument(create)
    add_notarization_receipts_argument(create, required=True)
    args = parser.parse_args()
    result = verify_command(args) if args.command == "verify" else create_command(args)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError) as exc:
        print(f"npm release evidence verification failed: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
