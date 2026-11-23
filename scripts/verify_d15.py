"""Read-only standard-library verifier, distributed verbatim as D15 verify.py."""

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

VERSION = "d15-delivery@1.0.0"
BASE = "9110dae9674ddedb75f08e538466df68ec9ff6e4b38eac5720f64fcd8ca11673"
OPEN_P1 = ["D10-001", "D10-002", "D10-003", "D10-004", "D10-005", "D10-006", "D10-009"]
PINS = {
    "deployment/d14-offline-02.zip": (
        "73a57b1ee6a6a3039c7608e97aef9a8b26e690623314f0d119eb0c8e1e1b7b01"
    ),
    "materials": "94ac0d73cd405cffa88dcf1cc683b407b9b2d5b3e5d6ba1c13e3c4dfe79dd217",
    "evaluation": "1616a03a993f61d28001fc445bfe2aa6d0fbcf898501f5ef0b00484759430c4f",
}
MANIFEST_KEYS = {
    "version",
    "created_at",
    "application_version",
    "database_head",
    "base_freeze_sha256",
    "release_status",
    "p0_release_ready",
    "open_p1",
    "source_archives",
    "files",
}


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def no_links(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError("LINK_PATH_REFUSED")


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or PureWindowsPath(name).drive
        or path.as_posix() != name
        or any(c in '<>"|?*' or ord(c) < 32 for c in name)
        or any(part in (".", "..") or part.endswith((".", " ")) for part in path.parts)
        or any(
            re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]", part.split(".")[0], re.I)
            for part in path.parts
        )
    ):
        raise ValueError("INVALID_PATH")
    return name


def records(root: Path) -> dict[str, dict[str, Any]]:
    no_links(root)
    result = {}
    aliases = set()
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in folders + files:
            no_links(Path(directory) / name)
        for name in files:
            path = Path(directory) / name
            relative = safe_name(path.relative_to(root).as_posix())
            if relative.casefold() in aliases:
                raise ValueError("DUPLICATE_PATH")
            aliases.add(relative.casefold())
            result[relative] = {"sha256": sha(path), "bytes": path.stat().st_size}
    return dict(sorted(result.items()))


def safe_zip(path: Path, *, max_bytes: int = 256 * 1024 * 1024) -> list[zipfile.ZipInfo]:
    """Validate the whole archive before any extraction; preserve only regular file bytes."""
    no_links(path)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 10000 or sum(info.file_size for info in entries) > max_bytes:
            raise ValueError("ZIP_EXPANSION_LIMIT")
        aliases = set()
        files = set()
        for info in entries:
            if info.orig_filename != info.filename:
                raise ValueError("NORMALIZED_ZIP_PATH_REFUSED")
            name = safe_name(info.filename[:-1] if info.is_dir() else info.filename)
            alias = name.casefold()
            if alias in aliases:
                raise ValueError("DUPLICATE_ZIP_PATH")
            aliases.add(alias)
            mode = stat.S_IFMT(info.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or info.flag_bits & 1:
                raise ValueError("ZIP_LINK_OR_ENCRYPTION_REFUSED")
            if not info.is_dir():
                files.add(alias)
        for alias in aliases:
            if any(parent.as_posix() in files for parent in PurePosixPath(alias).parents):
                raise ValueError("ZIP_PATH_COLLISION")
        if archive.testzip() is not None:
            raise ValueError("ZIP_CRC_FAILED")
        return entries


def read_json(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("MANIFEST_SCHEMA")
    return value


def verify(bundle: Path, expected_manifest: str | None = None) -> dict[str, Any]:
    no_links(bundle)
    manifest_path = bundle / "release-manifest.json"
    no_links(manifest_path)
    if expected_manifest is not None and sha(manifest_path) != expected_manifest:
        raise ValueError("MANIFEST_DIGEST_MISMATCH")
    manifest = read_json(manifest_path)
    if set(manifest) != MANIFEST_KEYS:
        raise ValueError("MANIFEST_SCHEMA")
    if (
        manifest["version"] != VERSION
        or manifest["application_version"] != "0.1.0.dev12"
        or manifest["database_head"] != "0006_d9"
        or manifest["base_freeze_sha256"] != BASE
        or manifest["release_status"] != "engineering_candidate"
        or manifest["p0_release_ready"] is not False
        or manifest["open_p1"] != OPEN_P1
    ):
        raise ValueError("VERSION_OR_ACCEPTANCE_CHANGED")
    if manifest["source_archives"] != PINS:
        raise ValueError("PINNED_SOURCE_CHANGED")
    expected = manifest["files"]
    if not isinstance(expected, dict) or not expected:
        raise ValueError("MANIFEST_SCHEMA")
    for name, item in expected.items():
        safe_name(name)
        if name in ("release-manifest.json", "SHA256SUMS"):
            raise ValueError("MANIFEST_SELF_REFERENCE")
        if (
            not isinstance(item, dict)
            or set(item) != {"sha256", "bytes"}
            or not isinstance(item["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
            or type(item["bytes"]) is not int
            or item["bytes"] < 0
        ):
            raise ValueError("MANIFEST_SCHEMA")
    # Fixed archive is independently pinned even when somebody edits the manifest.
    deployment = bundle / "deployment/d14-offline-02.zip"
    no_links(deployment)
    if sha(deployment) != PINS["deployment/d14-offline-02.zip"]:
        raise ValueError("PINNED_SOURCE_CHANGED")
    actual = records(bundle)
    if set(actual) != set(expected) | {"release-manifest.json", "SHA256SUMS"}:
        raise ValueError("FILE_SET_MISMATCH")
    if any(actual[name] != item for name, item in expected.items()):
        raise ValueError("FILE_CHANGED")
    checksums = {name: item["sha256"] for name, item in expected.items()}
    checksums["release-manifest.json"] = sha(manifest_path)
    text = "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items()))
    if (bundle / "SHA256SUMS").read_text(encoding="utf-8") != text:
        raise ValueError("CHECKSUM_LIST_CHANGED")
    entries = safe_zip(deployment)
    acceptance = read_json(bundle / "docs/d15-acceptance.json")
    if (
        acceptance.get("p0_release_ready") is not False
        or acceptance.get("inherited_open_p1") != OPEN_P1
        or acceptance.get("external_submission_completed") is not False
        or acceptance.get("human_signatures") != []
    ):
        raise ValueError("ACCEPTANCE_CHANGED")
    return {
        "integrity_verified": True,
        "files": len(actual),
        "deployment_entries": len(entries),
        "manifest_sha256": sha(manifest_path),
        "p0_release_ready": False,
        "open_p1": OPEN_P1,
        "release_status": "engineering_candidate",
        "external_submission_completed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(args.bundle, args.expected_manifest_sha256)
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        print(json.dumps({"integrity_verified": False, "code": str(error)}))
        raise SystemExit(2) from error
    result["strict_gate"] = "blocked" if args.strict else "not_requested"
    print(json.dumps(result))
    raise SystemExit(2 if args.strict else 0)


if __name__ == "__main__":
    main()
