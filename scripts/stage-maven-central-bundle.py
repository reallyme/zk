# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate and archive the four ZK Maven Central publications."""

from __future__ import annotations

from hashlib import file_digest
import json
from pathlib import Path
import re
import shutil
import sys
from xml.etree import ElementTree
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile


GROUP = "me.really"
MODULES = {
    "zk": ("jar", "zk-proto-codec"),
    "zk-android": ("aar", "zk"),
    "zk-proto-codec": ("jar", "zk-proto-generated"),
    "zk-proto-generated": ("jar", None),
}
CHECKSUM_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
POM = {"pom": "http://maven.apache.org/POM/4.0.0"}


def expected_files(root: Path, version: str):
    for artifact_id, (extension, _) in MODULES.items():
        directory = root / "me" / "really" / artifact_id / version
        base = f"{artifact_id}-{version}"
        yield artifact_id, tuple(
            directory / name
            for name in (
                f"{base}.{extension}",
                f"{base}.pom",
                f"{base}.module",
                f"{base}-sources.jar",
                f"{base}-javadoc.jar",
            )
        )


def require_file(path: Path) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise ValueError(f"missing or invalid publication file: {path.name}")


def verify_publication(artifact_id: str, files: tuple[Path, ...], version: str) -> None:
    for path in files:
        require_file(path)
    binary, pom_file, module_file, source_jar, documentation_jar = files
    pom = ElementTree.parse(pom_file).getroot()
    identity = tuple(pom.findtext(f"pom:{part}", namespaces=POM) for part in ("groupId", "artifactId", "version"))
    if identity != (GROUP, artifact_id, version):
        raise ValueError(f"unexpected POM coordinates for {artifact_id}")
    for field in ("name", "description", "url", "licenses", "developers", "scm"):
        if pom.find(f"pom:{field}", POM) is None:
            raise ValueError(f"missing POM metadata for {artifact_id}: {field}")
    _, dependency = MODULES[artifact_id]
    expected = {(dependency, version)} if dependency is not None else set()
    pom_dependencies = {
        (item.findtext("pom:artifactId", namespaces=POM), item.findtext("pom:version", namespaces=POM))
        for item in pom.findall("pom:dependencies/pom:dependency", POM)
        if item.findtext("pom:groupId", namespaces=POM) == GROUP
    }
    module = json.loads(module_file.read_text(encoding="utf-8"))
    component = module["component"]
    if (component["group"], component["module"], component["version"]) != identity:
        raise ValueError(f"unexpected Gradle metadata coordinates for {artifact_id}")
    gradle_dependencies = {
        (item["module"], item["version"]["requires"])
        for variant in module["variants"]
        for item in variant.get("dependencies", [])
        if item["group"] == GROUP
    }
    if pom_dependencies != expected or gradle_dependencies != expected:
        raise ValueError(f"unexpected dependencies for {artifact_id}")
    with binary.open("rb") as contents:
        binary_hash = file_digest(contents, "sha256").hexdigest()
    binary_entries = [
        item
        for variant in module["variants"]
        for item in variant.get("files", [])
        if item["url"] == binary.name
    ]
    if not binary_entries or any(item.get("sha256") != binary_hash for item in binary_entries):
        raise ValueError(f"Gradle metadata does not bind the binary for {artifact_id}")
    with ZipFile(source_jar) as sources:
        names = sources.namelist()
        if not {"LICENSE-MIT", "LICENSE-APACHE"}.issubset(names) or any(
            name.endswith((".class", ".so", ".a", ".aar", ".jar")) for name in names
        ):
            raise ValueError(f"invalid source archive for {artifact_id}")
    with ZipFile(documentation_jar) as documentation:
        if "README.md" not in documentation.namelist():
            raise ValueError(f"missing documentation for {artifact_id}")


def stage(repository: Path, bundle: Path, version: str) -> None:
    bundle.mkdir()
    checksums = []
    for artifact_id, files in expected_files(repository, version):
        verify_publication(artifact_id, files, version)
        for source in files:
            destination = bundle / source.relative_to(repository)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            with destination.open("rb") as contents:
                sha256 = file_digest(contents, "sha256").hexdigest()
            checksums.append(f"{sha256}  {destination.relative_to(bundle).as_posix()}\n")
    (bundle / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")


def reuse(prepared: Path, bundle: Path, version: str) -> None:
    require_file(prepared / "SHA256SUMS")
    stage(prepared, bundle, version)
    if (prepared / "SHA256SUMS").read_bytes() != (bundle / "SHA256SUMS").read_bytes():
        raise ValueError("the prepared publication has changed since validation")


def archive(bundle: Path, output: Path, version: str) -> None:
    with ZipFile(output, "x", compression=ZIP_DEFLATED) as target:
        for _, files in expected_files(bundle, version):
            for artifact in files:
                for path in (artifact, artifact.with_name(f"{artifact.name}.asc")):
                    require_file(path)
                    entry = path.relative_to(bundle).as_posix()
                    target.write(path, entry)
                    for algorithm in CHECKSUM_ALGORITHMS:
                        with path.open("rb") as contents:
                            checksum = file_digest(contents, algorithm).hexdigest()
                        target.writestr(f"{entry}.{algorithm}", f"{checksum}\n")


def main() -> int:
    args = sys.argv[1:]
    operations = {"--archive": archive, "--reuse": reuse}
    operation = operations[args.pop(0)] if args and args[0] in operations else stage
    if len(args) != 3 or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args[2]) is None:
        print("Expected [--archive|--reuse] input output version", file=sys.stderr)
        return 2
    try:
        operation(Path(args[0]), Path(args[1]), args[2])
    except (ValueError, OSError, KeyError, TypeError, BadZipFile, ElementTree.ParseError) as error:
        print(f"Maven Central bundle failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
