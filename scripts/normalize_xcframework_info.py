# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Normalize generated XCFramework metadata for reproducible archive bytes."""

from pathlib import Path
import plistlib
import sys
from xml.parsers.expat import ExpatError

MAX_METADATA_BYTES = 65_536
SLICE_ORDER = ("macos-arm64", "ios-arm64", "ios-arm64-simulator")


def main() -> int:
    if len(sys.argv) != 2:
        print("XCFramework metadata normalization failed: invalid arguments", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_METADATA_BYTES:
            raise ValueError("invalid metadata file")
        metadata = plistlib.loads(path.read_bytes())
        if not isinstance(metadata, dict):
            raise ValueError("invalid metadata structure")
        libraries = metadata.get("AvailableLibraries")
        if not isinstance(libraries, list) or len(libraries) != len(SLICE_ORDER):
            raise ValueError("invalid slice set")
        by_identifier = {}
        for library in libraries:
            if not isinstance(library, dict):
                raise ValueError("invalid slice metadata")
            identifier = library.get("LibraryIdentifier")
            if not isinstance(identifier, str) or identifier not in SLICE_ORDER or identifier in by_identifier:
                raise ValueError("invalid slice identity")
            by_identifier[identifier] = library
        # xcodebuild emits slice records in a nondeterministic order. Fix their
        # order while preserving every field that describes the built libraries.
        metadata["AvailableLibraries"] = [by_identifier[identifier] for identifier in SLICE_ORDER]
        path.write_bytes(plistlib.dumps(metadata, fmt=plistlib.FMT_XML, sort_keys=True))
    except (OSError, ValueError, TypeError, RecursionError, ExpatError, plistlib.InvalidFileException):
        print("XCFramework metadata normalization failed: invalid generated metadata", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
