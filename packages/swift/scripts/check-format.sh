#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

PACKAGE_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"

swift format lint \
  --strict \
  --recursive \
  "${PACKAGE_ROOT}/Sources/ReallyMeZK" \
  "${PACKAGE_ROOT}/Sources/ReallyMeZKProtoCodec" \
  "${PACKAGE_ROOT}/Tests/ReallyMeZKTests" \
  "${PACKAGE_ROOT}/Examples"
