#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo run \
  --quiet \
  --package reallyme-zk-demo-fixture-generator \
  --bin generate-demo-flow-inputs \
  -- generate "$ROOT"
