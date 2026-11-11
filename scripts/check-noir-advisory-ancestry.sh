#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TOOLCHAIN_LOCK="${TOOLCHAIN_LOCK:-${ROOT}/circuits/toolchain-lock.json}"
ADVISORY_FIXES="${ADVISORY_FIXES:-${ROOT}/docs/provenance/noir-1.0.0-security-fixes-v1.tsv}"

fail() {
  echo "Noir advisory ancestry check failed: $1" >&2
  exit 2
}

if [[ -z "${NOIR_CHECKOUT:-}" ]]; then
  fail "NOIR_CHECKOUT must name a complete noir-lang/noir Git checkout"
fi
if [[ ! -d "${NOIR_CHECKOUT}/.git" && ! -f "${NOIR_CHECKOUT}/.git" ]]; then
  fail "NOIR_CHECKOUT is not a Git checkout"
fi
if [[ ! -f "${TOOLCHAIN_LOCK}" || ! -f "${ADVISORY_FIXES}" ]]; then
  fail "required provenance input is missing"
fi

candidate_revision="$(
  node -e '
const fs = require("node:fs");
const lock = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const revision = lock?.candidateMatchedPair?.noir?.revision;
if (typeof revision !== "string" || !/^[0-9a-f]{40}$/u.test(revision)) {
  process.exit(2);
}
process.stdout.write(revision);
' "${TOOLCHAIN_LOCK}"
)" || fail "candidate Noir revision is malformed"

if ! git -C "${NOIR_CHECKOUT}" cat-file -e "${candidate_revision}^{commit}" 2>/dev/null; then
  fail "candidate Noir revision is absent from the checkout"
fi

if ! awk -F '\t' '
  NR == 1 {
    if ($0 != "advisory\ttitle\taffected_range\tpatched_release\tfix_or_release_revision\tapplicability\tevidence_url\tpublished_at\treviewed_at\tregression_gate") {
      exit 1
    }
    next
  }
  NF != 10 { exit 1 }
  $1 !~ /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/ { exit 1 }
  $2 == "" { exit 1 }
  $3 == "" { exit 1 }
  $4 != "unversioned" && $4 !~ /^1[.]0[.]0-beta[.][0-9]+$/ { exit 1 }
  $5 !~ /^[0-9a-f]{40}$/ { exit 1 }
  $6 != "noir_1_0_0_descends_from_patched_release" &&
    $6 != "noir_1_0_0_descends_from_fix_commit" { exit 1 }
  $7 !~ /^https:\/\/github[.]com\/noir-lang\/noir\/security\/advisories\/GHSA-/ { exit 1 }
  $8 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/ { exit 1 }
  $9 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ { exit 1 }
  $10 == "" { exit 1 }
  seen[$1] == 1 { exit 1 }
  { seen[$1] = 1 }
' "${ADVISORY_FIXES}"; then
  fail "advisory fix inventory is malformed"
fi

required_advisories=(
  GHSA-v2q4-prvf-7h73
  GHSA-2v53-vfw3-w489
  GHSA-wvh3-mhm3-7wwv
  GHSA-35pp-g9jq-9vf7
  GHSA-qqxj-59g5-7jcv
  GHSA-35h6-769r-84c9
  GHSA-mfqg-6wvq-m7mr
  GHSA-j4p3-qjx6-rmvx
  GHSA-w58m-gfcx-8pjq
  GHSA-jhqf-jg5f-f357
  GHSA-683h-pgp9-8cq4
  GHSA-mh2f-jqp7-m6gm
  GHSA-5pjx-p7xp-457j
  GHSA-pw32-6mqc-pr39
  GHSA-43f8-pw4p-5f5g
  GHSA-4wj9-6h6c-499v
  GHSA-7qph-55xp-rwfj
  GHSA-fvmx-g2j7-8v59
  GHSA-7c3c-hwwp-2r9v
  GHSA-3fmx-gqpv-c758
  GHSA-62rj-6v4x-8xcq
  GHSA-rh9h-x248-64rw
  GHSA-pgh4-36hc-pmrx
  GHSA-ghvp-f453-vh53
  GHSA-fch6-63xj-6qgm
  GHSA-hjcm-2547-whv2
  GHSA-jj7c-x25r-r8r3
  GHSA-h8h7-5532-qm79
  GHSA-j54m-w23j-938w
  GHSA-24hw-hj99-xgg2
  GHSA-6j45-727g-vcr2
  GHSA-q37h-c4fp-pq32
  GHSA-wq62-cp93-4556
  GHSA-h47v-w5hw-q4x3
  GHSA-jf3m-p678-f68m
  GHSA-7w64-wfwp-hh3q
  GHSA-jcmw-4hvr-rvcc
  GHSA-qqgg-vpmp-766w
  GHSA-rj6g-3r23-hw6x
  GHSA-wv86-2vvh-2j7g
  GHSA-vx9w-r3qr-jh3v
  GHSA-7cqc-cj32-3xq2
  GHSA-fjwm-gpjw-cjqh
  GHSA-g27f-jh2j-c39x
  GHSA-9v2p-vwxc-jfh4
  GHSA-3878-8pjf-wgcq
  GHSA-8wpq-5mw8-8j85
  GHSA-4462-q25g-3fmc
  GHSA-x8xh-hm9j-f85p
  GHSA-xw6r-48f5-gc77
  GHSA-cp84-xrj5-49vg
  GHSA-r693-v6fg-mvqw
  GHSA-959m-2cmp-9f4w
  GHSA-wc93-74wp-hpjh
  GHSA-g6r5-jjj6-7pj2
)
for required_advisory in "${required_advisories[@]}"; do
  if ! awk -F '\t' -v advisory="${required_advisory}" 'NR > 1 && $1 == advisory { found = 1 } END { exit found == 1 ? 0 : 1 }' "${ADVISORY_FIXES}"; then
    fail "${required_advisory} is absent from the advisory inventory"
  fi
done

checked=0
while IFS=$'\t' read -r advisory title affected_range patched_release fix_or_release_revision applicability evidence_url published_at reviewed_at regression_gate; do
  if [[ "${advisory}" == "advisory" ]]; then
    continue
  fi
  if ! git -C "${NOIR_CHECKOUT}" cat-file -e "${fix_or_release_revision}^{commit}" 2>/dev/null; then
    fail "${advisory} fix or release revision is absent from the checkout"
  fi
  if ! git -C "${NOIR_CHECKOUT}" merge-base --is-ancestor "${fix_or_release_revision}" "${candidate_revision}"; then
    fail "${advisory} fix or release revision is not an ancestor of the candidate revision"
  fi
  if [[ "${advisory}" == "GHSA-cp84-xrj5-49vg" && "${regression_gate}" != "field-to-u128-zero-branch" ]]; then
    fail "GHSA-cp84-xrj5-49vg must name the Field-to-u128 regression gate"
  fi
  checked=$((checked + 1))
done < "${ADVISORY_FIXES}"

if ((checked != ${#required_advisories[@]})); then
  fail "advisory fix inventory count does not match the required reviewed set"
fi

printf 'Noir advisory ancestry passed for %d advisory records at %s\n' \
  "${checked}" "${candidate_revision}"
