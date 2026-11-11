// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { downloadR2Artifact, R2ArtifactError } from "./r2-artifact-source.mjs";

const endpoint = "https://00000000000000000000000000000000.r2.cloudflarestorage.com";
const environment = Object.freeze({
  PATH: "/usr/bin:/bin",
  R2_ENDPOINT: endpoint,
  R2_ACCESS_KEY_ID: "fixture-access",
  R2_SECRET_ACCESS_KEY: "fixture-secret",
  AWS_PROFILE: "unrelated-profile",
  AWS_SESSION_TOKEN: "unrelated-session",
  AWS_ENDPOINT_URL: "https://unrelated.invalid",
  GITHUB_TOKEN: "unrelated-workflow-token",
});

function withOutput(action) {
  const root = mkdtempSync(join(tmpdir(), "reallyme-zk-r2-test-"));
  try { action(join(root, "artifact.download")); }
  finally { rmSync(root, { force: true, recursive: true }); }
}

function rejects(code, action) {
  assert.throws(action, (error) => error instanceof R2ArtifactError && error.code === code);
}

test("R2 transport fixes the bucket and prefix and isolates signing credentials", () => {
  withOutput((output) => {
    let called = false;
    downloadR2Artifact("circuits/digest/mobile-circuits.tar", output, {
      environment,
      run(command, args, options) {
        called = true;
        assert.equal(command, "aws");
        assert.deepEqual(args.slice(0, 2), ["s3api", "get-object"]);
        const argument = (name) => args[args.indexOf(name) + 1];
        assert.equal(argument("--endpoint-url"), endpoint);
        assert.equal(argument("--bucket"), "static");
        assert.equal(argument("--key"), "zk/circuits/digest/mobile-circuits.tar");
        assert.equal(argument("--region"), "auto");
        assert.equal(argument("--range"), "bytes=0-268435456");
        assert.equal(args.at(-1), output);
        assert.ok(!args.includes(environment.R2_ACCESS_KEY_ID));
        assert.ok(!args.includes(environment.R2_SECRET_ACCESS_KEY));
        assert.equal(options.env.AWS_ACCESS_KEY_ID, "fixture-access");
        assert.equal(options.env.AWS_SECRET_ACCESS_KEY, "fixture-secret");
        assert.equal(options.env.AWS_CONFIG_FILE, "/dev/null");
        assert.equal(options.env.AWS_SHARED_CREDENTIALS_FILE, "/dev/null");
        assert.equal(options.env.AWS_EC2_METADATA_DISABLED, "true");
        for (const key of ["AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL", "GITHUB_TOKEN"]) {
          assert.ok(!Object.hasOwn(options.env, key));
        }
        assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]);
        assert.equal(options.timeout, 300_000);
        assert.equal(options.killSignal, "SIGKILL");
        writeFileSync(output, "artifact");
        return { status: 0 };
      },
    });
    assert.ok(called);
    assert.equal(readFileSync(output, "utf8"), "artifact");
  });
});

test("R2 transport supports explicitly supplied temporary session credentials", () => {
  withOutput((output) => {
    downloadR2Artifact("crs/digest/g2.dat", output, {
      environment: { ...environment, R2_SESSION_TOKEN: "fixture-session" },
      run(_command, _args, options) {
        assert.equal(options.env.AWS_SESSION_TOKEN, "fixture-session");
        writeFileSync(output, "artifact");
        return { status: 0 };
      },
    });
  });
});

test("R2 rejects ambiguous endpoints before starting a signed request", () => {
  withOutput((output) => {
    for (const value of [undefined, "", "http://example.invalid", endpoint.replace("https://", "http://"),
      `${endpoint}/zk`, `${endpoint}?q=1`, `${endpoint}#fragment`, `${endpoint}:443`,
      endpoint.replace("https://", "https://user:password@"), `${endpoint}.invalid`,
      `${endpoint}/different-bucket`, `${endpoint}/static/zk`, `${endpoint}/static?key=value`,
      endpoint.replace("00000000000000000000000000000000", "short"), `${endpoint}\n`]) {
      rejects("invalid-r2-endpoint", () => downloadR2Artifact("circuits/digest/pack.tar", output, {
        environment: { ...environment, R2_ENDPOINT: value },
        run() { assert.fail("invalid endpoint reached the CLI"); },
      }));
    }
  });
});

test("R2 accepts standard and jurisdiction-specific origin endpoints", () => {
  withOutput((output) => {
    for (const value of [endpoint, `${endpoint}/`, `${endpoint}/static`, `${endpoint}/static/`,
      endpoint.replace(".r2.", ".eu.r2."), `${endpoint.replace(".r2.", ".eu.r2.")}/static`,
      endpoint.replace(".r2.", ".us.r2."),
      endpoint.replace(".r2.", ".fedramp.r2.")]) {
      downloadR2Artifact("crs/g2.dat", output, {
        environment: { ...environment, R2_ENDPOINT: value },
        run(_command, args) {
          assert.equal(args[args.indexOf("--endpoint-url") + 1], new URL(value).origin);
          writeFileSync(output, "artifact");
          return { status: 0 };
        },
      });
      rmSync(output);
    }
  });
});

test("R2 rejects unsafe object keys without starting the CLI", () => {
  withOutput((output) => {
    for (const key of [undefined, "", "/absolute", "../private", "a/../private", "a/./b", "a//b", "a/",
      "a\\b", "a%2fb", "a?b", "a\nb", "a\0b", "a".repeat(1022)]) {
      rejects("invalid-r2-object-key", () => downloadR2Artifact(key, output, {
        environment, run() { assert.fail("invalid key reached the CLI"); },
      }));
    }
  });
});

test("R2 rejects absent or malformed credentials without fallback", () => {
  withOutput((output) => {
    for (const name of ["R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_SESSION_TOKEN"]) {
      const values = ["", "has space", "has\nnewline", "x".repeat(4097)];
      if (name !== "R2_SESSION_TOKEN") values.push(undefined);
      for (const value of values) {
        rejects("invalid-r2-credentials", () => downloadR2Artifact("crs/g2.dat", output, {
          environment: { ...environment, [name]: value },
          run() { assert.fail("invalid credentials reached the CLI"); },
        }));
      }
    }
  });
});

test("R2 rejects relative or invalid destination paths", () => {
  for (const output of [undefined, "", "relative.download", "/absolute\0invalid"]) {
    rejects("invalid-r2-output-path", () => downloadR2Artifact("crs/g2.dat", output, {
      environment, run() { assert.fail("invalid output reached the CLI"); },
    }));
  }
});

test("R2 preserves existing destinations and refuses symlinks", () => {
  withOutput((output) => {
    const target = `${output}.target`;
    writeFileSync(target, "preserve");
    for (const kind of ["file", "symlink", "directory"]) {
      if (kind === "file") writeFileSync(output, "preserve");
      if (kind === "symlink") symlinkSync(target, output);
      if (kind === "directory") mkdirSync(output);
      rejects("r2-output-already-exists", () => downloadR2Artifact("crs/g2.dat", output, {
        environment, run() { assert.fail("existing output reached the CLI"); },
      }));
      assert.equal(readFileSync(target, "utf8"), "preserve");
      assert.ok(lstatSync(output));
      rmSync(output, { recursive: kind === "directory" });
    }
  });
});

test("R2 failures discard partial downloads without exposing CLI diagnostics", () => {
  withOutput((output) => {
    const privateDiagnostic = "signed-request-and-endpoint-must-remain-private";
    for (const result of [{ status: 1, stderr: privateDiagnostic },
      { status: null, error: new Error(privateDiagnostic) }, undefined]) {
      rejects("r2-download-failed", () => downloadR2Artifact("crs/g2.dat", output, {
        environment,
        run() { writeFileSync(output, "partial"); return result; },
      }));
      assert.ok(!existsSync(output));
    }
    rejects("r2-download-failed", () => downloadR2Artifact("crs/g2.dat", output, {
      environment,
      run() { writeFileSync(output, "partial"); throw new Error(privateDiagnostic); },
    }));
    assert.ok(!existsSync(output));
  });
});

test("R2 rejects missing, empty, oversized and non-regular CLI outputs", () => {
  withOutput((output) => {
    for (const kind of ["missing", "empty", "oversized", "symlink", "directory"]) {
      const target = `${output}.target`;
      writeFileSync(target, "preserve");
      const code = kind === "missing" ? "r2-download-failed" :
        kind === "directory" ? "r2-output-cleanup-failed" : "invalid-r2-object-size";
      rejects(code, () => downloadR2Artifact("crs/g2.dat", output, {
        environment,
        run() {
          if (kind === "empty" || kind === "oversized") writeFileSync(output, "");
          if (kind === "oversized") truncateSync(output, 268435457);
          if (kind === "symlink") symlinkSync(target, output);
          if (kind === "directory") mkdirSync(output);
          return { status: 0 };
        },
      }));
      assert.equal(readFileSync(target, "utf8"), "preserve");
      if (kind === "directory") rmSync(output, { recursive: true });
      else assert.ok(!existsSync(output));
    }
  });
});

test("R2 download diagnostics expose fixed reasons without CLI or service details", () => {
  withOutput((output) => {
    const privateDetails = "private-request-and-account-details";
    for (const [service, code] of [
      ["AccessDenied", "r2-access-denied"], ["InvalidAccessKeyId", "r2-invalid-access-key"],
      ["403", "r2-access-denied"], ["401", "r2-access-denied"],
      ["Unauthorized", "r2-access-denied"], ["Forbidden", "r2-access-denied"],
      ["SignatureDoesNotMatch", "r2-signature-mismatch"], ["NoSuchKey", "r2-object-not-found"],
      ["NoSuchBucket", "r2-bucket-not-found"], ["ExpiredToken", "r2-expired-token"],
      ["404", "r2-object-not-found"], ["AuthorizationHeaderMalformed", "r2-invalid-signing-configuration"],
      ["InvalidToken", "r2-invalid-token"], ["InvalidRange", "r2-invalid-range"],
      ["InvalidArgument", "r2-invalid-request"], ["InvalidRequest", "r2-invalid-request"],
      ["RequestTimeTooSkewed", "r2-request-time-skew"], ["UntrustedCode", "r2-download-failed"],
    ]) {
      rejects(code, () => downloadR2Artifact("crs/g2.dat", output, {
        environment,
        run() {
          return { status: 1, stderr: `An error occurred (${service}) when calling the GetObject operation: ${privateDetails}` };
        },
      }));
    }
    for (const [result, code] of [
      [{ status: null, error: { code: "ENOENT", message: privateDetails } }, "r2-cli-unavailable"],
      [{ status: null, error: { code: "ETIMEDOUT", message: privateDetails } }, "r2-download-timeout"],
      [{ status: 1, stderr: `Could not connect to the endpoint URL: ${privateDetails}` }, "r2-endpoint-unreachable"],
      [{ status: 1, stderr: `SSL validation failed for ${privateDetails}` }, "r2-tls-validation-failed"],
      [{ status: 1, stderr: `Unknown options: ${privateDetails}` }, "r2-cli-incompatible"],
    ]) {
      rejects(code, () => downloadR2Artifact("crs/g2.dat", output, {
        environment, run() { return result; },
      }));
    }
  });
});
