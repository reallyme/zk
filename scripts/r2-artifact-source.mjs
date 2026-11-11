// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { lstatSync, rmSync } from "node:fs";
import { isAbsolute } from "node:path";

const BUCKET = "static";
const OBJECT_PREFIX = "zk/";
const MAX_OBJECT_KEY_BYTES = 1024;
const MAX_OBJECT_BYTES = 256 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 300_000;
const MAX_CLI_OUTPUT_BYTES = 64 * 1024;
const ENDPOINT_PATTERN = /^(https:\/\/[a-f0-9]{32}(?:\.(?:eu|us|fedramp))?\.r2\.cloudflarestorage\.com)(?:\/static)?\/?$/u;
const RELATIVE_KEY_PATTERN = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u;

export class R2ArtifactError extends Error {
  constructor(code) {
    super(code);
    this.name = "R2ArtifactError";
    this.code = code;
  }
}

const fail = (code) => { throw new R2ArtifactError(code); };

function downloadFailure(result) {
  if (result?.error?.code === "ENOENT") return "r2-cli-unavailable";
  if (result?.error?.code === "ETIMEDOUT") return "r2-download-timeout";
  const stderr = typeof result?.stderr === "string" ? result.stderr : "";
  // Expose only recognized service codes. Never return CLI text, account
  // endpoints, signed requests, or arbitrary remote error descriptions.
  const serviceCode = /An error occurred \(([A-Za-z0-9]+)\) when calling the GetObject operation:/u.exec(stderr)?.[1];
  const reasons = new Map([
    ["AccessDenied", "r2-access-denied"],
    ["Unauthorized", "r2-access-denied"],
    ["Forbidden", "r2-access-denied"],
    ["401", "r2-access-denied"],
    ["403", "r2-access-denied"],
    ["InvalidAccessKeyId", "r2-invalid-access-key"],
    ["SignatureDoesNotMatch", "r2-signature-mismatch"],
    ["NoSuchKey", "r2-object-not-found"],
    ["NoSuchBucket", "r2-bucket-not-found"],
    ["404", "r2-object-not-found"],
    ["AuthorizationHeaderMalformed", "r2-invalid-signing-configuration"],
    ["ExpiredToken", "r2-expired-token"],
    ["InvalidToken", "r2-invalid-token"],
    ["InvalidRange", "r2-invalid-range"],
    ["InvalidArgument", "r2-invalid-request"],
    ["InvalidRequest", "r2-invalid-request"],
    ["RequestTimeTooSkewed", "r2-request-time-skew"],
  ]);
  if (reasons.has(serviceCode)) return reasons.get(serviceCode);
  if (stderr.includes("Could not connect to the endpoint URL:")) return "r2-endpoint-unreachable";
  if (stderr.includes("SSL validation failed for")) return "r2-tls-validation-failed";
  if (stderr.includes("Unknown options:")) return "r2-cli-incompatible";
  return "r2-download-failed";
}

function credential(environment, name, required) {
  const value = environment[name];
  if (!required && value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 ||
      /[\s\p{Cc}]/u.test(value)) {
    fail("invalid-r2-credentials");
  }
  return value;
}

function childEnvironment(environment) {
  // Isolate signing from local AWS profiles, service endpoints and unrelated
  // workflow secrets. Credentials are passed only through the child environment.
  const child = {
    PATH: typeof environment.PATH === "string" ? environment.PATH : "/usr/bin:/bin",
    LANG: "C",
    AWS_ACCESS_KEY_ID: credential(environment, "R2_ACCESS_KEY_ID", true),
    AWS_SECRET_ACCESS_KEY: credential(environment, "R2_SECRET_ACCESS_KEY", true),
    AWS_REGION: "auto",
    AWS_DEFAULT_REGION: "auto",
    AWS_CONFIG_FILE: "/dev/null",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_CLI_AUTO_PROMPT: "off",
    AWS_PAGER: "",
    AWS_MAX_ATTEMPTS: "2",
  };
  const session = credential(environment, "R2_SESSION_TOKEN", false);
  if (session !== undefined) child.AWS_SESSION_TOKEN = session;
  return child;
}

function assertAbsent(outputPath) {
  try {
    lstatSync(outputPath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    fail("r2-output-unavailable");
  }
  // The caller owns a fresh temporary path, then checks the pinned digest before
  // admission. Refusing existing files also prevents following an output symlink.
  fail("r2-output-already-exists");
}

export function downloadR2Artifact(remotePath, outputPath, {
  environment = process.env,
  run = spawnSync,
} = {}) {
  if (typeof remotePath !== "string" || remotePath.length > MAX_OBJECT_KEY_BYTES - OBJECT_PREFIX.length ||
      !RELATIVE_KEY_PATTERN.test(remotePath) ||
      remotePath.split("/").some((segment) => segment === "." || segment === "..")) {
    fail("invalid-r2-object-key");
  }
  if (typeof outputPath !== "string" || !isAbsolute(outputPath) || outputPath.includes("\0")) {
    fail("invalid-r2-output-path");
  }
  const suppliedEndpoint = environment.R2_ENDPOINT;
  const endpointMatch = typeof suppliedEndpoint === "string" ? ENDPOINT_PATTERN.exec(suppliedEndpoint) : null;
  if (endpointMatch === null) {
    fail("invalid-r2-endpoint");
  }
  // R2's dashboard may append the bucket to its copied S3 URL. The AWS CLI
  // takes the bucket separately; retaining that suffix would address it twice.
  const endpoint = endpointMatch[1];
  const child = childEnvironment(environment);
  assertAbsent(outputPath);
  try {
    const result = run("aws", [
      "s3api", "get-object",
      "--endpoint-url", endpoint,
      "--region", "auto",
      "--bucket", BUCKET,
      "--key", `${OBJECT_PREFIX}${remotePath}`,
      // Request one excess byte so a truncated oversized object cannot be
      // mistaken for a complete acceptable object. Admission still checks SHA-256.
      "--range", `bytes=0-${MAX_OBJECT_BYTES}`,
      "--cli-connect-timeout", "10",
      "--cli-read-timeout", "60",
      "--no-cli-pager", "--no-cli-auto-prompt",
      outputPath,
    ], {
      env: child,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: DOWNLOAD_TIMEOUT_MS,
      maxBuffer: MAX_CLI_OUTPUT_BYTES,
      killSignal: "SIGKILL",
    });
    // CLI diagnostics may include the account endpoint or signed request data.
    // Only a stable domain error crosses this boundary, including on timeout.
    if (result?.error !== undefined || result?.status !== 0) fail(downloadFailure(result));
    const metadata = lstatSync(outputPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() ||
        !Number.isSafeInteger(metadata.size) || metadata.size < 1 ||
        metadata.size > MAX_OBJECT_BYTES) {
      fail("invalid-r2-object-size");
    }
  } catch (error) {
    try { rmSync(outputPath, { force: true }); } catch { fail("r2-output-cleanup-failed"); }
    if (error instanceof R2ArtifactError) throw error;
    fail("r2-download-failed");
  } finally {
    // Environment values are immutable strings in Node. Drop additional
    // references promptly; signing and secret ownership remain in the AWS CLI.
    delete child.AWS_ACCESS_KEY_ID;
    delete child.AWS_SECRET_ACCESS_KEY;
    delete child.AWS_SESSION_TOKEN;
  }
}
