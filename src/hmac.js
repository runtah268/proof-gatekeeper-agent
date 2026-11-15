"use strict";

const crypto = require("crypto");
const { BN128_PRIME } = require("./fields");

/**
 * HMAC-SHA256 signing / verification for the Agent Games envelope protocol.
 *
 * The platform signs the RAW request body and sends it as the
 * `x-agent-games-signature` header; responses are signed the same way over
 * the raw response body. The secret is the platform-generated value from
 * Dashboard -> Rotate Secret — never a local placeholder.
 *
 * Inbound verification accepts hex or base64 of the same MAC bytes (with an
 * optional `sha256=` prefix), compared in constant time. The exact key
 * encoding is not documented on /build; this tolerant reader covers both.
 */
function hmacHex(secret, body) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function signBody(secret, body) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  return hmacHex(secret, buf);
}

function verifyBodySignature(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;
  let presented = String(signatureHeader).trim();
  if (presented.toLowerCase().startsWith("sha256=")) {
    presented = presented.slice("sha256=".length);
  }
  let presentedBytes;
  if (/^[0-9a-fA-F]+$/.test(presented) && presented.length % 2 === 0) {
    presentedBytes = Buffer.from(presented, "hex");
  } else {
    try {
      presentedBytes = Buffer.from(presented, "base64");
    } catch {
      return false;
    }
  }
  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest();
  if (presentedBytes.length !== expected.length) return false;
  return crypto.timingSafeEqual(presentedBytes, expected);
}

/**
 * Deterministic per-task circuit salt, so a redelivered task reproduces
 * identical proof inputs: HMAC(secret, "gatekeeper-salt:" + task_id) mod p.
 */
function deriveSalt(secret, taskId) {
  const mac = crypto
    .createHmac("sha256", secret)
    .update("gatekeeper-salt:" + taskId)
    .digest();
  const n = BigInt("0x" + mac.toString("hex"));
  return ((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME;
}

module.exports = { signBody, verifyBodySignature, deriveSalt };
