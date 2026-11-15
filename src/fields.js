"use strict";

const crypto = require("crypto");

/** BN128 (alt_bn128) scalar field prime. */
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Parse a non-negative integer given as a decimal string, hex string, or number. */
function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

/**
 * Convert an envelope value to a BN128 field element (decimal string).
 * Hex values are reduced mod p (a 32-byte hash does not fit the field);
 * reduction preserves the equality checks the circuit performs.
 * Free-form identifiers (e.g. task_id "gk_8d31_x") are hashed (SHA-256, mod p).
 */
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  const reduced = ((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME;
  return reduced.toString(10);
}

module.exports = { BN128_PRIME, parseUint, toFieldElement };
