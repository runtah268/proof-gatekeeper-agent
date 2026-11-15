/**
 * Dev tool: recover the gatekeeper circuit's input signal names from
 * gatekeeper.wasm, independently of any write-up.
 *
 * Circom's WASM witness calculator addresses input signals by FNV-1a hash;
 * getInputSignalSize(hash) returns the element count for a real input signal
 * and 0 for an unknown name, which turns a candidate-name dictionary into
 * an oracle. getInputSize() gives the total input count.
 *
 * Usage: node scripts/probe-signals.js [path-to-gatekeeper.wasm]
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { WitnessCalculatorBuilder } = require("circom_runtime");

function fnv1a64(str) {
  const MOD = 2n ** 64n;
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < str.length; i++) {
    h ^= BigInt(str.charCodeAt(i));
    h *= 0x100000001b3n;
    h %= MOD;
  }
  return h;
}

const CANDIDATES = [
  // expected (from the event page's task fields + circuit conventions)
  "taskId", "registeredVkHash", "proofVkHash", "minimum", "publicBalance",
  "expiryBlock", "currentBlock", "recipient", "conditionRecipient", "amount",
  "maxTransfer", "decision", "salt",
  // decoys that must NOT match
  "proofTxHash", "proofTx", "balance", "threshold", "vkHash",
  "commitment", "nullifier", "proof", "sender", "action", "value",
];

(async () => {
  const wasmPath =
    process.argv[2] || path.resolve(__dirname, "..", "circuits", "gatekeeper.wasm");
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(wasmPath));
  const ex = wc.instance.exports;
  console.log("getInputSize():", ex.getInputSize());
  console.log("getWitnessSize():", ex.getWitnessSize());
  const found = [];
  for (const name of CANDIDATES) {
    const h = fnv1a64(name);
    const hi = Number((h >> 32n) & 0xffffffffn);
    const lo = Number(h & 0xffffffffn);
    const size = ex.getInputSignalSize(hi, lo);
    if (size > 0) {
      found.push(name);
      console.log(`  input signal: ${name} (size ${size})`);
    }
  }
  console.log(`found ${found.length} input signals: ${found.join(", ")}`);
})().catch((e) => {
  console.error("probe failed:", e.message);
  process.exit(1);
});
