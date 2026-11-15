"use strict";

/**
 * Deterministic policy for Proof Gatekeeper. No model involvement: the final
 * call is made here, fail-closed. Checks mirror the trap taxonomy on
 * /events/proof-gatekeeper, in this priority order (each scored task carries
 * exactly one trap, so order only matters for malformed multi-trap input):
 *
 *   proof_vk != registered_vk          -> VK_SUBSTITUTION
 *   proof_tx already in the seen-set   -> PROOF_REUSED (no proof to submit)
 *   public_balance < minimum           -> THRESHOLD_MISMATCH
 *   current_block >= expiry_block      -> EXPIRED_CONDITION
 *   recipient != condition_recipient   -> RECIPIENT_MISMATCH
 *   amount > max_transfer              -> AMOUNT_OVERFLOW
 *   otherwise                          -> APPROVE / VALID_CONDITION
 *
 * The gatekeeper circuit enforces exactly these comparisons on its public
 * inputs: the `decision` input must equal the AND of the five field checks,
 * or witness generation fails. Boundaries: balance >= minimum passes,
 * amount <= max_transfer passes, current_block < expiry_block passes.
 */
const { parseUint, toFieldElement } = require("./fields");

function normalizeHex(v) {
  return (v ?? "").trim().toLowerCase();
}

/** Structural validation + parsing. Returns null on any malformed field. */
function parseInput(input) {
  if (!input || typeof input !== "object") return null;

  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);

  if (
    minimum === null || publicBalance === null || amount === null ||
    maxTransfer === null || expiryBlock === null || currentBlock === null
  ) {
    return null;
  }

  if (
    typeof input.registered_vk !== "string" || !input.registered_vk ||
    typeof input.proof_vk !== "string" || !input.proof_vk ||
    typeof input.recipient !== "string" || !input.recipient ||
    typeof input.condition_recipient !== "string" || !input.condition_recipient ||
    typeof input.proof_tx !== "string" || !input.proof_tx
  ) {
    return null;
  }

  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount,
    maxTransfer,
    proofTx: input.proof_tx,
  };
}

/**
 * @returns {{decision: "APPROVE"|"REJECT", reason_code: string, provable: boolean}}
 * provable=false only for PROOF_REUSED (the event page documents those tasks
 * as having no proof to submit).
 */
function evaluate(parsed, isProofTxSeen) {
  if (normalizeHex(parsed.proofVk) !== normalizeHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normalizeHex(parsed.recipient) !== normalizeHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

/**
 * Circuit inputs for gatekeeper.wasm. Signal names were recovered from the
 * artifact itself (scripts/probe-signals.js) and confirmed by proving:
 *   inputs: taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
 *           expiryBlock, currentBlock, recipient, conditionRecipient,
 *           amount, maxTransfer, decision, salt (private)
 *   public signals order: [commitment, registeredVkHash, proofVkHash,
 *           minimum, publicBalance, expiryBlock, currentBlock, recipient,
 *           conditionRecipient, amount, maxTransfer, decision, taskId]
 * where commitment = Poseidon(salt, taskId) is the circuit's only output
 * (verified experimentally: Poseidon(taskId, salt) does NOT match — the
 * circuit hashes salt first).
 */
function buildCircuitInputs(envelope, parsed, decision, salt) {
  return {
    taskId: toFieldElement(envelope.task_id),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

module.exports = { parseInput, evaluate, buildCircuitInputs };
