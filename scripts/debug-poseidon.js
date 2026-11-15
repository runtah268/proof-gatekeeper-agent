"use strict";

/**
 * Debug: what is publicSignals[0] (the circuit's "commitment" output)?
 * Compares the actual public[0] from a real proof against several
 * candidate Poseidon computations. Exits 0 when one candidate matches.
 */
const { buildPoseidon } = require("circomlibjs");
const { deriveSalt } = require("../src/hmac");
const { toFieldElement } = require("../src/fields");
const { buildCircuitInputs, parseInput } = require("../src/decision");
const { Prover } = require("../src/prover");

(async () => {
  const poseidon = await buildPoseidon();
  const taskId = "gk_test_valid_001";
  const secret = "test-hmac-secret-do-not-use-in-prod";
  const salt = deriveSalt(secret, taskId);
  const taskIdFe = BigInt(toFieldElement(taskId));
  console.log("taskIdFe:", taskIdFe.toString());
  console.log("salt:    ", salt.toString());

  const input = {
    registered_vk:
      "0x7d3a9c1e5f2a4b6d8e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f291",
    proof_vk:
      "0x7d3a9c1e5f2a4b6d8e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f291",
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: "0x1111111111111111111111111111111111111111",
    condition_recipient: "0x1111111111111111111111111111111111111111",
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0x" + "a".repeat(64),
  };
  const parsed = parseInput(input);
  const inputs = buildCircuitInputs({ task_id: taskId }, parsed, "APPROVE", salt);
  const prover = new Prover("./circuits");
  const { proof, publicSignals } = await prover.prove(inputs);
  const actual = publicSignals[0];
  console.log("actual public[0]:", actual);

  const candidates = {
    "Poseidon(taskId, salt)": poseidon.F.toString(poseidon([taskIdFe, salt])),
    "Poseidon(salt, taskId)": poseidon.F.toString(poseidon([salt, taskIdFe])),
    "Poseidon(taskId, salt, 0)": poseidon.F.toString(poseidon([taskIdFe, salt, 0n])),
    "Poseidon(taskId)": poseidon.F.toString(poseidon([taskIdFe])),
    "Poseidon(salt)": poseidon.F.toString(poseidon([salt])),
  };
  let matched = null;
  for (const [name, value] of Object.entries(candidates)) {
    const ok = value === actual;
    console.log(`${ok ? "MATCH" : "     "} ${name}: ${value}`);
    if (ok) matched = name;
  }
  console.log("verify:", await prover.verifyLocally(proof, publicSignals));
  console.log(matched ? `RESULT: commitment = ${matched}` : "RESULT: no candidate matched");
  process.exit(matched ? 0 : 1);
})().catch((e) => {
  console.error("ERR", e);
  process.exit(2);
});
