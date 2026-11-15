"use strict";

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

/**
 * Groth16 proving against the official gatekeeper circuit.
 * fullProve throws when the decision does not match the AND of the five
 * field checks — the circuit is the referee: a wrong decision is unprovable.
 */
class Prover {
  constructor(circuitsDir) {
    this.wasmPath = path.join(circuitsDir, "gatekeeper.wasm");
    this.zkeyPath = path.join(circuitsDir, "gatekeeper_final.zkey");
    this.vkPath = path.join(circuitsDir, "verification_key.json");
    if (!fs.existsSync(this.wasmPath) || !fs.existsSync(this.zkeyPath)) {
      throw new Error(
        `circuit artifacts missing in ${circuitsDir} (need gatekeeper.wasm + gatekeeper_final.zkey)`
      );
    }
  }

  async prove(circuitInputs) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      this.wasmPath,
      this.zkeyPath
    );
    return { proof, publicSignals: publicSignals.map(String) };
  }

  async verifyLocally(proof, publicSignals) {
    const vk = JSON.parse(fs.readFileSync(this.vkPath, "utf8"));
    return snarkjs.groth16.verify(vk, publicSignals, proof);
  }
}

module.exports = { Prover };
