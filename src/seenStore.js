"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Durable seen-set + idempotent response cache, JSON-file backed.
 *
 * - proof_tx seen-set: a proof reference already accepted in a previous task
 *   must be rejected as PROOF_REUSED. The set is only written AFTER a task
 *   is answered successfully, so a task never flags itself.
 * - response cache: a redelivered task_id returns the cached response body,
 *   never re-evaluated (a redelivery must not be mistaken for reuse).
 *
 * On a serverless host the file may reset on cold start; a single long-lived
 * instance is the safer deployment for cross-round PROOF_REUSED reliability.
 */
class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seen = new Set();
    this.responses = new Map();
    this.load();
  }

  load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      for (const tx of raw.seenProofTx || []) this.seen.add(tx);
      for (const [k, v] of Object.entries(raw.responses || {})) {
        this.responses.set(k, v);
      }
    } catch {
      // No store yet (or corrupt) — start empty.
    }
  }

  save() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(
        this.filePath,
        JSON.stringify(
          {
            seenProofTx: [...this.seen],
            responses: Object.fromEntries(this.responses),
          },
          null,
          2
        )
      );
    } catch (err) {
      console.error("[seen] failed to persist store:", err.message);
    }
  }

  hasProofTx(proofTx) {
    return this.seen.has(proofTx);
  }

  recordProofTx(proofTx) {
    this.seen.add(proofTx);
    this.save();
  }

  getResponse(taskId) {
    return this.responses.get(taskId) ?? null;
  }

  recordResponse(taskId, body) {
    this.responses.set(taskId, body);
    this.save();
  }
}

module.exports = { SeenStore };
