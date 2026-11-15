"use strict";

/**
 * Runtime configuration from the environment. No secrets are hardcoded;
 * the HMAC secret and the Kurier API key are supplied by the operator.
 *
 *   AGENT_GAMES_HMAC_SECRET  platform-generated secret (dashboard -> Rotate Secret)
 *   KURIER_API_KEY           mainnet Kurier key (optional; without it the agent
 *                            still answers with proof + public_signals, no proof_tx
 *                            from Kurier)
 *   KURIER_API_URL           default https://api.kurier.xyz/api/v1
 *   GATEKEEPER_VK_HASH       default = registered gatekeeper vk_hash from /api/circuit-info
 *   KURIER_POLL_BUDGET_MS    default 15000
 *   TASK_SOFT_DEADLINE_MS    default 50000 (hard platform deadline is 60 s)
 *   SEEN_STORE_PATH          default data/seen.json (relative to repo root)
 *   CIRCUITS_DIR             default circuits/
 *   PORT                     default 8787
 */
const path = require("path");

const ROOT = path.resolve(__dirname, "..");

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

const config = {
  port: intEnv("PORT", 8787),
  hmacSecret: process.env.AGENT_GAMES_HMAC_SECRET || "",
  kurierApiKey: process.env.KURIER_API_KEY || "",
  kurierApiUrl:
    process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1",
  gatekeeperVkHash:
    process.env.GATEKEEPER_VK_HASH ||
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  kurierPollBudgetMs: intEnv("KURIER_POLL_BUDGET_MS", 15000),
  kurierPollIntervalMs: intEnv("KURIER_POLL_INTERVAL_MS", 2000),
  taskSoftDeadlineMs: intEnv("TASK_SOFT_DEADLINE_MS", 50000),
  seenStorePath:
    process.env.SEEN_STORE_PATH || path.join(ROOT, "data", "seen.json"),
  circuitsDir: process.env.CIRCUITS_DIR || path.join(ROOT, "circuits"),
  protocolVersion: "v1",
};

module.exports = { config, ROOT };
