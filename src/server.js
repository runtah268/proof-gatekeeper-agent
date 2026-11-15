"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");

const { config } = require("./config");
const { AgentHandler } = require("./handler");
const { SeenStore } = require("./seenStore");

/**
 * Plain Node.js HTTP server (stdlib only) for the Proof Gatekeeper agent.
 *
 * Routes:
 *   POST /agent   registered endpoint: HMAC-verified preflight + task envelopes
 *   POST /task    alias of POST /agent (same envelope protocol)
 *   GET  /agent   health check  -> {"status":"ok","version":"1.0.0"}
 *   GET  /health  health check  -> {"status":"ok","version":"1.0.0"}
 *   GET  /ready   readiness     -> {"ready":true|false} (true only when the HMAC
 *                  secret is configured and the circuit artifacts are present)
 *
 * The platform registers ONE handler path (e.g. https://<host>/agent) and
 * POSTs signed preflight + task envelopes to it; the GET routes exist so a
 * health check against any of the documented shapes succeeds.
 */
function createServer(cfg, store) {
  const handler = new AgentHandler(cfg, store);

  function circuitsPresent() {
    return (
      fs.existsSync(path.join(cfg.circuitsDir, "gatekeeper.wasm")) &&
      fs.existsSync(path.join(cfg.circuitsDir, "gatekeeper_final.zkey"))
    );
  }

  function sendJson(res, status, body, signature) {
    res.writeHead(status, {
      "content-type": "application/json",
      ...(signature ? { "x-agent-games-signature": signature } : {}),
    });
    res.end(body);
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const pathname = url.pathname;

    if (req.method === "GET" && (pathname === "/health" || pathname === "/agent")) {
      return sendJson(res, 200, JSON.stringify({ status: "ok", version: "1.0.0" }));
    }

    if (req.method === "GET" && pathname === "/ready") {
      const ready = Boolean(cfg.hmacSecret) && circuitsPresent();
      return sendJson(
        res,
        200,
        JSON.stringify({
          ready,
          ...(ready ? {} : { reason: "hmac_secret_or_circuits_missing" }),
        })
      );
    }

    if (req.method === "POST" && (pathname === "/agent" || pathname === "/task")) {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", async () => {
        const rawBody = Buffer.concat(chunks);
        try {
          const result = await handler.handlePost(
            rawBody,
            req.headers["x-agent-games-signature"]
          );
          sendJson(res, result.status, result.body, result.signature);
        } catch (err) {
          console.error("[server] unexpected error:", err.message);
          sendJson(
            res,
            200,
            JSON.stringify({ decision: "REJECT", reason_code: "INVALID_TASK" })
          );
        }
      });
      return;
    }

    sendJson(res, 404, JSON.stringify({ error: "not_found" }));
  });

  return server;
}

if (require.main === module) {
  const store = new SeenStore(config.seenStorePath);
  const server = createServer(config, store);
  server.listen(config.port, () => {
    console.log(`[gatekeeper] listening on :${config.port}`);
    console.log(
      `[gatekeeper] hmac secret ${config.hmacSecret ? "configured" : "MISSING (set AGENT_GAMES_HMAC_SECRET)"}`
    );
    console.log(
      `[gatekeeper] kurier ${config.kurierApiKey ? "configured" : "not set (proofs answered locally, no proof_tx from Kurier)"}`
    );
  });
}

module.exports = { createServer };
