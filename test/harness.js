"use strict";

/**
 * End-to-end harness: boots the real server on a test port and replays
 * spec-shaped envelopes (event page sample numbers) through it.
 *
 * Checks:
 *   - GET /health, GET /ready, GET /agent
 *   - preflight handshake (valid HMAC -> signed {ok, protocolVersion}; bad/missing -> 401)
 *   - all 7 decision outcomes (VALID + 6 traps), each proof verified locally
 *     with snarkjs groth16 verify against the extracted verification key
 *   - public signals: [Poseidon(taskId, salt), ...12 inputs in order]
 *   - PROOF_REUSED carries no proof; redelivery returns the cached response
 *   - boundary semantics (balance == minimum, amount == max, current == expiry - 1)
 *   - malformed envelopes fail closed to REJECT / INVALID_TASK
 *   - circuit-as-referee: decision=1 on a trapped statement and decision=0 on
 *     a valid statement must FAIL witness generation
 *   - response time per task (hard deadline is 60 s)
 *
 * No network calls to Kurier (no API key set): proof_tx falls back to echoing
 * the task's proof_tx. Run: npm test
 */
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

process.env.AGENT_GAMES_HMAC_SECRET = "test-hmac-secret-do-not-use-in-prod";
process.env.PORT = "18787";
process.env.SEEN_STORE_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "gk-seen-")),
  "seen.json"
);
process.env.KURIER_API_KEY = "";

const { config } = require("../src/config");
const { createServer } = require("../src/server");
const { Prover } = require("../src/prover");
const { deriveSalt } = require("../src/hmac");
const { buildPoseidon } = require("circomlibjs");

const BASE = `http://127.0.0.1:${config.port}`;
const SECRET = config.hmacSecret;

let passed = 0;
let failed = 0;
const failures = [];

function check(name, ok, detail) {
  if (ok) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`);
  }
}

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}

async function postJson(pathname, obj, { rawBody, sig } = {}) {
  const body = rawBody !== undefined ? rawBody : JSON.stringify(obj);
  const res = await fetch(BASE + pathname, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(sig === null ? {} : { "x-agent-games-signature": sig ?? sign(body) }),
    },
    body,
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* non-JSON body */
  }
  return { status: res.status, text, json, sigHeader: res.headers.get("x-agent-games-signature") };
}

function verifyResponseSignature(text, sigHeader) {
  if (!sigHeader) return false;
  const expected = crypto.createHmac("sha256", SECRET).update(text).digest();
  let presented;
  if (/^[0-9a-fA-F]+$/.test(sigHeader)) presented = Buffer.from(sigHeader, "hex");
  else presented = Buffer.from(sigHeader, "base64");
  return (
    presented.length === expected.length && crypto.timingSafeEqual(presented, expected)
  );
}

// Sample numbers from the event page (full-length hex where the page truncates).
const VK_A = "0x7d3a9c1e5f2a4b6d8e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f291";
const VK_B = "0xa4c1b8ff9e2d3c4b5a69788796a5b4c3d2e1f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4";
const ADDR_1 = "0x1111111111111111111111111111111111111111";
const ADDR_2 = "0x2222222222222222222222222222222222222222";

function taskEnvelope(taskId, proofTx, overrides = {}) {
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date(now - 1000).toISOString(),
    deadline_at: new Date(now + 120000).toISOString(),
    input: {
      registered_vk: VK_A,
      proof_vk: VK_A,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: ADDR_1,
      condition_recipient: ADDR_1,
      amount: "500",
      max_transfer: "1000",
      proof_tx: proofTx,
      ...overrides,
    },
  };
}

const TX = (n) => "0x" + String(n).repeat(64);

(async () => {
  const { SeenStore } = require("../src/seenStore");
  const seenStore = new SeenStore(config.seenStorePath);
  const server = createServer(config, seenStore);
  await new Promise((resolve) => server.listen(config.port, resolve));
  console.log(`[harness] server on :${config.port}`);

  const prover = new Prover(config.circuitsDir);
  const poseidon = await buildPoseidon();

  try {
    console.log("\n== health / readiness ==");
    {
      const r = await fetch(BASE + "/health");
      const j = await r.json();
      check("GET /health -> {status:ok, version:1.0.0}", r.status === 200 && j.status === "ok" && j.version === "1.0.0", JSON.stringify(j));
    }
    {
      const r = await fetch(BASE + "/agent");
      const j = await r.json();
      check("GET /agent -> health JSON", r.status === 200 && j.status === "ok", JSON.stringify(j));
    }
    {
      const r = await fetch(BASE + "/ready");
      const j = await r.json();
      check("GET /ready -> {ready:true}", r.status === 200 && j.ready === true, JSON.stringify(j));
    }

    console.log("\n== preflight ==");
    {
      const body = JSON.stringify({ type: "agent-games.preflight.v1" });
      const r = await postJson("/agent", null, { rawBody: body });
      check(
        "preflight valid HMAC -> {ok:true, protocolVersion:v1} + valid signature",
        r.status === 200 && r.json?.ok === true && r.json?.protocolVersion === "v1" &&
          verifyResponseSignature(r.text, r.sigHeader),
        `status=${r.status} body=${r.text}`
      );
    }
    {
      const body = JSON.stringify({ type: "agent-games.preflight.v1" });
      const r = await postJson("/agent", null, { rawBody: body, sig: "deadbeef" });
      check("preflight bad HMAC -> 401", r.status === 401, `status=${r.status}`);
    }
    {
      const body = JSON.stringify({ type: "agent-games.preflight.v1" });
      const r = await postJson("/agent", null, { rawBody: body, sig: null });
      check("preflight missing HMAC -> 401", r.status === 401, `status=${r.status}`);
    }

    console.log("\n== decision matrix (7 outcomes) ==");
    const cases = [
      { name: "VALID_CONDITION", env: taskEnvelope("gk_test_valid_001", TX("a")), want: ["APPROVE", "VALID_CONDITION"], provable: true },
      { name: "VK_SUBSTITUTION", env: taskEnvelope("gk_test_vk_002", TX("b"), { proof_vk: VK_B }), want: ["REJECT", "VK_SUBSTITUTION"], provable: true },
      { name: "THRESHOLD_MISMATCH", env: taskEnvelope("gk_test_thr_003", TX("c"), { public_balance: "900" }), want: ["REJECT", "THRESHOLD_MISMATCH"], provable: true },
      { name: "EXPIRED_CONDITION", env: taskEnvelope("gk_test_exp_004", TX("d"), { current_block: 19842201 }), want: ["REJECT", "EXPIRED_CONDITION"], provable: true },
      { name: "RECIPIENT_MISMATCH", env: taskEnvelope("gk_test_rcp_005", TX("e"), { recipient: ADDR_2 }), want: ["REJECT", "RECIPIENT_MISMATCH"], provable: true },
      { name: "AMOUNT_OVERFLOW", env: taskEnvelope("gk_test_amt_006", TX("f"), { amount: "1500" }), want: ["REJECT", "AMOUNT_OVERFLOW"], provable: true },
    ];

    for (const c of cases) {
      const t0 = Date.now();
      const r = await postJson("/agent", c.env);
      const ms = Date.now() - t0;
      const okDecision =
        r.status === 200 && r.json?.decision === c.want[0] && r.json?.reason_code === c.want[1];
      check(`${c.name}: decision=${c.want[0]} reason=${c.want[1]}`, okDecision, `status=${r.status} body=${r.text.slice(0, 200)}`);
      check(`${c.name}: response signed`, verifyResponseSignature(r.text, r.sigHeader));
      check(`${c.name}: answered in ${ms}ms (< 60s)`, ms < 60000);
      if (c.provable && r.json?.proof && r.json?.public_signals) {
        const okVerify = await prover.verifyLocally(r.json.proof, r.json.public_signals);
        check(`${c.name}: Groth16 proof verifies locally`, okVerify === true);
        check(`${c.name}: 13 public signals`, r.json.public_signals.length === 13, `got ${r.json.public_signals?.length}`);
        // Public signal [0] must be Poseidon(taskId, salt).
        const salt = deriveSalt(SECRET, c.env.task_id);
        const { toFieldElement } = require("../src/fields");
        const taskIdFe = BigInt(toFieldElement(c.env.task_id));
        const commitment = poseidon.F.toString(poseidon([salt, taskIdFe]));
        check(`${c.name}: public[0] == Poseidon(taskId, salt)`, r.json.public_signals[0] === commitment,
          `got ${r.json.public_signals[0]} want ${commitment}`);
        // Public signals [1..12] must equal the 12 inputs in order.
        const { buildCircuitInputs, parseInput } = require("../src/decision");
        const parsed = parseInput(c.env.input);
        const inputs = buildCircuitInputs(c.env, parsed, c.want[0], salt);
        const expectedOrder = [
          inputs.registeredVkHash, inputs.proofVkHash, inputs.minimum,
          inputs.publicBalance, inputs.expiryBlock, inputs.currentBlock,
          inputs.recipient, inputs.conditionRecipient, inputs.amount,
          inputs.maxTransfer, inputs.decision, inputs.taskId,
        ];
        const restOk = expectedOrder.every((v, i) => r.json.public_signals[i + 1] === v);
        check(`${c.name}: public[1..12] == inputs in order`, restOk);
        check(`${c.name}: proof_tx echoes task proof_tx (no Kurier key)`, r.json.proof_tx === c.env.input.proof_tx);
      } else if (c.provable) {
        check(`${c.name}: proof + public_signals present`, false, `body=${r.text.slice(0, 200)}`);
      }
    }

    console.log("\n== PROOF_REUSED + idempotency ==");
    {
      // Same proof_tx as the VALID case above, new task_id -> must be REUSED, no proof.
      const env = taskEnvelope("gk_test_reuse_007", TX("a"));
      const r = await postJson("/agent", env);
      check(
        "PROOF_REUSED: decision=REJECT reason=PROOF_REUSED, no proof attached",
        r.status === 200 && r.json?.decision === "REJECT" &&
          r.json?.reason_code === "PROOF_REUSED" && !r.json?.proof && !r.json?.public_signals,
        `body=${r.text.slice(0, 200)}`
      );
      check("PROOF_REUSED: proof_tx echoes input", r.json?.proof_tx === TX("a"));
    }
    {
      // Redelivery of the VALID task -> identical cached body, still APPROVE.
      const env = taskEnvelope("gk_test_valid_001", TX("a"));
      const r1 = await postJson("/agent", env);
      const r2 = await postJson("/agent", env);
      check(
        "redelivery: identical cached response, still APPROVE",
        r1.status === 200 && r2.status === 200 && r1.text === r2.text &&
          r2.json?.decision === "APPROVE",
        `r1=${r1.text.slice(0, 120)} r2=${r2.text.slice(0, 120)}`
      );
    }

    console.log("\n== boundaries ==");
    const boundaries = [
      { name: "balance == minimum -> APPROVE", env: taskEnvelope("gk_test_bnd_008", TX("1"), { public_balance: "1000" }), want: "APPROVE" },
      { name: "amount == max_transfer -> APPROVE", env: taskEnvelope("gk_test_bnd_009", TX("2"), { amount: "1000" }), want: "APPROVE" },
      { name: "current == expiry - 1 -> APPROVE", env: taskEnvelope("gk_test_bnd_010", TX("3"), { current_block: 19842200 }), want: "APPROVE" },
      { name: "current == expiry -> REJECT/EXPIRED", env: taskEnvelope("gk_test_bnd_011", TX("4"), { current_block: 19842201 }), want: "REJECT" },
    ];
    for (const b of boundaries) {
      const r = await postJson("/agent", b.env);
      check(`${b.name}`, r.status === 200 && r.json?.decision === b.want, `body=${r.text.slice(0, 160)}`);
      if (r.json?.proof && r.json?.public_signals) {
        check(`${b.name}: proof verifies`, (await prover.verifyLocally(r.json.proof, r.json.public_signals)) === true);
      }
    }

    console.log("\n== malformed / fail-closed ==");
    {
      const r = await postJson("/agent", null, { rawBody: "{not json" });
      check("malformed JSON -> REJECT INVALID_TASK", r.json?.decision === "REJECT" && r.json?.reason_code === "INVALID_TASK", `status=${r.status} body=${r.text.slice(0, 120)}`);
    }
    {
      const r = await postJson("/agent", { type: "agent-games.unknown.v1" });
      check("unknown type -> 400 REJECT INVALID_TASK", r.status === 400 && r.json?.decision === "REJECT", `status=${r.status}`);
    }
    {
      const env = taskEnvelope("gk_test_bad_012", TX("5"));
      delete env.input.amount;
      const r = await postJson("/agent", env);
      check("missing field -> REJECT INVALID_TASK", r.json?.decision === "REJECT" && r.json?.reason_code === "INVALID_TASK", `body=${r.text.slice(0, 160)}`);
    }
    {
      const env = taskEnvelope("gk_test_bad_013", TX("6"));
      env.deadline_at = new Date(Date.now() - 60000).toISOString();
      const r = await postJson("/agent", env);
      check("past deadline -> REJECT INVALID_TASK", r.json?.decision === "REJECT" && r.json?.reason_code === "INVALID_TASK", `body=${r.text.slice(0, 160)}`);
    }
    {
      // POST /task alias behaves like POST /agent.
      const env = taskEnvelope("gk_test_alias_014", TX("7"));
      const r = await postJson("/task", env);
      check("POST /task alias -> APPROVE", r.status === 200 && r.json?.decision === "APPROVE", `status=${r.status} body=${r.text.slice(0, 160)}`);
    }

    console.log("\n== circuit as referee (direct fullProve) ==");
    {
      const { buildCircuitInputs, parseInput } = require("../src/decision");
      const salt = deriveSalt(SECRET, "gk_test_referee");
      // Trapped statement with decision=1 must FAIL.
      const trapped = taskEnvelope("gk_test_referee", TX("8"), { proof_vk: VK_B });
      const parsedT = parseInput(trapped.input);
      const inputsT = buildCircuitInputs(trapped, parsedT, "APPROVE", salt);
      let trappedFailed = false;
      try {
        await prover.prove(inputsT);
      } catch {
        trappedFailed = true;
      }
      check("decision=1 on trapped statement fails witness generation", trappedFailed);
      // Valid statement with decision=0 must FAIL.
      const valid = taskEnvelope("gk_test_referee", TX("8"));
      const parsedV = parseInput(valid.input);
      const inputsV = buildCircuitInputs(valid, parsedV, "REJECT", salt);
      let validFailed = false;
      try {
        await prover.prove(inputsV);
      } catch {
        validFailed = true;
      }
      check("decision=0 on valid statement fails witness generation", validFailed);
      // And the correct pair must succeed + verify.
      const inputsOk = buildCircuitInputs(valid, parsedV, "APPROVE", salt);
      const { proof, publicSignals } = await prover.prove(inputsOk);
      check("decision=1 on valid statement proves + verifies", (await prover.verifyLocally(proof, publicSignals)) === true);
    }
  } finally {
    server.close();
  }

  console.log(`\n==== RESULT: ${passed} passed, ${failed} failed ====`);
  if (failures.length) {
    console.log("failures:", failures.join("; "));
  }
  // Force exit: fetch keep-alive sockets can keep the event loop alive.
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error("harness crashed:", e);
  process.exit(2);
});
