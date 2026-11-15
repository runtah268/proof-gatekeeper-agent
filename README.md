# Proof Gatekeeper Agent

An HTTPS agent endpoint for the **Proof Gatekeeper** event in the zkVerify
Agent Games (Season 01, 21 Oct – 21 Nov 2026). The platform POSTs signed task
envelopes; this service verifies the HMAC, makes a deterministic APPROVE/REJECT
decision, generates a real Groth16 proof locally with snarkjs against the
official gatekeeper circuit, optionally submits it to zkVerify via Kurier, and
returns a signed response — well inside the 60-second hard deadline
(typical end-to-end: ~0.3–1.0 s).

Target repository (GitHub account already linked to the Agent Games account):
**https://github.com/runtah268/proof-gatekeeper-agent** — push this directory
there (see "Publish" below). No push has been made from here; pushing needs
the owner's GitHub auth.

## Architecture

```
POST /agent (or POST /task)
  │
  ├─ 1. HMAC-SHA256 over the RAW body vs `x-agent-games-signature`
  │     (verified BEFORE JSON parsing; mismatch → HTTP 401)
  ├─ 2. type = "agent-games.preflight.v1"
  │     → signed `{ ok: true, protocolVersion: "v1" }`
  └─ 3. type = "agent-games.proof-gatekeeper.v1"
        ├─ idempotency cache (same task_id → cached response)
        ├─ deadline/timestamp sanity → fail closed
        ├─ deterministic policy (src/decision.js) → decision + reason_code
        ├─ snarkjs fullProve with gatekeeper.wasm / gatekeeper_final.zkey
        │    (skipped only for PROOF_REUSED — documented as having no proof)
        ├─ Kurier submit + bounded poll (≤15 s) → on-chain txHash as proof_tx
        └─ signed JSON response
```

Fail-closed throughout: malformed envelopes, internal errors, and proof
generation failures all resolve to REJECT, never to an unproven APPROVE.

### File layout

| Path | Purpose |
| --- | --- |
| `src/server.js` | Plain Node HTTP server (`npm start` / `npm run dev`). |
| `src/handler.js` | Framework-agnostic request pipeline. |
| `src/hmac.js` | HMAC sign/verify + per-task circuit salt derivation. |
| `src/decision.js` | Deterministic policy + envelope→circuit field conversion. |
| `src/fields.js` | BN128 field arithmetic (parseUint, toFieldElement). |
| `src/prover.js` | snarkjs `groth16.fullProve` wrapper + local verify. |
| `src/kurier.js` | Kurier submit-proof + job-status polling (never throws). |
| `src/seenStore.js` | proof_tx seen-set + response cache, JSON-file backed. |
| `src/config.js` | Environment configuration. |
| `circuits/` | `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` (extracted from the zkey). |
| `scripts/probe-signals.js` | Dev tool that recovered the circuit's input signal names from the WASM. |
| `test/harness.js` | Local end-to-end harness (`npm test`). |

## Protocol details (from the /build spec + event page)

**Task envelope** (`POST /agent`):

```
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_...",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x…", "proof_vk": "0x…",
    "minimum": "1000", "public_balance": "1460",
    "expiry_block": 8430000, "current_block": 8420000,
    "recipient": "0x…", "condition_recipient": "0x…",
    "amount": "500", "max_transfer": "1000",
    "proof_tx": "0x…"
  }
}
```

**Response** (all fields the spec mentions, so either verification path finds
what it needs):

```
{
  "decision": "APPROVE" | "REJECT",
  "reason_code": "VALID_CONDITION" | "VK_SUBSTITUTION" | "PROOF_REUSED"
               | "THRESHOLD_MISMATCH" | "EXPIRED_CONDITION"
               | "RECIPIENT_MISMATCH" | "AMOUNT_OVERFLOW",
  "proof": { "pi_a": […], "pi_b": […], "pi_c": […], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<13 field elements>"],
  "proof_tx": "0x…"
}
```

plus the `x-agent-games-signature` header (HMAC over the raw response body).

For `PROOF_REUSED` the response carries no proof — the event page states
those tasks "have no proof to submit and are excluded" from proof scoring.

**Decision rules** (mirroring the circuit exactly, boundaries included):
APPROVE only if `proof_vk == registered_vk`, `proof_tx` unseen,
`public_balance >= minimum`, `current_block < expiry_block`,
`recipient == condition_recipient`, and `amount <= max_transfer`.

**Score model** (event page): correct APPROVE/REJECT +12 each; wrong APPROVE
−6; wrong REJECT −3; timeout −2; missing/invalid proof −2; reliability bonus
+0 to +5 pro-rated by the share of provable tasks whose proof verified.
8 tasks per agent per round, 8 daily rounds (13–20 Nov), cumulative.

## The circuit (recovered from the artifacts)

Input signal names are not published; they were recovered from
`gatekeeper.wasm` with an FNV-1a hash oracle over the WASM's
`getInputSignalSize` export (see `scripts/probe-signals.js`), then confirmed
by proving. The circuit (`GatekeeperEvaluation`) takes 13 inputs:

```
taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer,
decision, salt (private)
```

and emits 13 public signals: `[Poseidon(salt, taskId), …the 12 public inputs
in the order above…]`. Critically, the circuit **asserts `decision == (all
five field checks)`**: witness generation fails for `decision=1` on a trapped
statement and for `decision=0` on a valid one — the circuit is the referee,
exactly as the /build page describes. Field elements are the envelope values
reduced mod the BN128 prime (a 32-byte hash does not fit the field; reduction
preserves the equality checks the circuit performs). `salt` is derived
deterministically as `HMAC(secret, "gatekeeper-salt:" + task_id) mod p`, so a
redelivered task reproduces identical proof inputs.

Circuit artifacts (downloaded 15 Nov 2026, verified against the site's own
published hashes in independent write-ups):
- `gatekeeper.wasm` — 1,755,820 bytes,
  sha256 `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
- `gatekeeper_final.zkey` — 309,750 bytes,
  sha256 `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`
- Registered vk_hash (`/api/circuit-info`): 
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- Verification key exported from the zkey: curve bn128, nPublic 13.

## Environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform-generated; dashboard → agent → **Rotate Secret**, copy the one-time plaintext. Never a local placeholder. |
| `KURIER_API_KEY` | no | Mainnet Kurier key (sign up at https://kurier.xyz). If unset, submission is skipped gracefully and the agent still answers with proof + public_signals. |
| `KURIER_API_URL` | no | Default `https://api.kurier.xyz/api/v1` (mainnet). |
| `GATEKEEPER_VK_HASH` | no | Defaults to the registered gatekeeper vk_hash `0x6b79c6…77b0`. |
| `KURIER_POLL_BUDGET_MS` | no | Default 15000. Live measurement by another participant: txHash exists from the Submitted status (~4 s); full finalization takes ~27 s and continues server-side at Kurier after we stop polling. |
| `TASK_SOFT_DEADLINE_MS` | no | Default 50000 (hard platform deadline is 60 s). |
| `SEEN_STORE_PATH` | no | Default `data/seen.json` locally, `/tmp/…` on serverless. |
| `CIRCUITS_DIR`, `PORT` | no | Artifact location override; local port (default 8787). |

No secrets are hardcoded anywhere; `.env` is gitignored and `.env.example`
ships blank values.

## Registration & preflight flow

1. Publish this repo to **github.com/runtah268/proof-gatekeeper-agent**
   (public, personal account — already linked to the Agent Games account).
2. Deploy somewhere with a public HTTPS endpoint (`npm start` on any Node
   ≥18 host, or a serverless host; the circuits must ship with the deploy).
3. Register the full handler path — `https://<host>/agent`, not the root —
   in the Agent Games dashboard, track **Proof Gatekeeper**.
4. Dashboard → **Rotate Secret** → set the revealed plaintext as
   `AGENT_GAMES_HMAC_SECRET` → redeploy/restart.
5. The platform sends a signed preflight (`type: agent-games.preflight.v1`);
   this agent answers `{ ok: true, protocolVersion: "v1" }` signed, and the
   dashboard marks the agent active. `GET /agent` also serves as the health
   check; `GET /ready` reports readiness.
6. Complete at least one practice task before scored rounds.
7. Rounds run daily 17:30–03:30 WIB (4:00 PM–2:00 AM IST); Round 3 is
   15 Nov, Round 8 is 20 Nov. Season ends 21 Nov 2026.

## Local test results

`npm test` boots the real server and replays spec-shaped envelopes — see
[TEST-RESULTS.md](TEST-RESULTS.md) for the full run.

## Deployment notes

- **Seen-set durability:** the seen-set lives in process memory + a JSON
  file. On serverless the file is in `/tmp` and state can reset on cold start;
  within a round, warm instances retain it. For maximum PROOF_REUSED
  reliability across the 8 rounds, a single long-lived instance
  (`npm start` on a small VM/container) is the safer host.
- **Kurier costs/credits** are the operator's: every provable task submits
  one proof to zkVerify mainnet when a key is configured.

## Spec ambiguities handled defensively

- **HMAC encoding:** /build mandates HMAC over the raw body but never names
  the algorithm/encoding. Outbound signing is HMAC-SHA256 hex; inbound
  verification accepts hex or base64 of the same MAC bytes (and an optional
  `sha256=` prefix), compared in constant time.
- **"Finalized before approval"** (Security checklist): the envelope carries
  no independently checkable finality proof for the referenced on-chain
  proof, so this is implemented as: our own proof is submitted to Kurier and
  its on-chain `txHash` is returned as `proof_tx` as soon as the submission
  transaction exists (the Submitted status, ~4 s live); finalization itself
  completes server-side at Kurier (~27 s live) without blocking the response.
- **`INVALID_TASK`** is a local fallback reason code for envelope-level
  failures (malformed input, past deadline, internal error). It is outside
  the documented 7-code taxonomy and only reachable off the scored paths.
- **`proof_tx` in the response:** the event page's sample echoes the task's
  own proof_tx; the /build guide asks for "enough proof evidence for the
  platform to independently confirm the network transaction". This agent
  returns the Kurier on-chain txHash when submission succeeded, otherwise
  echoes the task's proof_tx — and always includes the full `proof` +
  `public_signals`, so either verification path finds what it needs.
- **task_id → field element:** free-form ids (e.g. `gk_8d31_…`) are hashed
  (SHA-256, mod p) into the circuit's `taskId` input; numeric/hex ids are
  used directly.
- **Decision priority when several traps apply:** the event page's trap
  shares sum to 100%, so each scored task carries exactly one trap. The
  implementation checks in this order: VK_SUBSTITUTION → PROOF_REUSED →
  THRESHOLD_MISMATCH → EXPIRED_CONDITION → RECIPIENT_MISMATCH →
  AMOUNT_OVERFLOW.
- **Practice Mode** could not be read from the public site (requires login);
  the practice flow is expected to work through the same POST /agent
  endpoint with `mode: "practice"` envelopes — to be confirmed at preflight.

## Publish

```bash
cd ~/workspace/agent-games/gatekeeper-agent
git init
git add .
git commit -m "Proof Gatekeeper agent for zkVerify Agent Games Season 01"
git branch -M main
git remote add origin https://github.com/runtah268/proof-gatekeeper-agent.git
git push -u origin main
```

(Requires the owner's GitHub auth; nothing has been pushed from here.)
