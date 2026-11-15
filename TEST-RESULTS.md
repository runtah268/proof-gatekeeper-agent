# Test Results — Proof Gatekeeper Agent

## Latest run

- **Date:** 15 Nov 2026, ~12:45 WIB
- **Command:** `npm test` (boots the real server on port 18787, replays
  spec-shaped envelopes)
- **Environment:** Node v24.22.1, snarkjs 0.7.6, circomlibjs 0.1.7,
  circom_runtime 0.1.28
- **Result: 73 passed, 0 failed** (exit 0, ~7.4 s)

## Coverage

| Section | Checks | Result |
| --- | --- | --- |
| GET /health, GET /agent, GET /ready | 3 | pass |
| Preflight (valid HMAC → signed ok; bad/missing HMAC → 401) | 3 | pass |
| Decision matrix — all 7 outcomes (VALID + 6 traps) | 6 × 8 = 48 | pass |
| PROOF_REUSED (no proof attached, proof_tx echoed) | 2 | pass |
| Idempotent redelivery (identical cached body, still APPROVE) | 1 | pass |
| Boundaries (balance == minimum, amount == max, current == expiry − 1 → APPROVE; current == expiry → REJECT) | 4 + 4 proof verifies | pass |
| Malformed / fail-closed (bad JSON, unknown type, missing field, past deadline) | 4 | pass |
| POST /task alias | 1 | pass |
| Circuit as referee (direct fullProve) | 3 | pass |

Per decision case the harness checks: correct decision + reason_code,
response HMAC signature, response time < 60 s, Groth16 proof verifies
locally with `snarkjs groth16 verify` against the extracted verification
key, exactly 13 public signals, `public[0] == Poseidon(salt, taskId)`,
`public[1..12]` equal the 12 inputs in order, and `proof_tx` echoing the
task's proof_tx (no Kurier key configured in tests).

## Response times (local)

- First task (cold, incl. WASM load): ~945 ms
- Warm tasks: 303–406 ms
- All far under the 60 s hard deadline, even with the 15 s Kurier poll
  budget on top.

## Circuit-as-referee checks (the important ones)

- `decision=1` on a trapped statement → witness generation **fails**
  (stderr shows `Error in template GatekeeperEvaluation_79 line: 102` —
  this is the circuit asserting, expected noise, not a test failure).
- `decision=0` on a valid statement → witness generation **fails**.
- `decision=1` on a valid statement → proves and verifies.

A wrong decision is unprovable. The circuit enforces the policy, not just
the code.

## Signal recovery (independent verification)

`node scripts/probe-signals.js` against the downloaded artifact:

- `getInputSize()`: 13, `getWitnessSize()`: 647
- 13 input signals found, all size 1: taskId, registeredVkHash,
  proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, decision, salt
- Decoys correctly absent: proofTxHash, proofTx, balance, threshold,
  vkHash, commitment, nullifier, proof, sender, action, value

## Commitment order — correction to published write-ups

Independent write-ups of this event state the first public signal is
`Poseidon(taskId, salt)`. Experimentally (scripts/debug-poseidon.js) that
does **not** match. The circuit actually emits **`Poseidon(salt, taskId)`**
— salt first. The harness asserts the corrected order and passes.

This does not change agent behavior (the salt is private; the platform
cannot recompute the commitment either way — it checks the other 12 public
signals against the task envelope), but the documentation is corrected
here so nobody "fixes" it back to the wrong order.

## Circuit artifacts (downloaded 15 Nov 2026)

- `gatekeeper.wasm` — 1,755,820 bytes,
  sha256 `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
- `gatekeeper_final.zkey` — 309,750 bytes,
  sha256 `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`
- Verification key exported from the zkey: curve bn128, protocol groth16,
  nPublic 13.
- Registered vk_hash (`/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

## Not tested here (needs live platform / user steps)

- Kurier mainnet submission (no API key in this environment) — code path
  implemented per the Kurier docs; submission + polling never tested live.
- Platform preflight against the real dashboard (needs registration +
  the platform-generated HMAC secret from Rotate Secret).
- Practice tasks (mode "practice" envelopes are behind the logged-in
  dashboard; same POST /agent path is expected).
- Deployment (no host chosen yet) and the 60 s deadline under real load.
