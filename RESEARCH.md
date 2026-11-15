# Research notes — Proof Gatekeeper (Agent Games Season 01)

Sources read 15 Nov 2026 (all public, no login except where noted):
- https://agentgames.zkverify.io/build (Builder Field Guide)
- https://agentgames.zkverify.io/events/proof-gatekeeper (task sample,
  response shape, trap encyclopedia, score model, round schedule, checklist)
- https://agentgames.zkverify.io/events
- https://agentgames.zkverify.io/api/circuit-info (vk hashes)
- https://docs.zkverify.io/overview/getting-started/kurier (Kurier REST API)
- https://github.com/andruu21/proof-gatekeeper-agent (independent participant
  implementation — used as reference for protocol details; code here is
  written independently)
- Medium write-ups by @saifulsidik801 and @dickycan42 (circuit probing
  approach), dev.to by @andruu21

## Verified facts

- Task envelope: `agent-games.proof-gatekeeper.v1`, fields
  registered_vk / proof_vk / minimum / public_balance / expiry_block /
  current_block / recipient / condition_recipient / amount / max_transfer /
  proof_tx. Response: decision + reason_code + proof + public_signals +
  proof_tx, signed with `x-agent-games-signature` (HMAC-SHA256 over raw body).
- Preflight: `agent-games.preflight.v1` → `{ok: true, protocolVersion: "v1"}`.
- 7 outcomes: VALID_CONDITION (APPROVE, ~50%), VK_SUBSTITUTION (~13%),
  THRESHOLD_MISMATCH (~8%), PROOF_REUSED (~11%, no proof),
  EXPIRED_CONDITION (~6%), RECIPIENT_MISMATCH (~6%), AMOUNT_OVERFLOW (~6%).
- Score: correct +12, wrong APPROVE −6, wrong REJECT −3, timeout −2,
  missing/invalid proof −2, reliability bonus +0..+5 (pro-rated by verified
  proofs; PROOF_REUSED excluded).
- Rounds: 13–20 Nov 2026, 4:00 PM–2:00 AM IST (= 17:30–03:30 WIB), 8 tasks
  per agent per round, cumulative. R1 (13 Nov) + R2 (14 Nov) done; R3 is
  15 Nov; R8 is 20 Nov; season ends 21 Nov.
- Circuit: Groth16/BN128, Circom 2.x, 13 public inputs, witness 647.
  Signal names recovered independently by probing the WASM (FNV-1a oracle
  over `getInputSignalSize`): taskId, registeredVkHash, proofVkHash,
  minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, salt (private).
  Public signals: [Poseidon(salt, taskId), + 12 inputs in order].
  Decision must equal the AND of the five field checks (verified: wrong
  decision fails witness generation).
- Kurier mainnet: https://api.kurier.xyz/api/v1, API key from kurier.xyz
  signup. POST /submit-proof/{key} {proofType, vkRegistered: true,
  proofOptions, proofData: {proof, publicSignals, vk: vkHash}} →
  {jobId, optimisticVerify}. GET /job-status/{key}/{jobId}; statuses
  Queued → Valid → Submitted → IncludedInBlock → Finalized | Failed.
  txHash exists from Submitted onward.
- Gatekeeper vk is already registered on mainnet; no register-vk call needed.
- HMAC secret comes from the dashboard (Rotate Secret) after registration;
  the exact key encoding is NOT documented — implementation accepts hex or
  base64 (optional `sha256=` prefix), constant-time compare.
- Steal the VFY is a separate track (not built here): 20-turn matches,
  policy proofs, strategy commitment hash before Swiss Round 1.

## Gaps / assumptions (not verified from official docs)

1. **Practice Mode is behind login** — the dashboard practice page could
   not be read via text fetch. Assumed to use the same POST /agent endpoint
   with `mode: "practice"` envelopes. Must be confirmed at preflight.
2. **proof_tx semantics** — the event page sample echoes the task's own
   proof_tx; the /build guide asks for evidence "to independently confirm
   the network transaction". Implementation returns the Kurier txHash when
   submission succeeded, otherwise echoes the task's proof_tx, and always
   includes the full proof + public_signals.
3. **Decision priority when several traps apply** — trap shares sum to
   100%, so each scored task carries exactly one trap. Order used:
   VK_SUBSTITUTION → PROOF_REUSED → THRESHOLD_MISMATCH →
   EXPIRED_CONDITION → RECIPIENT_MISMATCH → AMOUNT_OVERFLOW.
4. **"Finalized before approval"** — the envelope carries no independently
   checkable finality proof for the referenced on-chain proof. Implemented
   as: submit our own proof to Kurier and return its txHash as soon as the
   submission transaction exists (Submitted status); finalization completes
   server-side.
5. **Commitment order** — published write-ups say Poseidon(taskId, salt);
   experiment proves it is Poseidon(salt, taskId). Corrected here.
6. **Endpoint shapes** — the /build guide's architecture section is
   diagram-based (no body text in the fetch). The working protocol is one
   POST endpoint (/agent) for preflight + tasks, with GET on the same path
   as health check. This agent additionally exposes GET /health,
   GET /ready and POST /task as aliases so every documented shape answers.
7. **Kurier live behavior** — submission + polling code is implemented per
   the docs but never executed against mainnet (no API key). txHash timing
   (~4 s to Submitted, ~27 s to Finalized) is from another participant's
   live measurement, not mine.
8. **Round-3 timing** — entries lock while a round is open; registration +
   preflight + practice must complete before a round's tasks are assigned.
   Round 3 opens 15 Nov 17:30 WIB; the build finished ~12:50 WIB, leaving
   ~4.5 h for repo publish + deploy + register + preflight + practice.

## Participant account state (15 Nov 12:40 WIB, from parent)

- Agent Games account @0x-g0blinz (registered 14 Nov), Creator Track
  submitted and PENDING, points 0.0, rank NOT RANKED.
- GitHub **runtah268** (github.com/runtah268) linked to the account;
  country "Indonesia" recorded; eligibility 4/5 (missing "At least one
  scored agent").
- Suggested repo: github.com/runtah268/proof-gatekeeper-agent.
