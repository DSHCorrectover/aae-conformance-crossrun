# AAE conformance vectors v1.4.0 — receiver-side cross-run (clean room)

Recorded run: `MoltyCel/aae-conformance-vectors` tag `v1.4.0`, commit `531f880155ea1ce993a7ca74137b12c255d5b2ee`, checked out by tag and verified by commit SHA (`git rev-parse v1.4.0` → `531f880…`). License: Apache-2.0 (see the vectors repository).

Receiver: Correctover. Provenance: **clean_room** — our verifier (`aae-receiver-verify.py`, sha-256 `f9aec0d6b3f6be73bf81d1ffce5805609aafee35b32d5ad44a55e31beadcf07e`) was written from the text of `draft-kroehl-agentic-trust-aae-00` (Sections 2.4, 3, 5, fetched from datatracker.ietf.org) and the vector-format description in the vectors repository README (lines 1–82 at the pin). The reference verifier source (`examples/python-verify.py`) was **not** read. DID resolution uses the offline `testkeys/did-documents/` mapping implied by the testkeys directory layout.

## Result

**15/15 vectors match**: our result equals `expected.result` for every vector, and for every REJECT our `verification_step` equals the expected step.

Recount (done from `per-case.json` without re-running the verifier): see `recount.json` — 15 vectors, 15 matches, 0 non-matches.

## What this run is / is not

- It establishes: an independent receiver-side implementation of the Section 5 algorithm agrees with all 15 expected outcomes at the pin, including the step at which each rejection occurs.
- It does **not** establish: conformance of any production system; behavior of the challenge-response flow over a live transport (steps 4's challenge flag is harness-supplied by the vectors); revocation over real HTTPS (the vectors supply canned responses); correctness of the vectors themselves.

## Files

- `per-case.json` — one record per vector, exactly as our verifier returned them (result, step, reason), next to the expected values.
- `input-digests.json` — sha-256 of each vector file's bytes at the pin.
- `recount.json` — our own recount from those records.
- `environment.json` — verifier digest, interpreter/library versions, OS and architecture.

## Scan statement

This run directory was scanned before publication: it contains no keys, no tokens, no credentials, no text taken from correspondence, and no absolute user paths.
