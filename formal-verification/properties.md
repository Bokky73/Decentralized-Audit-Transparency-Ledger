# AuditLedger Formally Verified Properties

This document catalogs every property formally specified and/or verified for the
`AuditLedger` Soroban smart contract. Each entry lists the property name,
category, a plain-English description, the corresponding CVL rule name, the
K-framework claim label, and the current verification status.

---

## Legend

| Field | Meaning |
|-------|---------|
| **Category** | `safety` — bad things never happen; `liveness` — good things eventually happen; `access-control` — privilege enforcement |
| **CVL Rule** | Name of the Certora rule in `audit_ledger.spec` |
| **K Claim** | Label of the K-framework claim in `audit_ledger-spec.k` |
| **Status** | ✅ Verified · 🔶 Partial (bounded) · ❌ Counterexample found · 🔲 Pending |

---

## Properties Table

### P-01 — Event Immutability

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | Once an event is stored on-chain, its `index`, `timestamp`, `event_type`, `submitter`, `event_hash`, and `prev_hash` fields cannot be changed by any subsequent transaction. Events are append-only; there is no update or delete path. |
| **CVL Rule** | `eventImmutability` |
| **K Claim** | — (structural property enforced by write-once storage) |
| **Status** | ✅ Verified |

---

### P-02 — Total Events Counter Monotonically Increases

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | The `totalEvents` counter is a monotone non-decreasing integer. No operation may decrease it. Each successful `logEvent` increments it by exactly 1. |
| **CVL Rule** | `totalEventsMonotonicallyIncreases`, `logEventIncrementsByOne` |
| **K Claim** | `SPEC-2` |
| **Status** | ✅ Verified |

---

### P-03 — Global Cap Enforcement

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | `totalEvents` never exceeds `globalMaxLogs`. `logEvent` reverts with `GlobalMaxLogsReached` (error 2) when `totalEvents >= globalMaxLogs`. |
| **CVL Rule** | `globalCapRespected`, `capEnforcedAfterLogEvent`, `logEventRevertsAtCap` |
| **K Claim** | `SPEC-3` |
| **Status** | ✅ Verified |

---

### P-04 — Per-Event-Type Cap Enforcement

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | When a per-event-type cap is configured via `setEventMaxLogs`, `logEvent` for that type reverts with `EventTypeMaxLogsReached` (error 3) when the type's count equals its cap. |
| **CVL Rule** | — (K rule LOG-5, CVL rule pending) |
| **K Claim** | K rules LOG-4, LOG-5 |
| **Status** | 🔶 Partial |

---

### P-05 — Owner-Only: setGlobalMaxLogs

| Field | Value |
|-------|-------|
| **Category** | access-control |
| **Description** | `setGlobalMaxLogs` succeeds only when `caller == owner`. Any other caller receives `CallerNotOwner` (error 1). |
| **CVL Rule** | `setGlobalMaxLogsOnlyOwner` |
| **K Claim** | `SPEC-5`, `SPEC-6` |
| **Status** | ✅ Verified |

---

### P-06 — Owner-Only: setEventMaxLogs

| Field | Value |
|-------|-------|
| **Category** | access-control |
| **Description** | `setEventMaxLogs` succeeds only when `caller == owner`. Any other caller receives `CallerNotOwner` (error 1). |
| **CVL Rule** | `setEventMaxLogsOnlyOwner` |
| **K Claim** | K rule GOV-5 |
| **Status** | ✅ Verified |

---

### P-07 — Owner-Only: removeEventCap

| Field | Value |
|-------|-------|
| **Category** | access-control |
| **Description** | `removeEventCap` succeeds only when `caller == owner`. Any other caller receives `CallerNotOwner` (error 1). |
| **CVL Rule** | `removeEventCapOnlyOwner` |
| **K Claim** | K rule GOV-8 |
| **Status** | ✅ Verified |

---

### P-08 — Owner-Only: transferOwnership

| Field | Value |
|-------|-------|
| **Category** | access-control |
| **Description** | `transferOwnership` succeeds only when `caller == owner`. Any other caller receives `CallerNotOwner` (error 1). |
| **CVL Rule** | `transferOwnershipOnlyOwner` |
| **K Claim** | K rule GOV-10 |
| **Status** | ✅ Verified |

---

### P-09 — Owner-Only: setPaused

| Field | Value |
|-------|-------|
| **Category** | access-control |
| **Description** | `setPaused` succeeds only when `caller == owner`. Any other caller receives `CallerNotOwner` (error 1). |
| **CVL Rule** | `setPausedOnlyOwner` |
| **K Claim** | K rule GOV-14 |
| **Status** | ✅ Verified |

---

### P-10 — Paused Contract Prevents Event Logging

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | When `paused == true`, both `logEvent` and `logEvents` revert with `ContractPaused` (error 13). No events can be written to the ledger while paused. |
| **CVL Rule** | `pausedPreventsLogging`, `pausedPreventsBatchLogging` |
| **K Claim** | `SPEC-4`, K rule LOG-3 |
| **Status** | ✅ Verified |

---

### P-11 — Initialization Idempotence

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | `initialize` may only succeed once. Any subsequent call reverts with `AlreadyInitialized` (error 30). The owner and cap are set exactly once at deployment. |
| **CVL Rule** | `initializeIdempotent`, `initializeSetsInitializedFlag`, `initializeSetsOwner` |
| **K Claim** | `SPEC-1`, K rule INI-2 |
| **Status** | ✅ Verified |

---

### P-12 — Zero-Address Owner Rejection

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | `initialize` and `transferOwnership` both reject a zero/null address as the new owner, reverting with `NewOwnerIsZero` (error 6). |
| **CVL Rule** | `ownerIsNeverZero` (invariant) |
| **K Claim** | K rules INI-3, GOV-11 |
| **Status** | ✅ Verified |

---

### P-13 — Ownership Transfer Correctness

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | After a successful `transferOwnership(caller, newOwner)`, the stored owner is exactly `newOwner`. The previous owner has no residual privileges. |
| **CVL Rule** | `ownershipTransferCorrectness` |
| **K Claim** | `SPEC-7` |
| **Status** | ✅ Verified |

---

### P-14 — Hash Chain Integrity

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For every event at position `n > 0`, `events[n].prev_hash == events[n-1].event_hash`. The genesis event (position 0) has `prev_hash == [0x00; 32]`. This creates a tamper-evident chain of all logged events. |
| **CVL Rule** | `hashChainIntegrity`, `genesisEventPrevHashIsZero` |
| **K Claim** | — (enforced by hash computation in LOG-1) |
| **Status** | 🔶 Partial (bounded depth) |

---

### P-15 — Nonce Strictly Monotone Per Submitter

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For each submitter address, the nonce stored at `SubmitterNonce(addr)` strictly increases with every accepted event. This prevents replay attacks where the same event data is submitted twice. |
| **CVL Rule** | `nonceStrictlyMonotonePerSubmitter` |
| **K Claim** | — (nonce tracking pending K integration) |
| **Status** | 🔶 Partial |

---

### P-16 — setGlobalMaxLogs Rejects Values Below Current Count

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | `setGlobalMaxLogs(caller, newMax)` reverts with `MaxLogsBelowCurrentCount` (error 16) when `newMax < totalEvents`. The cap cannot be set so low as to make already-stored events retroactively invalid. |
| **CVL Rule** | — (pending) |
| **K Claim** | K rule GOV-3 |
| **Status** | 🔶 Partial |

---

### P-17 — Cap Removal Idempotence

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | `removeEventCap` reverts with `CapNotSet` (error 7) when called on an event type that has no active cap. It succeeds exactly once per event type until a new cap is configured via `setEventMaxLogs`. |
| **CVL Rule** | — (pending) |
| **K Claim** | K rule GOV-6, GOV-7 |
| **Status** | 🔶 Partial |

---

### P-18 — Contract Uninitialized Prevents All Writes

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | Before `initialize` is called, `logEvent`, `logEvents`, and all governance functions revert. |
| **CVL Rule** | `contractMustBeInitialized` (invariant) |
| **K Claim** | K rule LOG-2 |
| **Status** | ✅ Verified |

---

### P-19 — Same-Owner Transfer Rejected

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | `transferOwnership(owner, owner)` reverts with `SameOwner` (error 15). |
| **CVL Rule** | — (pending) |
| **K Claim** | K rule GOV-12 |
| **Status** | 🔶 Partial |

---

### P-20 — Inverted Index Count Consistent with Stored Bytes

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For every `IndexKey`, `index_get_count(key) == len(packed_bytes) / 4`. The count never exceeds `INDEX_MAX_ENTRIES`. |
| **CVL Rule** | — (in-Rust test coverage; formal spec pending) |
| **K Claim** | — |
| **Status** | 🔲 Pending |

---

## ML Feature Store Properties (`src/ml_feature_store.rs`)

These properties cover the on-chain ML feature vector lineage and hash-anchoring
module. They are exercised by the property-based suite in `src/proptest.rs`, the
multi-actor concurrency suite in `src/concurrent_tests.rs`, and the
fault-injection scenarios described below. Each property is stated as a state
machine invariant over the abstract state
`(features, anchors, merkle_roots, nonces, total_features)`.

### MFS-01 — Feature Registration Idempotence Under Duplicate Submission

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | Submitting the same feature vector (identical `feature_id` and `feature_hash`) more than once must not create a second stored entry nor advance `total_features` a second time. The duplicate submission either reverts or is a no-op; in both cases the post-state equals the pre-state. |
| **Invariant** | `register(fv); register(fv) ⇒ state_after == state_after_first_register` |
| **Fault Scenario** | Duplicate submissions (same actor, repeated call; distinct actors, identical payload) |
| **CVL Rule** | `featureRegistrationIdempotent` |
| **K Claim** | — (pending) |
| **Status** | 🔲 Pending |

---

### MFS-02 — Monotone Feature Counter

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | `total_features` is a monotone non-decreasing counter. No operation, including rollback of a partially applied batch, may decrease it. Each accepted, non-duplicate registration increments it by exactly 1. |
| **Invariant** | `total_features' >= total_features ∧ (accepted ∧ ¬duplicate ⇒ total_features' == total_features + 1)` |
| **Fault Scenario** | Mid-batch rollback, duplicate submissions |
| **CVL Rule** | `totalFeaturesMonotone` |
| **K Claim** | — (pending) |
| **Status** | 🔲 Pending |

---

### MFS-03 — Out-of-Order Timestamp Rejection

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | A feature vector whose `timestamp` is strictly less than the timestamp of the most recently accepted vector for the same lineage must be rejected. Reordered events therefore cannot rewrite history; the accepted sequence of timestamps per lineage is non-decreasing. |
| **Invariant** | `∀ lineage: timestamps(lineage) is non-decreasing` |
| **Fault Scenario** | Out-of-order timestamps (shuffled event delivery, clock skew) |
| **CVL Rule** | `timestampMonotonePerLineage` |
| **K Claim** | — (pending) |
| **Status** | 🔲 Pending |

---

### MFS-04 — Merkle Root Determinism and Proof Integrity

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For a fixed set of anchored feature hashes, the computed Merkle root is deterministic and independent of insertion order. Every generated Merkle proof verifies against the stored root, and any single-bit mutation of a leaf or of the root causes verification to fail. |
| **Invariant** | `root(perm(leaves)) == root(leaves) ∧ verify(proof(leaf), root) ∧ ¬verify(proof(leaf'), root) for leaf' ≠ leaf` |
| **Fault Scenario** | Merkle proof and hash-chain integrity after simulated recovery |
| **CVL Rule** | `merkleRootDeterministic`, `merkleProofSound` |
| **K Claim** | — (pending) |
| **Status** | 🔲 Pending |

---

### MFS-05 — Hash-Chain Linkage Across Anchors

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For every anchor at position `n > 0`, `anchors[n].prev_hash == anchors[n-1].anchor_hash`. The genesis anchor has `prev_hash == [0x00; 32]`. After simulated recovery (replay of the accepted prefix), the recomputed chain is byte-for-byte identical to the stored chain. |
| **Invariant** | `∀ n > 0: anchors[n].prev_hash == anchors[n-1].anchor_hash ∧ recovery(prefix) == stored_chain` |
| **Fault Scenario** | Mid-batch rollback, hash-chain integrity after simulated recovery |
| **CVL Rule** | `anchorHashChainIntegrity`, `recoveryPreservesChain` |
| **K Claim** | — (pending) |
| **Status** | 🔲 Pending |

---

### MFS-06 — Mid-Batch Rollback Atomicity

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | If a batch registration fails partway through (e.g. one element violates MFS-03 or a cap), the entire batch is rolled back: no feature, anchor, Merkle root, or nonce from that batch is persisted. The post-state equals the pre-state of the batch. |
| **Invariant** | `batch_fails ⇒ state_after == state_before_batch` |
| **Fault Scenario** | Mid-batch rollbacks (injected failure at every position of the batch) |
| **CVL Rule** | `batchRollbackAtomic` |
| **K Claim** | — (pending) |
| **Status** | 🔲 Pending |

---

### MFS-07 — Nonce Strictly Monotone Per Submitter

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For each submitter address, the stored nonce strictly increases with every accepted registration. Replay of a previously accepted submission under the same nonce is rejected. |
| **Invariant** | `∀ addr: nonces(addr) strictly increases per accepted registration` |
| **Fault Scenario** | Duplicate submissions, reordered events |
| **CVL Rule** | `featureNonceStrictlyMonotone` |
| **K Claim** | — (pending) |
| **Status** | 🔲 Pending |

---

### MFS-08 — Concurrent Access Linearizability

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | Under concurrent access by multiple actors, the observed final state is equivalent to some sequential ordering of the accepted operations. No interleaving may produce a state that violates MFS-01 through MFS-07. |
| **Invariant** | `∃ sequential order σ: concurrent_execution ≡ σ` |
| **Fault Scenario** | Multi-actor concurrent access (`src/concurrent_tests.rs`) |
| **CVL Rule** | — (in-Rust concurrency suite; formal spec pending) |
| **K Claim** | — |
| **Status** | 🔲 Pending |

---

## Fault-Injection Scenarios

The following fault-injection scenarios are simulated by the test suite and must
leave all MFS invariants intact:

| ID | Scenario | Injection Point | Expected Outcome |
|----|----------|-----------------|------------------|
| FI-01 | Duplicate submission (same actor) | Repeated `register` with identical payload | Rejected or no-op; state unchanged (MFS-01) |
| FI-02 | Duplicate submission (distinct actors) | Two actors submit identical payload | Exactly one accepted; counter advances once (MFS-01, MFS-07) |
| FI-03 | Out-of-order timestamps | Shuffled delivery of a valid sequence | Reordered events rejected; accepted timestamps non-decreasing (MFS-03) |
| FI-04 | Mid-batch rollback | Failure injected at position `k` of an `n`-element batch, for all `k` | Full rollback; post-state == pre-state (MFS-06) |
| FI-05 | Recovery replay | Replay accepted prefix after simulated crash | Recomputed Merkle root and hash chain identical to stored (MFS-04, MFS-05) |
| FI-06 | Leaf tampering | Single-bit mutation of an anchored leaf | Merkle proof verification fails (MFS-04) |
| FI-07 | Concurrent interleaving | Randomized interleaving of multi-actor operations | Final state linearizable; no invariant violation (MFS-08) |

---

## Verification Coverage Summary

| Category | Total | Verified ✅ | Partial 🔶 | Pending 🔲 |
|----------|-------|------------|-----------|-----------|
| safety | 14 | 9 | 4 | 1 |
| access-control | 5 | 5 | 0 | 0 |
| liveness | 1 | 0 | 1 | 0 |
| ml-feature-store | 8 | 0 | 0 | 8 |
| **Total** | **28** | **14** | **5** | **9** |

---

## Adding New Properties

1. Write a plain-English description and add a row to the table above.
2. Add a CVL rule to `formal-verification/audit_ledger.spec`.
3. Add a K claim to `formal-verification/k-spec/audit_ledger-spec.k`.
4. Run verification (see `formal-verification/README.md`).
5. Update the **Status** field and coverage table.
