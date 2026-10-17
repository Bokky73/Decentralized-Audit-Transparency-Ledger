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

### P-21 — SupTech Feed Dispatcher Consistency Under Partial Failures

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/suptech_feeds.rs`, every dispatched regulatory telemetry batch is applied atomically: after any partial failure or mid-batch rollback, the dispatcher state (per-feed sequence numbers, pending queue, and committed cursor) is either fully advanced to the pre-batch state or fully advanced to the post-batch state — never a mixture. No feed may observe a committed cursor ahead of its own sequence number. |
| **CVL Rule** | `suptechFeedAtomicBatchApply`, `suptechFeedCursorNeverAheadOfSequence` |
| **K Claim** | `SUPTECH-1`, `SUPTECH-2` |
| **Status** | 🔲 Pending |

---

### P-22 — SupTech Feed Reordered / Duplicate Event Idempotence

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/suptech_feeds.rs`, duplicate submissions and out-of-order timestamps never corrupt feed state: a re-delivered event with an already-seen `(feed_id, sequence)` is rejected or ignored without mutating state, and events arriving out of timestamp order are either buffered or rejected but never cause the committed sequence to move backwards. |
| **CVL Rule** | `suptechFeedDuplicateRejected`, `suptechFeedSequenceMonotone` |
| **K Claim** | `SUPTECH-3`, `SUPTECH-4` |
| **Status** | 🔲 Pending |

---

### P-23 — SupTech Feed Merkle Proof and Hash-Chain Integrity After Recovery

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/suptech_feeds.rs`, after any simulated recovery (crash, restart, or replayed batch), every committed feed entry's Merkle proof verifies against the stored root and the hash chain linking consecutive entries remains intact (`entry[n].prev_hash == entry[n-1].entry_hash`). Recovery never produces a root that fails verification for a committed entry. |
| **CVL Rule** | `suptechFeedMerkleProofValid`, `suptechFeedHashChainIntactAfterRecovery` |
| **K Claim** | `SUPTECH-5`, `SUPTECH-6` |
| **Status** | 🔲 Pending |

---

### P-24 — SupTech Feed Concurrency Safety Under Multi-Actor Access

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/suptech_feeds.rs`, concurrent dispatches from multiple actors (RBAC-checked per `src/rbac.rs`) are serializable: the resulting committed state is equivalent to some sequential ordering of the accepted operations, and no interleaving loses an accepted event or double-applies a rejected one. |
| **CVL Rule** | `suptechFeedSerializableUnderConcurrency` |
| **K Claim** | `SUPTECH-7` |
| **Status** | 🔲 Pending |

---

### P-25 — CBDC Offline Voucher Double-Spend Reconciliation Consistency

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/cbdc_offline.rs`, the offline voucher reconciliation verifier never accepts two distinct vouchers that redeem the same underlying value: after reconciliation, the set of settled voucher identifiers is duplicate-free, and any voucher presented twice is flagged as a double-spend rather than settled twice. |
| **CVL Rule** | `cbdcOfflineNoDoubleSpend`, `cbdcOfflineSettledSetDuplicateFree` |
| **K Claim** | `CBDC-1`, `CBDC-2` |
| **Status** | 🔲 Pending |

---

### P-26 — CBDC Offline Voucher Reconciliation Atomicity Under Partial Failures

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/cbdc_offline.rs`, reconciliation of a batch of offline vouchers is atomic: a mid-batch rollback leaves the settled set, spent-value counters, and reconciliation cursor exactly as they were before the batch. Partial application of a batch is never observable. |
| **CVL Rule** | `cbdcOfflineReconcileAtomic`, `cbdcOfflineNoPartialBatchState` |
| **K Claim** | `CBDC-3`, `CBDC-4` |
| **Status** | 🔲 Pending |

---

### P-27 — CBDC Offline Voucher Reordered / Duplicate Submission Idempotence

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/cbdc_offline.rs`, duplicate voucher submissions and out-of-order timestamps are idempotent: re-submitting a voucher already present in the settled set does not change the settled set or spent-value counters, and out-of-order arrivals never cause a voucher to be settled before its dependencies are satisfied. |
| **CVL Rule** | `cbdcOfflineDuplicateIdempotent`, `cbdcOfflineOrderIndependentSettlement` |
| **K Claim** | `CBDC-5`, `CBDC-6` |
| **Status** | 🔲 Pending |

---

### P-28 — CBDC Offline Voucher Merkle Proof and Hash-Chain Integrity After Recovery

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/cbdc_offline.rs`, after any simulated recovery, every settled voucher's Merkle proof verifies against the stored reconciliation root and the hash chain over settled vouchers remains intact. Recovery never invalidates a previously verified proof for a settled voucher. |
| **CVL Rule** | `cbdcOfflineMerkleProofValid`, `cbdcOfflineHashChainIntactAfterRecovery` |
| **K Claim** | `CBDC-7`, `CBDC-8` |
| **Status** | 🔲 Pending |

---

### P-29 — CBDC Offline Voucher Concurrency Safety Under Multi-Actor Access

| Field | Value |
|-------|-------|
| **Category** | safety |
| **Description** | For `src/cbdc_offline.rs`, concurrent voucher submissions from multiple actors (RBAC-checked per `src/rbac.rs`) are serializable with respect to the settled set and spent-value counters: the outcome is equivalent to some sequential ordering, and no interleaving permits a double-spend that a sequential execution would have rejected. |
| **CVL Rule** | `cbdcOfflineSerializableUnderConcurrency` |
| **K Claim** | `CBDC-9` |
| **Status** | 🔲 Pending |

---

## Verification Coverage Summary

| Category | Total | Verified ✅ | Partial 🔶 | Pending 🔲 |
|----------|-------|------------|-----------|-----------|
| safety | 23 | 9 | 4 | 10 |
| access-control | 5 | 5 | 0 | 0 |
| liveness | 1 | 0 | 1 | 0 |
| **Total** | **29** | **14** | **5** | **10** |

---

## Adding New Properties

1. Write a plain-English description and add a row to the table above.
2. Add a CVL rule to `formal-verification/audit_ledger.spec`.
3. Add a K claim to `formal-verification/k-spec/audit_ledger-spec.k`.
4. Run verification (see `formal-verification/README.md`).
5. Update the **Status** field and coverage table.
