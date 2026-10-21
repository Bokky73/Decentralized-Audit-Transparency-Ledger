# Formal Verification & State Machine Invariants (`src/suptech_rules.rs`)

This specification defines the formal state machine, safety invariants, and fault-recovery
properties for the Supervisory Technology (`SupTech`) automated rule evaluation engine
(`src/suptech_rules.rs`, Issue #833).

## 1. State Space Definition

Let the contract state of `suptech_rules` be a tuple:

$$\Sigma = \langle R, L, S, \tau_{\text{last}}, \Delta_{\text{drift}}, H_{\text{tip}}, M_{\text{root}}, C \rangle$$

where:
- $R: \mathbb{N} \rightharpoonup \text{SuptechRule}$ maps `rule_id` to rule definitions.
- $L = [e_0, e_1, \dots, e_{n-1}]$ is the ordered append-only evaluation log of length $n = \text{total\_evaluations}$.
- $S \subseteq \mathbb{B}^{32}$ is the set of committed `submission_id` digests.
- $\tau_{\text{last}} \in \mathbb{N}$ is the maximum accepted `event_timestamp`.
- $\Delta_{\text{drift}} \in \mathbb{N}$ is the configured maximum out-of-order timestamp drift.
- $H_{\text{tip}} \in \mathbb{B}^{32}$ is the current SHA-256 hash-chain tip.
- $M_{\text{root}} \in \mathbb{B}^{32}$ is the binary Merkle root over leaf hashes $[e_0.\text{eval\_hash}, \dots, e_{n-1}.\text{eval\_hash}]$.
- $C: \mathbb{N} \rightharpoonup \text{RecoveryCheckpoint}$ maps `checkpoint_id` to saved state snapshots.

## 2. Safety & Consistency Invariants

### `INV-SEQ` — Contiguous Monotonic Sequence Invariant
$$\forall i \in [0, |L|): L[i].\text{sequence} = i \land \text{total\_violations} = |\{e \in L \mid \neg e.\text{compliant}\}|$$

### `INV-IDEMPOTENT` — Duplicate Submission Rejection Invariant
$$\forall i, j \in [0, |L|): i \neq j \implies L[i].\text{submission\_id} \neq L[j].\text{submission\_id}$$
$$\forall s \in S: \text{evaluate\_submission}(s) = \text{Err}(\text{DuplicateSubmission}) \land \Sigma' = \Sigma$$

### `INV-TIMESTAMP` — Bounded Out-of-Order Timestamp Invariant
$$\forall x \in \text{SubmissionInput}: x.\text{event\_timestamp} < \max(0, \tau_{\text{last}} - \Delta_{\text{drift}}) \implies \text{Err}(\text{OutOfOrderTimestamp}) \land \Sigma' = \Sigma$$

### `INV-BATCH-ATOMIC` — Atomic Mid-Batch Rollback Invariant
For any batch $B = [b_0, \dots, b_{m-1}]$, if $\exists k \in [0, m)$ such that $b_k$ violates `INV-IDEMPOTENT`, `INV-TIMESTAMP`, or references an inactive/missing rule in $R$:
$$\text{evaluate\_submission\_batch}(B) = \text{Err}(\text{BatchRollbackTriggered}) \land \Sigma' = \Sigma$$

### `INV-CRYPTO` — Hash-Chain & Merkle Soundness Invariant
- Genesis link: $L[0].\text{prev\_hash} = 0^{32}$
- Inductive link: $\forall i \in [1, |L|): L[i].\text{prev\_hash} = L[i-1].\text{eval\_hash}$
- Tip equivalence: $|L| > 0 \implies H_{\text{tip}} = L[|L|-1].\text{eval\_hash}$
- Merkle inclusion soundness: $\forall i \in [0, |L|): \text{verify\_merkle\_proof}(L[i].\text{eval\_hash}, \text{generate\_merkle\_proof}(i), M_{\text{root}}) = \text{true}$
