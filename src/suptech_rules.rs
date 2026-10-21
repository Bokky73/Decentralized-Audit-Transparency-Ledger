//! # Supervisory Technology (SupTech) Automated Rule Evaluation Engine (`suptech_rules`)
//!
//! Provides deterministic, tamper-evident supervisory compliance rule evaluation, atomic batch
//! processing with mid-batch rollback guarantees, duplicate submission protection, out-of-order
//! timestamp validation, hash-chain linking, Merkle inclusion proof generation/verification, and
//! checkpoint recovery (Issue #833).
//!
//! ## Core State Machine Invariants
//!
//! 1. **Contiguous Monotonic Evaluation Log (`INV-SEQ`)**: Committed evaluations are indexed
//!    contiguously in `0..total_evaluations`. Failed or rolled-back operations never advance
//!    the sequence counter.
//! 2. **Strict Idempotency (`INV-IDEMPOTENT`)**: Every committed `submission_id` is recorded
//!    once. Subsequent single or batch submissions carrying an already-committed `submission_id`
//!    are rejected with [`SuptechError::DuplicateSubmission`].
//! 3. **Bounded Timestamp Ordering (`INV-TIMESTAMP`)**: Any submission whose `event_timestamp`
//!    falls behind `last_accepted_timestamp.saturating_sub(max_drift_seconds)` is rejected with
//!    [`SuptechError::OutOfOrderTimestamp`].
//! 4. **Atomic Batch Rollback (`INV-BATCH-ATOMIC`)**: In [`evaluate_submission_batch`], if item
//!    `k` (`0 <= k < batch.len()`) fails validation, no partial state from `0..k` is committed;
//!    `total_evaluations`, `chain_tip_hash`, `merkle_root`, and `violation_count` remain identical
//!    to their pre-batch values.
//! 5. **Cryptographic Hash-Chain & Merkle Soundness (`INV-CRYPTO`)**: Every committed evaluation
//!    links `prev_hash` to the prior record's `eval_hash`, and its leaf digest is verifiable
//!    against the current `merkle_root` via [`verify_merkle_proof`].

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Bytes, BytesN, Env, Vec};

use crate::rbac::{
    authorize_mutation, compute_state_diff_digest, record_audit_event, u32_le_bytes, u64_le_bytes,
    Permission,
};

/// Stable error codes for the SupTech rule evaluation engine (Issue #833).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SuptechError {
    /// Caller failed RBAC authorization or DID status check.
    RbacRejected = 2001,
    /// Referenced supervisory rule does not exist or is inactive.
    RuleNotFoundOrInactive = 2002,
    /// Submission ID has already been evaluated and committed.
    DuplicateSubmission = 2003,
    /// Submission timestamp violates the configured out-of-order drift bound.
    OutOfOrderTimestamp = 2004,
    /// Invalid rule configuration parameters.
    InvalidRuleConfig = 2005,
    /// Atomic batch evaluation aborted and rolled back due to an invalid item.
    BatchRollbackTriggered = 2006,
    /// Referenced recovery checkpoint does not exist.
    CheckpointNotFound = 2007,
    /// Evaluation record index is out of bounds.
    EvaluationNotFound = 2008,
}

/// Storage keys for the SupTech automated rule evaluation engine.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuptechDataKey {
    /// Supervisory rule definition (`rule_id -> SuptechRule`).
    Rule(u32),
    /// Total committed rule evaluations.
    TotalEvaluations,
    /// Total committed rule violations.
    TotalViolations,
    /// Evaluation record by sequential index (`seq -> EvaluationRecord`).
    EvaluationByIndex(u32),
    /// Idempotency lookup (`submission_id -> seq`).
    SubmissionSeen(BytesN<32>),
    /// Latest accepted event timestamp for monotonic drift enforcement.
    LastAcceptedTimestamp,
    /// Maximum allowed out-of-order timestamp drift in seconds.
    MaxTimestampDrift,
    /// Latest hash-chain tip (`BytesN<32>`).
    ChainTipHash,
    /// Current Merkle root over all committed `EvaluationRecord` leaf hashes.
    MerkleRoot,
    /// Packed 32-byte leaf hashes (`seq * 32..(seq + 1) * 32`) for single-read Merkle tree construction.
    LeafDigests,
    /// Saved state checkpoint (`checkpoint_id -> RecoveryCheckpoint`).
    Checkpoint(u32),
}

/// Supervisory compliance rule definition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuptechRule {
    /// Unique numeric rule identifier.
    pub rule_id: u32,
    /// Maximum allowed transaction/metric amount before triggering a violation.
    pub max_amount: u64,
    /// Maximum allowed risk score (`0..=10_000` bps).
    pub max_risk_bps: u32,
    /// Whether this rule is currently active.
    pub active: bool,
    /// Principal that configured the rule.
    pub updated_by: Address,
    /// Ledger timestamp of last update.
    pub updated_at: u64,
}

/// Input payload for evaluating a single supervisory event submission.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionInput {
    /// Unique 32-byte submission identifier used for idempotency.
    pub submission_id: BytesN<32>,
    /// Target rule ID to evaluate against.
    pub rule_id: u32,
    /// Reported transaction/exposure amount.
    pub amount: u64,
    /// Reported risk score in basis points (`0..=10_000`).
    pub risk_bps: u32,
    /// Event timestamp reported by the submitter.
    pub event_timestamp: u64,
}

/// Tamper-evident evaluation record committed to the SupTech ledger.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationRecord {
    /// Sequential 0-based evaluation index.
    pub sequence: u32,
    /// Unique submission identifier.
    pub submission_id: BytesN<32>,
    /// Evaluated rule ID.
    pub rule_id: u32,
    /// Reported amount.
    pub amount: u64,
    /// Reported risk score in basis points.
    pub risk_bps: u32,
    /// Event timestamp.
    pub event_timestamp: u64,
    /// `true` if compliant, `false` if rule thresholds were breached.
    pub compliant: bool,
    /// Authenticated actor that submitted the evaluation.
    pub actor: Address,
    /// SHA-256 hash of the previous evaluation record (`[0u8; 32]` for genesis).
    pub prev_hash: BytesN<32>,
    /// SHA-256 hash of this evaluation record (also serves as its Merkle leaf hash).
    pub eval_hash: BytesN<32>,
}

/// Sibling node in a binary Merkle inclusion proof.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProofStep {
    /// Sibling 32-byte digest at this tree level.
    pub sibling: BytesN<32>,
    /// `true` if `sibling` is on the left (`H(sibling || current)`), `false` if on the right (`H(current || sibling)`).
    pub sibling_is_left: bool,
}

/// Snapshot checkpoint used to verify deterministic state recovery after simulated chaos faults.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCheckpoint {
    /// Checkpoint identifier.
    pub checkpoint_id: u32,
    /// Committed evaluation count at checkpoint creation.
    pub total_evaluations: u32,
    /// Committed violation count at checkpoint creation.
    pub total_violations: u32,
    /// Last accepted event timestamp at checkpoint creation.
    pub last_accepted_timestamp: u64,
    /// Hash-chain tip at checkpoint creation.
    pub chain_tip_hash: BytesN<32>,
    /// Merkle root at checkpoint creation.
    pub merkle_root: BytesN<32>,
}

/// Configure the maximum allowed out-of-order timestamp drift in seconds.
/// Requires [`Permission::ConfigureShardThreshold`] (`Role::CapacityPlanner`+).
pub fn configure_timestamp_drift(
    env: &Env,
    caller: &Address,
    max_drift_seconds: u64,
) -> Result<(), SuptechError> {
    let op = symbol_short!("sup_drft");
    let pre = u64_le_bytes(env, get_max_timestamp_drift(env));
    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::ConfigureShardThreshold,
        &pre,
    )
    .map_err(|_| SuptechError::RbacRejected)?;

    env.storage()
        .instance()
        .set(&SuptechDataKey::MaxTimestampDrift, &max_drift_seconds);

    let post = u64_le_bytes(env, max_drift_seconds);
    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Permission::ConfigureShardThreshold.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );
    Ok(())
}

/// Register or update a supervisory compliance rule.
/// Requires [`Permission::ConfigureShardThreshold`] (`Role::CapacityPlanner`+).
pub fn upsert_suptech_rule(
    env: &Env,
    caller: &Address,
    rule_id: u32,
    max_amount: u64,
    max_risk_bps: u32,
    active: bool,
) -> Result<SuptechRule, SuptechError> {
    let op = symbol_short!("sup_rule");
    let pre = Bytes::from_slice(env, b"suptech:rule:pre");
    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::ConfigureShardThreshold,
        &pre,
    )
    .map_err(|_| SuptechError::RbacRejected)?;

    if max_amount == 0 || max_risk_bps == 0 || max_risk_bps > 10_000 {
        return Err(SuptechError::InvalidRuleConfig);
    }

    let ts = env.ledger().timestamp();
    let rule = SuptechRule {
        rule_id,
        max_amount,
        max_risk_bps,
        active,
        updated_by: caller.clone(),
        updated_at: ts,
    };

    env.storage()
        .instance()
        .set(&SuptechDataKey::Rule(rule_id), &rule);

    let mut post = Bytes::new(env);
    post.append(&u32_le_bytes(env, rule_id));
    post.append(&u64_le_bytes(env, max_amount));
    post.append(&u32_le_bytes(env, max_risk_bps));

    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Permission::ConfigureShardThreshold.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(rule)
}

/// Evaluate and commit a single supervisory submission.
/// Requires [`Permission::RecordShardTelemetry`] (`Role::Operator`+).
pub fn evaluate_submission(
    env: &Env,
    caller: &Address,
    input: SubmissionInput,
) -> Result<EvaluationRecord, SuptechError> {
    let op = symbol_short!("sup_eval");
    let pre = u32_le_bytes(env, total_evaluations(env));
    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::RecordShardTelemetry,
        &pre,
    )
    .map_err(|_| SuptechError::RbacRejected)?;

    let record = validate_and_apply_single(env, caller, &input)?;

    let post = u32_le_bytes(env, record.sequence + 1);
    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Permission::RecordShardTelemetry.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(record)
}

/// Atomically evaluate a batch of supervisory submissions.
///
/// Pre-validates the entire batch (including intra-batch duplicates, historical duplicates,
/// active rule existence, and timestamp drift across the simulated batch progression) BEFORE
/// mutating state. If any item in `inputs` fails validation, the entire batch is rolled back
/// with zero state mutations.
pub fn evaluate_submission_batch(
    env: &Env,
    caller: &Address,
    inputs: Vec<SubmissionInput>,
) -> Result<Vec<EvaluationRecord>, SuptechError> {
    let op = symbol_short!("sup_btch");
    let pre = u32_le_bytes(env, total_evaluations(env));
    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::RecordShardTelemetry,
        &pre,
    )
    .map_err(|_| SuptechError::RbacRejected)?;

    let drift = get_max_timestamp_drift(env);
    let mut simulated_last_ts = last_accepted_timestamp(env);

    // Phase 1: Full pre-validation of all items (atomic rollback guarantee)
    for i in 0..inputs.len() {
        let item = inputs.get(i).unwrap();

        // Check historical duplicate
        if is_submission_seen(env, &item.submission_id) {
            return Err(SuptechError::BatchRollbackTriggered);
        }

        // Check intra-batch duplicate against earlier items in the same batch
        for j in 0..i {
            let earlier = inputs.get(j).unwrap();
            if earlier.submission_id == item.submission_id {
                return Err(SuptechError::BatchRollbackTriggered);
            }
        }

        // Check rule exists and is active
        match get_suptech_rule(env, item.rule_id) {
            Some(r) if r.active => {}
            _ => return Err(SuptechError::BatchRollbackTriggered),
        }

        // Check timestamp ordering against simulated progression
        if item.event_timestamp < simulated_last_ts.saturating_sub(drift) {
            return Err(SuptechError::BatchRollbackTriggered);
        }
        if item.event_timestamp > simulated_last_ts {
            simulated_last_ts = item.event_timestamp;
        }
    }

    // Phase 2: Commit all validated items
    let mut results = Vec::new(env);
    for i in 0..inputs.len() {
        let item = inputs.get(i).unwrap();
        let rec = validate_and_apply_single(env, caller, &item)?;
        results.push_back(rec);
    }

    let post = u32_le_bytes(env, total_evaluations(env));
    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Permission::RecordShardTelemetry.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(results)
}

/// Create a tamper-evident recovery checkpoint capturing current hash-chain and Merkle state.
/// Requires [`Permission::OverrideCapacityPolicy`] (`Role::Auditor`+).
pub fn create_recovery_checkpoint(
    env: &Env,
    caller: &Address,
    checkpoint_id: u32,
) -> Result<RecoveryCheckpoint, SuptechError> {
    let op = symbol_short!("sup_ckpt");
    let pre = u32_le_bytes(env, total_evaluations(env));
    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::OverrideCapacityPolicy,
        &pre,
    )
    .map_err(|_| SuptechError::RbacRejected)?;

    let cp = RecoveryCheckpoint {
        checkpoint_id,
        total_evaluations: total_evaluations(env),
        total_violations: total_violations(env),
        last_accepted_timestamp: last_accepted_timestamp(env),
        chain_tip_hash: chain_tip_hash(env),
        merkle_root: current_merkle_root(env),
    };

    env.storage()
        .instance()
        .set(&SuptechDataKey::Checkpoint(checkpoint_id), &cp);

    let post = u32_le_bytes(env, checkpoint_id);
    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Permission::OverrideCapacityPolicy.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(cp)
}

/// Restore the SupTech evaluation ledger to a previously saved [`RecoveryCheckpoint`],
/// pruning any uncommitted/post-checkpoint entries and recomputing the Merkle root.
/// Requires [`Permission::OverrideCapacityPolicy`] (`Role::Auditor`+).
pub fn recover_from_checkpoint(
    env: &Env,
    caller: &Address,
    checkpoint_id: u32,
) -> Result<RecoveryCheckpoint, SuptechError> {
    let op = symbol_short!("sup_rcvr");
    let pre = u32_le_bytes(env, total_evaluations(env));
    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::OverrideCapacityPolicy,
        &pre,
    )
    .map_err(|_| SuptechError::RbacRejected)?;

    let cp: RecoveryCheckpoint = env
        .storage()
        .instance()
        .get(&SuptechDataKey::Checkpoint(checkpoint_id))
        .ok_or(SuptechError::CheckpointNotFound)?;

    let current_total = total_evaluations(env);
    for seq in cp.total_evaluations..current_total {
        if let Some(rec) = get_evaluation_by_index(env, seq) {
            env.storage()
                .persistent()
                .remove(&SuptechDataKey::SubmissionSeen(rec.submission_id));
            env.storage()
                .persistent()
                .remove(&SuptechDataKey::EvaluationByIndex(seq));
        }
    }

    env.storage()
        .instance()
        .set(&SuptechDataKey::TotalEvaluations, &cp.total_evaluations);
    env.storage()
        .instance()
        .set(&SuptechDataKey::TotalViolations, &cp.total_violations);
    env.storage().instance().set(
        &SuptechDataKey::LastAcceptedTimestamp,
        &cp.last_accepted_timestamp,
    );
    env.storage()
        .instance()
        .set(&SuptechDataKey::ChainTipHash, &cp.chain_tip_hash);
    env.storage()
        .instance()
        .set(&SuptechDataKey::MerkleRoot, &cp.merkle_root);

    let packed_leaves: Bytes = env
        .storage()
        .persistent()
        .get(&SuptechDataKey::LeafDigests)
        .unwrap_or_else(|| Bytes::new(env));
    let target_byte_len = cp.total_evaluations * 32;
    if packed_leaves.len() > target_byte_len {
        let truncated = packed_leaves.slice(0..target_byte_len);
        env.storage()
            .persistent()
            .set(&SuptechDataKey::LeafDigests, &truncated);
    }

    let post = u32_le_bytes(env, cp.total_evaluations);
    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Permission::OverrideCapacityPolicy.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(cp)
}

/// Verify the full hash chain of committed SupTech evaluation records (`0..total_evaluations`).
pub fn verify_suptech_hash_chain(env: &Env) -> bool {
    let total = total_evaluations(env);
    let mut expected_prev = BytesN::from_array(env, &[0u8; 32]);

    for seq in 0..total {
        let rec = match get_evaluation_by_index(env, seq) {
            Some(r) => r,
            None => return false,
        };
        if rec.sequence != seq || rec.prev_hash != expected_prev {
            return false;
        }
        let recomputed = compute_evaluation_hash(
            env,
            rec.sequence,
            &rec.submission_id,
            rec.rule_id,
            rec.amount,
            rec.risk_bps,
            rec.event_timestamp,
            rec.compliant,
            &rec.prev_hash,
        );
        if rec.eval_hash != recomputed {
            return false;
        }
        expected_prev = rec.eval_hash;
    }

    expected_prev == chain_tip_hash(env)
}

/// Generate a binary Merkle inclusion proof for the evaluation record at `target_index`.
pub fn generate_merkle_proof(
    env: &Env,
    target_index: u32,
) -> Result<Vec<MerkleProofStep>, SuptechError> {
    let total = total_evaluations(env);
    if target_index >= total {
        return Err(SuptechError::EvaluationNotFound);
    }

    let mut level = load_leaf_hashes(env, total);

    let mut proof: Vec<MerkleProofStep> = Vec::new(env);
    let mut idx = target_index;

    while level.len() > 1 {
        let len = level.len();
        let sibling_idx = if idx % 2 == 0 {
            if idx + 1 < len {
                idx + 1
            } else {
                idx
            }
        } else {
            idx - 1
        };

        let sibling = level.get(sibling_idx).unwrap();
        let sibling_is_left = idx % 2 == 1;
        proof.push_back(MerkleProofStep {
            sibling,
            sibling_is_left,
        });

        let mut next_level: Vec<BytesN<32>> = Vec::new(env);
        let mut i = 0;
        while i < len {
            let left = level.get(i).unwrap();
            let right = if i + 1 < len {
                level.get(i + 1).unwrap()
            } else {
                left.clone()
            };
            next_level.push_back(hash_pair(env, &left, &right));
            i += 2;
        }

        level = next_level;
        idx /= 2;
    }

    Ok(proof)
}

/// Verify a binary Merkle inclusion proof for `leaf_hash` against `expected_root`.
pub fn verify_merkle_proof(
    env: &Env,
    leaf_hash: &BytesN<32>,
    proof: &Vec<MerkleProofStep>,
    expected_root: &BytesN<32>,
) -> bool {
    let mut current = leaf_hash.clone();
    for i in 0..proof.len() {
        let step = proof.get(i).unwrap();
        current = if step.sibling_is_left {
            hash_pair(env, &step.sibling, &current)
        } else {
            hash_pair(env, &current, &step.sibling)
        };
    }
    &current == expected_root
}

/// Read a [`SuptechRule`] by `rule_id`.
pub fn get_suptech_rule(env: &Env, rule_id: u32) -> Option<SuptechRule> {
    env.storage().instance().get(&SuptechDataKey::Rule(rule_id))
}

/// Read an [`EvaluationRecord`] by its sequential index.
pub fn get_evaluation_by_index(env: &Env, sequence: u32) -> Option<EvaluationRecord> {
    env.storage()
        .persistent()
        .get(&SuptechDataKey::EvaluationByIndex(sequence))
}

/// Check if a `submission_id` has already been committed.
pub fn is_submission_seen(env: &Env, submission_id: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&SuptechDataKey::SubmissionSeen(submission_id.clone()))
}

/// Return the total count of committed evaluations.
pub fn total_evaluations(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&SuptechDataKey::TotalEvaluations)
        .unwrap_or(0)
}

/// Return the total count of committed non-compliant evaluations (violations).
pub fn total_violations(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&SuptechDataKey::TotalViolations)
        .unwrap_or(0)
}

/// Return the latest accepted event timestamp.
pub fn last_accepted_timestamp(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&SuptechDataKey::LastAcceptedTimestamp)
        .unwrap_or(0)
}

/// Return the configured maximum out-of-order timestamp drift in seconds (default `0`).
pub fn get_max_timestamp_drift(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&SuptechDataKey::MaxTimestampDrift)
        .unwrap_or(0)
}

/// Return the current hash-chain tip (`[0u8; 32]` if empty).
pub fn chain_tip_hash(env: &Env) -> BytesN<32> {
    env.storage()
        .instance()
        .get(&SuptechDataKey::ChainTipHash)
        .unwrap_or_else(|| BytesN::from_array(env, &[0u8; 32]))
}

/// Return the current Merkle root over all committed evaluations (`[0u8; 32]` if empty).
pub fn current_merkle_root(env: &Env) -> BytesN<32> {
    let total = total_evaluations(env);
    let root = recompute_merkle_root(env, total);
    env.storage()
        .instance()
        .set(&SuptechDataKey::MerkleRoot, &root);
    root
}

fn validate_and_apply_single(
    env: &Env,
    caller: &Address,
    input: &SubmissionInput,
) -> Result<EvaluationRecord, SuptechError> {
    if is_submission_seen(env, &input.submission_id) {
        return Err(SuptechError::DuplicateSubmission);
    }

    let rule = match get_suptech_rule(env, input.rule_id) {
        Some(r) if r.active => r,
        _ => return Err(SuptechError::RuleNotFoundOrInactive),
    };

    let last_ts = last_accepted_timestamp(env);
    let drift = get_max_timestamp_drift(env);
    if input.event_timestamp < last_ts.saturating_sub(drift) {
        return Err(SuptechError::OutOfOrderTimestamp);
    }

    let seq = total_evaluations(env);
    let prev_hash = chain_tip_hash(env);
    let compliant = input.amount <= rule.max_amount && input.risk_bps <= rule.max_risk_bps;

    let eval_hash = compute_evaluation_hash(
        env,
        seq,
        &input.submission_id,
        input.rule_id,
        input.amount,
        input.risk_bps,
        input.event_timestamp,
        compliant,
        &prev_hash,
    );

    let record = EvaluationRecord {
        sequence: seq,
        submission_id: input.submission_id.clone(),
        rule_id: input.rule_id,
        amount: input.amount,
        risk_bps: input.risk_bps,
        event_timestamp: input.event_timestamp,
        compliant,
        actor: caller.clone(),
        prev_hash,
        eval_hash: eval_hash.clone(),
    };

    env.storage()
        .persistent()
        .set(&SuptechDataKey::EvaluationByIndex(seq), &record);
    env.storage().persistent().set(
        &SuptechDataKey::SubmissionSeen(input.submission_id.clone()),
        &seq,
    );
    env.storage()
        .instance()
        .set(&SuptechDataKey::TotalEvaluations, &(seq + 1));

    if !compliant {
        let v = total_violations(env);
        env.storage()
            .instance()
            .set(&SuptechDataKey::TotalViolations, &(v + 1));
    }

    if input.event_timestamp > last_ts {
        env.storage().instance().set(
            &SuptechDataKey::LastAcceptedTimestamp,
            &input.event_timestamp,
        );
    }

    env.storage()
        .instance()
        .set(&SuptechDataKey::ChainTipHash, &eval_hash);

    let mut packed_leaves: Bytes = env
        .storage()
        .persistent()
        .get(&SuptechDataKey::LeafDigests)
        .unwrap_or_else(|| Bytes::new(env));
    let leaf_bytes: Bytes = eval_hash.clone().into();
    packed_leaves.append(&leaf_bytes);
    env.storage()
        .persistent()
        .set(&SuptechDataKey::LeafDigests, &packed_leaves);

    Ok(record)
}

#[allow(clippy::too_many_arguments)]
fn compute_evaluation_hash(
    env: &Env,
    sequence: u32,
    submission_id: &BytesN<32>,
    rule_id: u32,
    amount: u64,
    risk_bps: u32,
    event_timestamp: u64,
    compliant: bool,
    prev_hash: &BytesN<32>,
) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.append(&u32_le_bytes(env, sequence));
    preimage.append(&submission_id.clone().into());
    preimage.append(&u32_le_bytes(env, rule_id));
    preimage.append(&u64_le_bytes(env, amount));
    preimage.append(&u32_le_bytes(env, risk_bps));
    preimage.append(&u64_le_bytes(env, event_timestamp));
    preimage.append(&u32_le_bytes(env, if compliant { 1 } else { 0 }));
    preimage.append(&prev_hash.clone().into());
    env.crypto().sha256(&preimage).into()
}

fn load_leaf_hashes(env: &Env, total: u32) -> Vec<BytesN<32>> {
    let packed: Bytes = env
        .storage()
        .persistent()
        .get(&SuptechDataKey::LeafDigests)
        .unwrap_or_else(|| Bytes::new(env));
    let mut leaves: Vec<BytesN<32>> = Vec::new(env);
    for i in 0..total {
        let start = i * 32;
        let slice = packed.slice(start..(start + 32));
        let mut arr = [0u8; 32];
        slice.copy_into_slice(&mut arr);
        leaves.push_back(BytesN::from_array(env, &arr));
    }
    leaves
}

fn recompute_merkle_root(env: &Env, total: u32) -> BytesN<32> {
    if total == 0 {
        return BytesN::from_array(env, &[0u8; 32]);
    }
    let mut level = load_leaf_hashes(env, total);
    while level.len() > 1 {
        let len = level.len();
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let mut i = 0;
        while i < len {
            let left = level.get(i).unwrap();
            let right = if i + 1 < len {
                level.get(i + 1).unwrap()
            } else {
                left.clone()
            };
            next.push_back(hash_pair(env, &left, &right));
            i += 2;
        }
        level = next;
    }
    level.get(0).unwrap()
}

fn hash_pair(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut combined = Bytes::new(env);
    combined.append(&left.clone().into());
    combined.append(&right.clone().into());
    env.crypto().sha256(&combined).into()
}
