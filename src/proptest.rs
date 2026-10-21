//! # Property-Based State Machine Invariant & Chaos Resilience Tests (`proptest`)
//!
//! Executes 1,000+ deterministic pseudo-random operation sequences and fault-injection
//! scenarios against [`crate::suptech_rules`] to verify state machine invariants under
//! duplicate submissions, out-of-order timestamps, mid-batch rollbacks, and checkpoint
//! recovery (Issue #833).

use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

use crate::rbac::Role;
use crate::suptech_rules::{self, SubmissionInput, SuptechError};
use crate::{AuditLedger, AuditLedgerClient};

/// Deterministic Xorshift64 PRNG for reproducible property-based sequence generation in `#![no_std]`.
struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xCAFE_BABE_DEAD_BEEF
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            0
        } else {
            self.next_u64() % max
        }
    }
}

fn submission_id_from_u32(env: &Env, id_num: u32) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = (id_num & 0xff) as u8;
    arr[1] = ((id_num >> 8) & 0xff) as u8;
    arr[2] = ((id_num >> 16) & 0xff) as u8;
    arr[3] = ((id_num >> 24) & 0xff) as u8;
    BytesN::from_array(env, &arr)
}

/// Assert all global state machine invariants (`INV-SEQ`, `INV-IDEMPOTENT`, `INV-TIMESTAMP`,
/// `INV-CRYPTO`) hold on the current contract state.
fn assert_state_machine_invariants(
    env: &Env,
    contract_id: &Address,
    expected_total: u32,
    expected_violations: u32,
    expected_last_ts: u64,
) {
    env.as_contract(contract_id, || {
        let total = suptech_rules::total_evaluations(env);
        let violations = suptech_rules::total_violations(env);
        let last_ts = suptech_rules::last_accepted_timestamp(env);

        assert_eq!(total, expected_total, "INV-SEQ: total_evaluations mismatch");
        assert_eq!(
            violations, expected_violations,
            "INV-SEQ: total_violations mismatch"
        );
        assert_eq!(
            last_ts, expected_last_ts,
            "INV-TIMESTAMP: last_accepted_timestamp mismatch"
        );

        // INV-CRYPTO: hash chain must verify end-to-end
        assert!(
            suptech_rules::verify_suptech_hash_chain(env),
            "INV-CRYPTO: hash chain integrity check failed"
        );

        // Verify contiguous indices and violation tally
        let mut counted_violations = 0u32;
        for seq in 0..total {
            let rec = suptech_rules::get_evaluation_by_index(env, seq)
                .expect("INV-SEQ: contiguous record missing");
            assert_eq!(rec.sequence, seq);
            assert!(
                suptech_rules::is_submission_seen(env, &rec.submission_id),
                "INV-IDEMPOTENT: committed submission_id must be marked seen"
            );
            if !rec.compliant {
                counted_violations += 1;
            }
        }
        assert_eq!(counted_violations, violations);

        // Spot-check Merkle inclusion proof on latest leaf when non-empty
        if total > 0 {
            let root = suptech_rules::current_merkle_root(env);
            let latest_idx = total - 1;
            let latest_rec = suptech_rules::get_evaluation_by_index(env, latest_idx).unwrap();
            let proof = suptech_rules::generate_merkle_proof(env, latest_idx).unwrap();
            assert!(
                suptech_rules::verify_merkle_proof(env, &latest_rec.eval_hash, &proof, &root),
                "INV-CRYPTO: Merkle inclusion proof failed for latest record"
            );
        }
    });
}

#[test]
fn test_proptest_1000_plus_generated_sequences_zero_invariant_violations() {
    let mut rng = Xorshift64::new(0x900_0833_2026);
    let mut total_generated_steps: u32 = 0;
    let mut total_committed_across_runs: u32 = 0;

    // Execute 32 independent generated state-machine sequences of 32 operations each
    // (1,024 generated operations total) covering valid submissions, duplicates,
    // out-of-order timestamps, inactive rules, and atomic mid-batch rollbacks.
    const RUNS: u32 = 32;
    const STEPS_PER_RUN: u32 = 32;

    for _run in 0..RUNS {
        let env = Env::default();
        env.cost_estimate().disable_resource_limits();
        env.ledger().set_timestamp(1_700_000_000);
        env.mock_all_auths();

        let owner = Address::generate(&env);
        let planner = Address::generate(&env);
        let operator = Address::generate(&env);

        let contract_id = env.register(AuditLedger, ());
        let client = AuditLedgerClient::new(&env, &contract_id);
        client.initialize(&owner, &100_000);

        client.grant_role(
            &owner,
            &planner,
            &Role::CapacityPlanner,
            &Bytes::from_slice(&env, b"did:stellar:prop-planner"),
        );
        client.grant_role(
            &owner,
            &operator,
            &Role::Operator,
            &Bytes::from_slice(&env, b"did:stellar:prop-operator"),
        );

        env.as_contract(&contract_id, || {
            suptech_rules::configure_timestamp_drift(&env, &planner, 50).unwrap();
        });
        env.as_contract(&contract_id, || {
            suptech_rules::upsert_suptech_rule(&env, &planner, 1, 1_000, 5_000, true).unwrap();
        });
        env.as_contract(&contract_id, || {
            suptech_rules::upsert_suptech_rule(&env, &planner, 2, 5_000, 8_000, true).unwrap();
        });

        let mut model_total: u32 = 0;
        let mut model_violations: u32 = 0;
        let mut model_last_ts: u64 = 1_000;
        let mut next_unique_id: u32 = 1;

        // Seed initial valid evaluation at timestamp 1_000
        env.as_contract(&contract_id, || {
            let first = SubmissionInput {
                submission_id: submission_id_from_u32(&env, next_unique_id),
                rule_id: 1,
                amount: 500,
                risk_bps: 2_000,
                event_timestamp: model_last_ts,
            };
            next_unique_id += 1;
            suptech_rules::evaluate_submission(&env, &operator, first).unwrap();
            model_total += 1;
        });

        for step in 0..STEPS_PER_RUN {
            total_generated_steps += 1;
            let action = rng.next_range(10);

            env.as_contract(&contract_id, || match action {
                0..=4 => {
                    let sub_id = submission_id_from_u32(&env, next_unique_id);
                    next_unique_id += 1;
                    let rule_id = if rng.next_range(2) == 0 { 1 } else { 2 };
                    let amount = 200 + rng.next_range(6_000);
                    let risk_bps = (500 + rng.next_range(9_000)) as u32;
                    let ts = if rng.next_range(3) == 0 {
                        model_last_ts.saturating_sub(rng.next_range(45))
                    } else {
                        model_last_ts + rng.next_range(20)
                    };

                    let rec = suptech_rules::evaluate_submission(
                        &env,
                        &operator,
                        SubmissionInput {
                            submission_id: sub_id,
                            rule_id,
                            amount,
                            risk_bps,
                            event_timestamp: ts,
                        },
                    )
                    .expect("valid generated submission must succeed");

                    model_total += 1;
                    if !rec.compliant {
                        model_violations += 1;
                    }
                    if ts > model_last_ts {
                        model_last_ts = ts;
                    }
                }
                5..=6 => {
                    let existing_id_num = 1 + (rng.next_range((next_unique_id - 1) as u64) as u32);
                    let dup_id = submission_id_from_u32(&env, existing_id_num);
                    let res = suptech_rules::evaluate_submission(
                        &env,
                        &operator,
                        SubmissionInput {
                            submission_id: dup_id,
                            rule_id: 1,
                            amount: 100,
                            risk_bps: 100,
                            event_timestamp: model_last_ts + 1,
                        },
                    );
                    assert_eq!(res, Err(SuptechError::DuplicateSubmission));
                }
                7 => {
                    let stale_ts = model_last_ts.saturating_sub(51 + rng.next_range(500));
                    let fresh_id = submission_id_from_u32(&env, next_unique_id + 500_000 + step);
                    let res = suptech_rules::evaluate_submission(
                        &env,
                        &operator,
                        SubmissionInput {
                            submission_id: fresh_id,
                            rule_id: 1,
                            amount: 100,
                            risk_bps: 100,
                            event_timestamp: stale_ts,
                        },
                    );
                    assert_eq!(res, Err(SuptechError::OutOfOrderTimestamp));
                }
                8 => {
                    let pre_tip = suptech_rules::chain_tip_hash(&env);
                    let pre_total = suptech_rules::total_evaluations(&env);
                    let candidate_id =
                        submission_id_from_u32(&env, next_unique_id + 900_000 + step);
                    let dup_id = submission_id_from_u32(&env, 1);

                    let mut batch = Vec::new(&env);
                    batch.push_back(SubmissionInput {
                        submission_id: candidate_id.clone(),
                        rule_id: 1,
                        amount: 300,
                        risk_bps: 1_000,
                        event_timestamp: model_last_ts + 5,
                    });
                    batch.push_back(SubmissionInput {
                        submission_id: dup_id,
                        rule_id: 1,
                        amount: 300,
                        risk_bps: 1_000,
                        event_timestamp: model_last_ts + 6,
                    });

                    let res = suptech_rules::evaluate_submission_batch(&env, &operator, batch);
                    assert_eq!(res, Err(SuptechError::BatchRollbackTriggered));
                    assert!(!suptech_rules::is_submission_seen(&env, &candidate_id));
                    assert_eq!(suptech_rules::total_evaluations(&env), pre_total);
                    assert_eq!(suptech_rules::chain_tip_hash(&env), pre_tip);
                }
                _ => {
                    let unused_id = submission_id_from_u32(&env, next_unique_id + 700_000 + step);
                    let res = suptech_rules::evaluate_submission(
                        &env,
                        &operator,
                        SubmissionInput {
                            submission_id: unused_id,
                            rule_id: 999,
                            amount: 100,
                            risk_bps: 100,
                            event_timestamp: model_last_ts,
                        },
                    );
                    assert_eq!(res, Err(SuptechError::RuleNotFoundOrInactive));
                }
            });
        }

        assert_state_machine_invariants(
            &env,
            &contract_id,
            model_total,
            model_violations,
            model_last_ts,
        );
        total_committed_across_runs += model_total;
    }

    assert!(total_generated_steps >= 1_000);
    assert!(total_committed_across_runs > 400);
}

#[test]
fn test_simulated_recovery_preserves_merkle_proof_and_hash_chain_integrity() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let planner = Address::generate(&env);
    let operator = Address::generate(&env);
    let auditor = Address::generate(&env);

    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);
    client.initialize(&owner, &10_000);

    client.grant_role(
        &owner,
        &planner,
        &Role::CapacityPlanner,
        &Bytes::from_slice(&env, b"did:stellar:rec-planner"),
    );
    client.grant_role(
        &owner,
        &operator,
        &Role::Operator,
        &Bytes::from_slice(&env, b"did:stellar:rec-operator"),
    );
    client.grant_role(
        &owner,
        &auditor,
        &Role::Auditor,
        &Bytes::from_slice(&env, b"did:stellar:rec-auditor"),
    );

    env.as_contract(&contract_id, || {
        suptech_rules::upsert_suptech_rule(&env, &planner, 10, 1_000, 5_000, true).unwrap();
    });

    // Commit 5 evaluations before checkpoint
    for i in 1..=5u32 {
        env.as_contract(&contract_id, || {
            suptech_rules::evaluate_submission(
                &env,
                &operator,
                SubmissionInput {
                    submission_id: submission_id_from_u32(&env, i),
                    rule_id: 10,
                    amount: (i as u64) * 250,
                    risk_bps: i * 1_000,
                    event_timestamp: 10_000 + (i as u64) * 10,
                },
            )
            .unwrap();
        });
    }

    // Save checkpoint #1 at 5 evaluations
    let cp = env.as_contract(&contract_id, || {
        suptech_rules::create_recovery_checkpoint(&env, &auditor, 1).unwrap()
    });
    assert_eq!(cp.total_evaluations, 5);

    // Commit 3 additional post-checkpoint evaluations (indices 5, 6, 7)
    for i in 6..=8u32 {
        env.as_contract(&contract_id, || {
            suptech_rules::evaluate_submission(
                &env,
                &operator,
                SubmissionInput {
                    submission_id: submission_id_from_u32(&env, i),
                    rule_id: 10,
                    amount: 500,
                    risk_bps: 2_000,
                    event_timestamp: 10_000 + (i as u64) * 10,
                },
            )
            .unwrap();
        });
    }

    // Simulate chaos recovery back to checkpoint #1
    env.as_contract(&contract_id, || {
        assert_eq!(suptech_rules::total_evaluations(&env), 8);
        let restored = suptech_rules::recover_from_checkpoint(&env, &auditor, 1).unwrap();
        assert_eq!(restored.total_evaluations, 5);
        assert_eq!(suptech_rules::total_evaluations(&env), 5);
        assert!(!suptech_rules::is_submission_seen(
            &env,
            &submission_id_from_u32(&env, 6)
        ));

        // Verify hash-chain integrity and Merkle inclusion proofs for all 5 surviving records
        assert!(suptech_rules::verify_suptech_hash_chain(&env));
        let root = suptech_rules::current_merkle_root(&env);
        assert_eq!(root, cp.merkle_root);

        for idx in 0..5u32 {
            let rec = suptech_rules::get_evaluation_by_index(&env, idx).unwrap();
            let proof = suptech_rules::generate_merkle_proof(&env, idx).unwrap();
            assert!(suptech_rules::verify_merkle_proof(
                &env,
                &rec.eval_hash,
                &proof,
                &root
            ));
        }
    });

    // Resubmitting #6 after rollback to checkpoint #1 now succeeds cleanly
    env.as_contract(&contract_id, || {
        let resub = suptech_rules::evaluate_submission(
            &env,
            &operator,
            SubmissionInput {
                submission_id: submission_id_from_u32(&env, 6),
                rule_id: 10,
                amount: 300,
                risk_bps: 1_500,
                event_timestamp: 10_060,
            },
        )
        .unwrap();
        assert_eq!(resub.sequence, 5);
        assert!(suptech_rules::verify_suptech_hash_chain(&env));
    });
}
