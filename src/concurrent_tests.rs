//! # Multi-Actor Concurrent Access & Interleaved Scenario Tests (`concurrent_tests`)
//!
//! Tests concurrent multi-operator submissions, competing batch evaluations with colliding
//! `submission_id`s, mid-stream rule reconfiguration by planners/auditors, and dynamic RBAC
//! role revocation/suspension during active supervisory windows (Issue #833).

use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

use crate::rbac::Role;
use crate::suptech_rules::{self, SubmissionInput, SuptechError};
use crate::{AuditLedger, AuditLedgerClient};

fn sub_id(env: &Env, tag: u8, seq: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = tag;
    bytes[1] = seq;
    BytesN::from_array(env, &bytes)
}

#[test]
fn test_multi_actor_interleaved_submissions_and_competing_batches() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_100_000);
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let planner = Address::generate(&env);
    let auditor = Address::generate(&env);
    let op_alpha = Address::generate(&env);
    let op_beta = Address::generate(&env);
    let op_gamma = Address::generate(&env);

    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);
    client.initialize(&owner, &50_000);

    client.grant_role(
        &owner,
        &planner,
        &Role::CapacityPlanner,
        &Bytes::from_slice(&env, b"did:stellar:conc-planner"),
    );
    client.grant_role(
        &owner,
        &auditor,
        &Role::Auditor,
        &Bytes::from_slice(&env, b"did:stellar:conc-auditor"),
    );
    client.grant_role(
        &owner,
        &op_alpha,
        &Role::Operator,
        &Bytes::from_slice(&env, b"did:stellar:op-alpha"),
    );
    client.grant_role(
        &owner,
        &op_beta,
        &Role::Operator,
        &Bytes::from_slice(&env, b"did:stellar:op-beta"),
    );
    client.grant_role(
        &owner,
        &op_gamma,
        &Role::Operator,
        &Bytes::from_slice(&env, b"did:stellar:op-gamma"),
    );

    env.as_contract(&contract_id, || {
        suptech_rules::configure_timestamp_drift(&env, &planner, 30).unwrap();
    });
    env.as_contract(&contract_id, || {
        suptech_rules::upsert_suptech_rule(&env, &planner, 100, 10_000, 7_000, true).unwrap();
    });
    env.as_contract(&contract_id, || {
        suptech_rules::upsert_suptech_rule(&env, &planner, 200, 2_000, 4_000, true).unwrap();
    });

    // Round-robin interleaved submissions from three concurrent operators
    let actors = [&op_alpha, &op_beta, &op_gamma];
    for round in 0..10u8 {
        for (actor_idx, actor) in actors.iter().enumerate() {
            env.as_contract(&contract_id, || {
                let rec = suptech_rules::evaluate_submission(
                    &env,
                    actor,
                    SubmissionInput {
                        submission_id: sub_id(&env, (actor_idx as u8) + 1, round),
                        rule_id: if round % 2 == 0 { 100 } else { 200 },
                        amount: 1_500 + (round as u64) * 200,
                        risk_bps: 3_500,
                        event_timestamp: 50_000 + (round as u64) * 10 + (actor_idx as u64),
                    },
                )
                .unwrap();
                assert_eq!(&rec.actor, *actor);
            });
        }
    }

    // Competing batch scenario: op_alpha submits a valid 3-item batch;
    // op_beta concurrently submits a 3-item batch whose 3rd item collides with op_alpha's 2nd item.
    let shared_collision_id = sub_id(&env, 0xCC, 1);

    env.as_contract(&contract_id, || {
        assert_eq!(suptech_rules::total_evaluations(&env), 30);

        let mut alpha_batch = Vec::new(&env);
        alpha_batch.push_back(SubmissionInput {
            submission_id: sub_id(&env, 0xAA, 1),
            rule_id: 100,
            amount: 1_000,
            risk_bps: 2_000,
            event_timestamp: 51_000,
        });
        alpha_batch.push_back(SubmissionInput {
            submission_id: shared_collision_id.clone(),
            rule_id: 100,
            amount: 2_000,
            risk_bps: 2_000,
            event_timestamp: 51_005,
        });
        alpha_batch.push_back(SubmissionInput {
            submission_id: sub_id(&env, 0xAA, 3),
            rule_id: 100,
            amount: 3_000,
            risk_bps: 2_000,
            event_timestamp: 51_010,
        });

        let alpha_res =
            suptech_rules::evaluate_submission_batch(&env, &op_alpha, alpha_batch).unwrap();
        assert_eq!(alpha_res.len(), 3);
        assert_eq!(suptech_rules::total_evaluations(&env), 33);
    });

    env.as_contract(&contract_id, || {
        let mut beta_batch = Vec::new(&env);
        beta_batch.push_back(SubmissionInput {
            submission_id: sub_id(&env, 0xBB, 1),
            rule_id: 100,
            amount: 1_000,
            risk_bps: 2_000,
            event_timestamp: 51_015,
        });
        beta_batch.push_back(SubmissionInput {
            submission_id: sub_id(&env, 0xBB, 2),
            rule_id: 100,
            amount: 1_000,
            risk_bps: 2_000,
            event_timestamp: 51_020,
        });
        beta_batch.push_back(SubmissionInput {
            submission_id: shared_collision_id,
            rule_id: 100,
            amount: 1_000,
            risk_bps: 2_000,
            event_timestamp: 51_025,
        });

        let beta_res = suptech_rules::evaluate_submission_batch(&env, &op_beta, beta_batch);
        assert_eq!(beta_res, Err(SuptechError::BatchRollbackTriggered));
        // Neither 0xBB:1 nor 0xBB:2 may be committed after atomic rollback
        assert!(!suptech_rules::is_submission_seen(
            &env,
            &sub_id(&env, 0xBB, 1)
        ));
        assert!(!suptech_rules::is_submission_seen(
            &env,
            &sub_id(&env, 0xBB, 2)
        ));
        assert_eq!(suptech_rules::total_evaluations(&env), 33);
        assert!(suptech_rules::verify_suptech_hash_chain(&env));
    });
}

#[test]
fn test_concurrent_governance_rule_toggle_and_mid_flight_rbac_suspension() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_200_000);
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let planner = Address::generate(&env);
    let op_1 = Address::generate(&env);
    let op_2 = Address::generate(&env);

    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);
    client.initialize(&owner, &50_000);

    client.grant_role(
        &owner,
        &planner,
        &Role::CapacityPlanner,
        &Bytes::from_slice(&env, b"did:stellar:gov-planner"),
    );
    client.grant_role(
        &owner,
        &op_1,
        &Role::Operator,
        &Bytes::from_slice(&env, b"did:stellar:gov-op1"),
    );
    client.grant_role(
        &owner,
        &op_2,
        &Role::Operator,
        &Bytes::from_slice(&env, b"did:stellar:gov-op2"),
    );

    env.as_contract(&contract_id, || {
        suptech_rules::upsert_suptech_rule(&env, &planner, 77, 1_000, 5_000, true).unwrap();
    });

    // op_1 succeeds while active
    env.as_contract(&contract_id, || {
        suptech_rules::evaluate_submission(
            &env,
            &op_1,
            SubmissionInput {
                submission_id: sub_id(&env, 0x77, 1),
                rule_id: 77,
                amount: 800,
                risk_bps: 3_000,
                event_timestamp: 60_000,
            },
        )
        .unwrap();
    });

    // Owner suspends op_1 mid-flight -> op_1 is rejected while op_2 continues unaffected
    client.suspend_submitter_did(&owner, &op_1);

    env.as_contract(&contract_id, || {
        let blocked_op1 = suptech_rules::evaluate_submission(
            &env,
            &op_1,
            SubmissionInput {
                submission_id: sub_id(&env, 0x77, 2),
                rule_id: 77,
                amount: 800,
                risk_bps: 3_000,
                event_timestamp: 60_010,
            },
        );
        assert_eq!(blocked_op1, Err(SuptechError::RbacRejected));
    });

    env.as_contract(&contract_id, || {
        let allowed_op2 = suptech_rules::evaluate_submission(
            &env,
            &op_2,
            SubmissionInput {
                submission_id: sub_id(&env, 0x77, 3),
                rule_id: 77,
                amount: 800,
                risk_bps: 3_000,
                event_timestamp: 60_020,
            },
        );
        assert!(allowed_op2.is_ok());
    });

    // Planner deactivates rule 77 -> op_2's subsequent submission to rule 77 is rejected
    env.as_contract(&contract_id, || {
        suptech_rules::upsert_suptech_rule(&env, &planner, 77, 1_000, 5_000, false).unwrap();
    });

    env.as_contract(&contract_id, || {
        let inactive_res = suptech_rules::evaluate_submission(
            &env,
            &op_2,
            SubmissionInput {
                submission_id: sub_id(&env, 0x77, 4),
                rule_id: 77,
                amount: 800,
                risk_bps: 3_000,
                event_timestamp: 60_030,
            },
        );
        assert_eq!(inactive_res, Err(SuptechError::RuleNotFoundOrInactive));
        assert!(suptech_rules::verify_suptech_hash_chain(&env));
    });
}
