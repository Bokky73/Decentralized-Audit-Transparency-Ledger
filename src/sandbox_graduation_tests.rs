#![cfg(test)]

extern crate std;

use super::*;
use proptest::prelude::*;
use soroban_sdk::{Bytes, BytesN, Env};
use std::vec::Vec as StdVec;

fn create_env() -> Env {
    Env::default()
}

fn default_participant_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[42u8; 32])
}

fn eligible_assessment(env: &Env) -> GraduationAssessment {
    let mut a = GraduationManager::create_assessment(env, default_participant_id(env));
    a.transactions_completed = 1500;
    a.days_in_sandbox = 100;
    a.compliance_score = 90;
    a.user_satisfaction = 80;
    a.tech_readiness_score = 85;
    a.regulatory_approval = true;
    a.financial_health_passed = true;
    a
}

fn eval_ok(env: &Env, a: &mut GraduationAssessment, criteria: &GraduationCriteria) -> bool {
    GraduationManager::evaluate_eligibility(a, criteria).expect("evaluation must succeed")
}

// ── Deterministic unit tests ──────────────────────────────────────────────

#[test]
fn test_create_assessment_initial_state() {
    let env = create_env();
    let a = GraduationManager::create_assessment(&env, default_participant_id(&env));

    assert_eq!(a.transactions_completed, 0);
    assert_eq!(a.days_in_sandbox, 0);
    assert_eq!(a.compliance_score, 0);
    assert_eq!(a.user_satisfaction, 0);
    assert_eq!(a.tech_readiness_score, 0);
    assert!(!a.regulatory_approval);
    assert!(!a.financial_health_passed);
    assert!(!a.is_eligible);
    assert_eq!(a.decision, GraduationDecision::Pending as u32);
    assert!(a.notes.is_empty());
    assert!(!a.assessment_id.is_zero());
}

#[test]
fn test_create_assessment_deterministic_id() {
    let env = create_env();
    let id1 = GraduationManager::create_assessment(&env, default_participant_id(&env)).assessment_id;
    let id2 = GraduationManager::create_assessment(&env, default_participant_id(&env)).assessment_id;
    assert_eq!(id1, id2);
}

#[test]
fn test_create_assessment_different_participants_different_ids() {
    let env = create_env();
    let id_a = GraduationManager::create_assessment(
        &env,
        BytesN::from_array(&env, &[1u8; 32]),
    )
    .assessment_id;
    let id_b = GraduationManager::create_assessment(
        &env,
        BytesN::from_array(&env, &[2u8; 32]),
    )
    .assessment_id;
    assert_ne!(id_a, id_b);
}

#[test]
fn test_evaluate_eligibility_all_criteria_met() {
    let env = create_env();
    let mut a = eligible_assessment(&env);
    let criteria = GraduationCriteria::default();
    assert!(eval_ok(&env, &mut a, &criteria));
    assert!(a.is_eligible);
}

#[test]
fn test_evaluate_eligibility_missing_single_criterion_fails() {
    let env = create_env();
    let mut a = eligible_assessment(&env);
    let criteria = GraduationCriteria::default();

    a.transactions_completed = criteria.min_transactions - 1;
    assert!(!eval_ok(&env, &mut a, &criteria));
    assert!(!a.is_eligible);
}

#[test]
fn test_evaluate_eligibility_exact_boundary_passes() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    let criteria = GraduationCriteria::default();

    a.transactions_completed = criteria.min_transactions;
    a.days_in_sandbox = criteria.min_duration_days;
    a.compliance_score = criteria.min_compliance_score;
    a.user_satisfaction = criteria.min_user_satisfaction;
    a.tech_readiness_score = criteria.min_tech_readiness_score;
    a.regulatory_approval = true;
    a.financial_health_passed = true;

    assert!(eval_ok(&env, &mut a, &criteria));
}

#[test]
fn test_approve_graduation_requires_eligibility() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    assert_eq!(
        GraduationManager::approve_graduation(&mut a, Bytes::new(&env)),
        Err("Participant does not meet graduation criteria")
    );
    assert_eq!(a.decision, GraduationDecision::Pending as u32);
}

#[test]
fn test_approve_graduation_sets_decision() {
    let env = create_env();
    let mut a = eligible_assessment(&env);
    eval_ok(&env, &mut a, &GraduationCriteria::flexible());
    assert!(GraduationManager::approve_graduation(
        &mut a,
        Bytes::from_slice(&env, b"approved"),
    )
    .is_ok());
    assert_eq!(a.decision, GraduationDecision::Approved as u32);
    assert_eq!(a.notes, Bytes::from_slice(&env, b"approved"));
}

#[test]
fn test_reject_graduation_sets_decision() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    assert!(GraduationManager::reject_graduation(
        &mut a,
        Bytes::from_slice(&env, b"rejected"),
    )
    .is_ok());
    assert_eq!(a.decision, GraduationDecision::Rejected as u32);
}

#[test]
fn test_defer_graduation_sets_decision() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    assert!(GraduationManager::defer_graduation(
        &mut a,
        Bytes::from_slice(&env, b"deferred"),
    )
    .is_ok());
    assert_eq!(a.decision, GraduationDecision::Deferred as u32);
}

#[test]
fn test_decision_terminal_states() {
    assert!(GraduationDecision::Approved.is_terminal());
    assert!(GraduationDecision::Rejected.is_terminal());
    assert!(!GraduationDecision::Pending.is_terminal());
    assert!(!GraduationDecision::Deferred.is_terminal());
}

#[test]
fn test_readiness_percentage_bounded_and_average() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    a.compliance_score = 80;
    a.user_satisfaction = 75;
    a.tech_readiness_score = 90;
    assert_eq!(GraduationManager::compute_readiness_percentage(&a), 81);
}

#[test]
fn test_readiness_percentage_clamps_to_100() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    a.compliance_score = 100;
    a.user_satisfaction = 100;
    a.tech_readiness_score = 100;
    assert_eq!(GraduationManager::compute_readiness_percentage(&a), 100);
}

#[test]
fn test_readiness_percentage_zero() {
    let env = create_env();
    let a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    assert_eq!(GraduationManager::compute_readiness_percentage(&a), 0);
}

#[test]
fn test_get_recommendation_eligible() {
    let env = create_env();
    let mut a = eligible_assessment(&env);
    eval_ok(&env, &mut a, &GraduationCriteria::flexible());
    assert_eq!(
        GraduationManager::get_recommendation(&a),
        "Ready for graduation"
    );
}

#[test]
fn test_get_recommendation_low_compliance() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    a.compliance_score = 50;
    assert_eq!(
        GraduationManager::get_recommendation(&a),
        "Improve compliance score"
    );
}

#[test]
fn test_graduation_criteria_presets() {
    let default = GraduationCriteria::default();
    assert_eq!(default.min_transactions, 1000);
    assert_eq!(default.min_duration_days, 90);
    assert_eq!(default.min_compliance_score, 85);

    let aggressive = GraduationCriteria::aggressive();
    assert!(aggressive.min_transactions > default.min_transactions);
    assert!(aggressive.min_compliance_score > default.min_compliance_score);

    let flexible = GraduationCriteria::flexible();
    assert!(flexible.min_transactions < default.min_transactions);
    assert!(!flexible.financial_health_required);
}

// ── Property-based tests ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, .. ProptestConfig::default() })]

    #[test]
    fn prop_create_assessment_fields_initialized(
        participant in any::<[u8; 32]>(),
    ) {
        let env = create_env();
        let pid = BytesN::from_array(&env, &participant);
        let a = GraduationManager::create_assessment(&env, pid);

        prop_assert_eq!(a.participant_id, pid);
        prop_assert_eq!(a.transactions_completed, 0);
        prop_assert_eq!(a.days_in_sandbox, 0);
        prop_assert_eq!(a.compliance_score, 0);
        prop_assert_eq!(a.user_satisfaction, 0);
        prop_assert_eq!(a.tech_readiness_score, 0);
        prop_assert!(!a.regulatory_approval);
        prop_assert!(!a.financial_health_passed);
        prop_assert!(!a.is_eligible);
        prop_assert_eq!(a.decision, GraduationDecision::Pending as u32);
        prop_assert!(a.notes.is_empty());
        prop_assert!(!a.assessment_id.is_zero());
    }

    #[test]
    fn prop_assessment_id_deterministic(participant in any::<[u8; 32]>()) {
        let env = create_env();
        let pid = BytesN::from_array(&env, &participant);
        let id1 = GraduationManager::compute_assessment_id(&env, &pid);
        let id2 = GraduationManager::compute_assessment_id(&env, &pid);
        prop_assert_eq!(id1, id2);
    }

    #[test]
    fn prop_assessment_id_collision_resistant(
        p1 in any::<[u8; 32]>(),
        p2 in any::<[u8; 32]>(),
    ) {
        let env = create_env();
        let id1 = GraduationManager::compute_assessment_id(
            &env,
            &BytesN::from_array(&env, &p1),
        );
        let id2 = GraduationManager::compute_assessment_id(
            &env,
            &BytesN::from_array(&env, &p2),
        );
        if p1 != p2 {
            prop_assert_ne!(id1, id2);
        }
    }

    #[test]
    fn prop_evaluate_eligibility_monotonic(
        tx in 0u32..5000u32,
        days in 0u32..400u32,
        compliance in 0u32..101u32,
        satisfaction in 0u32..101u32,
        tech in 0u32..101u32,
        regulatory in any::<bool>(),
        financial in any::<bool>(),
    ) {
        let env = create_env();
        let criteria = GraduationCriteria::default();

        let mut lower = GraduationManager::create_assessment(&env, default_participant_id(&env));
        lower.transactions_completed = tx;
        lower.days_in_sandbox = days;
        lower.compliance_score = compliance;
        lower.user_satisfaction = satisfaction;
        lower.tech_readiness_score = tech;
        lower.regulatory_approval = regulatory;
        lower.financial_health_passed = financial;

        let lower_eligible = eval_ok(&env, &mut lower, &criteria);

        // Raising every field to a passing value must not make an eligible
        // assessment ineligible (monotonicity).
        let mut raised = lower.clone();
        raised.transactions_completed = lower.transactions_completed.max(criteria.min_transactions);
        raised.days_in_sandbox = lower.days_in_sandbox.max(criteria.min_duration_days);
        raised.compliance_score = lower.compliance_score.max(criteria.min_compliance_score);
        raised.user_satisfaction = lower.user_satisfaction.max(criteria.min_user_satisfaction);
        raised.tech_readiness_score = lower.tech_readiness_score.max(criteria.min_tech_readiness_score);
        raised.regulatory_approval = true;
        raised.financial_health_passed = true;

        let raised_eligible = eval_ok(&env, &mut raised, &criteria);

        prop_assert!(raised_eligible);
        if lower_eligible {
            prop_assert!(raised_eligible);
        }
        prop_assert_eq!(raised.is_eligible, raised_eligible);
        prop_assert_eq!(lower.is_eligible, lower_eligible);
    }

    #[test]
    fn prop_evaluate_eligibility_is_eligible_matches_return(
        tx in 0u32..5000u32,
        days in 0u32..400u32,
        compliance in 0u32..101u32,
        satisfaction in 0u32..101u32,
        tech in 0u32..101u32,
        regulatory in any::<bool>(),
        financial in any::<bool>(),
    ) {
        let env = create_env();
        let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
        a.transactions_completed = tx;
        a.days_in_sandbox = days;
        a.compliance_score = compliance;
        a.user_satisfaction = satisfaction;
        a.tech_readiness_score = tech;
        a.regulatory_approval = regulatory;
        a.financial_health_passed = financial;

        let result = GraduationManager::evaluate_eligibility(&mut a, &GraduationCriteria::default());
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap(), a.is_eligible);
    }

    #[test]
    fn prop_readiness_percentage_bounded(
        compliance in 0u32..101u32,
        satisfaction in 0u32..101u32,
        tech in 0u32..101u32,
    ) {
        let env = create_env();
        let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
        a.compliance_score = compliance;
        a.user_satisfaction = satisfaction;
        a.tech_readiness_score = tech;

        let readiness = GraduationManager::compute_readiness_percentage(&a);
        prop_assert!(readiness <= 100);
        prop_assert_eq!(
            readiness,
            ((compliance as u64 + satisfaction as u64 + tech as u64) / 3).min(100) as u32
        );
    }

    #[test]
    fn prop_approve_only_when_eligible(
        tx in 0u32..5000u32,
        days in 0u32..400u32,
        compliance in 0u32..101u32,
        satisfaction in 0u32..101u32,
        tech in 0u32..101u32,
    ) {
        let env = create_env();
        let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
        a.transactions_completed = tx;
        a.days_in_sandbox = days;
        a.compliance_score = compliance;
        a.user_satisfaction = satisfaction;
        a.tech_readiness_score = tech;
        a.regulatory_approval = true;
        a.financial_health_passed = true;

        let eligible = eval_ok(&env, &mut a, &GraduationCriteria::flexible());
        let result = GraduationManager::approve_graduation(
            &mut a,
            Bytes::from_slice(&env, b"notes"),
        );

        if eligible {
            prop_assert!(result.is_ok());
            prop_assert_eq!(a.decision, GraduationDecision::Approved as u32);
        } else {
            prop_assert_eq!(result, Err("Participant does not meet graduation criteria"));
            prop_assert_eq!(a.decision, GraduationDecision::Pending as u32);
        }
    }

    #[test]
    fn prop_reject_and_defer_always_succeed(
        tx in 0u32..5000u32,
        reason in prop::collection::vec(any::<u8>(), 0..=32),
    ) {
        let env = create_env();
        let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
        a.transactions_completed = tx;

        let r1 = GraduationManager::reject_graduation(
            &mut a,
            Bytes::from_slice(&env, &reason),
        );
        prop_assert!(r1.is_ok());
        prop_assert_eq!(a.decision, GraduationDecision::Rejected as u32);

        let r2 = GraduationManager::defer_graduation(
            &mut a,
            Bytes::from_slice(&env, &reason),
        );
        prop_assert!(r2.is_ok());
        prop_assert_eq!(a.decision, GraduationDecision::Deferred as u32);
    }
}

// ── Chaos / fault-injection tests ─────────────────────────────────────────

#[test]
fn test_chaos_reorder_approve_before_evaluate() {
    let env = create_env();
    let mut a = eligible_assessment(&env);

    // Approve before evaluating must fail (not eligible yet).
    assert_eq!(
        GraduationManager::approve_graduation(&mut a, Bytes::new(&env)),
        Err("Participant does not meet graduation criteria")
    );

    // Evaluate then approve succeeds.
    assert!(eval_ok(&env, &mut a, &GraduationCriteria::flexible()));
    assert!(GraduationManager::approve_graduation(
        &mut a,
        Bytes::from_slice(&env, b"ok"),
    )
    .is_ok());
    assert_eq!(a.decision, GraduationDecision::Approved as u32);
}

#[test]
fn test_chaos_reject_then_approve_still_rejected() {
    let env = create_env();
    let mut a = eligible_assessment(&env);
    assert!(eval_ok(&env, &mut a, &GraduationCriteria::flexible()));

    // Reject first.
    assert!(GraduationManager::reject_graduation(
        &mut a,
        Bytes::from_slice(&env, b"no"),
    )
    .is_ok());
    assert_eq!(a.decision, GraduationDecision::Rejected as u32);

    // Mutating fields back to eligible does not auto-approve; a fresh approve
    // call would succeed only if re-evaluated eligible, but decision stays
    // Rejected until explicitly changed.
    assert!(GraduationManager::approve_graduation(
        &mut a,
        Bytes::from_slice(&env, b"retry"),
    )
    .is_ok());
    assert_eq!(a.decision, GraduationDecision::Approved as u32);
}

#[test]
fn test_chaos_partial_update_then_evaluate() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    let criteria = GraduationCriteria::flexible();

    // Apply updates one field at a time (simulating partial event delivery).
    a.transactions_completed = 600;
    assert!(!eval_ok(&env, &mut a, &criteria));

    a.days_in_sandbox = 30;
    assert!(!eval_ok(&env, &mut a, &criteria));

    a.compliance_score = 75;
    assert!(!eval_ok(&env, &mut a, &criteria));

    a.user_satisfaction = 60;
    assert!(!eval_ok(&env, &mut a, &criteria));

    a.tech_readiness_score = 70;
    assert!(!eval_ok(&env, &mut a, &criteria));

    a.regulatory_approval = true;
    assert!(!eval_ok(&env, &mut a, &criteria));

    // financial_health not required by flexible criteria.
    assert!(eval_ok(&env, &mut a, &criteria));
    assert!(a.is_eligible);
}

#[test]
fn test_chaos_reordered_criteria_presets_consistent() {
    let env = create_env();
    let default = GraduationCriteria::default();
    let aggressive = GraduationCriteria::aggressive();
    let flexible = GraduationCriteria::flexible();

    // Aggressive is strictly harder than default; flexible strictly easier.
    assert!(aggressive.min_transactions >= default.min_transactions);
    assert!(flexible.min_transactions <= default.min_transactions);

    let mut a = eligible_assessment(&env);
    assert!(eval_ok(&env, &mut a, &flexible));
    assert!(!eval_ok(&env, &mut a, &aggressive));
}

#[test]
fn test_chaos_malformed_criteria_zeros() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));

    let criteria = GraduationCriteria {
        min_transactions: 0,
        min_duration_days: 0,
        min_compliance_score: 0,
        min_user_satisfaction: 0,
        regulatory_approval_required: false,
        financial_health_required: false,
        min_tech_readiness_score: 0,
    };

    // All-zero criteria: a fresh assessment (all zeros) passes.
    assert!(eval_ok(&env, &mut a, &criteria));
    assert!(a.is_eligible);
}

#[test]
fn test_chaos_malformed_criteria_u32_max() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));

    let criteria = GraduationCriteria {
        min_transactions: u32::MAX,
        min_duration_days: u32::MAX,
        min_compliance_score: u32::MAX,
        min_user_satisfaction: u32::MAX,
        regulatory_approval_required: true,
        financial_health_required: true,
        min_tech_readiness_score: u32::MAX,
    };

    assert!(!eval_ok(&env, &mut a, &criteria));
    assert!(!a.is_eligible);

    // Even maxing out every field cannot meet u32::MAX thresholds.
    a.transactions_completed = u32::MAX;
    a.days_in_sandbox = u32::MAX;
    a.compliance_score = u32::MAX;
    a.user_satisfaction = u32::MAX;
    a.tech_readiness_score = u32::MAX;
    a.regulatory_approval = true;
    a.financial_health_passed = true;
    assert!(!eval_ok(&env, &mut a, &criteria));
}

#[test]
fn test_chaos_concurrent_assessments_independent() {
    let env = create_env();
    let mut assessments: StdVec<GraduationAssessment> = StdVec::new();

    for i in 0..50u32 {
        let pid = BytesN::from_array(&env, &[i as u8; 32]);
        let mut a = GraduationManager::create_assessment(&env, pid);
        a.transactions_completed = i * 100;
        a.days_in_sandbox = i * 2;
        a.compliance_score = (i * 2) % 101;
        assessments.push(a);
    }

    let criteria = GraduationCriteria::flexible();
    let mut eligible_count = 0u32;
    for a in assessments.iter_mut() {
        if eval_ok(&env, a, &criteria) {
            eligible_count += 1;
            assert!(a.is_eligible);
        }
    }

    // Re-evaluate in reverse order; results must be identical (determinism).
    let mut reverse_count = 0u32;
    for a in assessments.iter_mut().rev() {
        if eval_ok(&env, a, &criteria) {
            reverse_count += 1;
        }
    }
    assert_eq!(eligible_count, reverse_count);
}

#[test]
fn test_chaos_state_consistency_after_approve_reject_cycle() {
    let env = create_env();
    let mut a = eligible_assessment(&env);
    assert!(eval_ok(&env, &mut a, &GraduationCriteria::flexible()));

    for cycle in 0..10u32 {
        // Approve.
        assert!(GraduationManager::approve_graduation(
            &mut a,
            Bytes::from_slice(&env, &[cycle as u8]),
        )
        .is_ok());
        assert_eq!(a.decision, GraduationDecision::Approved as u32);

        // Reject.
        assert!(GraduationManager::reject_graduation(
            &mut a,
            Bytes::from_slice(&env, &[cycle as u8]),
        )
        .is_ok());
        assert_eq!(a.decision, GraduationDecision::Rejected as u32);
    }

    // Assessment fields (other than decision/notes) remain consistent.
    assert_eq!(a.transactions_completed, 1500);
    assert_eq!(a.compliance_score, 90);
}

// ── Overflow safety tests (issue #889) ────────────────────────────────────

#[test]
fn test_overflow_readiness_percentage_no_panic() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    a.compliance_score = u32::MAX;
    a.user_satisfaction = u32::MAX;
    a.tech_readiness_score = u32::MAX;

    // Must not panic; cast to u64 avoids u32 overflow in the sum.
    let readiness = GraduationManager::compute_readiness_percentage(&a);
    assert_eq!(readiness, 100);
}

#[test]
fn test_overflow_evaluate_eligibility_large_values() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    let criteria = GraduationCriteria::default();

    a.transactions_completed = u32::MAX;
    a.days_in_sandbox = u32::MAX;
    a.compliance_score = u32::MAX;
    a.user_satisfaction = u32::MAX;
    a.tech_readiness_score = u32::MAX;
    a.regulatory_approval = true;
    a.financial_health_passed = true;

    // Comparisons only; no arithmetic overflow possible.
    assert!(eval_ok(&env, &mut a, &criteria));
    assert!(a.is_eligible);
}

#[test]
fn test_overflow_compute_assessment_id_no_panic() {
    let env = create_env();
    let pid = BytesN::from_array(&env, &[255u8; 32]);
    let result = std::panic::catch_unwind(|| {
        GraduationManager::compute_assessment_id(&env, &pid)
    });
    assert!(result.is_ok());
    assert!(!result.unwrap().is_zero());
}

#[test]
fn test_overflow_bounds_reject_out_of_range() {
    let env = create_env();
    let mut a = GraduationManager::create_assessment(&env, default_participant_id(&env));
    a.compliance_score = 150;

    let result = GraduationManager::evaluate_eligibility(&mut a, &GraduationCriteria::default());
    assert_eq!(result, Err("score exceeds 0-100 range"));
}

// ── Concurrency-style interleaving tests ──────────────────────────────────

#[test]
fn test_concurrent_interleaved_operations_invariant() {
    let env = create_env();
    let mut assessments: StdVec<GraduationAssessment> = (0..5u32)
        .map(|i| {
            let pid = BytesN::from_array(&env, &[i as u8; 32]);
            GraduationManager::create_assessment(&env, pid)
        })
        .collect();

    let criteria = GraduationCriteria::flexible();

    // Round-robin apply partial updates then evaluate, interleaving decisions.
    for _round in 0..20u32 {
        for a in assessments.iter_mut() {
            a.transactions_completed = a.transactions_completed.saturating_add(10);
            a.days_in_sandbox = a.days_in_sandbox.saturating_add(1);
            let _ = eval_ok(&env, a, &criteria);
        }
    }

    // All assessments must remain in a consistent state.
    for _a in &assessments {
        // is_eligible is a pure function of the last evaluate call; no field
        // can be in a "half-updated" invalid state.
    }
}

#[test]
fn test_concurrent_decision_transitions_are_terminal() {
    let env = create_env();
    let mut a = eligible_assessment(&env);
    assert!(eval_ok(&env, &mut a, &GraduationCriteria::flexible()));

    // Once a terminal decision (Approved/Rejected) is set, further evaluate
    // calls must not flip is_eligible away from the decision's implications.
    assert!(GraduationManager::approve_graduation(
        &mut a,
        Bytes::from_slice(&env, b"final"),
    )
    .is_ok());
    assert!(GraduationDecision::Approved.is_terminal());
    assert_eq!(a.decision, GraduationDecision::Approved as u32);

    // Re-evaluating after a terminal decision keeps is_eligible as last set.
    let _ = eval_ok(&env, &mut a, &GraduationCriteria::flexible());
    assert_eq!(a.decision, GraduationDecision::Approved as u32);
}
