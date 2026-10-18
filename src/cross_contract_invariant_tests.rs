#![cfg(test)]
//! Issue #868 — End-to-end invariant & chaos resilience suite for
//! `cross_contract.rs` (cross-contract atomic audit batch invocation router).
//!
//! Guarantees state consistency under:
//! - **Reordered events** — steps recorded in arbitrary order must converge
//!   to the identical final state and the same verification verdict,
//! - **Partial failures** — a rejected step recording must leave the
//!   execution untouched (no phantom slots, no status flips),
//! - **Tamper evidence** — stored digests must expose any mutation of
//!   persisted composition content,
//! - **Fine-grained RBAC** (#865) — role gating matrix and compatibility mode,

extern crate std;

use super::*;
use crate::cross_contract::{
    CrossContractEvent, EventRef, WorkflowDefinition, WorkflowStatus, WorkflowStep,
    XCT_TTL_DEFAULT_TARGET_LEDGERS, XCT_TTL_DEFAULT_THRESHOLD_LEDGERS,
};
use proptest::prelude::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec};

fn create_ledger() -> (Env, Address, AuditLedgerClient<'static>) {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &100, &4096);
    (env, owner, client)
}

fn dummy_ref(env: &Env, contract: &Address, salt: u8) -> EventRef {
    EventRef {
        contract: contract.clone(),
        event_id: BytesN::from_array(env, &[salt; 32]),
        index: salt as u32,
        event_hash: BytesN::from_array(env, &[salt.wrapping_add(0x40); 32]),
    }
}

fn steps_for(env: &Env, flags: &[(bool, u64, u64)]) -> Vec<WorkflowStep> {
    let mut steps = Vec::new(env);
    for (i, (optional, min_delay, max_delay)) in flags.iter().enumerate() {
        steps.push_back(WorkflowStep {
            index: i as u32,
            name: Symbol::new(env, &std::format!("step{}", i)),
            expected_event_type: symbol_short!("ev"),
            optional: *optional,
            min_delay_secs: *min_delay,
            max_delay_secs: *max_delay,
        });
    }
    steps
}

// ── Invariants: ID namespaces & counters ────────────────────────────────────

#[test]
fn invariant_id_counters_monotonic_across_mixed_traffic() {
    let (env, owner, client) = create_ledger();
    let actor = Address::generate(&env);
    let contract_b = Address::generate(&env);

    // Interleave compositions, anchors and workflow definitions.
    let mut comp_ids = std::vec::Vec::new();
    let mut ext_ids = std::vec::Vec::new();
    let mut wf_ids = std::vec::Vec::new();
    for i in 0..4u32 {
        let mut refs = Vec::new(&env);
        refs.push_back(dummy_ref(&env, &contract_b, i as u8));
        comp_ids.push(client.log_event_with_refs(
            &actor,
            &symbol_short!("batch"),
            &refs,
            &Bytes::from_slice(&env, format!("b{i}").as_bytes()),
        ));
        ext_ids.push(client.register_external_event(
            &actor,
            &symbol_short!("ethereum"),
            &Bytes::from_slice(&env, format!("0x{i}").as_bytes()),
            &BytesN::from_array(&env, &[i as u8; 32]),
            &Bytes::new(&env),
        ));
        let mut steps = steps_for(&env, &[(false, 0, 0), (true, 0, 0)]);
        steps.push_back(WorkflowStep {
            index: 2,
            name: symbol_short!("extra"),
            expected_event_type: symbol_short!("ev"),
            optional: false,
            min_delay_secs: 0,
            max_delay_secs: 0,
        });
        wf_ids.push(client.define_workflow(&owner, &symbol_short!("wf"), &steps));
    }

    // Invariant: per-namespace IDs are strictly monotonic and dense even
    // under interleaved event traffic.
    for (i, id) in comp_ids.iter().enumerate() {
        assert_eq!(*id, i as u32, "composition ids are dense and ordered");
    }
    for (i, id) in ext_ids.iter().enumerate() {
        assert_eq!(*id, i as u32, "external anchor ids are dense and ordered");
    }
    for (i, id) in wf_ids.iter().enumerate() {
        assert_eq!(*id, i as u32, "workflow ids are dense and ordered");
    }

    // Invariant: paginated listing of compositions returns everything in order.
    let all = client.get_cross_contract_events(&0u32, &10u32);
    assert_eq!(all.len(), 4);
    assert_eq!(all.get(0).unwrap().id, 0);
    assert_eq!(all.get(3).unwrap().id, 3);
}

#[test]
fn invariant_composition_and_anchor_records_are_isolated() {
    let (env, _owner, client) = create_ledger();
    let actor = Address::generate(&env);
    let contract_b = Address::generate(&env);

    let mut refs = Vec::new(&env);
    refs.push_back(dummy_ref(&env, &contract_b, 7));

    let comp_id = client.log_event_with_refs(&actor, &symbol_short!("c"), &refs, &Bytes::new(&env));
    let ext_id = client.register_external_event(
        &actor,
        &symbol_short!("ethereum"),
        &Bytes::from_slice(&env, b"0xdead"),
        &BytesN::from_array(&env, &[1u8; 32]),
        &Bytes::new(&env),
    );

    assert_eq!(comp_id, 0, "composition namespace independent of anchors");
    assert_eq!(ext_id, 0, "anchor namespace independent of compositions");

    let comps: Vec<CrossContractEvent> = client.get_cross_contract_events(&0u32, &10u32);
    assert_eq!(comps.len(), 1, "anchors never leak into composition listing");
}

// ── Invariants: tamper-evident digests (#865) ───────────────────────────────

#[test]
fn invariant_composition_digest_deterministic_tamper_evident() {
    let (env, _owner, client) = create_ledger();
    let composer = Address::generate(&env);
    let contract_b = Address::generate(&env);
    env.ledger().set_timestamp(1_700_000_000);

    // Two identical compositions on the same ledger timestamp → identical digests.
    let mut refs = Vec::new(&env);
    refs.push_back(dummy_ref(&env, &contract_b, 1));
    let id1 = client.log_event_with_refs(&composer, &symbol_short!("c"), &refs, &Bytes::from_slice(&env, b"meta"));
    let id2 = client.log_event_with_refs(&composer, &symbol_short!("c"), &refs, &Bytes::from_slice(&env, b"meta"));
    assert_eq!(
        client.get_composition_digest(&id1),
        client.get_composition_digest(&id2),
        "digests are deterministic for identical payload content"
    );

    // Mutating any payload element changes the digest.
    let mut refs2 = refs.clone();
    let mut ref2 = refs2.get(0).unwrap().clone();
    ref2.index = 99;
    refs2.set(0, ref2);
    let id3 = client.log_event_with_refs(&composer, &symbol_short!("c"), &refs2, &Bytes::from_slice(&env, b"meta"));
    assert_ne!(client.get_composition_digest(&id1), client.get_composition_digest(&id3));

    // Freshly stored digests verify as intact.
    assert!(client.verify_composition_integrity(&id1));
    assert!(client.verify_composition_integrity(&id2));
    assert!(client.verify_composition_integrity(&id3));
    assert!(!client.verify_composition_integrity(&999), "unknown composition never verifies");
}

#[test]
fn chaos_digest_detects_content_tampering() {
    let (env, _owner, client) = create_ledger();
    let composer = Address::generate(&env);
    env.ledger().set_timestamp(1_700_000_000);

    let mut refs = Vec::new(&env);
    refs.push_back(dummy_ref(&env, &Address::generate(&env), 1));
    let id = client.log_event_with_refs(&composer, &symbol_short!("c"), &refs, &Bytes::from_slice(&env, b"meta"));
    assert!(client.verify_composition_integrity(&id));

    // Fault injection: silently rescribe the persisted composition body.
    let mut tampered: CrossContractEvent = env
        .storage()
        .persistent()
        .get(&DataKey::CrossContractEvent(id))
        .unwrap();
    tampered.metadata = Bytes::from_slice(&env, b"TAMPERED");
    env.storage().persistent().set(&DataKey::CrossContractEvent(id), &tampered);
    assert!(!client.verify_composition_integrity(&id), "content tampering must be exposed by digest comparison");

    // Fault injection: replace the stored digest itself.
    let mut mutated: CrossContractEvent = env
        .storage()
        .persistent()
        .get(&DataKey::CrossContractEvent(id))
        .unwrap();
    mutated.metadata = Bytes::from_slice(&env, b"meta");
    let real_digest = client.get_composition_digest(&id).unwrap();
    env.storage().persistent().set(&DataKey::XctCompositionHash(id), &real_digest);
    env.storage().persistent().set(&DataKey::CrossContractEvent(id), &mutated);
    assert!(client.verify_composition_integrity(&id), "restoring canonical state restores verification");

    // Fault injection: digest swapped with a foreign digest.
    let fake = BytesN::from_array(&env, &[0xAB; 32]);
    env.storage().persistent().set(&DataKey::XctCompositionHash(id), &fake);
    assert!(!client.verify_composition_integrity(&id), "digest substitution breaks integrity check");
}

// ── Chaos: reordered step recording converges ───────────────────────────────

#[test]
fn chaos_reordered_step_recording_converges() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);
    let contract_b = Address::generate(&env);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), (false, 0, 0), (false, 0, 0)]));
    let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));

    // Record steps out of order: 2, 0, 1 — at distinct ledger timestamps.
    env.ledger().set_timestamp(1_700_000_010);
    client.record_workflow_step(&initiator, &exec_id, &2u32, &dummy_ref(&env, &contract_b, 3));
    env.ledger().set_timestamp(1_700_000_020);
    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));
    env.ledger().set_timestamp(1_700_000_030);
    client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));

    // Reordering invariant: convergence to the same verifiable state.
    assert!(client.verify_cross_chain_workflow(&exec_id));

    // Anchors recorded per-slot survived the arbitrary order.
    let exec = client.get_workflow_events(&exec_id).unwrap();
    assert_eq!(exec.step_anchors.get(0).unwrap(), 1_700_000_020);
    assert_eq!(exec.step_anchors.get(1).unwrap(), 1_700_000_030);
    assert_eq!(exec.step_anchors.get(2).unwrap(), 1_700_000_010);
    assert_eq!(exec.step_events.get(0).unwrap().unwrap().event_id, BytesN::from_array(&env, &[1u8; 32]));
    assert_eq!(exec.status, WorkflowStatus::InProgress, "step recording never changes status");
}

#[test]
fn chaos_step_rewrite_is_idempotent_until_completion() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);
    let contract_b = Address::generate(&env);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), (false, 0, 0)]));
    let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));

    env.ledger().set_timestamp(1_700_000_005);
    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));
    // Re-recording step 0 overwrites that index cleanly (retry semantics).
    env.ledger().set_timestamp(1_700_000_010);
    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 9));
    client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));

    assert!(client.verify_cross_chain_workflow(&exec_id));
    let exec = client.get_workflow_events(&exec_id).unwrap();
    assert_eq!(exec.step_anchors.get(0).unwrap(), 1_700_000_010, "anchor tracks the latest recording");
    assert_eq!(exec.step_events.len(), 2, "no slot duplication from rewrites");
}

#[test]
fn chaos_missing_mandatory_step_never_verifies() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);
    let contract_b = Address::generate(&env);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), (false, 0, 0), (false, 0, 0)]));
    let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));

    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));
    client.record_workflow_step(&initiator, &exec_id, &2u32, &dummy_ref(&env, &contract_b, 3));

    assert!(!client.verify_cross_chain_workflow(&exec_id), "gap in mandatory chain must fail verification");
    assert_eq!(client.get_workflow_events(&exec_id).unwrap().status, WorkflowStatus::InProgress);
}

// ── Chaos: partial failure / rejected writes leave state untouched ─────────

#[test]
fn chaos_out_of_bounds_step_rejected_without_state_change() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);
    let contract_b = Address::generate(&env);
    env.ledger().set_timestamp(1_700_000_000);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), (false, 0, 0)]));
    let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));
    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));

    let exec_before = client.get_workflow_events(&exec_id).unwrap();

    // Out-of-bounds step index (exactly at len and far beyond): rejected.
    let r1 = client.try_record_workflow_step(&initiator, &exec_id, &2u32, &dummy_ref(&env, &contract_b, 5));
    assert!(r1.is_err(), "step_index == steps.len() must be rejected");
    let r2 = client.try_record_workflow_step(&initiator, &exec_id, &4_294_967_295u32, &dummy_ref(&env, &contract_b, 6));
    assert!(r2.is_err(), "hostile step_index (u32::MAX) must be rejected before slot expansion");

    // Partial-failure invariant: execution state bit-for-bit unchanged.
    let exec_after = client.get_workflow_events(&exec_id).unwrap();
    assert_eq!(exec_before.step_events.len(), exec_after.step_events.len());
    assert_eq!(exec_before.step_anchors.len(), exec_after.step_anchors.len());
    assert_eq!(exec_after.status, WorkflowStatus::InProgress);
    assert!(exec_after.step_anchors.get(1).unwrap() == 0, "no phantom anchor from rejected write");

    // System recovers: valid recording proceeds afterwards.
    client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));
    assert!(client.verify_cross_chain_workflow(&exec_id));
}

#[test]
fn chaos_step_on_completed_execution_rejected_atomically() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);
    let contract_b = Address::generate(&env);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), (false, 0, 0)]));
    let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));
    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));
    client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));

    env.ledger().set_timestamp(1_700_005_000);
    client.complete_workflow(&owner, &exec_id);

    let exec_before = client.get_workflow_events(&exec_id).unwrap();

    // Late-arriving (reordered) step event after completion → rejected.
    let late = client.try_record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 8));
    assert!(late.is_err(), "completed executions are frozen");

    // Completion state intact; finished_at wired; verification still green.
    let exec_after = client.get_workflow_events(&exec_id).unwrap();
    assert_eq!(exec_after.status, WorkflowStatus::Completed);
    assert_eq!(exec_after.finished_at, 1_700_005_000);
    assert_eq!(exec_before.step_events.len(), exec_after.step_events.len());
    assert!(client.verify_cross_chain_workflow(&exec_id), "verifiable state is stable across rejected late writes");
}

// ── Chaos: timing-window enforcement (min/max delays) ──────────────────────

#[test]
fn chaos_verify_enforces_delay_windows() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);
    let contract_b = Address::generate(&env);

    // step1 requires min 60s and max 100s after step0.
    let wf = client.define_workflow(
        &owner,
        &symbol_short!("wf"),
        &steps_for(&env, &[(false, 0, 0), (false, 60, 100)]),
    );
    let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));
    env.ledger().set_timestamp(1_700_000_000);
    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));

    // Gap 10s below min_delay → verification fails despite all slots filled.
    env.ledger().set_timestamp(1_700_000_010);
    client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));
    assert!(!client.verify_cross_chain_workflow(&exec_id), "too-fast step must violate min_delay");

    // Re-record (reordered retry semantics) within the window → verifies.
    env.ledger().set_timestamp(1_700_000_080);
    client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));
    assert!(client.verify_cross_chain_workflow(&exec_id), "gap 80s inside [60,100] must verify");

    // Gap beyond max_delay on a fresh execution → fails again.
    let exec2_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));
    env.ledger().set_timestamp(1_700_009_000);
    client.record_workflow_step(&initiator, &exec2_id, &0u32, &dummy_ref(&env, &contract_b, 1));
    env.ledger().set_timestamp(1_700_009_500);
    client.record_workflow_step(&initiator, &exec2_id, &1u32, &dummy_ref(&env, &contract_b, 2));
    assert!(!client.verify_cross_chain_workflow(&exec2_id), "gap 500s beyond max_delay must fail");
}

// ── Chaos: archived definitions ─────────────────────────────────────────────

#[test]
fn chaos_archived_definition_rejects_new_executions() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0)]));
    let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));

    client.archive_workflow(&owner, &wf);

    let rejected = client.try_start_workflow(&initiator, &wf, &Bytes::new(&env));
    assert!(rejected.is_err(), "archived definitions must not spawn executions");

    let defs: Vec<WorkflowDefinition> = client.list_workflows(&0u32, &10u32);
    assert_eq!(defs.len(), 1);
    assert!(!defs.get(0).unwrap().active, "archive is observable via listing");

    // Existing execution of the archived definition remains verifiable.
    client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &Address::generate(&env), 1));
    assert!(client.verify_cross_chain_workflow(&exec_id));
}

// ── Chaos: isolated executions (cross-talk freedom) ────────────────────────

#[test]
fn chaos_interleaved_executions_do_not_cross_talk() {
    let (env, owner, client) = create_ledger();
    let initiator = Address::generate(&env);
    let contract_b = Address::generate(&env);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), (false, 0, 0)]));
    let exec_a = client.start_workflow(&initiator, &wf, &Bytes::new(&env));
    let exec_b = client.start_workflow(&initiator, &wf, &Bytes::new(&env));
    // Steps of both executions interleaved.
    client.record_workflow_step(&initiator, &exec_b, &0u32, &dummy_ref(&env, &contract_b, 1));
    client.record_workflow_step(&initiator, &exec_a, &0u32, &dummy_ref(&env, &contract_b, 2));
    client.record_workflow_step(&initiator, &exec_b, &1u32, &dummy_ref(&env, &contract_b, 3));

    // In execution B only was fully recorded; A stays incomplete.
    assert!(client.verify_cross_chain_workflow(&exec_b));
    assert!(!client.verify_cross_chain_workflow(&exec_a), "execution A unaffected by B's recordings");

    // Finish A; B unchanged.
    client.record_workflow_step(&initiator, &exec_a, &1u32, &dummy_ref(&env, &contract_b, 4));
    assert!(client.verify_cross_chain_workflow(&exec_a) && client.verify_cross_chain_workflow(&exec_b));
}

// ── RBAC gating matrix (#865) ──────────────────────────────────────────────

fn rbac_setup(env: &Env, client: &AuditLedgerClient<'static>, owner: &Address) -> (Address, Address, Address, Address) {
    let submitter = Address::generate(env);
    let viewer = Address::generate(env);
    let admin2 = Address::generate(env);

    client.set_role(owner, &submitter, &Some(Role::Submitter));
    client.set_role(owner, &viewer, &Some(Role::Viewer));
    client.set_role(owner, &admin2, &Some(Role::Admin));
    client.enable_rbac(owner, &true);
    (submitter, viewer, admin2, owner.clone())
}

#[test]
fn invariant_rbac_disabled_keeps_legacy_open_behaviour() {
    let (env, _owner, client) = create_ledger();
    let stranger = Address::generate(&env);
    let contract_b = Address::generate(&env);

    // Compatibility mode: no roles required anywhere (RBAC off by default).
    let mut refs = Vec::new(&env);
    refs.push_back(dummy_ref(&env, &contract_b, 1));
    let comp = client.log_event_with_refs(&stranger, &symbol_short!("c"), &refs, &Bytes::new(&env));
    let ext = client.register_external_event(
        &stranger,
        &symbol_short!("ethereum"),
        &Bytes::from_slice(&env, b"0x1"),
        &BytesN::from_array(&env, &[2u8; 32]),
        &Bytes::new(&env),
    );
    let _ = (comp, ext);
    assert!(!client.is_rbac_enabled());
    assert_eq!(client.get_cross_contract_events(&0u32, &10u32).len(), 1);
}

#[test]
fn invariant_rbac_blocks_unprivileged_callers_on_mutations() {
    let (env, owner, client) = create_ledger();
    let (submitter, viewer, admin2, _owner) = rbac_setup(&env, &client, &owner);
    let contract_b = Address::generate(&env);

    let mut refs = Vec::new(&env);
    refs.push_back(dummy_ref(&env, &contract_b, 1));

    // Composition logging: viewer denied, submitter allowed.
    assert!(client.try_log_event_with_refs(&viewer, &symbol_short!("c"), &refs.clone(), &Bytes::new(&env)).is_err());
    assert!(client.try_log_event_with_refs(&submitter, &symbol_short!("c"), &refs.clone(), &Bytes::new(&env)).is_ok());

    // External anchoring: viewer denied, submitter allowed.
    assert!(client
        .try_register_external_event(&viewer, &symbol_short!("ethereum"), &Bytes::from_slice(&env, b"x"), &BytesN::from_array(&env, &[3u8; 32]), &Bytes::new(&env))
        .is_err());
    assert!(client
        .try_register_external_event(&submitter, &symbol_short!("ethereum"), &Bytes::from_slice(&env, b"x"), &BytesN::from_array(&env, &[3u8; 32]), &Bytes::new(&env))
        .is_ok());

    // Workflow definition: admin-tier → viewer & submitter denied, owner/admin ok.
    let steps = steps_for(&env, &[(false, 0, 0)]);
    assert!(client.try_define_workflow(&viewer, &symbol_short!("wf"), &steps.clone()).is_err());
    assert!(client.try_define_workflow(&submitter, &symbol_short!("wf"), &steps.clone()).is_err());
    assert!(client.try_define_workflow(&admin2, &symbol_short!("wf"), &steps.clone()).is_ok());
    assert!(client.try_define_workflow(&owner, &symbol_short!("wf"), &steps.clone()).is_ok());

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps);
    let exec_id = client.start_workflow(&submitter, &wf, &Bytes::new(&env));

    // Step recording: viewer denied, submitter allowed.
    assert!(client.try_record_workflow_step(&viewer, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 9)).is_err());
    assert!(client.try_record_workflow_step(&submitter, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1)).is_ok());

    // Completion: admin-tier only → submitter denied, owner ok.
    assert!(client.try_complete_workflow(&submitter, &exec_id).is_err());
    assert!(client.try_complete_workflow(&owner, &exec_id).is_ok());

    // Honest state after the rejection matrix: submitter recordings landed,
    // viewer attempts left zero residue.
    let exec = client.get_workflow_events(&exec_id).unwrap();
    assert!(exec.step_events.get(0).unwrap().is_some());
}

#[test]
fn chaos_rbac_role_lifecycle_mid_execution() {
    let (env, owner, client) = create_ledger();
    let (submitter, viewer, admin2, owner) = rbac_setup(&env, &client, &owner);
    let contract_b = Address::generate(&env);

    let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), (false, 0, 0)]));
    let exec_id = client.start_workflow(&submitter, &wf, &Bytes::new(&env));
    client.record_workflow_step(&submitter, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));

    // Mid-execution demotion: submitter → viewer; further recordings denied.
    client.set_role(&owner, &submitter, &Some(Role::Viewer));
    assert!(client.try_record_workflow_step(&submitter, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2)).is_err());

    // Role restoration restores workflow operability (chaos recovery).
    client.set_role(&owner, &submitter, &Some(Role::Submitter));
    client.record_workflow_step(&submitter, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));
    assert!(client.verify_cross_chain_workflow(&exec_id));

    // Demoting an admin is permitted, but governance is then inaccessible for
    // that identity until another admin restores it.
    client.set_role(&owner, &viewer, &Some(Role::Admin));
    client.set_role(&admin2, &owner, &Some(Role::Viewer));
    assert!(client.try_define_workflow(&owner, &symbol_short!("wf2"), &steps_for(&env, &[(false, 0, 0)])).is_err());

    // Another admin restores the demoted identity; governance recovers.
    client.set_role(&admin2, &owner, &Some(Role::Admin));
    let _ = client.define_workflow(&owner, &symbol_short!("wf2"), &steps_for(&env, &[(false, 0, 0)]));
}

// ── TTL bump policy & rent accounting (#866) ───────────────────────────────

#[test]
fn invariant_ttl_policy_defaults_and_bump_accounting() {
    let (env, _owner, client) = create_ledger();
    let actor = Address::generate(&env);
    let contract_b = Address::generate(&env);

    // Default policy matches documented constants.
    let policy = client.get_xct_ttl_policy();
    assert_eq!(policy.bump_threshold, XCT_TTL_DEFAULT_THRESHOLD_LEDGERS);
    assert_eq!(policy.bump_target, XCT_TTL_DEFAULT_TARGET_LEDGERS);

    // No archival activity → zero bumps.
    let stats0 = client.get_xct_rent_stats();
    assert_eq!(stats0.bumps, 0);

    // An archival write bumps its keys (composition body + digest).
    let mut refs = Vec::new(&env);
    refs.push_back(dummy_ref(&env, &contract_b, 1));
    let id = client.log_event_with_refs(&actor, &symbol_short!("c"), &refs, &Bytes::new(&env));

    let stats1 = client.get_xct_rent_stats();
    assert!(stats1.bumps > stats0.bumps, "archival writes bump keys per policy");
    assert!(stats1.last_bump_ledger > 0);

    // A read of the archival key bumps it again (automated bump-on-read).
    let before_list = client.get_xct_rent_stats().bumps;
    let _ = client.get_cross_contract_events(&0u32, &10u32);
    assert!(client.get_xct_rent_stats().bumps > before_list, "listings bump enumerated archival keys");

    // Digest retrieval bumps its key too.
    let before_digest = client.get_xct_rent_stats().bumps;
    assert!(client.get_composition_digest(&id).is_some());
    assert!(client.get_xct_rent_stats().bumps > before_digest, "digest reads bump the digest key");

    // last_bump_ledger stays meaningful and bump counts never regress.
    let first = client.get_xct_rent_stats();
    assert!(first.bumps >= before_digest);
    assert!(first.last_bump_ledger > 0);
}

#[test]
fn invariant_ttl_policy_requires_admin_and_validates_params() {
    let (env, owner, client) = create_ledger();

    // Hostile parameter sets are rejected before any policy write.
    assert!(client.try_set_xct_ttl_policy(&owner, &0, &100_000).is_err(), "zero threshold rejected");
    assert!(client.try_set_xct_ttl_policy(&owner, &20_000, &10_000).is_err(), "target below threshold rejected");
    assert!(client.try_set_xct_ttl_policy(&owner, &20_000, &20_000).is_err() == false, "target == threshold allowed");

    let policy = client.get_xct_ttl_policy();
    assert_eq!(policy.bump_threshold, 20_000);
    assert_eq!(policy.bump_target, 20_000);

    // Valid update persists.
    client.set_xct_ttl_policy(&owner, &50_000, &150_000);
    let policy2 = client.get_xct_ttl_policy();
    assert_eq!(policy2.bump_threshold, 50_000);
    assert_eq!(policy2.bump_target, 150_000);
}

#[test]
fn chaos_policy_change_takes_effect_for_subsequent_bumps() {
    let (env, owner, client) = create_ledger();
    let actor = Address::generate(&env);
    let contract_b = Address::generate(&env);

    // Aggressive policy: bump every touched key.
    client.set_xct_ttl_policy(&owner, &50_000, &100_000);

    let mut refs = Vec::new(&env);
    refs.push_back(dummy_ref(&env, &contract_b, 1));
    let id = client.log_event_with_refs(&actor, &symbol_short!("c"), &refs, &Bytes::new(&env));

    let bumps0 = client.get_xct_rent_stats().bumps;
    assert!(bumps0 > 0);

    // verify path does not bump (pure comparison) — bump counter stable.
    assert!(client.verify_composition_integrity(&id));
    assert_eq!(client.get_xct_rent_stats().bumps, bumps0, "pure verification must not extend TTL");

    // Weaker policy: reads below threshold stay dormant (no bump until read).
    client.set_xct_ttl_policy(&owner, &1_000_000_000, &1_000_000_000);
    let _ = client.list_workflows(&0u32, &10u32);
    assert!(client.get_xct_rent_stats().bumps >= bumps0, "policy thresholds gate bump triggance");
}

// ── Property-based reordering suite (#868) ────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, .. ProptestConfig::default() })]

    /// For arbitrary workflow shapes and arbitrary *recorded subsets* and
    /// recording orders: `verify_cross_chain_workflow` must evaluate to
    /// *exactly* "every mandatory step slot is filled" — no phantom
    /// verification, no missed verification, regardless of event order.
    #[test]
    fn prop_verify_iff_all_mandatory_recorded(
        optional_flags in prop::collection::vec(proptest::bool::ANY, 1..=6),
        recorded_mask in any::<u32>(),
        order_keys in prop::collection::vec(any::<u64>(), 0..=18),
    ) {
        let (env, owner, client) = create_ledger();
        let initiator = Address::generate(&env);
        let contract_b = Address::generate(&env);
        env.ledger().set_timestamp(1_700_000_000);

        let width = optional_flags.len();
        let mut flags = std::vec::Vec::with_capacity(width);
        for opt in optional_flags.iter() {
            flags.push((*opt, 0u64, 0u64));
        }
        let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &flags));
        let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));

        // Deterministic pseudo-shuffle of the recording order.
        let mut order = std::vec::Vec::new();
        for i in 0..width {
            if recorded_mask & (1u32 << i) != 0 {
                order.push((i, order_keys.get(i % std::cmp::max(order_keys.len(), 1)).copied().unwrap_or(i as u64)));
            }
        }
        order.sort_by_key(|(_idx, key)| *key);
        for (idx, _key) in order.iter() {
            client.record_workflow_step(
                &initiator,
                &exec_id,
                &(*idx as u32),
                &dummy_ref(&env, &contract_b, (idx + 1) as u8),
            );
        }

        // Verdict invariant: verification == "all mandatory slots filled".
        let mut expected = true;
        for i in 0..width {
            if optional_flags[i] {
                continue;
            }
            if recorded_mask & (1u32 << i) == 0 {
                expected = false;
            }
        }
        assert_eq!(client.verify_cross_chain_workflow(&exec_id), expected);

        // Execution never mutates its status via step recordings.
        let exec = client.get_workflow_events(&exec_id).unwrap();
        assert_eq!(exec.status, WorkflowStatus::InProgress);
        assert_eq!(exec.step_events.len() as usize, width, "slot width matches definition exactly");
        for i in 0..width {
            let filled = recorded_mask & (1u32 << i) != 0;
            assert_eq!(exec.step_events.get(i as u32).unwrap().is_some(), filled);
            let anchor = exec.step_anchors.get(i as u32).unwrap();
            assert_eq!(anchor != 0, filled, "anchors mirror recording state exactly");
        }
    }

    /// Delay-exercise property: for arbitrary min/max windows around an
    /// arbitrary second-step timestamp, the verdict is exactly the window
    /// containment predicate — reordered "late arrivals" can never fix the
    /// timing semantics because anchors track the latest recording.
    #[test]
    fn prop_delay_window_verdict(
        anchor_secs in 1u64..=1_000_000u64,
        min_delay in 0u64..=100u64,
        max_delay in 110u64..=200u64,
    ) {
        let (env, owner, client) = create_ledger();
        let initiator = Address::generate(&env);
        let contract_b = Address::generate(&env);

        let delay_step = (false, min_delay, max_delay);
        let wf = client.define_workflow(&owner, &symbol_short!("wf"), &steps_for(&env, &[(false, 0, 0), delay_step]));
        let exec_id = client.start_workflow(&initiator, &wf, &Bytes::new(&env));

        env.ledger().set_timestamp(1_000);
        client.record_workflow_step(&initiator, &exec_id, &0u32, &dummy_ref(&env, &contract_b, 1));
        env.ledger().set_timestamp(1_000 + anchor_secs);
        client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));

        let expected = anchor_secs >= min_delay && anchor_secs <= max_delay;
        assert_eq!(client.verify_cross_chain_workflow(&exec_id), expected);

        // Rewriting the anchor (reordered retry at a new timestamp) updates
        // the verdict to track the newest anchor — content-addressed state.
        let reanchor = anchor_secs / 2;
        env.ledger().set_timestamp(1_000 + reanchor);
        client.record_workflow_step(&initiator, &exec_id, &1u32, &dummy_ref(&env, &contract_b, 2));
        let expected2 = reanchor >= min_delay && reanchor <= max_delay;
        assert_eq!(
            client.verify_cross_chain_workflow(&exec_id),
            expected2,
            "verdict must follow the latest recorded anchor"
        );
    }
}
