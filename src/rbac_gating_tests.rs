#![cfg(test)]
//! RBAC Gating and Precedence Unit Tests (#686 #689 #688 #687)

use super::rbac::*;
use super::supply_chain::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

#[test]
fn test_rbac_roles_and_privilege_ladder() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let auditor = Address::generate(&env);
    let submitter = Address::generate(&env);
    let viewer = Address::generate(&env);

    env.mock_all_auths();
    Rbac::init_admin(&env, &admin);

    assert_eq!(Rbac::get_role(&env, &admin), Some(Role::Admin));
    assert!(Rbac::has_role_min(&env, &admin, Role::Admin));

    // Assign Auditor
    Rbac::set_role(&env, &admin, &auditor, Role::Auditor).unwrap();
    assert_eq!(Rbac::get_role(&env, &auditor), Some(Role::Auditor));
    assert!(Rbac::has_role_min(&env, &auditor, Role::Auditor));
    assert!(Rbac::has_role_min(&env, &auditor, Role::Submitter));
    assert!(Rbac::has_role_min(&env, &auditor, Role::Viewer));
    assert!(!Rbac::has_role_min(&env, &auditor, Role::Admin));

    // Assign Submitter
    Rbac::set_role(&env, &admin, &submitter, Role::Submitter).unwrap();
    assert_eq!(Rbac::get_role(&env, &submitter), Some(Role::Submitter));
    assert!(Rbac::has_role_min(&env, &submitter, Role::Submitter));
    assert!(Rbac::has_role_min(&env, &submitter, Role::Viewer));
    assert!(!Rbac::has_role_min(&env, &submitter, Role::Auditor));

    // Assign Viewer
    Rbac::set_role(&env, &admin, &viewer, Role::Viewer).unwrap();
    assert_eq!(Rbac::get_role(&env, &viewer), Some(Role::Viewer));
    assert!(Rbac::has_role_min(&env, &viewer, Role::Viewer));
    assert!(!Rbac::has_role_min(&env, &viewer, Role::Submitter));
}

#[test]
fn test_rbac_non_admin_cannot_promote() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let rogue = Address::generate(&env);
    let target = Address::generate(&env);

    env.mock_all_auths();
    Rbac::init_admin(&env, &admin);

    let err = Rbac::set_role(&env, &rogue, &target, Role::Admin);
    assert_eq!(err, Err(RbacError::InsufficientRole));
}

#[test]
fn test_rbac_cannot_remove_sole_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);

    env.mock_all_auths();
    Rbac::init_admin(&env, &admin);

    let err = Rbac::set_role(&env, &admin, &admin, Role::Viewer);
    assert_eq!(err, Err(RbacError::CannotRevokeLastAdmin));
}

// ---------------------------------------------------------------------------
// Supply chain mutating entrypoint RBAC matrix (#870)
// ---------------------------------------------------------------------------

fn sc_setup(env: &Env) -> (Address, Address, Address, Address) {
    let admin = Address::generate(env);
    let auditor = Address::generate(env);
    let submitter = Address::generate(env);
    let viewer = Address::generate(env);

    env.mock_all_auths();
    Rbac::init_admin(env, &admin);
    Rbac::set_role(env, &admin, &auditor, Role::Auditor).unwrap();
    Rbac::set_role(env, &admin, &submitter, Role::Submitter).unwrap();
    Rbac::set_role(env, &admin, &viewer, Role::Viewer).unwrap();

    (admin, auditor, submitter, viewer)
}

fn sc_did(env: &Env, tag: &str) -> String {
    String::from_str(env, tag)
}

#[test]
fn test_supply_chain_register_requires_submitter_role() {
    let env = Env::default();
    let (_admin, auditor, submitter, viewer) = sc_setup(&env);

    // Positive: Submitter (and higher) may register a custody record.
    let ok = SupplyChain::register_record(
        &env,
        &submitter,
        &sc_did(&env, "did:sc:submitter"),
        &sc_did(&env, "lot-1"),
    );
    assert!(ok.is_ok());

    // Auditor sits above Submitter in the privilege ladder -> allowed.
    let ok_auditor = SupplyChain::register_record(
        &env,
        &auditor,
        &sc_did(&env, "did:sc:auditor"),
        &sc_did(&env, "lot-2"),
    );
    assert!(ok_auditor.is_ok());

    // Negative: Viewer is below Submitter -> stable RBAC error code.
    let err = SupplyChain::register_record(
        &env,
        &viewer,
        &sc_did(&env, "did:sc:viewer"),
        &sc_did(&env, "lot-3"),
    );
    assert_eq!(err, Err(RbacError::InsufficientRole));

    // Negative: unregistered caller has no role at all.
    let stranger = Address::generate(&env);
    let err_stranger = SupplyChain::register_record(
        &env,
        &stranger,
        &sc_did(&env, "did:sc:stranger"),
        &sc_did(&env, "lot-4"),
    );
    assert_eq!(err_stranger, Err(RbacError::InsufficientRole));
}

#[test]
fn test_supply_chain_handoff_requires_submitter_role() {
    let env = Env::default();
    let (_admin, auditor, submitter, viewer) = sc_setup(&env);

    SupplyChain::register_record(
        &env,
        &submitter,
        &sc_did(&env, "did:sc:submitter"),
        &sc_did(&env, "lot-h1"),
    )
    .unwrap();

    // Positive: Submitter performs the custody handoff.
    let ok = SupplyChain::handoff(
        &env,
        &submitter,
        &sc_did(&env, "lot-h1"),
        &sc_did(&env, "did:sc:next"),
    );
    assert!(ok.is_ok());

    // Negative: Viewer cannot mutate custody state.
    let err = SupplyChain::handoff(
        &env,
        &viewer,
        &sc_did(&env, "lot-h1"),
        &sc_did(&env, "did:sc:next2"),
    );
    assert_eq!(err, Err(RbacError::InsufficientRole));

    // Auditor is above Submitter, so the handoff is permitted.
    let ok_auditor = SupplyChain::handoff(
        &env,
        &auditor,
        &sc_did(&env, "lot-h1"),
        &sc_did(&env, "did:sc:next3"),
    );
    assert!(ok_auditor.is_ok());
}

#[test]
fn test_supply_chain_suspended_submitter_is_blocked() {
    let env = Env::default();
    let (admin, _auditor, submitter, _viewer) = sc_setup(&env);

    SupplyChain::register_record(
        &env,
        &submitter,
        &sc_did(&env, "did:sc:submitter"),
        &sc_did(&env, "lot-s1"),
    )
    .unwrap();

    // Suspend the submitter DID; further mutations must be rejected.
    Rbac::suspend(&env, &admin, &submitter).unwrap();

    let err = SupplyChain::handoff(
        &env,
        &submitter,
        &sc_did(&env, "lot-s1"),
        &sc_did(&env, "did:sc:next"),
    );
    assert_eq!(err, Err(RbacError::Suspended));

    // Revocation behaves the same way.
    Rbac::set_role(&env, &admin, &submitter, Role::Viewer).unwrap();
    let err_revoked = SupplyChain::handoff(
        &env,
        &submitter,
        &sc_did(&env, "lot-s1"),
        &sc_did(&env, "did:sc:next"),
    );
    assert_eq!(err_revoked, Err(RbacError::InsufficientRole));
}

#[test]
fn test_supply_chain_emits_audit_events_on_success_and_rejection() {
    let env = Env::default();
    let (_admin, _auditor, submitter, viewer) = sc_setup(&env);

    // Successful mutation emits a structured audit event.
    SupplyChain::register_record(
        &env,
        &submitter,
        &sc_did(&env, "did:sc:submitter"),
        &sc_did(&env, "lot-e1"),
    )
    .unwrap();
    let success_events = env.events().all();
    assert!(!success_events.is_empty());

    // Rejected access attempt also emits an audit event.
    let before = env.events().all().len();
    let err = SupplyChain::register_record(
        &env,
        &viewer,
        &sc_did(&env, "did:sc:viewer"),
        &sc_did(&env, "lot-e2"),
    );
    assert_eq!(err, Err(RbacError::InsufficientRole));
    let after = env.events().all().len();
    assert!(after > before);
}
