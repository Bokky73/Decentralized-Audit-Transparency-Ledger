#![cfg(test)]
//! RBAC Gating and Precedence Unit Tests (#686 #689 #688 #687)
//!
//! Includes the positive/negative RBAC matrix integration tests for the
//! `esg_reporting` module (#875): role hierarchy precedence, revocation
//! behavior, rejection of unauthorized/suspended submitter DIDs with stable
//! error codes, and structured audit event emission for both successful
//! mutations and rejected access attempts.

use super::esg_reporting::*;
use super::rbac::*;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, Env, IntoVal, Symbol};

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
// ESG reporting RBAC matrix integration tests (#875)
// ---------------------------------------------------------------------------

/// Helper: set up an ESG ledger with an admin and return the admin address.
fn setup_esg(env: &Env) -> Address {
    let admin = Address::generate(env);
    env.mock_all_auths();
    Rbac::init_admin(env, &admin);
    EsgReporting::init(env, &admin);
    admin
}

/// Helper: assert that an audit event with the given topic/action was emitted.
fn assert_audit_event(env: &Env, action: Symbol) {
    let events = env.events().all();
    let mut found = false;
    for (_contract, topics, _data) in events.iter() {
        if let Some(first) = topics.get(0) {
            let topic: Symbol = first.into_val(env);
            if topic == action {
                found = true;
                break;
            }
        }
    }
    assert!(found, "expected audit event for action");
}

#[test]
fn test_esg_rbac_matrix_positive_roles() {
    let env = Env::default();
    let admin = setup_esg(&env);

    let submitter = Address::generate(&env);
    let auditor = Address::generate(&env);

    Rbac::set_role(&env, &admin, &submitter, Role::Submitter).unwrap();
    Rbac::set_role(&env, &admin, &auditor, Role::Auditor).unwrap();

    // Submitter may record emissions (state mutation).
    let res = EsgReporting::record_emissions(&env, &submitter, 1, 100, 0);
    assert!(res.is_ok(), "submitter should be allowed to record emissions");

    // Auditor may verify/attest but not mutate the ledger.
    let res = EsgReporting::verify_emissions(&env, &auditor, 1);
    assert!(res.is_ok(), "auditor should be allowed to verify emissions");

    // Admin retains full privileges.
    let res = EsgReporting::record_emissions(&env, &admin, 2, 50, 0);
    assert!(res.is_ok(), "admin should be allowed to record emissions");
}

#[test]
fn test_esg_rbac_matrix_negative_roles() {
    let env = Env::default();
    let admin = setup_esg(&env);

    let viewer = Address::generate(&env);
    let rogue = Address::generate(&env);

    Rbac::set_role(&env, &admin, &viewer, Role::Viewer).unwrap();

    // Viewer lacks Submitter privileges: mutation must be rejected.
    let err = EsgReporting::record_emissions(&env, &viewer, 1, 100, 0);
    assert_eq!(err, Err(EsgError::InsufficientRole));

    // Unknown caller (no role at all) must be rejected.
    let err = EsgReporting::record_emissions(&env, &rogue, 1, 100, 0);
    assert_eq!(err, Err(EsgError::InsufficientRole));

    // Viewer cannot verify either (requires Auditor).
    let err = EsgReporting::verify_emissions(&env, &viewer, 1);
    assert_eq!(err, Err(EsgError::InsufficientRole));
}

#[test]
fn test_esg_role_hierarchy_precedence() {
    let env = Env::default();
    let admin = setup_esg(&env);

    let auditor = Address::generate(&env);
    Rbac::set_role(&env, &admin, &auditor, Role::Auditor).unwrap();

    // Auditor outranks Submitter: inherits Submitter capabilities.
    assert!(Rbac::has_role_min(&env, &auditor, Role::Submitter));
    let res = EsgReporting::record_emissions(&env, &auditor, 1, 100, 0);
    assert!(res.is_ok(), "auditor should inherit submitter capability");

    // Admin outranks Auditor.
    assert!(Rbac::has_role_min(&env, &admin, Role::Auditor));
}

#[test]
fn test_esg_revocation_blocks_mutation() {
    let env = Env::default();
    let admin = setup_esg(&env);

    let submitter = Address::generate(&env);
    Rbac::set_role(&env, &admin, &submitter, Role::Submitter).unwrap();

    // Allowed while holding the role.
    assert!(EsgReporting::record_emissions(&env, &submitter, 1, 100, 0).is_ok());

    // Revoke the role.
    Rbac::set_role(&env, &admin, &submitter, Role::Viewer).unwrap();

    // Subsequent mutation must be rejected with a stable error code.
    let err = EsgReporting::record_emissions(&env, &submitter, 2, 100, 0);
    assert_eq!(err, Err(EsgError::InsufficientRole));
}

#[test]
fn test_esg_suspended_submitter_rejected() {
    let env = Env::default();
    let admin = setup_esg(&env);

    let submitter = Address::generate(&env);
    Rbac::set_role(&env, &admin, &submitter, Role::Submitter).unwrap();

    // Suspend the submitter DID.
    Rbac::suspend(&env, &admin, &submitter).unwrap();

    let err = EsgReporting::record_emissions(&env, &submitter, 1, 100, 0);
    assert_eq!(err, Err(EsgError::Suspended));

    // Reinstating restores access.
    Rbac::unsuspend(&env, &admin, &submitter).unwrap();
    assert!(EsgReporting::record_emissions(&env, &submitter, 1, 100, 0).is_ok());
}

#[test]
fn test_esg_audit_events_on_success_and_rejection() {
    let env = Env::default();
    let admin = setup_esg(&env);

    let submitter = Address::generate(&env);
    let rogue = Address::generate(&env);
    Rbac::set_role(&env, &admin, &submitter, Role::Submitter).unwrap();

    // Successful mutation emits a structured audit event.
    EsgReporting::record_emissions(&env, &submitter, 1, 100, 0).unwrap();
    assert_audit_event(&env, Symbol::new(&env, "esg_record"));

    // Rejected access attempt also emits an audit event.
    let _ = EsgReporting::record_emissions(&env, &rogue, 1, 100, 0);
    assert_audit_event(&env, Symbol::new(&env, "esg_denied"));
}
