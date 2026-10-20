//! # Positive and Negative RBAC Matrix Integration Tests (`rbac_gating_tests`)
//!
//! Verifies fine-grained Role-Based Access Control (`src/rbac.rs`) and structured tamper-evident
//! audit/diagnostic event emission across all state-mutating entrypoints of `src/capacity_planning.rs`
//! (Issue #900).

use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{Address, Bytes, BytesN, Env};

use crate::capacity_planning::{self, AlertSeverity, AlertStatus};
use crate::rbac::{self, Permission, RbacError, Role};
use crate::{AuditLedger, AuditLedgerClient};

struct RbacTestFixture {
    env: Env,
    contract_id: Address,
    client: AuditLedgerClient<'static>,
    owner: Address,
    admin: Address,
    auditor: Address,
    planner: Address,
    operator: Address,
    viewer: Address,
    outsider: Address,
}

fn setup_fixture() -> RbacTestFixture {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let admin = Address::generate(&env);
    let auditor = Address::generate(&env);
    let planner = Address::generate(&env);
    let operator = Address::generate(&env);
    let viewer = Address::generate(&env);
    let outsider = Address::generate(&env);

    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);
    client.initialize(&owner, &10_000);

    client.grant_role(
        &owner,
        &admin,
        &Role::Admin,
        &Bytes::from_slice(&env, b"did:stellar:admin-01"),
    );
    client.grant_role(
        &admin,
        &auditor,
        &Role::Auditor,
        &Bytes::from_slice(&env, b"did:stellar:auditor-01"),
    );
    client.grant_role(
        &admin,
        &planner,
        &Role::CapacityPlanner,
        &Bytes::from_slice(&env, b"did:stellar:planner-01"),
    );
    client.grant_role(
        &admin,
        &operator,
        &Role::Operator,
        &Bytes::from_slice(&env, b"did:stellar:operator-01"),
    );
    client.grant_role(
        &admin,
        &viewer,
        &Role::Viewer,
        &Bytes::from_slice(&env, b"did:stellar:viewer-01"),
    );

    RbacTestFixture {
        env,
        contract_id,
        client,
        owner,
        admin,
        auditor,
        planner,
        operator,
        viewer,
        outsider,
    }
}

#[test]
fn test_role_hierarchy_precedence_matrix() {
    let roles = [
        Role::Viewer,
        Role::Operator,
        Role::CapacityPlanner,
        Role::Auditor,
        Role::Admin,
    ];

    for (i, r_low) in roles.iter().enumerate() {
        for (j, r_high) in roles.iter().enumerate() {
            if j >= i {
                assert!(
                    r_high.satisfies(*r_low),
                    "{:?} should satisfy {:?}",
                    r_high,
                    r_low
                );
            } else {
                assert!(
                    !r_high.satisfies(*r_low),
                    "{:?} must not satisfy {:?}",
                    r_high,
                    r_low
                );
            }
        }
    }

    assert!(Role::Admin.has_permission(Permission::AdministerRbac));
    assert!(!Role::Auditor.has_permission(Permission::AdministerRbac));
    assert!(Role::Auditor.has_permission(Permission::ResolveAlert));
    assert!(Role::Auditor.has_permission(Permission::ConfigureShardThreshold));
    assert!(!Role::CapacityPlanner.has_permission(Permission::ResolveAlert));
    assert!(Role::CapacityPlanner.has_permission(Permission::ConfigureShardThreshold));
    assert!(Role::CapacityPlanner.has_permission(Permission::RecordShardTelemetry));
    assert!(!Role::Operator.has_permission(Permission::ConfigureShardThreshold));
    assert!(Role::Operator.has_permission(Permission::RecordShardTelemetry));
    assert!(!Role::Viewer.has_permission(Permission::RecordShardTelemetry));
    assert!(Role::Viewer.has_permission(Permission::ReadCapacityState));
}

#[test]
fn test_positive_and_negative_matrix_configure_shard_threshold() {
    let f = setup_fixture();

    // Negative: Outsider (unassigned) -> UnauthorizedCaller (1001)
    let res_outsider = f.env.as_contract(&f.contract_id, || {
        capacity_planning::configure_shard_threshold(&f.env, &f.outsider, 1, 10_000, 7500, 9000)
    });
    assert_eq!(res_outsider, Err(RbacError::UnauthorizedCaller));

    // Negative: Viewer -> InsufficientRole (1002)
    let res_viewer = f.env.as_contract(&f.contract_id, || {
        capacity_planning::configure_shard_threshold(&f.env, &f.viewer, 1, 10_000, 7500, 9000)
    });
    assert_eq!(res_viewer, Err(RbacError::InsufficientRole));

    // Negative: Operator -> InsufficientRole (1002)
    let res_operator = f.env.as_contract(&f.contract_id, || {
        capacity_planning::configure_shard_threshold(&f.env, &f.operator, 1, 10_000, 7500, 9000)
    });
    assert_eq!(res_operator, Err(RbacError::InsufficientRole));

    // Positive: CapacityPlanner -> Allowed
    let cfg_planner = f
        .client
        .configure_shard_threshold(&f.planner, &1, &10_000, &7500, &9000);
    assert_eq!(cfg_planner.shard_id, 1);
    assert_eq!(cfg_planner.max_capacity_events, 10_000);
    assert_eq!(cfg_planner.updated_by, f.planner);

    // Positive (hierarchy precedence): Auditor (> CapacityPlanner) -> Allowed
    let cfg_auditor = f
        .client
        .configure_shard_threshold(&f.auditor, &1, &20_000, &7000, &8500);
    assert_eq!(cfg_auditor.max_capacity_events, 20_000);
    assert_eq!(cfg_auditor.updated_by, f.auditor);

    // Positive: Owner (implicit Admin) -> Allowed
    let cfg_owner = f
        .client
        .configure_shard_threshold(&f.owner, &1, &30_000, &8000, &9500);
    assert_eq!(cfg_owner.max_capacity_events, 30_000);
    assert_eq!(cfg_owner.updated_by, f.owner);
}

#[test]
fn test_positive_and_negative_matrix_record_utilization_and_alerts() {
    let f = setup_fixture();
    f.client
        .configure_shard_threshold(&f.planner, &1, &1_000, &7500, &9000);

    // Negative: Outsider -> UnauthorizedCaller
    let res_outsider = f.env.as_contract(&f.contract_id, || {
        capacity_planning::record_shard_utilization(&f.env, &f.outsider, 1, 500, 25)
    });
    assert_eq!(res_outsider, Err(RbacError::UnauthorizedCaller));

    // Negative: Viewer -> InsufficientRole
    let res_viewer = f.env.as_contract(&f.contract_id, || {
        capacity_planning::record_shard_utilization(&f.env, &f.viewer, 1, 500, 25)
    });
    assert_eq!(res_viewer, Err(RbacError::InsufficientRole));

    // Positive: Operator records 800/1000 (8000 bps >= 7500 warning) -> triggers Warning alert #0
    let sample = f
        .client
        .record_shard_utilization(&f.operator, &1, &800, &50);
    assert_eq!(sample.utilization_bps, 8000);
    assert_eq!(sample.triggered_alert_id, 0);

    let alert0 = f
        .env
        .as_contract(&f.contract_id, || {
            capacity_planning::get_threshold_alert(&f.env, 0)
        })
        .unwrap();
    assert_eq!(alert0.severity, AlertSeverity::Warning);
    assert_eq!(alert0.status, AlertStatus::Open);

    // Positive (hierarchy precedence): CapacityPlanner records 950/1000 (9500 bps >= 9000 critical) -> triggers Critical alert #1
    let sample2 = f.client.record_shard_utilization(&f.planner, &1, &950, &60);
    assert_eq!(sample2.utilization_bps, 9500);
    assert_eq!(sample2.triggered_alert_id, 1);

    let alert1 = f
        .env
        .as_contract(&f.contract_id, || {
            capacity_planning::get_threshold_alert(&f.env, 1)
        })
        .unwrap();
    assert_eq!(alert1.severity, AlertSeverity::Critical);
}

#[test]
fn test_positive_and_negative_matrix_forecast_and_alert_resolution() {
    let f = setup_fixture();
    f.client
        .configure_shard_threshold(&f.planner, &2, &10_000, &7500, &9000);
    f.client
        .record_shard_utilization(&f.operator, &2, &8_000, &200);

    // Forecast gating: Operator cannot generate forecast -> InsufficientRole
    let res_op_fcst = f.env.as_contract(&f.contract_id, || {
        capacity_planning::generate_capacity_forecast(&f.env, &f.operator, 2, 24)
    });
    assert_eq!(res_op_fcst, Err(RbacError::InsufficientRole));

    // CapacityPlanner can generate forecast
    let forecast = f.client.generate_capacity_forecast(&f.planner, &2, &24);
    assert_eq!(forecast.projected_events, 8_000 + 200 * 24);
    assert_eq!(forecast.projected_utilization_bps, 12_800);
    assert_eq!(forecast.estimated_hours_to_exhaustion, 10);
    assert!(forecast.recommended_additional_shards >= 1);

    // Alert acknowledgement: Viewer rejected, Operator allowed
    let res_view_ack = f.env.as_contract(&f.contract_id, || {
        capacity_planning::acknowledge_threshold_alert(&f.env, &f.viewer, 0)
    });
    assert_eq!(res_view_ack, Err(RbacError::InsufficientRole));

    let acked = f.client.acknowledge_threshold_alert(&f.operator, &0);
    assert_eq!(acked.status, AlertStatus::Acknowledged);

    // Alert resolution: Operator and CapacityPlanner rejected, Auditor and Admin allowed
    let resolution_hash = BytesN::from_array(&f.env, &[0xAB; 32]);
    let res_op_resolve = f.env.as_contract(&f.contract_id, || {
        capacity_planning::resolve_threshold_alert(&f.env, &f.operator, 0, resolution_hash.clone())
    });
    assert_eq!(res_op_resolve, Err(RbacError::InsufficientRole));

    let res_plan_resolve = f.env.as_contract(&f.contract_id, || {
        capacity_planning::resolve_threshold_alert(&f.env, &f.planner, 0, resolution_hash.clone())
    });
    assert_eq!(res_plan_resolve, Err(RbacError::InsufficientRole));

    let resolved = f
        .client
        .resolve_threshold_alert(&f.auditor, &0, &resolution_hash);
    assert_eq!(resolved.status, AlertStatus::Resolved);
    assert_eq!(resolved.resolution_digest, resolution_hash);

    // Policy override: CapacityPlanner rejected, Auditor allowed
    let res_plan_ovr = f.env.as_contract(&f.contract_id, || {
        capacity_planning::override_shard_capacity_policy(&f.env, &f.planner, 2, 50_000, true)
    });
    assert_eq!(res_plan_ovr, Err(RbacError::InsufficientRole));

    let overridden = f
        .client
        .override_shard_capacity_policy(&f.auditor, &2, &50_000, &true);
    assert_eq!(overridden.max_capacity_events, 50_000);
    assert!(overridden.emergency_frozen);
}

#[test]
fn test_role_revocation_and_suspended_submitter_did_rejection() {
    let f = setup_fixture();
    f.client
        .configure_shard_threshold(&f.planner, &3, &5_000, &7000, &9000);

    // Suspend planner's DID -> rejected with SuspendedSubmitterDid (1003)
    f.client.suspend_submitter_did(&f.admin, &f.planner);

    let res_suspended = f.env.as_contract(&f.contract_id, || {
        capacity_planning::generate_capacity_forecast(&f.env, &f.planner, 3, 12)
    });
    assert_eq!(res_suspended, Err(RbacError::SuspendedSubmitterDid));

    // Also verify via client.try_* that stable ContractError 1003 is returned
    let try_res = f.client.try_generate_capacity_forecast(&f.planner, &3, &12);
    assert_eq!(try_res, Err(Ok(RbacError::SuspendedSubmitterDid)));

    // Reinstate planner's DID -> succeeds again
    f.client.reinstate_submitter_did(&f.admin, &f.planner);
    let fcst = f.client.generate_capacity_forecast(&f.planner, &3, &12);
    assert_eq!(fcst.shard_id, 3);

    // Revoke planner's role -> rejected with RevokedRole (1004)
    f.client.revoke_role(&f.admin, &f.planner);
    let res_revoked = f.env.as_contract(&f.contract_id, || {
        capacity_planning::generate_capacity_forecast(&f.env, &f.planner, 3, 12)
    });
    assert_eq!(res_revoked, Err(RbacError::RevokedRole));
}

#[test]
fn test_structured_audit_events_emitted_on_success_and_rejection() {
    let f = setup_fixture();
    let count_before = f.client.rbac_audit_trail_count();

    // 1. Successful mutation by planner
    f.env.ledger().set_timestamp(1_700_000_500);
    f.client
        .configure_shard_threshold(&f.planner, &7, &10_000, &7500, &9000);

    // Verify Soroban host events (`rbac_aud` and `cap_diag`) were emitted on success
    let success_host_events = f.env.events().all();
    assert!(!success_host_events.events().is_empty());

    let count_after_success = f.client.rbac_audit_trail_count();
    assert_eq!(count_after_success, count_before + 1);

    let success_evt = f.client.get_rbac_audit_event(&count_before).unwrap();
    assert_eq!(success_evt.caller, f.planner);
    assert!(success_evt.authorized);
    assert_eq!(success_evt.error_code, 0);
    assert_eq!(success_evt.timestamp, 1_700_000_500);
    assert_eq!(
        success_evt.submitter_did,
        Bytes::from_slice(&f.env, b"did:stellar:planner-01")
    );
    assert_ne!(
        success_evt.state_diff_digest,
        BytesN::from_array(&f.env, &[0u8; 32])
    );

    // 2. Rejected mutation by viewer
    f.env.ledger().set_timestamp(1_700_000_900);
    let denied = f.env.as_contract(&f.contract_id, || {
        capacity_planning::configure_shard_threshold(&f.env, &f.viewer, 7, 20_000, 7500, 9000)
    });
    assert_eq!(denied, Err(RbacError::InsufficientRole));

    let count_after_denial = f.client.rbac_audit_trail_count();
    assert_eq!(count_after_denial, count_after_success + 1);

    let denial_evt = f.client.get_rbac_audit_event(&count_after_success).unwrap();
    assert_eq!(denial_evt.caller, f.viewer);
    assert!(!denial_evt.authorized);
    assert_eq!(denial_evt.error_code, RbacError::InsufficientRole as u32);
    assert_eq!(denial_evt.timestamp, 1_700_000_900);
    assert_eq!(
        denial_evt.submitter_did,
        Bytes::from_slice(&f.env, b"did:stellar:viewer-01")
    );
    assert_ne!(
        denial_evt.state_diff_digest,
        BytesN::from_array(&f.env, &[0u8; 32])
    );
}

#[test]
fn test_invalid_did_and_domain_validation_errors_recorded_in_audit_trail() {
    let f = setup_fixture();
    let candidate = Address::generate(&f.env);

    // Malformed DID rejected with InvalidDid (1005)
    let bad_did = f.env.as_contract(&f.contract_id, || {
        rbac::grant_role(
            &f.env,
            &f.admin,
            &candidate,
            Role::Operator,
            Bytes::from_slice(&f.env, b"invalid-did"),
        )
    });
    assert_eq!(bad_did, Err(RbacError::InvalidDid));

    // Invalid threshold config (warning_bps >= critical_bps) rejected with InvalidThresholdConfig (1007)
    let bad_cfg = f.env.as_contract(&f.contract_id, || {
        capacity_planning::configure_shard_threshold(&f.env, &f.planner, 9, 10_000, 9500, 9000)
    });
    assert_eq!(bad_cfg, Err(RbacError::InvalidThresholdConfig));

    // Missing shard rejected with ShardNotFound (1006)
    let missing_shard = f.env.as_contract(&f.contract_id, || {
        capacity_planning::record_shard_utilization(&f.env, &f.operator, 404, 100, 10)
    });
    assert_eq!(missing_shard, Err(RbacError::ShardNotFound));

    // Zero forecast horizon rejected with InvalidForecastParameters (1008)
    f.client
        .configure_shard_threshold(&f.planner, &9, &10_000, &7000, &9000);
    let bad_horizon = f.env.as_contract(&f.contract_id, || {
        capacity_planning::generate_capacity_forecast(&f.env, &f.planner, 9, 0)
    });
    assert_eq!(bad_horizon, Err(RbacError::InvalidForecastParameters));

    // Missing alert rejected with AlertNotFound (1009)
    let missing_alert = f.env.as_contract(&f.contract_id, || {
        capacity_planning::acknowledge_threshold_alert(&f.env, &f.operator, 999)
    });
    assert_eq!(missing_alert, Err(RbacError::AlertNotFound));
}
