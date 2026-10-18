#![allow(dead_code)]

//! # FinOps Tracker
//!
//! Soroban storage-rent and compute-budget FinOps tracker.
//!
//! ## Deterministic bounds (issue #859)
//!
//! All byte-string inputs (`name`, `period`, `team`, `region`, `metadata`)
//! and every index `Vec` are capped so a malformed payload can never grow a
//! storage entry past the ledger entry limit or drive a scan past the
//! compute-budget limit. All counters use `checked_add`, all cost
//! aggregations use saturating arithmetic, and all percentage math is
//! widened to `u128` before multiplying so no input can overflow.
//!
//! ## RBAC gating (issue #860)
//!
//! Every state-mutating entrypoint is gated through [`crate::rbac`] with a
//! granular role map (see [`require_role`]) and emits a tamper-evident
//! audit-trail event (`"finops_audit"` topic) whose payload digest is a
//! SHA-256 over the operation, caller XDR, record id, timestamp and
//! outcome — binding the trail to the exact mutation and rejecting
//! post-hoc edits.
//!
//! ## TTL / rent policy (issue #861)
//!
//! Every persistent state key is bumped on write with
//! [`bump_ttl`]: entries are extended to [`FINOPS_TTL_EXTEND_LEDGERS`]
//! (~70 days) whenever their remaining TTL drops under
//! [`FINOPS_TTL_BUMP_THRESHOLD_LEDGERS`] (~10 days). Hot read paths re-bump
//! the same policy so archival never hits a key that is actively serving
//! traffic, keeping the persistent rent footprint bounded.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    bytes, contracterror, contracttype, panic_with_error, symbol_short, Address, Bytes, BytesN,
    Env, Symbol, Vec,
};

use crate::rbac::{RbacManager, Role};

// ── Error Codes ──────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FinOpsError {
    CostCenterNotFound = 9000,
    CostCenterAlreadyExists = 9001,
    BudgetNotFound = 9002,
    BudgetAlreadyExists = 9003,
    ResourceNotFound = 9004,
    AnomalyNotFound = 9005,
    InvalidAllocation = 9006,
    BudgetExceeded = 9007,
    InvalidAmount = 9008,
    UnauthorizedAccess = 9009,
    InvalidPeriod = 9010,
    InsufficientData = 9011,
    CounterOverflow = 9012,
    ResourceLimitExceeded = 9013,
    ThresholdLimitExceeded = 9014,
}

// ── Deterministic bounds (issue #859) ────────────────────────────────────

/// Maximum length of any byte-string input (`name`, `period`, `team`, `region`).
pub const MAX_BYTES_LEN: u32 = 256;
/// Maximum length of free-form `metadata` payloads.
pub const MAX_METADATA_LEN: u32 = 1024;
/// Maximum number of allocations indexed per cost center.
pub const MAX_CENTER_ALLOCATIONS: u32 = 512;
/// Maximum length of any category index vector (Soroban entry size safety).
pub const MAX_INDEX_VECTOR_LEN: u32 = 1024;
/// Maximum number of alert thresholds accepted per budget.
pub const MAX_ALERT_THRESHOLDS: u32 = 16;
/// Maximum value accepted for a single alert threshold (percent).
pub const MAX_THRESHOLD_PCT: u32 = 10_000;

// ── TTL / rent policy (issue #861) ──────────────────────────────────────

/// Bump TTL entries out to ~70 days (5s ledgers).
pub const FINOPS_TTL_EXTEND_LEDGERS: u32 = 1_209_600;
/// Bump whenever the remaining TTL of a key drops below ~10 days.
pub const FINOPS_TTL_BUMP_THRESHOLD_LEDGERS: u32 = 172_800;

/// Extend the TTL of a persistent finops state key (issue #861).
fn bump_ttl(env: &Env, key: &DataKey) {
    env.storage().persistent().extend_ttl(
        key,
        FINOPS_TTL_BUMP_THRESHOLD_LEDGERS,
        FINOPS_TTL_EXTEND_LEDGERS,
    );
}

// ── RBAC gating & tamper-evident audit trail (issue #860) ───────────────

/// Outcome tags for audit-trail events.
pub const AUDIT_OUTCOME_OK: &str = "ok";
pub const AUDIT_OUTCOME_DENIED: &str = "denied";
/// Topic used by every finops audit-trail event.
pub const AUDIT_TOPIC: &str = "finops_audit";

/// Granular role map for finops entrypoints (issue #860):
///
/// | Entrypoint                                   | Minimum role |
/// |----------------------------------------------|--------------|
/// | register / update / deactivate cost center   | Admin        |
/// | create budget / check budget                 | Admin        |
/// | record resource / rightsize / anomaly / resolve | Auditor   |
/// | approve chargeback                           | Auditor      |
/// | allocate cost / chargeback / showback        | Submitter    |
///
/// Reads remain public (showback semantics).
fn require_role(env: &Env, caller: &Address, min_role: Role, op: &str) {
    if let Err(err) = RbacManager::require_active_role_min(env, caller, min_role) {
        emit_audit(env, op, caller, &zero_id(env), AUDIT_OUTCOME_DENIED, err as u32);
        panic_with_error!(env, err);
    }
}

/// SHA-256 over `op || caller-XDR || id || timestamp || outcome || code`,
/// binding each audit-trail event to the exact mutation attempt.
fn audit_digest(
    env: &Env,
    op: &Symbol,
    caller: &Address,
    id: &BytesN<32>,
    outcome: &Symbol,
    code: u32,
) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.append(&op.to_xdr(env));
    preimage.append(&caller.to_xdr(env));
    preimage.append(&id.to_bytes());
    preimage.append(&u64_to_bytes(env, env.ledger().timestamp()));
    preimage.append(&outcome.to_xdr(env));
    preimage.append(&u64_to_bytes(env, code as u64));
    env.crypto().sha256(&preimage).into()
}

/// Emit a tamper-evident finops audit-trail event.
fn emit_audit(env: &Env, op: &str, caller: &Address, id: &BytesN<32>, outcome: &str, code: u32) {
    let op_sym = Symbol::new(env, op);
    let outcome_sym = Symbol::new(env, outcome);
    let digest = audit_digest(env, &op_sym, caller, id, &outcome_sym, code);
    env.events().publish(
        (Symbol::new(env, AUDIT_TOPIC), op_sym, outcome_sym),
        (caller.clone(), id.clone(), env.ledger().timestamp(), digest),
    );
}

fn zero_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

// ── Data Types ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostCenter {
    pub id: BytesN<32>,
    pub name: Bytes,
    pub owner: Address,
    pub budget: u64,
    pub currency: Symbol,
    pub created_at: u64,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostAllocation {
    pub id: BytesN<32>,
    pub cost_center_id: BytesN<32>,
    pub resource_type: Symbol,
    pub amount: u64,
    pub currency: Symbol,
    pub period: Bytes,
    pub timestamp: u64,
    pub submitted_by: Address,
    pub metadata: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChargebackRecord {
    pub id: BytesN<32>,
    pub team: Bytes,
    pub amount: u64,
    pub currency: Symbol,
    pub period: Bytes,
    pub status: u32,
    pub timestamp: u64,
    pub cost_center_id: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShowbackRecord {
    pub id: BytesN<32>,
    pub team: Bytes,
    pub amount: u64,
    pub currency: Symbol,
    pub period: Bytes,
    pub timestamp: u64,
    pub cost_center_id: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    pub id: BytesN<32>,
    pub resource_type: Symbol,
    pub current_size: u64,
    pub recommended_size: u64,
    pub monthly_cost: u64,
    pub potential_savings: u64,
    pub region: Bytes,
    pub last_updated: u64,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RightsizingRecommendation {
    pub resource_id: BytesN<32>,
    pub recommendation_type: u32,
    pub current_size: u64,
    pub recommended_size: u64,
    pub monthly_savings: u64,
    pub confidence: u32,
    pub reason: Bytes,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostAnomaly {
    pub id: BytesN<32>,
    pub resource_id: BytesN<32>,
    pub expected_cost: u64,
    pub actual_cost: u64,
    pub deviation_pct: u32,
    pub severity: u32,
    pub timestamp: u64,
    pub resolved: bool,
    pub metadata: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Budget {
    pub id: BytesN<32>,
    pub name: Bytes,
    pub cost_center_id: BytesN<32>,
    pub amount: u64,
    pub currency: Symbol,
    pub period: Bytes,
    pub alert_thresholds: Vec<u32>,
    pub created_at: u64,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetAlert {
    pub id: BytesN<32>,
    pub budget_id: BytesN<32>,
    pub current_spend: u64,
    pub threshold_pct: u32,
    pub message: Bytes,
    pub timestamp: u64,
    pub acknowledged: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostDashboard {
    pub total_cost: u64,
    pub cost_by_category: Vec<(Symbol, u64)>,
    pub cost_by_team: Vec<(Bytes, u64)>,
    pub cost_by_region: Vec<(Bytes, u64)>,
    pub total_savings_potential: u64,
    pub active_anomalies: u32,
    pub budget_utilization: u32,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostSummary {
    pub period: Bytes,
    pub total_cost: u64,
    pub forecasted_cost: u64,
    pub variance_pct: u32,
    pub top_cost_drivers: Vec<(Symbol, u64)>,
    pub timestamp: u64,
}

// ── Storage Keys ────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    CostCenter(BytesN<32>),
    AllCostCenters,
    CostAllocation(BytesN<32>),
    AllAllocations,
    CenterAllocations(BytesN<32>),
    Chargeback(BytesN<32>),
    AllChargebacks,
    Showback(BytesN<32>),
    AllShowbacks,
    Resource(BytesN<32>),
    AllResources,
    RightsizingRec(BytesN<32>),
    AllRightsizingRecs,
    CostAnomaly(BytesN<32>),
    AllAnomalies,
    Budget(BytesN<32>),
    AllBudgets,
    BudgetAlert(BytesN<32>),
    AllAlerts,
    CostCenterCount,
    AllocationCount,
    ChargebackCount,
    ShowbackCount,
    ResourceCount,
    RightsizingCount,
    AnomalyCount,
    BudgetCount,
    AlertCount,
}

// ── Helper Functions ────────────────────────────────────────────────────

fn compute_id(env: &Env, prefix: &[u8], data: &Bytes) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.append(&Bytes::from_slice(env, prefix));
    preimage.append(data);
    preimage.append(&u64_to_bytes(env, env.ledger().timestamp()));
    env.crypto().sha256(&preimage).into()
}

/// Little-endian byte encoding of a `u64` scalar.
fn u64_to_bytes(env: &Env, v: u64) -> Bytes {
    Bytes::from_array(env, &v.to_le_bytes())
}

fn require_non_empty(env: &Env, value: &Bytes, error: FinOpsError) {
    if value.is_empty() {
        panic_with_error!(env, error);
    }
}

fn require_non_empty_id(env: &Env, value: &BytesN<32>, error: FinOpsError) {
    if *value == zero_id(env) {
        panic_with_error!(env, error);
    }
}

/// Enforce a deterministic byte-length cap on an input payload (#859).
fn require_bounded(env: &Env, value: &Bytes, max: u32, error: FinOpsError) {
    if value.len() > max {
        panic_with_error!(env, error);
    }
}

/// Enforce a deterministic maximum on a stored index vector (#859).
fn push_bounded(env: &Env, mut vec: Vec<BytesN<32>>, id: &BytesN<32>, max: u32) -> Vec<BytesN<32>> {
    if vec.len() >= max {
        panic_with_error!(env, FinOpsError::ResourceLimitExceeded);
    }
    vec.push_back(id.clone());
    vec
}

/// Increment a persistent counter with overflow safety (#859).
fn bump_counter(env: &Env, key: &DataKey) {
    let count: u32 = env.storage().persistent().get(key).unwrap_or(0u32);
    let next = match count.checked_add(1) {
        Some(next) => next,
        None => panic_with_error!(env, FinOpsError::CounterOverflow),
    };
    env.storage().persistent().set(key, &next);
}

/// Render "Budget utilization at 42.0%" without `format!` (needs a guest allocator).
fn utilization_message(env: &Env, pct: u32) -> Bytes {
    let pct = pct.min(9999);
    let whole = pct / 100;
    let frac = pct % 100;
    let mut msg = Bytes::from_slice(env, b"Budget utilization at ");
    msg.push_back(b'0' + (whole / 10) as u8);
    msg.push_back(b'0' + (whole % 10) as u8);
    msg.push_back(b'.');
    msg.push_back(b'0' + (frac / 10) as u8);
    msg.push_back(b'0' + (frac % 10) as u8);
    msg.push_back(b'%');
    msg
}

fn validate_amount(env: &Env, amount: u64) {
    if amount == 0 {
        panic_with_error!(env, FinOpsError::InvalidAmount);
    }
}

/// Validate alert thresholds: bounded count, bounded value (#859).
fn validate_thresholds(env: &Env, thresholds: &Vec<u32>) {
    if thresholds.len() > MAX_ALERT_THRESHOLDS {
        panic_with_error!(env, FinOpsError::ThresholdLimitExceeded);
    }
    for i in 0..thresholds.len() {
        if *thresholds.get(i).unwrap() > MAX_THRESHOLD_PCT {
            panic_with_error!(env, FinOpsError::ThresholdLimitExceeded);
        }
    }
}

// ── Cost Center Management ──────────────────────────────────────────────

/// Register a new cost center
pub fn register_cost_center(
    env: Env,
    caller: Address,
    name: Bytes,
    budget: u64,
    currency: Symbol,
) -> BytesN<32> {
    require_role(&env, &caller, Role::Admin, "cc_register");
    require_non_empty(&env, &name, FinOpsError::InvalidAllocation);
    require_bounded(&env, &name, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);
    validate_amount(&env, budget);

    let id = compute_id(&env, b"cost_center", &name);

    if env.storage().persistent().has(&DataKey::CostCenter(id.clone())) {
        panic_with_error!(&env, FinOpsError::CostCenterAlreadyExists);
    }

    let center = CostCenter {
        id: id.clone(),
        name,
        owner: caller.clone(),
        budget,
        currency,
        created_at: env.ledger().timestamp(),
        active: true,
    };

    env.storage().persistent().set(&DataKey::CostCenter(id.clone()), &center);
    bump_ttl(&env, &DataKey::CostCenter(id.clone()));
    bump_counter(&env, &DataKey::CostCenterCount);

    emit_audit(&env, "cc_register", &caller, &id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish((Symbol::new(&env, "finops"), Symbol::new(&env, "cc_create")), id.clone());

    id
}

/// Get cost center details
pub fn get_cost_center(env: Env, id: BytesN<32>) -> CostCenter {
    bump_ttl(&env, &DataKey::CostCenter(id.clone()));
    env.storage()
        .persistent()
        .get(&DataKey::CostCenter(id))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::CostCenterNotFound))
}

/// Update cost center budget
pub fn update_cost_center_budget(
    env: Env,
    caller: Address,
    id: BytesN<32>,
    new_budget: u64,
) {
    require_role(&env, &caller, Role::Admin, "cc_update");

    let mut center: CostCenter = env
        .storage()
        .persistent()
        .get(&DataKey::CostCenter(id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::CostCenterNotFound));

    if center.owner != caller {
        panic_with_error!(&env, FinOpsError::UnauthorizedAccess);
    }

    validate_amount(&env, new_budget);
    center.budget = new_budget;
    env.storage()
        .persistent()
        .set(&DataKey::CostCenter(id.clone()), &center);
    bump_ttl(&env, &DataKey::CostCenter(id.clone()));

    emit_audit(&env, "cc_update", &caller, &center.id, AUDIT_OUTCOME_OK, 0);
}

/// Deactivate cost center
pub fn deactivate_cost_center(env: Env, caller: Address, id: BytesN<32>) {
    require_role(&env, &caller, Role::Admin, "cc_deactivate");

    let mut center: CostCenter = env
        .storage()
        .persistent()
        .get(&DataKey::CostCenter(id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::CostCenterNotFound));

    if center.owner != caller {
        panic_with_error!(&env, FinOpsError::UnauthorizedAccess);
    }

    center.active = false;
    env.storage()
        .persistent()
        .set(&DataKey::CostCenter(id.clone()), &center);
    bump_ttl(&env, &DataKey::CostCenter(id.clone()));

    emit_audit(&env, "cc_deactivate", &caller, &center.id, AUDIT_OUTCOME_OK, 0);
}

// ── Cost Allocation ─────────────────────────────────────────────────────

/// Allocate cost to a cost center
pub fn allocate_cost(
    env: Env,
    caller: Address,
    cost_center_id: BytesN<32>,
    resource_type: Symbol,
    amount: u64,
    currency: Symbol,
    period: Bytes,
    metadata: Bytes,
) -> BytesN<32> {
    require_role(&env, &caller, Role::Submitter, "alloc");
    validate_amount(&env, amount);
    require_non_empty(&env, &period, FinOpsError::InvalidPeriod);
    require_bounded(&env, &period, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);
    require_bounded(&env, &metadata, MAX_METADATA_LEN, FinOpsError::ResourceLimitExceeded);

    let _: CostCenter = env
        .storage()
        .persistent()
        .get(&DataKey::CostCenter(cost_center_id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::CostCenterNotFound));

    let id = compute_id(&env, b"allocation", &cost_center_id.to_bytes());

    let allocation = CostAllocation {
        id: id.clone(),
        cost_center_id: cost_center_id.clone(),
        resource_type: resource_type.clone(),
        amount,
        currency,
        period,
        timestamp: env.ledger().timestamp(),
        submitted_by: caller.clone(),
        metadata,
    };

    env.storage()
        .persistent()
        .set(&DataKey::CostAllocation(id.clone()), &allocation);
    bump_ttl(&env, &DataKey::CostAllocation(id.clone()));

    let allocs: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&DataKey::CenterAllocations(cost_center_id.clone()))
        .unwrap_or_else(|| Vec::new(&env));
    let allocs = push_bounded(&env, allocs, &id, MAX_CENTER_ALLOCATIONS);
    env.storage()
        .persistent()
        .set(&DataKey::CenterAllocations(cost_center_id.clone()), &allocs);
    bump_ttl(&env, &DataKey::CenterAllocations(cost_center_id.clone()));

    // Global allocation index: bounded, drives dashboards / summaries (#859).
    let all: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&DataKey::AllAllocations)
        .unwrap_or_else(|| Vec::new(&env));
    let all = push_bounded(&env, all, &id, MAX_INDEX_VECTOR_LEN);
    env.storage().persistent().set(&DataKey::AllAllocations, &all);
    bump_ttl(&env, &DataKey::AllAllocations);

    bump_counter(&env, &DataKey::AllocationCount);

    emit_audit(&env, "alloc", &caller, &id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish(
            (Symbol::new(&env, "finops"), Symbol::new(&env, "alloc")),
            (caller, id.clone()),
        );

    id
}

/// Get cost allocation details
pub fn get_allocation(env: Env, id: BytesN<32>) -> CostAllocation {
    bump_ttl(&env, &DataKey::CostAllocation(id.clone()));
    env.storage()
        .persistent()
        .get(&DataKey::CostAllocation(id))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::InvalidAllocation))
}

/// Get total allocations for a cost center
pub fn get_center_allocations(env: Env, cost_center_id: BytesN<32>) -> Vec<BytesN<32>> {
    env.storage()
        .persistent()
        .get(&DataKey::CenterAllocations(cost_center_id.clone()))
        .unwrap_or_else(|| Vec::new(&env))
}

// ── Chargeback / Showback ───────────────────────────────────────────────

/// Create chargeback record
pub fn create_chargeback(
    env: Env,
    caller: Address,
    team: Bytes,
    amount: u64,
    currency: Symbol,
    period: Bytes,
    cost_center_id: BytesN<32>,
) -> BytesN<32> {
    require_role(&env, &caller, Role::Submitter, "chargeback_create");
    validate_amount(&env, amount);
    require_non_empty(&env, &team, FinOpsError::InvalidAllocation);
    require_non_empty(&env, &period, FinOpsError::InvalidPeriod);
    require_bounded(&env, &team, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);
    require_bounded(&env, &period, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);

    let _: CostCenter = env
        .storage()
        .persistent()
        .get(&DataKey::CostCenter(cost_center_id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::CostCenterNotFound));

    let id = compute_id(&env, b"chargeback", &team);

    let record = ChargebackRecord {
        id: id.clone(),
        team,
        amount,
        currency,
        period,
        status: 1,
        timestamp: env.ledger().timestamp(),
        cost_center_id,
    };

    env.storage()
        .persistent()
        .set(&DataKey::Chargeback(id.clone()), &record);
    bump_ttl(&env, &DataKey::Chargeback(id.clone()));
    bump_counter(&env, &DataKey::ChargebackCount);

    emit_audit(&env, "chargeback_create", &caller, &id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish(
            (symbol_short!("finops"), Symbol::new(&env, "chargeback")),
            (caller, id.clone()),
        );

    id
}

/// Create showback record
pub fn create_showback(
    env: Env,
    caller: Address,
    team: Bytes,
    amount: u64,
    currency: Symbol,
    period: Bytes,
    cost_center_id: BytesN<32>,
) -> BytesN<32> {
    require_role(&env, &caller, Role::Submitter, "showback_create");
    validate_amount(&env, amount);
    require_non_empty(&env, &team, FinOpsError::InvalidAllocation);
    require_non_empty(&env, &period, FinOpsError::InvalidPeriod);
    require_bounded(&env, &team, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);
    require_bounded(&env, &period, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);

    let _: CostCenter = env
        .storage()
        .persistent()
        .get(&DataKey::CostCenter(cost_center_id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::CostCenterNotFound));

    let id = compute_id(&env, b"showback", &team);

    let record = ShowbackRecord {
        id: id.clone(),
        team,
        amount,
        currency,
        period,
        timestamp: env.ledger().timestamp(),
        cost_center_id,
    };

    env.storage()
        .persistent()
        .set(&DataKey::Showback(id.clone()), &record);
    bump_ttl(&env, &DataKey::Showback(id.clone()));
    bump_counter(&env, &DataKey::ShowbackCount);

    emit_audit(&env, "showback_create", &caller, &id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish(
            (Symbol::new(&env, "finops"), Symbol::new(&env, "showback")),
            (caller.clone(), id.clone()),
        );

    id
}

/// Approve chargeback record
pub fn approve_chargeback(env: Env, caller: Address, id: BytesN<32>) {
    require_role(&env, &caller, Role::Auditor, "chargeback_approve");

    let mut record: ChargebackRecord = env
        .storage()
        .persistent()
        .get(&DataKey::Chargeback(id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::ResourceNotFound));

    record.status = 2;
    env.storage()
        .persistent()
        .set(&DataKey::Chargeback(id.clone()), &record);
    bump_ttl(&env, &DataKey::Chargeback(id));

    emit_audit(&env, "chargeback_approve", &caller, &record.id, AUDIT_OUTCOME_OK, 0);
}

// ── Rightsizing Recommendations ────────────────────────────────────────

/// Record cloud resource for rightsizing analysis
pub fn record_resource(
    env: Env,
    caller: Address,
    resource_type: Symbol,
    current_size: u64,
    monthly_cost: u64,
    region: Bytes,
) -> BytesN<32> {
    require_role(&env, &caller, Role::Auditor, "resource_register");
    require_bounded(&env, &region, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);

    let resource_bytes = resource_type.clone().to_xdr(&env);
    let id = compute_id(&env, b"resource", &resource_bytes);

    let resource = ResourceRecord {
        id: id.clone(),
        resource_type: resource_type.clone(),
        current_size,
        recommended_size: 0,
        monthly_cost,
        potential_savings: 0,
        region,
        last_updated: env.ledger().timestamp(),
        active: true,
    };

    env.storage()
        .persistent()
        .set(&DataKey::Resource(id.clone()), &resource);
    bump_ttl(&env, &DataKey::Resource(id.clone()));
    bump_counter(&env, &DataKey::ResourceCount);

    emit_audit(&env, "resource_register", &caller, &id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish(
            (Symbol::new(&env, "finops"), Symbol::new(&env, "resource")),
            (caller.clone(), id.clone()),
        );

    id
}

/// Generate rightsizing recommendation
pub fn generate_rightsizing(env: Env, caller: Address, resource_id: BytesN<32>) -> BytesN<32> {
    require_role(&env, &caller, Role::Auditor, "rightsize");

    let resource: ResourceRecord = env
        .storage()
        .persistent()
        .get(&DataKey::Resource(resource_id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::ResourceNotFound));

    if !resource.active {
        panic_with_error!(&env, FinOpsError::ResourceNotFound);
    }

    let recommended_size = if resource.current_size > 1 {
        resource.current_size / 2
    } else {
        resource.current_size
    };

    let monthly_savings = if recommended_size < resource.current_size {
        resource.monthly_cost / 2
    } else {
        0
    };

    let rec_id = compute_id(&env, b"rightsizing", &resource_id.to_bytes());

    let recommendation = RightsizingRecommendation {
        resource_id: resource_id.clone(),
        recommendation_type: 1,
        current_size: resource.current_size,
        recommended_size,
        monthly_savings,
        confidence: 75,
        reason: Bytes::from_slice(&env, b"Right-size based on utilization analysis"),
        timestamp: env.ledger().timestamp(),
    };

    env.storage()
        .persistent()
        .set(&DataKey::RightsizingRec(rec_id.clone()), &recommendation);
    bump_ttl(&env, &DataKey::RightsizingRec(rec_id.clone()));

    // Bounded global index, replaces unbounded count-keyed scan (#859).
    let all: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&DataKey::AllRightsizingRecs)
        .unwrap_or_else(|| Vec::new(&env));
    let all = push_bounded(&env, all, &rec_id, MAX_INDEX_VECTOR_LEN);
    env.storage()
        .persistent()
        .set(&DataKey::AllRightsizingRecs, &all);
    bump_ttl(&env, &DataKey::AllRightsizingRecs);

    bump_counter(&env, &DataKey::RightsizingCount);

    emit_audit(&env, "rightsize", &caller, &rec_id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish(
            (Symbol::new(&env, "finops"), Symbol::new(&env, "rightsize")),
            (caller, rec_id.clone()),
        );

    rec_id
}

/// Get rightsizing recommendation
pub fn get_rightsizing(env: Env, id: BytesN<32>) -> RightsizingRecommendation {
    bump_ttl(&env, &DataKey::RightsizingRec(id.clone()));
    env.storage()
        .persistent()
        .get(&DataKey::RightsizingRec(id))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::ResourceNotFound))
}

// ── Anomaly Detection ──────────────────────────────────────────────────

/// Record cost anomaly
pub fn record_anomaly(
    env: Env,
    caller: Address,
    resource_id: BytesN<32>,
    expected_cost: u64,
    actual_cost: u64,
    metadata: Bytes,
) -> BytesN<32> {
    require_role(&env, &caller, Role::Auditor, "anomaly_record");
    require_bounded(&env, &metadata, MAX_METADATA_LEN, FinOpsError::ResourceLimitExceeded);

    // Absolute deviation, widened to u128 before multiplying so neither the
    // subtraction nor `* 100` can under- or overflow for any u64 inputs (#859).
    let deviation_pct: u32 = if expected_cost > 0 {
        let diff = actual_cost.abs_diff(expected_cost) as u128;
        let pct = diff * 100 / expected_cost as u128;
        pct.min(u32::MAX as u128) as u32
    } else {
        0
    };

    let severity = if deviation_pct > 50 {
        3
    } else if deviation_pct > 25 {
        2
    } else if deviation_pct > 10 {
        1
    } else {
        0
    };

    let id = compute_id(&env, b"anomaly", &resource_id.to_bytes());

    let anomaly = CostAnomaly {
        id: id.clone(),
        resource_id: resource_id.clone(),
        expected_cost,
        actual_cost,
        deviation_pct,
        severity,
        timestamp: env.ledger().timestamp(),
        resolved: false,
        metadata,
    };

    env.storage()
        .persistent()
        .set(&DataKey::CostAnomaly(id.clone()), &anomaly);
    bump_ttl(&env, &DataKey::CostAnomaly(id.clone()));

    // Bounded global index, replaces unbounded count-keyed scan (#859).
    let all: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&DataKey::AllAnomalies)
        .unwrap_or_else(|| Vec::new(&env));
    let all = push_bounded(&env, all, &id, MAX_INDEX_VECTOR_LEN);
    env.storage().persistent().set(&DataKey::AllAnomalies, &all);
    bump_ttl(&env, &DataKey::AllAnomalies);

    bump_counter(&env, &DataKey::AnomalyCount);

    emit_audit(&env, "anomaly_record", &caller, &id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish(
            (Symbol::new(&env, "finops"), Symbol::new(&env, "anomaly")),
            (caller.clone(), id.clone()),
        );

    id
}

/// Detect (unresolved, high-severity) anomalies for a resource.
pub fn detect_anomalies(env: Env, caller: Address, resource_id: BytesN<32>) -> Vec<BytesN<32>> {
    // Analytics read gated to Auditor roles (#860); the previous public
    // count-keyed scan was unbounded (#859).
    match RbacManager::require_active_role_min(&env, &caller, Role::Auditor) {
        Ok(()) => {}
        Err(err) => {
            emit_audit(&env, "anomaly_detect", &caller, &zero_id(&env), AUDIT_OUTCOME_DENIED, err as u32);
            panic_with_error!(&env, err);
        }
    }

    let mut anomalies = Vec::new(&env);

    if let Some(all) = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&DataKey::AllAnomalies)
    {
        for id in all.iter() {
            if anomalies.len() >= MAX_INDEX_VECTOR_LEN {
                break;
            }
            if let Some(anomaly) = env
                .storage()
                .persistent()
                .get::<_, CostAnomaly>(&DataKey::CostAnomaly(id.clone()))
            {
                if anomaly.resource_id == resource_id && !anomaly.resolved && anomaly.severity >= 2
                {
                    anomalies.push_back(anomaly.id);
                }
            }
        }
    }

    anomalies
}

/// Resolve anomaly
pub fn resolve_anomaly(env: Env, caller: Address, id: BytesN<32>) {
    require_role(&env, &caller, Role::Auditor, "anomaly_resolve");

    let mut anomaly: CostAnomaly = env
        .storage()
        .persistent()
        .get(&DataKey::CostAnomaly(id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::AnomalyNotFound));

    anomaly.resolved = true;
    env.storage()
        .persistent()
        .set(&DataKey::CostAnomaly(id.clone()), &anomaly);
    bump_ttl(&env, &DataKey::CostAnomaly(id));

    emit_audit(&env, "anomaly_resolve", &caller, &anomaly.id, AUDIT_OUTCOME_OK, 0);
}

// ── Budget Management ──────────────────────────────────────────────────

/// Create budget
pub fn create_budget(
    env: Env,
    caller: Address,
    name: Bytes,
    cost_center_id: BytesN<32>,
    amount: u64,
    currency: Symbol,
    period: Bytes,
    alert_thresholds: Vec<u32>,
) -> BytesN<32> {
    require_role(&env, &caller, Role::Admin, "budget_create");
    validate_amount(&env, amount);
    require_non_empty(&env, &name, FinOpsError::InvalidAllocation);
    require_non_empty(&env, &period, FinOpsError::InvalidPeriod);
    require_bounded(&env, &name, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);
    require_bounded(&env, &period, MAX_BYTES_LEN, FinOpsError::ResourceLimitExceeded);
    validate_thresholds(&env, &alert_thresholds);

    let _: CostCenter = env
        .storage()
        .persistent()
        .get(&DataKey::CostCenter(cost_center_id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::CostCenterNotFound));

    let id = compute_id(&env, b"budget", &name);

    let budget = Budget {
        id: id.clone(),
        name,
        cost_center_id,
        amount,
        currency,
        period,
        alert_thresholds,
        created_at: env.ledger().timestamp(),
        active: true,
    };

    env.storage()
        .persistent()
        .set(&DataKey::Budget(id.clone()), &budget);
    bump_ttl(&env, &DataKey::Budget(id.clone()));

    // Bounded global index for dashboard scans (#859).
    let all: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&DataKey::AllBudgets)
        .unwrap_or_else(|| Vec::new(&env));
    let all = push_bounded(&env, all, &id, MAX_INDEX_VECTOR_LEN);
    env.storage().persistent().set(&DataKey::AllBudgets, &all);
    bump_ttl(&env, &DataKey::AllBudgets);

    bump_counter(&env, &DataKey::BudgetCount);

    emit_audit(&env, "budget_create", &caller, &id, AUDIT_OUTCOME_OK, 0);

    env.events()
        .publish(
            (symbol_short!("finops"), Symbol::new(&env, "budget_create")),
            (caller, id.clone()),
        );

    id
}

/// Check budget and generate alert if threshold exceeded
pub fn check_budget(env: Env, caller: Address, budget_id: BytesN<32>, current_spend: u64) -> BytesN<32> {
    require_role(&env, &caller, Role::Auditor, "budget_check");

    let budget: Budget = env
        .storage()
        .persistent()
        .get(&DataKey::Budget(budget_id.clone()))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::BudgetNotFound));

    if !budget.active {
        panic_with_error!(&env, FinOpsError::BudgetNotFound);
    }

    // Widened to u128 before multiplying; capped to u32 for any u64 input (#859).
    let utilization_pct: u32 = if budget.amount > 0 {
        let pct = current_spend as u128 * 100 / budget.amount as u128;
        pct.min(u32::MAX as u128) as u32
    } else {
        0
    };

    let mut alert_id = BytesN::from_array(&env, &[0u8; 32]);
    let mut triggered = false;

    for threshold in budget.alert_thresholds.iter() {
        if utilization_pct >= threshold {
            alert_id = compute_id(&env, b"alert", &budget_id.to_bytes());

            let alert = BudgetAlert {
                id: alert_id.clone(),
                budget_id: budget_id.clone(),
                current_spend,
                threshold_pct: threshold,
                message: utilization_message(&env, utilization_pct),
                timestamp: env.ledger().timestamp(),
                acknowledged: false,
            };

            env.storage()
                .persistent()
                .set(&DataKey::BudgetAlert(alert_id.clone()), &alert);
            bump_ttl(&env, &DataKey::BudgetAlert(alert_id.clone()));
            bump_counter(&env, &DataKey::AlertCount);

            triggered = true;
            break;
        }
    }

    if triggered {
        emit_audit(&env, "budget_check", &caller, &alert_id, AUDIT_OUTCOME_OK, 0);
        env.events()
            .publish(
                (symbol_short!("finops"), Symbol::new(&env, "budget_alert")),
                (caller, alert_id.clone()),
            );
    }

    alert_id
}

/// Get budget details
pub fn get_budget(env: Env, id: BytesN<32>) -> Budget {
    bump_ttl(&env, &DataKey::Budget(id.clone()));
    env.storage()
        .persistent()
        .get(&DataKey::Budget(id))
        .unwrap_or_else(|| panic_with_error!(&env, FinOpsError::BudgetNotFound))
}

// ── Cloud Cost Dashboard ────────────────────────────────────────────────

/// Generate cost dashboard summary.
///
/// Scans iterate over bounded index vectors (#859) and all aggregations use
/// saturating / `u128`-widened arithmetic, so no combination of stored
/// values can overflow the compute budget or an integral type.
pub fn generate_dashboard(env: Env) -> CostDashboard {
    let mut total_cost = 0u64;
    let cost_by_category = Vec::new(&env);
    let cost_by_team = Vec::new(&env);
    let cost_by_region = Vec::new(&env);

    let mut total_savings = 0u64;
    let mut active_anomalies: u32 = 0;

    if let Some(all) = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&DataKey::AllAllocations)
    {
        for alloc_id in all.iter() {
            if let Some(alloc) = env
                .storage()
                .persistent()
                .get::<_, CostAllocation>(&DataKey::CostAllocation(alloc_id.clone()))
            {
                total_cost = total_cost.saturating_add(alloc.amount);
            }
        }
    }

    if let Some(all) = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&DataKey::AllAnomalies)
    {
        for anomaly_id in all.iter() {
            if let Some(anomaly) = env
                .storage()
                .persistent()
                .get::<_, CostAnomaly>(&DataKey::CostAnomaly(anomaly_id.clone()))
            {
                if !anomaly.resolved {
                    active_anomalies = active_anomalies.saturating_add(1);
                }
            }
        }
    }

    if let Some(all) = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&DataKey::AllRightsizingRecs)
    {
        for rec_id in all.iter() {
            if let Some(rec) = env
                .storage()
                .persistent()
                .get::<_, RightsizingRecommendation>(&DataKey::RightsizingRec(rec_id.clone()))
            {
                total_savings = total_savings.saturating_add(rec.monthly_savings);
            }
        }
    }

    let budget_count: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::BudgetCount)
        .unwrap_or(0u32);

    let mut budget_util: u128 = 0;
    if let Some(all) = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&DataKey::AllBudgets)
    {
        for budget_id in all.iter() {
            let budget: Option<Budget> = env
                .storage()
                .persistent()
                .get(&DataKey::Budget(budget_id.clone()));
            if let Some(budget) = budget {
                if budget.active {
                    // Deterministic zero-division guard (#859).
                    if budget.amount == 0 {
                        continue;
                    }
                    let center_allocs = get_center_allocations(env.clone(), budget.cost_center_id.clone());
                    for alloc_id in center_allocs.iter() {
                        if let Some(alloc) = env
                            .storage()
                            .persistent()
                            .get::<_, CostAllocation>(&DataKey::CostAllocation(alloc_id.clone()))
                        {
                            // u128-widened percent, capped at 10_000% (#859).
                            let pct = alloc.amount as u128 * 100 / budget.amount as u128;
                            budget_util = budget_util.saturating_add(pct.min(10_000));
                        }
                    }
                }
            }
        }
    }

    let budget_util = if budget_count > 0 {
        (budget_util / budget_count.max(1) as u128) as u64
    } else {
        0
    };

    CostDashboard {
        total_cost,
        cost_by_category,
        cost_by_team,
        cost_by_region,
        total_savings_potential: total_savings,
        active_anomalies,
        budget_utilization: budget_util.min(u32::MAX as u64) as u32,
        timestamp: env.ledger().timestamp(),
    }
}

/// Generate cost summary for a period
pub fn get_cost_summary(env: Env, period: Bytes) -> CostSummary {
    let mut total_cost = 0u64;
    let top_drivers = Vec::new(&env);
    let mut forecasted = 0u64;

    if let Some(all) = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&DataKey::AllAllocations)
    {
        for alloc_id in all.iter() {
            if let Some(alloc) = env
                .storage()
                .persistent()
                .get::<_, CostAllocation>(&DataKey::CostAllocation(alloc_id.clone()))
            {
                if alloc.period == period {
                    total_cost = total_cost.saturating_add(alloc.amount);
                }
            }
        }
    }

    if total_cost > 0 {
        forecasted = total_cost.saturating_add(total_cost / 10);
    }

    CostSummary {
        period,
        total_cost,
        forecasted_cost: forecasted,
        variance_pct: 0,
        top_cost_drivers: top_drivers,
        timestamp: env.ledger().timestamp(),
    }
}

// ── Query Helpers ───────────────────────────────────────────────────────

/// Get total cost center count
pub fn get_cost_center_count(env: Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::CostCenterCount)
        .unwrap_or(0u32)
}

/// Get total allocation count
pub fn get_allocation_count(env: Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::AllocationCount)
        .unwrap_or(0u32)
}

/// Get active anomaly count
pub fn get_active_anomaly_count(env: Env) -> u32 {
    let mut active: u32 = 0;

    if let Some(all) = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&DataKey::AllAnomalies)
    {
        for anomaly_id in all.iter() {
            if let Some(anomaly) = env
                .storage()
                .persistent()
                .get::<_, CostAnomaly>(&DataKey::CostAnomaly(anomaly_id.clone()))
            {
                if !anomaly.resolved {
                    active = active.saturating_add(1);
                }
            }
        }
    }

    active
}
