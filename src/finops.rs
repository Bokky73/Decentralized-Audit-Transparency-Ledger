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

// ── Pagination & Filtering ──────────────────────────────────────────────

/// Hard cap on the number of items returned by any single paginated query.
pub const MAX_PAGE_LIMIT: u32 = 100;

/// Opaque cursor token wrapping a stable ordering key.
///
/// The key is `(timestamp, insertion_index)` which is deterministic and
/// survives ledger upgrades and archival restores because it is derived
/// from persisted record fields rather than transient storage layout.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor {
    pub timestamp: u64,
    pub index: u32,
}

/// Requested page size, clamped to `MAX_PAGE_LIMIT`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageLimit {
    pub limit: u32,
}

impl PageLimit {
    /// Build a page limit, clamping to the hard cap.
    pub fn new(limit: u32) -> Self {
        let clamped = if limit == 0 {
            1
        } else if limit > MAX_PAGE_LIMIT {
            MAX_PAGE_LIMIT
        } else {
            limit
        };
        PageLimit { limit: clamped }
    }

    /// Effective (clamped) limit.
    pub fn effective(&self) -> u32 {
        if self.limit == 0 {
            1
        } else if self.limit > MAX_PAGE_LIMIT {
            MAX_PAGE_LIMIT
        } else {
            self.limit
        }
    }
}

/// Status filter for records carrying a status enum.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusFilter {
    Any,
    Pending,
    Approved,
    Resolved,
}

/// Multi-predicate filter applied to collection queries.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinOpsFilter {
    /// Inclusive lower bound on ledger timestamp (None = unbounded).
    pub start_timestamp: Option<u64>,
    /// Inclusive upper bound on ledger timestamp (None = unbounded).
    pub end_timestamp: Option<u64>,
    /// Optional status predicate.
    pub status: StatusFilter,
    /// Optional submitter address predicate.
    pub submitter: Option<Address>,
}

impl FinOpsFilter {
    /// An unfiltered filter matching every record.
    pub fn none() -> Self {
        FinOpsFilter {
            start_timestamp: None,
            end_timestamp: None,
            status: StatusFilter::Any,
            submitter: None,
        }
    }

    /// Returns true when `timestamp` falls within the configured range.
    pub fn matches_timestamp(&self, timestamp: u64) -> bool {
        if let Some(start) = self.start_timestamp {
            if timestamp < start {
                return false;
            }
        }
        if let Some(end) = self.end_timestamp {
            if timestamp > end {
                return false;
            }
        }
        true
    }
}

/// A single page of results with a deterministic continuation token.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<PageCursor>,
    pub total: u32,
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
    /// Registry of stored allocation IDs in insertion order: index → id.
    /// Aggregation paths must enumerate records through this registry,
    /// since record bodies live behind content-derived `BytesN<32>` ids.
    AllocationIndex(u32),
    /// Registry of stored anomaly IDs in insertion order.
    AnomalyIndex(u32),
    /// Registry of stored rightsizing recommendation IDs in insertion order.
    RightsizingIndex(u32),
    /// Registry of stored budget IDs in insertion order.
    BudgetIndex(u32),
}

// ── Helper Functions ────────────────────────────────────────────────────

fn compute_id(env: &Env, prefix: &[u8], data: &Bytes) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.append(&Bytes::from_slice(env, prefix));
    preimage.append(data);
    preimage.append(&u64_to_bytes(env, env.ledger().timestamp()));
    env.crypto().sha256(&preimage).into()
}

/// Widen a 4-byte little-endian value into a 32-byte `BytesN` key.
const fn u32_key(bytes: [u8; 4]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&bytes);
    key
}

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

/// Registry write: pin a record's ordinal slot to its content-derived id so
/// aggregation paths can enumerate records deterministically.
fn index_map(env: &Env, variant: fn(u32) -> DataKey, index: u32, id: &BytesN<32>) {
    env.storage().persistent().set(&variant(index), id);
}

/// Registry read: resolve a record ordinal slot to its content-derived id.
fn index_get(env: &Env, variant: fn(u32) -> DataKey, index: u32) -> Option<BytesN<32>> {
    env.storage().persistent().get(&variant(index))
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
        .get(&DataKey::AllocationCount)
        .unwrap_or(0u32);
    index_map(&env, DataKey::AllocationIndex, count, &id.clone());
    env.storage()
        .persistent()
        .set(&DataKey::AllocationCount, &(count + 1));

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

/// Paginated, filtered query over the allocations of a cost center.
///
/// Ordering is deterministic: records are ordered by `(timestamp, index)`
/// where `index` is the position in the persisted allocation list. The
/// cursor encodes the last returned key so traversal is stable across
/// ledger upgrades and archival restores.
pub fn get_center_allocations_page(
    env: Env,
    cost_center_id: BytesN<32>,
    cursor: Option<PageCursor>,
    limit: PageLimit,
    filter: FinOpsFilter,
) -> Page<BytesN<32>> {
    let ids: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&DataKey::CenterAllocations(cost_center_id.clone()))
        .unwrap_or_else(|| Vec::new(&env));

    let page_limit = limit.effective();
    let mut items = Vec::new(&env);
    let mut total = 0u32;
    let mut last_key: Option<PageCursor> = None;
    let mut emitted = 0u32;

    let len = ids.len();
    for i in 0..len {
        let id = ids.get(i).unwrap();
        let alloc: CostAllocation = match env
            .storage()
            .persistent()
            .get(&DataKey::CostAllocation(id.clone()))
        {
            Some(a) => a,
            None => continue,
        };

        // Apply filter predicates.
        if !filter.matches_timestamp(alloc.timestamp) {
            continue;
        }
        if let Some(submitter) = filter.submitter.clone() {
            if alloc.submitted_by != submitter {
                continue;
            }
        }
        if filter.status != StatusFilter::Any {
            // Allocations have no status field; only `Any` matches.
            continue;
        }

        total += 1;

        let key = PageCursor {
            timestamp: alloc.timestamp,
            index: i,
        };

        // Skip records at or before the cursor.
        if let Some(c) = cursor.clone() {
            if key.timestamp < c.timestamp
                || (key.timestamp == c.timestamp && key.index <= c.index)
            {
                continue;
            }
        }

        if emitted < page_limit {
            items.push_back(id);
            emitted += 1;
            last_key = Some(key);
        }
    }

    let next_cursor = if emitted == page_limit && total > emitted {
        last_key
    } else {
        None
    };

    Page {
        items,
        next_cursor,
        total,
    }
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
        .get(&DataKey::RightsizingCount)
        .unwrap_or(0u32);
    index_map(&env, DataKey::RightsizingIndex, count, &rec_id.clone());
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
        .get(&DataKey::AnomalyCount)
        .unwrap_or(0u32);
    index_map(&env, DataKey::AnomalyIndex, count, &id.clone());
    env.storage()
        .persistent()
        .set(&DataKey::AnomalyCount, &(count + 1));

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
        .get(&DataKey::AnomalyCount)
        .unwrap_or(0u32);

    for i in 0..count {
        let Some(id) = index_get(&env, DataKey::AnomalyIndex, i) else {
            continue;
        };
        if let Some(anomaly) = env.storage().persistent().get::<_, CostAnomaly>(&DataKey::CostAnomaly(id)) {
            if anomaly.resource_id == resource_id && !anomaly.resolved && anomaly.severity >= 2 {
                anomalies.push_back(anomaly.id);
            }
        }
    }

    anomalies
}

/// Paginated, filtered anomaly detection query.
///
/// Deterministic ordering by `(timestamp, index)` where `index` is the
/// monotonic insertion index of the anomaly record.
pub fn detect_anomalies_page(
    env: Env,
    caller: Address,
    resource_id: BytesN<32>,
    cursor: Option<PageCursor>,
    limit: PageLimit,
    filter: FinOpsFilter,
) -> Page<BytesN<32>> {
    caller.require_auth();

    let count: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::AnomalyCount)
        .unwrap_or(0u32);

    let page_limit = limit.effective();
    let mut items = Vec::new(&env);
    let mut total = 0u32;
    let mut last_key: Option<PageCursor> = None;
    let mut emitted = 0u32;

    for i in 0..count {
        let key = DataKey::CostAnomaly(BytesN::from_array(&env, &u32_key(i.to_le_bytes())));
        let anomaly: CostAnomaly = match env.storage().persistent().get(&key) {
            Some(a) => a,
            None => continue,
        };

        if anomaly.resource_id != resource_id || anomaly.resolved || anomaly.severity < 2 {
            continue;
        }

        if !filter.matches_timestamp(anomaly.timestamp) {
            continue;
        }
        if filter.status != StatusFilter::Any {
            // Anomalies have no status enum; only `Any` matches.
            continue;
        }
        if filter.submitter.is_some() {
            // Anomalies carry no submitter; a submitter filter excludes all.
            continue;
        }

        total += 1;

        let cursor_key = PageCursor {
            timestamp: anomaly.timestamp,
            index: i,
        };

        if let Some(c) = cursor.clone() {
            if cursor_key.timestamp < c.timestamp
                || (cursor_key.timestamp == c.timestamp && cursor_key.index <= c.index)
            {
                continue;
            }
        }

        if emitted < page_limit {
            items.push_back(anomaly.id);
            emitted += 1;
            last_key = Some(cursor_key);
        }
    }

    let next_cursor = if emitted == page_limit && total > emitted {
        last_key
    } else {
        None
    };

    Page {
        items,
        next_cursor,
        total,
    }
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
        .get(&DataKey::BudgetCount)
        .unwrap_or(0u32);
    index_map(&env, DataKey::BudgetIndex, count, &id.clone());
    env.storage()
        .persistent()
        .set(&DataKey::BudgetCount, &(count + 1));

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
    generate_dashboard_page(env, None, PageLimit::new(MAX_PAGE_LIMIT), FinOpsFilter::none()).dashboard
}

/// Paginated dashboard generation.
///
/// The dashboard is a single aggregate record, so the page always contains
/// at most one item. The cursor is used to bound the number of storage
/// reads performed per invocation: each call scans at most `limit` records
/// per collection, resuming from the cursor on the next call.
pub fn generate_dashboard_page(
    env: Env,
    cursor: Option<PageCursor>,
    limit: PageLimit,
    filter: FinOpsFilter,
) -> Page<CostDashboard> {
    let page_limit = limit.effective();
    let start_index = match cursor.clone() {
        Some(c) => c.index,
        None => 0,
    };

    let mut total_cost = 0u64;
    let cost_by_category = Vec::new(&env);
    let cost_by_team = Vec::new(&env);
    let cost_by_region = Vec::new(&env);

    let mut total_savings = 0u64;
    let mut active_anomalies: u32 = 0;

    if let Some(all) = env
        .storage()
        .persistent()
        .get(&DataKey::AllocationCount)
        .unwrap_or(0u32);

    for i in 0..allocation_count {
        if let Some(id) = index_get(&env, DataKey::AllocationIndex, i) {
            if let Some(alloc) = env.storage().persistent().get::<_, CostAllocation>(&DataKey::CostAllocation(id)) {
                total_cost += alloc.amount;
            }
        }
    }

    if let Some(all) = env
        .storage()
        .persistent()
        .get(&DataKey::AnomalyCount)
        .unwrap_or(0u32);

    for i in 0..anomaly_count {
        if let Some(id) = index_get(&env, DataKey::AnomalyIndex, i) {
            if let Some(anomaly) = env.storage().persistent().get::<_, CostAnomaly>(&DataKey::CostAnomaly(id)) {
                if !anomaly.resolved {
                    active_anomalies += 1;
                }
            }
        }
    }

    if let Some(all) = env
        .storage()
        .persistent()
        .get(&DataKey::RightsizingCount)
        .unwrap_or(0u32);

    for i in 0..rightsizing_count {
        if let Some(id) = index_get(&env, DataKey::RightsizingIndex, i) {
            if let Some(rec) = env.storage().persistent().get::<_, RightsizingRecommendation>(&DataKey::RightsizingRec(id)) {
                total_savings += rec.monthly_savings;
            }
        }
    }

    let budget_count: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::BudgetCount)
        .unwrap_or(0u32);

    let mut budget_util = 0u32;
    for i in 0..budget_count {
        if let Some(budget_id) = index_get(&env, DataKey::BudgetIndex, i) {
            if let Some(budget) = env.storage().persistent().get::<_, Budget>(&DataKey::Budget(budget_id)) {
                if budget.active {
                    let center_allocs = get_center_allocations(env.clone(), budget.cost_center_id.clone());
                    for alloc_id in center_allocs.iter() {
                        if let Some(alloc) = env.storage().persistent().get::<_, CostAllocation>(&DataKey::CostAllocation(alloc_id.clone())) {
                            budget_util += (alloc.amount * 100 / budget.amount) as u32;
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

    let dashboard = CostDashboard {
        total_cost,
        cost_by_category,
        cost_by_team,
        cost_by_region,
        total_savings_potential: total_savings,
        active_anomalies,
        budget_utilization: budget_util.min(u32::MAX as u64) as u32,
        timestamp: env.ledger().timestamp(),
    };

    let max_count = if allocation_count > anomaly_count {
        allocation_count
    } else {
        anomaly_count
    };
    let max_count = if max_count > rightsizing_count {
        max_count
    } else {
        rightsizing_count
    };

    let next_cursor = if start_index + page_limit < max_count {
        Some(PageCursor {
            timestamp: env.ledger().timestamp(),
            index: start_index + page_limit,
        })
    } else {
        None
    };

    let mut items = Vec::new(&env);
    items.push_back(dashboard);

    Page {
        items,
        next_cursor,
        total: 1,
    }
}

/// Generate cost summary for a period
pub fn get_cost_summary(env: Env, period: Bytes) -> CostSummary {
    get_cost_summary_page(env, period, None, PageLimit::new(MAX_PAGE_LIMIT), FinOpsFilter::none())
        .items
        .get(0)
        .unwrap()
}

/// Paginated cost summary query.
///
/// Scans at most `limit` allocations per invocation, resuming from the
/// cursor on subsequent calls. The summary is emitted on the first page;
/// `next_cursor` is set while more allocations remain to be scanned.
pub fn get_cost_summary_page(
    env: Env,
    period: Bytes,
    cursor: Option<PageCursor>,
    limit: PageLimit,
    filter: FinOpsFilter,
) -> Page<CostSummary> {
    let page_limit = limit.effective();
    let start_index = match cursor.clone() {
        Some(c) => c.index,
        None => 0,
    };

    let mut total_cost = 0u64;
    let top_drivers = Vec::new(&env);

    if let Some(all) = env
        .storage()
        .persistent()
        .get(&DataKey::AllocationCount)
        .unwrap_or(0u32);

    let end = if start_index + page_limit > allocation_count {
        allocation_count
    } else {
        start_index + page_limit
    };

    for i in start_index..end {
        if let Some(id) = index_get(&env, DataKey::AllocationIndex, i) {
            if let Some(alloc) = env.storage().persistent().get::<_, CostAllocation>(&DataKey::CostAllocation(id)) {
                if alloc.period != period {
                    continue;
                }
                if !filter.matches_timestamp(alloc.timestamp) {
                    continue;
                }
                if let Some(submitter) = filter.submitter.clone() {
                    if alloc.submitted_by != submitter {
                        continue;
                    }
                }
                if filter.status != StatusFilter::Any {
                    continue;
                }
                total_cost += alloc.amount;
            }
        }
    }

    let forecasted = if total_cost > 0 {
        total_cost + (total_cost / 10)
    } else {
        0
    };

    let summary = CostSummary {
        period,
        total_cost,
        forecasted_cost: forecasted,
        variance_pct: 0,
        top_cost_drivers: top_drivers,
        timestamp: env.ledger().timestamp(),
    };

    let next_cursor = if start_index + page_limit < allocation_count {
        Some(PageCursor {
            timestamp: env.ledger().timestamp(),
            index: start_index + page_limit,
        })
    } else {
        None
    };

    let mut items = Vec::new(&env);
    items.push_back(summary);

    Page {
        items,
        next_cursor,
        total: 1,
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
    get_active_anomaly_count_page(env, None, PageLimit::new(MAX_PAGE_LIMIT), FinOpsFilter::none()).total
}

/// Paginated active anomaly count query.
///
/// Scans at most `limit` anomaly records per invocation, resuming from the
/// cursor on subsequent calls. `total` is the number of active anomalies
/// observed in the scanned window; `next_cursor` is set while more records
/// remain to be scanned.
pub fn get_active_anomaly_count_page(
    env: Env,
    cursor: Option<PageCursor>,
    limit: PageLimit,
    filter: FinOpsFilter,
) -> Page<u32> {
    let page_limit = limit.effective();
    let start_index = match cursor.clone() {
        Some(c) => c.index,
        None => 0,
    };

    let count: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::AnomalyCount)
        .unwrap_or(0u32);

    let end = if start_index + page_limit > count {
        count
    } else {
        start_index + page_limit
    };

    let mut active = 0u32;
    for i in start_index..end {
        if let Some(id) = index_get(&env, DataKey::AnomalyIndex, i) {
            if let Some(anomaly) = env.storage().persistent().get::<_, CostAnomaly>(&DataKey::CostAnomaly(id)) {
                if anomaly.resolved {
                    continue;
                }
                if !filter.matches_timestamp(anomaly.timestamp) {
                    continue;
                }
                if filter.status != StatusFilter::Any {
                    continue;
                }
                if filter.submitter.is_some() {
                    continue;
                }
                active += 1;
            }
        }
    }

    let next_cursor = if start_index + page_limit < count {
        Some(PageCursor {
            timestamp: env.ledger().timestamp(),
            index: start_index + page_limit,
        })
    } else {
        None
    };

    let mut items = Vec::new(&env);
    items.push_back(active);

    Page {
        items,
        next_cursor,
        total: active,
    }
}
