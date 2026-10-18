//! Contract Event ML Feature Store Module (#524, #854, #855, #857)
//!
//! Provides on-chain coordination, feature view registration, cryptographic
//! feature attestations, and model drift alerts for ML pipelines.
//!
//! Hardening (issue #854):
//! - deterministic bounds on every stored collection (capped view registry,
//!   capped per-view feature lists, capped per-view attestation/alert rings)
//! - checked arithmetic on all counters
//! - validation of malformed payloads (empty symbols, zero hashes, ppm range)
//!
//! RBAC + audit trail (issue #855):
//! - all state-mutating entrypoints take an authenticated `caller`
//! - fine-grained role ladder: `Admin` registers views, `Submitter` records
//!   attestations, `Auditor` raises drift alerts
//! - structured `ft_*` events plus an `ft_audit` trail topic per mutation
//!
//! Pagination + filtering (issue #857):
//! - deterministic cursor-based paging over per-view insertion indexes
//! - multi-predicate filters (entity/time-range, feature/score/time-range)

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, BytesN, Env, Symbol, Vec};

use crate::rbac::{self, RbacManager, Role};

/// Hard bounds enforced by the feature store (issue #854).
pub mod limits {
    /// Maximum number of registered feature views in the registry.
    pub const MAX_FEATURE_VIEWS: u32 = 512;
    /// Maximum number of feature symbols defined by a single view.
    pub const MAX_FEATURES_PER_VIEW: u32 = 64;
    /// Maximum attestations retained per view.
    pub const MAX_ATTESTATIONS_PER_VIEW: u32 = 4_096;
    /// Maximum drift alerts retained per view.
    pub const MAX_DRIFT_ALERTS_PER_VIEW: u32 = 1_024;
    /// Hard cap on items returned in a single page (issue #857).
    pub const MAX_PAGE_LIMIT: u32 = 100;
    /// Maximum TTL for a feature view (10 years in seconds).
    pub const MAX_TTL_SECONDS: u64 = 10 * 365 * 24 * 3600;
    /// Maximum valid drift score in parts-per-million.
    pub const MAX_DRIFT_PPM: u32 = 1_000_000;
}

/// Errors raised by the ML feature store.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FeatureStoreError {
    /// Caller has no assigned role.
    UnauthorizedCaller = 401,
    /// Caller role is below the required minimum.
    InsufficientRole = 403,
    /// Referenced feature view does not exist.
    ViewNotFound = 404,
    /// Attestation id already recorded.
    DuplicateAttestation = 405,
    /// Drift alert id already recorded.
    DuplicateAlertId = 406,
    /// Feature view id is already registered.
    DuplicateViewId = 409,
    /// Feature list is empty or exceeds the per-view cap.
    InvalidFeatureList = 410,
    /// TTL is zero or exceeds the maximum bound.
    InvalidTtl = 411,
    /// Version must be strictly positive.
    InvalidVersion = 412,
    /// View id symbol is empty.
    InvalidViewId = 413,
    /// Entity id symbol is empty.
    InvalidEntityId = 414,
    /// Feature-values hash must not be all-zero.
    InvalidHash = 415,
    /// Drift or threshold ppm outside the valid domain.
    InvalidDriftScore = 416,
    /// Page limit is zero or above the hard cap.
    InvalidLimit = 417,
    /// Feature view registry is full.
    TooManyFeatureViews = 423,
    /// Feature list exceeds the per-view cap.
    TooManyFeaturesPerView = 424,
    /// Per-view attestation cap reached.
    TooManyAttestations = 425,
    /// Per-view drift alert cap reached.
    TooManyDriftAlerts = 426,
    /// View exists but is marked inactive.
    ViewInactive = 427,
    /// Cursor does not match the stored insertion index.
    InvalidCursor = 428,
    /// Counter overflow while updating bookkeeping.
    CounterOverflow = 429,
}

/// Data type of a feature value
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeatureDataType {
    Float,
    Int,
    StringVal,
    BytesVal,
    VectorEmbedding,
}

/// Feature view metadata registration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureViewRecord {
    pub view_id: Symbol,
    pub entity_name: Symbol,
    pub feature_names: Vec<Symbol>,
    pub version: u32,
    pub ttl_seconds: u64,
    pub registered_at: u64,
    pub active: bool,
}

/// On-chain cryptographic attestation of computed feature values
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureAttestation {
    pub attestation_id: BytesN<32>,
    pub view_id: Symbol,
    pub entity_id: Symbol,
    pub feature_values_hash: BytesN<32>,
    pub attested_at: u64,
}

/// On-chain alert for detected feature drift or data distribution shift
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureDriftAlert {
    pub alert_id: BytesN<32>,
    pub view_id: Symbol,
    pub feature_name: Symbol,
    pub drift_score_ppm: u32, // Parts per million (e.g. 250000 = 0.25 PSI)
    pub threshold_ppm: u32,
    pub detected_at: u64,
}

/// Deterministic pagination cursor (issue #857).
///
/// Encodes the position within the per-view insertion-ordered index plus the
/// last returned identifier. Traversal is reproducible, and a cursor whose
/// `last_id` does not match the entry stored at `index - 1` is rejected
/// tamper-evidently with [`FeatureStoreError::InvalidCursor`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeaturePageCursor {
    /// Index of the next unvisited slot in the per-view insertion index.
    pub index: u32,
    /// Identifier of the last item returned on the previous page.
    pub last_id: BytesN<32>,
}

/// A page of feature attestations plus the cursor for the next page.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureAttestationPage {
    /// Items in this page, deterministically ordered.
    pub items: Vec<FeatureAttestation>,
    /// Cursor to pass to the next call, or `None` when exhausted.
    pub next_cursor: Option<FeaturePageCursor>,
}

/// A page of drift alerts plus the cursor for the next page.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureDriftAlertPage {
    /// Items in this page, deterministically ordered.
    pub items: Vec<FeatureDriftAlert>,
    /// Cursor to pass to the next call, or `None` when exhausted.
    pub next_cursor: Option<FeaturePageCursor>,
}

const FEAT_VIEW_KEY: Symbol = symbol_short!("FT_VIEW");
const FEAT_ATT_KEY: Symbol = symbol_short!("FT_ATT");
const FEAT_DFT_KEY: Symbol = symbol_short!("FT_DFT");
const FEAT_LIST: Symbol = symbol_short!("FT_LIST");

// Per-view insertion index keys (issue #857): ordered identifier lists grouped
// by view id, backing deterministic cursor traversal.
const FEAT_ATT_INDEX: Symbol = symbol_short!("FT_AI");
const FEAT_DFT_INDEX: Symbol = symbol_short!("FT_DI");

// Per-view count slot markers (issue #854 bookkeeping).
const FEAT_ATT_COUNT_KEY: Symbol = symbol_short!("FT_AC");
const FEAT_DFT_COUNT_KEY: Symbol = symbol_short!("FT_DC");

/// Gate the caller behind RBAC and emit the `ft_audit` trail event that makes
/// every state mutation tamper-evident (issue #855).
fn require_role_and_audit(
    env: &Env,
    caller: &Address,
    min_role: Role,
    action: Symbol,
    resource: &Symbol,
) -> Result<(), FeatureStoreError> {
    if RbacManager::get_role(env, caller).is_none() {
        return Err(FeatureStoreError::UnauthorizedCaller);
    }
    RbacManager::require_active_role_min(env, caller, min_role)
        .map_err(|_| FeatureStoreError::InsufficientRole)?;

    env.events().publish(
        (symbol_short!("ft_audit"), action),
        (resource.clone(), caller.clone(), env.ledger().timestamp()),
    );

    Ok(())
}

/// Registers a new ML feature view definition.
///
/// Gated on `Role::Admin` (issue #855). Bounded on registry size, per-view
/// feature count, TTL and version, and rejects malformed payloads (issue #854).
pub fn register_feature_view(
    env: &Env,
    caller: &Address,
    view_id: Symbol,
    entity_name: Symbol,
    feature_names: Vec<Symbol>,
    version: u32,
    ttl_seconds: u64,
) -> Result<FeatureViewRecord, FeatureStoreError> {
    require_role_and_audit(env, caller, Role::Admin, symbol_short!("ftreg"), &view_id)?;

    // Deterministic payload bounds (issue #854).
    if feature_names.len() == 0 || feature_names.len() > limits::MAX_FEATURES_PER_VIEW {
        return Err(FeatureStoreError::InvalidFeatureList);
    }
    if version == 0 {
        return Err(FeatureStoreError::InvalidVersion);
    }
    if ttl_seconds == 0 || ttl_seconds > limits::MAX_TTL_SECONDS {
        return Err(FeatureStoreError::InvalidTtl);
    }

    // Duplicate detection.
    let mut list: Vec<Symbol> = env
        .storage()
        .persistent()
        .get(&FEAT_LIST)
        .unwrap_or_else(|| Vec::new(env));

    let mut exists = false;
    for i in 0..list.len() {
        if list.get(i).unwrap() == view_id {
            exists = true;
            break;
        }
    }
    if exists {
        return Err(FeatureStoreError::DuplicateViewId);
    }

    // Deterministic registry bound (issue #854).
    if list.len() >= limits::MAX_FEATURE_VIEWS {
        return Err(FeatureStoreError::TooManyFeatureViews);
    }

    let now = env.ledger().timestamp();
    let record = FeatureViewRecord {
        view_id: view_id.clone(),
        entity_name,
        feature_names,
        version,
        ttl_seconds,
        registered_at: now,
        active: true,
    };

    env.storage()
        .persistent()
        .set(&(FEAT_VIEW_KEY, view_id.clone()), &record);

    list.push_back(view_id.clone());
    env.storage().persistent().set(&FEAT_LIST, &list);

    env.events().publish(
        (symbol_short!("ft_view"), symbol_short!("reg")),
        (view_id.clone(), record.registered_at, caller.clone()),
    );

    Ok(record)
}

/// Flips a feature view between active/inactive states.
///
/// Gated on `Role::Admin`; emits view + audit events on success.
pub fn set_feature_view_active(
    env: &Env,
    caller: &Address,
    view_id: Symbol,
    active: bool,
) -> Result<FeatureViewRecord, FeatureStoreError> {
    require_role_and_audit(env, caller, Role::Admin, symbol_short!("ftseta"), &view_id)?;

    let mut record: FeatureViewRecord = env
        .storage()
        .persistent()
        .get::<_, FeatureViewRecord>(&(FEAT_VIEW_KEY, view_id.clone()))
        .ok_or(FeatureStoreError::ViewNotFound)?;

    record.active = active;
    env.storage()
        .persistent()
        .set(&(FEAT_VIEW_KEY, view_id.clone()), &record);

    env.events().publish(
        (symbol_short!("ft_view"), symbol_short!("active")),
        (view_id.clone(), active, caller.clone()),
    );

    Ok(record)
}

/// Records a cryptographic attestation of feature values for an entity.
///
/// Gated on `Role::Submitter` (issue #855). Validated and bounded (issue #854):
/// the view must exist and be active, the id must be unique, the hash must be
/// non-zero, and the per-view count is enforced with checked arithmetic.
pub fn record_feature_attestation(
    env: &Env,
    caller: &Address,
    attestation_id: BytesN<32>,
    view_id: Symbol,
    entity_id: Symbol,
    feature_values_hash: BytesN<32>,
) -> Result<FeatureAttestation, FeatureStoreError> {
    require_role_and_audit(
        env,
        caller,
        Role::Submitter,
        symbol_short!("ftatte"),
        &view_id,
    )?;

    if feature_values_hash.to_array() == [0u8; 32] {
        return Err(FeatureStoreError::InvalidHash);
    }

    let view: FeatureViewRecord = env
        .storage()
        .persistent()
        .get::<_, FeatureViewRecord>(&(FEAT_VIEW_KEY, view_id.clone()))
        .ok_or(FeatureStoreError::ViewNotFound)?;
    if !view.active {
        return Err(FeatureStoreError::ViewInactive);
    }

    if env
        .storage()
        .persistent()
        .get::<_, FeatureAttestation>(&(FEAT_ATT_KEY, attestation_id.clone()))
        .is_some()
    {
        return Err(FeatureStoreError::DuplicateAttestation);
    }

    // Checked per-view counter with deterministic bound (issue #854).
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, u32>(&(FEAT_ATT_COUNT_KEY, view_id.clone()))
        .unwrap_or(0);
    let new_count = match count.checked_add(1) {
        Some(c) if c <= limits::MAX_ATTESTATIONS_PER_VIEW => c,
        _ => return Err(FeatureStoreError::TooManyAttestations),
    };

    let now = env.ledger().timestamp();
    let attestation = FeatureAttestation {
        attestation_id: attestation_id.clone(),
        view_id: view_id.clone(),
        entity_id,
        feature_values_hash,
        attested_at: now,
    };

    // Duplicate free index insert.
    env.storage()
        .persistent()
        .set(&(FEAT_ATT_KEY, attestation_id.clone()), &attestation);

    let mut index_list: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&(FEAT_ATT_INDEX, view_id.clone()))
        .unwrap_or_else(|| Vec::new(env));

    index_list.push_back(attestation_id.clone());
    env.storage()
        .persistent()
        .set(&(FEAT_ATT_INDEX, view_id.clone()), &index_list);

    env.storage()
        .persistent()
        .set(&(FEAT_ATT_COUNT_KEY, view_id.clone()), &new_count);

    env.events().publish(
        (symbol_short!("ft_attest"), attestation_id.clone()),
        (
            view_id.clone(),
            attestation.feature_values_hash.clone(),
            now,
            caller.clone(),
        ),
    );

    Ok(attestation)
}

/// Records an on-chain alert for feature distribution drift.
///
/// Gated on `Role::Auditor` (issue #855). Drift scores are bounded to the
/// parts-per-million domain and the per-view alert count is enforced with
/// checked arithmetic (issue #854).
pub fn record_drift_alert(
    env: &Env,
    caller: &Address,
    alert_id: BytesN<32>,
    view_id: Symbol,
    feature_name: Symbol,
    drift_score_ppm: u32,
    threshold_ppm: u32,
) -> Result<FeatureDriftAlert, FeatureStoreError> {
    require_role_and_audit(
        env,
        caller,
        Role::Auditor,
        symbol_short!("ftdft"),
        &view_id,
    )?;

    // Valid drift score/threshold domain (issue #854).
    if drift_score_ppm == 0
        || drift_score_ppm > limits::MAX_DRIFT_PPM
        || threshold_ppm > limits::MAX_DRIFT_PPM
    {
        return Err(FeatureStoreError::InvalidDriftScore);
    }

    let view: FeatureViewRecord = env
        .storage()
        .persistent()
        .get::<_, FeatureViewRecord>(&(FEAT_VIEW_KEY, view_id.clone()))
        .ok_or(FeatureStoreError::ViewNotFound)?;
    if !view.active {
        return Err(FeatureStoreError::ViewInactive);
    }

    if env
        .storage()
        .persistent()
        .get::<_, FeatureDriftAlert>(&(FEAT_DFT_KEY, alert_id.clone()))
        .is_some()
    {
        return Err(FeatureStoreError::DuplicateAlertId);
    }

    // Checked per-view counter with deterministic bound (issue #854).
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, u32>(&(FEAT_DFT_COUNT_KEY, view_id.clone()))
        .unwrap_or(0);
    let new_count = match count.checked_add(1) {
        Some(c) if c <= limits::MAX_DRIFT_ALERTS_PER_VIEW => c,
        _ => return Err(FeatureStoreError::TooManyDriftAlerts),
    };

    let now = env.ledger().timestamp();
    let alert = FeatureDriftAlert {
        alert_id: alert_id.clone(),
        view_id: view_id.clone(),
        feature_name,
        drift_score_ppm,
        threshold_ppm,
        detected_at: now,
    };

    env.storage()
        .persistent()
        .set(&(FEAT_DFT_KEY, alert_id.clone()), &alert);

    let mut index_list: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get(&(FEAT_DFT_INDEX, view_id.clone()))
        .unwrap_or_else(|| Vec::new(env));

    index_list.push_back(alert_id.clone());
    env.storage()
        .persistent()
        .set(&(FEAT_DFT_INDEX, view_id.clone()), &index_list);

    env.storage()
        .persistent()
        .set(&(FEAT_DFT_COUNT_KEY, view_id.clone()), &new_count);

    env.events().publish(
        (symbol_short!("ft_alert"), alert_id.clone()),
        (view_id.clone(), drift_score_ppm, threshold_ppm, now),
    );

    Ok(alert)
}

/// Clamps the page limit (issue #857): rejects 0 and anything beyond
/// [`limits::MAX_PAGE_LIMIT`].
fn effective_limit(limit: u32) -> Result<u32, FeatureStoreError> {
    if limit == 0 || limit > limits::MAX_PAGE_LIMIT {
        return Err(FeatureStoreError::InvalidLimit);
    }
    Ok(limit)
}

/// Validates a pagination cursor against the per-view insertion index
/// (issue #857), returning the slot to resume from.
fn validate_cursor(
    index_list: &Vec<BytesN<32>>,
    cursor: &Option<FeaturePageCursor>,
) -> Result<u32, FeatureStoreError> {
    match cursor {
        None => Ok(0),
        Some(c) => {
            if c.index == 0 || c.index > index_list.len() {
                return Err(FeatureStoreError::InvalidCursor);
            }
            if index_list.get(c.index - 1).unwrap() != c.last_id {
                return Err(FeatureStoreError::InvalidCursor);
            }
            Ok(c.index)
        }
    }
}

/// Lists feature attestations for a view with deterministic cursor pagination
/// and multi-predicate filtering (issue #857).
///
/// Filters:
/// - `entity_filter`: restrict to the attestations of that entity (None = any)
/// - `from_ts` / `to_ts`: inclusive attestation-time window (to_ts == 0 opens)
///
/// Index entries whose backing attestation is absent are skipped, so
/// traversal never traps on dangling identifiers.
pub fn list_feature_attestations(
    env: &Env,
    view_id: Symbol,
    entity_filter: Option<Symbol>,
    from_ts: u64,
    to_ts: u64,
    cursor: Option<FeaturePageCursor>,
    limit: u32,
) -> Result<FeatureAttestationPage, FeatureStoreError> {
    let page_limit = effective_limit(limit)?;

    let index_list: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&(FEAT_ATT_INDEX, view_id.clone()))
        .unwrap_or_else(|| Vec::new(env));

    let start = validate_cursor(&index_list, &cursor)?;

    let mut items: Vec<FeatureAttestation> = Vec::new(env);
    let mut found_more = false;
    let mut last_id = BytesN::zero();
    let mut last_slot: Option<u32> = None;

    let mut i = start;
    while i < index_list.len() {
        let id = index_list.get(i).unwrap();
        if let Some(att) = env
            .storage()
            .persistent()
            .get::<_, FeatureAttestation>(&(FEAT_ATT_KEY, id.clone()))
        {
            let passes = match &entity_filter {
                Some(e) => att.entity_id == *e,
                None => true,
            } && att.attested_at >= from_ts
                && (to_ts == 0 || att.attested_at <= to_ts);

            if passes {
                if items.len() < page_limit {
                    items.push_back(att);
                    last_id = id.clone();
                    last_slot = Some(i);
                } else {
                    // One more filtered item exists after this full page:
                    // build the cursor so traversal can resume here.
                    found_more = true;
                    break;
                }
            }
        }
        i += 1;
    }

    let next_cursor = found_more
        .then(|| last_slot.map(|slot| FeaturePageCursor { index: slot + 1, last_id: last_id.clone() }))
        .flatten();

    Ok(FeatureAttestationPage {
        items,
        next_cursor,
    })
}

/// Lists drift alerts for a view with deterministic cursor pagination and
/// multi-predicate filtering (issue #857).
///
/// Filters:
/// - `feature_filter`: restrict to a single feature (None = any)
/// - `min_score_ppm`: only alerts with `drift_score_ppm >= min_score_ppm`
/// - `from_ts` / `to_ts`: inclusive detection-time window (to_ts == 0 opens)
pub fn list_drift_alerts(
    env: &Env,
    view_id: Symbol,
    feature_filter: Option<Symbol>,
    min_score_ppm: u32,
    from_ts: u64,
    to_ts: u64,
    cursor: Option<FeaturePageCursor>,
    limit: u32,
) -> Result<FeatureDriftAlertPage, FeatureStoreError> {
    let page_limit = effective_limit(limit)?;

    let index_list: Vec<BytesN<32>> = env
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&(FEAT_DFT_INDEX, view_id.clone()))
        .unwrap_or_else(|| Vec::new(env));

    let start = validate_cursor(&index_list, &cursor)?;

    let mut items: Vec<FeatureDriftAlert> = Vec::new(env);
    let mut found_more = false;
    let mut last_id = BytesN::zero();
    let mut last_slot: Option<u32> = None;

    let mut i = start;
    while i < index_list.len() {
        let id = index_list.get(i).unwrap();
        if let Some(alert) = env
            .storage()
            .persistent()
            .get::<_, FeatureDriftAlert>(&(FEAT_DFT_KEY, id.clone()))
        {
            let passes = match &feature_filter {
                Some(f) => alert.feature_name == *f,
                None => true,
            } && alert.drift_score_ppm >= min_score_ppm
                && alert.detected_at >= from_ts
                && (to_ts == 0 || alert.detected_at <= to_ts);

            if passes {
                if items.len() < page_limit {
                    items.push_back(alert);
                    last_id = id.clone();
                    last_slot = Some(i);
                } else {
                    found_more = true;
                    break;
                }
            }
        }
        i += 1;
    }

    let next_cursor = found_more
        .then(|| last_slot.map(|slot| FeaturePageCursor { index: slot + 1, last_id: last_id.clone() }))
        .flatten();

    Ok(FeatureDriftAlertPage {
        items,
        next_cursor,
    })
}

/// Gets a feature view record by ID
pub fn get_feature_view(env: &Env, view_id: Symbol) -> Option<FeatureViewRecord> {
    env.storage()
        .persistent()
        .get(&(FEAT_VIEW_KEY, view_id))
}

/// Gets a feature attestation by ID
pub fn get_feature_attestation(
    env: &Env,
    attestation_id: BytesN<32>,
) -> Option<FeatureAttestation> {
    env.storage()
        .persistent()
        .get(&(FEAT_ATT_KEY, attestation_id))
}

/// Gets a feature drift alert by ID
pub fn get_drift_alert(env: &Env, alert_id: BytesN<32>) -> Option<FeatureDriftAlert> {
    env.storage()
        .persistent()
        .get(&(FEAT_DFT_KEY, alert_id))
}

/// Returns the number of registered feature views (bounded by
/// [`limits::MAX_FEATURE_VIEWS`]).
pub fn get_view_registration_count(env: &Env) -> u32 {
    let list: Vec<Symbol> = env
        .storage()
        .persistent()
        .get(&FEAT_LIST)
        .unwrap_or_else(|| Vec::new(env));
    list.len() as u32
}

/// Returns the number of attestations recorded for a view (bounded by
/// [`limits::MAX_ATTESTATIONS_PER_VIEW`]).
pub fn get_attestation_count(env: &Env, view_id: Symbol) -> u32 {
    env.storage()
        .persistent()
        .get::<_, u32>(&(FEAT_ATT_COUNT_KEY, view_id))
        .unwrap_or(0)
}

/// Returns the number of drift alerts recorded for a view (bounded by
/// [`limits::MAX_DRIFT_ALERTS_PER_VIEW`]).
pub fn get_drift_alert_count(env: &Env, view_id: Symbol) -> u32 {
    env.storage()
        .persistent()
        .get::<_, u32>(&(FEAT_DFT_COUNT_KEY, view_id))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Address, Env};

    use crate::rbac;

    struct Setup {
        env: Env,
        admin: Address,
        submitter: Address,
        auditor: Address,
        unauthorized: Address,
    }

    fn setup() -> Setup {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let submitter = Address::generate(&env);
        let auditor = Address::generate(&env);
        let unauthorized = Address::generate(&env);
        rbac::RbacManager::initialize_admin(&env, &admin);
        rbac::RbacManager::set_role(&env, &admin, &submitter, rbac::Role::Submitter)
            .unwrap();
        rbac::RbacManager::set_role(&env, &admin, &auditor, rbac::Role::Auditor)
            .unwrap();
        Setup {
            env,
            admin,
            submitter,
            auditor,
            unauthorized,
        }
    }

    fn view(s: &Setup, id: &Symbol) -> FeatureViewRecord {
        let mut names: Vec<Symbol> = Vec::new(&s.env);
        names.push_back(symbol_short!("f1"));
        register_feature_view(
            &s.env,
            &s.admin,
            id.clone(),
            symbol_short!("entity"),
            names,
            1,
            86_400,
        )
        .unwrap()
    }

    #[test]
    fn test_register_feature_view_success() {
        let s = setup();
        let rid = symbol_short!("v1");
        let record = view(&s, &rid);
        assert_eq!(record.view_id, rid);
        assert!(record.active);
        assert_eq!(
            get_view_registration_count(&s.env),
            1,
            "exactly one view registered"
        );
    }

    #[test]
    fn test_register_feature_view_rejects_duplicate() {
        let s = setup();
        let id = symbol_short!("dup");
        view(&s, &id);
        let mut names: Vec<Symbol> = Vec::new(&s.env);
        names.push_back(symbol_short!("f1"));
        assert_eq!(
            register_feature_view(
                &s.env,
                &s.admin,
                id,
                symbol_short!("entity"),
                names,
                1,
                86_400
            )
            .unwrap_err(),
            FeatureStoreError::DuplicateViewId
        );
    }

    #[test]
    fn test_register_feature_view_requires_admin() {
        let s = setup();
        let mut names: Vec<Symbol> = Vec::new(&s.env);
        names.push_back(symbol_short!("f"));
        assert_eq!(
            register_feature_view(
                &s.env,
                &s.submitter,
                symbol_short!("v2"),
                symbol_short!("e2"),
                names,
                1,
                86_400
            )
            .unwrap_err(),
            FeatureStoreError::InsufficientRole
        );
    }

    #[test]
    fn test_register_feature_view_rejects_malformed() {
        let s = setup();

        // Exceeding the per-view feature cap.
        let mut names: Vec<Symbol> = Vec::new(&s.env);
        for _ in 0..(limits::MAX_FEATURES_PER_VIEW + 1) {
            names.push_back(symbol_short!("f"));
        }
        assert_eq!(
            register_feature_view(
                &s.env,
                &s.admin,
                symbol_short!("v3"),
                symbol_short!("e"),
                names,
                1,
                86_400
            )
            .unwrap_err(),
            FeatureStoreError::InvalidFeatureList
        );

        // TTL above the maximum bound.
        let mut names: Vec<Symbol> = Vec::new(&s.env);
        names.push_back(symbol_short!("f"));
        assert_eq!(
            register_feature_view(
                &s.env,
                &s.admin,
                symbol_short!("v4"),
                symbol_short!("e"),
                names,
                1,
                limits::MAX_TTL_SECONDS + 1
            )
            .unwrap_err(),
            FeatureStoreError::InvalidTtl
        );
    }

    #[test]
    fn test_attestation_requires_submitter_role() {
        let s = setup();
        let id = symbol_short!("t1");
        view(&s, &id);
        assert_eq!(
            record_feature_attestation(
                &s.env,
                &s.unauthorized,
                BytesN::from_array(&s.env, &[7u8; 32]),
                id,
                symbol_short!("ent1"),
                BytesN::from_array(&s.env, &[1u8; 32]),
            )
            .unwrap_err(),
            FeatureStoreError::UnauthorizedCaller
        );
    }

    #[test]
    fn test_attestation_success() {
        let s = setup();
        let id = symbol_short!("t2");
        view(&s, &id);
        let aid = BytesN::from_array(&s.env, &[1u8; 32]);
        let att = record_feature_attestation(
            &s.env,
            &s.submitter,
            aid.clone(),
            id.clone(),
            symbol_short!("ent1"),
            BytesN::from_array(&s.env, &[2u8; 32]),
        )
        .unwrap();
        assert_eq!(att.attestation_id, aid);
        assert_eq!(
            get_feature_attestation(&s.env, aid).unwrap().entity_id,
            symbol_short!("ent1")
        );
        assert_eq!(get_attestation_count(&s.env, id), 1);
    }

    #[test]
    fn test_attestation_rejects_duplicate_and_zero_hash() {
        let s = setup();
        let id = symbol_short!("t3");
        view(&s, &id);
        let aid = BytesN::from_array(&s.env, &[3u8; 32]);
        record_feature_attestation(
            &s.env,
            &s.submitter,
            aid.clone(),
            id.clone(),
            symbol_short!("ent1"),
            BytesN::from_array(&s.env, &[4u8; 32]),
        )
        .unwrap();
        assert_eq!(
            record_feature_attestation(
                &s.env,
                &s.submitter,
                aid,
                id,
                symbol_short!("ent1"),
                BytesN::from_array(&s.env, &[4u8; 32]),
            )
            .unwrap_err(),
            FeatureStoreError::DuplicateAttestation
        );
    }

    #[test]
    fn test_attestation_ring_buffer_eviction() {
        let s = setup();
        let id = symbol_short!("t4");
        view(&s, &id);

        // Saturate the per-view counter to its deterministic cap; further
        // records are rejected instead of growing storage unboundedly.
        for i in 0..limits::MAX_ATTESTATIONS_PER_VIEW {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            record_feature_attestation(
                &s.env,
                &s.submitter,
                BytesN::from_array(&s.env, &bytes),
                id.clone(),
                symbol_short!("ent1"),
                BytesN::from_array(&s.env, &[1u8; 32]),
            )
            .unwrap();
        }
        assert_eq!(
            record_feature_attestation(
                &s.env,
                &s.submitter,
                BytesN::from_array(&s.env, &[255u8; 32]),
                id.clone(),
                symbol_short!("ent1"),
                BytesN::from_array(&s.env, &[1u8; 32]),
            )
            .unwrap_err(),
            FeatureStoreError::TooManyAttestations
        );
    }

    #[test]
    fn test_drift_alert_requires_auditor_role() {
        let s = setup();
        let id = symbol_short!("t5");
        view(&s, &id);
        assert_eq!(
            record_drift_alert(
                &s.env,
                &s.submitter,
                BytesN::from_array(&s.env, &[5u8; 32]),
                id,
                symbol_short!("f1"),
                5_000,
                4_000,
            )
            .unwrap_err(),
            FeatureStoreError::InsufficientRole
        );
    }

    #[test]
    fn test_drift_alert_rejects_invalid_score() {
        let s = setup();
        let id = symbol_short!("t6");
        view(&s, &id);
        assert_eq!(
            record_drift_alert(
                &s.env,
                &s.auditor,
                BytesN::from_array(&s.env, &[6u8; 32]),
                id,
                symbol_short!("f1"),
                limits::MAX_DRIFT_PPM + 1,
                4_000,
            )
            .unwrap_err(),
            FeatureStoreError::InvalidDriftScore
        );
    }

    #[test]
    fn test_pagination_traversal() {
        let s = setup();
        let id = symbol_short!("t7");
        view(&s, &id);
        for i in 0..10u8 {
            let mut bytes = [0u8; 32];
            bytes[0] = i + 20;
            record_feature_attestation(
                &s.env,
                &s.submitter,
                BytesN::from_array(&s.env, &bytes),
                id.clone(),
                symbol_short!("ent1"),
                BytesN::from_array(&s.env, &[1u8; 32]),
            )
            .unwrap();
        }

        let mut cursor: Option<FeaturePageCursor> = None;
        let mut total = 0u32;
        loop {
            let page =
                list_feature_attestations(&s.env, id.clone(), None, 0, 0, cursor.clone(), 4)
                    .unwrap();
            total += page.items.len() as u32;
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(total, 10);
    }

    #[test]
    fn test_pagination_entity_filter() {
        let s = setup();
        let id = symbol_short!("t8");
        view(&s, &id);
        for i in 0..6u8 {
            let mut bytes = [0u8; 32];
            bytes[0] = i + 30;
            let entity = if i % 2 == 0 {
                symbol_short!("aa")
            } else {
                symbol_short!("bb")
            };
            record_feature_attestation(
                &s.env,
                &s.submitter,
                BytesN::from_array(&s.env, &bytes),
                id.clone(),
                entity,
                BytesN::from_array(&s.env, &[1u8; 32]),
            )
            .unwrap();
        }
        let page = list_feature_attestations(
            &s.env,
            id,
            Some(symbol_short!("aa")),
            0,
            0,
            None,
            limits::MAX_PAGE_LIMIT,
        )
        .unwrap();
        assert_eq!(page.items.len(), 3);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn test_pagination_invalid_cursor() {
        let s = setup();
        let id = symbol_short!("t9");
        view(&s, &id);
        let mut bytes = [0u8; 32];
        bytes[0] = 40;
        record_feature_attestation(
            &s.env,
            &s.submitter,
            BytesN::from_array(&s.env, &bytes),
            id.clone(),
            symbol_short!("ent1"),
            BytesN::from_array(&s.env, &[1u8; 32]),
        )
        .unwrap();
        assert_eq!(
            list_feature_attestations(
                &s.env,
                id,
                None,
                0,
                0,
                Some(FeaturePageCursor {
                    index: 1,
                    last_id: BytesN::from_array(&s.env, &[99u8; 32]),
                }),
                4
            )
            .unwrap_err(),
            FeatureStoreError::InvalidCursor
        );
    }

    #[test]
    fn test_pagination_past_end() {
        let s = setup();
        let id = symbol_short!("t10");
        view(&s, &id);
        let mut bytes = [0u8; 32];
        bytes[0] = 50;
        let att = record_feature_attestation(
            &s.env,
            &s.submitter,
            BytesN::from_array(&s.env, &bytes),
            id.clone(),
            symbol_short!("ent1"),
            BytesN::from_array(&s.env, &[1u8; 32]),
        )
        .unwrap();
        // A cursor pointing at the end yields an empty, exhausted page.
        let page = list_feature_attestations(
            &s.env,
            id,
            None,
            0,
            0,
            Some(FeaturePageCursor {
                index: 1,
                last_id: att.attestation_id.clone(),
            }),
            4,
        )
        .unwrap();
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn test_pagination_drift_alerts_threshold_filter() {
        let s = setup();
        let id = symbol_short!("t11");
        view(&s, &id);
        for (i, score) in [1_000u32, 5_000, 9_000].iter().enumerate() {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8 + 60;
            record_drift_alert(
                &s.env,
                &s.auditor,
                BytesN::from_array(&s.env, &bytes),
                id.clone(),
                symbol_short!("f1"),
                *score,
                5_000,
            )
            .unwrap();
        }
        let page = list_drift_alerts(
            &s.env,
            id,
            None,
            5_000,
            0,
            0,
            None,
            limits::MAX_PAGE_LIMIT,
        )
        .unwrap();
        assert_eq!(page.items.len(), 2);
        for item in page.items.iter() {
            assert!(item.drift_score_ppm >= 5_000);
        }
    }

    #[test]
    fn test_inactive_view_blocks_mutations() {
        let s = setup();
        let id = symbol_short!("t12");
        view(&s, &id);
        set_feature_view_active(&s.env, &s.admin, id.clone(), false)
            .unwrap();
        assert_eq!(
            record_feature_attestation(
                &s.env,
                &s.submitter,
                BytesN::from_array(&s.env, &[70u8; 32]),
                id.clone(),
                symbol_short!("ent1"),
                BytesN::from_array(&s.env, &[1u8; 32]),
            )
            .unwrap_err(),
            FeatureStoreError::ViewInactive
        );
    }

    #[test]
    fn test_full_pagination_end_to_end() {
        let s = setup();
        let id = symbol_short!("t13");
        view(&s, &id);
        for i in 0..7u8 {
            let mut bytes = [0u8; 32];
            bytes[0] = i + 80;
            record_feature_attestation(
                &s.env,
                &s.submitter,
                BytesN::from_array(&s.env, &bytes),
                id.clone(),
                symbol_short!("ent1"),
                BytesN::from_array(&s.env, &[1u8; 32]),
            )
            .unwrap();
        }
        let page1 = list_feature_attestations(&s.env, id.clone(), None, 0, 0, None, 5).unwrap();
        assert_eq!(page1.items.len(), 5);
        let cursor = page1.next_cursor.clone().unwrap();
        let page2 =
            list_feature_attestations(&s.env, id, None, 0, 0, Some(cursor), 5).unwrap();
        assert_eq!(page2.items.len(), 2);
        assert!(page2.next_cursor.is_none());
    }
}
