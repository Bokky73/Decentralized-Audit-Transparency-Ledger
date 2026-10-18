//! Contract Event ML Feature Store Module (#524)
//!
//! Provides on-chain coordination, feature view registration, cryptographic
//! feature attestations, and model drift alerts for ML pipelines.

use soroban_sdk::{
    contracttype, symbol_short, BytesN, Env, Symbol, Vec,
};

/// Storage tier classification for keys managed by this module.
///
/// Retention SLA drives the tier:
/// - `Persistent`: archival-critical audit records (feature views, attestations,
///   drift alerts, and the view index) that must survive until explicitly removed.
/// - `Temporary`: short-lived scratch data with no archival guarantee.
/// - `Instance`: contract-instance scoped configuration/metadata.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StorageTier {
    Persistent = 0,
    Temporary = 1,
    Instance = 2,
}

/// Data type of a feature value.
///
/// Discriminants are pinned to compact `u32` values so the XDR encoding stays
/// minimal and stable across releases.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FeatureDataType {
    Float = 0,
    Int = 1,
    StringVal = 2,
    BytesVal = 3,
    VectorEmbedding = 4,
}

/// Feature view metadata registration.
///
/// Fields are ordered widest-first to keep XDR padding minimal. `version` and
/// `active` are packed into the trailing word.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureViewRecord {
    pub feature_names: Vec<Symbol>,
    pub ttl_seconds: u64,
    pub registered_at: u64,
    pub view_id: Symbol,
    pub entity_name: Symbol,
    pub version: u32,
    pub active: bool,
}

/// On-chain cryptographic attestation of computed feature values.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureAttestation {
    pub feature_values_hash: BytesN<32>,
    pub attestation_id: BytesN<32>,
    pub attested_at: u64,
    pub view_id: Symbol,
    pub entity_id: Symbol,
}

/// On-chain alert for detected feature drift or data distribution shift.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureDriftAlert {
    pub alert_id: BytesN<32>,
    pub detected_at: u64,
    pub drift_score_ppm: u32, // Parts per million (e.g. 250000 = 0.25 PSI)
    pub threshold_ppm: u32,
    pub view_id: Symbol,
    pub feature_name: Symbol,
}

const FEAT_VIEW_KEY: Symbol = symbol_short!("FT_VIEW");
const FEAT_ATT_KEY: Symbol = symbol_short!("FT_ATT");
const FEAT_DFT_KEY: Symbol = symbol_short!("FT_DFT");
const FEAT_LIST: Symbol = symbol_short!("FT_LIST");

/// Default TTL extension (in ledgers) applied to archival-critical records.
/// At ~5s per ledger this is roughly 30 days.
pub const DEFAULT_TTL_EXTEND_LEDGERS: u32 = 518_400;

/// Threshold (in ledgers) below which a record is considered at risk of
/// archival and should be bumped by `extend_ttl`.
pub const TTL_BUMP_THRESHOLD_LEDGERS: u32 = 17_280;

/// Returns the storage tier for a given key, per the retention SLA.
pub fn storage_tier_for(key: &Symbol) -> StorageTier {
    if *key == FEAT_VIEW_KEY || *key == FEAT_ATT_KEY || *key == FEAT_DFT_KEY || *key == FEAT_LIST {
        StorageTier::Persistent
    } else {
        StorageTier::Temporary
    }
}

/// Permissionless TTL extension helper for archival-critical records.
///
/// Anyone may call this to keep active audit records (feature views,
/// attestations, drift alerts, and the view index) from being archived. It is
/// idempotent and safe to call repeatedly; it never mutates record contents.
pub fn extend_ttl(env: &Env, key: Symbol) {
    let threshold = TTL_BUMP_THRESHOLD_LEDGERS;
    let extend_to = DEFAULT_TTL_EXTEND_LEDGERS;

    match storage_tier_for(&key) {
        StorageTier::Persistent => {
            env.storage()
                .persistent()
                .extend_ttl(&key, threshold, extend_to);
        }
        StorageTier::Temporary => {
            env.storage()
                .temporary()
                .extend_ttl(&key, threshold, extend_to);
        }
        StorageTier::Instance => {
            env.storage()
                .instance()
                .extend_ttl(threshold, extend_to);
        }
    }
}

/// Permissionless TTL extension for a specific feature view record.
pub fn extend_feature_view_ttl(env: &Env, view_id: Symbol) {
    env.storage().persistent().extend_ttl(
        &(FEAT_VIEW_KEY, view_id),
        TTL_BUMP_THRESHOLD_LEDGERS,
        DEFAULT_TTL_EXTEND_LEDGERS,
    );
}

/// Permissionless TTL extension for a specific attestation record.
pub fn extend_attestation_ttl(env: &Env, attestation_id: BytesN<32>) {
    env.storage().persistent().extend_ttl(
        &(FEAT_ATT_KEY, attestation_id),
        TTL_BUMP_THRESHOLD_LEDGERS,
        DEFAULT_TTL_EXTEND_LEDGERS,
    );
}

/// Permissionless TTL extension for a specific drift alert record.
pub fn extend_drift_alert_ttl(env: &Env, alert_id: BytesN<32>) {
    env.storage().persistent().extend_ttl(
        &(FEAT_DFT_KEY, alert_id),
        TTL_BUMP_THRESHOLD_LEDGERS,
        DEFAULT_TTL_EXTEND_LEDGERS,
    );
}

/// Registers a new ML feature view definition
pub fn register_feature_view(
    env: &Env,
    view_id: Symbol,
    entity_name: Symbol,
    feature_names: Vec<Symbol>,
    version: u32,
    ttl_seconds: u64,
) -> FeatureViewRecord {
    let now = env.ledger().timestamp();
    let record = FeatureViewRecord {
        feature_names,
        ttl_seconds,
        registered_at: now,
        view_id: view_id.clone(),
        entity_name,
        version,
        active: true,
    };

    let view_key = (FEAT_VIEW_KEY, view_id.clone());
    env.storage().persistent().set(&view_key, &record);
    env.storage().persistent().extend_ttl(
        &view_key,
        TTL_BUMP_THRESHOLD_LEDGERS,
        DEFAULT_TTL_EXTEND_LEDGERS,
    );

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
    if !exists {
        list.push_back(view_id);
        env.storage().persistent().set(&FEAT_LIST, &list);
        env.storage().persistent().extend_ttl(
            &FEAT_LIST,
            TTL_BUMP_THRESHOLD_LEDGERS,
            DEFAULT_TTL_EXTEND_LEDGERS,
        );
    }

    record
}

/// Records a cryptographic attestation of feature values for an entity
pub fn record_feature_attestation(
    env: &Env,
    attestation_id: BytesN<32>,
    view_id: Symbol,
    entity_id: Symbol,
    feature_values_hash: BytesN<32>,
) -> FeatureAttestation {
    let now = env.ledger().timestamp();
    let attestation = FeatureAttestation {
        feature_values_hash,
        attestation_id: attestation_id.clone(),
        attested_at: now,
        view_id,
        entity_id,
    };

    let att_key = (FEAT_ATT_KEY, attestation_id);
    env.storage().persistent().set(&att_key, &attestation);
    env.storage().persistent().extend_ttl(
        &att_key,
        TTL_BUMP_THRESHOLD_LEDGERS,
        DEFAULT_TTL_EXTEND_LEDGERS,
    );
    attestation
}

/// Records an on-chain alert for feature distribution drift
pub fn record_drift_alert(
    env: &Env,
    alert_id: BytesN<32>,
    view_id: Symbol,
    feature_name: Symbol,
    drift_score_ppm: u32,
    threshold_ppm: u32,
) -> FeatureDriftAlert {
    let now = env.ledger().timestamp();
    let alert = FeatureDriftAlert {
        alert_id: alert_id.clone(),
        detected_at: now,
        drift_score_ppm,
        threshold_ppm,
        view_id,
        feature_name,
    };

    let alert_key = (FEAT_DFT_KEY, alert_id);
    env.storage().persistent().set(&alert_key, &alert);
    env.storage().persistent().extend_ttl(
        &alert_key,
        TTL_BUMP_THRESHOLD_LEDGERS,
        DEFAULT_TTL_EXTEND_LEDGERS,
    );
    alert
}

/// Gets a feature view record by ID
pub fn get_feature_view(env: &Env, view_id: Symbol) -> Option<FeatureViewRecord> {
    env.storage().persistent().get(&(FEAT_VIEW_KEY, view_id))
}

/// Gets a feature attestation by ID
pub fn get_feature_attestation(env: &Env, attestation_id: BytesN<32>) -> Option<FeatureAttestation> {
    env.storage().persistent().get(&(FEAT_ATT_KEY, attestation_id))
}

/// Gets a feature drift alert by ID
pub fn get_drift_alert(env: &Env, alert_id: BytesN<32>) -> Option<FeatureDriftAlert> {
    env.storage().persistent().get(&(FEAT_DFT_KEY, alert_id))
}
