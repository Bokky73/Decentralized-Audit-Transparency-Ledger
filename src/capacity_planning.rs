//! # Contract Event Capacity Planning and Auto-Scaling Module
//!
//! Provides on-chain capacity telemetry recording, multi-tenant quota tier management,
//! predictive scaling recommendation anchoring, and resource utilization auditing
//! for the Decentralized Audit Transparency Ledger.
//!
//! ## Core Features:
//! - **Capacity Telemetry Ledger**: Periodic snapshots of TPS, storage growth, gas consumption, and compute load.
//! - **Multi-Tenant Quota Tiers**: Dynamic daily event quotas, burst TPS limits, and per-submitter rate-limiting.
//! - **Predictive Scaling Recommendations**: On-chain anchoring of ML-driven replica and resource sizing decisions.
//! - **Cost Accounting & Optimization**: Gas and storage cost tracking per submitter tier.

#![no_std]
use soroban_sdk::{
    contracterror, contracttype, panic_with_error, Address, BytesN, Env, Symbol,
};

// ── Error Codes ──────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CapacityError {
    /// Quota tier not found
    QuotaTierNotFound = 7001,
    /// Submitter daily event quota exceeded
    QuotaExceeded = 7002,
    /// Submitter is currently throttled due to burst rate limit
    BurstRateExceeded = 7003,
    /// Caller is not authorized as capacity administrator
    UnauthorizedAdmin = 7004,
    /// Invalid recommendation parameters
    InvalidRecommendation = 7005,
    /// Telemetry capacity limit reached
    TelemetryCapacityExceeded = 7006,
    /// Policy parameter out of allowable bounds
    InvalidPolicyBounds = 7007,
}

// ── Data Types ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityMetricRecord {
    pub timestamp: u64,
    pub current_tps: u32,
    pub peak_tps: u32,
    pub storage_bytes_used: u64,
    pub active_submitters: u32,
    pub gas_consumed_stroops: u64,
    pub cpu_utilization_basis_pts: u32, // 10000 = 100%
    pub memory_mb_used: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaTier {
    pub tier_id: u32,
    pub tier_name: Symbol,
    pub max_daily_events: u64,
    pub max_burst_tps: u32,
    pub storage_quota_bytes: u64,
    pub max_batch_size: u32,
    pub cost_per_m_events_stroops: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitterQuotaRecord {
    pub submitter: Address,
    pub tier_id: u32,
    pub events_in_current_window: u64,
    pub window_start: u64,
    pub is_throttled: bool,
    pub total_cost_billed_stroops: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalingRecommendationRecord {
    pub timestamp: u64,
    pub recommended_min_replicas: u32,
    pub recommended_max_replicas: u32,
    pub recommended_cpu_millicores: u32,
    pub recommended_memory_mb: u32,
    pub forecast_horizon_hours: u32,
    pub confidence_score_percent: u32,
    pub estimated_monthly_cost_usd: u32,
    pub model_digest: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityPolicy {
    pub auto_scaling_enabled: bool,
    pub target_cpu_percent: u32,
    pub target_tps_per_replica: u32,
    pub cooldown_period_seconds: u32,
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub last_scaled_at: u64,
}

// ── Storage Keys ─────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapacityStorageKey {
    TelemetrySnapshot(u32),
    TelemetryCount,
    Tier(u32),
    SubmitterQuota(Address),
    LatestRecommendation,
    Policy,
}

/// Deterministic bounds to cap on-chain storage, memory and CPU usage.
const MAX_TELEMETRY_SNAPSHOTS: u32 = 1000;
const MAX_BATCH_SIZE: u32 = 10_000;
const MAX_REPLICAS: u32 = 10_000;
const MAX_CPU_BASIS_PTS: u32 = 10_000; // 100.00%
const MAX_TPS: u32 = 1_000_000;
const MAX_MEMORY_MB: u32 = 1_000_000;
const MAX_FORECAST_HOURS: u32 = 8_760; // 1 year
const MAX_CONFIDENCE_PCT: u32 = 100;

// ── Capacity Planning Functions ──────────────────────────────────────────

pub struct CapacityPlanning;

impl CapacityPlanning {
    /// Record a point-in-time capacity and resource telemetry metric
    pub fn record_telemetry(
        env: &Env,
        caller: Address,
        metric: CapacityMetricRecord,
    ) {
        caller.require_auth();

        // Reject malformed metric payloads.
        if metric.current_tps > MAX_TPS
            || metric.peak_tps > MAX_TPS
            || metric.cpu_utilization_basis_pts > MAX_CPU_BASIS_PTS
            || metric.memory_mb_used > MAX_MEMORY_MB
        {
            panic_with_error!(env, CapacityError::InvalidRecommendation);
        }

        let count: u32 = env
            .storage()
            .persistent()
            .get(&CapacityStorageKey::TelemetryCount)
            .unwrap_or(0);

        // Ring buffer: deterministic, bounded snapshot count.
        let next_idx = count % MAX_TELEMETRY_SNAPSHOTS;
        let key = CapacityStorageKey::TelemetrySnapshot(next_idx);
        env.storage().persistent().set(&key, &metric);

        let next_count = count
            .checked_add(1)
            .unwrap_or(MAX_TELEMETRY_SNAPSHOTS);
        env.storage()
            .persistent()
            .set(&CapacityStorageKey::TelemetryCount, &next_count);
    }

    /// Register or update a multi-tenant quota tier
    pub fn set_quota_tier(
        env: &Env,
        admin: Address,
        tier: QuotaTier,
    ) {
        admin.require_auth();

        // Reject malformed / out-of-bounds tier parameters.
        if tier.max_daily_events == 0
            || tier.max_burst_tps > MAX_TPS
            || tier.storage_quota_bytes == 0
            || tier.max_batch_size == 0
            || tier.max_batch_size > MAX_BATCH_SIZE
            || tier.cost_per_m_events_stroops == 0
        {
            panic_with_error!(env, CapacityError::InvalidPolicyBounds);
        }

        let key = CapacityStorageKey::Tier(tier.tier_id);
        env.storage().persistent().set(&key, &tier);
    }

    /// Assign a submitter to a quota tier
    pub fn set_submitter_quota(
        env: &Env,
        admin: Address,
        submitter: Address,
        tier_id: u32,
    ) {
        admin.require_auth();

        let tier_key = CapacityStorageKey::Tier(tier_id);
        if !env.storage().persistent().has(&tier_key) {
            panic_with_error!(env, CapacityError::QuotaTierNotFound);
        }

        let record = SubmitterQuotaRecord {
            submitter: submitter.clone(),
            tier_id,
            events_in_current_window: 0,
            window_start: env.ledger().timestamp(),
            is_throttled: false,
            total_cost_billed_stroops: 0,
        };

        let sub_key = CapacityStorageKey::SubmitterQuota(submitter);
        env.storage().persistent().set(&sub_key, &record);
    }

    /// Check and consume quota for a submitter logging batch events
    pub fn consume_quota(
        env: &Env,
        submitter: Address,
        event_count: u32,
    ) -> bool {
        submitter.require_auth();

        // Reject empty or oversized batches to bound per-call work.
        if event_count == 0 || event_count > MAX_BATCH_SIZE {
            panic_with_error!(env, CapacityError::InvalidRecommendation);
        }

        let sub_key = CapacityStorageKey::SubmitterQuota(submitter.clone());
        let mut sub_record: SubmitterQuotaRecord = match env.storage().persistent().get(&sub_key) {
            Some(r) => r,
            None => {
                // Default Tier 1 (Standard)
                SubmitterQuotaRecord {
                    submitter: submitter.clone(),
                    tier_id: 1,
                    events_in_current_window: 0,
                    window_start: env.ledger().timestamp(),
                    is_throttled: false,
                    total_cost_billed_stroops: 0,
                }
            }
        };

        let tier_key = CapacityStorageKey::Tier(sub_record.tier_id);
        let tier: QuotaTier = env.storage().persistent().get(&tier_key).unwrap_or(QuotaTier {
            tier_id: 1,
            tier_name: Symbol::new(env, "standard"),
            max_daily_events: 100_000,
            max_burst_tps: 50,
            storage_quota_bytes: 1_000_000_000,
            max_batch_size: 100,
            cost_per_m_events_stroops: 5_000_000,
        });

        // Enforce per-batch size cap from the tier's own policy.
        if event_count > tier.max_batch_size {
            panic_with_error!(env, CapacityError::InvalidRecommendation);
        }

        let now = env.ledger().timestamp();
        // 24-hour sliding window reset
        if now >= sub_record.window_start + 86400 {
            sub_record.events_in_current_window = 0;
            sub_record.window_start = now;
            sub_record.is_throttled = false;
        }

        let added = event_count as u64;
        let projected = sub_record
            .events_in_current_window
            .checked_add(added)
            .unwrap_or(u64::MAX);

        if projected > tier.max_daily_events {
            sub_record.is_throttled = true;
            env.storage().persistent().set(&sub_key, &sub_record);
            panic_with_error!(env, CapacityError::QuotaExceeded);
        }

        sub_record.events_in_current_window = projected;

        // Overflow-safe batch cost: (event_count * cost_per_m) / 1_000_000
        let batch_cost = added
            .checked_mul(tier.cost_per_m_events_stroops)
            .and_then(|v| v.checked_div(1_000_000))
            .unwrap_or(0);

        let new_total = sub_record
            .total_cost_billed_stroops
            .checked_add(batch_cost)
            .unwrap_or(u64::MAX);
        sub_record.total_cost_billed_stroops = new_total;

        env.storage().persistent().set(&sub_key, &sub_record);
        true
    }

    /// Record predictive scaling recommendation generated by ML forecasting model
    pub fn record_recommendation(
        env: &Env,
        reporter: Address,
        rec: ScalingRecommendationRecord,
    ) {
        reporter.require_auth();

        if rec.recommended_min_replicas == 0
            || rec.recommended_max_replicas < rec.recommended_min_replicas
            || rec.recommended_max_replicas > MAX_REPLICAS
            || rec.recommended_cpu_millicores == 0
            || rec.recommended_memory_mb > MAX_MEMORY_MB
            || rec.forecast_horizon_hours == 0
            || rec.forecast_horizon_hours > MAX_FORECAST_HOURS
            || rec.confidence_score_percent > MAX_CONFIDENCE_PCT
        {
            panic_with_error!(env, CapacityError::InvalidRecommendation);
        }

        env.storage()
            .persistent()
            .set(&CapacityStorageKey::LatestRecommendation, &rec);
    }

    /// Configure auto-scaling policy parameters
    pub fn update_policy(
        env: &Env,
        admin: Address,
        policy: CapacityPolicy,
    ) {
        admin.require_auth();

        if policy.min_replicas == 0
            || policy.max_replicas < policy.min_replicas
            || policy.max_replicas > MAX_REPLICAS
            || policy.min_replicas > MAX_REPLICAS
            || policy.target_cpu_percent > MAX_CPU_BASIS_PTS
            || policy.cooldown_period_seconds == 0
        {
            panic_with_error!(env, CapacityError::InvalidPolicyBounds);
        }

        env.storage()
            .persistent()
            .set(&CapacityStorageKey::Policy, &policy);
    }

    /// Query latest scaling recommendation
    pub fn get_latest_recommendation(env: &Env) -> Option<ScalingRecommendationRecord> {
        env.storage().persistent().get(&CapacityStorageKey::LatestRecommendation)
    }

    /// Query active auto-scaling policy
    pub fn get_policy(env: &Env) -> Option<CapacityPolicy> {
        env.storage().persistent().get(&CapacityStorageKey::Policy)
    }

    /// Query submitter quota record
    pub fn get_submitter_quota(env: &Env, submitter: Address) -> Option<SubmitterQuotaRecord> {
        let key = CapacityStorageKey::SubmitterQuota(submitter);
        env.storage().persistent().get(&key)
    }

    /// Query quota tier definition
    pub fn get_quota_tier(env: &Env, tier_id: u32) -> Option<QuotaTier> {
        let key = CapacityStorageKey::Tier(tier_id);
        env.storage().persistent().get(&key)
    }
}
