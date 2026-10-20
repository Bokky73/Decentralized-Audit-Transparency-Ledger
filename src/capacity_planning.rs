//! # Ledger Shard Capacity Forecasting & Threshold Alerting (`capacity_planning`)
//!
//! This module manages ledger shard capacity configurations, utilization telemetry ingestion,
//! deterministic exhaustion forecasting, and multi-tier threshold alerting for the
//! Decentralized Audit & Transparency Ledger (Issue #900).
//!
//! Every state-mutating entrypoint in this module is gated by fine-grained Role-Based Access
//! Control ([`crate::rbac`]) and emits standardized, tamper-evident Soroban diagnostic (`cap_diag`)
//! and audit (`rbac_aud`) events containing the authenticated `caller`, ledger `timestamp`,
//! `submitter_did`, and a cryptographic `state_diff_digest` (SHA-256 over pre/post state).
//!
//! ## RBAC Gating Matrix for Mutating Entrypoints
//!
//! | Entrypoint | Required Permission | Minimum Role | Allowed Roles (by Hierarchy) |
//! |------------|---------------------|--------------|------------------------------|
//! | [`record_shard_utilization`] | [`Permission::RecordShardTelemetry`] | [`Role::Operator`] | `Operator`, `CapacityPlanner`, `Auditor`, `Admin` |
//! | [`acknowledge_threshold_alert`] | [`Permission::AcknowledgeAlert`] | [`Role::Operator`] | `Operator`, `CapacityPlanner`, `Auditor`, `Admin` |
//! | [`configure_shard_threshold`] | [`Permission::ConfigureShardThreshold`] | [`Role::CapacityPlanner`] | `CapacityPlanner`, `Auditor`, `Admin` |
//! | [`generate_capacity_forecast`] | [`Permission::GenerateForecast`] | [`Role::CapacityPlanner`] | `CapacityPlanner`, `Auditor`, `Admin` |
//! | [`resolve_threshold_alert`] | [`Permission::ResolveAlert`] | [`Role::Auditor`] | `Auditor`, `Admin` |
//! | [`override_shard_capacity_policy`] | [`Permission::OverrideCapacityPolicy`] | [`Role::Auditor`] | `Auditor`, `Admin` |
//!
//! ## Regulator Compliance Mapping Table
//!
//! | Regulator / Standard | Control Reference | Compliance Objective | Module Enforcement |
//! |----------------------|-------------------|----------------------|--------------------|
//! | **EU DORA** | Art. 11 (ICT Capacity & Performance) | Continuous monitoring of ledger capacity thresholds and proactive forecasting | [`configure_shard_threshold`], [`record_shard_utilization`], and [`generate_capacity_forecast`] enforce basis-point warning/critical watermarks and compute exhaustion horizons. |
//! | **SOC 2 Type II** | CC6.1 / CC7.2 | Logical access controls on infrastructure capacity configuration & anomaly alerting | [`authorize_mutation`] validates caller signatures, active DID status, and hierarchical RBAC roles prior to any state mutation. |
//! | **ISO/IEC 27001:2022** | A.8.6 (Capacity Management) | Monitoring and projection of storage resource utilization | [`CapacityForecast`] persists deterministic utilization projections, exhaustion ETAs, and shard scaling recommendations. |
//! | **NIST SP 800-53 Rev. 5** | AU-3 / AU-9 / SI-4 | Tamper-evident audit record content and system monitoring alerts | Every allowed or denied mutation records a SHA-256 `state_diff_digest` via [`record_audit_event`] and emits Soroban diagnostic events. |
//! | **FFIEC IT Handbook** | Operations — Capacity Planning | Segregation of duties between telemetry operators, capacity planners, and auditors | Distinct minimum role tiers (`Operator` < `CapacityPlanner` < `Auditor` < `Admin`) prevent unauthorized alert suppression or threshold tampering. |

use soroban_sdk::{contracttype, symbol_short, Address, Bytes, BytesN, Env};

use crate::rbac::{
    authorize_mutation, compute_state_diff_digest, record_audit_event, u32_le_bytes, u64_le_bytes,
    Permission, RbacError,
};

/// Maximum basis points representing 100.00% shard utilization.
pub const MAX_BPS: u32 = 10_000;

/// Storage keys isolated to the capacity planning subsystem.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapacityDataKey {
    /// Per-shard capacity threshold configuration (`shard_id -> ShardCapacityConfig`).
    ShardConfig(u32),
    /// Latest shard utilization telemetry (`shard_id -> ShardTelemetrySample`).
    ShardTelemetry(u32),
    /// Latest computed capacity forecast (`shard_id -> CapacityForecast`).
    ShardForecast(u32),
    /// Sequential counter of generated threshold alerts.
    AlertCount,
    /// Stored threshold alert (`alert_id -> ThresholdAlert`).
    AlertEntry(u32),
}

/// Capacity threshold configuration for a ledger shard.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardCapacityConfig {
    /// Unique shard identifier.
    pub shard_id: u32,
    /// Maximum event capacity allocated to this shard.
    pub max_capacity_events: u64,
    /// Warning watermark in basis points (`1..critical_bps`).
    pub warning_bps: u32,
    /// Critical watermark in basis points (`warning_bps + 1..=10_000`).
    pub critical_bps: u32,
    /// Whether emergency capacity freeze is active on this shard.
    pub emergency_frozen: bool,
    /// Address of the last authorized principal to update this configuration.
    pub updated_by: Address,
    /// Ledger timestamp of the last configuration update.
    pub updated_at: u64,
}

/// Utilization telemetry snapshot recorded for a shard.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardTelemetrySample {
    /// Target shard identifier.
    pub shard_id: u32,
    /// Current number of stored events in the shard.
    pub used_events: u64,
    /// Observed event ingestion velocity (events per hour).
    pub growth_rate_per_hour: u64,
    /// Computed utilization in basis points (`(used_events * 10_000) / max_capacity_events`).
    pub utilization_bps: u32,
    /// Operator or higher-privileged principal that submitted the sample.
    pub recorded_by: Address,
    /// Ledger timestamp when the sample was recorded.
    pub timestamp: u64,
    /// Optional alert ID triggered by this telemetry sample (`u32::MAX` if no threshold breached).
    pub triggered_alert_id: u32,
}

/// Deterministic capacity forecast for a ledger shard.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityForecast {
    /// Target shard identifier.
    pub shard_id: u32,
    /// Forecast horizon in hours.
    pub horizon_hours: u64,
    /// Projected total events at the end of `horizon_hours`.
    pub projected_events: u64,
    /// Projected utilization in basis points at the end of `horizon_hours`.
    pub projected_utilization_bps: u32,
    /// Estimated hours until 100% shard capacity exhaustion (`u64::MAX` if growth rate is zero).
    pub estimated_hours_to_exhaustion: u64,
    /// Recommended additional shards to provision to stay below `warning_bps`.
    pub recommended_additional_shards: u32,
    /// Principal that generated the forecast.
    pub generated_by: Address,
    /// Ledger timestamp when the forecast was computed.
    pub timestamp: u64,
    /// SHA-256 state diff digest committed with this forecast.
    pub state_diff_digest: BytesN<32>,
}

/// Severity level of a shard capacity threshold alert.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AlertSeverity {
    /// Utilization reached or exceeded `warning_bps`.
    Warning = 1,
    /// Utilization reached or exceeded `critical_bps`.
    Critical = 2,
}

/// Lifecycle state of a shard capacity threshold alert.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AlertStatus {
    /// Alert is newly triggered and awaiting operator acknowledgement.
    Open = 1,
    /// Alert has been acknowledged by an operator or higher role.
    Acknowledged = 2,
    /// Alert has been formally resolved by an auditor or admin.
    Resolved = 3,
}

/// Threshold breach alert generated when shard utilization crosses configured watermarks.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdAlert {
    /// Sequential alert identifier (0-based).
    pub alert_id: u32,
    /// Shard that breached its threshold.
    pub shard_id: u32,
    /// Severity level (`Warning` or `Critical`).
    pub severity: AlertSeverity,
    /// Lifecycle status (`Open`, `Acknowledged`, `Resolved`).
    pub status: AlertStatus,
    /// Utilization in basis points at the moment of breach.
    pub utilization_bps: u32,
    /// Principal whose telemetry submission or action last updated the alert.
    pub updated_by: Address,
    /// Ledger timestamp when the alert was last updated.
    pub updated_at: u64,
    /// Optional 32-byte resolution evidence hash (all-zeros until resolved).
    pub resolution_digest: BytesN<32>,
}

/// Configure or update capacity thresholds for `shard_id`.
///
/// Requires [`Permission::ConfigureShardThreshold`] (minimum [` crate::rbac::Role::CapacityPlanner`]).
pub fn configure_shard_threshold(
    env: &Env,
    caller: &Address,
    shard_id: u32,
    max_capacity_events: u64,
    warning_bps: u32,
    critical_bps: u32,
) -> Result<ShardCapacityConfig, RbacError> {
    let op = symbol_short!("cfg_shrd");
    let existing = env
        .storage()
        .instance()
        .get::<_, ShardCapacityConfig>(&CapacityDataKey::ShardConfig(shard_id));
    let pre_state = encode_config_state(env, &existing);

    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::ConfigureShardThreshold,
        &pre_state,
    )?;

    let timestamp = env.ledger().timestamp();

    if max_capacity_events == 0
        || warning_bps == 0
        || warning_bps >= critical_bps
        || critical_bps > MAX_BPS
    {
        let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
        record_audit_event(
            env,
            caller,
            op,
            Permission::ConfigureShardThreshold.minimum_role(),
            Some(caller_role),
            false,
            RbacError::InvalidThresholdConfig as u32,
            digest,
        );
        return Err(RbacError::InvalidThresholdConfig);
    }

    let emergency_frozen = existing.map(|c| c.emergency_frozen).unwrap_or(false);
    let config = ShardCapacityConfig {
        shard_id,
        max_capacity_events,
        warning_bps,
        critical_bps,
        emergency_frozen,
        updated_by: caller.clone(),
        updated_at: timestamp,
    };

    env.storage()
        .instance()
        .set(&CapacityDataKey::ShardConfig(shard_id), &config);

    let post_state = encode_config_state(env, &Some(config.clone()));
    let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &post_state);

    record_audit_event(
        env,
        caller,
        op,
        Permission::ConfigureShardThreshold.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(config)
}

/// Record a shard utilization telemetry sample and automatically trigger a [`ThresholdAlert`]
/// if `warning_bps` or `critical_bps` is reached.
///
/// Requires [`Permission::RecordShardTelemetry`] (minimum [`crate::rbac::Role::Operator`]).
pub fn record_shard_utilization(
    env: &Env,
    caller: &Address,
    shard_id: u32,
    used_events: u64,
    growth_rate_per_hour: u64,
) -> Result<ShardTelemetrySample, RbacError> {
    let op = symbol_short!("rec_util");
    let prev_sample = env
        .storage()
        .instance()
        .get::<_, ShardTelemetrySample>(&CapacityDataKey::ShardTelemetry(shard_id));
    let pre_state = encode_telemetry_state(env, &prev_sample);

    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::RecordShardTelemetry,
        &pre_state,
    )?;

    let timestamp = env.ledger().timestamp();

    let config = match env
        .storage()
        .instance()
        .get::<_, ShardCapacityConfig>(&CapacityDataKey::ShardConfig(shard_id))
    {
        Some(cfg) => cfg,
        None => {
            let digest =
                compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
            record_audit_event(
                env,
                caller,
                op,
                Permission::RecordShardTelemetry.minimum_role(),
                Some(caller_role),
                false,
                RbacError::ShardNotFound as u32,
                digest,
            );
            return Err(RbacError::ShardNotFound);
        }
    };

    let utilization_bps =
        ((used_events.saturating_mul(MAX_BPS as u64)) / config.max_capacity_events) as u32;

    let mut triggered_alert_id = u32::MAX;
    if utilization_bps >= config.warning_bps {
        let severity = if utilization_bps >= config.critical_bps {
            AlertSeverity::Critical
        } else {
            AlertSeverity::Warning
        };
        let alert_id: u32 = env
            .storage()
            .instance()
            .get(&CapacityDataKey::AlertCount)
            .unwrap_or(0);
        let alert = ThresholdAlert {
            alert_id,
            shard_id,
            severity,
            status: AlertStatus::Open,
            utilization_bps,
            updated_by: caller.clone(),
            updated_at: timestamp,
            resolution_digest: BytesN::from_array(env, &[0u8; 32]),
        };
        env.storage()
            .instance()
            .set(&CapacityDataKey::AlertEntry(alert_id), &alert);
        env.storage()
            .instance()
            .set(&CapacityDataKey::AlertCount, &(alert_id + 1));
        triggered_alert_id = alert_id;
    }

    let sample = ShardTelemetrySample {
        shard_id,
        used_events,
        growth_rate_per_hour,
        utilization_bps,
        recorded_by: caller.clone(),
        timestamp,
        triggered_alert_id,
    };

    env.storage()
        .instance()
        .set(&CapacityDataKey::ShardTelemetry(shard_id), &sample);

    let post_state = encode_telemetry_state(env, &Some(sample.clone()));
    let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &post_state);

    record_audit_event(
        env,
        caller,
        op,
        Permission::RecordShardTelemetry.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(sample)
}

/// Generate and store a deterministic shard capacity forecast over `horizon_hours`.
///
/// Requires [`Permission::GenerateForecast`] (minimum [`crate::rbac::Role::CapacityPlanner`]).
pub fn generate_capacity_forecast(
    env: &Env,
    caller: &Address,
    shard_id: u32,
    horizon_hours: u64,
) -> Result<CapacityForecast, RbacError> {
    let op = symbol_short!("gen_fcst");
    let prev_forecast = env
        .storage()
        .instance()
        .get::<_, CapacityForecast>(&CapacityDataKey::ShardForecast(shard_id));
    let pre_state = encode_forecast_state(env, &prev_forecast);

    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::GenerateForecast,
        &pre_state,
    )?;

    let timestamp = env.ledger().timestamp();

    if horizon_hours == 0 {
        let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
        record_audit_event(
            env,
            caller,
            op,
            Permission::GenerateForecast.minimum_role(),
            Some(caller_role),
            false,
            RbacError::InvalidForecastParameters as u32,
            digest,
        );
        return Err(RbacError::InvalidForecastParameters);
    }

    let config = match env
        .storage()
        .instance()
        .get::<_, ShardCapacityConfig>(&CapacityDataKey::ShardConfig(shard_id))
    {
        Some(cfg) => cfg,
        None => {
            let digest =
                compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
            record_audit_event(
                env,
                caller,
                op,
                Permission::GenerateForecast.minimum_role(),
                Some(caller_role),
                false,
                RbacError::ShardNotFound as u32,
                digest,
            );
            return Err(RbacError::ShardNotFound);
        }
    };

    let telemetry = env
        .storage()
        .instance()
        .get::<_, ShardTelemetrySample>(&CapacityDataKey::ShardTelemetry(shard_id))
        .unwrap_or(ShardTelemetrySample {
            shard_id,
            used_events: 0,
            growth_rate_per_hour: 0,
            utilization_bps: 0,
            recorded_by: caller.clone(),
            timestamp,
            triggered_alert_id: u32::MAX,
        });

    let delta = telemetry.growth_rate_per_hour.saturating_mul(horizon_hours);
    let projected_events = telemetry.used_events.saturating_add(delta);
    let projected_utilization_bps =
        ((projected_events.saturating_mul(MAX_BPS as u64)) / config.max_capacity_events) as u32;

    let estimated_hours_to_exhaustion = if telemetry.growth_rate_per_hour == 0 {
        u64::MAX
    } else if telemetry.used_events >= config.max_capacity_events {
        0
    } else {
        let remaining = config.max_capacity_events - telemetry.used_events;
        remaining / telemetry.growth_rate_per_hour
    };

    let safe_shard_capacity = (config
        .max_capacity_events
        .saturating_mul(config.warning_bps as u64))
        / (MAX_BPS as u64);
    let recommended_additional_shards =
        if safe_shard_capacity == 0 || projected_events <= safe_shard_capacity {
            0
        } else {
            let excess = projected_events - safe_shard_capacity;
            ((excess + safe_shard_capacity - 1) / safe_shard_capacity) as u32
        };

    let mut post_preview = Bytes::new(env);
    post_preview.append(&u32_le_bytes(env, shard_id));
    post_preview.append(&u64_le_bytes(env, horizon_hours));
    post_preview.append(&u64_le_bytes(env, projected_events));
    post_preview.append(&u32_le_bytes(env, projected_utilization_bps));

    let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &post_preview);

    let forecast = CapacityForecast {
        shard_id,
        horizon_hours,
        projected_events,
        projected_utilization_bps,
        estimated_hours_to_exhaustion,
        recommended_additional_shards,
        generated_by: caller.clone(),
        timestamp,
        state_diff_digest: digest.clone(),
    };

    env.storage()
        .instance()
        .set(&CapacityDataKey::ShardForecast(shard_id), &forecast);

    record_audit_event(
        env,
        caller,
        op,
        Permission::GenerateForecast.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(forecast)
}

/// Acknowledge an active capacity threshold alert (`Open -> Acknowledged`).
///
/// Requires [`Permission::AcknowledgeAlert`] (minimum [`crate::rbac::Role::Operator`]).
pub fn acknowledge_threshold_alert(
    env: &Env,
    caller: &Address,
    alert_id: u32,
) -> Result<ThresholdAlert, RbacError> {
    let op = symbol_short!("ack_alrt");
    let existing = env
        .storage()
        .instance()
        .get::<_, ThresholdAlert>(&CapacityDataKey::AlertEntry(alert_id));
    let pre_state = encode_alert_state(env, &existing);

    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::AcknowledgeAlert,
        &pre_state,
    )?;

    let timestamp = env.ledger().timestamp();

    let mut alert = match existing {
        Some(a) => a,
        None => {
            let digest =
                compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
            record_audit_event(
                env,
                caller,
                op,
                Permission::AcknowledgeAlert.minimum_role(),
                Some(caller_role),
                false,
                RbacError::AlertNotFound as u32,
                digest,
            );
            return Err(RbacError::AlertNotFound);
        }
    };

    alert.status = AlertStatus::Acknowledged;
    alert.updated_by = caller.clone();
    alert.updated_at = timestamp;

    env.storage()
        .instance()
        .set(&CapacityDataKey::AlertEntry(alert_id), &alert);

    let post_state = encode_alert_state(env, &Some(alert.clone()));
    let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &post_state);

    record_audit_event(
        env,
        caller,
        op,
        Permission::AcknowledgeAlert.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(alert)
}

/// Formally resolve a capacity threshold alert with a tamper-evident resolution digest (`-> Resolved`).
///
/// Requires [`Permission::ResolveAlert`] (minimum [`crate::rbac::Role::Auditor`]).
pub fn resolve_threshold_alert(
    env: &Env,
    caller: &Address,
    alert_id: u32,
    resolution_digest: BytesN<32>,
) -> Result<ThresholdAlert, RbacError> {
    let op = symbol_short!("res_alrt");
    let existing = env
        .storage()
        .instance()
        .get::<_, ThresholdAlert>(&CapacityDataKey::AlertEntry(alert_id));
    let pre_state = encode_alert_state(env, &existing);

    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::ResolveAlert,
        &pre_state,
    )?;

    let timestamp = env.ledger().timestamp();

    let mut alert = match existing {
        Some(a) => a,
        None => {
            let digest =
                compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
            record_audit_event(
                env,
                caller,
                op,
                Permission::ResolveAlert.minimum_role(),
                Some(caller_role),
                false,
                RbacError::AlertNotFound as u32,
                digest,
            );
            return Err(RbacError::AlertNotFound);
        }
    };

    alert.status = AlertStatus::Resolved;
    alert.updated_by = caller.clone();
    alert.updated_at = timestamp;
    alert.resolution_digest = resolution_digest;

    env.storage()
        .instance()
        .set(&CapacityDataKey::AlertEntry(alert_id), &alert);

    let post_state = encode_alert_state(env, &Some(alert.clone()));
    let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &post_state);

    record_audit_event(
        env,
        caller,
        op,
        Permission::ResolveAlert.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(alert)
}

/// Override a shard's capacity ceiling and emergency freeze flag during an audit or incident response.
///
/// Requires [`Permission::OverrideCapacityPolicy`] (minimum [`crate::rbac::Role::Auditor`]).
pub fn override_shard_capacity_policy(
    env: &Env,
    caller: &Address,
    shard_id: u32,
    new_max_capacity_events: u64,
    emergency_frozen: bool,
) -> Result<ShardCapacityConfig, RbacError> {
    let op = symbol_short!("ovr_pol");
    let existing = env
        .storage()
        .instance()
        .get::<_, ShardCapacityConfig>(&CapacityDataKey::ShardConfig(shard_id));
    let pre_state = encode_config_state(env, &existing);

    let caller_role = authorize_mutation(
        env,
        caller,
        op.clone(),
        Permission::OverrideCapacityPolicy,
        &pre_state,
    )?;

    let timestamp = env.ledger().timestamp();

    if new_max_capacity_events == 0 {
        let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
        record_audit_event(
            env,
            caller,
            op,
            Permission::OverrideCapacityPolicy.minimum_role(),
            Some(caller_role),
            false,
            RbacError::InvalidThresholdConfig as u32,
            digest,
        );
        return Err(RbacError::InvalidThresholdConfig);
    }

    let mut config = match existing {
        Some(cfg) => cfg,
        None => {
            let digest =
                compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &pre_state);
            record_audit_event(
                env,
                caller,
                op,
                Permission::OverrideCapacityPolicy.minimum_role(),
                Some(caller_role),
                false,
                RbacError::ShardNotFound as u32,
                digest,
            );
            return Err(RbacError::ShardNotFound);
        }
    };

    config.max_capacity_events = new_max_capacity_events;
    config.emergency_frozen = emergency_frozen;
    config.updated_by = caller.clone();
    config.updated_at = timestamp;

    env.storage()
        .instance()
        .set(&CapacityDataKey::ShardConfig(shard_id), &config);

    let post_state = encode_config_state(env, &Some(config.clone()));
    let digest = compute_state_diff_digest(env, caller, &op, timestamp, &pre_state, &post_state);

    record_audit_event(
        env,
        caller,
        op,
        Permission::OverrideCapacityPolicy.minimum_role(),
        Some(caller_role),
        true,
        0,
        digest,
    );

    Ok(config)
}

/// Read the current [`ShardCapacityConfig`] for `shard_id`.
pub fn get_shard_config(env: &Env, shard_id: u32) -> Option<ShardCapacityConfig> {
    env.storage()
        .instance()
        .get(&CapacityDataKey::ShardConfig(shard_id))
}

/// Read the latest [`ShardTelemetrySample`] for `shard_id`.
pub fn get_shard_telemetry(env: &Env, shard_id: u32) -> Option<ShardTelemetrySample> {
    env.storage()
        .instance()
        .get(&CapacityDataKey::ShardTelemetry(shard_id))
}

/// Read the latest [`CapacityForecast`] for `shard_id`.
pub fn get_latest_forecast(env: &Env, shard_id: u32) -> Option<CapacityForecast> {
    env.storage()
        .instance()
        .get(&CapacityDataKey::ShardForecast(shard_id))
}

/// Read a [`ThresholdAlert`] by `alert_id`.
pub fn get_threshold_alert(env: &Env, alert_id: u32) -> Option<ThresholdAlert> {
    env.storage()
        .instance()
        .get(&CapacityDataKey::AlertEntry(alert_id))
}

/// Return the total count of generated [`ThresholdAlert`] records.
pub fn total_threshold_alerts(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&CapacityDataKey::AlertCount)
        .unwrap_or(0)
}

fn encode_config_state(env: &Env, cfg: &Option<ShardCapacityConfig>) -> Bytes {
    match cfg {
        None => Bytes::from_slice(env, b"cfg:none"),
        Some(c) => {
            let mut b = Bytes::new(env);
            b.append(&u32_le_bytes(env, c.shard_id));
            b.append(&u64_le_bytes(env, c.max_capacity_events));
            b.append(&u32_le_bytes(env, c.warning_bps));
            b.append(&u32_le_bytes(env, c.critical_bps));
            b.append(&u32_le_bytes(env, if c.emergency_frozen { 1 } else { 0 }));
            b
        }
    }
}

fn encode_telemetry_state(env: &Env, sample: &Option<ShardTelemetrySample>) -> Bytes {
    match sample {
        None => Bytes::from_slice(env, b"telemetry:none"),
        Some(s) => {
            let mut b = Bytes::new(env);
            b.append(&u32_le_bytes(env, s.shard_id));
            b.append(&u64_le_bytes(env, s.used_events));
            b.append(&u64_le_bytes(env, s.growth_rate_per_hour));
            b.append(&u32_le_bytes(env, s.utilization_bps));
            b.append(&u32_le_bytes(env, s.triggered_alert_id));
            b
        }
    }
}

fn encode_forecast_state(env: &Env, forecast: &Option<CapacityForecast>) -> Bytes {
    match forecast {
        None => Bytes::from_slice(env, b"forecast:none"),
        Some(f) => {
            let mut b = Bytes::new(env);
            b.append(&u32_le_bytes(env, f.shard_id));
            b.append(&u64_le_bytes(env, f.horizon_hours));
            b.append(&u64_le_bytes(env, f.projected_events));
            b.append(&u32_le_bytes(env, f.projected_utilization_bps));
            b
        }
    }
}

fn encode_alert_state(env: &Env, alert: &Option<ThresholdAlert>) -> Bytes {
    match alert {
        None => Bytes::from_slice(env, b"alert:none"),
        Some(a) => {
            let mut b = Bytes::new(env);
            b.append(&u32_le_bytes(env, a.alert_id));
            b.append(&u32_le_bytes(env, a.shard_id));
            b.append(&u32_le_bytes(env, a.severity as u32));
            b.append(&u32_le_bytes(env, a.status as u32));
            b.append(&u32_le_bytes(env, a.utilization_bps));
            b.append(&a.resolution_digest.clone().into());
            b
        }
    }
}
