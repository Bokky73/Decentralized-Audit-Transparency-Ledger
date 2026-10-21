//! # Fine-Grained Role-Based Access Control (RBAC) & Tamper-Evident Audit Trail
//!
//! This module implements hierarchical Role-Based Access Control (`RBAC`), Decentralised Identifier
//! (`DID`) lifecycle enforcement, and structured tamper-evident diagnostic/audit event emission
//! for the Decentralized Audit & Transparency Ledger (Issue #900).
//!
//! ## Role Hierarchy & Precedence
//!
//! Roles are ordered in a strict privilege hierarchy where higher-privilege roles inherit all
//! permissions of lower-privilege roles:
//!
//! ```text
//! Admin (5) > Auditor (4) > CapacityPlanner (3) > Operator (2) > Viewer (1)
//! ```
//!
//! - [`Role::Viewer`] (`1`): Read-only inspection of shard capacity state, forecasts, and alerts.
//! - [`Role::Operator`] (`2`): Record shard utilization telemetry and acknowledge active capacity alerts.
//! - [`Role::CapacityPlanner`] (`3`): Configure shard capacity thresholds, execute/store capacity forecasts,
//!   and calibrate alert policies.
//! - [`Role::Auditor`] (`4`): Resolve or override capacity threshold alerts and conduct compliance reviews.
//! - [`Role::Admin`] (`5`): Full RBAC governance (grant/revoke roles, suspend/reinstate submitter DIDs)
//!   plus implicit authorization for all lower-tier operations. The contract `Owner` holds implicit
//!   [`Role::Admin`] privileges unless explicitly suspended.
//!
//! ## Regulator Compliance Mapping Table
//!
//! | Framework | Control ID | Requirement Summary | Implementation Mechanism |
//! |-----------|------------|---------------------|--------------------------|
//! | **SOC 2** | CC6.1 / CC6.3 | Logical access security & role-based restriction | [`authorize_mutation`] enforces `caller.require_auth()`, role hierarchy checks, and permission bitmasks on every mutating entrypoint. |
//! | **ISO/IEC 27001** | A.9.2.3 / A.9.4.1 | Management of privileged access rights & information access restriction | [`grant_role`], [`revoke_role`], and [`Role::satisfies`] enforce least-privilege access with immediate revocation effect. |
//! | **NIST SP 800-53** | AC-2 / AC-3 / AC-6 | Account management, access enforcement, and least privilege | [`DidStatus`] (`Active`, `Suspended`, `Revoked`) gates submitter DIDs with deterministic [`RbacError`] codes (`1001`..`1009`). |
//! | **NIST SP 800-53** | AU-2 / AU-3 / AU-12 | Event logging, content of audit records, and audit generation | [`RbacAuditEvent`] records `caller`, `submitter_did`, `timestamp`, `operation`, `authorized`, `error_code`, and `state_diff_digest`. |
//! | **EU DORA** | Art. 9 / Art. 11 | ICT protection, capacity monitoring, and anomaly detection | Structured Soroban events (`rbac_audit` and `cap_diag`) emitted on both successful mutations and rejected access attempts. |
//! | **GDPR** | Art. 32 | Security of processing & pseudonymised integrity digests | State mutations commit SHA-256 `state_diff_digest` hashes without exposing raw PII in diagnostic topics. |

use soroban_sdk::{
    bytes, contracterror, contracttype, symbol_short, Address, Bytes, BytesN, Env, Symbol,
};

use crate::DataKey;

/// Stable RBAC and capacity-planning error codes (Issue #900).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RbacError {
    /// Caller has no assigned RBAC role and is not the contract owner.
    UnauthorizedCaller = 1001,
    /// Caller's active role does not satisfy the required role/permission level.
    InsufficientRole = 1002,
    /// Caller address or associated submitter DID is currently suspended.
    SuspendedSubmitterDid = 1003,
    /// Caller's RBAC role was explicitly revoked.
    RevokedRole = 1004,
    /// Provided submitter DID URI is empty or malformed (must start with `did:`).
    InvalidDid = 1005,
    /// Target shard capacity configuration does not exist.
    ShardNotFound = 1006,
    /// Capacity threshold configuration is invalid (e.g. zero max capacity or warning >= critical).
    InvalidThresholdConfig = 1007,
    /// Forecast horizon or telemetry sample window is invalid.
    InvalidForecastParameters = 1008,
    /// Referenced capacity alert ID does not exist.
    AlertNotFound = 1009,
}

/// Hierarchical RBAC roles ordered from lowest privilege (`Viewer`) to highest (`Admin`).
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Role {
    /// Read-only observer role.
    Viewer = 1,
    /// Operational telemetry submitter and alert acknowledger.
    Operator = 2,
    /// Capacity planner authorized to configure thresholds and generate shard forecasts.
    CapacityPlanner = 3,
    /// Compliance auditor authorized to resolve/override alerts and policies.
    Auditor = 4,
    /// Administrative superuser authorized to manage roles, DIDs, and all mutations.
    Admin = 5,
}

impl Role {
    /// Numeric privilege rank used for hierarchy comparisons.
    pub fn rank(&self) -> u32 {
        match self {
            Role::Viewer => 1,
            Role::Operator => 2,
            Role::CapacityPlanner => 3,
            Role::Auditor => 4,
            Role::Admin => 5,
        }
    }

    /// Returns `true` if `self` satisfies `required` under role hierarchy precedence.
    pub fn satisfies(&self, required: Role) -> bool {
        self.rank() >= required.rank()
    }

    /// Returns `true` if `self` grants the specified fine-grained [`Permission`].
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.rank() >= permission.minimum_role().rank()
    }
}

/// Granular operational permissions enforced across capacity planning entrypoints.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Permission {
    /// Read capacity configurations, forecasts, and audit logs.
    ReadCapacityState = 1,
    /// Record shard utilization samples and telemetry snapshots.
    RecordShardTelemetry = 2,
    /// Acknowledge active threshold alerts.
    AcknowledgeAlert = 3,
    /// Create or update shard capacity thresholds.
    ConfigureShardThreshold = 4,
    /// Compute and persist shard capacity forecasts.
    GenerateForecast = 5,
    /// Resolve or override active capacity threshold alerts.
    ResolveAlert = 6,
    /// Rebalance or decommission shard capacity policies.
    OverrideCapacityPolicy = 7,
    /// Grant/revoke RBAC roles and suspend/reinstate submitter DIDs.
    AdministerRbac = 8,
}

impl Permission {
    /// Returns the minimum [`Role`] required to exercise this permission.
    pub fn minimum_role(&self) -> Role {
        match self {
            Permission::ReadCapacityState => Role::Viewer,
            Permission::RecordShardTelemetry => Role::Operator,
            Permission::AcknowledgeAlert => Role::Operator,
            Permission::ConfigureShardThreshold => Role::CapacityPlanner,
            Permission::GenerateForecast => Role::CapacityPlanner,
            Permission::ResolveAlert => Role::Auditor,
            Permission::OverrideCapacityPolicy => Role::Auditor,
            Permission::AdministerRbac => Role::Admin,
        }
    }
}

/// Lifecycle status of a submitter's Decentralised Identifier (DID).
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DidStatus {
    /// Submitter DID is active and eligible for role-gated operations.
    Active = 1,
    /// Submitter DID is temporarily suspended; all mutations are rejected with [`RbacError::SuspendedSubmitterDid`].
    Suspended = 2,
    /// Submitter DID is permanently revoked; all mutations are rejected with [`RbacError::SuspendedSubmitterDid`].
    Revoked = 3,
}

/// Storage keys for RBAC role assignments, DID status, and tamper-evident audit records.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RbacDataKey {
    /// Assigned role for a caller address.
    CallerRole(Address),
    /// Explicit revocation tombstone for a caller address.
    RoleRevoked(Address),
    /// Bound submitter DID URI (`did:...`) for a caller address.
    SubmitterDid(Address),
    /// DID lifecycle status indexed by caller address.
    CallerDidStatus(Address),
    /// DID lifecycle status indexed by raw DID URI bytes.
    DidUriStatus(Bytes),
    /// Sequential count of RBAC audit trail events.
    AuditTrailCount,
    /// Stored tamper-evident RBAC audit event by sequential index.
    AuditTrailEntry(u32),
}

/// Structured tamper-evident audit event emitted on every RBAC check and state mutation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RbacAuditEvent {
    /// Monotonic audit sequence number (0-based).
    pub sequence: u32,
    /// Authenticated caller address.
    pub caller: Address,
    /// Submitter DID URI associated with the caller (or default `did:stellar:unregistered` if unset).
    pub submitter_did: Bytes,
    /// Operation symbol being invoked.
    pub operation: Symbol,
    /// Minimum role required for the operation.
    pub required_role: Role,
    /// Effective role held by the caller (`0` if none/revoked, `1..=5` otherwise).
    pub effective_role_rank: u32,
    /// Whether access was granted (`true`) or rejected (`false`).
    pub authorized: bool,
    /// `0` on success, or the numeric [`RbacError`] code on rejection.
    pub error_code: u32,
    /// Ledger timestamp at the moment of evaluation.
    pub timestamp: u64,
    /// SHA-256 digest over `(caller || submitter_did || operation || timestamp || pre_state_hash || post_state_hash)`.
    pub state_diff_digest: BytesN<32>,
}

/// Validate that a DID URI is non-empty and begins with the standard `"did:"` prefix.
pub fn validate_did(did: &Bytes) -> bool {
    if did.len() < 7 {
        return false;
    }
    did.get(0) == Some(b'd')
        && did.get(1) == Some(b'i')
        && did.get(2) == Some(b'd')
        && did.get(3) == Some(b':')
}

/// Compute a deterministic SHA-256 state diff digest from pre-state bytes, post-state bytes,
/// caller address, operation symbol, and ledger timestamp.
pub fn compute_state_diff_digest(
    env: &Env,
    caller: &Address,
    operation: &Symbol,
    timestamp: u64,
    pre_state: &Bytes,
    post_state: &Bytes,
) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.append(&caller.to_string().to_bytes());
    preimage.append(&u64_le_bytes(env, operation.to_val().get_payload()));
    preimage.append(&u64_le_bytes(env, timestamp));
    let pre_hash: BytesN<32> = env.crypto().sha256(pre_state).into();
    let post_hash: BytesN<32> = env.crypto().sha256(post_state).into();
    preimage.append(&pre_hash.into());
    preimage.append(&post_hash.into());
    env.crypto().sha256(&preimage).into()
}

/// Resolve the effective [`Role`] for `caller`.
///
/// If the caller has an explicitly assigned role in storage, that role is returned.
/// Otherwise, if the caller is the contract `Owner` (and has not had their role revoked),
/// [`Role::Admin`] is returned.
pub fn effective_role(env: &Env, caller: &Address) -> Option<Role> {
    if env
        .storage()
        .instance()
        .get::<_, bool>(&RbacDataKey::RoleRevoked(caller.clone()))
        .unwrap_or(false)
    {
        return None;
    }
    if let Some(role) = env
        .storage()
        .instance()
        .get::<_, Role>(&RbacDataKey::CallerRole(caller.clone()))
    {
        return Some(role);
    }
    if let Some(owner) = env.storage().instance().get::<_, Address>(&DataKey::Owner) {
        if &owner == caller {
            return Some(Role::Admin);
        }
    }
    None
}

/// Retrieve the registered submitter DID for `caller`, or a canonical fallback DID if none was bound.
pub fn get_submitter_did(env: &Env, caller: &Address) -> Bytes {
    env.storage()
        .instance()
        .get::<_, Bytes>(&RbacDataKey::SubmitterDid(caller.clone()))
        .unwrap_or_else(|| Bytes::from_slice(env, b"did:stellar:default"))
}

/// Check whether `caller` or its bound submitter DID is suspended or revoked.
pub fn is_submitter_suspended(env: &Env, caller: &Address) -> bool {
    if let Some(status) = env
        .storage()
        .instance()
        .get::<_, DidStatus>(&RbacDataKey::CallerDidStatus(caller.clone()))
    {
        if status != DidStatus::Active {
            return true;
        }
    }
    if let Some(did) = env
        .storage()
        .instance()
        .get::<_, Bytes>(&RbacDataKey::SubmitterDid(caller.clone()))
    {
        if let Some(uri_status) = env
            .storage()
            .instance()
            .get::<_, DidStatus>(&RbacDataKey::DidUriStatus(did))
        {
            if uri_status != DidStatus::Active {
                return true;
            }
        }
    }
    false
}

/// Emit both a standardized Soroban audit event (`rbac_audit`) and a diagnostic event (`cap_diag`),
/// and persist the [`RbacAuditEvent`] in the contract's tamper-evident audit trail.
#[allow(deprecated)]
#[allow(clippy::too_many_arguments)]
pub fn record_audit_event(
    env: &Env,
    caller: &Address,
    operation: Symbol,
    required_role: Role,
    effective_role_opt: Option<Role>,
    authorized: bool,
    error_code: u32,
    state_diff_digest: BytesN<32>,
) -> RbacAuditEvent {
    let timestamp = env.ledger().timestamp();
    let submitter_did = get_submitter_did(env, caller);
    let effective_role_rank = effective_role_opt.map(|r| r.rank()).unwrap_or(0);

    let seq: u32 = env
        .storage()
        .instance()
        .get(&RbacDataKey::AuditTrailCount)
        .unwrap_or(0);

    let audit_evt = RbacAuditEvent {
        sequence: seq,
        caller: caller.clone(),
        submitter_did: submitter_did.clone(),
        operation: operation.clone(),
        required_role,
        effective_role_rank,
        authorized,
        error_code,
        timestamp,
        state_diff_digest: state_diff_digest.clone(),
    };

    env.storage()
        .persistent()
        .set(&RbacDataKey::AuditTrailEntry(seq), &audit_evt);
    env.storage()
        .instance()
        .set(&RbacDataKey::AuditTrailCount, &(seq + 1));

    // Emit standardized Soroban audit event
    env.events().publish(
        (
            symbol_short!("rbac_aud"),
            operation.clone(),
            caller.clone(),
            authorized,
        ),
        audit_evt.clone(),
    );

    // Emit standardized Soroban diagnostic event with caller, timestamp, and state diff digest
    env.events().publish(
        (symbol_short!("cap_diag"), operation, caller.clone()),
        (timestamp, state_diff_digest, error_code, submitter_did),
    );

    audit_evt
}

/// Verify caller authentication (`caller.require_auth()`), DID suspension status, and required
/// [`Permission`] / [`Role`] hierarchy level.
///
/// On rejection, emits a structured audit/diagnostic event recording the rejected access attempt
/// and returns the stable [`RbacError`] code.
pub fn authorize_mutation(
    env: &Env,
    caller: &Address,
    operation: Symbol,
    permission: Permission,
    pre_state: &Bytes,
) -> Result<Role, RbacError> {
    caller.require_auth();

    let required_role = permission.minimum_role();
    let timestamp = env.ledger().timestamp();

    // 1. Reject suspended or revoked submitter DIDs first
    if is_submitter_suspended(env, caller) {
        let current_role = effective_role(env, caller);
        let digest =
            compute_state_diff_digest(env, caller, &operation, timestamp, pre_state, pre_state);
        record_audit_event(
            env,
            caller,
            operation,
            required_role,
            current_role,
            false,
            RbacError::SuspendedSubmitterDid as u32,
            digest,
        );
        return Err(RbacError::SuspendedSubmitterDid);
    }

    // 2. Reject callers whose role was explicitly revoked
    if env
        .storage()
        .instance()
        .get::<_, bool>(&RbacDataKey::RoleRevoked(caller.clone()))
        .unwrap_or(false)
    {
        let digest =
            compute_state_diff_digest(env, caller, &operation, timestamp, pre_state, pre_state);
        record_audit_event(
            env,
            caller,
            operation,
            required_role,
            None,
            false,
            RbacError::RevokedRole as u32,
            digest,
        );
        return Err(RbacError::RevokedRole);
    }

    // 3. Resolve effective role and enforce hierarchy precedence
    let role = match effective_role(env, caller) {
        Some(r) => r,
        None => {
            let digest =
                compute_state_diff_digest(env, caller, &operation, timestamp, pre_state, pre_state);
            record_audit_event(
                env,
                caller,
                operation,
                required_role,
                None,
                false,
                RbacError::UnauthorizedCaller as u32,
                digest,
            );
            return Err(RbacError::UnauthorizedCaller);
        }
    };

    if !role.has_permission(permission) {
        let digest =
            compute_state_diff_digest(env, caller, &operation, timestamp, pre_state, pre_state);
        record_audit_event(
            env,
            caller,
            operation,
            required_role,
            Some(role),
            false,
            RbacError::InsufficientRole as u32,
            digest,
        );
        return Err(RbacError::InsufficientRole);
    }

    Ok(role)
}

/// Grant an RBAC [`Role`] and bind a validated submitter DID URI to `target`.
/// Requires [`Permission::AdministerRbac`] (`Role::Admin`).
pub fn grant_role(
    env: &Env,
    caller: &Address,
    target: &Address,
    role: Role,
    submitter_did: Bytes,
) -> Result<(), RbacError> {
    let op = symbol_short!("grant_rl");
    let pre = Bytes::from_slice(env, b"rbac:grant:pre");
    let caller_role =
        authorize_mutation(env, caller, op.clone(), Permission::AdministerRbac, &pre)?;

    if !validate_did(&submitter_did) {
        let ts = env.ledger().timestamp();
        let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &pre);
        record_audit_event(
            env,
            caller,
            op,
            Role::Admin,
            Some(caller_role),
            false,
            RbacError::InvalidDid as u32,
            digest,
        );
        return Err(RbacError::InvalidDid);
    }

    env.storage()
        .instance()
        .set(&RbacDataKey::CallerRole(target.clone()), &role);
    env.storage()
        .instance()
        .set(&RbacDataKey::RoleRevoked(target.clone()), &false);
    env.storage()
        .instance()
        .set(&RbacDataKey::SubmitterDid(target.clone()), &submitter_did);
    env.storage().instance().set(
        &RbacDataKey::CallerDidStatus(target.clone()),
        &DidStatus::Active,
    );
    env.storage().instance().set(
        &RbacDataKey::DidUriStatus(submitter_did.clone()),
        &DidStatus::Active,
    );

    let mut post = Bytes::new(env);
    post.append(&target.to_string().to_bytes());
    post.append(&u32_le_bytes(env, role.rank()));
    post.append(&submitter_did);

    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Role::Admin,
        Some(caller_role),
        true,
        0,
        digest,
    );
    Ok(())
}

/// Revoke any assigned RBAC [`Role`] from `target`.
/// Requires [`Permission::AdministerRbac`] (`Role::Admin`).
pub fn revoke_role(env: &Env, caller: &Address, target: &Address) -> Result<(), RbacError> {
    let op = symbol_short!("revok_rl");
    let pre = Bytes::from_slice(env, b"rbac:revoke:pre");
    let caller_role =
        authorize_mutation(env, caller, op.clone(), Permission::AdministerRbac, &pre)?;

    env.storage()
        .instance()
        .remove(&RbacDataKey::CallerRole(target.clone()));
    env.storage()
        .instance()
        .set(&RbacDataKey::RoleRevoked(target.clone()), &true);

    let mut post = Bytes::new(env);
    post.append(&target.to_string().to_bytes());
    post.append(&Bytes::from_slice(env, b":revoked"));

    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Role::Admin,
        Some(caller_role),
        true,
        0,
        digest,
    );
    Ok(())
}

/// Suspend a submitter address and its bound DID URI so all future mutations are rejected with
/// [`RbacError::SuspendedSubmitterDid`].
/// Requires [`Permission::AdministerRbac`] (`Role::Admin`).
pub fn suspend_submitter_did(
    env: &Env,
    caller: &Address,
    target: &Address,
) -> Result<(), RbacError> {
    let op = symbol_short!("susp_did");
    let pre = Bytes::from_slice(env, b"rbac:suspend:pre");
    let caller_role =
        authorize_mutation(env, caller, op.clone(), Permission::AdministerRbac, &pre)?;

    env.storage().instance().set(
        &RbacDataKey::CallerDidStatus(target.clone()),
        &DidStatus::Suspended,
    );
    if let Some(did) = env
        .storage()
        .instance()
        .get::<_, Bytes>(&RbacDataKey::SubmitterDid(target.clone()))
    {
        env.storage()
            .instance()
            .set(&RbacDataKey::DidUriStatus(did), &DidStatus::Suspended);
    }

    let mut post = Bytes::new(env);
    post.append(&target.to_string().to_bytes());
    post.append(&Bytes::from_slice(env, b":suspended"));

    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Role::Admin,
        Some(caller_role),
        true,
        0,
        digest,
    );
    Ok(())
}

/// Reinstate a previously suspended submitter address and its bound DID URI to [`DidStatus::Active`].
/// Requires [`Permission::AdministerRbac`] (`Role::Admin`).
pub fn reinstate_submitter_did(
    env: &Env,
    caller: &Address,
    target: &Address,
) -> Result<(), RbacError> {
    let op = symbol_short!("rein_did");
    let pre = Bytes::from_slice(env, b"rbac:reinstate:pre");
    let caller_role =
        authorize_mutation(env, caller, op.clone(), Permission::AdministerRbac, &pre)?;

    env.storage().instance().set(
        &RbacDataKey::CallerDidStatus(target.clone()),
        &DidStatus::Active,
    );
    if let Some(did) = env
        .storage()
        .instance()
        .get::<_, Bytes>(&RbacDataKey::SubmitterDid(target.clone()))
    {
        env.storage()
            .instance()
            .set(&RbacDataKey::DidUriStatus(did), &DidStatus::Active);
    }

    let mut post = Bytes::new(env);
    post.append(&target.to_string().to_bytes());
    post.append(&Bytes::from_slice(env, b":active"));

    let ts = env.ledger().timestamp();
    let digest = compute_state_diff_digest(env, caller, &op, ts, &pre, &post);
    record_audit_event(
        env,
        caller,
        op,
        Role::Admin,
        Some(caller_role),
        true,
        0,
        digest,
    );
    Ok(())
}

/// Return the total number of recorded RBAC audit trail events.
pub fn audit_trail_count(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&RbacDataKey::AuditTrailCount)
        .unwrap_or(0)
}

/// Retrieve an [`RbacAuditEvent`] by its sequential index.
pub fn get_audit_trail_event(env: &Env, sequence: u32) -> Option<RbacAuditEvent> {
    env.storage()
        .persistent()
        .get(&RbacDataKey::AuditTrailEntry(sequence))
}

pub(crate) fn u32_le_bytes(env: &Env, v: u32) -> Bytes {
    bytes!(
        env,
        [
            (v & 0xff) as u8,
            ((v >> 8) & 0xff) as u8,
            ((v >> 16) & 0xff) as u8,
            ((v >> 24) & 0xff) as u8,
        ]
    )
}

pub(crate) fn u64_le_bytes(env: &Env, v: u64) -> Bytes {
    bytes!(
        env,
        [
            (v & 0xff) as u8,
            ((v >> 8) & 0xff) as u8,
            ((v >> 16) & 0xff) as u8,
            ((v >> 24) & 0xff) as u8,
            ((v >> 32) & 0xff) as u8,
            ((v >> 40) & 0xff) as u8,
            ((v >> 48) & 0xff) as u8,
            ((v >> 56) & 0xff) as u8,
        ]
    )
}
