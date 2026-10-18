//! Issue #410 — Cross-Contract Event Composition & Workflows
//! Issue #865 — Granular RBAC role gating & tamper-evident audit-trail events
//! Issue #866 — Automated Soroban storage TTL bump policy & rent optimization
//!
//! Provides primitives for referencing events across contracts, composing
//! multi-step workflow definitions, recording workflow executions, and
//! verifying cross-chain workflow integrity.
//!
//! ## Storage tier & rent model (issue #866)
//!
//! Bulky archival records (compositions, external anchors, workflow
//! definitions, workflow executions) live in `persistent` storage so they can
//! be TTL-managed per key, instead of inflating the contract instance blob
//! that is deserialized on *every* invocation. Counters and the TTL policy
//! stay in the cheap `instance` tier. Every read/write of an archival key
//! applies the automated bump policy (`extend_ttl` with a config threshold /
//! target), so archival audit state never lapses while idle keys cost rent
//! only for their last extension.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contractimpl, contracttype, panic_with_error, Address, Bytes, BytesN, Env, Symbol, Vec};

use crate::rbac::{RbacError, RbacManager, Role as RbacRole};
use crate::{AuditLedger, AuditLedgerArgs, AuditLedgerClient, ContractError, DataKey, Role};

// Pagination primitives

/// Hard cap on the number of items returned by any single paginated query.
pub const MAX_PAGE_LIMIT: u32 = 100;

/// Opaque cursor token over a stable, deterministic ordering key.
///
/// The token encodes the last-seen ordering key (a monotonically increasing
/// id) so that traversal is stable across ledger upgrades and archival
/// restores: ordering never depends on storage iteration order, only on the
/// immutable id assigned at write time.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageCursor {
    /// Last-seen ordering key. The next page starts strictly after this id.
    pub after_id: u32,
}

/// Requested page size. Clamped to `MAX_PAGE_LIMIT` at query time.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageLimit {
    pub limit: u32,
}

impl PageLimit {
    /// Return the effective page size, enforcing the hard cap.
    pub fn effective(&self) -> u32 {
        if self.limit == 0 {
            MAX_PAGE_LIMIT
        } else if self.limit > MAX_PAGE_LIMIT {
            MAX_PAGE_LIMIT
        } else {
            self.limit
        }
    }
}

/// A single page of results plus the cursor for the following page.
///
/// `next_cursor` is `None` when the traversal is exhausted (including when the
/// supplied cursor is past the end of the collection).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<PageCursor>,
}

/// Multi-predicate filter applied to paginated collection queries.
///
/// All fields are optional; `None` means "no constraint on this predicate".
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryFilter {
    /// Inclusive lower bound on the record's ledger timestamp.
    pub min_timestamp: Option<u64>,
    /// Inclusive upper bound on the record's ledger timestamp.
    pub max_timestamp: Option<u64>,
    /// Restrict to a specific workflow status.
    pub status: Option<WorkflowStatus>,
    /// Restrict to records submitted/initiated by this address.
    pub submitter: Option<Address>,
}

impl QueryFilter {
    /// An unconstrained filter matching every record.
    pub fn none() -> Self {
        QueryFilter {
            min_timestamp: None,
            max_timestamp: None,
            status: None,
            submitter: None,
        }
    }

    /// Returns `true` if `timestamp` satisfies the configured range.
    pub fn matches_timestamp(&self, timestamp: u64) -> bool {
        if let Some(min) = self.min_timestamp {
            if timestamp < min {
                return false;
            }
        }
        if let Some(max) = self.max_timestamp {
            if timestamp > max {
                return false;
            }
        }
        true
    }

    /// Returns `true` if `status` satisfies the configured status predicate.
    pub fn matches_status(&self, status: WorkflowStatus) -> bool {
        match &self.status {
            Some(want) => *want == status,
            None => true,
        }
    }

    /// Returns `true` if `submitter` satisfies the configured address predicate.
    pub fn matches_submitter(&self, submitter: &Address) -> bool {
        match &self.submitter {
            Some(want) => want == submitter,
            None => true,
        }
    }
}

// ── TTL bump policy constants (issue #866) ─────────────────────────────────

/// Automated bump triggers when remaining TTL drops below this ledger count
/// (~10k ledgers, mirrors `cbdc_interop::TTL_BUMP_THRESHOLD_LEDGERS`).
pub const XCT_TTL_DEFAULT_THRESHOLD_LEDGERS: u32 = 10_000;

/// Automated bump extends the TTL to this many ledgers from the current
/// ledger sequence (~100k ledgers, mirrors `cbdc_interop::DEFAULT_TTL_EXTEND_LEDGERS`).
pub const XCT_TTL_DEFAULT_TARGET_LEDGERS: u32 = 100_000;

//──────────────────────────────────────────────────────────────────────────────
// Cross-contract event reference
//──────────────────────────────────────────────────────────────────────────────

/// A reference to an event that may live on a different contract instance.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    /// Address of the AuditLedger contract that owns the event.
    pub contract: Address,
    /// Content-addressed event ID (SHA-256 hash).
    pub event_id: BytesN<32>,
    /// Sequential index of the event within that contract's log.
    pub index: u32,
    /// Snapshot of the event's hash at the time of reference creation.
    pub event_hash: BytesN<32>,
}

// Cross-contract composed event

/// An event that is composed from multiple events across one or more contracts.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossContractEvent {
    /// Auto-incrementing composition ID.
    pub id: u32,
    /// Human-readable composition name (e.g., `"payment_cleared"`).
    pub name: Symbol,
    /// Ordered list of event references that make up this composition.
    pub refs: Vec<EventRef>,
    /// Address that created this composition.
    pub composer: Address,
    /// Ledger timestamp of composition.
    pub composed_at: u64,
    /// Optional metadata (JSON description, correlation ID, etc.).
    pub metadata: Bytes,
}

// External event reference (from off-chain / other chains)

/// A reference to an event on an external system (off-chain or another
/// blockchain), anchored on this ledger for audit purposes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalEvent {
    /// Auto-incrementing external-event ID.
    pub id: u32,
    /// Identifier of the external system (e.g., `"ethereum"`, `"offchain-erpv2"`).
    pub system_id: Symbol,
    /// Opaque external event identifier as bytes (tx hash, record ID, etc.).
    pub external_id: Bytes,
    /// SHA-256 of the external event payload for integrity pinning.
    pub payload_hash: BytesN<32>,
    /// Ledger timestamp when this anchor was recorded.
    pub anchored_at: u64,
    /// Address that submitted this anchor.
    pub submitter: Address,
    /// Optional metadata.
    pub metadata: Bytes,
}

// Workflow definition

/// A step within a workflow definition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowStep {
    /// 0-based step index.
    pub index: u32,
    /// Step name (e.g., `"approve"`, `"ship"`, `"settle"`).
    pub name: Symbol,
    /// Expected event type for this step.
    pub expected_event_type: Symbol,
    /// Whether this step is optional (can be skipped).
    pub optional: bool,
    /// Minimum number of seconds after the previous step before this one is valid.
    pub min_delay_secs: u64,
    /// Maximum number of seconds after the previous step (0 = no limit).
    pub max_delay_secs: u64,
}

/// A named, versioned workflow definition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowDefinition {
    /// Auto-incrementing workflow definition ID.
    pub id: u32,
    /// Unique name for this workflow.
    pub name: Symbol,
    /// Version number (start at 1, increment on updates).
    pub version: u32,
    /// Ordered list of steps.
    pub steps: Vec<WorkflowStep>,
    /// Address that created this definition.
    pub created_by: Address,
    /// Ledger timestamp of creation / last update.
    pub updated_at: u64,
    /// Whether this workflow definition is active (false = archived).
    pub active: bool,
}

// Workflow execution

/// Current execution status of a workflow instance.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowStatus {
    InProgress = 0,
    Completed = 1,
    Failed = 2,
    Cancelled = 3,
}

/// A running or completed workflow execution instance.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowExecution {
    /// Auto-incrementing execution ID.
    pub id: u32,
    /// ID of the workflow definition being executed.
    pub definition_id: u32,
    /// Version of the definition used for this execution.
    pub definition_version: u32,
    /// Event references recorded for each completed step (index = step index).
    pub step_events: Vec<Option<EventRef>>,
    /// Ledger timestamp when each step was recorded (0 = not yet recorded).
    /// Enables `min_delay_secs` / `max_delay_secs` enforcement and gives the
    /// audit trail a tamper-evident timeline anchor per step.
    pub step_anchors: Vec<u64>,
    /// Current status.
    pub status: WorkflowStatus,
    /// Address that initiated the execution.
    pub initiator: Address,
    /// Ledger timestamp when the execution started.
    pub started_at: u64,
    /// Ledger timestamp when the execution completed / failed (0 = still running).
    pub finished_at: u64,
    /// Optional correlation metadata.
    pub metadata: Bytes,
}

// Automated TTL policy types (issue #866)

/// Storage-rent policy for cross-contract archival keys.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XctTtlPolicy {
    /// Bump when remaining TTL is at or below this many ledgers.
    pub bump_threshold: u32,
    /// Extend the TTL to this many ledgers from the current sequence.
    pub bump_target: u32,
}

/// Monotonic accounting of automated TTL bump operations (#866).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XctRentStats {
    /// Total automated bumps performed on cross-contract persistent keys.
    pub bumps: u32,
    /// Ledger sequence of the most recent bump (0 = never bumped).
    pub last_bump_ledger: u32,
}

// AuditLedger implementation

#[contractimpl]
impl AuditLedger {
    // ── Storage & rent helpers (issue #866) ────────────────────────────────

    /// Current TTL bump policy (default applies when unset).
    fn xct_ttl_policy(env: &Env) -> XctTtlPolicy {
        env.storage()
            .instance()
            .get(&DataKey::XctTtlPolicy)
            .unwrap_or(XctTtlPolicy {
                bump_threshold: XCT_TTL_DEFAULT_THRESHOLD_LEDGERS,
                bump_target: XCT_TTL_DEFAULT_TARGET_LEDGERS,
            })
    }

    /// Automated TTL bump for a cross-contract archival key, recorded in
    /// monotonic bump statistics. Safe to call on live keys only.
    fn xct_bump(env: &Env, key: &DataKey) {
        let policy = Self::xct_ttl_policy(env);
        env.storage().persistent().extend_ttl(key, policy.bump_threshold, policy.bump_target);

        let stats: XctRentStats = env
            .storage()
            .instance()
            .get(&DataKey::XctBumpStats)
            .unwrap_or(XctRentStats { bumps: 0, last_bump_ledger: 0 });
        env.storage().instance().set(
            &DataKey::XctBumpStats,
            &XctRentStats {
                bumps: stats.bumps + 1,
                last_bump_ledger: env.ledger().sequence(),
            },
        );
    }

    /// Read a composition (persistent tier) and apply the bump-on-read policy.
    fn xct_read_composition(env: &Env, id: u32) -> Option<CrossContractEvent> {
        let key = DataKey::CrossContractEvent(id);
        let value: Option<CrossContractEvent> = env.storage().persistent().get(&key);
        if value.is_some() {
            Self::xct_bump(env, &key);
        }
        value
    }

    /// Read an external anchor (persistent tier) and apply the bump-on-read policy.
    fn xct_read_external(env: &Env, id: u32) -> Option<ExternalEvent> {
        let key = DataKey::ExternalEventData(id);
        let value: Option<ExternalEvent> = env.storage().persistent().get(&key);
        if value.is_some() {
            Self::xct_bump(env, &key);
        }
        value
    }

    /// Read a workflow definition (persistent tier) and apply the bump policy.
    fn xct_read_definition(env: &Env, id: u32) -> Option<WorkflowDefinition> {
        let key = DataKey::WorkflowDef(id);
        let value: Option<WorkflowDefinition> = env.storage().persistent().get(&key);
        if value.is_some() {
            Self::xct_bump(env, &key);
        }
        value
    }

    /// Read a workflow execution (persistent tier) and apply the bump policy.
    fn xct_read_execution(env: &Env, id: u32) -> Option<WorkflowExecution> {
        let key = DataKey::WorkflowExec(id);
        let value: Option<WorkflowExecution> = env.storage().persistent().get(&key);
        if value.is_some() {
            Self::xct_bump(env, &key);
        }
        value
    }

    // ── Fine-grained RBAC gating (issue #865) ─────────────────────────────

    /// Fine-grained gate for cross-contract mutation paths.
    ///
    /// Layering:
    /// 1. The persistent RBAC store ([`crate::rbac`]) — when the DID holds an
    ///    explicit role there, the granular privilege ladder decides. DIDs
    ///    suspended in the RBAC store are rejected with the stable
    ///    [`RbacError::SubmitterSuspended`] code.
    /// 2. Legacy behaviour otherwise: inline RBAC (no-op when disabled) or
    ///    owner/multisig for admin-tier operations, fully backward-compatible.
    fn require_xct_role(env: &Env, caller: &Address, min_legacy: Role, min_rbac: RbacRole) {
        if RbacManager::is_suspended(env, caller) {
            panic_with_error!(env, RbacError::SubmitterSuspended);
        }
        if RbacManager::get_role(env, caller).is_some() {
            if !RbacManager::has_role_min(env, caller, min_rbac) {
                panic_with_error!(env, RbacError::InsufficientRole);
            }
            return;
        }
        Self::require_role_min(env, caller, min_legacy);
    }

    /// Fine-grained admin-tier gate for cross-contract governance paths
    /// ([`RbacRole::Admin`] in the RBAC store; owner/multisig fallback).
    fn require_xct_admin(env: &Env, caller: &Address) {
        if RbacManager::get_role(env, caller).is_some() {
            if !RbacManager::has_role_min(env, caller, RbacRole::Admin) {
                panic_with_error!(env, RbacError::InsufficientRole);
            }
            return;
        }
        Self::require_owner_or_multisig(env, caller);
    }

    // ── Tamper-evident digest helpers (issue #865) ────────────────────────

    /// Canonical SHA-256 digest over a composition's full payload. The digest
    /// is deterministic: identical content (name, refs, composer, timestamps,
    /// metadata) always produces the identical digest, so tampering with any
    /// stored field is detectable by re-deriving and comparing.
    fn composition_digest(env: &Env, composition: &CrossContractEvent) -> BytesN<32> {
        let mut preimage = Bytes::new(env);
        preimage.append(&Bytes::from_slice(env, b"xct_composed"));
        preimage.append(&composition.name.to_xdr(env));
        for i in 0..composition.refs.len() {
            let r = composition.refs.get(i).unwrap();
            preimage.append(&r.event_id.to_bytes());
            preimage.append(&r.event_hash.to_bytes());
            preimage.append(&Bytes::from_array(env, &r.index.to_le_bytes()));
        }
        preimage.append(&composition.composer.to_xdr(env));
        preimage.append(&Bytes::from_array(env, &composition.composed_at.to_le_bytes()));
        preimage.append(&composition.metadata);
        preimage.append(&Bytes::from_array(env, &composition.id.to_le_bytes()));
        env.crypto().sha256(&preimage).into()
    }

    /// Canonical SHA-256 digest over an external event anchor payload.
    fn external_digest(env: &Env, anchor: &ExternalEvent) -> BytesN<32> {
        let mut preimage = Bytes::new(env);
        preimage.append(&Bytes::from_slice(env, b"xct_ext_anchored"));
        preimage.append(&anchor.system_id.to_xdr(env));
        preimage.append(&anchor.external_id);
        preimage.append(&anchor.payload_hash.to_bytes());
        preimage.append(&Bytes::from_array(env, &anchor.anchored_at.to_le_bytes()));
        preimage.append(&anchor.submitter.to_xdr(env));
        preimage.append(&anchor.metadata);
        preimage.append(&Bytes::from_array(env, &anchor.id.to_le_bytes()));
        env.crypto().sha256(&preimage).into()
    }

    // Cross-contract event composition

    /// Log an event that references events from other contract instances.
    /// Records a `CrossContractEvent` composition (persistent, TTL-bumped
    /// archival tier), stores its tamper-evident digest, then publishes a
    /// structured audit-trail event carrying the digest.
    pub fn log_event_with_refs(env: Env, composer: Address, name: Symbol, refs: Vec<EventRef>, metadata: Bytes) -> u32 {
        composer.require_auth();
        Self::require_xct_role(&env, &composer, Role::Submitter, RbacRole::Submitter);

        let comp_id: u32 = env.storage().instance().get(&DataKey::CrossContractCount).unwrap_or(0);

        let composition = CrossContractEvent {
            id: comp_id,
            name: name.clone(),
            refs,
            composer: composer.clone(),
            composed_at: env.ledger().timestamp(),
            metadata,
        };

        let digest: BytesN<32> = Self::composition_digest(&env, &composition);

        let comp_key = DataKey::CrossContractEvent(comp_id);
        env.storage().persistent().set(&comp_key, &composition);
        Self::xct_bump(&env, &comp_key);
        env.storage().instance().set(&DataKey::CrossContractCount, &(comp_id + 1));

        let digest_key = DataKey::XctCompositionHash(comp_id);
        env.storage().persistent().set(&digest_key, &digest);
        Self::xct_bump(&env, &digest_key);

        env.events().publish(
            (Symbol::new(&env, "xcontract"), Symbol::new(&env, "composed")),
            (comp_id, composer, name, digest),
        );
        comp_id
    }

    /// Validate that all `EventRef`s in a composition are self-consistent
    /// (event IDs are 32 bytes) and non-redundant. Returns `true` if all
    /// refs are structurally valid.
    pub fn validate_cross_contract_refs(env: Env, refs: Vec<EventRef>) -> bool {
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        let mut seen: Vec<BytesN<32>> = Vec::new(&env);
        for i in 0..refs.len() {
            let r = refs.get(i).unwrap();
            if r.event_id == zero {
                return false;
            }
            if seen.contains(&r.event_id) {
                return false;
            }
            seen.push_back(r.event_id);
        }
        true
    }

    /// Register an anchor record for an event from an external system.
    /// Stores the anchor in the persistent archival tier with the automated
    /// TTL bump and a tamper-evident digest audit event.
    pub fn register_external_event(
        env: Env,
        submitter: Address,
        system_id: Symbol,
        external_id: Bytes,
        payload_hash: BytesN<32>,
        metadata: Bytes,
    ) -> u32 {
        submitter.require_auth();
        Self::require_xct_role(&env, &submitter, Role::Submitter, RbacRole::Submitter);

        let ext_id: u32 = env.storage().instance().get(&DataKey::ExternalEventCount).unwrap_or(0);

        let ext = ExternalEvent {
            id: ext_id,
            system_id: system_id.clone(),
            external_id,
            payload_hash,
            anchored_at: env.ledger().timestamp(),
            submitter: submitter.clone(),
            metadata,
        };

        let digest: BytesN<32> = Self::external_digest(&env, &ext);

        let ext_key = DataKey::ExternalEventData(ext_id);
        env.storage().persistent().set(&ext_key, &ext);
        Self::xct_bump(&env, &ext_key);
        env.storage()
            .instance()
            .set(&DataKey::ExternalEventCount, &(ext_id + 1));

        env.events().publish(
            (Symbol::new(&env, "xcontract"), Symbol::new(&env, "ext_anchored")),
            (ext_id, submitter, system_id, digest),
        );
        ext_id
    }

    // Workflow definitions

    /// Define a new workflow (admin tier: RBAC-store Admin, else owner/multisig).
    pub fn define_workflow(env: Env, caller: Address, name: Symbol, steps: Vec<WorkflowStep>) -> u32 {
        caller.require_auth();
        Self::require_xct_admin(&env, &caller);

        let wf_id: u32 = env.storage().instance().get(&DataKey::WorkflowCount).unwrap_or(0);

        let wf = WorkflowDefinition {
            id: wf_id,
            name: name.clone(),
            version: 1,
            steps,
            created_by: caller.clone(),
            updated_at: env.ledger().timestamp(),
            active: true,
        };

        let wf_key = DataKey::WorkflowDef(wf_id);
        env.storage().persistent().set(&wf_key, &wf);
        Self::xct_bump(&env, &wf_key);
        env.storage().instance().set(&DataKey::WorkflowCount, &(wf_id + 1));

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "defined")),
            (wf_id, caller, name),
        );
        wf_id
    }

    /// Archive (soft-retire) a workflow definition. Archived definitions
    /// cannot start new executions but remain readable for the audit trail.
    pub fn archive_workflow(env: Env, caller: Address, definition_id: u32) {
        caller.require_auth();
        Self::require_xct_admin(&env, &caller);

        let wf_key = DataKey::WorkflowDef(definition_id);
        let mut wf: WorkflowDefinition = match env.storage().persistent().get(&wf_key) {
            Some(w) => w,
            None => panic_with_error!(env, ContractError::EventDoesNotExist),
        };

        wf.active = false;
        wf.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&wf_key, &wf);
        Self::xct_bump(&env, &wf_key);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "archived")),
            (definition_id, caller),
        );
    }

    /// Record a step in a workflow execution.
    ///
    /// Enforces:
    /// - fine-grained RBAC (submitter tier or explicit RBAC-store role),
    /// - `step_index` bounds against the definition's step count, and
    /// - the execution is still `InProgress`.
    ///
    /// Re-recording a step is allowed until completion (idempotent rewrite of
    /// that index), which makes reordering/loading of step events safe. The
    /// recording timestamp is anchored tamper-evidently for later
    /// `min/max_delay_secs` verification.
    pub fn record_workflow_step(env: Env, caller: Address, execution_id: u32, step_index: u32, event_ref: EventRef) {
        caller.require_auth();
        Self::require_xct_role(&env, &caller, Role::Submitter, RbacRole::Submitter);

        let exec_key = DataKey::WorkflowExec(execution_id);
        let mut exec: WorkflowExecution = match env.storage().persistent().get(&exec_key) {
            Some(e) => e,
            None => panic_with_error!(env, ContractError::EventDoesNotExist),
        };

        if exec.status != WorkflowStatus::InProgress {
            panic_with_error!(&env, ContractError::WorkflowNotInProgress);
        }

        let def_key = DataKey::WorkflowDef(exec.definition_id);
        let wf: WorkflowDefinition = match env.storage().persistent().get(&def_key) {
            Some(w) => w,
            None => panic_with_error!(env, ContractError::EventDoesNotExist),
        };

        if step_index >= wf.steps.len() {
            panic_with_error!(&env, ContractError::WorkflowStepOutOfRange);
        }

        // Extend step_events / step_anchors Vecs if needed, then write slot.
        while exec.step_events.len() <= step_index {
            exec.step_events.push_back(None);
        }
        while exec.step_anchors.len() <= step_index {
            exec.step_anchors.push_back(0);
        }
        exec.step_events.set(step_index, Some(event_ref.clone()));
        exec.step_anchors.set(step_index, env.ledger().timestamp());
        env.storage().persistent().set(&exec_key, &exec);
        Self::xct_bump(&env, &exec_key);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "step_recorded")),
            (execution_id, step_index, caller, event_ref.event_hash),
        );
    }

    /// Verify all mandatory steps of a cross-chain workflow are complete, in
    /// the correct order, and respect each step's `min/max_delay_secs` timing
    /// window relative to the previously recorded mandatory step (or the
    /// execution start). Returns `true` if the workflow is valid.
    pub fn verify_cross_chain_workflow(env: Env, execution_id: u32) -> bool {
        let exec_key = DataKey::WorkflowExec(execution_id);
        let exec: WorkflowExecution = match env.storage().persistent().get(&exec_key) {
            Some(e) => e,
            None => return false,
        };

        let def_key = DataKey::WorkflowDef(exec.definition_id);
        let wf: WorkflowDefinition = match env.storage().persistent().get(&def_key) {
            Some(w) => w,
            None => return false,
        };

        // Completions freeze step content; that is a stable verifiable state.
        let mut prev_anchor: Option<u64> = None;
        for i in 0..wf.steps.len() {
            let step = wf.steps.get(i).unwrap();
            if step.optional {
                continue;
            }
            if i >= exec.step_events.len() {
                return false;
            }
            if exec.step_events.get(i).unwrap().is_none() {
                return false;
            }

            // Timing-window enforcement: the recorded anchor must fall within
            // [prev + min_delay, prev + max_delay] relative to the prior
            // mandatory step (or execution start for the first step).
            let anchor = exec.step_anchors.get(i).unwrap_or(0u64);
            let base = prev_anchor.unwrap_or(exec.started_at);
            let elapsed = anchor.saturating_sub(base);
            if elapsed < step.min_delay_secs {
                return false;
            }
            if step.max_delay_secs > 0 && elapsed > step.max_delay_secs {
                return false;
            }
            prev_anchor = Some(anchor);
        }
        true
    }

    /// Return a workflow execution instance (persistent, bump-on-read).
    pub fn get_workflow_events(env: Env, execution_id: u32) -> Option<WorkflowExecution> {
        Self::xct_read_execution(&env, execution_id)
    }

    /// Return all workflow definitions (paginated by count starting at 0).
    /// Each definition read applies the automated TTL bump policy.
    pub fn list_workflows(env: Env, start: u32, limit: u32) -> Vec<WorkflowDefinition> {
        let total: u32 = env.storage().instance().get(&DataKey::WorkflowCount).unwrap_or(0);
        let mut out: Vec<WorkflowDefinition> = Vec::new(&env);
        let end = (start.saturating_add(limit)).min(total);
        for i in start..end {
            if let Some(wf) = Self::xct_read_definition(&env, i) {
                out.push_back(wf);
            }
        }
        out
    }

    /// Return a page of workflow definitions using deterministic cursor-based
    /// pagination and multi-predicate filtering.
    pub fn list_workflows_cursor(
        env: Env,
        cursor: Option<PageCursor>,
        limit: PageLimit,
        filter: QueryFilter,
    ) -> Page<WorkflowDefinition> {
        let total: u32 = env.storage().instance().get(&DataKey::WorkflowCount).unwrap_or(0);
        let page_size = limit.effective();
        let start = match cursor {
            Some(c) => c.after_id.saturating_add(1),
            None => 0,
        };

        let mut items: Vec<WorkflowDefinition> = Vec::new(&env);
        let mut next_cursor: Option<PageCursor> = None;

        if start >= total {
            return Page { items, next_cursor };
        }

        let mut scanned: u32 = 0;
        let mut i = start;
        while i < total && scanned < page_size {
            scanned += 1;
            if let Some(wf) = env
                .storage()
                .instance()
                .get::<_, WorkflowDefinition>(&DataKey::WorkflowDef(i))
            {
                if filter.matches_timestamp(wf.updated_at)
                    && filter.matches_submitter(&wf.created_by)
                {
                    items.push_back(wf);
                }
            }
            i += 1;
        }

        if i < total {
            next_cursor = Some(PageCursor { after_id: i - 1 });
        }

        Page { items, next_cursor }
    }

    /// Return cross-contract compositions (paginated). Each composition read
    /// applies the automated TTL bump policy.
    pub fn get_cross_contract_events(env: Env, start: u32, limit: u32) -> Vec<CrossContractEvent> {
        let total: u32 = env.storage().instance().get(&DataKey::CrossContractCount).unwrap_or(0);
        let mut out: Vec<CrossContractEvent> = Vec::new(&env);
        let end = (start.saturating_add(limit)).min(total);
        for i in start..end {
            if let Some(ev) = Self::xct_read_composition(&env, i) {
                out.push_back(ev);
            }
        }
        out
    }

    /// Return a page of cross-contract compositions using deterministic
    /// cursor-based pagination and multi-predicate filtering.
    pub fn get_cross_contract_events_cursor(
        env: Env,
        cursor: Option<PageCursor>,
        limit: PageLimit,
        filter: QueryFilter,
    ) -> Page<CrossContractEvent> {
        let total: u32 = env.storage().instance().get(&DataKey::CrossContractCount).unwrap_or(0);
        let page_size = limit.effective();
        let start = match cursor {
            Some(c) => c.after_id.saturating_add(1),
            None => 0,
        };

        let mut items: Vec<CrossContractEvent> = Vec::new(&env);
        let mut next_cursor: Option<PageCursor> = None;

        if start >= total {
            return Page { items, next_cursor };
        }

        let mut scanned: u32 = 0;
        let mut i = start;
        while i < total && scanned < page_size {
            scanned += 1;
            if let Some(ev) = env
                .storage()
                .instance()
                .get::<_, CrossContractEvent>(&DataKey::CrossContractEvent(i))
            {
                if filter.matches_timestamp(ev.composed_at)
                    && filter.matches_submitter(&ev.composer)
                {
                    items.push_back(ev);
                }
            }
            i += 1;
        }

        if i < total {
            next_cursor = Some(PageCursor { after_id: i - 1 });
        }

        Page { items, next_cursor }
    }

    /// Return a page of workflow executions using deterministic cursor-based
    /// pagination and multi-predicate filtering.
    ///
    /// Ordering is by immutable execution id (ascending). At most
    /// `MAX_PAGE_LIMIT` storage reads are performed per invocation.
    pub fn list_workflow_executions(
        env: Env,
        cursor: Option<PageCursor>,
        limit: PageLimit,
        filter: QueryFilter,
    ) -> Page<WorkflowExecution> {
        let total: u32 = env.storage().instance().get(&DataKey::WorkflowExecCount).unwrap_or(0);
        let page_size = limit.effective();
        let start = match cursor {
            Some(c) => c.after_id.saturating_add(1),
            None => 0,
        };

        let mut items: Vec<WorkflowExecution> = Vec::new(&env);
        let mut next_cursor: Option<PageCursor> = None;

        // Cursor past the end: return an empty page with no continuation.
        if start >= total {
            return Page { items, next_cursor };
        }

        let mut scanned: u32 = 0;
        let mut i = start;
        while i < total && scanned < page_size {
            scanned += 1;
            if let Some(exec) = env
                .storage()
                .instance()
                .get::<_, WorkflowExecution>(&DataKey::WorkflowExec(i))
            {
                if filter.matches_timestamp(exec.started_at)
                    && filter.matches_status(exec.status)
                    && filter.matches_submitter(&exec.initiator)
                {
                    items.push_back(exec);
                }
            }
            i += 1;
        }

        if i < total {
            next_cursor = Some(PageCursor { after_id: i - 1 });
        }

        Page { items, next_cursor }
    }

    /// Return a page of external event anchors using deterministic
    /// cursor-based pagination and multi-predicate filtering.
    ///
    /// Ordering is by immutable external-event id (ascending). At most
    /// `MAX_PAGE_LIMIT` storage reads are performed per invocation.
    pub fn list_external_events(
        env: Env,
        cursor: Option<PageCursor>,
        limit: PageLimit,
        filter: QueryFilter,
    ) -> Page<ExternalEvent> {
        let total: u32 = env.storage().instance().get(&DataKey::ExternalEventCount).unwrap_or(0);
        let page_size = limit.effective();
        let start = match cursor {
            Some(c) => c.after_id.saturating_add(1),
            None => 0,
        };

        let mut items: Vec<ExternalEvent> = Vec::new(&env);
        let mut next_cursor: Option<PageCursor> = None;

        // Cursor past the end: return an empty page with no continuation.
        if start >= total {
            return Page { items, next_cursor };
        }

        let mut scanned: u32 = 0;
        let mut i = start;
        while i < total && scanned < page_size {
            scanned += 1;
            if let Some(ev) = env
                .storage()
                .instance()
                .get::<_, ExternalEvent>(&DataKey::ExternalEventData(i))
            {
                if filter.matches_timestamp(ev.anchored_at)
                    && filter.matches_submitter(&ev.submitter)
                {
                    items.push_back(ev);
                }
            }
            i += 1;
        }

        if i < total {
            next_cursor = Some(PageCursor { after_id: i - 1 });
        }

        Page { items, next_cursor }
    }

    /// Start a new workflow execution instance (submitter tier for RBAC).
    pub fn start_workflow(env: Env, initiator: Address, definition_id: u32, metadata: Bytes) -> u32 {
        initiator.require_auth();
        Self::require_xct_role(&env, &initiator, Role::Submitter, RbacRole::Submitter);

        let def_key = DataKey::WorkflowDef(definition_id);
        let wf: WorkflowDefinition = match env.storage().persistent().get(&def_key) {
            Some(w) => w,
            None => panic_with_error!(env, ContractError::EventDoesNotExist),
        };

        if !wf.active {
            panic_with_error!(&env, ContractError::WorkflowNotActive);
        }

        Self::xct_bump(&env, &def_key);

        let exec_id: u32 = env.storage().instance().get(&DataKey::WorkflowExecCount).unwrap_or(0);

        let step_count = wf.steps.len();
        let mut step_events: Vec<Option<EventRef>> = Vec::new(&env);
        let mut step_anchors: Vec<u64> = Vec::new(&env);
        for _ in 0..step_count {
            step_events.push_back(None);
            step_anchors.push_back(0);
        }

        let exec = WorkflowExecution {
            id: exec_id,
            definition_id,
            definition_version: wf.version,
            step_events,
            step_anchors,
            status: WorkflowStatus::InProgress,
            initiator: initiator.clone(),
            started_at: env.ledger().timestamp(),
            finished_at: 0,
            metadata,
        };

        let exec_key = DataKey::WorkflowExec(exec_id);
        env.storage().persistent().set(&exec_key, &exec);
        Self::xct_bump(&env, &exec_key);
        env.storage()
            .instance()
            .set(&DataKey::WorkflowExecCount, &(exec_id + 1));

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "started")),
            (exec_id, initiator, definition_id),
        );
        exec_id
    }

    /// Complete a workflow execution. Admin tier only (RBAC-store Admin or
    /// legacy owner/multisig).
    pub fn complete_workflow(env: Env, caller: Address, execution_id: u32) {
        caller.require_auth();
        Self::require_xct_admin(&env, &caller);

        let exec_key = DataKey::WorkflowExec(execution_id);
        let mut exec: WorkflowExecution = match env.storage().persistent().get(&exec_key) {
            Some(e) => e,
            None => panic_with_error!(env, ContractError::EventDoesNotExist),
        };

        exec.status = WorkflowStatus::Completed;
        exec.finished_at = env.ledger().timestamp();
        env.storage().persistent().set(&exec_key, &exec);
        Self::xct_bump(&env, &exec_key);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "completed")),
            (execution_id, caller),
        );
    }

    // ── TTL policy & rent accounting entrypoints (issue #866) ─────────────

    /// Configure the automated TTL bump policy for cross-contract archival
    /// keys. Admin tier only. Validates `bump_target >= bump_threshold > 0`.
    pub fn set_xct_ttl_policy(env: Env, caller: Address, bump_threshold: u32, bump_target: u32) {
        caller.require_auth();
        Self::require_xct_admin(&env, &caller);

        if bump_threshold == 0 || bump_target < bump_threshold {
            panic_with_error!(&env, ContractError::InvalidTtlPolicy);
        }

        let old = Self::xct_ttl_policy(&env);
        let policy = XctTtlPolicy {
            bump_threshold,
            bump_target,
        };
        env.storage().instance().set(&DataKey::XctTtlPolicy, &policy);

        env.events().publish(
            (Symbol::new(&env, "xcontract"), Symbol::new(&env, "ttl_policy")),
            (caller, old.bump_threshold, old.bump_target, bump_threshold, bump_target),
        );
    }

    /// Current automated TTL bump policy (default when never configured).
    pub fn get_xct_ttl_policy(env: Env) -> XctTtlPolicy {
        Self::xct_ttl_policy(&env)
    }

    /// Monotonic rent accounting: how many automated TTL bumps have been
    /// performed and when the last one happened.
    pub fn get_xct_rent_stats(env: Env) -> XctRentStats {
        env.storage()
            .instance()
            .get(&DataKey::XctBumpStats)
            .unwrap_or(XctRentStats { bumps: 0, last_bump_ledger: 0 })
    }

    /// Stored tamper-evident digest of a composition, if any.
    pub fn get_composition_digest(env: Env, composition_id: u32) -> Option<BytesN<32>> {
        let key = DataKey::XctCompositionHash(composition_id);
        let digest: Option<BytesN<32>> = env.storage().persistent().get(&key);
        if digest.is_some() {
            Self::xct_bump(&env, &key);
        }
        digest
    }

    /// Re-derive the composition digest from persisted content and compare
    /// with the stored tamper-evident digest. Returns `true` when intact.
    /// Returns `false` if the composition or its digest are missing, or if
    /// any field was tampered with (or the digest itself was replaced).
    pub fn verify_composition_integrity(env: Env, composition_id: u32) -> bool {
        let composition: CrossContractEvent = match env
            .storage()
            .persistent()
            .get(&DataKey::CrossContractEvent(composition_id))
        {
            Some(c) => c,
            None => return false,
        };

        let digest_key = DataKey::XctCompositionHash(composition_id);
        let stored: BytesN<32> = match env.storage().persistent().get(&digest_key) {
            Some(d) => d,
            None => return false,
        };

        let recomputed = Self::composition_digest(&env, &composition);
        recomputed == stored
    }
}
