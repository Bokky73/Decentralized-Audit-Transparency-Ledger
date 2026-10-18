//! Issue #410 — Cross-Contract Event Composition & Workflows
//!
//! Provides primitives for referencing events across contracts, composing
//! multi-step workflow definitions, recording workflow executions, and
//! verifying cross-chain workflow integrity.
//!
//! ## Deterministic bounds & overflow safety (issue #864)
//!
//! Every user-supplied payload (`refs`, steps, `external_id`, `metadata`,
//! pagination) is capped by [`MAX_REFS`], [`MAX_WORKFLOW_STEPS`],
//! [`MAX_EXTERNAL_ID_LEN`], [`MAX_METADATA_LEN`] and [`MAX_PAGE_SIZE`].
//! Workflow `step_index` writes are bounds-checked against the referenced
//! definition, so `record_workflow_step` can never grow
//! `step_events` unbounded (the previous `while len <= step_index` push
//! loop would trap on a `u32::MAX` index). Every integer counter is
//! incremented through [`bump_u32_counter`], which fails with a stable
//! error instead of an arithmetic trap, and every `EventRef` /
//! `ExternalEvent` payload is validated against zero-value identifiers
//! before it reaches storage.

use soroban_sdk::{
    contracterror, contractimpl, contracttype, panic_with_error, Address, Bytes, BytesN, Env,
    Symbol, Vec,
};

use crate::{AuditLedger, ContractError, DataKey};

// Deterministic bounds (issue #864)

/// Maximum number of event references in one composition.
pub const MAX_REFS: u32 = 64;
/// Maximum number of steps in one workflow definition.
pub const MAX_WORKFLOW_STEPS: u32 = 64;
/// Maximum length of free-form `metadata` payloads.
pub const MAX_METADATA_LEN: u32 = 1024;
/// Maximum length of an external event identifier.
pub const MAX_EXTERNAL_ID_LEN: u32 = 256;
/// Maximum number of records returned by paginated queries.
pub const MAX_PAGE_SIZE: u32 = 100;

// Cross-contract error codes (issue #864)

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum XContractError {
    /// A bounded payload exceeded its deterministic limit.
    LimitExceeded = 9700,
    /// A payload failed structural validation (empty / malformed).
    InvalidInput = 9701,
    /// An auto-increment counter would overflow u32.
    CounterOverflow = 9702,
    /// An event reference carries a zero-valued identifier.
    InvalidEventRef = 9703,
    /// A workflow step index is outside the definition's step range.
    StepIndexOutOfBounds = 9704,
    /// A workflow step failed structural validation (index order, delays).
    InvalidWorkflowStep = 9705,
}

/// Increment an instance-storage counter with overflow safety (#864).
fn bump_u32_counter(env: &Env, key: &DataKey) -> u32 {
    let cur: u32 = env.storage().instance().get(key).unwrap_or(0);
    let next = match cur.checked_add(1) {
        Some(next) => next,
        None => panic_with_error!(env, XContractError::CounterOverflow),
    };
    env.storage().instance().set(key, &next);
    next
}

/// Enforce a deterministic upper bound on a `Bytes` payload length (#864).
fn require_bounded_bytes(env: &Env, value: &Bytes, max: u32) {
    if value.len() > max {
        panic_with_error!(env, XContractError::InvalidInput);
    }
}

/// Reject empty `Bytes` payloads whose emptiness is structurally invalid (#864).
fn require_non_empty_bytes(env: &Env, value: &Bytes) {
    if value.is_empty() {
        panic_with_error!(env, XContractError::InvalidInput);
    }
}

/// Validate a cross-contract / external event reference identity (#864).
fn require_valid_event_ref(env: &Env, event_ref: &EventRef) {
    let zero = BytesN::from_array(env, &[0u8; 32]);
    if event_ref.event_id == zero || event_ref.event_hash == zero {
        panic_with_error!(env, XContractError::InvalidEventRef);
    }
}

// Cross-contract event reference

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

// AuditLedger implementation

#[contractimpl]
impl AuditLedger {
    // Cross-contract event composition

    /// Log an event that references events from other contract instances.
    /// Records a `CrossContractEvent` composition, then logs the composition
    /// as an ordinary audit event on this ledger.
    pub fn log_event_with_refs(env: Env, composer: Address, name: Symbol, refs: Vec<EventRef>, metadata: Bytes) -> u32 {
        composer.require_auth();

        // Deterministic payload bounds (#864): a malformed or hostile
        // composition can never blow the instance-storage entry limit or the
        // compute budget via an unbounded refs vector.
        if refs.len() > MAX_REFS {
            panic_with_error!(&env, XContractError::LimitExceeded);
        }
        require_bounded_bytes(&env, &metadata, MAX_METADATA_LEN);
        for i in 0..refs.len() {
            let event_ref = refs.get(i).unwrap();
            require_valid_event_ref(&env, event_ref);
        }

        let comp_id: u32 = bump_u32_counter(&env, &DataKey::CrossContractCount);

        let composition = CrossContractEvent {
            id: comp_id,
            name: name.clone(),
            refs,
            composer: composer.clone(),
            composed_at: env.ledger().timestamp(),
            metadata,
        };
        env.storage()
            .instance()
            .set(&DataKey::CrossContractEvent(comp_id), &composition);

        env.events().publish(
            (Symbol::new(&env, "xcontract"), Symbol::new(&env, "composed")),
            (comp_id, composer, name),
        );
        comp_id
    }

    /// Validate that all `EventRef`s in a composition are self-consistent
    /// (identifiers are non-zero, payload hashes are non-zero).
    /// Returns `true` if all refs are structurally valid.
    pub fn validate_cross_contract_refs(env: Env, refs: Vec<EventRef>) -> bool {
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        if refs.len() > MAX_REFS {
            return false;
        }
        for i in 0..refs.len() {
            let r = refs.get(i).unwrap();
            if r.event_id == zero || r.event_hash == zero {
                return false;
            }
        }
        true
    }

    /// Register an anchor record for an event from an external system.
    pub fn register_external_event(
        env: Env,
        submitter: Address,
        system_id: Symbol,
        external_id: Bytes,
        payload_hash: BytesN<32>,
        metadata: Bytes,
    ) -> u32 {
        submitter.require_auth();

        // Deterministic payload bounds (#864).
        require_non_empty_bytes(&env, &external_id);
        require_bounded_bytes(&env, &external_id, MAX_EXTERNAL_ID_LEN);
        require_bounded_bytes(&env, &metadata, MAX_METADATA_LEN);
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        if payload_hash == zero {
            panic_with_error!(&env, XContractError::InvalidEventRef);
        }

        let ext_id: u32 = bump_u32_counter(&env, &DataKey::ExternalEventCount);

        let ext = ExternalEvent {
            id: ext_id,
            system_id: system_id.clone(),
            external_id,
            payload_hash,
            anchored_at: env.ledger().timestamp(),
            submitter: submitter.clone(),
            metadata,
        };
        env.storage().instance().set(&DataKey::ExternalEventData(ext_id), &ext);

        env.events().publish(
            (Symbol::new(&env, "xcontract"), Symbol::new(&env, "ext_anchored")),
            (ext_id, submitter, system_id),
        );
        ext_id
    }

    // Workflow definitions

    /// Define a new workflow (owner-only).
    pub fn define_workflow(env: Env, caller: Address, name: Symbol, steps: Vec<WorkflowStep>) -> u32 {
        caller.require_auth();
        Self::require_owner_or_multisig(&env, &caller);

        // Deterministic payload bounds (#864).
        if steps.is_empty() {
            panic_with_error!(&env, XContractError::InvalidInput);
        }
        if steps.len() > MAX_WORKFLOW_STEPS {
            panic_with_error!(&env, XContractError::LimitExceeded);
        }
        for i in 0..steps.len() {
            let step = steps.get(i).unwrap();
            // `WorkflowExecution.step_events` is indexed positionally (see
            // `verify_cross_chain_workflow` and `start_workflow`), so a
            // definition whose steps are out of order is malformed.
            if step.index != i {
                panic_with_error!(&env, XContractError::InvalidWorkflowStep);
            }
            // `max_delay_secs == 0` means "no limit"; otherwise the window
            // must be consistent.
            if step.max_delay_secs != 0 && step.max_delay_secs < step.min_delay_secs {
                panic_with_error!(&env, XContractError::InvalidWorkflowStep);
            }
        }

        let wf_id: u32 = bump_u32_counter(&env, &DataKey::WorkflowCount);

        let wf = WorkflowDefinition {
            id: wf_id,
            name: name.clone(),
            version: 1,
            steps,
            created_by: caller.clone(),
            updated_at: env.ledger().timestamp(),
            active: true,
        };
        env.storage().instance().set(&DataKey::WorkflowDef(wf_id), &wf);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "defined")),
            (wf_id, caller, name),
        );
        wf_id
    }

    /// Record a step in a workflow execution.
    pub fn record_workflow_step(env: Env, caller: Address, execution_id: u32, step_index: u32, event_ref: EventRef) {
        caller.require_auth();

        let exec_key = DataKey::WorkflowExec(execution_id);
        let mut exec: WorkflowExecution = env
            .storage()
            .instance()
            .get(&exec_key)
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::EventDoesNotExist));

        if exec.status != WorkflowStatus::InProgress {
            panic_with_error!(&env, ContractError::WorkflowNotInProgress);
        }

        // Bounds-check the step index against the referenced definition so
        // the extension loop below can never grow `step_events` beyond the
        // definition's step count (issue #864: a `u32::MAX` index previously
        // trapped on an unbounded `push_back` loop).
        let wf: WorkflowDefinition = env
            .storage()
            .instance()
            .get(&DataKey::WorkflowDef(exec.definition_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::EventDoesNotExist));
        if step_index >= wf.steps.len() {
            panic_with_error!(&env, XContractError::StepIndexOutOfBounds);
        }

        // Validate the referenced event identity (#864).
        require_valid_event_ref(&env, &event_ref);

        // Extend step_events Vec if needed (bounded by the check above).
        while exec.step_events.len() <= step_index {
            exec.step_events.push_back(None);
        }
        exec.step_events.set(step_index, Some(event_ref));
        env.storage().instance().set(&exec_key, &exec);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "step_recorded")),
            (execution_id, step_index, caller),
        );
    }

    /// Verify all mandatory steps of a cross-chain workflow are complete and
    /// in the correct order.  Returns `true` if the workflow is valid.
    pub fn verify_cross_chain_workflow(env: Env, execution_id: u32) -> bool {
        let exec_key = DataKey::WorkflowExec(execution_id);
        let exec: WorkflowExecution = match env.storage().instance().get(&exec_key) {
            Some(e) => e,
            None => return false,
        };
        let wf: WorkflowDefinition = match env.storage().instance().get(&DataKey::WorkflowDef(exec.definition_id)) {
            Some(w) => w,
            None => return false,
        };

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
        }
        true
    }

    /// Return all workflow execution IDs.
    pub fn get_workflow_events(env: Env, execution_id: u32) -> Option<WorkflowExecution> {
        env.storage().instance().get(&DataKey::WorkflowExec(execution_id))
    }

    /// Return all workflow definitions (paginated by count starting at 0).
    pub fn list_workflows(env: Env, start: u32, limit: u32) -> Vec<WorkflowDefinition> {
        // Deterministic page bound (#864).
        let limit = limit.min(MAX_PAGE_SIZE);
        let total: u32 = env.storage().instance().get(&DataKey::WorkflowCount).unwrap_or(0);
        let mut out: Vec<WorkflowDefinition> = Vec::new(&env);
        let end = (start.saturating_add(limit)).min(total);
        for i in start..end {
            if let Some(wf) = env
                .storage()
                .instance()
                .get::<_, WorkflowDefinition>(&DataKey::WorkflowDef(i))
            {
                out.push_back(wf);
            }
        }
        out
    }

    /// Return cross-contract compositions (paginated).
    pub fn get_cross_contract_events(env: Env, start: u32, limit: u32) -> Vec<CrossContractEvent> {
        // Deterministic page bound (#864).
        let limit = limit.min(MAX_PAGE_SIZE);
        let total: u32 = env.storage().instance().get(&DataKey::CrossContractCount).unwrap_or(0);
        let mut out: Vec<CrossContractEvent> = Vec::new(&env);
        let end = (start.saturating_add(limit)).min(total);
        for i in start..end {
            if let Some(ev) = env
                .storage()
                .instance()
                .get::<_, CrossContractEvent>(&DataKey::CrossContractEvent(i))
            {
                out.push_back(ev);
            }
        }
        out
    }

    /// Start a new workflow execution instance.
    pub fn start_workflow(env: Env, initiator: Address, definition_id: u32, metadata: Bytes) -> u32 {
        initiator.require_auth();

        let wf: WorkflowDefinition = env
            .storage()
            .instance()
            .get(&DataKey::WorkflowDef(definition_id))
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::EventDoesNotExist));

        if !wf.active {
            panic_with_error!(&env, ContractError::WorkflowNotActive);
        }

        // Deterministic payload bounds (#864).
        require_bounded_bytes(&env, &metadata, MAX_METADATA_LEN);

        let exec_id: u32 = bump_u32_counter(&env, &DataKey::WorkflowExecCount);

        let step_count = wf.steps.len();
        let mut step_events: Vec<Option<EventRef>> = Vec::new(&env);
        for _ in 0..step_count {
            step_events.push_back(None);
        }

        let exec = WorkflowExecution {
            id: exec_id,
            definition_id,
            definition_version: wf.version,
            step_events,
            status: WorkflowStatus::InProgress,
            initiator: initiator.clone(),
            started_at: env.ledger().timestamp(),
            finished_at: 0,
            metadata,
        };
        env.storage().instance().set(&DataKey::WorkflowExec(exec_id), &exec);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "started")),
            (exec_id, initiator, definition_id),
        );
        exec_id
    }

    /// Complete a workflow execution.  Owner-only.
    pub fn complete_workflow(env: Env, caller: Address, execution_id: u32) {
        caller.require_auth();
        Self::require_owner_or_multisig(&env, &caller);

        let exec_key = DataKey::WorkflowExec(execution_id);
        let mut exec: WorkflowExecution = env
            .storage()
            .instance()
            .get(&exec_key)
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::EventDoesNotExist));

        // Idempotency guard (#864): a completed, failed or cancelled
        // execution can never be re-completed (or have its finish
        // timestamp rewritten after the fact).
        if exec.status != WorkflowStatus::InProgress {
            panic_with_error!(&env, ContractError::WorkflowNotInProgress);
        }

        exec.status = WorkflowStatus::Completed;
        exec.finished_at = env.ledger().timestamp();
        env.storage().instance().set(&exec_key, &exec);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "completed")),
            (execution_id, caller),
        );
    }

    /// Verify an execution satisfies its definition's mandatory steps.
    pub fn verify_cross_chain_workflow(env: Env, execution_id: u32) -> bool {
        let exec_key = DataKey::WorkflowExec(execution_id);
        let exec: WorkflowExecution = match env.storage().instance().get(&exec_key) {
            Some(e) => e,
            None => return false,
        };
        let wf: WorkflowDefinition = match env.storage().instance().get(&DataKey::WorkflowDef(exec.definition_id)) {
            Some(w) => w,
            None => return false,
        };

        let zero = BytesN::from_array(&env, &[0u8; 32]);
        for i in 0..wf.steps.len() {
            let step = wf.steps.get(i).unwrap();
            if step.optional {
                continue;
            }
            if i >= exec.step_events.len() {
                return false;
            }
            match exec.step_events.get(i).unwrap() {
                // Deterministic identity validation (#864): a recorded
                // reference carrying zero-valued identifiers makes the
                // verification fail outright, even if the slot is filled.
                Some(r) => {
                    if r.event_id == zero || r.event_hash == zero {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}
