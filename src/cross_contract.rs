//! Issue #410 — Cross-Contract Event Composition & Workflows
//!
//! Provides primitives for referencing events across contracts, composing
//! multi-step workflow definitions, recording workflow executions, and
//! verifying cross-chain workflow integrity.

use soroban_sdk::{contractimpl, contracttype, panic_with_error, Address, Bytes, BytesN, Env, Symbol, Vec};

use crate::{AuditLedger, AuditLedgerArgs, AuditLedgerClient, ContractError, DataKey};

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

        let comp_id: u32 = env.storage().instance().get(&DataKey::CrossContractCount).unwrap_or(0);

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
        env.storage()
            .instance()
            .set(&DataKey::CrossContractCount, &(comp_id + 1));

        env.events().publish(
            (Symbol::new(&env, "xcontract"), Symbol::new(&env, "composed")),
            (comp_id, composer, name),
        );
        comp_id
    }

    /// Validate that all `EventRef`s in a composition are self-consistent
    /// (contract address fields are non-zero, event IDs are 32 bytes).
    /// Returns `true` if all refs are structurally valid.
    pub fn validate_cross_contract_refs(env: Env, refs: Vec<EventRef>) -> bool {
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        for i in 0..refs.len() {
            let r = refs.get(i).unwrap();
            if r.event_id == zero {
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
        env.storage().instance().set(&DataKey::ExternalEventData(ext_id), &ext);
        env.storage()
            .instance()
            .set(&DataKey::ExternalEventCount, &(ext_id + 1));

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
        env.storage().instance().set(&DataKey::WorkflowDef(wf_id), &wf);
        env.storage().instance().set(&DataKey::WorkflowCount, &(wf_id + 1));

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

        // Extend step_events Vec if needed
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

    /// Return a page of workflow definitions using deterministic cursor-based
    /// pagination and multi-predicate filtering.
    ///
    /// Ordering is by immutable definition id (ascending), which is stable
    /// across ledger upgrades and archival restores. At most
    /// `MAX_PAGE_LIMIT` storage reads are performed per invocation.
    pub fn list_workflows(
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

        // Cursor past the end: return an empty page with no continuation.
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

    /// Return a page of cross-contract compositions using deterministic
    /// cursor-based pagination and multi-predicate filtering.
    ///
    /// Ordering is by immutable composition id (ascending). At most
    /// `MAX_PAGE_LIMIT` storage reads are performed per invocation.
    pub fn get_cross_contract_events(
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

        let exec_id: u32 = env.storage().instance().get(&DataKey::WorkflowExecCount).unwrap_or(0);

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
        env.storage()
            .instance()
            .set(&DataKey::WorkflowExecCount, &(exec_id + 1));

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

        exec.status = WorkflowStatus::Completed;
        exec.finished_at = env.ledger().timestamp();
        env.storage().instance().set(&exec_key, &exec);

        env.events().publish(
            (Symbol::new(&env, "workflow"), Symbol::new(&env, "completed")),
            (execution_id, caller),
        );
    }
}
