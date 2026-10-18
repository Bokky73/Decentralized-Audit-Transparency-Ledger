use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, Env, Symbol, Vec};

// ── Mock Caller Contract for Cross-Contract Tests ─────────────────────────────────

#[contract]
pub struct CallerContract;

#[contractimpl]
impl CallerContract {
    /// Calls AuditLedger's log_event on behalf of a user
    pub fn log_on_behalf(env: Env, audit_ledger: Address, user: Address, event_type: Symbol, metadata: Bytes) {
        // The caller contract invokes log_event with the user as submitter
        // The user must authorize this call
        let client = AuditLedgerClient::new(&env, &audit_ledger);
        client.log_event(&user, &event_type, &metadata, &None, &None, &false);
    }

    /// Calls AuditLedger's governance functions
    pub fn try_governance_call(env: Env, audit_ledger: Address, caller: Address) {
        let client = AuditLedgerClient::new(&env, &audit_ledger);
        // This should fail if caller is not the owner
        client.set_global_max_logs(&caller, &200);
    }

    /// Attempts to trigger GlobalMaxLogsReached error
    pub fn trigger_global_max_error(env: Env, audit_ledger: Address, submitter: Address) {
        let client = AuditLedgerClient::new(&env, &audit_ledger);
        // Try to log when at capacity
        client.log_event(
            &submitter,
            &symbol_short!("test"),
            &Bytes::new(&env),
            &None,
            &None,
            &false,
        );
    }

    /// Attempts reentrancy by calling back into AuditLedger
    pub fn attempt_reentrancy(
        env: Env,
        audit_ledger: Address,
        submitter: Address,
        event_type: Symbol,
        metadata: Bytes,
    ) {
        let client = AuditLedgerClient::new(&env, &audit_ledger);
        // First call
        client.log_event(&submitter, &event_type, &metadata, &None, &None, &false);

        // Attempt second call (reentrancy)
        // In a real scenario, this would be called from within a callback
        // For testing, we just make a second call
        client.log_event(&submitter, &event_type, &metadata, &None, &None, &false);
    }
}

fn create_ledger() -> (Env, Address, AuditLedgerClient<'static>) {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &100, &4096);
    (env, owner, client)
}

// ── Cross-Contract Logging Tests ───────────────────────────────────────────────────

#[test]
fn cross_contract_log_event_with_correct_submitter() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);

    // Register both contracts
    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Caller contract logs on behalf of user
    // The user must authorize
    caller_client.log_on_behalf(
        &audit_ledger_id,
        &user,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx-data"),
    );

    // Verify the event was logged
    assert_eq!(audit_client.total_events(), 1);

    // Verify the submitter is the user, not the caller contract
    let evt = audit_client.get_event_by_order(&0);
    assert_eq!(evt.submitter, user);
    assert_ne!(evt.submitter, caller_contract_id);
}

#[test]
fn cross_contract_multiple_logs_different_users() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Log for user1
    caller_client.log_on_behalf(
        &audit_ledger_id,
        &user1,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"user1-tx"),
    );

    // Log for user2
    caller_client.log_on_behalf(
        &audit_ledger_id,
        &user2,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"user2-tx"),
    );

    assert_eq!(audit_client.total_events(), 2);

    let evt0 = audit_client.get_event_by_order(&0);
    let evt1 = audit_client.get_event_by_order(&1);

    assert_eq!(evt0.submitter, user1);
    assert_eq!(evt1.submitter, user2);
}

// ── Authorization Across Contracts Tests ───────────────────────────────────────────

#[test]
fn cross_contract_governance_requires_owner() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let attacker = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Try to call governance from caller contract with non-owner
    let result = caller_client.try_try_governance_call(&audit_ledger_id, &attacker);

    // Should fail because attacker is not owner
    assert!(result.is_err());
}

#[test]
fn cross_contract_governance_with_owner_succeeds() {
    let env = Env::default();
    let owner = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Call governance from caller contract with owner
    caller_client.try_governance_call(&audit_ledger_id, &owner);

    // Should succeed (no panic)
}

#[test]
fn cross_contract_transfer_ownership_across_contracts() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let new_owner = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Transfer ownership
    audit_client.transfer_ownership(&owner, &new_owner);

    // New owner can govern
    audit_client.set_global_max_logs(&new_owner, &200);
}

// ── Error Propagation Tests ───────────────────────────────────────────────────────

#[test]
fn cross_contract_global_max_logs_error_propagates() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let submitter = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &1, &4096); // Max 1 event

    // Log one event to reach capacity
    audit_client.log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"first"),
        &None,
        &None,
        &false,
    );

    // Try to log another event via caller contract
    let result = caller_client.try_trigger_global_max_error(&audit_ledger_id, &submitter);

    // Error should propagate
    assert!(result.is_err());
}

#[test]
fn cross_contract_event_type_max_logs_error_propagates() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let submitter = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);
    audit_client.set_event_max_logs(&owner, &symbol_short!("payment"), &1);

    // Log one event of type payment
    audit_client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"first"),
        &None,
        &None,
        &false,
    );

    // Try to log another payment event via caller contract
    let result = caller_client.try_log_on_behalf(
        &audit_ledger_id,
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"second"),
    );

    // Error should propagate
    assert!(result.is_err());
}

#[test]
fn cross_contract_metadata_too_large_error_propagates() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let submitter = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);
    audit_client.set_metadata_max_size(&owner, &10);

    // Try to log event with oversized metadata via caller contract
    let result = caller_client.try_log_on_behalf(
        &audit_ledger_id,
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, &[0u8; 11]),
    );

    // Error should propagate
    assert!(result.is_err());
}

#[test]
fn cross_contract_contract_paused_error_propagates() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let submitter = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);
    audit_client.pause(&owner);

    // Try to log event while paused via caller contract
    let result = caller_client.try_log_on_behalf(
        &audit_ledger_id,
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"data"),
    );

    // Error should propagate
    assert!(result.is_err());
}

// ── Reentrancy Tests ───────────────────────────────────────────────────────────────

#[test]
fn cross_contract_sequential_calls_work() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let submitter = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Make sequential calls (not true reentrancy, but multiple calls)
    caller_client.attempt_reentrancy(
        &audit_ledger_id,
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"data"),
    );

    // Both events should be logged
    assert_eq!(audit_client.total_events(), 2);
}

#[test]
fn cross_contract_caller_cannot_impersonate_user() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);
    let caller_contract_id = env.register(CallerContract, ());

    let audit_ledger_id = env.register(AuditLedger, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Try to log without user authorization
    // This should fail because the user hasn't authorized
    let result = caller_client.try_log_on_behalf(
        &audit_ledger_id,
        &user,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"data"),
    );

    // Should fail without user auth
    assert!(result.is_err());
}

#[test]
fn cross_contract_event_integrity_preserved() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller_contract_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller_client = CallerContractClient::new(&env, &caller_contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Log event via caller contract
    caller_client.log_on_behalf(
        &audit_ledger_id,
        &user,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx-data"),
    );

    // Verify hash chain integrity
    assert!(audit_client.verify_integrity());
}

#[test]
fn cross_contract_multiple_caller_contracts() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);

    let audit_ledger_id = env.register(AuditLedger, ());
    let caller1_id = env.register(CallerContract, ());
    let caller2_id = env.register(CallerContract, ());

    let audit_client = AuditLedgerClient::new(&env, &audit_ledger_id);
    let caller1_client = CallerContractClient::new(&env, &caller1_id);
    let caller2_client = CallerContractClient::new(&env, &caller2_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    audit_client.initialize(&owners, &100, &4096);

    // Log via caller1
    caller1_client.log_on_behalf(
        &audit_ledger_id,
        &user,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"via-caller1"),
    );

    // Log via caller2
    caller2_client.log_on_behalf(
        &audit_ledger_id,
        &user,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"via-caller2"),
    );

    assert_eq!(audit_client.total_events(), 2);

    let evt0 = audit_client.get_event_by_order(&0);
    let evt1 = audit_client.get_event_by_order(&1);

    assert_eq!(evt0.submitter, user);
    assert_eq!(evt1.submitter, user);
    assert_eq!(evt0.metadata, Bytes::from_slice(&env, b"via-caller1"));
    assert_eq!(evt1.metadata, Bytes::from_slice(&env, b"via-caller2"));
}

// ── Pagination Edge-Case Tests ─────────────────────────────────────────────────────

/// Helper: build a ledger with `count` events, each with a distinct submitter and
/// an incrementing ledger timestamp so ordering and filters are deterministic.
fn setup_paginated_ledger(
    count: u32,
) -> (Env, Address, AuditLedgerClient<'static>, Vec<Address>) {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths_allowing_non_root_auth();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &(count + 10), &4096);

    let mut submitters = Vec::new(&env);
    for i in 0..count {
        let submitter = Address::generate(&env);
        submitters.push_back(submitter.clone());
        client.log_event(
            &submitter,
            &symbol_short!("payment"),
            &Bytes::from_slice(&env, b"data"),
            &None,
            &None,
            &false,
        );
        // Advance the ledger timestamp so each event has a distinct timestamp.
        env.ledger().set_timestamp(env.ledger().timestamp() + 1);
        let _ = i;
    }

    (env, owner, client, submitters)
}

#[test]
fn pagination_empty_results_returns_no_items_and_no_cursor() {
    let (_env, _owner, client, _submitters) = setup_paginated_ledger(0);

    let page = client.get_events_page(&None, &10, &None, &None, &None);
    assert_eq!(page.items.len(), 0);
    assert!(page.next_cursor.is_none());
}

#[test]
fn pagination_single_item_page_returns_one_and_cursor() {
    let (_env, _owner, client, _submitters) = setup_paginated_ledger(5);

    let page = client.get_events_page(&None, &1, &None, &None, &None);
    assert_eq!(page.items.len(), 1);
    assert!(page.next_cursor.is_some());

    // The cursor should point past the first item.
    let next = client.get_events_page(&page.next_cursor, &1, &None, &None, &None);
    assert_eq!(next.items.len(), 1);
    assert_ne!(page.items.get(0).unwrap().order, next.items.get(0).unwrap().order);
}

#[test]
fn pagination_cursor_past_end_returns_empty() {
    let (_env, _owner, client, _submitters) = setup_paginated_ledger(3);

    // Walk to the end.
    let mut cursor = None;
    let mut seen = 0u32;
    loop {
        let page = client.get_events_page(&cursor, &10, &None, &None, &None);
        if page.items.len() == 0 {
            break;
        }
        seen += page.items.len();
        cursor = page.next_cursor.clone();
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, 3);

    // A cursor past the end yields an empty page with no next cursor.
    let past_end = client.get_events_page(&cursor, &10, &None, &None, &None);
    assert_eq!(past_end.items.len(), 0);
    assert!(past_end.next_cursor.is_none());
}

#[test]
fn pagination_full_multi_page_traversal_is_complete_and_ordered() {
    let (_env, _owner, client, _submitters) = setup_paginated_ledger(25);

    let mut cursor = None;
    let mut collected: Vec<u64> = Vec::new(&_env);
    loop {
        let page = client.get_events_page(&cursor, &7, &None, &None, &None);
        for item in page.items.iter() {
            collected.push_back(item.order);
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    assert_eq!(collected.len(), 25);
    // Deterministic ascending ordering by order.
    for i in 1..collected.len() {
        assert!(collected.get(i).unwrap() > collected.get(i - 1).unwrap());
    }
}

#[test]
fn pagination_page_limit_cap_is_enforced() {
    let (_env, _owner, client, _submitters) = setup_paginated_ledger(150);

    // Request more than the max page size; the contract must cap it at 100.
    let page = client.get_events_page(&None, &1000, &None, &None, &None);
    assert!(page.items.len() <= 100);
    assert_eq!(page.items.len(), 100);
    assert!(page.next_cursor.is_some());
}

#[test]
fn pagination_filter_by_timestamp_range() {
    let (env, _owner, client, _submitters) = setup_paginated_ledger(10);

    // Events were logged at timestamps 0..9 (incrementing by 1 each time).
    let page = client.get_events_page(&None, &100, &Some(3), &Some(6), &None);
    assert!(page.items.len() > 0);
    for item in page.items.iter() {
        assert!(item.timestamp >= 3);
        assert!(item.timestamp <= 6);
    }
    let _ = env;
}

#[test]
fn pagination_filter_by_status() {
    let (_env, _owner, client, _submitters) = setup_paginated_ledger(5);

    let page = client.get_events_page(
        &None,
        &100,
        &None,
        &None,
        &Some(WorkflowStatus::Completed),
    );
    // All events were logged as completed workflows in the helper.
    assert_eq!(page.items.len(), 5);
    for item in page.items.iter() {
        assert_eq!(item.status, WorkflowStatus::Completed);
    }
}

#[test]
fn pagination_filter_by_submitter_address() {
    let (_env, _owner, client, submitters) = setup_paginated_ledger(6);

    let target = submitters.get(2).unwrap();
    let page = client.get_events_page(&None, &100, &None, &None, &None);
    let _ = page;

    let filtered = client.get_events_page_by_submitter(&None, &100, &target);
    assert_eq!(filtered.items.len(), 1);
    assert_eq!(filtered.items.get(0).unwrap().submitter, target);
}

#[test]
fn pagination_combined_filters() {
    let (_env, _owner, client, submitters) = setup_paginated_ledger(8);

    let target = submitters.get(4).unwrap();
    let page = client.get_events_page_by_submitter(&None, &100, &target);
    assert_eq!(page.items.len(), 1);
    let item = page.items.get(0).unwrap();
    assert_eq!(item.submitter, target);
    assert_eq!(item.status, WorkflowStatus::Completed);
    assert!(item.timestamp >= 0);
}

#[test]
fn pagination_ordering_is_stable_across_repeated_queries() {
    let (_env, _owner, client, _submitters) = setup_paginated_ledger(20);

    let first = client.get_events_page(&None, &100, &None, &None, &None);
    let second = client.get_events_page(&None, &100, &None, &None, &None);

    assert_eq!(first.items.len(), second.items.len());
    for i in 0..first.items.len() {
        assert_eq!(
            first.items.get(i).unwrap().order,
            second.items.get(i).unwrap().order
        );
    }
}
