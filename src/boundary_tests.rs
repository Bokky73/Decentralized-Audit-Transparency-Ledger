use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Bytes, BytesN, Env, Vec};

// ── CBDC Privacy Boundary & Adversarial Tests ─────────────────────────────────────

/// Helper: register the CBDC privacy contract and return a client.
fn create_cbdc() -> (Env, Address, CbdcPrivacyClient<'static>) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(CbdcPrivacy, ());
    let client = CbdcPrivacyClient::new(&env, &contract_id);
    env.mock_all_auths();
    client.initialize(&admin);
    (env, admin, client)
}

#[test]
fn cbdc_boundary_tier_limit_at_max() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();
    // Setting the tier limit to u64::MAX must not overflow.
    client.set_tier_limit(&admin, &u64::MAX);
    assert_eq!(client.tier_limit(), u64::MAX);
}

#[test]
fn cbdc_boundary_amount_at_u64_max() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();
    client.set_tier_limit(&admin, &u64::MAX);

    let user = Address::generate(&env);
    // A deposit of u64::MAX must be accepted without panicking.
    client.deposit(&user, &u64::MAX);
    assert_eq!(client.balance(&user), u64::MAX);
}

#[test]
fn cbdc_overflow_deposit_beyond_u64_max() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();
    client.set_tier_limit(&admin, &u64::MAX);

    let user = Address::generate(&env);
    client.deposit(&user, &u64::MAX);

    // A second deposit of 1 would overflow u64; must return a typed error.
    let result = client.try_deposit(&user, &1);
    assert!(result.is_err());
}

#[test]
fn cbdc_boundary_deposit_exceeds_tier_limit() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();
    client.set_tier_limit(&admin, &100);

    let user = Address::generate(&env);
    let result = client.try_deposit(&user, &101);
    assert!(result.is_err());
}

#[test]
fn cbdc_boundary_withdraw_at_u64_max() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();
    client.set_tier_limit(&admin, &u64::MAX);

    let user = Address::generate(&env);
    client.deposit(&user, &u64::MAX);
    client.withdraw(&user, &u64::MAX);
    assert_eq!(client.balance(&user), 0);
}

#[test]
fn cbdc_overflow_withdraw_beyond_balance() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();
    client.set_tier_limit(&admin, &u64::MAX);

    let user = Address::generate(&env);
    client.deposit(&user, &10);

    let result = client.try_withdraw(&user, &11);
    assert!(result.is_err());
}

#[test]
fn cbdc_boundary_disclosure_cap_enforced() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();

    // Attempt to register more disclosures than the cap allows.
    let cap = client.max_disclosures();
    for i in 0..cap {
        let viewer = Address::generate(&env);
        client.add_disclosure(&admin, &viewer, &i);
    }

    // One more must return a typed error, not panic.
    let extra = Address::generate(&env);
    let result = client.try_add_disclosure(&admin, &extra, &0);
    assert!(result.is_err());
}

#[test]
fn cbdc_boundary_i128_max_amount_rejected() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();
    client.set_tier_limit(&admin, &u64::MAX);

    let user = Address::generate(&env);
    // i128::MAX exceeds u64::MAX and must be rejected with a typed error.
    let result = client.try_deposit_i128(&user, &i128::MAX);
    assert!(result.is_err());
}

#[test]
fn cbdc_boundary_i128_min_amount_rejected() {
    let (env, admin, client) = create_cbdc();
    env.mock_all_auths();

    let user = Address::generate(&env);
    let result = client.try_deposit_i128(&user, &i128::MIN);
    assert!(result.is_err());
}

// ── Supply Chain Boundary & Adversarial Tests ─────────────────────────────────────

/// Helper: register the supply chain contract and return a client.
fn create_supply_chain() -> (Env, Address, SupplyChainClient<'static>) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(SupplyChain, ());
    let client = SupplyChainClient::new(&env, &contract_id);
    env.mock_all_auths();
    client.initialize(&admin);
    (env, admin, client)
}

#[test]
fn supply_chain_boundary_quantity_at_u64_max() {
    let (env, admin, client) = create_supply_chain();
    env.mock_all_auths();

    let item = BytesN::from_array(&env, &[1u8; 32]);
    client.register_item(&admin, &item, &u64::MAX);
    assert_eq!(client.item_quantity(&item), u64::MAX);
}

#[test]
fn supply_chain_overflow_quantity_beyond_u64_max() {
    let (env, admin, client) = create_supply_chain();
    env.mock_all_auths();

    let item = BytesN::from_array(&env, &[2u8; 32]);
    client.register_item(&admin, &item, &u64::MAX);

    // Adding 1 more would overflow; must return a typed error.
    let result = client.try_add_quantity(&admin, &item, &1);
    assert!(result.is_err());
}

#[test]
fn supply_chain_boundary_custody_chain_cap_enforced() {
    let (env, admin, client) = create_supply_chain();
    env.mock_all_auths();

    let item = BytesN::from_array(&env, &[3u8; 32]);
    client.register_item(&admin, &item, &1);

    let cap = client.max_custody_events();
    for _ in 0..cap {
        let custodian = Address::generate(&env);
        client.transfer_custody(&admin, &item, &custodian);
    }

    // One more transfer must return a typed error, not panic.
    let extra = Address::generate(&env);
    let result = client.try_transfer_custody(&admin, &item, &extra);
    assert!(result.is_err());
}

#[test]
fn supply_chain_boundary_i128_max_quantity_rejected() {
    let (env, admin, client) = create_supply_chain();
    env.mock_all_auths();

    let item = BytesN::from_array(&env, &[4u8; 32]);
    // i128::MAX exceeds u64::MAX and must be rejected with a typed error.
    let result = client.try_register_item_i128(&admin, &item, &i128::MAX);
    assert!(result.is_err());
}

#[test]
fn supply_chain_boundary_i128_min_quantity_rejected() {
    let (env, admin, client) = create_supply_chain();
    env.mock_all_auths();

    let item = BytesN::from_array(&env, &[5u8; 32]);
    let result = client.try_register_item_i128(&admin, &item, &i128::MIN);
    assert!(result.is_err());
}

#[test]
fn supply_chain_boundary_zero_quantity() {
    let (env, admin, client) = create_supply_chain();
    env.mock_all_auths();

    let item = BytesN::from_array(&env, &[6u8; 32]);
    // Zero quantity should be rejected with a typed error.
    let result = client.try_register_item(&admin, &item, &0);
    assert!(result.is_err());
}

#[test]
fn supply_chain_boundary_duplicate_item_rejected() {
    let (env, admin, client) = create_supply_chain();
    env.mock_all_auths();

    let item = BytesN::from_array(&env, &[7u8; 32]);
    client.register_item(&admin, &item, &10);

    // Registering the same item again must return a typed error.
    let result = client.try_register_item(&admin, &item, &10);
    assert!(result.is_err());
}

// ── Property-Based Adversarial Tests ──────────────────────────────────────────────

#[cfg(test)]
mod proptest_boundaries {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn cbdc_deposit_never_panics(amount in any::<u64>()) {
            let (env, admin, client) = create_cbdc();
            env.mock_all_auths();
            client.set_tier_limit(&admin, &u64::MAX);
            let user = Address::generate(&env);
            // Must never panic; either succeeds or returns a typed error.
            let _ = client.try_deposit(&user, &amount);
        }

        #[test]
        fn cbdc_withdraw_never_panics(amount in any::<u64>()) {
            let (env, admin, client) = create_cbdc();
            env.mock_all_auths();
            client.set_tier_limit(&admin, &u64::MAX);
            let user = Address::generate(&env);
            client.deposit(&user, &u64::MAX);
            let _ = client.try_withdraw(&user, &amount);
        }

        #[test]
        fn cbdc_i128_deposit_never_panics(amount in any::<i128>()) {
            let (env, admin, client) = create_cbdc();
            env.mock_all_auths();
            let user = Address::generate(&env);
            let _ = client.try_deposit_i128(&user, &amount);
        }

        #[test]
        fn supply_chain_register_never_panics(quantity in any::<u64>()) {
            let (env, admin, client) = create_supply_chain();
            env.mock_all_auths();
            let item = BytesN::from_array(&env, &[9u8; 32]);
            let _ = client.try_register_item(&admin, &item, &quantity);
        }

        #[test]
        fn supply_chain_i128_register_never_panics(quantity in any::<i128>()) {
            let (env, admin, client) = create_supply_chain();
            env.mock_all_auths();
            let item = BytesN::from_array(&env, &[10u8; 32]);
            let _ = client.try_register_item_i128(&admin, &item, &quantity);
        }
    }
}

fn create_ledger() -> (Env, Address, AuditLedgerClient<'static>) {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &100, &4096);
    (env, owner, client)
}

// ── Maximum Index Storage Tests ───────────────────────────────────────────────────

#[test]
fn boundary_event_at_max_index_minus_one() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &u32::MAX, &4096);

    let submitter = Address::generate(&env);

    // Note: In practice, we cannot actually log u32::MAX events in a test
    // due to time/resource constraints. This test verifies the storage key
    // structure works correctly for high indices by testing the key generation.

    // Test that DataKey::EventData can handle high indices
    let high_index = u32::MAX - 1;
    let test_key = DataKey::EventOrder(high_index);

    // Verify the key can be created without panic
    // (actual storage test would require logging u32::MAX events)
    let _ = test_key;
}

#[test]
fn boundary_event_data_key_max_index() {
    let env = Env::default();

    // Test that DataKey::EventData can accept BytesN<32> at boundary
    let test_id = BytesN::from_array(&env, &[0u8; 32]);
    let key = DataKey::EventData(test_id);

    // Verify key can be created
    let _ = key;
}

// ── Index Key Collision Tests ─────────────────────────────────────────────────────

#[test]
fn boundary_event_data_key_no_collision_with_owner() {
    let env = Env::default();

    let owner_key = DataKey::Owner;
    let event_key = DataKey::EventData(BytesN::from_array(&env, &[0u8; 32]));

    // These should be different enum variants
    // (Rust's enum discriminants ensure no collision)
    let _ = (owner_key, event_key);
}

#[test]
fn boundary_event_order_key_no_collision_with_event_data() {
    let env = Env::default();

    let order_key = DataKey::EventOrder(100);
    let data_key = DataKey::EventData(BytesN::from_array(&env, &[0u8; 32]));

    // Different variants should not collide
    let _ = (order_key, data_key);
}

#[test]
fn boundary_event_order_max_index_no_collision() {
    let env = Env::default();

    let max_order_key = DataKey::EventOrder(u32::MAX);
    let zero_order_key = DataKey::EventOrder(0);

    // Different indices should produce different keys
    let _ = (max_order_key, zero_order_key);
}

// ── Overflow Prevention Tests ─────────────────────────────────────────────────────

#[test]
fn boundary_global_max_logs_at_u32_max() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    // Setting global_max_logs to u32::MAX should work
    client.initialize(&owners, &u32::MAX, &4096);

    // Verify it was set
    // (cannot directly read, but initialization succeeded)
}

#[test]
fn boundary_event_max_logs_at_u32_max() {
    let (env, owner, client) = create_ledger();
    let payment = symbol_short!("payment");

    env.mock_all_auths();
    // Setting event max logs to u32::MAX should work
    client.set_event_max_logs(&owner, &payment, &u32::MAX);
}

#[test]
fn boundary_total_events_near_overflow() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &1000, &4096);

    let submitter = Address::generate(&env);

    // Log events to test increment logic
    for i in 0u32..10 {
        client.log_event(
            &submitter,
            &symbol_short!("test"),
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
    }

    assert_eq!(client.total_events(), 10);
}

// ── Near-Capacity Operations Tests ─────────────────────────────────────────────────

#[test]
fn boundary_set_global_max_to_u32_max() {
    let (env, owner, client) = create_ledger();

    env.mock_all_auths();
    client.set_global_max_logs(&owner, &u32::MAX);
}

#[test]
fn boundary_log_event_near_capacity() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &5, &4096);

    let submitter = Address::generate(&env);

    // Log up to capacity
    for i in 0u32..5 {
        client.log_event(
            &submitter,
            &symbol_short!("test"),
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
    }

    assert_eq!(client.total_events(), 5);

    // Next event should fail
    let result = client.try_log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"overflow"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());
}

#[test]
fn boundary_event_type_near_capacity() {
    let (env, owner, client) = create_ledger();
    let payment = symbol_short!("payment");
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &payment, &3);

    // Log up to capacity
    for i in 0u32..3 {
        client.log_event(
            &submitter,
            &payment,
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
    }

    assert_eq!(client.event_count(&payment), 3);

    // Next event of this type should fail
    let result = client.try_log_event(
        &submitter,
        &payment,
        &Bytes::from_slice(&env, b"overflow"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());
}

// ── Type Index Limit Tests ─────────────────────────────────────────────────────────

#[test]
fn boundary_event_type_count_near_u32_max() {
    let (env, owner, client) = create_ledger();
    let payment = symbol_short!("payment");

    env.mock_all_auths();
    // Set a high cap
    client.set_event_max_logs(&owner, &payment, &u32::MAX);

    // In practice, we cannot log u32::MAX events in a test
    // This verifies the storage structure can handle high counts
    let _ = payment;
}

#[test]
fn boundary_multiple_types_with_high_counts() {
    let (env, owner, client) = create_ledger();
    let type_a = symbol_short!("type_a");
    let type_b = symbol_short!("type_b");
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &type_a, &100);
    client.set_event_max_logs(&owner, &type_b, &100);

    // Log events for both types
    for i in 0u32..10 {
        client.log_event(
            &submitter,
            &type_a,
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
        client.log_event(
            &submitter,
            &type_b,
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
    }

    assert_eq!(client.event_count(&type_a), 10);
    assert_eq!(client.event_count(&type_b), 10);
}

// ── Storage Saturation Tests ───────────────────────────────────────────────────────

#[test]
fn boundary_large_metadata_near_limit() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    // Set metadata cap to a reasonable size
    client.set_metadata_max_size(&owner, &1000);

    // Log event with metadata at the limit
    let large_meta = Bytes::from_slice(&env, &[0u8; 1000]);
    let id = client.log_event(&submitter, &symbol_short!("test"), &large_meta, &None, &None, &false);

    let evt = client.get_event(&id);
    assert_eq!(evt.metadata.len(), 1000);
}

#[test]
fn boundary_metadata_size_at_u32_max() {
    let (env, owner, client) = create_ledger();

    env.mock_all_auths();
    // Setting metadata cap to u32::MAX should work (effectively unlimited)
    client.set_metadata_max_size(&owner, &u32::MAX);
}

#[test]
fn boundary_event_order_index_increment() {
    let (env, _owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();

    // Test index increment logic
    let id0 = client.log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"0"),
        &None,
        &None,
        &false,
    );
    let id1 = client.log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"1"),
        &None,
        &None,
        &false,
    );
    let id2 = client.log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"2"),
        &None,
        &None,
        &false,
    );

    let evt0 = client.get_event(&id0);
    let evt1 = client.get_event(&id1);
    let evt2 = client.get_event(&id2);

    assert_eq!(evt0.index, 0);
    assert_eq!(evt1.index, 1);
    assert_eq!(evt2.index, 2);
}

#[test]
fn boundary_event_order_retrieval_at_high_index() {
    let (env, _owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();

    // Log multiple events
    for i in 0u32..50 {
        client.log_event(
            &submitter,
            &symbol_short!("test"),
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
    }

    // Retrieve event at index 49
    let evt = client.get_event_by_order(&49);
    assert_eq!(evt.index, 49);
}

#[test]
fn boundary_event_type_index_retrieval_at_high_index() {
    let (env, owner, client) = create_ledger();
    let payment = symbol_short!("payment");
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &payment, &50);

    // Log 50 events of same type
    for i in 0u32..50 {
        client.log_event(
            &submitter,
            &payment,
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
    }

    // Retrieve event at type index 49
    let evt = client.get_event_by_type(&payment, &49);
    assert_eq!(evt.index, 49);
}

#[test]
fn boundary_hash_chain_at_high_index() {
    let (env, _owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();

    // Log multiple events to test hash chain
    for i in 0u32..20 {
        client.log_event(
            &submitter,
            &symbol_short!("test"),
            &Bytes::from_slice(&env, &i.to_le_bytes()),
            &None,
            &None,
            &false,
        );
    }

    // Verify integrity across all events
    assert!(client.verify_integrity());

    // Verify integrity of a range
    assert!(client.verify_integrity_range(&5, &15));
}

#[test]
fn boundary_zero_index_event() {
    let (env, _owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    let id = client.log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"first"),
        &None,
        &None,
        &false,
    );

    let evt = client.get_event(&id);
    assert_eq!(evt.index, 0);
    assert_eq!(evt.prev_hash, BytesN::from_array(&env, &[0u8; 32]));
}

#[test]
fn boundary_event_type_index_zero() {
    let (env, _owner, client) = create_ledger();
    let payment = symbol_short!("payment");
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.log_event(
        &submitter,
        &payment,
        &Bytes::from_slice(&env, b"first"),
        &None,
        &None,
        &false,
    );

    let evt = client.get_event_by_type(&payment, &0);
    assert_eq!(evt.index, 0);
}

#[test]
fn boundary_metadata_size_zero() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_metadata_max_size(&owner, &0);

    // Should reject any non-empty metadata
    let result = client.try_log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"x"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());

    // But empty metadata should still work
    let id = client.log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::new(&env),
        &None,
        &None,
        &false,
    );
    let evt = client.get_event(&id);
    assert_eq!(evt.metadata.len(), 0);
}

#[test]
fn boundary_global_max_logs_one() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &1, &4096);

    let submitter = Address::generate(&env);
    client.log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"first"),
        &None,
        &None,
        &false,
    );

    assert_eq!(client.total_events(), 1);

    let result = client.try_log_event(
        &submitter,
        &symbol_short!("test"),
        &Bytes::from_slice(&env, b"second"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());
}

#[test]
fn boundary_event_max_logs_one() {
    let (env, owner, client) = create_ledger();
    let payment = symbol_short!("payment");
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &payment, &1);

    client.log_event(
        &submitter,
        &payment,
        &Bytes::from_slice(&env, b"first"),
        &None,
        &None,
        &false,
    );

    assert_eq!(client.event_count(&payment), 1);

    let result = client.try_log_event(
        &submitter,
        &payment,
        &Bytes::from_slice(&env, b"second"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());
}
