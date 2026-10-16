use super::*;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{symbol_short, Bytes, BytesN, Env, Vec};

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

// ── Chaos Engineering: Key Rotation ───────────────────────────────────────────

#[test]
fn chaos_key_rotation_old_key_denied() {
    let (env, owner, client) = create_ledger();
    let new_owner = Address::generate(&env);

    env.mock_all_auths();
    client.transfer_ownership(&owner, &new_owner);

    // Verify new owner can call governance
    let result = client.try_set_global_max_logs(&new_owner, &200);
    assert!(result.is_ok());

    // Verify old owner is now denied
    let result = client.try_set_global_max_logs(&owner, &300);
    assert!(result.is_err());
}

#[test]
fn chaos_key_rotation_events_preserved() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);
    let new_owner = Address::generate(&env);

    env.mock_all_auths();
    let id = client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );

    client.transfer_ownership(&owner, &new_owner);

    // Events should still be readable after ownership transfer
    let evt = client.get_event(&id);
    assert_eq!(evt.submitter, submitter);
    assert_eq!(evt.metadata, Bytes::from_slice(&env, b"tx1"));
}

#[test]
fn chaos_key_rotation_multiple_rotations() {
    let (env, owner1, client) = create_ledger();
    let owner2 = Address::generate(&env);
    let owner3 = Address::generate(&env);

    env.mock_all_auths();
    client.transfer_ownership(&owner1, &owner2);
    client.transfer_ownership(&owner2, &owner3);

    let result = client.try_set_global_max_logs(&owner1, &200);
    assert!(result.is_err());

    let result = client.try_set_global_max_logs(&owner2, &200);
    assert!(result.is_err());

    let result = client.try_set_global_max_logs(&owner3, &200);
    assert!(result.is_ok());
}

// ── Chaos Engineering: Permission Changes ─────────────────────────────────────

#[test]
fn chaos_permission_change_pause_blocks_writes() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.pause(&owner);

    let result = client.try_log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());

    client.unpause(&owner);

    let id = client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );
    assert_eq!(client.total_events(), 1);
}

#[test]
fn chaos_permission_change_governance_denied_while_paused() {
    let (env, owner, client) = create_ledger();

    env.mock_all_auths();
    client.pause(&owner);

    let result = client.try_set_global_max_logs(&owner, &200);
    assert!(result.is_err());

    client.unpause(&owner);

    let result = client.try_set_global_max_logs(&owner, &200);
    assert!(result.is_ok());
}

#[test]
fn chaos_permission_change_submitter_blocklist() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );

    client.block_submitter(&owner, &submitter);

    let result = client.try_log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx2"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());

    client.unblock_submitter(&owner, &submitter);

    let id = client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx2"),
        &None,
        &None,
        &false,
    );
    assert_eq!(client.total_events(), 2);
}

#[test]
fn chaos_permission_change_allowlist_mode() {
    let (env, owner, client) = create_ledger();
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);

    env.mock_all_auths();
    client.enable_allowlist_mode(&owner);
    client.allow_submitter(&owner, &allowed);

    let result = client.try_log_event(
        &blocked,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());

    let id = client.log_event(
        &allowed,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );
    assert_eq!(client.total_events(), 1);
}

// ── Chaos Engineering: Metadata Schema Changes ─────────────────────────────────

#[test]
fn chaos_metadata_schema_change_enforces_constraint() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_metadata_schema(
        &owner,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, &8u32.to_le_bytes()),
    );

    let result = client.try_log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"short"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());

    client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"long enough"),
        &None,
        &None,
        &false,
    );
}

// ── Chaos Engineering: Event Cap Changes ──────────────────────────────────────

#[test]
fn chaos_event_cap_change_removal() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);
    let payment = symbol_short!("payment");

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &payment, &2);

    client.log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx1"), &None, &None, &false);
    client.log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx2"), &None, &None, &false);

    let result = client.try_log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx3"), &None, &None, &false);
    assert!(result.is_err());

    client.remove_event_cap(&owner, &payment);

    client.log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx3"), &None, &None, &false);
    assert_eq!(client.event_count(&payment), 3);
}

// ── Chaos Engineering: TTL and Storage ────────────────────────────────────────

#[test]
fn chaos_ttl_configuration_change() {
    let (env, owner, client) = create_ledger();

    env.mock_all_auths();
    client.set_event_ttl(&owner, &100);

    assert_eq!(client.get_event_ttl(), 100);

    client.set_event_ttl(&owner, &0);
    assert_eq!(client.get_event_ttl(), 0);
}

// ── Chaos Engineering: Nonce Configuration Changes ────────────────────────────

#[test]
fn chaos_nonce_configuration_change() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_submitter_nonce_config(&owner, &submitter, &10, &1000);

    client.log_event_with_nonce(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &1,
    );
    assert_eq!(client.get_submitter_nonce(&submitter), 1);

    client.log_event_with_nonce(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx10"),
        &10,
    );
    assert_eq!(client.get_submitter_nonce(&submitter), 10);
}

// ── Chaos Engineering: Rate Limit Changes ─────────────────────────────────────

#[test]
fn chaos_rate_limit_change() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();
    client.set_submitter_rate_limit(&owner, &submitter, &1);

    env.ledger().set_timestamp(1000);
    client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );

    let result = client.try_log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx2"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());
}

// ── Chaos Engineering: Suptech Feeds ──────────────────────────────────────────

fn create_suptech_feeds() -> (Env, Address, SuptechFeedsClient<'static>) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(SuptechFeeds, ());
    let client = SuptechFeedsClient::new(&env, &contract_id);

    env.mock_all_auths();
    client.initialize(&admin);
    (env, admin, client)
}

#[test]
fn chaos_suptech_feeds_duplicate_submission_rejected() {
    let (env, admin, client) = create_suptech_feeds();
    let reporter = Address::generate(&env);

    env.mock_all_auths();
    let payload = Bytes::from_slice(&env, b"feed-1");

    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &1);

    // Duplicate submission with the same sequence must be rejected.
    let result = client.try_submit_feed(&reporter, &symbol_short!("trade"), &payload, &1);
    assert!(result.is_err());

    // State remains consistent after the rejected duplicate.
    assert_eq!(client.feed_count(&reporter), 1);
}

#[test]
fn chaos_suptech_feeds_out_of_order_timestamps() {
    let (env, admin, client) = create_suptech_feeds();
    let reporter = Address::generate(&env);

    env.mock_all_auths();
    let payload = Bytes::from_slice(&env, b"feed");

    // Submit events out of timestamp order; the dispatcher must accept them
    // and preserve the hash chain regardless of arrival order.
    env.ledger().set_timestamp(3000);
    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &3);

    env.ledger().set_timestamp(1000);
    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &1);

    env.ledger().set_timestamp(2000);
    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &2);

    assert_eq!(client.feed_count(&reporter), 3);
    assert!(client.verify_hash_chain());
}

#[test]
fn chaos_suptech_feeds_mid_batch_rollback() {
    let (env, admin, client) = create_suptech_feeds();
    let reporter = Address::generate(&env);

    env.mock_all_auths();
    let payload = Bytes::from_slice(&env, b"feed");

    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &1);

    // A batch that fails partway through must not leave partial state.
    let result = client.try_submit_batch(
        &reporter,
        &Vec::from_array(
            &env,
            [
                (symbol_short!("trade"), payload.clone(), 2u64),
                (symbol_short!("trade"), payload.clone(), 2u64), // duplicate -> fails
            ],
        ),
    );
    assert!(result.is_err());

    // No partial writes from the rolled-back batch.
    assert_eq!(client.feed_count(&reporter), 1);
    assert!(client.verify_hash_chain());
}

#[test]
fn chaos_suptech_feeds_recovery_preserves_merkle_proof() {
    let (env, admin, client) = create_suptech_feeds();
    let reporter = Address::generate(&env);

    env.mock_all_auths();
    let payload = Bytes::from_slice(&env, b"feed");

    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &1);
    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &2);

    let root_before = client.merkle_root();

    // Simulate a failure and recovery cycle.
    client.pause(&admin);
    let result = client.try_submit_feed(&reporter, &symbol_short!("trade"), &payload, &3);
    assert!(result.is_err());
    client.unpause(&admin);

    // Merkle root and hash chain must be unchanged after recovery.
    assert_eq!(client.merkle_root(), root_before);
    assert!(client.verify_hash_chain());

    // The proof for an existing leaf still verifies after recovery.
    let proof = client.get_merkle_proof(&1);
    assert!(client.verify_merkle_proof(&1, &proof));
}

#[test]
fn chaos_suptech_feeds_recovery_after_rollback() {
    let (env, admin, client) = create_suptech_feeds();
    let reporter = Address::generate(&env);

    env.mock_all_auths();
    let payload = Bytes::from_slice(&env, b"feed");

    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &1);

    let result = client.try_submit_batch(
        &reporter,
        &Vec::from_array(
            &env,
            [
                (symbol_short!("trade"), payload.clone(), 2u64),
                (symbol_short!("trade"), payload.clone(), 2u64),
            ],
        ),
    );
    assert!(result.is_err());

    // Recovery: a valid submission after the rollback succeeds and the chain
    // remains intact.
    client.submit_feed(&reporter, &symbol_short!("trade"), &payload, &2);
    assert_eq!(client.feed_count(&reporter), 2);
    assert!(client.verify_hash_chain());
}

// ── Chaos Engineering: CBDC Offline ───────────────────────────────────────────

fn create_cbdc_offline() -> (Env, Address, CbdcOfflineClient<'static>) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(CbdcOffline, ());
    let client = CbdcOfflineClient::new(&env, &contract_id);

    env.mock_all_auths();
    client.initialize(&admin);
    (env, admin, client)
}

#[test]
fn chaos_cbdc_offline_duplicate_voucher_rejected() {
    let (env, admin, client) = create_cbdc_offline();
    let holder = Address::generate(&env);

    env.mock_all_auths();
    let voucher = BytesN::from_array(&env, &[7u8; 32]);

    client.redeem_voucher(&holder, &voucher, &100);

    // Re-submitting the same voucher is a double-spend and must be rejected.
    let result = client.try_redeem_voucher(&holder, &voucher, &100);
    assert!(result.is_err());

    assert_eq!(client.redeemed_count(), 1);
}

#[test]
fn chaos_cbdc_offline_out_of_order_timestamps() {
    let (env, admin, client) = create_cbdc_offline();
    let holder = Address::generate(&env);

    env.mock_all_auths();
    let v1 = BytesN::from_array(&env, &[1u8; 32]);
    let v2 = BytesN::from_array(&env, &[2u8; 32]);
    let v3 = BytesN::from_array(&env, &[3u8; 32]);

    // Vouchers arrive out of order; reconciliation must still converge.
    env.ledger().set_timestamp(3000);
    client.redeem_voucher(&holder, &v3, &100);

    env.ledger().set_timestamp(1000);
    client.redeem_voucher(&holder, &v1, &100);

    env.ledger().set_timestamp(2000);
    client.redeem_voucher(&holder, &v2, &100);

    assert_eq!(client.redeemed_count(), 3);
    assert!(client.verify_hash_chain());
}

#[test]
fn chaos_cbdc_offline_mid_batch_rollback() {
    let (env, admin, client) = create_cbdc_offline();
    let holder = Address::generate(&env);

    env.mock_all_auths();
    let v1 = BytesN::from_array(&env, &[1u8; 32]);
    let v2 = BytesN::from_array(&env, &[2u8; 32]);

    client.redeem_voucher(&holder, &v1, &100);

    // Batch contains a duplicate voucher -> must roll back entirely.
    let result = client.try_redeem_batch(
        &holder,
        &Vec::from_array(&env, [(v2.clone(), 100i128), (v2.clone(), 100i128)]),
    );
    assert!(result.is_err());

    assert_eq!(client.redeemed_count(), 1);
    assert!(client.verify_hash_chain());
}

#[test]
fn chaos_cbdc_offline_recovery_preserves_merkle_proof() {
    let (env, admin, client) = create_cbdc_offline();
    let holder = Address::generate(&env);

    env.mock_all_auths();
    let v1 = BytesN::from_array(&env, &[1u8; 32]);
    let v2 = BytesN::from_array(&env, &[2u8; 32]);

    client.redeem_voucher(&holder, &v1, &100);
    client.redeem_voucher(&holder, &v2, &100);

    let root_before = client.merkle_root();

    // Simulate a failure and recovery cycle.
    client.pause(&admin);
    let v3 = BytesN::from_array(&env, &[3u8; 32]);
    let result = client.try_redeem_voucher(&holder, &v3, &100);
    assert!(result.is_err());
    client.unpause(&admin);

    // Merkle root and hash chain must be unchanged after recovery.
    assert_eq!(client.merkle_root(), root_before);
    assert!(client.verify_hash_chain());

    let proof = client.get_merkle_proof(&v1);
    assert!(client.verify_merkle_proof(&v1, &proof));
}

#[test]
fn chaos_cbdc_offline_recovery_after_rollback() {
    let (env, admin, client) = create_cbdc_offline();
    let holder = Address::generate(&env);

    env.mock_all_auths();
    let v1 = BytesN::from_array(&env, &[1u8; 32]);
    let v2 = BytesN::from_array(&env, &[2u8; 32]);

    client.redeem_voucher(&holder, &v1, &100);

    let result = client.try_redeem_batch(
        &holder,
        &Vec::from_array(&env, [(v2.clone(), 100i128), (v2.clone(), 100i128)]),
    );
    assert!(result.is_err());

    // Recovery: a valid redemption after the rollback succeeds.
    client.redeem_voucher(&holder, &v2, &100);
    assert_eq!(client.redeemed_count(), 2);
    assert!(client.verify_hash_chain());
}

// ── Chaos Engineering: Recovery After Failure ─────────────────────────────────

#[test]
fn chaos_recovery_after_pause_unpause() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);

    env.mock_all_auths();

    // Log some events
    client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );

    // Pause
    client.pause(&owner);

    // Attempt to log during pause
    let result = client.try_log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx2"),
        &None,
        &None,
        &false,
    );
    assert!(result.is_err());

    // Unpause
    client.unpause(&owner);

    // Recover and log again
    client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx2"),
        &None,
        &None,
        &false,
    );
    assert_eq!(client.total_events(), 2);
}

#[test]
fn chaos_recovery_after_key_rotation() {
    let (env, owner1, client) = create_ledger();
    let owner2 = Address::generate(&env);
    let submitter = Address::generate(&env);

    env.mock_all_auths();

    // Log event with old owner
    client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx1"),
        &None,
        &None,
        &false,
    );

    // Rotate key
    client.transfer_ownership(&owner1, &owner2);

    // Continue operating with new owner
    client.set_global_max_logs(&owner2, &200);
    client.log_event(
        &submitter,
        &symbol_short!("payment"),
        &Bytes::from_slice(&env, b"tx2"),
        &None,
        &None,
        &false,
    );

    assert_eq!(client.total_events(), 2);
}

#[test]
fn chaos_recovery_after_cap_removal() {
    let (env, owner, client) = create_ledger();
    let submitter = Address::generate(&env);
    let payment = symbol_short!("payment");

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &payment, &1);

    client.log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx1"), &None, &None, &false);

    let result = client.try_log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx2"), &None, &None, &false);
    assert!(result.is_err());

    client.remove_event_cap(&owner, &payment);

    client.log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx2"), &None, &None, &false);
    client.log_event(&submitter, &payment, &Bytes::from_slice(&env, b"tx3"), &None, &None, &false);
    assert_eq!(client.event_count(&payment), 3);
}
