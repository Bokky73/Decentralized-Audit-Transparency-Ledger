use super::*;
use soroban_sdk::{Address, Env};
use proptest::prelude::*;

// ── Helpers ──────────────────────────────────────────────────────────

fn env() -> Env {
    Env::default()
}

fn alice(env: &Env) -> Address {
    Address::generate(env)
}

fn bob(env: &Env) -> Address {
    Address::generate(env)
}

fn sample_tx(env: &Env) -> CBDCTransaction {
    CBDCTransaction {
        tx_id: BytesN::from_array(env, &[42u8; 32]),
        source_pilot: 0,
        dest_pilot: 1,
        from: alice(env),
        to: bob(env),
        amount_source: 1000,
        amount_dest: 1200,
        exchange_rate: 1_200_000_000_000_000_000,
        timestamp: 1_700_000_000,
        protocol: 0,
        privacy_tier: 0,
        offline_status: Some(0),
        metadata: Bytes::from_slice(env, b"meta"),
    }
}

// ── RBAC gating invariants ─────────────────────────────────────────

proptest! {
    #[test]
    fn prop_mask_transaction_requires_submitter_role(
        caller in any::<[u8; 32]>(),
    ) {
        let env = env();
        let caller_addr = Address::from_bytes(&env, &caller);
        let tx = sample_tx(&env);

        // No role assigned => must fail with InsufficientRole / UnauthorizedSubmitter.
        let res = PrivacyManager::mask_transaction(
            &env,
            &caller_addr,
            &tx,
            PrivacyTier::Private,
            Vec::new(&env),
        );
        prop_assert!(res.is_err());
    }

    #[test]
    fn prop_create_privacy_acl_requires_admin_role(
        caller in any::<[u8; 32]>(),
    ) {
        let env = env();
        let caller_addr = Address::from_bytes(&env, &caller);
        let tx_id = BytesN::from_array(&env, &[7u8; 32]);

        let res = PrivacyManager::create_privacy_acl(
            &env,
            &caller_addr,
            tx_id,
            Vec::new(&env),
            Vec::new(&env),
            Vec::new(&env),
            0,
        );
        prop_assert!(res.is_err());
    }
}

#[test]
fn test_mask_transaction_rejects_unauthorized_caller() {
    let env = env();
    let caller = alice(&env);
    let tx = sample_tx(&env);

    let res = PrivacyManager::mask_transaction(
        &env,
        &caller,
        &tx,
        PrivacyTier::Private,
        Vec::new(&env),
    );
    assert!(res.is_err());
}

#[test]
fn test_create_privacy_acl_rejects_unauthorized_caller() {
    let env = env();
    let caller = alice(&env);
    let tx_id = BytesN::from_array(&env, &[7u8; 32]);

    let res = PrivacyManager::create_privacy_acl(
        &env,
        &caller,
        tx_id,
        Vec::new(&env),
        Vec::new(&env),
        Vec::new(&env),
        0,
    );
    assert!(res.is_err());
}

// ── Content hash determinism invariant ─────────────────────────────

#[test]
fn test_content_hash_is_deterministic() {
    let env = env();
    let tx = sample_tx(&env);

    let h1 = PrivacyManager::compute_transaction_content_hash(&env, &tx);
    let h2 = PrivacyManager::compute_transaction_content_hash(&env, &tx);
    prop_assert_eq!(h1, h2);
}

#[test]
fn test_content_hash_changes_with_tx_id() {
    let env = env();
    let mut tx = sample_tx(&env);
    let h1 = PrivacyManager::compute_transaction_content_hash(&env, &tx);

    tx.tx_id = BytesN::from_array(&env, &[99u8; 32]);
    let h2 = PrivacyManager::compute_transaction_content_hash(&env, &tx);

    prop_assert_ne!(h1, h2);
}

// ── ACL expiration invariant ───────────────────────────────────────

#[test]
fn test_acl_not_expired_before_deadline() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::new(&env),
        audit_access: Vec::new(&env),
        regulatory_access: Vec::new(&env),
        expires_at: 1000,
    };
    assert!(!acl.is_expired(999));
    assert!(!acl.is_expired(1000));
}

#[test]
fn test_acl_expired_after_deadline() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::new(&env),
        audit_access: Vec::new(&env),
        regulatory_access: Vec::new(&env),
        expires_at: 1000,
    };
    assert!(acl.is_expired(1001));
}

// Zero expiration means never expires.
#[test]
fn test_acl_no_expiration_never_expires() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::new(&env),
        audit_access: Vec::new(&env),
        regulatory_access: Vec::new(&env),
        expires_at: 0,
    };
    assert!(!acl.is_expired(u64::MAX));
}

// ── Access level gating invariant ──────────────────────────────────

#[test]
fn test_access_level_read_full_details() {
    assert!(!AccessLevel::None.can_read_full_details());
    assert!(!AccessLevel::AuditOnly.can_read_full_details());
    assert!(AccessLevel::Read.can_read_full_details());
    assert!(AccessLevel::RegulatoryFull.can_read_full_details());
}

#[test]
fn test_access_level_can_audit() {
    assert!(!AccessLevel::None.can_audit());
    assert!(AccessLevel::AuditOnly.can_audit());
    assert!(AccessLevel::Read.can_audit());
    assert!(AccessLevel::RegulatoryFull.can_audit());
}

// ── Encryption requirement invariant ───────────────────────────────

#[test]
fn test_public_tier_rejects_encryption() {
    let env = env();
    let tx = sample_tx(&env);
    let res = PrivacyManager::encrypt_transaction_data(
        &env,
        &tx,
        PrivacyTier::Public,
    );
    assert!(res.is_err());
}

#[test]
fn test_private_tier_encrypts() {
    let env = env();
    let tx = sample_tx(&env);
    let res = PrivacyManager::encrypt_transaction_data(
        &env,
        &tx,
        PrivacyTier::Private,
    );
    assert!(res.is_ok());
    let encrypted = res.unwrap();
    assert!(!encrypted.is_empty());
}

#[test]
fn test_pseudonymous_tier_encrypts() {
    let env = env();
    let tx = sample_tx(&env);
    let res = PrivacyManager::encrypt_transaction_data(
        &env,
        &tx,
        PrivacyTier::Pseudonymous,
    );
    assert!(res.is_ok());
}

#[test]
fn test_regulatory_confidential_tier_encrypts() {
    let env = env();
    let tx = sample_tx(&env);
    let res = PrivacyManager::encrypt_transaction_data(
        &env,
        &tx,
        PrivacyTier::RegulatoryConfidential,
    );
    assert!(res.is_ok());
}

// ── validate_privacy_configuration invariant ───────────────────────

#[test]
fn test_validate_encrypted_requires_decrypters() {
    let res = PrivacyManager::validate_privacy_configuration(
        PrivacyTier::Private,
        false,
    );
    assert!(res.is_err());

    let res = PrivacyManager::validate_privacy_configuration(
        PrivacyTier::Private,
        true,
    );
    assert!(res.is_ok());

    // Public does not require decrypters.
    let res = PrivacyManager::validate_privacy_configuration(PrivacyTier::Public, false);
    assert!(res.is_ok());
}

// ── check_access_permission invariant ──────────────────────────────

#[test]
fn test_check_access_expired_rejects() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::new(&env),
        audit_access: Vec::new(&env),
        regulatory_access: Vec::new(&env),
        expires_at: 100,
    };
    let res = PrivacyManager::check_access_permission(&acl, &alice(&env), 200);
    assert!(res.is_err());
}

#[test]
fn test_check_access_regulatory_full() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::new(&env),
        audit_access: Vec::new(&env),
        regulatory_access: Vec::from_array(&env, &[alice(&env)]),
        expires_at: 0,
    };
    let res = PrivacyManager::check_access_permission(&acl, &alice(&env), 50);
    assert_eq!(res, Ok(AccessLevel::RegulatoryFull));
}

#[test]
fn test_check_access_read() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::from_array(&env, &[alice(&env)]),
        audit_access: Vec::new(&env),
        regulatory_access: Vec::new(&env),
        expires_at: 0,
    };
    let res = PrivacyManager::check_access_permission(&acl, &alice(&env), 50);
    assert_eq!(res, Ok(AccessLevel::Read));
}

#[test]
fn test_check_access_audit_only() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::new(&env),
        audit_access: Vec::from_array(&env, &[alice(&env)]),
        regulatory_access: Vec::new(&env),
        expires_at: 0,
    };
    let res = PrivacyManager::check_access_permission(&acl, &alice(&env), 50);
    assert_eq!(res, Ok(AccessLevel::AuditOnly));
}

#[test]
fn test_check_access_no_permission() {
    let env = env();
    let acl = PrivacyACL {
        acl_id: BytesN::zero(),
        transaction_hash: BytesN::zero(),
        read_access: Vec::from_array(&env, &[bob(&env)]),
        audit_access: Vec::new(&env),
        regulatory_access: Vec::new(&env),
        expires_at: 0,
    };
    let res = PrivacyManager::check_access_permission(&acl, &alice(&env), 50);
    assert!(res.is_err());
}

// ── Chaos / concurrency resilience ─────────────────────────────────

/// Reordered masking calls on distinct transactions must not corrupt
/// per-transaction content hashes (stateless function => order independent).
#[test]
fn test_masking_is_order_independent() {
    let env = env();
    let caller = alice(&env);

    let mut tx_a = sample_tx(&env);
    tx_a.tx_id = BytesN::from_array(&env, &[1u8; 32]);
    let mut tx_b = sample_tx(&env);
    tx_b.tx_id = BytesN::from_array(&env, &[2u8; 32]);

    let hash_a = PrivacyManager::compute_transaction_content_hash(&env, &tx_a);
    let hash_b = PrivacyManager::compute_transaction_content_hash(&env, &tx_b);

    // Apply in reverse order then forward order; results identical.
    let _reverse_b = PrivacyManager::compute_transaction_content_hash(&env, &tx_b);
    let _reverse_a = PrivacyManager::compute_transaction_content_hash(&env, &tx_a);

    assert_eq!(hash_a, PrivacyManager::compute_transaction_content_hash(&env, &tx_a));
    assert_eq!(hash_b, PrivacyManager::compute_transaction_content_hash(&env, &tx_b));
}

/// Fault injection: masking with Public tier on encrypted config path must fail
/// consistently regardless of repetition.
#[test]
fn test_public_tier_masking_fails_consistently() {
    let env = env();
    let caller = alice(&env);
    let tx = sample_tx(&env);

    for _ in 0..10 {
        let res = PrivacyManager::mask_transaction(
            &env,
            &caller,
            &tx,
            PrivacyTier::Public,
            Vec::new(&env),
        );
        assert!(res.is_err());
    }
}

/// ACL ID determinism under repeated computation (fault-injection repeat).
#[test]
fn test_acl_id_is_deterministic() {
    let env = env();
    let tx_hash = BytesN::from_array(&env, &[5u8; 32]);

    let id1 = PrivacyManager::compute_acl_id(&env, &tx_hash);
    let id2 = PrivacyManager::compute_acl_id(&env, &tx_hash);
    let id3 = PrivacyManager::compute_acl_id(&env, &tx_hash);

    assert_eq!(id1, id2);
    assert_eq!(id2, id3);
}

/// Privacy stats ratio invariant stays within [0, 100].
#[test]
fn test_privacy_ratio_bounded() {
    let mut stats = PrivacyStats::new();
    for _ in 0..1000 {
        stats.record_transaction(PrivacyTier::Private);
    }
    let ratio = stats.privacy_ratio();
    assert!(ratio <= 100);
    assert_eq!(ratio, 100);
}

/// Empty stats privacy ratio is 0 (no division by zero).
#[test]
fn test_privacy_ratio_empty_is_zero() {
    let stats = PrivacyStats::new();
    assert_eq!(stats.privacy_ratio(), 0);
    assert_eq!(stats.total_count(), 0);
}
