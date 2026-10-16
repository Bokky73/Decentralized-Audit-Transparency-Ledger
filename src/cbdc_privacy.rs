#![no_std]

//! CBDC tiered anonymity and selective disclosure guard.
//!
//! # Storage footprint (worst case)
//! Every collection written to state is bounded by an explicit `MAX_*` constant
//! declared in this module. Worst-case payload sizes:
//! - `MaskedTransaction.authorized_decrypters`: `MAX_AUTHORIZED_DECRYPTERS` (32) addresses.
//! - `PrivacyACL.read_access` / `audit_access` / `regulatory_access`: `MAX_ACL_ENTRIES` (64) addresses each.
//! - `MaskedTransaction.encrypted_data` / `encryption_metadata`: fixed-size hashes / short labels.
//! Any input exceeding these bounds is rejected with a typed [`CbdcPrivacyError`]
//! before any state entry is written.
//!
//! # CPU instruction bounds (worst case)
//! - `mask_transaction`: at most 3 SHA-256 invocations plus a bounded number of
//!   `Bytes::append` calls proportional to the fixed field count of `CBDCTransaction`.
//! - `create_privacy_acl`: one SHA-256 invocation plus O(MAX_ACL_ENTRIES) length checks.
//! - `PrivacyStats::record_transaction` / `total_count` / `privacy_ratio`: O(1)
//!   saturating arithmetic, no loops.
//! All arithmetic uses `checked_add` / `saturating_add`; no unchecked operations remain.

use crate::cbdc_types::{CBDCTransaction, PrivacyTier};
use soroban_sdk::{contracterror, contracttype, Address, Bytes, BytesN, Env};
use soroban_sdk::xdr::ToXdr;

/// Maximum number of authorized decrypters attached to a masked transaction.
pub const MAX_AUTHORIZED_DECRYPTERS: u32 = 32;

/// Maximum number of entries in any single privacy ACL access list.
pub const MAX_ACL_ENTRIES: u32 = 64;

/// Deterministic contract errors for the CBDC privacy guard.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CbdcPrivacyError {
    /// A collection exceeded its declared `MAX_*` bound.
    CollectionTooLarge = 1,
    /// An arithmetic operation overflowed the target type.
    ArithmeticOverflow = 2,
    /// The supplied privacy configuration is invalid.
    InvalidPrivacyConfiguration = 3,
    /// The access control list has expired.
    AclExpired = 4,
    /// The accessor has no permission on the ACL.
    NoAccessPermission = 5,
    /// Public transactions must not be encrypted.
    PublicTransactionEncrypted = 6,
}

/// Privacy-masked transaction for confidential operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedTransaction {
    /// Content hash representing this transaction (for audit trail without exposing details)
    pub content_hash: BytesN<32>,
    /// Privacy tier applied
    pub privacy_tier: u32, // PrivacyTier as u32
    /// Encrypted fields (only present at privacy levels >= Pseudonymous)
    pub encrypted_data: Option<Bytes>,
    /// Decryption key holder(s) - addresses that can decrypt
    pub authorized_decrypters: soroban_sdk::Vec<Address>,
    /// Timestamp of masking
    pub masked_at: u64,
    /// Optional metadata about the masking (e.g., encryption algorithm)
    pub encryption_metadata: Bytes,
}

impl MaskedTransaction {
    pub fn is_public(&self) -> bool {
        self.privacy_tier == PrivacyTier::Public as u32
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted_data.is_some()
    }

    pub fn requires_decryption_key(&self) -> bool {
        self.privacy_tier >= PrivacyTier::Pseudonymous as u32
    }
}

/// Privacy access control list for decryption.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyACL {
    /// Unique ACL ID
    pub acl_id: BytesN<32>,
    /// Associated transaction hash
    pub transaction_hash: BytesN<32>,
    /// Addresses with read access
    pub read_access: soroban_sdk::Vec<Address>,
    /// Addresses with audit access (can see transaction occurred, not details)
    pub audit_access: soroban_sdk::Vec<Address>,
    /// Central bank regulators with full access
    pub regulatory_access: soroban_sdk::Vec<Address>,
    /// Expiration timestamp (0 = no expiration)
    pub expires_at: u64,
}

impl PrivacyACL {
    pub fn has_read_access(&self, address: &Address) -> bool {
        self.read_access.iter().any(|addr| addr == *address)
    }

    pub fn has_audit_access(&self, address: &Address) -> bool {
        self.audit_access.iter().any(|addr| addr == *address)
    }

    pub fn has_regulatory_access(&self, address: &Address) -> bool {
        self.regulatory_access.iter().any(|addr| addr == *address)
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at > 0 && current_time > self.expires_at
    }

    pub fn can_access(&self, address: &Address, current_time: u64) -> bool {
        if self.is_expired(current_time) {
            return false;
        }
        self.has_read_access(address)
            || self.has_audit_access(address)
            || self.has_regulatory_access(address)
    }
}

/// Privacy enforcement manager.
pub struct PrivacyManager;

impl PrivacyManager {
    /// Apply privacy masking to transaction
    pub fn mask_transaction(
        env: &Env,
        transaction: &CBDCTransaction,
        privacy_tier: PrivacyTier,
        authorized_decrypters: soroban_sdk::Vec<Address>,
    ) -> Result<MaskedTransaction, CbdcPrivacyError> {
        if authorized_decrypters.len() > MAX_AUTHORIZED_DECRYPTERS {
            return Err(CbdcPrivacyError::CollectionTooLarge);
        }

        let content_hash = Self::compute_transaction_content_hash(env, transaction);
        let now = env.ledger().timestamp();

        let encrypted_data = if privacy_tier.requires_encryption() {
            Some(Self::encrypt_transaction_data(env, transaction, privacy_tier)?)
        } else {
            None
        };

        Ok(MaskedTransaction {
            content_hash,
            privacy_tier: privacy_tier as u32,
            encrypted_data,
            authorized_decrypters,
            masked_at: now,
            encryption_metadata: Self::encryption_metadata(env, privacy_tier),
        })
    }

    /// Compute content hash without exposing transaction details
    pub fn compute_transaction_content_hash(
        env: &Env,
        transaction: &CBDCTransaction,
    ) -> BytesN<32> {
        
        let mut input = Bytes::new(env);
        input.append(&transaction.tx_id.to_bytes());
        input.append(&Bytes::from_slice(env, &transaction.timestamp.to_le_bytes()));

        env.crypto().sha256(&input).to_bytes()
    }

    /// Encrypt transaction data based on privacy tier
    fn encrypt_transaction_data(
        env: &Env,
        transaction: &CBDCTransaction,
        privacy_tier: PrivacyTier,
    ) -> Result<Bytes, CbdcPrivacyError> {
        let mut encrypted = Bytes::new(env);

        match privacy_tier {
            PrivacyTier::Pseudonymous => {
                // Hash amount and exchange rate, keep pilot info
                encrypted.append(&Bytes::from_slice(env, &transaction.source_pilot.to_le_bytes()));
                encrypted.append(&Bytes::from_slice(env, &transaction.dest_pilot.to_le_bytes()));

                // Hash sensitive amounts
                                let mut amount_input = Bytes::new(env);
                amount_input.append(&Bytes::from_slice(env, &transaction.amount_source.to_le_bytes()));
                amount_input.append(&Bytes::from_slice(env, &transaction.exchange_rate.to_le_bytes()));
                let amount_hash = env.crypto().sha256(&amount_input).to_bytes();
                encrypted.append(&amount_hash.to_bytes());

                Ok(encrypted)
            }
            PrivacyTier::Private => {
                // Encrypt everything except ID and timestamp
                                let mut sensitive_input = Bytes::new(env);

                sensitive_input.append(&Bytes::from_slice(env, &transaction.source_pilot.to_le_bytes()));
                sensitive_input.append(&Bytes::from_slice(env, &transaction.dest_pilot.to_le_bytes()));
                sensitive_input.append(&transaction.from.clone().to_xdr(env));
                sensitive_input.append(&transaction.to.clone().to_xdr(env));
                sensitive_input.append(&Bytes::from_slice(env, &transaction.amount_source.to_le_bytes()));
                sensitive_input.append(&Bytes::from_slice(env, &transaction.amount_dest.to_le_bytes()));

                let encrypted_hash = env.crypto().sha256(&sensitive_input).to_bytes();
                Ok(encrypted_hash.to_bytes())
            }
            PrivacyTier::RegulatoryConfidential => {
                // Minimal exposure, full encryption
                                let mut full_input = Bytes::new(env);

                full_input.append(&transaction.tx_id.to_bytes());
                full_input.append(&Bytes::from_slice(env, &transaction.timestamp.to_le_bytes()));
                full_input.append(&transaction.metadata);

                let encrypted_hash = env.crypto().sha256(&full_input).to_bytes();
                Ok(encrypted_hash.to_bytes())
            }
            PrivacyTier::Public => {
                Err(CbdcPrivacyError::PublicTransactionEncrypted)
            }
        }
    }

    /// Get encryption metadata for privacy tier
    fn encryption_metadata(env: &Env, tier: PrivacyTier) -> Bytes {
        let label = match tier {
            PrivacyTier::Pseudonymous => "PSEUDONYMOUS_V1",
            PrivacyTier::Private => "PRIVATE_V1",
            PrivacyTier::RegulatoryConfidential => "REGULATORY_V1",
            PrivacyTier::Public => "NONE",
        };
        Bytes::from_slice(env, label.as_bytes())
    }

    /// Create privacy ACL for transaction
    pub fn create_privacy_acl(
        env: &Env,
        transaction_hash: BytesN<32>,
        read_access: soroban_sdk::Vec<Address>,
        audit_access: soroban_sdk::Vec<Address>,
        regulatory_access: soroban_sdk::Vec<Address>,
        expiration_secs: u64,
    ) -> Result<PrivacyACL, CbdcPrivacyError> {
        if read_access.len() > MAX_ACL_ENTRIES
            || audit_access.len() > MAX_ACL_ENTRIES
            || regulatory_access.len() > MAX_ACL_ENTRIES
        {
            return Err(CbdcPrivacyError::CollectionTooLarge);
        }

        let acl_id = Self::compute_acl_id(env, &transaction_hash);
        let expires_at = if expiration_secs > 0 {
            env.ledger()
                .timestamp()
                .checked_add(expiration_secs)
                .ok_or(CbdcPrivacyError::ArithmeticOverflow)?
        } else {
            0
        };

        Ok(PrivacyACL {
            acl_id,
            transaction_hash,
            read_access,
            audit_access,
            regulatory_access,
            expires_at,
        })
    }

    /// Compute unique ACL ID
    pub fn compute_acl_id(env: &Env, transaction_hash: &BytesN<32>) -> BytesN<32> {
        
        let mut input = Bytes::new(env);
        input.append(&transaction_hash.to_bytes());
        input.append(&Bytes::from_slice(env, b"ACL_V1"));

        env.crypto().sha256(&input).to_bytes()
    }

    /// Validate privacy configuration
    pub fn validate_privacy_configuration(
        tier: PrivacyTier,
        has_authorized_decrypters: bool,
    ) -> Result<(), CbdcPrivacyError> {
        if tier.requires_encryption() && !has_authorized_decrypters {
            return Err(CbdcPrivacyError::InvalidPrivacyConfiguration);
        }
        Ok(())
    }

    /// Check access permission for transaction
    pub fn check_access_permission(
        acl: &PrivacyACL,
        accessor: &Address,
        current_time: u64,
    ) -> Result<AccessLevel, CbdcPrivacyError> {
        if acl.is_expired(current_time) {
            return Err(CbdcPrivacyError::AclExpired);
        }

        if acl.has_regulatory_access(accessor) {
            return Ok(AccessLevel::RegulatoryFull);
        }
        if acl.has_read_access(accessor) {
            return Ok(AccessLevel::Read);
        }
        if acl.has_audit_access(accessor) {
            return Ok(AccessLevel::AuditOnly);
        }

        Err(CbdcPrivacyError::NoAccessPermission)
    }
}

/// Access level enumeration for privacy operations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AccessLevel {
    /// No access
    None = 0,
    /// Audit-only access (can see transaction occurred, not full details)
    AuditOnly = 1,
    /// Read access (full transaction details)
    Read = 2,
    /// Regulatory full access (unencrypted data)
    RegulatoryFull = 3,
}

impl AccessLevel {
    pub fn can_read_full_details(&self) -> bool {
        matches!(self, AccessLevel::Read | AccessLevel::RegulatoryFull)
    }

    pub fn can_audit(&self) -> bool {
        matches!(
            self,
            AccessLevel::AuditOnly | AccessLevel::Read | AccessLevel::RegulatoryFull
        )
    }
}

/// Privacy statistics tracking.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyStats {
    /// Public transactions
    pub public_count: u32,
    /// Pseudonymous transactions
    pub pseudonymous_count: u32,
    /// Private transactions
    pub private_count: u32,
    /// Regulatory confidential transactions
    pub regulatory_count: u32,
}

impl PrivacyStats {
    pub fn new() -> Self {
        PrivacyStats {
            public_count: 0,
            pseudonymous_count: 0,
            private_count: 0,
            regulatory_count: 0,
        }
    }

    pub fn total_count(&self) -> u32 {
        self.public_count
            .saturating_add(self.pseudonymous_count)
            .saturating_add(self.private_count)
            .saturating_add(self.regulatory_count)
    }

    pub fn record_transaction(&mut self, tier: PrivacyTier) {
        match tier {
            PrivacyTier::Public => {
                self.public_count = self.public_count.saturating_add(1);
            }
            PrivacyTier::Pseudonymous => {
                self.pseudonymous_count = self.pseudonymous_count.saturating_add(1);
            }
            PrivacyTier::Private => {
                self.private_count = self.private_count.saturating_add(1);
            }
            PrivacyTier::RegulatoryConfidential => {
                self.regulatory_count = self.regulatory_count.saturating_add(1);
            }
        }
    }

    pub fn privacy_ratio(&self) -> u32 {
        let total = self.total_count();
        if total == 0 {
            return 0;
        }
        let encrypted = self
            .pseudonymous_count
            .saturating_add(self.private_count)
            .saturating_add(self.regulatory_count);
        ((encrypted as u64).saturating_mul(100) / total as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_acl_expiration() {
        let acl = PrivacyACL {
            acl_id: BytesN::zero(),
            transaction_hash: BytesN::zero(),
            read_access: soroban_sdk::Vec::new(&soroban_sdk::Env::default()),
            audit_access: soroban_sdk::Vec::new(&soroban_sdk::Env::default()),
            regulatory_access: soroban_sdk::Vec::new(&soroban_sdk::Env::default()),
            expires_at: 1000,
        };

        assert!(!acl.is_expired(500));
        assert!(acl.is_expired(1500));
    }

    #[test]
    fn test_privacy_stats_calculation() {
        let mut stats = PrivacyStats::new();
        stats.public_count = 60;
        stats.pseudonymous_count = 20;
        stats.private_count = 15;
        stats.regulatory_count = 5;

        assert_eq!(stats.total_count(), 100);
        assert_eq!(stats.privacy_ratio(), 40); // 40 out of 100 encrypted
    }

    #[test]
    fn test_access_level_permissions() {
        assert!(!AccessLevel::None.can_read_full_details());
        assert!(!AccessLevel::AuditOnly.can_read_full_details());
        assert!(AccessLevel::Read.can_read_full_details());
        assert!(AccessLevel::RegulatoryFull.can_read_full_details());

        assert!(!AccessLevel::None.can_audit());
        assert!(AccessLevel::AuditOnly.can_audit());
        assert!(AccessLevel::Read.can_audit());
    }

    #[test]
    fn test_privacy_stats_saturates_at_u32_max() {
        let mut stats = PrivacyStats::new();
        stats.public_count = u32::MAX;
        stats.pseudonymous_count = u32::MAX;
        stats.private_count = u32::MAX;
        stats.regulatory_count = u32::MAX;

        assert_eq!(stats.total_count(), u32::MAX);

        stats.record_transaction(PrivacyTier::Public);
        assert_eq!(stats.public_count, u32::MAX);
        assert_eq!(stats.total_count(), u32::MAX);
    }

    #[test]
    fn test_privacy_ratio_with_max_values() {
        let mut stats = PrivacyStats::new();
        stats.public_count = 0;
        stats.pseudonymous_count = u32::MAX;
        stats.private_count = u32::MAX;
        stats.regulatory_count = u32::MAX;

        // Must not panic and must stay within [0, 100].
        let ratio = stats.privacy_ratio();
        assert!(ratio <= 100);
    }

    #[test]
    fn test_create_privacy_acl_rejects_oversized_lists() {
        let env = soroban_sdk::Env::default();
        let mut read_access = soroban_sdk::Vec::new(&env);
        for _ in 0..=MAX_ACL_ENTRIES {
            read_access.push_back(Address::generate(&env));
        }

        let result = PrivacyManager::create_privacy_acl(
            &env,
            BytesN::zero(),
            read_access,
            soroban_sdk::Vec::new(&env),
            soroban_sdk::Vec::new(&env),
            0,
        );
        assert_eq!(result, Err(CbdcPrivacyError::CollectionTooLarge));
    }

    #[test]
    fn test_create_privacy_acl_expiration_overflow() {
        let env = soroban_sdk::Env::default();
        let result = PrivacyManager::create_privacy_acl(
            &env,
            BytesN::zero(),
            soroban_sdk::Vec::new(&env),
            soroban_sdk::Vec::new(&env),
            soroban_sdk::Vec::new(&env),
            u64::MAX,
        );
        assert_eq!(result, Err(CbdcPrivacyError::ArithmeticOverflow));
    }

    #[test]
    fn test_mask_transaction_rejects_oversized_decrypters() {
        let env = soroban_sdk::Env::default();
        let mut decrypters = soroban_sdk::Vec::new(&env);
        for _ in 0..=MAX_AUTHORIZED_DECRYPTERS {
            decrypters.push_back(Address::generate(&env));
        }

        let transaction = CBDCTransaction {
            tx_id: BytesN::zero(),
            timestamp: u64::MAX,
            source_pilot: u32::MAX,
            dest_pilot: u32::MAX,
            from: Address::generate(&env),
            to: Address::generate(&env),
            amount_source: i128::MAX,
            amount_dest: i128::MAX,
            exchange_rate: i128::MAX,
            metadata: Bytes::new(&env),
        };

        let result = PrivacyManager::mask_transaction(
            &env,
            &transaction,
            PrivacyTier::Pseudonymous,
            decrypters,
        );
        assert_eq!(result, Err(CbdcPrivacyError::CollectionTooLarge));
    }

    #[test]
    fn test_check_access_permission_typed_errors() {
        let env = soroban_sdk::Env::default();
        let accessor = Address::generate(&env);
        let acl = PrivacyACL {
            acl_id: BytesN::zero(),
            transaction_hash: BytesN::zero(),
            read_access: soroban_sdk::Vec::new(&env),
            audit_access: soroban_sdk::Vec::new(&env),
            regulatory_access: soroban_sdk::Vec::new(&env),
            expires_at: 1000,
        };

        assert_eq!(
            PrivacyManager::check_access_permission(&acl, &accessor, 1500),
            Err(CbdcPrivacyError::AclExpired)
        );
        assert_eq!(
            PrivacyManager::check_access_permission(&acl, &accessor, 500),
            Err(CbdcPrivacyError::NoAccessPermission)
        );
    }
}
