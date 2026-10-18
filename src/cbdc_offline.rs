#![no_std]

use crate::cbdc_types::{BatchSettlement, CBDCTransaction, CBDCInteropError, OfflineStatus};
use crate::rbac::{RbacError, RbacManager, Role};
use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Symbol, Vec};

/// Maximum offline transaction amount (prevents unbounded value growth).
pub const MAX_OFFLINE_TX_AMOUNT: u128 = 1_000_000_000_000_000_000;
/// Maximum byte length of offline transaction metadata.
pub const MAX_OFFLINE_METADATA_BYTES: u32 = 4_096;
/// Maximum number of transactions in a batch settlement.
pub const MAX_OFFLINE_BATCH_SIZE: u32 = 1_000;

/// Audit event topic for offline transaction operations.
const AUDIT_TOPIC: &str = "cbdc_offline";
/// Audit event outcome values.
const AUDIT_OK: &str = "ok";
const AUDIT_DENIED: &str = "denied";

/// Represents an offline-signed transaction before reconciliation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineTransaction {
    /// Transaction hash (deterministic ID)
    pub tx_hash: BytesN<32>,
    /// The actual transaction
    pub transaction: CBDCTransaction,
    /// Cryptographic signature (e.g., Ed25519)
    pub signature: Bytes,
    /// Public key of signer
    pub signer_pubkey: Bytes,
    /// Reconciliation status
    pub status: u32, // OfflineStatus as u32
    /// Timestamp of offline creation
    pub created_at: u64,
    /// Timestamp of reconciliation (if any)
    pub reconciled_at: Option<u64>,
    /// Nonce to prevent replay attacks
    pub nonce: u32,
}

impl OfflineTransaction {
    /// Verify signature is valid (signature format check only, actual verification delegated)
    pub fn has_valid_signature_format(&self) -> bool {
        !self.signature.is_empty() && !self.signer_pubkey.is_empty()
    }

    /// Check if transaction is settled
    pub fn is_settled(&self) -> bool {
        self.status == OfflineStatus::Reconciled as u32
    }

    /// Check if transaction has failed
    pub fn is_failed(&self) -> bool {
        self.status == OfflineStatus::FailedReconciliation as u32
    }
}

/// Batch reconciliation state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationState {
    /// Total transactions in batch
    pub total_transactions: u32,
    /// Successfully reconciled transactions
    pub successful_count: u32,
    /// Failed transactions
    pub failed_count: u32,
    /// Pending reconciliation
    pub pending_count: u32,
    /// Dispute/reversal transactions
    pub disputed_count: u32,
}

impl ReconciliationState {
    pub fn new() -> Self {
        ReconciliationState {
            total_transactions: 0,
            successful_count: 0,
            failed_count: 0,
            pending_count: 0,
            disputed_count: 0,
        }
    }

    pub fn all_settled(&self) -> bool {
        self.successful_count == self.total_transactions
    }

    pub fn any_failed(&self) -> bool {
        self.failed_count > 0 || self.disputed_count > 0
    }

    /// Reconciliation rate as a percentage (0-100), computed with saturating
    /// arithmetic to avoid overflow on adversarial counts.
    pub fn reconciliation_rate(&self) -> u32 {
        if self.total_transactions == 0 {
            return 100;
        }
        let numerator = self
            .successful_count
            .checked_mul(100)
            .unwrap_or(u32::MAX);
        numerator.saturating_div(self.total_transactions)
    }
}

/// Offline transaction manager.
pub struct OfflineManager;

impl OfflineManager {
    /// Validate a CBDCTransaction's amount and metadata bounds.
    fn validate_transaction_bounds(transaction: &CBDCTransaction) -> Result<(), &'static str> {
        if transaction.amount_source == 0 {
            return Err("Transaction amount cannot be zero");
        }
        if transaction.amount_source > MAX_OFFLINE_TX_AMOUNT {
            return Err("Transaction amount exceeds maximum bound");
        }
        if transaction.amount_dest > MAX_OFFLINE_TX_AMOUNT {
            return Err("Destination amount exceeds maximum bound");
        }
        if transaction.metadata.len() as u32 > MAX_OFFLINE_METADATA_BYTES {
            return Err("Transaction metadata exceeds maximum byte length");
        }
        Ok(())
    }

    /// Create offline transaction with signature
    pub fn create_offline_transaction(
        env: &Env,
        caller: &Address,
        transaction: CBDCTransaction,
        signature: Bytes,
        signer_pubkey: Bytes,
        nonce: u32,
    ) -> Result<OfflineTransaction, &'static str> {
        Self::require_authorization(env, caller, "create_offline_transaction")?;

        if signature.is_empty() {
            Self::emit_denied_event(env, caller, "create_offline_transaction", "empty_signature");
            return Err("Signature cannot be empty");
        }
        if signer_pubkey.is_empty() {
            Self::emit_denied_event(env, caller, "create_offline_transaction", "empty_pubkey");
            return Err("Signer public key cannot be empty");
        }
        if let Err(e) = Self::validate_transaction_bounds(&transaction) {
            Self::emit_denied_event(env, caller, "create_offline_transaction", e);
            return Err(e);
        }
        if nonce == 0 {
            // Nonce can be 1+, 0 is reserved
            Self::emit_denied_event(env, caller, "create_offline_transaction", "invalid_nonce");
            return Err("Invalid nonce");
        }

        // Compute hash of transaction for offline verification
        let tx_hash = Self::compute_offline_tx_hash(env, &transaction, nonce);

        let result = OfflineTransaction {
            tx_hash,
            transaction,
            signature,
            signer_pubkey,
            status: OfflineStatus::PendingReconciliation as u32,
            created_at: env.ledger().timestamp(),
            reconciled_at: None,
            nonce,
        };
        Self::emit_success_event(env, caller, "create_offline_transaction");
        Ok(result)
    }

    /// Compute deterministic offline transaction hash
    pub fn compute_offline_tx_hash(
        env: &Env,
        transaction: &CBDCTransaction,
        nonce: u32,
    ) -> BytesN<32> {
        let mut input = Bytes::new(env);

        // Hash transaction fields
        input.append(&transaction.tx_id.to_bytes());
        input.append(&Bytes::from_slice(env, &transaction.source_pilot.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.dest_pilot.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.amount_source.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.amount_dest.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.exchange_rate.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &nonce.to_le_bytes()));

        env.crypto().sha256(&input).to_bytes()
    }

    /// Validate offline transaction before reconciliation
    pub fn validate_offline_transaction(
        tx: &OfflineTransaction,
    ) -> Result<(), &'static str> {
        if !tx.has_valid_signature_format() {
            return Err("Invalid signature format");
        }
        if tx.transaction.amount_source == 0 {
            return Err("Transaction amount cannot be zero");
        }
        if tx.transaction.amount_source > MAX_OFFLINE_TX_AMOUNT {
            return Err("Transaction amount exceeds maximum bound");
        }
        if tx.transaction.metadata.len() as u32 > MAX_OFFLINE_METADATA_BYTES {
            return Err("Transaction metadata exceeds maximum byte length");
        }
        if tx.nonce == 0 {
            // Nonce can be 1+, 0 is reserved
            return Err("Invalid nonce");
        }
        Ok(())
    }

    /// Reconcile offline transaction to on-chain state
    pub fn reconcile_transaction(
        env: &Env,
        caller: &Address,
        offline_tx: &mut OfflineTransaction,
    ) -> Result<(), &'static str> {
        Self::require_authorization(env, caller, "reconcile_transaction")?;

        if offline_tx.status != OfflineStatus::PendingReconciliation as u32 {
            Self::emit_denied_event(
                env,
                caller,
                "reconcile_transaction",
                "not_pending",
            );
            return Err("Transaction is not in pending state");
        }

        // Mark as reconciled
        offline_tx.status = OfflineStatus::Reconciled as u32;
        offline_tx.reconciled_at = Some(env.ledger().timestamp());

        Self::emit_success_event(env, caller, "reconcile_transaction");
        Ok(())
    }

    /// Mark transaction as failed reconciliation
    pub fn fail_reconciliation(
        env: &Env,
        caller: &Address,
        offline_tx: &mut OfflineTransaction,
    ) -> Result<(), &'static str> {
        Self::require_authorization(env, caller, "fail_reconciliation")?;

        if offline_tx.status == OfflineStatus::Reconciled as u32 {
            Self::emit_denied_event(
                env,
                caller,
                "fail_reconciliation",
                "already_reconciled",
            );
            return Err("Cannot fail already reconciled transaction");
        }

        offline_tx.status = OfflineStatus::FailedReconciliation as u32;
        offline_tx.reconciled_at = Some(env.ledger().timestamp());

        Self::emit_success_event(env, caller, "fail_reconciliation");
        Ok(())
    }

    /// Create batch settlement from offline transactions
    pub fn create_batch_settlement(
        env: &Env,
        caller: &Address,
        tx_ids: Vec<BytesN<32>>,
        total_amount: u128,
    ) -> Result<BatchSettlement, &'static str> {
        Self::require_authorization(env, caller, "create_batch_settlement")?;

        let batch_len = tx_ids.len() as u32;
        if batch_len == 0 {
            Self::emit_denied_event(env, caller, "create_batch_settlement", "empty_batch");
            return Err("Batch cannot be empty");
        }
        if batch_len > MAX_OFFLINE_BATCH_SIZE {
            Self::emit_denied_event(env, caller, "create_batch_settlement", "batch_too_large");
            return Err("Batch exceeds maximum transaction count");
        }
        if total_amount == 0 {
            Self::emit_denied_event(env, caller, "create_batch_settlement", "zero_amount");
            return Err("Batch amount cannot be zero");
        }
        if total_amount > MAX_OFFLINE_TX_AMOUNT {
            Self::emit_denied_event(env, caller, "create_batch_settlement", "amount_exceeds_bound");
            return Err("Batch total amount exceeds maximum bound");
        }

        let batch_id = Self::compute_batch_id(env, &tx_ids);

        let result = BatchSettlement {
            batch_id,
            transaction_ids: tx_ids,
            total_amount,
            settlement_status: OfflineStatus::PendingReconciliation as u32,
            created_at: env.ledger().timestamp(),
            settled_at: None,
        };
        Self::emit_success_event(env, caller, "create_batch_settlement");
        Ok(result)
    }

    /// Compute deterministic batch ID
    pub fn compute_batch_id(env: &Env, tx_ids: &Vec<BytesN<32>>) -> BytesN<32> {
        let mut input = Bytes::new(env);

        for tx_id in tx_ids.iter() {
            input.append(&tx_id.to_bytes());
        }

        env.crypto().sha256(&input).to_bytes()
    }

    /// Settle batch on-chain
    pub fn settle_batch(
        env: &Env,
        caller: &Address,
        batch: &mut BatchSettlement,
    ) -> Result<(), &'static str> {
        Self::require_authorization(env, caller, "settle_batch")?;

        if batch.settlement_status != OfflineStatus::PendingReconciliation as u32 {
            Self::emit_denied_event(
                env,
                caller,
                "settle_batch",
                "not_pending",
            );
            return Err("Batch is not in pending state");
        }

        batch.settlement_status = OfflineStatus::Reconciled as u32;
        batch.settled_at = Some(env.ledger().timestamp());

        Self::emit_success_event(env, caller, "settle_batch");
        Ok(())
    }

    /// Detect and prevent replay attacks using nonce
    pub fn verify_nonce(
        last_nonce: u32,
        current_nonce: u32,
    ) -> Result<(), &'static str> {
        if current_nonce <= last_nonce {
            return Err("Nonce replay detected or invalid sequence");
        }
        Ok(())
    }

    /// Compute reconciliation state from transaction statuses
    pub fn compute_reconciliation_state(
        statuses: &Vec<u32>,
    ) -> ReconciliationState {
        let mut state = ReconciliationState::new();
        state.total_transactions = statuses.len() as u32;

        for status in statuses.iter() {
            match status {
                s if s == OfflineStatus::Reconciled as u32 => {
                    state.successful_count = state.successful_count.saturating_add(1);
                }
                s if s == OfflineStatus::FailedReconciliation as u32 => {
                    state.failed_count = state.failed_count.saturating_add(1);
                }
                s if s == OfflineStatus::PendingReconciliation as u32 => {
                    state.pending_count = state.pending_count.saturating_add(1);
                }
                s if s == OfflineStatus::Disputed as u32 => {
                    state.disputed_count = state.disputed_count.saturating_add(1);
                }
                _ => {}
            }
        }

        state
    }

    /// Verify offline transaction integrity
    pub fn verify_transaction_integrity(
        env: &Env,
        offline_tx: &OfflineTransaction,
    ) -> bool {
        let recomputed_hash = Self::compute_offline_tx_hash(
            env,
            &offline_tx.transaction,
            offline_tx.nonce,
        );
        recomputed_hash == offline_tx.tx_hash
    }

    /// Enforce RBAC gating: caller must be an authenticated, non-suspended
    /// submitter (or higher). Emits a denied audit event on failure.
    fn require_authorization(
        env: &Env,
        caller: &Address,
        operation: &str,
    ) -> Result<(), &'static str> {
        caller.require_auth();

        if RbacManager::is_suspended(env, caller) {
            Self::emit_denied_event(env, caller, operation, "submitter_suspended");
            return Err("Submitter is suspended");
        }
        if RbacManager::get_role(env, caller).is_none() {
            Self::emit_denied_event(env, caller, operation, "no_role");
            return Err("No role assigned");
        }
        if !RbacManager::has_role_min(env, caller, Role::Submitter) {
            Self::emit_denied_event(env, caller, operation, "insufficient_role");
            return Err("Insufficient role");
        }
        Ok(())
    }

    /// Emit a success audit event for a completed mutation.
    fn emit_success_event(env: &Env, caller: &Address, operation: &str) {
        let topic = Symbol::new(env, AUDIT_TOPIC);
        let op = Symbol::new(env, operation);
        let result = Symbol::new(env, AUDIT_OK);

        env.events().publish(
            (topic.clone(), op.clone(), caller.clone()),
            (env.ledger().timestamp(), result.clone()),
        );
        env.events().publish(
            (Symbol::new(env, "cbdc_offline_audit_ok"), op, result),
            (caller.clone(), env.ledger().timestamp()),
        );
    }

    /// Emit a denied audit event for a rejected mutation attempt.
    fn emit_denied_event(
        env: &Env,
        caller: &Address,
        operation: &str,
        error_code: &str,
    ) {
        let topic = Symbol::new(env, AUDIT_TOPIC);
        let op = Symbol::new(env, operation);
        let result = Symbol::new(env, AUDIT_DENIED);
        let code = Symbol::new(env, error_code);

        env.events().publish(
            (topic.clone(), op.clone(), caller.clone()),
            (env.ledger().timestamp(), result.clone(), code),
        );
        env.events().publish(
            (Symbol::new(env, "cbdc_offline_audit_denied"), op, result),
            (caller.clone(), env.ledger().timestamp(), code),
        );
    }
}

/// Offline transaction queue for batching reconciliations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationQueue {
    /// Queue of transaction hashes pending reconciliation
    pub pending_tx_hashes: soroban_sdk::Vec<BytesN<32>>,
    /// Maximum queue size before flush
    pub max_queue_size: u32,
    /// Timestamp of last flush
    pub last_flush_time: u64,
}

impl ReconciliationQueue {
    pub fn new(env: &Env, max_size: u32) -> Self {
        ReconciliationQueue {
            pending_tx_hashes: Vec::new(env),
            max_queue_size: max_size,
            last_flush_time: 0,
        }
    }

    pub fn is_full(&self) -> bool {
        self.pending_tx_hashes.len() as u32 >= self.max_queue_size
    }

    pub fn add_transaction(&mut self, tx_hash: BytesN<32>) -> Result<(), &'static str> {
        if self.is_full() {
            return Err("Reconciliation queue is full");
        }
        self.pending_tx_hashes.push_back(tx_hash);
        Ok(())
    }

    pub fn clear(&mut self, timestamp: u64) {
        self.pending_tx_hashes = Vec::new(self.pending_tx_hashes.env());
        self.last_flush_time = timestamp;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offline_transaction_status() {
        let offline_tx = OfflineTransaction {
            tx_hash: BytesN::zero(),
            transaction: CBDCTransaction {
                tx_id: BytesN::zero(),
                source_pilot: 0,
                dest_pilot: 1,
                from: Address::generate(&soroban_sdk::Env::default()),
                to: Address::generate(&soroban_sdk::Env::default()),
                amount_source: 1000,
                amount_dest: 1200,
                exchange_rate: 1_200_000_000_000_000_000,
                timestamp: 1000,
                protocol: 0,
                privacy_tier: 0,
                offline_status: Some(0),
                metadata: Bytes::new(&soroban_sdk::Env::default()),
            },
            signature: Bytes::new(&soroban_sdk::Env::default()),
            signer_pubkey: Bytes::new(&soroban_sdk::Env::default()),
            status: OfflineStatus::PendingReconciliation as u32,
            created_at: 1000,
            reconciled_at: None,
            nonce: 1,
        };

        assert!(!offline_tx.is_settled());
        assert!(!offline_tx.is_failed());
    }

    #[test]
    fn test_reconciliation_state_calculation() {
        let statuses = Vec::from_array(
            &soroban_sdk::Env::default(),
            &[
                OfflineStatus::Reconciled as u32,
                OfflineStatus::Reconciled as u32,
                OfflineStatus::FailedReconciliation as u32,
            ],
        );

        let state = OfflineManager::compute_reconciliation_state(&statuses);
        assert_eq!(state.total_transactions, 3);
        assert_eq!(state.successful_count, 2);
        assert_eq!(state.failed_count, 1);
        assert_eq!(state.reconciliation_rate(), 66);
    }

    #[test]
    fn test_nonce_replay_detection() {
        assert!(OfflineManager::verify_nonce(1, 2).is_ok());
        assert!(OfflineManager::verify_nonce(5, 5).is_err()); // same nonce
        assert!(OfflineManager::verify_nonce(5, 3).is_err()); // lower nonce
    }
}
