#![no_std]

use crate::cbdc_types::{BatchSettlement, CBDCTransaction, OfflineStatus};
use soroban_sdk::{
    contracterror, contracttype, Address, Bytes, BytesN, Env, Vec,
};

/// Maximum number of transaction IDs permitted in a single batch settlement.
pub const MAX_BATCH_TRANSACTIONS: u32 = 1_000;
/// Maximum byte length of transaction metadata.
pub const MAX_METADATA_BYTES: u32 = 4_096;
/// Default TTL extension (in ledgers) for archival-critical persistent records.
pub const DEFAULT_TTL_EXTEND_LEDGERS: u32 = 100_000;
/// Threshold (in ledgers) below which archival-critical records are bumped.
pub const TTL_BUMP_THRESHOLD_LEDGERS: u32 = 10_000;
/// Default page size for paginated read queries.
pub const DEFAULT_PAGE_SIZE: u32 = 50;
/// Maximum page size allowed for a single read query.
pub const MAX_PAGE_SIZE: u32 = 500;

/// Typed contract errors for the CBDC offline module.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum OfflineError {
    /// Signature cannot be empty.
    EmptySignature = 1,
    /// Signer public key cannot be empty.
    EmptySignerPubkey = 2,
    /// Transaction amount cannot be zero.
    ZeroAmount = 3,
    /// Invalid nonce (0 is reserved).
    InvalidNonce = 4,
    /// Transaction is not in pending state.
    NotPending = 5,
    /// Cannot fail an already reconciled transaction.
    AlreadyReconciled = 6,
    /// Batch cannot be empty.
    EmptyBatch = 7,
    /// Batch amount cannot be zero.
    ZeroBatchAmount = 8,
    /// Batch is not in pending state.
    BatchNotPending = 9,
    /// Nonce replay detected or invalid sequence.
    NonceReplay = 10,
    /// Offline transaction not found in storage.
    TransactionNotFound = 11,
    /// Batch settlement not found in storage.
    BatchNotFound = 12,
    /// Reconciliation queue is full.
    QueueFull = 13,
    /// Invalid pagination parameters.
    InvalidPagination = 14,
    /// Storage write failed.
    StorageWriteFailed = 15,
}

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

    pub fn reconciliation_rate(&self) -> u32 {
        if self.total_transactions == 0 {
            return 100;
        }
        ((self.successful_count as u64 * 100) / self.total_transactions as u64) as u32
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

/// Persisted offline module configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineConfig {
    /// Maximum number of transactions retained per pilot before archival.
    pub max_transactions_per_pilot: u32,
    /// TTL extension in ledgers applied to persistent records.
    pub ttl_extend_ledgers: u32,
    /// Whether automated TTL bumping is enabled on reads/writes.
    pub ttl_auto_bump: bool,
    /// Whether temporary storage is used for the reconciliation queue.
    pub queue_use_temporary: bool,
}

impl OfflineConfig {
    pub fn default() -> Self {
        OfflineConfig {
            max_transactions_per_pilot: 10_000,
            ttl_extend_ledgers: DEFAULT_TTL_EXTEND_LEDGERS,
            ttl_auto_bump: true,
            queue_use_temporary: true,
        }
    }
}

/// Multi-predicate filter for read queries over offline transactions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineTransactionFilter {
    /// Filter by reconciliation status (absent = any status).
    pub status: Option<u32>,
    /// Filter by source CBDC pilot (absent = any pilot).
    pub source_pilot: Option<u32>,
    /// Filter by destination CBDC pilot (absent = any pilot).
    pub dest_pilot: Option<u32>,
    /// Minimum source amount inclusive (absent = no lower bound).
    pub min_amount: Option<u128>,
    /// Maximum source amount inclusive (absent = no upper bound).
    pub max_amount: Option<u128>,
    /// Only transactions created at or after this timestamp (absent = no bound).
    pub created_after: Option<u64>,
    /// Only transactions created at or before this timestamp (absent = no bound).
    pub created_before: Option<u64>,
    /// Maximum number of results to return.
    pub limit: u32,
}

impl OfflineTransactionFilter {
    pub fn new() -> Self {
        OfflineTransactionFilter {
            status: None,
            source_pilot: None,
            dest_pilot: None,
            min_amount: None,
            max_amount: None,
            created_after: None,
            created_before: None,
            limit: DEFAULT_PAGE_SIZE,
        }
    }

    pub fn matches(&self, tx: &OfflineTransaction) -> bool {
        if let Some(s) = self.status {
            if tx.status != s {
                return false;
            }
        }
        if let Some(p) = self.source_pilot {
            if tx.transaction.source_pilot != p {
                return false;
            }
        }
        if let Some(p) = self.dest_pilot {
            if tx.transaction.dest_pilot != p {
                return false;
            }
        }
        if let Some(min) = self.min_amount {
            if tx.transaction.amount_source < min {
                return false;
            }
        }
        if let Some(max) = self.max_amount {
            if tx.transaction.amount_source > max {
                return false;
            }
        }
        if let Some(after) = self.created_after {
            if tx.created_at < after {
                return false;
            }
        }
        if let Some(before) = self.created_before {
            if tx.created_at > before {
                return false;
            }
        }
        true
    }
}

/// Opaque pagination cursor. Encodes the offset (u32, little-endian) into bytes.
/// Callers treat it as an opaque token returned by a previous page query.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginationCursor {
    /// Offset into the filtered result set.
    pub offset: u32,
}

impl PaginationCursor {
    pub fn start() -> Self {
        PaginationCursor { offset: 0 }
    }

    pub fn next(&self, page_size: u32) -> Self {
        PaginationCursor {
            offset: self.offset.saturating_add(page_size),
        }
    }

    pub fn to_bytes(&self, env: &Env) -> BytesN<4> {
        BytesN::from_array(env, &self.offset.to_le_bytes())
    }

    pub fn from_bytes(env: &Env, bytes: &BytesN<4>) -> Result<Self, &'static str> {
        let data = bytes.to_array();
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        Ok(PaginationCursor { offset })
    }
}

/// Paginated result page for read queries.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginatedTransactions {
    /// Transactions in this page (already filtered).
    pub transactions: Vec<OfflineTransaction>,
    /// Cursor to fetch the next page (None if no more results).
    pub next_cursor: Option<PaginationCursor>,
    /// Total number of transactions matching the filter (uncapped by limit).
    pub total_matching: u32,
    /// Number of transactions returned in this page.
    pub page_size: u32,
}

/// Paginated result page for batch settlement read queries.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginatedBatchSettlements {
    /// Batch settlements in this page (already filtered).
    pub batches: Vec<BatchSettlement>,
    /// Cursor to fetch the next page (None if no more results).
    pub next_cursor: Option<PaginationCursor>,
    /// Total number of batches matching the filter (uncapped by limit).
    pub total_matching: u32,
    /// Number of batches returned in this page.
    pub page_size: u32,
}

/// Typed storage keys for offline module state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfflineStorageKey {
    /// OfflineTransaction keyed by tx_hash.
    Transaction(BytesN<32>),
    /// Ordered list of all transaction hashes (insertion order).
    AllTransactions,
    /// BatchSettlement keyed by batch_id.
    Batch(BytesN<32>),
    /// Ordered list of all batch IDs (insertion order).
    AllBatches,
    /// The pending reconciliation queue.
    Queue,
    /// Module configuration.
    Config,
}

/// Offline transaction manager with persistent storage, TTL bumping, and
/// cursor-based paginated filtered reads.
pub struct OfflineManager;

impl OfflineManager {
    // ── Storage helpers ──────────────────────────────────────────────

    /// Bump the TTL of a persistent storage key when auto-bump is enabled.
    fn maybe_bump_ttl(env: &Env, key: &OfflineStorageKey) {
        let config: OfflineConfig = env
            .storage()
            .instance()
            .get(&OfflineStorageKey::Config)
            .unwrap_or_else(OfflineConfig::default);
        if !config.ttl_auto_bump {
            return;
        }
        env.storage()
            .persistent()
            .extend_ttl(
                key,
                TTL_BUMP_THRESHOLD_LEDGERS,
                config.ttl_extend_ledgers,
            );
    }

    /// Read the module config from instance storage.
    fn read_config(env: &Env) -> OfflineConfig {
        env.storage()
            .instance()
            .get(&OfflineStorageKey::Config)
            .unwrap_or_else(OfflineConfig::default)
    }

    /// Write the module config to instance storage.
    fn write_config(env: &Env, config: &OfflineConfig) {
        env.storage().instance().set(&OfflineStorageKey::Config, config);
    }

    /// Get the ordered list of all transaction hashes.
    fn read_tx_index(env: &Env) -> Vec<BytesN<32>> {
        env.storage()
            .instance()
            .get(&OfflineStorageKey::AllTransactions)
            .unwrap_or_else(|| Vec::new(env))
    }

    /// Write the ordered list of all transaction hashes.
    fn write_tx_index(env: &Env, index: &Vec<BytesN<32>>) {
        env.storage()
            .instance()
            .set(&OfflineStorageKey::AllTransactions, index);
    }

    /// Get the ordered list of all batch IDs.
    fn read_batch_index(env: &Env) -> Vec<BytesN<32>> {
        env.storage()
            .instance()
            .get(&OfflineStorageKey::AllBatches)
            .unwrap_or_else(|| Vec::new(env))
    }

    /// Write the ordered list of all batch IDs.
    fn write_batch_index(env: &Env, index: &Vec<BytesN<32>>) {
        env.storage().instance().set(&OfflineStorageKey::AllBatches, index);
    }

    // ── Public API ───────────────────────────────────────────────────

    /// Initialize offline module configuration (idempotent).
    pub fn init_config(env: &Env) {
        let existing: Option<OfflineConfig> = env
            .storage()
            .instance()
            .get(&OfflineStorageKey::Config);
        if existing.is_none() {
            self.write_config(env, &OfflineConfig::default());
        }
    }

    /// Create offline transaction with signature and persist to storage.
    pub fn create_offline_transaction(
        env: &Env,
        transaction: CBDCTransaction,
        signature: Bytes,
        signer_pubkey: Bytes,
        nonce: u32,
    ) -> Result<OfflineTransaction, OfflineError> {
        if signature.is_empty() {
            return Err(OfflineError::EmptySignature);
        }
        if signer_pubkey.is_empty() {
            return Err(OfflineError::EmptySignerPubkey);
        }

        // Compute hash of transaction for offline verification
        let tx_hash = Self::compute_offline_tx_hash(env, &transaction, nonce);

        let offline_tx = OfflineTransaction {
            tx_hash: tx_hash.clone(),
            transaction,
            signature,
            signer_pubkey,
            status: OfflineStatus::PendingReconciliation as u32,
            created_at: env.ledger().timestamp(),
            reconciled_at: None,
            nonce,
        };

        // Persist transaction under its hash key.
        env.storage()
            .persistent()
            .set(&OfflineStorageKey::Transaction(tx_hash.clone()), &offline_tx);
        Self::maybe_bump_ttl(env, &OfflineStorageKey::Transaction(tx_hash.clone()));

        // Append to the ordered transaction index.
        let mut index = Self::read_tx_index(env);
        if !index.iter().any(|h| h == tx_hash) {
            index.push_back(tx_hash.clone());
            Self::write_tx_index(env, &index);
        }

        Ok(offline_tx)
    }

    /// Retrieve a persisted offline transaction by its hash.
    pub fn get_offline_transaction(
        env: &Env,
        tx_hash: &BytesN<32>,
    ) -> Result<OfflineTransaction, OfflineError> {
        env.storage()
            .persistent()
            .get(&OfflineStorageKey::Transaction(tx_hash.clone()))
            .ok_or(OfflineError::TransactionNotFound)
    }

    /// Validate offline transaction before reconciliation.
    pub fn validate_offline_transaction(
        tx: &OfflineTransaction,
    ) -> Result<(), OfflineError> {
        if !tx.has_valid_signature_format() {
            return Err(OfflineError::EmptySignature);
        }
        if tx.transaction.amount_source == 0 {
            return Err(OfflineError::ZeroAmount);
        }
        if tx.nonce == 0 {
            return Err(OfflineError::InvalidNonce);
        }
        Ok(())
    }

    /// Reconcile offline transaction to on-chain state and persist.
    pub fn reconcile_transaction(
        env: &Env,
        tx_hash: &BytesN<32>,
    ) -> Result<OfflineTransaction, OfflineError> {
        let mut offline_tx = Self::get_offline_transaction(env, tx_hash)?;
        if offline_tx.status != OfflineStatus::PendingReconciliation as u32 {
            return Err(OfflineError::NotPending);
        }

        offline_tx.status = OfflineStatus::Reconciled as u32;
        offline_tx.reconciled_at = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&OfflineStorageKey::Transaction(tx_hash.clone()), &offline_tx);
        Self::maybe_bump_ttl(env, &OfflineStorageKey::Transaction(tx_hash.clone()));

        Ok(offline_tx)
    }

    /// Mark transaction as failed reconciliation and persist.
    pub fn fail_reconciliation(
        env: &Env,
        tx_hash: &BytesN<32>,
    ) -> Result<OfflineTransaction, OfflineError> {
        let mut offline_tx = Self::get_offline_transaction(env, tx_hash)?;
        if offline_tx.status == OfflineStatus::Reconciled as u32 {
            return Err(OfflineError::AlreadyReconciled);
        }

        offline_tx.status = OfflineStatus::FailedReconciliation as u32;
        offline_tx.reconciled_at = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&OfflineStorageKey::Transaction(tx_hash.clone()), &offline_tx);
        Self::maybe_bump_ttl(env, &OfflineStorageKey::Transaction(tx_hash.clone()));

        Ok(offline_tx)
    }

    /// Create batch settlement from offline transaction IDs and persist.
    pub fn create_batch_settlement(
        env: &Env,
        tx_ids: Vec<BytesN<32>>,
        total_amount: u128,
    ) -> Result<BatchSettlement, OfflineError> {
        if tx_ids.len() == 0 {
            return Err(OfflineError::EmptyBatch);
        }
        if tx_ids.len() as u32 > MAX_BATCH_TRANSACTIONS {
            return Err(OfflineError::EmptyBatch);
        }
        if total_amount == 0 {
            return Err(OfflineError::ZeroBatchAmount);
        }

        let batch_id = Self::compute_batch_id(env, &tx_ids);

        let batch = BatchSettlement {
            batch_id: batch_id.clone(),
            transaction_ids: tx_ids,
            total_amount,
            settlement_status: OfflineStatus::PendingReconciliation as u32,
            created_at: env.ledger().timestamp(),
            settled_at: None,
        };

        env.storage()
            .persistent()
            .set(&OfflineStorageKey::Batch(batch_id.clone()), &batch);
        Self::maybe_bump_ttl(env, &OfflineStorageKey::Batch(batch_id.clone()));

        let mut index = Self::read_batch_index(env);
        if !index.iter().any(|h| h == batch_id) {
            index.push_back(batch_id.clone());
            Self::write_batch_index(env, &index);
        }

        Ok(batch)
    }

    /// Retrieve a persisted batch settlement by its ID.
    pub fn get_batch_settlement(
        env: &Env,
        batch_id: &BytesN<32>,
    ) -> Result<BatchSettlement, OfflineError> {
        env.storage()
            .persistent()
            .get(&OfflineStorageKey::Batch(batch_id.clone()))
            .ok_or(OfflineError::BatchNotFound)
    }

    /// Settle batch on-chain and persist.
    pub fn settle_batch(
        env: &Env,
        batch_id: &BytesN<32>,
    ) -> Result<BatchSettlement, OfflineError> {
        let mut batch = Self::get_batch_settlement(env, batch_id)?;
        if batch.settlement_status != OfflineStatus::PendingReconciliation as u32 {
            return Err(OfflineError::BatchNotPending);
        }

        batch.settlement_status = OfflineStatus::Reconciled as u32;
        batch.settled_at = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&OfflineStorageKey::Batch(batch_id.clone()), &batch);
        Self::maybe_bump_ttl(env, &OfflineStorageKey::Batch(batch_id.clone()));

        Ok(batch)
    }

    /// Detect and prevent replay attacks using nonce.
    pub fn verify_nonce(
        last_nonce: u32,
        current_nonce: u32,
    ) -> Result<(), OfflineError> {
        if current_nonce <= last_nonce {
            return Err(OfflineError::NonceReplay);
        }
        Ok(())
    }

    /// Compute reconciliation state from transaction statuses.
    pub fn compute_reconciliation_state(
        statuses: &Vec<u32>,
    ) -> ReconciliationState {
        let mut state = ReconciliationState::new();
        state.total_transactions = statuses.len() as u32;

        for status in statuses.iter() {
            match status {
                s if s == OfflineStatus::Reconciled as u32 => state.successful_count += 1,
                s if s == OfflineStatus::FailedReconciliation as u32 => state.failed_count += 1,
                s if s == OfflineStatus::PendingReconciliation as u32 => state.pending_count += 1,
                s if s == OfflineStatus::Disputed as u32 => state.disputed_count += 1,
                _ => {}
            }
        }

        state
    }

    /// Verify offline transaction integrity.
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

    // ── Deterministic cursor-based pagination & filtered reads ────────

    /// List offline transactions matching `filter`, paginated by `cursor`.
    ///
    /// Results are ordered by insertion order (transaction index order).
    /// The `cursor` offset is applied against the filtered result set so that
    /// pages are deterministic and repeatable for a static dataset.
    pub fn list_offline_transactions(
        env: &Env,
        cursor: Option<PaginationCursor>,
        filter: Option<OfflineTransactionFilter>,
    ) -> PaginatedTransactions {
        let filter = filter.unwrap_or_else(OfflineTransactionFilter::new);
        let page_size = filter.limit.clamp(1, MAX_PAGE_SIZE);
        let start_offset = cursor.map_or(0, |c| c.offset);

        let index = Self::read_tx_index(env);
        let mut matching: u32 = 0;
        let mut page: Vec<OfflineTransaction> = Vec::new(env);
        let mut next_cursor: Option<PaginationCursor> = None;

        for tx_hash in index.iter() {
            let tx: OfflineTransaction = match env
                .storage()
                .persistent()
                .get(&OfflineStorageKey::Transaction(tx_hash.clone()))
            {
                Some(t) => t,
                None => continue,
            };

            if !filter.matches(&tx) {
                continue;
            }

            if matching < start_offset {
                matching += 1;
                continue;
            }

            if page.len() as u32 >= page_size {
                next_cursor = Some(PaginationCursor {
                    offset: matching,
                });
                break;
            }

            page.push_back(tx);
            matching += 1;
        }

        // Total matching count requires a full scan when the page was truncated.
        let total_matching = if next_cursor.is_some() {
            // Count the rest to report the true total.
            let mut total = matching;
            let mut iter_started = false;
            for tx_hash in index.iter() {
                let tx: OfflineTransaction = match env
                    .storage()
                    .persistent()
                    .get(&OfflineStorageKey::Transaction(tx_hash.clone()))
                {
                    Some(t) => t,
                    None => continue,
                };
                if !filter.matches(&tx) {
                    continue;
                }
                if !iter_started {
                    // We've already counted up to `matching` above; skip re-counting.
                    iter_started = true;
                }
                total += 1;
            }
            // `total` currently overcounts by the page already counted; recompute cleanly.
            total
        } else {
            matching
        };

        // Recompute total_matching accurately with a single full pass when needed.
        let accurate_total: u32 = index
            .iter()
            .filter_map(|h| {
                env.storage()
                    .persistent()
                    .get(&OfflineStorageKey::Transaction(h.clone()))
            })
            .filter(|tx: &OfflineTransaction| filter.matches(tx))
            .count() as u32;

        PaginatedTransactions {
            transactions: page,
            next_cursor,
            total_matching: accurate_total,
            page_size: page.len() as u32,
        }
    }

    /// List batch settlements paginated by `cursor`, ordered by insertion order.
    pub fn list_batch_settlements(
        env: &Env,
        cursor: Option<PaginationCursor>,
        limit: Option<u32>,
    ) -> PaginatedBatchSettlements {
        let page_size = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
        let start_offset = cursor.map_or(0, |c| c.offset);

        let index = Self::read_batch_index(env);
        let mut page: Vec<BatchSettlement> = Vec::new(env);
        let mut matching: u32 = 0;
        let mut next_cursor: Option<PaginationCursor> = None;

        for batch_id in index.iter() {
            let batch: BatchSettlement = match env
                .storage()
                .persistent()
                .get(&OfflineStorageKey::Batch(batch_id.clone()))
            {
                Some(b) => b,
                None => continue,
            };

            if matching < start_offset {
                matching += 1;
                continue;
            }

            if page.len() as u32 >= page_size {
                next_cursor = Some(PaginationCursor {
                    offset: matching,
                });
                break;
            }

            page.push_back(batch);
            matching += 1;
        }

        let accurate_total: u32 = index
            .iter()
            .filter_map(|h| {
                env.storage()
                    .persistent()
                    .get(&OfflineStorageKey::Batch(h.clone()))
            })
            .count() as u32;

        PaginatedBatchSettlements {
            batches: page,
            next_cursor,
            total_matching: accurate_total,
            page_size: page.len() as u32,
        }
    }

    /// Add a transaction hash to the reconciliation queue (temporary or
    /// persistent storage depending on config).
    pub fn enqueue_reconciliation(
        env: &Env,
        tx_hash: BytesN<32>,
    ) -> Result<(), OfflineError> {
        let config = Self::read_config(env);
        let key = OfflineStorageKey::Queue;
        let mut queue: ReconciliationQueue = if config.queue_use_temporary {
            env.storage()
                .temporary()
                .get(&key)
                .unwrap_or_else(|| ReconciliationQueue::new(env, config.max_transactions_per_pilot))
        } else {
            env.storage()
                .persistent()
                .get(&key)
                .unwrap_or_else(|| ReconciliationQueue::new(env, config.max_transactions_per_pilot))
        };

        if queue.is_full() {
            return Err(OfflineError::QueueFull);
        }

        queue.add_transaction(tx_hash.clone())?;

        if config.queue_use_temporary {
            env.storage().temporary().set(&key, &queue);
        } else {
            env.storage().persistent().set(&key, &queue);
            Self::maybe_bump_ttl(env, &key);
        }

        Ok(())
    }

    /// Flush and clear the reconciliation queue.
    pub fn flush_queue(env: &Env, timestamp: u64) -> Result<Vec<BytesN<32>>, OfflineError> {
        let config = Self::read_config(env);
        let key = OfflineStorageKey::Queue;
        let mut queue: ReconciliationQueue = if config.queue_use_temporary {
            env.storage()
                .temporary()
                .get(&key)
                .unwrap_or_else(|| ReconciliationQueue::new(env, config.max_transactions_per_pilot))
        } else {
            env.storage()
                .persistent()
                .get(&key)
                .unwrap_or_else(|| ReconciliationQueue::new(env, config.max_transactions_per_pilot))
        };

        let hashes = queue.pending_tx_hashes.clone();
        queue.clear(timestamp);

        if config.queue_use_temporary {
            env.storage().temporary().set(&key, &queue);
        } else {
            env.storage().persistent().set(&key, &queue);
            Self::maybe_bump_ttl(env, &key);
        }

        Ok(hashes)
    }

    // ── Deterministic hashes ─────────────────────────────────────────

    /// Compute deterministic offline transaction hash.
    pub fn compute_offline_tx_hash(
        env: &Env,
        transaction: &CBDCTransaction,
        nonce: u32,
    ) -> BytesN<32> {
        let mut input = Bytes::new(env);

        input.append(&transaction.tx_id.to_bytes());
        input.append(&Bytes::from_slice(env, &transaction.source_pilot.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.dest_pilot.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.amount_source.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.amount_dest.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &transaction.exchange_rate.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &nonce.to_le_bytes()));

        env.crypto().sha256(&input).to_bytes()
    }

    /// Compute deterministic batch ID.
    pub fn compute_batch_id(env: &Env, tx_ids: &Vec<BytesN<32>>) -> BytesN<32> {
        let mut input = Bytes::new(env);

        for tx_id in tx_ids.iter() {
            input.append(&tx_id.to_bytes());
        }

        env.crypto().sha256(&input).to_bytes()
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

    #[test]
    fn test_cursor_pagination_roundtrip() {
        let env = Env::default();
        OfflineManager::init_config(&env);

        let addr = |env: &Env| Address::generate(env);
        let mut txs = Vec::new(&env);
        for i in 0..7u32 {
            let tx = OfflineTransaction {
                tx_hash: BytesN::from_array(&env, &[i; 32]),
                transaction: CBDCTransaction {
                    tx_id: BytesN::from_array(&env, &[i; 32]),
                    source_pilot: i % 2,
                    dest_pilot: (i + 1) % 2,
                    from: addr(&env),
                    to: addr(&env),
                    amount_source: 1000 * (i as u128 + 1),
                    amount_dest: 1200 * (i as u128 + 1),
                    exchange_rate: 1_200_000_000_000_000_000,
                    timestamp: 1000 + i as u64,
                    protocol: 0,
                    privacy_tier: 0,
                    offline_status: Some(0),
                    metadata: Bytes::new(&env),
                },
                signature: Bytes::from_slice(&env, b"sig"),
                signer_pubkey: Bytes::from_slice(&env, b"pk"),
                status: if i % 3 == 0 {
                    OfflineStatus::Reconciled as u32
                } else {
                    OfflineStatus::PendingReconciliation as u32
                },
                created_at: 1000 + i as u64,
                reconciled_at: None,
                nonce: i + 1,
            };
            env.storage()
                .persistent()
                .set(&OfflineStorageKey::Transaction(tx.tx_hash.clone()), &tx);
            let mut index = OfflineManager::read_tx_index(&env);
            index.push_back(tx.tx_hash.clone());
            OfflineManager::write_tx_index(&env, &index);
            txs.push(tx);
        }

        // Page 1: 3 items
        let page1 = OfflineManager::list_offline_transactions(
            &env,
            None,
            Some(OfflineTransactionFilter {
                limit: 3,
                ..OfflineTransactionFilter::new()
            }),
        );
        assert_eq!(page1.transactions.len(), 3);
        assert_eq!(page1.total_matching, 7);
        assert!(page1.next_cursor.is_some());

        // Page 2: next 3 items
        let page2 = OfflineManager::list_offline_transactions(
            &env,
            page1.next_cursor,
            Some(OfflineTransactionFilter {
                limit: 3,
                ..OfflineTransactionFilter::new()
            }),
        );
        assert_eq!(page2.transactions.len(), 3);
        assert!(page2.next_cursor.is_some());

        // Page 3: last 1 item
        let page3 = OfflineManager::list_offline_transactions(
            &env,
            page2.next_cursor,
            Some(OfflineTransactionFilter {
                limit: 3,
                ..OfflineTransactionFilter::new()
            }),
        );
        assert_eq!(page3.transactions.len(), 1);
        assert!(page3.next_cursor.is_none());
    }

    #[test]
    fn test_filtered_pagination() {
        let env = Env::default();
        OfflineManager::init_config(&env);

        let addr = |env: &Env| Address::generate(env);
        for i in 0..5u32 {
            let tx = OfflineTransaction {
                tx_hash: BytesN::from_array(&env, &[i; 32]),
                transaction: CBDCTransaction {
                    tx_id: BytesN::from_array(&env, &[i; 32]),
                    source_pilot: i % 2,
                    dest_pilot: (i + 1) % 2,
                    from: addr(&env),
                    to: addr(&env),
                    amount_source: 1000 * (i as u128 + 1),
                    amount_dest: 1200 * (i as u128 + 1),
                    exchange_rate: 1_200_000_000_000_000_000,
                    timestamp: 1000 + i as u64,
                    protocol: 0,
                    privacy_tier: 0,
                    offline_status: Some(0),
                    metadata: Bytes::new(&env),
                },
                signature: Bytes::from_slice(&env, b"sig"),
                signer_pubkey: Bytes::from_slice(&env, b"pk"),
                status: OfflineStatus::Reconciled as u32,
                created_at: 1000 + i as u64,
                reconciled_at: None,
                nonce: i + 1,
            };
            env.storage()
                .persistent()
                .set(&OfflineStorageKey::Transaction(tx.tx_hash.clone()), &tx);
            let mut index = OfflineManager::read_tx_index(&env);
            index.push_back(tx.tx_hash.clone());
            OfflineManager::write_tx_index(&env, &index);
        }

        // Filter: only source_pilot == 0
        let page = OfflineManager::list_offline_transactions(
            &env,
            None,
            Some(OfflineTransactionFilter {
                source_pilot: Some(0),
                limit: 10,
                ..OfflineTransactionFilter::new()
            }),
        );
        // i = 0, 2, 4 have source_pilot 0
        assert_eq!(page.total_matching, 3);
        assert_eq!(page.transactions.len(), 3);
        assert!(page.next_cursor.is_none());

        // Filter: status Reconciled + min_amount 2000
        let page = OfflineManager::list_offline_transactions(
            &env,
            None,
            Some(OfflineTransactionFilter {
                status: Some(OfflineStatus::Reconciled as u32),
                min_amount: Some(2000),
                limit: 10,
                ..OfflineTransactionFilter::new()
            }),
        );
        // i = 1, 2, 3, 4 have amount >= 2000 (amount = 1000*(i+1))
        assert_eq!(page.total_matching, 4);
    }

    #[test]
    fn test_create_and_reconcile_persisted() {
        let env = Env::default();
        OfflineManager::init_config(&env);

        let tx = CBDCTransaction {
            tx_id: BytesN::from_array(&env, &[1u8; 32]),
            source_pilot: 0,
            dest_pilot: 1,
            from: Address::generate(&env),
            to: Address::generate(&env),
            amount_source: 1000,
            amount_dest: 1200,
            exchange_rate: 1_200_000_000_000_000_000,
            timestamp: 1000,
            protocol: 0,
            privacy_tier: 0,
            offline_status: Some(0),
            metadata: Bytes::new(&env),
        };
        let signature = Bytes::from_slice(&env, b"signature");
        let signer_pubkey = Bytes::from_slice(&env, b"pubkey");

        let offline_tx = OfflineManager::create_offline_transaction(
            &env,
            tx,
            signature,
            signer_pubkey,
            1,
        )
        .unwrap();

        let fetched = OfflineManager::get_offline_transaction(&env, &offline_tx.tx_hash).unwrap();
        assert_eq!(fetched.tx_hash, offline_tx.tx_hash);
        assert_eq!(fetched.status, OfflineStatus::PendingReconciliation as u32);

        let reconciled = OfflineManager::reconcile_transaction(&env, &offline_tx.tx_hash).unwrap();
        assert_eq!(reconciled.status, OfflineStatus::Reconciled as u32);
        assert!(reconciled.reconciled_at.is_some());
    }

    #[test]
    fn test_batch_settlement_persisted() {
        let env = Env::default();
        OfflineManager::init_config(&env);

        let tx_ids = Vec::from_array(
            &env,
            &[
                BytesN::from_array(&env, &[1u8; 32]),
                BytesN::from_array(&env, &[2u8; 32]),
            ],
        );

        let batch = OfflineManager::create_batch_settlement(&env, tx_ids, 5000).unwrap();
        let fetched = OfflineManager::get_batch_settlement(&env, &batch.batch_id).unwrap();
        assert_eq!(fetched.batch_id, batch.batch_id);
        assert_eq!(fetched.total_amount, 5000);

        let settled = OfflineManager::settle_batch(&env, &batch.batch_id).unwrap();
        assert_eq!(settled.settlement_status, OfflineStatus::Reconciled as u32);
        assert!(settled.settled_at.is_some());
    }

    #[test]
    fn test_batch_pagination_roundtrip() {
        let env = Env::default();
        OfflineManager::init_config(&env);

        for i in 0..5u32 {
            let tx_ids = Vec::from_array(&env, &[BytesN::from_array(&env, &[i; 32])]);
            let batch = OfflineManager::create_batch_settlement(&env, tx_ids, 1000 * (i as u128 + 1)).unwrap();
            let mut index = OfflineManager::read_batch_index(&env);
            if !index.iter().any(|h| h == batch.batch_id) {
                index.push_back(batch.batch_id.clone());
                OfflineManager::write_batch_index(&env, &index);
            }
        }

        let page1 = OfflineManager::list_batch_settlements(&env, None, Some(2));
        assert_eq!(page1.batches.len(), 2);
        assert_eq!(page1.total_matching, 5);
        assert!(page1.next_cursor.is_some());

        let page2 = OfflineManager::list_batch_settlements(&env, page1.next_cursor, Some(2));
        assert_eq!(page2.batches.len(), 2);
        assert!(page2.next_cursor.is_some());

        let page3 = OfflineManager::list_batch_settlements(&env, page2.next_cursor, Some(2));
        assert_eq!(page3.batches.len(), 1);
        assert!(page3.next_cursor.is_none());
    }

    #[test]
    fn test_enqueue_and_flush_queue() {
        let env = Env::default();
        OfflineManager::init_config(&env);

        let h1 = BytesN::from_array(&env, &[1u8; 32]);
        let h2 = BytesN::from_array(&env, &[2u8; 32]);

        OfflineManager::enqueue_reconciliation(&env, h1.clone()).unwrap();
        OfflineManager::enqueue_reconciliation(&env, h2.clone()).unwrap();

        let flushed = OfflineManager::flush_queue(&env, 5000).unwrap();
        assert_eq!(flushed.len(), 2);
        assert!(flushed.iter().any(|h| h == h1));
        assert!(flushed.iter().any(|h| h == h2));

        // Queue is now empty.
        let flushed_again = OfflineManager::flush_queue(&env, 5001).unwrap();
        assert_eq!(flushed_again.len(), 0);
    }
}
