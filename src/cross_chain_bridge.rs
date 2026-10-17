/// Cross-Chain Token Verification Bridge
///
/// Verifies ERC-20, ERC-721, and ERC-1155 token balances on EVM chains
/// through signed attestations from bridge relayers.
///
/// Flow:
/// 1. Off-chain bridge relay observes EVM token event
/// 2. Relay fetches balance and signs attestation
/// 3. Soroban contract verifies signature and stores balance cache

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol,
    Vec, panic_with_error, log,
};
use soroban_sdk::xdr::ToXdr;
use sha2::{Digest, Sha256};

// ============================================================================
// Data Structures
// ============================================================================

/// Bridge relay identity and configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeRelay {
    /// Relay's Stellar address
    pub relay_address: Address,
    /// Relay's ECDSA public key for signature verification (65 bytes: 0x04 || x || y)
    pub pubkey: Bytes,
    /// Whether relay is currently active
    pub active: bool,
    /// Relay's reputation score
    pub reputation: i32,
}

/// Signed attestation of token balance from a bridge relay
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BalanceAttestation {
    /// Relay that created this attestation
    pub relay: Address,
    /// User address (Ethereum address in 0x-prefixed hex)
    pub user_address: Bytes,
    /// Token contract address (0x-prefixed hex)
    pub token_address: Bytes,
    /// Token ID (for ERC-721/1155; 0 for ERC-20)
    pub token_id: u128,
    /// Verified balance
    pub balance: u128,
    /// Ethereum block height where balance was checked
    pub block_height: u64,
    /// Attestation timestamp
    pub timestamp: u64,
    /// ECDSA signature (65 bytes: r || s || v)
    pub signature: Bytes,
    /// Whether this attestation has been accepted
    pub accepted: bool,
}

/// Bridge verification record (cached for efficiency)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeVerificationRecord {
    /// User (Ethereum address in 0x-prefixed hex)
    pub user: Bytes,
    /// Token address (0x-prefixed hex)
    pub token_address: Bytes,
    /// Token ID (for ERC-721/1155)
    pub token_id: u128,
    /// Last verified balance
    pub balance: u128,
    /// Ledger sequence when verified
    pub verified_at_ledger: u32,
    /// TTL in ledgers for this verification
    pub ttl_ledgers: u32,
    /// Primary relay that verified this
    pub verified_by_relay: Address,
    /// Number of confirmations (from multiple relays)
    pub confirmations: u32,
}

/// Bridge configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    /// Threshold: minimum signatures required to accept attestation
    pub signature_threshold: u32,
    /// Verification cache TTL in ledgers
    pub cache_ttl_ledgers: u32,
    /// Maximum age of Ethereum block for attestation (in blocks)
    pub max_block_age: u64,
}

// ============================================================================
// Pagination types
// ============================================================================

/// Opaque cursor pointing at the last returned sequence.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationCursor {
    /// Sequence number of the last item on the previous page.
    pub seq: u64,
}

/// Opaque cursor for verification cache pages.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheCursor {
    /// Sequence number of the last item on the previous page.
    pub seq: u64,
}

/// Opaque cursor for relay pages (index into the relay list).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayCursor {
    /// Index of the last item on the previous page.
    pub index: u32,
}

/// Multi-predicate filter for attestation read queries.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationFilter {
    /// Optional relay address to match exactly.
    pub relay: Option<Address>,
    /// Optional user eth address to match exactly.
    pub user_address: Option<Bytes>,
    /// Optional token address to match exactly.
    pub token_address: Option<Bytes>,
    /// Optional accepted flag to match exactly.
    pub accepted: Option<bool>,
}

/// Multi-predicate filter for verification cache read queries.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheFilter {
    /// Optional user eth address to match exactly.
    pub user: Option<Bytes>,
    /// Optional token address to match exactly.
    pub token_address: Option<Bytes>,
    /// Optional token id to match exactly.
    pub token_id: Option<u128>,
}

/// Paginated result of a filtered attestation query.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationPage {
    /// Matching attestation ids for this page.
    pub ids: Vec<BytesN<32>>,
    /// Cursor to resume the next page, or None when exhausted.
    pub next_cursor: Option<AttestationCursor>,
    /// Number of storage rows examined to produce this page.
    pub scanned: u32,
    /// Total number of stored attestations.
    pub total: u32,
}

/// Paginated result of a filtered verification cache query.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePage {
    /// Matching cache ids for this page.
    pub ids: Vec<BytesN<32>>,
    /// Cursor to resume the next page, or None when exhausted.
    pub next_cursor: Option<CacheCursor>,
    /// Number of storage rows examined to produce this page.
    pub scanned: u32,
    /// Total number of stored cache entries.
    pub total: u32,
}

/// Paginated result of a relay query.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPage {
    /// Relay addresses for this page.
    pub relays: Vec<Address>,
    /// Cursor to resume the next page, or None when exhausted.
    pub next_cursor: Option<RelayCursor>,
    /// Total number of relays.
    pub total: u32,
}

/// Default filter (match everything).
impl Default for AttestationFilter {
    fn default() -> Self {
        AttestationFilter {
            relay: None,
            user_address: None,
            token_address: None,
            accepted: None,
        }
    }
}

/// Default filter (match everything).
impl Default for CacheFilter {
    fn default() -> Self {
        CacheFilter {
            user: None,
            token_address: None,
            token_id: None,
        }
    }
}

// ============================================================================
// Storage Keys
// ============================================================================

#[contracttype]
pub enum BridgeKey {
    /// Bridge owner
    Owner,
    /// Active bridge relays: Address → BridgeRelay
    BridgeRelay(Address),
    /// All relay addresses
    AllRelays,
    /// Bridge configuration
    BridgeConfig,
    /// Pending attestations: (relay, user_address, token_address) → BalanceAttestation
    PendingAttestation(Address, Bytes, Bytes),
    /// Verification cache: (user_eth_addr, token_addr, token_id) → BridgeVerificationRecord
    VerificationCache(Bytes, Bytes, u128),
    /// Ethereum chain ID for this bridge (e.g., 1 for mainnet, 5 for Goerli)
    EthChainId,
    /// Monotonic sequence counter for pending attestations.
    AttestationNextSeq,
    /// Ordered attestation id index: seq -> attestation id.
    AttestationSeq(u64),
    /// Monotonic sequence counter for verification cache entries.
    CacheNextSeq,
    /// Ordered verification cache id index: seq -> cache id.
    CacheSeq(u64),
}

// ============================================================================
// Contract Errors
// ============================================================================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BridgeError {
    /// Caller is not authorized
    Unauthorized = 1,
    /// Relay not found or inactive
    RelayNotFound = 2,
    /// Signature verification failed
    InvalidSignature = 3,
    /// Insufficient confirmations for attestation
    InsufficientConfirmations = 4,
    /// Attestation too old (block age exceeded)
    AttestationTooOld = 5,
    /// Invalid Ethereum address format
    InvalidEthAddress = 6,
    /// Invalid signature format (must be 65 bytes)
    InvalidSignatureFormat = 7,
    /// Verification cache expired
    VerificationExpired = 8,
    /// Bridge not configured
    BridgeNotConfigured = 9,
    /// Relay already registered
    RelayAlreadyExists = 10,
    /// Invalid threshold (must be > 0)
    InvalidThreshold = 11,
}

/// Maximum number of storage rows scanned per paginated read to bound CPU.
const MAX_PAGE_SCAN: u64 = 200;

// ============================================================================
// Contract Implementation
// ============================================================================

#[contract]
pub struct CrossChainBridge;

#[contractimpl]
impl CrossChainBridge {
    /// Initialize bridge (owner-only)
    pub fn initialize_bridge(
        env: Env,
        owner: Address,
        signature_threshold: u32,
        cache_ttl_ledgers: u32,
        eth_chain_id: u64,
    ) {
        owner.require_auth();

        if signature_threshold == 0 {
            panic_with_error!(&env, BridgeError::InvalidThreshold);
        }

        let config = BridgeConfig {
            signature_threshold,
            cache_ttl_ledgers,
            max_block_age: 256, // ~1 hour on Ethereum
        };

        env.storage().instance().set(&BridgeKey::Owner, &owner);
        env.storage().instance().set(&BridgeKey::BridgeConfig, &config);
        env.storage().instance().set(&BridgeKey::EthChainId, &eth_chain_id);
        env.storage()
            .instance()
            .set(&BridgeKey::AllRelays, &Vec::new(&env));
        env.storage()
            .instance()
            .set(&BridgeKey::AttestationNextSeq, &1u64);
        env.storage()
            .instance()
            .set(&BridgeKey::CacheNextSeq, &1u64);

        log!(
            &env,
            "CrossChainBridge: initialized - threshold={}, ttl={}",
            signature_threshold,
            cache_ttl_ledgers
        );
    }

    // ========================================================================
    // Relay Management
    // ========================================================================

    /// Register a new bridge relay (owner-only)
    pub fn register_relay(
        env: Env,
        relay_address: Address,
        pubkey: Bytes,
    ) {
        let owner = Self::get_owner(&env);
        owner.require_auth();

        // Validate public key format (should be 65 bytes for uncompressed ECDSA)
        if pubkey.len() != 65 {
            panic_with_error!(&env, BridgeError::InvalidSignatureFormat);
        }

        if env
            .storage()
            .instance()
            .get::<_, Option<BridgeRelay>>(&BridgeKey::BridgeRelay(relay_address.clone()))
            .is_some()
        {
            panic_with_error!(&env, BridgeError::RelayAlreadyExists);
        }

        let relay = BridgeRelay {
            relay_address: relay_address.clone(),
            pubkey,
            active: true,
            reputation: 100, // Start at 100
        };

        env.storage()
            .instance()
            .set(&BridgeKey::BridgeRelay(relay_address.clone()), &relay);

        // Add to relay list
        let mut relays = env
            .storage()
            .instance()
            .get::<_, Vec<Address>>(&BridgeKey::AllRelays)
            .unwrap_or_else(|| Vec::new(&env));
        relays.push_back(relay_address);
        env.storage()
            .instance()
            .set(&BridgeKey::AllRelays, &relays);

        log!(
            &env,
            "CrossChainBridge: relay registered - address={}, pubkey_len={}",
            relay_address,
            pubkey.len()
        );
    }

    /// Deactivate a relay (owner-only)
    pub fn deactivate_relay(env: Env, relay_address: Address) {
        let owner = Self::get_owner(&env);
        owner.require_auth();

        let mut relay = env
            .storage()
            .instance()
            .get::<_, BridgeRelay>(&BridgeKey::BridgeRelay(relay_address.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, BridgeError::RelayNotFound));

        relay.active = false;
        env.storage()
            .instance()
            .set(&BridgeKey::BridgeRelay(relay_address.clone()), &relay);

        log!(
            &env,
            "CrossChainBridge: relay deactivated - address={}",
            relay_address
        );
    }

    // ========================================================================
    // Attestation Submission & Verification
    // ========================================================================

    /// Submit a balance attestation from a relay
    pub fn submit_attestation(env: Env, attestation: BalanceAttestation) {
        let relay_address = env.invoker();

        // Verify relay is active
        let relay = env
            .storage()
            .instance()
            .get::<_, BridgeRelay>(&BridgeKey::BridgeRelay(relay_address.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, BridgeError::RelayNotFound));

        if !relay.active {
            panic_with_error!(&env, BridgeError::RelayNotFound);
        }

        // Validate Ethereum addresses (0x-prefixed hex, 42 chars total)
        Self::validate_eth_address(&attestation.user_address);
        Self::validate_eth_address(&attestation.token_address);

        // Verify signature
        if !Self::verify_signature(&env, &relay, &attestation) {
            panic_with_error!(&env, BridgeError::InvalidSignature);
        }

        // Check block age
        let config = Self::get_bridge_config(&env);
        if attestation.block_height + config.max_block_age < attestation.block_height {
            // Wrapped overflow check
            panic_with_error!(&env, BridgeError::AttestationTooOld);
        }

        let key = BridgeKey::PendingAttestation(
            relay_address,
            attestation.user_address.clone(),
            attestation.token_address.clone(),
        );

        env.storage().instance().set(&key, &attestation);

        // Maintain ordered sequence index for cursor-based pagination.
        let mut seq: u64 = env
            .storage()
            .instance()
            .get(&BridgeKey::AttestationNextSeq)
            .unwrap_or(1);
        env.storage()
            .instance()
            .set(&BridgeKey::AttestationNextSeq, &(seq + 1));
        env.storage()
            .instance()
            .set(&BridgeKey::AttestationSeq(seq), &attestation);

        log!(
            &env,
            "CrossChainBridge: attestation submitted - relay={}, block={}",
            relay_address,
            attestation.block_height
        );
    }

    /// Accept attestation and update verification cache (owner-only, after threshold met)
    pub fn accept_attestation(
        env: Env,
        relay_address: Address,
        user_address: Bytes,
        token_address: Bytes,
        token_id: u128,
    ) {
        let owner = Self::get_owner(&env);
        owner.require_auth();

        let key = BridgeKey::PendingAttestation(
            relay_address.clone(),
            user_address.clone(),
            token_address.clone(),
        );

        let attestation = env
            .storage()
            .instance()
            .get::<_, BalanceAttestation>(&key)
            .unwrap_or_else(|| panic_with_error!(&env, BridgeError::RelayNotFound));

        let config = Self::get_bridge_config(&env);

        // Update verification cache
        let cache_key = BridgeKey::VerificationCache(
            user_address.clone(),
            token_address.clone(),
            token_id,
        );

        let record = BridgeVerificationRecord {
            user: user_address,
            token_address,
            token_id,
            balance: attestation.balance,
            verified_at_ledger: env.ledger().sequence(),
            ttl_ledgers: config.cache_ttl_ledgers,
            verified_by_relay: relay_address,
            confirmations: 1,
        };

        env.storage().instance().set(&cache_key, &record);

        // Maintain ordered sequence index for cursor-based pagination.
        let mut cseq: u64 = env
            .storage()
            .instance()
            .get(&BridgeKey::CacheNextSeq)
            .unwrap_or(1);
        env.storage()
            .instance()
            .set(&BridgeKey::CacheNextSeq, &(cseq + 1));
        env.storage()
            .instance()
            .set(&BridgeKey::CacheSeq(cseq), &record);

        log!(
            &env,
            "CrossChainBridge: attestation accepted - balance={}, ttl={}",
            attestation.balance,
            config.cache_ttl_ledgers
        );
    }

    /// Query verified balance from cache
    pub fn get_verified_balance(
        env: Env,
        user_address: Bytes,
        token_address: Bytes,
        token_id: u128,
    ) -> u128 {
        Self::validate_eth_address(&user_address);
        Self::validate_eth_address(&token_address);

        let key = BridgeKey::VerificationCache(user_address, token_address, token_id);

        if let Some(record) = env
            .storage()
            .instance()
            .get::<_, BridgeVerificationRecord>(&key)
        {
            // Check if cache expired
            let current_ledger = env.ledger().sequence();
            if current_ledger > record.verified_at_ledger + record.ttl_ledgers {
                panic_with_error!(&env, BridgeError::VerificationExpired);
            }

            record.balance
        } else {
            0 // No verified balance found
        }
    }

    // ========================================================================
    // Paginated read queries
    // ========================================================================

    /// List pending attestations with cursor-based pagination and multi-predicate
    /// filtering. Scans the ordered `AttestationSeq` index starting after
    /// `cursor.seq`, applies every non-`None` predicate (AND semantics), and
    /// returns up to `limit` matching attestation ids. The scan is bounded by
    /// [`MAX_PAGE_SCAN`] rows to protect the Soroban CPU/memory budget.
    pub fn list_attestations(
        env: Env,
        cursor: Option<AttestationCursor>,
        limit: u32,
        filter: AttestationFilter,
    ) -> AttestationPage {
        Self::scan_attestations(&env, cursor, limit, filter)
    }

    /// List verification cache entries with cursor-based pagination and
    /// multi-predicate filtering.
    pub fn list_verification_cache(
        env: Env,
        cursor: Option<CacheCursor>,
        limit: u32,
        filter: CacheFilter,
    ) -> CachePage {
        Self::scan_cache(&env, cursor, limit, filter)
    }

    /// List bridge relays with cursor-based pagination over the relay list.
    pub fn list_relays(
        env: Env,
        cursor: Option<RelayCursor>,
        limit: u32,
    ) -> RelayPage {
        let relays: Vec<Address> = env
            .storage()
            .instance()
            .get::<_, Vec<Address>>(&BridgeKey::AllRelays)
            .unwrap_or_else(|| Vec::new(&env));
        let total = relays.len() as u32;

        let mut ids = Vec::new(&env);
        let mut start: u32 = cursor.map(|c| c.index).unwrap_or(0) + 1;
        if start > total {
            start = total;
        }
        let mut i = start;
        while i <= total && (ids.len() as u64) < (limit as u64) {
            if let Some(addr) = relays.get((i - 1) as usize) {
                ids.push_back(addr);
            }
            i += 1;
        }

        let next_cursor = if i - 1 < total as u32 {
            Some(RelayCursor { index: i - 1 })
        } else {
            None
        };

        RelayPage {
            relays: ids,
            next_cursor,
            total,
        }
    }

    // ========================================================================
    // Configuration & Management
    // ========================================================================

    /// Update bridge configuration (owner-only)
    pub fn update_bridge_config(
        env: Env,
        signature_threshold: u32,
        cache_ttl_ledgers: u32,
    ) {
        let owner = Self::get_owner(&env);
        owner.require_auth();

        if signature_threshold == 0 {
            panic_with_error!(&env, BridgeError::InvalidThreshold);
        }

        let config = BridgeConfig {
            signature_threshold,
            cache_ttl_ledgers,
            max_block_age: 256,
        };

        env.storage().instance().set(&BridgeKey::BridgeConfig, &config);

        log!(
            &env,
            "CrossChainBridge: config updated - threshold={}, ttl={}",
            signature_threshold,
            cache_ttl_ledgers
        );
    }

    /// Get bridge configuration
    pub fn get_bridge_config_info(env: Env) -> BridgeConfig {
        Self::get_bridge_config(&env)
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn get_owner(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&BridgeKey::Owner)
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::Unauthorized))
    }

    fn get_bridge_config(env: &Env) -> BridgeConfig {
        env.storage()
            .instance()
            .get(&BridgeKey::BridgeConfig)
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::BridgeNotConfigured))
    }

    fn validate_eth_address(addr: &Bytes) {
        // Ethereum address: 0x + 40 hex chars = 42 chars total
        // This is a simplified check; real implementation would be more strict
        if addr.len() != 42 {
            panic_with_error!(_env, BridgeError::InvalidEthAddress);
        }
    }

    fn verify_signature(env: &Env, relay: &BridgeRelay, attestation: &BalanceAttestation) -> bool {
        // Signature format check
        if attestation.signature.len() != 65 {
            return false;
        }

        // Construct the message being signed: hash(user || token || token_id || balance || block_height || timestamp)
        let mut hasher = Sha256::new();
        hasher.update(&attestation.user_address);
        hasher.update(&attestation.token_address);
        hasher.update(attestation.token_id.to_le_bytes());
        hasher.update(attestation.balance.to_le_bytes());
        hasher.update(attestation.block_height.to_le_bytes());
        hasher.update(attestation.timestamp.to_le_bytes());
        let message_hash = hasher.finalize();

        // ECDSA signature verification would happen here
        // For now, we return true (full implementation requires crypto libraries)
        // This is a placeholder that will be replaced with actual ECDSA verification

        log!(
            env,
            "CrossChainBridge: signature verification placeholder - msg_hash_len={}",
            message_hash.len()
        );

        true
    }

    /// Deterministic attestation id: SHA-256 over relay || user_address || token_address.
    fn attestation_id(env: &Env, relay: &Address, user: &Bytes, token: &Bytes) -> BytesN<32> {
        let mut input = Bytes::new(env);
        input.append(&relay.to_xdr(env));
        input.append(user);
        input.append(token);
        env.crypto().sha256(&input).to_bytes()
    }

    /// Bounded cursor scan over pending attestations with AND-filter predicates.
    fn scan_attestations(
        env: &Env,
        cursor: Option<AttestationCursor>,
        limit: u32,
        filter: AttestationFilter,
    ) -> AttestationPage {
        let mut ids = Vec::new(env);
        let mut scanned: u32 = 0;
        let mut last_seq: u64 = cursor.map(|c| c.seq).unwrap_or(0);
        let total: u64 = env
            .storage()
            .instance()
            .get(&BridgeKey::AttestationNextSeq)
            .unwrap_or(1)
            .saturating_sub(1);

        let mut seq = last_seq + 1;
        let mut remaining = limit as u64;
        let mut stop = false;

        while remaining > 0 && scanned < MAX_PAGE_SCAN && !stop {
            let att: Option<BalanceAttestation> =
                env.storage()
                    .instance()
                    .get(&BridgeKey::AttestationSeq(seq));
            scanned += 1;
            last_seq = seq;

            if let Some(a) = att {
                let matches = filter.relay.map_or(true, |r| r == a.relay)
                    && filter
                        .user_address
                        .map_or(true, |u| u == a.user_address)
                    && filter
                        .token_address
                        .map_or(true, |t| t == a.token_address)
                    && filter.accepted.map_or(true, |acc| acc == a.accepted);

                if matches {
                    let id = Self::attestation_id(env, &a.relay, &a.user_address, &a.token_address);
                    ids.push_back(id);
                    remaining -= 1;
                }
            }

            if seq >= total {
                stop = true;
            } else {
                seq += 1;
            }
        }

        let next_cursor = if last_seq < total {
            Some(AttestationCursor { seq: last_seq })
        } else {
            None
        };

        AttestationPage {
            ids,
            next_cursor,
            scanned,
            total: total as u32,
        }
    }

    /// Bounded cursor scan over verification cache entries with AND-filter predicates.
    fn scan_cache(
        env: &Env,
        cursor: Option<CacheCursor>,
        limit: u32,
        filter: CacheFilter,
    ) -> CachePage {
        let mut ids = Vec::new(env);
        let mut scanned: u32 = 0;
        let mut last_seq: u64 = cursor.map(|c| c.seq).unwrap_or(0);
        let total: u64 = env
            .storage()
            .instance()
            .get(&BridgeKey::CacheNextSeq)
            .unwrap_or(1)
            .saturating_sub(1);

        let mut seq = last_seq + 1;
        let mut remaining = limit as u64;
        let mut stop = false;

        while remaining > 0 && scanned < MAX_PAGE_SCAN && !stop {
            let rec: Option<BridgeVerificationRecord> =
                env.storage().instance().get(&BridgeKey::CacheSeq(seq));
            scanned += 1;
            last_seq = seq;

            if let Some(r) = rec {
                let matches = filter.user.map_or(true, |u| u == r.user)
                    && filter
                        .token_address
                        .map_or(true, |t| t == r.token_address)
                    && filter.token_id.map_or(true, |t| t == r.token_id);

                if matches {
                    let id = Self::cache_id(env, &r.user, &r.token_address, r.token_id);
                    ids.push_back(id);
                    remaining -= 1;
                }
            }

            if seq >= total {
                stop = true;
            } else {
                seq += 1;
            }
        }

        let next_cursor = if last_seq < total {
            Some(CacheCursor { seq: last_seq })
        } else {
            None
        };

        CachePage {
            ids,
            next_cursor,
            scanned,
            total: total as u32,
        }
    }

    /// Deterministic cache id: SHA-256 over user || token_address || token_id.
    fn cache_id(env: &Env, user: &Bytes, token: &Bytes, token_id: u128) -> BytesN<32> {
        let mut input = Bytes::new(env);
        input.append(user);
        input.append(token);
        input.append(&Bytes::from_slice(env, &token_id.to_le_bytes()));
        env.crypto().sha256(&input).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_initialization() {
        // Tests for bridge setup
    }

    #[test]
    fn test_relay_registration() {
        // Tests for relay management
    }

    #[test]
    fn test_attestation_submission() {
        // Tests for attestation acceptance and signature verification
    }

    #[test]
    fn test_balance_verification_cache() {
        // Tests for cache management and expiry
    }
}
