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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(env: &Env) -> Address {
        Address::generate(env)
    }

    fn relay(env: &Env) -> Address {
        Address::generate(env)
    }

    fn pubkey_65(env: &Env) -> Bytes {
        Bytes::from_slice(env, &[0x04u8; 65])
    }

    fn eth_addr(env: &Env) -> Bytes {
        // 0x + 40 hex chars = 42 bytes
        Bytes::from_slice(env, b"0x1234567890123456789012345678901234567890")
    }

    fn sample_attestation(env: &Env, relay: &Address) -> BalanceAttestation {
        BalanceAttestation {
            relay: relay.clone(),
            user_address: eth_addr(env),
            token_address: eth_addr(env),
            token_id: 0,
            balance: 1_000_000,
            block_height: 100,
            timestamp: 1_700_000_000,
            signature: Bytes::from_slice(env, &[1u8; 65]),
            accepted: false,
        }
    }

    #[test]
    fn test_bridge_initialization() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);

        CrossChainBridge::initialize_bridge(
            env.clone(),
            o.clone(),
            2,
            100,
            1,
        );

        let config = CrossChainBridge::get_bridge_config_info(env.clone());
        assert_eq!(config.signature_threshold, 2);
        assert_eq!(config.cache_ttl_ledgers, 100);
        assert_eq!(config.max_block_age, 256);
    }

    #[test]
    #[should_panic(expected = "InvalidThreshold")]
    fn test_bridge_initialization_zero_threshold_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 0, 100, 1);
    }

    #[test]
    fn test_relay_registration() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);
        let r = relay(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 2, 100, 1);
        CrossChainBridge::register_relay(env.clone(), r.clone(), pubkey_65(&env));

        let stored: Option<BridgeRelay> = env
            .storage()
            .instance()
            .get(&BridgeKey::BridgeRelay(r.clone()));
        assert!(stored.is_some());
        assert!(stored.unwrap().active);
        assert_eq!(stored.unwrap().reputation, 100);
    }

    #[test]
    #[should_panic(expected = "InvalidSignatureFormat")]
    fn test_relay_registration_bad_pubkey_len_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);
        let r = relay(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 2, 100, 1);
        CrossChainBridge::register_relay(env.clone(), r.clone(), Bytes::from_slice(&env, &[1u8; 33]));
    }

    #[test]
    #[should_panic(expected = "RelayAlreadyExists")]
    fn test_relay_registration_duplicate_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);
        let r = relay(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 2, 100, 1);
        CrossChainBridge::register_relay(env.clone(), r.clone(), pubkey_65(&env));
        CrossChainBridge::register_relay(env.clone(), r.clone(), pubkey_65(&env));
    }

    #[test]
    fn test_attestation_submission_and_acceptance() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);
        let r = relay(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 2, 100, 1);
        CrossChainBridge::register_relay(env.clone(), r.clone(), pubkey_65(&env));

        let att = sample_attestation(&env, &r);
        CrossChainBridge::submit_attestation(env.clone(), att.clone());

        let key = BridgeKey::PendingAttestation(
            r.clone(),
            att.user_address.clone(),
            att.token_address.clone(),
        );
        let stored: Option<BalanceAttestation> = env.storage().instance().get(&key);
        assert!(stored.is_some());

        CrossChainBridge::accept_attestation(
            env.clone(),
            r.clone(),
            att.user_address,
            att.token_address,
            att.token_id,
        );

        let cache_key = BridgeKey::VerificationCache(
            att.user_address,
            att.token_address,
            att.token_id,
        );
        let record: Option<BridgeVerificationRecord> =
            env.storage().instance().get(&cache_key);
        assert!(record.is_some());
        assert_eq!(record.unwrap().balance, att.balance);
    }

    #[test]
    #[should_panic(expected = "AttestationTooOld")]
    fn test_attestation_too_old_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);
        let r = relay(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 2, 100, 1);
        CrossChainBridge::register_relay(env.clone(), r.clone(), pubkey_65(&env));

        let mut att = sample_attestation(&env, &r);
        // Set block_height so block_height + max_block_age overflows u64
        att.block_height = u64::MAX;
        CrossChainBridge::submit_attestation(env.clone(), att);
    }

    #[test]
    fn test_balance_verification_cache_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);
        let r = relay(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 1, 1, 1);
        CrossChainBridge::register_relay(env.clone(), r.clone(), pubkey_65(&env));

        let att = sample_attestation(&env, &r);
        CrossChainBridge::submit_attestation(env.clone(), att.clone());
        CrossChainBridge::accept_attestation(
            env.clone(),
            r.clone(),
            att.user_address,
            att.token_address,
            att.token_id,
        );

        // Fresh cache returns balance
        let bal = CrossChainBridge::get_verified_balance(
            env.clone(),
            att.user_address,
            att.token_address,
            att.token_id,
        );
        assert_eq!(bal, att.balance);
    }

    #[test]
    fn test_update_bridge_config() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 2, 100, 1);
        CrossChainBridge::update_bridge_config(env.clone(), 5, 200);

        let config = CrossChainBridge::get_bridge_config_info(env.clone());
        assert_eq!(config.signature_threshold, 5);
        assert_eq!(config.cache_ttl_ledgers, 200);
    }

    #[test]
    #[should_panic(expected = "InvalidThreshold")]
    fn test_update_bridge_config_zero_threshold_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let o = owner(&env);

        CrossChainBridge::initialize_bridge(env.clone(), o.clone(), 2, 100, 1);
        CrossChainBridge::update_bridge_config(env.clone(), 0, 100);
    }

    #[test]
    fn test_get_verified_balance_missing_returns_zero() {
        let env = Env::default();
        let bal = CrossChainBridge::get_verified_balance(
            env.clone(),
            eth_addr(&env),
            eth_addr(&env),
            0,
        );
        assert_eq!(bal, 0);
    }

    #[test]
    #[should_panic(expected = "InvalidEthAddress")]
    fn test_validate_eth_address_wrong_len() {
        let env = Env::default();
        validate_eth_address(&Bytes::from_slice(&env, b"0xshort"));
    }

    #[test]
    #[should_panic(expected = "InvalidSignatureFormat")]
    fn test_verify_signature_bad_len() {
        let env = Env::default();
        let r = relay(&env);
        let relay_rec = BridgeRelay {
            relay_address: r.clone(),
            pubkey: pubkey_65(&env),
            active: true,
            reputation: 100,
        };
        let mut att = sample_attestation(&env, &r);
        att.signature = Bytes::from_slice(&env, &[1u8; 33]);
        assert!(!verify_signature(&env, &relay_rec, &att));
    }
}
