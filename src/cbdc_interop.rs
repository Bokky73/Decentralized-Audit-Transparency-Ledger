#![no_std]

//! CBDC cross-ledger settlement and ISO-20022 message bridge.
//!
//! # Determinism & overflow safety
//!
//! All arithmetic in this module uses `checked_*` / `saturating_*` helpers.
//! Boundary violations return typed [`InteropError`] variants instead of
//! panicking, so the contract never aborts on adversarial input.
//!
//! # Storage footprint (worst case)
//!
//! * [`ExchangeRate`]: 2 × u32 + 3 × u128 + u64 + u32 = 8 + 48 + 8 + 4 = 68 bytes
//!   of XDR payload (plus enum/struct discriminants).
//! * [`SettlementInstruction`]: `BytesN<32>` + `CBDCTransaction` + 2 × u32 +
//!   u64 + `Option<BytesN<32>>` ≈ 32 + 96 + 8 + 8 + 33 = 177 bytes.
//! * [`SettlementPath`]: bounded by [`MAX_PATH_HOPS`] hops and
//!   [`MAX_RATES_LEN`] rates; worst case ≈ 2 + 32 + 16 × 16 + 4 = 294 bytes.
//!
//! # CPU instruction bounds (worst case)
//!
//! * [`InteropManager::convert_amount`]: O(1), ≤ 2 checked mul/div.
//! * [`SettlementPath::compute_final_amount`]: O([`MAX_PATH_HOPS`]) conversions,
//!   ≤ 2 × [`MAX_PATH_HOPS`] checked mul/div.
//! * [`InteropManager::execute_atomic_swap`] / `execute_hub_and_spoke`: one
//!   SHA-256 over a bounded input (≤ 128 bytes).
//!
//! # TTL policy
//!
//! * [`ExchangeRate`] and [`SettlementInstruction`] are archival-critical and
//!   stored in `Persistent` storage; use [`InteropManager::extend_ttl`] to bump
//!   their TTL before expiry.
//! * [`SettlementPath`] is derived/ephemeral and stored in `Temporary` storage.
//! * Module-level configuration lives in `Instance` storage.

use crate::cbdc_types::{CBDCTransaction, InteropProtocol};
use soroban_sdk::{contracterror, contracttype, Address, Bytes, BytesN, Env, Symbol};
use soroban_sdk::xdr::ToXdr;

/// Maximum number of hops allowed in a [`SettlementPath`].
pub const MAX_PATH_HOPS: u32 = 16;
/// Maximum number of exchange rates allowed in a [`SettlementPath`].
pub const MAX_RATES_LEN: u32 = 16;
/// Minimum number of pilots required for a valid [`SettlementPath`].
pub const MIN_PATH_HOPS: u32 = 2;
/// Maximum basis points (100%).
pub const MAX_BPS: u32 = 10_000;
/// Scale factor for exchange rates (1e18).
pub const RATE_SCALE: u128 = 1_000_000_000_000_000_000;
/// Default TTL extension (in ledgers) for archival-critical records.
pub const DEFAULT_TTL_EXTEND_LEDGERS: u32 = 100_000;
/// Threshold (in ledgers) below which archival-critical records are bumped.
pub const TTL_BUMP_THRESHOLD_LEDGERS: u32 = 10_000;

/// Typed contract errors for the CBDC interop module.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum InteropError {
    /// Exchange rate is stale.
    StaleRate = 1,
    /// Exchange rate is zero.
    ZeroRate = 2,
    /// Bid/ask price is zero.
    ZeroPrice = 3,
    /// Bid price exceeds ask price.
    BidExceedsAsk = 4,
    /// Amount is zero.
    ZeroAmount = 5,
    /// Arithmetic overflow during conversion.
    ConversionOverflow = 6,
    /// Division by zero during conversion.
    DivisionByZero = 7,
    /// Fee basis points exceed [`MAX_BPS`].
    FeeBpsTooHigh = 8,
    /// Fee calculation overflow.
    FeeOverflow = 9,
    /// Settlement amounts are zero.
    ZeroSettlementAmount = 10,
    /// Settlement exchange rate is zero.
    ZeroSettlementRate = 11,
    /// Path has fewer than [`MIN_PATH_HOPS`] pilots.
    PathTooShort = 12,
    /// Path exceeds [`MAX_PATH_HOPS`] hops.
    PathTooLong = 13,
    /// Rates vector exceeds [`MAX_RATES_LEN`] entries.
    RatesTooLong = 14,
    /// Path length does not match rates length.
    PathLengthMismatch = 15,
    /// Source and destination pilots are identical.
    SamePilot = 16,
    /// Pilot identifier is out of range.
    InvalidPilot = 17,
    /// Spread computation overflowed.
    SpreadOverflow = 18,
}

/// Exchange rate between two CBDC pilots.
///
/// Field order is chosen to minimize XDR padding: small integers first,
/// then the wide `u128` values.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeRate {
    /// Source CBDC pilot
    pub source_pilot: u32, // CBDCPilot as u8
    /// Destination CBDC pilot
    pub dest_pilot: u32, // CBDCPilot as u8
    /// Maximum volatility tolerated (percentage * 100)
    pub max_volatility: u32,
    /// Timestamp of rate (for staleness checks)
    pub timestamp: u64,
    /// Rate scaled by 1e18 for precision
    pub rate: u128,
    /// Bid price (lower)
    pub bid_price: u128,
    /// Ask price (higher)
    pub ask_price: u128,
}

impl ExchangeRate {
    /// Check if rate is stale (older than 1 hour by default)
    pub fn is_stale(&self, current_time: u64, staleness_threshold: u64) -> bool {
        current_time.saturating_sub(self.timestamp) > staleness_threshold
    }

    /// Compute mid-price between bid and ask (saturating).
    pub fn mid_price(&self) -> u128 {
        self.bid_price.saturating_add(self.ask_price) / 2
    }

    /// Apply spread from mid-price. Returns a typed error on overflow.
    pub fn spread_bps(&self) -> Result<u128, InteropError> {
        let mid = self.mid_price();
        if mid == 0 {
            return Ok(0);
        }
        let diff = self.ask_price.saturating_sub(self.bid_price);
        let scaled = diff
            .checked_mul(MAX_BPS as u128)
            .ok_or(InteropError::SpreadOverflow)?;
        Ok(scaled / mid)
    }
}

/// Represents a settlement instruction for cross-CBDC transfer.
///
/// Stored in `Persistent` storage (archival-critical audit record).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementInstruction {
    /// Settlement ID
    pub settlement_id: BytesN<32>,
    /// Source transaction
    pub transaction: CBDCTransaction,
    /// Interoperability protocol
    pub protocol: u32, // InteropProtocol as u8
    /// Settlement status
    pub status: u32, // SettlementStatus as u8
    /// Settlement timestamp
    pub timestamp: u64,
    /// Confirmation hash from destination ledger
    pub confirmation_hash: Option<BytesN<32>>,
}

/// Settlement status enumeration.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SettlementStatus {
    /// Instruction created, awaiting execution
    Created = 0,
    /// Settlement initiated on source ledger
    InitiatedSource = 1,
    /// Settlement confirmed on source ledger
    ConfirmedSource = 2,
    /// Settlement awaiting confirmation on destination
    AwaitingDestination = 3,
    /// Settlement completed on both ledgers
    Completed = 4,
    /// Settlement failed or disputed
    Failed = 5,
}

impl SettlementStatus {
    pub fn as_symbol(&self, env: &Env) -> Symbol {
        match self {
            SettlementStatus::Created => Symbol::new(env, "CREATED"),
            SettlementStatus::InitiatedSource => Symbol::new(env, "INIT_SRC"),
            SettlementStatus::ConfirmedSource => Symbol::new(env, "CONF_SRC"),
            SettlementStatus::AwaitingDestination => Symbol::new(env, "AWAIT_DST"),
            SettlementStatus::Completed => Symbol::new(env, "COMPLETE"),
            SettlementStatus::Failed => Symbol::new(env, "FAILED"),
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, SettlementStatus::Completed | SettlementStatus::Failed)
    }
}

/// Interoperability operation manager.
pub struct InteropManager;

impl InteropManager {
    /// Validate exchange rate for transaction
    pub fn validate_exchange_rate(
        rate: &ExchangeRate,
        current_time: u64,
        staleness_threshold: u64,
    ) -> Result<(), InteropError> {
        if rate.is_stale(current_time, staleness_threshold) {
            return Err(InteropError::StaleRate);
        }
        if rate.rate == 0 {
            return Err(InteropError::ZeroRate);
        }
        if rate.bid_price == 0 || rate.ask_price == 0 {
            return Err(InteropError::ZeroPrice);
        }
        if rate.bid_price > rate.ask_price {
            return Err(InteropError::BidExceedsAsk);
        }
        Ok(())
    }

    /// Convert amount using exchange rate
    pub fn convert_amount(amount: u128, rate: u128) -> Result<u128, InteropError> {
        if rate == 0 {
            return Err(InteropError::ZeroRate);
        }
        if amount == 0 {
            return Err(InteropError::ZeroAmount);
        }

        // Calculate: (amount * rate) / 1e18, handling overflow
        let scaled_amount = amount
            .checked_mul(rate)
            .ok_or(InteropError::ConversionOverflow)?
            .checked_div(RATE_SCALE)
            .ok_or(InteropError::DivisionByZero)?;

        Ok(scaled_amount)
    }

    /// Execute atomic swap protocol
    pub fn execute_atomic_swap(
        env: &Env,
        from: &Address,
        to: &Address,
        source_amount: u128,
        dest_amount: u128,
        _timeout_ledgers: u32,
    ) -> Result<BytesN<32>, InteropError> {
        if source_amount == 0 || dest_amount == 0 {
            return Err(InteropError::ZeroAmount);
        }

        // Generate swap ID
        let mut input = Bytes::new(env);
        input.append(&from.to_xdr(env));
        input.append(&to.to_xdr(env));
        input.append(&Bytes::from_slice(env, &source_amount.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &dest_amount.to_le_bytes()));

        Ok(env.crypto().sha256(&input).to_bytes())
    }

    /// Execute hub-and-spoke settlement
    pub fn execute_hub_and_spoke(
        env: &Env,
        hub_address: &Address,
        source_amount: u128,
        dest_amount: u128,
    ) -> Result<BytesN<32>, InteropError> {
        if source_amount == 0 || dest_amount == 0 {
            return Err(InteropError::ZeroAmount);
        }

        // Generate settlement ID
        let mut input = Bytes::new(env);
        input.append(&hub_address.to_xdr(env));
        input.append(&Bytes::from_slice(env, &source_amount.to_le_bytes()));
        input.append(&Bytes::from_slice(env, &dest_amount.to_le_bytes()));

        Ok(env.crypto().sha256(&input).to_bytes())
    }

    /// Validate settlement instruction
    pub fn validate_settlement_instruction(
        instruction: &SettlementInstruction,
    ) -> Result<(), InteropError> {
        if instruction.transaction.amount_source == 0 || instruction.transaction.amount_dest == 0
        {
            return Err(InteropError::ZeroSettlementAmount);
        }
        if instruction.transaction.exchange_rate == 0 {
            return Err(InteropError::ZeroSettlementRate);
        }
        Ok(())
    }

    /// Permissionless TTL extension for archival-critical records.
    ///
    /// Bumps the TTL of the given persistent storage key so active audit
    /// records are never unexpectedly archived. Safe to call by anyone.
    pub fn extend_ttl(env: &Env, key: &Symbol) {
        env.storage().persistent().extend_ttl(
            key,
            TTL_BUMP_THRESHOLD_LEDGERS,
            DEFAULT_TTL_EXTEND_LEDGERS,
        );
    }

    /// Get protocol version string
    pub fn protocol_version(protocol: InteropProtocol) -> &'static str {
        protocol.version()
    }

    /// Determine settlement status transition validity
    pub fn is_valid_status_transition(
        from: SettlementStatus,
        to: SettlementStatus,
    ) -> bool {
        match (from, to) {
            (SettlementStatus::Created, SettlementStatus::InitiatedSource) => true,
            (SettlementStatus::InitiatedSource, SettlementStatus::ConfirmedSource) => true,
            (SettlementStatus::ConfirmedSource, SettlementStatus::AwaitingDestination) => true,
            (SettlementStatus::AwaitingDestination, SettlementStatus::Completed) => true,
            (SettlementStatus::AwaitingDestination, SettlementStatus::Failed) => true,
            (_, SettlementStatus::Failed) => true, // Can fail from any state
            _ => false,
        }
    }

    /// Compute settlement fee based on amount
    pub fn compute_settlement_fee(amount: u128, fee_bps: u32) -> Result<u128, InteropError> {
        if fee_bps > MAX_BPS {
            return Err(InteropError::FeeBpsTooHigh);
        }

        let fee = amount
            .checked_mul(fee_bps as u128)
            .ok_or(InteropError::FeeOverflow)?
            .checked_div(MAX_BPS as u128)
            .ok_or(InteropError::DivisionByZero)?;

        Ok(fee)
    }

    /// Validate cross-pilot compatibility
    pub fn validate_pilot_pair(source: u8, dest: u8) -> Result<(), InteropError> {
        if source == dest {
            return Err(InteropError::SamePilot);
        }
        if source > 3 || dest > 3 {
            return Err(InteropError::InvalidPilot);
        }
        Ok(())
    }
}

/// Settlement path finding for multi-hop transfers.
///
/// Stored in `Temporary` storage (derived/ephemeral routing data).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementPath {
    /// Sequence of pilots in path (e.g., [EUR, USD, CNY])
    pub path: Bytes,
    /// Exchange rates for each hop
    pub rates: soroban_sdk::Vec<u128>,
    /// Total cost in basis points
    pub total_cost_bps: u32,
}

impl SettlementPath {
    /// Calculate final amount after all conversions.
    ///
    /// Enforces [`MIN_PATH_HOPS`], [`MAX_PATH_HOPS`] and [`MAX_RATES_LEN`]
    /// bounds before iterating, returning typed errors on violation.
    pub fn compute_final_amount(&self, initial_amount: u128) -> Result<u128, InteropError> {
        let path_len = self.path.len();
        let rates_len = self.rates.len();

        if path_len < MIN_PATH_HOPS {
            return Err(InteropError::PathTooShort);
        }
        if path_len > MAX_PATH_HOPS {
            return Err(InteropError::PathTooLong);
        }
        if rates_len > MAX_RATES_LEN {
            return Err(InteropError::RatesTooLong);
        }
        if path_len != rates_len {
            return Err(InteropError::PathLengthMismatch);
        }

        let mut amount = initial_amount;
        for rate in self.rates.iter() {
            amount = InteropManager::convert_amount(amount, rate)?;
        }

        Ok(amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exchange_rate_validation() {
        let rate = ExchangeRate {
            source_pilot: 0,
            dest_pilot: 1,
            max_volatility: 500,
            timestamp: 1000,
            rate: 1_000_000_000_000_000_000,
            bid_price: 0_950_000_000_000_000_000,
            ask_price: 1_050_000_000_000_000_000,
        };

        assert!(InteropManager::validate_exchange_rate(&rate, 2000, 3600).is_ok());
        assert_eq!(
            InteropManager::validate_exchange_rate(&rate, 10000, 3600),
            Err(InteropError::StaleRate)
        );
    }

    #[test]
    fn test_conversion_calculation() {
        let amount = 1_000_000_000_000_000_000u128; // 1e18
        let rate = 1_200_000_000_000_000_000u128; // 1.2x rate

        let result = InteropManager::convert_amount(amount, rate).unwrap();
        assert_eq!(result, 1_200_000_000_000_000_000);
    }

    #[test]
    fn test_conversion_overflow_returns_typed_error() {
        assert_eq!(
            InteropManager::convert_amount(u128::MAX, u128::MAX),
            Err(InteropError::ConversionOverflow)
        );
        assert_eq!(
            InteropManager::convert_amount(0, 1),
            Err(InteropError::ZeroAmount)
        );
        assert_eq!(
            InteropManager::convert_amount(1, 0),
            Err(InteropError::ZeroRate)
        );
    }

    #[test]
    fn test_settlement_fee_calculation() {
        let amount = 1_000_000u128;
        let fee_bps = 25; // 0.25%

        let fee = InteropManager::compute_settlement_fee(amount, fee_bps).unwrap();
        assert_eq!(fee, 250);
    }

    #[test]
    fn test_settlement_fee_boundaries() {
        assert_eq!(
            InteropManager::compute_settlement_fee(1, MAX_BPS + 1),
            Err(InteropError::FeeBpsTooHigh)
        );
        assert_eq!(
            InteropManager::compute_settlement_fee(u128::MAX, MAX_BPS),
            Err(InteropError::FeeOverflow)
        );
    }

    #[test]
    fn test_spread_bps_overflow_is_typed() {
        let rate = ExchangeRate {
            source_pilot: 0,
            dest_pilot: 1,
            max_volatility: 0,
            timestamp: 0,
            rate: 1,
            bid_price: 0,
            ask_price: u128::MAX,
        };
        assert_eq!(rate.spread_bps(), Err(InteropError::SpreadOverflow));
    }

    #[test]
    fn test_status_transitions() {
        assert!(InteropManager::is_valid_status_transition(
            SettlementStatus::Created,
            SettlementStatus::InitiatedSource
        ));
        assert!(!InteropManager::is_valid_status_transition(
            SettlementStatus::Created,
            SettlementStatus::Completed
        ));
        assert!(InteropManager::is_valid_status_transition(
            SettlementStatus::AwaitingDestination,
            SettlementStatus::Failed
        ));
    }

    #[test]
    fn test_pilot_pair_boundaries() {
        assert_eq!(
            InteropManager::validate_pilot_pair(1, 1),
            Err(InteropError::SamePilot)
        );
        assert_eq!(
            InteropManager::validate_pilot_pair(0, 4),
            Err(InteropError::InvalidPilot)
        );
        assert!(InteropManager::validate_pilot_pair(0, 3).is_ok());
    }

    #[test]
    fn test_path_bounds_enforced() {
        let env = Env::default();

        // Too short
        let short = SettlementPath {
            path: Bytes::from_slice(&env, &[0u8]),
            rates: soroban_sdk::Vec::new(&env),
            total_cost_bps: 0,
        };
        assert_eq!(
            short.compute_final_amount(1),
            Err(InteropError::PathTooShort)
        );

        // Length mismatch
        let mismatch = SettlementPath {
            path: Bytes::from_slice(&env, &[0u8, 1u8]),
            rates: soroban_sdk::Vec::new(&env),
            total_cost_bps: 0,
        };
        assert_eq!(
            mismatch.compute_final_amount(1),
            Err(InteropError::PathLengthMismatch)
        );

        // Rates vector too long
        let mut rates = soroban_sdk::Vec::new(&env);
        for _ in 0..(MAX_RATES_LEN + 1) {
            rates.push_back(RATE_SCALE);
        }
        let too_long = SettlementPath {
            path: Bytes::from_slice(&env, &[0u8, 1u8]),
            rates,
            total_cost_bps: 0,
        };
        assert_eq!(
            too_long.compute_final_amount(1),
            Err(InteropError::RatesTooLong)
        );
    }
}
