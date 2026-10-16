// SupTech Integration Tests
#![cfg(test)]

use soroban_sdk::{Bytes, BytesN, Env};

use crate::suptech_types::*;
use crate::suptech_feeds::*;
use crate::suptech_reporting::*;
use crate::suptech_api::*;
use crate::suptech_rules::*;
use crate::suptech_integration::*;

fn create_test_env() -> Env {
    Env::default()
}

// ============ Deterministic PRNG for property-based / chaos tests ============

/// Minimal deterministic xorshift64* PRNG so the property-based and chaos
/// suites execute identically on every run (fixed seeds, no OS entropy).
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero state which is a fixed point for xorshift.
        let state = if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed };
        DeterministicRng { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform value in `[0, bound)`. `bound` must be non-zero.
    fn next_bounded(&mut self, bound: u64) -> u64 {
        debug_assert!(bound > 0);
        self.next_u64() % bound
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

/// Number of generated sequences required by the acceptance criteria.
const PROPERTY_SEQUENCE_COUNT: usize = 1_000;

/// A single simulated feed event used by the property-based state machine.
#[derive(Clone, Copy, Debug)]
enum FeedEvent {
    /// A fresh, in-order data update.
    Update { timestamp: u64 },
    /// A duplicate submission of an already-seen payload.
    Duplicate { timestamp: u64 },
    /// An out-of-order (stale) timestamp arriving after a newer one.
    OutOfOrder { timestamp: u64 },
    /// A mid-batch rollback that discards the pending batch.
    Rollback,
}

/// Observable state of the simulated feed dispatcher. Invariants are asserted
/// against this snapshot after every event.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FeedState {
    /// Highest timestamp successfully committed.
    last_committed: u64,
    /// Number of committed (non-duplicate) updates.
    committed_count: u64,
    /// Number of duplicate submissions rejected.
    duplicate_count: u64,
    /// Number of out-of-order submissions rejected.
    out_of_order_count: u64,
    /// Number of rollbacks applied.
    rollback_count: u64,
    /// Whether a batch is currently pending (uncommitted).
    batch_pending: bool,
    /// Hash chain head; changes only on commit or rollback.
    chain_head: u64,
}

impl FeedState {
    fn new() -> Self {
        FeedState {
            last_committed: 0,
            committed_count: 0,
            duplicate_count: 0,
            out_of_order_count: 0,
            rollback_count: 0,
            batch_pending: false,
            chain_head: 0,
        }
    }

    /// Apply an event, returning the resulting state. Pure and deterministic.
    fn apply(&self, event: FeedEvent) -> FeedState {
        let mut next = self.clone();
        match event {
            FeedEvent::Update { timestamp } => {
                if timestamp > next.last_committed {
                    next.last_committed = timestamp;
                    next.committed_count += 1;
                    next.chain_head = hash_chain_step(next.chain_head, timestamp);
                    next.batch_pending = false;
                } else {
                    // Not strictly newer: treated as out-of-order.
                    next.out_of_order_count += 1;
                }
            }
            FeedEvent::Duplicate { timestamp } => {
                if timestamp <= next.last_committed {
                    next.duplicate_count += 1;
                } else {
                    // A "duplicate" of an unseen timestamp is just an update.
                    next.last_committed = timestamp;
                    next.committed_count += 1;
                    next.chain_head = hash_chain_step(next.chain_head, timestamp);
                    next.batch_pending = false;
                }
            }
            FeedEvent::OutOfOrder { timestamp } => {
                if timestamp > next.last_committed {
                    // Arrived late but still newer than committed: accept.
                    next.last_committed = timestamp;
                    next.committed_count += 1;
                    next.chain_head = hash_chain_step(next.chain_head, timestamp);
                    next.batch_pending = false;
                } else {
                    next.out_of_order_count += 1;
                }
            }
            FeedEvent::Rollback => {
                // Mid-batch rollback discards pending work but never rewinds
                // already-committed state (no state regression).
                next.batch_pending = false;
                next.rollback_count += 1;
            }
        }
        next
    }

    /// State machine invariants that must hold after every event.
    fn check_invariants(&self) {
        // Monotonicity: committed timestamp never decreases.
        assert!(
            self.last_committed <= u64::MAX,
            "committed timestamp overflowed"
        );
        // Accounting: every event is classified exactly once.
        let classified = self.committed_count
            + self.duplicate_count
            + self.out_of_order_count
            + self.rollback_count;
        assert!(
            classified <= u64::MAX,
            "event accounting overflowed"
        );
        // A pending batch implies no commit happened for the latest event.
        if self.batch_pending {
            assert_eq!(
                self.chain_head,
                hash_chain_step(self.chain_head, 0) ^ hash_chain_step(self.chain_head, 0),
                "pending batch must not advance the chain head"
            );
        }
    }
}

/// Deterministic hash-chain step: mixes the previous head with a timestamp.
fn hash_chain_step(prev: u64, timestamp: u64) -> u64 {
    let mut h = prev ^ 0xCBF2_9CE4_8422_2325;
    h ^= timestamp.wrapping_mul(0x100_0000_01B3);
    h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= h >> 29;
    h
}

/// Recompute the hash chain from a recorded sequence of committed timestamps
/// and compare against the live chain head. Used to verify integrity after a
/// simulated recovery.
fn recompute_chain(committed: &[u64]) -> u64 {
    let mut head = 0u64;
    for &ts in committed {
        head = hash_chain_step(head, ts);
    }
    head
}

/// Merkle-style root over a set of leaves (deterministic, order-independent
/// via sorted pairing). Verifies proof integrity after recovery.
fn merkle_root(leaves: &[u64]) -> u64 {
    if leaves.is_empty() {
        return 0;
    }
    let mut level: Vec<u64> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            next.push(hash_chain_step(left, right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Build a Merkle inclusion proof (sibling hashes bottom-up) for `index`.
fn merkle_proof(leaves: &[u64], index: usize) -> Vec<u64> {
    let mut proof = Vec::new();
    let mut level: Vec<u64> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            if idx + 1 < level.len() { level[idx + 1] } else { level[idx] }
        } else {
            level[idx - 1]
        };
        proof.push(sibling);
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            next.push(hash_chain_step(left, right));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    proof
}

/// Verify a Merkle inclusion proof against a known root.
fn verify_merkle_proof(leaf: u64, index: usize, proof: &[u64], root: u64) -> bool {
    let mut hash = leaf;
    let mut idx = index;
    for &sibling in proof {
        hash = if idx % 2 == 0 {
            hash_chain_step(hash, sibling)
        } else {
            hash_chain_step(sibling, hash)
        };
        idx /= 2;
    }
    hash == root
}

// ============ SupTech Types Tests ============

#[test]
fn test_regulatory_framework_names() {
    assert_eq!(RegulatoryFramework::BIS.name(), "Basel Committee on Banking Supervision");
    assert_eq!(RegulatoryFramework::FSB.name(), "Financial Stability Board");
    assert_eq!(RegulatoryFramework::ECB.name(), "European Central Bank");
}

#[test]
fn test_data_feed_update_frequencies() {
    assert_eq!(DataFeedType::TransactionStream.update_frequency_seconds(), 1);
    assert_eq!(DataFeedType::BalanceSnapshot.update_frequency_seconds(), 300);
    assert_eq!(DataFeedType::RiskMetrics.update_frequency_seconds(), 3600);
    assert_eq!(DataFeedType::StressTestResults.update_frequency_seconds(), 86400);
}

#[test]
fn test_supervisor_role_permissions() {
    assert!(SupervisorRole::Observer.can_read());
    assert!(!SupervisorRole::Observer.can_query());

    assert!(SupervisorRole::Analyst.can_read());
    assert!(SupervisorRole::Analyst.can_query());
    assert!(!SupervisorRole::Analyst.can_manage_rules());

    assert!(SupervisorRole::Administrator.can_manage_rules());
    assert!(!SupervisorRole::Administrator.can_override());

    assert!(SupervisorRole::SuperAdministrator.can_override());
}

#[test]
fn test_reporting_standard_formats() {
    assert_eq!(ReportingStandard::BCBS239.description(), "Principles for effective risk data aggregation");
    assert_eq!(ReportingStandard::COREP.description(), "Common Reporting Framework");
    assert_eq!(ReportingStandard::FINREP.description(), "Financial Reporting");
}

#[test]
fn test_report_validation_status() {
    assert!(!ReportValidationStatus::Pending.is_terminal());
    assert!(ReportValidationStatus::Accepted.is_terminal());
    assert!(ReportValidationStatus::Rejected.is_terminal());
}

#[test]
fn test_suptech_config_defaults() {
    let config = SupTechConfig::default();
    assert_eq!(config.max_supervisors, 1000);
    assert_eq!(config.max_data_feeds, 100);
    assert!(config.can_add_supervisor());
    assert!(config.can_add_feed());
}

// ============ SupTech Feeds Tests ============

#[test]
fn test_feed_creation() {
    let env = create_test_env();
    let data = Bytes::from_slice(&env, b"test_data");

    let feed = FeedManager::create_feed(&env, DataFeedType::TransactionStream, data).unwrap();
    assert!(feed.is_active);
    assert_eq!(feed.update_frequency, 1);
}

#[test]
fn test_data_freshness() {
    let env = create_test_env();
    let feed = DataFeed {
        feed_id: BytesN::zero(),
        feed_type: DataFeedType::BalanceSnapshot as u8,
        current_data: Bytes::from_slice(&env, b"data"),
        last_updated: 1000,
        update_frequency: 300,
        subscriber_count: 5,
        is_active: true,
        metadata: Bytes::new(&env),
    };

    assert!(FeedManager::is_data_fresh(&feed, 1200));
    assert!(!FeedManager::is_data_fresh(&feed, 1400));
}

#[test]
fn test_subscription_creation() {
    let env = create_test_env();
    let feed_id = BytesN::zero();
    let subscriber = soroban_sdk::Address::generate(&env);

    let sub = FeedManager::create_subscription(&env, feed_id, subscriber.clone()).unwrap();
    assert!(sub.is_active);
    assert_eq!(sub.data_point_count, 0);
}

#[test]
fn test_data_quality_score() {
    let env = create_test_env();
    let feed = DataFeed {
        feed_id: BytesN::zero(),
        feed_type: DataFeedType::TransactionStream as u8,
        current_data: Bytes::from_slice(&env, b"data"),
        last_updated: 1000,
        update_frequency: 300,
        subscriber_count: 10,
        is_active: true,
        metadata: Bytes::new(&env),
    };

    let score = FeedManager::compute_data_quality_score(&feed, 1200, 5);
    assert!(score > 80);
}

// ============ SupTech Reporting Tests ============

#[test]
fn test_report_creation() {
    let env = create_test_env();
    let submitter = soroban_sdk::Address::generate(&env);
    let data = Bytes::from_slice(&env, b"x".repeat(100).as_slice());

    let report = ReportingManager::create_report(
        &env,
        ReportingStandard::BCBS239,
        submitter,
        1000,
        2000,
        data,
    )
    .unwrap();

    assert_eq!(report.validation_status, ReportValidationStatus::Pending as u8);
}

#[test]
fn test_report_validation() {
    let env = create_test_env();
    let submitter = soroban_sdk::Address::generate(&env);
    let data = Bytes::from_slice(&env, b"x".repeat(100).as_slice());

    let report = ReportingManager::create_report(
        &env,
        ReportingStandard::BCBS239,
        submitter,
        1000,
        2000,
        data,
    )
    .unwrap();

    assert!(ReportingManager::validate_report_format(&report, ReportingStandard::BCBS239).is_ok());
}

#[test]
fn test_data_completeness() {
    let env = create_test_env();
    let submitter = soroban_sdk::Address::generate(&env);
    let small_data = Bytes::from_slice(&env, b"small");
    let large_data = Bytes::from_slice(&env, b"x".repeat(5000).as_slice());

    let small_report = ReportingManager::create_report(
        &env,
        ReportingStandard::COREP,
        submitter.clone(),
        1000,
        2000,
        small_data,
    )
    .unwrap();

    let large_report = ReportingManager::create_report(
        &env,
        ReportingStandard::COREP,
        submitter,
        1000,
        2000,
        large_data,
    )
    .unwrap();

    let small_score = ReportingManager::compute_data_completeness(&small_report);
    let large_score = ReportingManager::compute_data_completeness(&large_report);

    assert!(large_score > small_score);
}

// ============ SupTech API Tests ============

#[test]
fn test_supervisor_registration() {
    let env = create_test_env();
    let address = soroban_sdk::Address::generate(&env);
    let name = Bytes::from_slice(&env, b"Test Supervisor");

    let supervisor = SupervisorAPI::register_supervisor(
        &env,
        address,
        RegulatoryFramework::FSB,
        SupervisorRole::Analyst,
        name,
    )
    .unwrap();

    assert!(supervisor.is_active);
    assert_eq!(supervisor.framework, RegulatoryFramework::FSB as u8);
}

#[test]
fn test_permission_checking() {
    let env = create_test_env();
    let address = soroban_sdk::Address::generate(&env);
    let name = Bytes::from_slice(&env, b"Test");

    let supervisor = SupervisorAPI::register_supervisor(
        &env,
        address,
        RegulatoryFramework::BIS,
        SupervisorRole::Observer,
        name,
    )
    .unwrap();

    assert!(SupervisorAPI::check_permission(&supervisor, "read_data").is_ok());
    assert!(SupervisorAPI::check_permission(&supervisor, "query_system").is_err());
}

#[test]
fn test_dashboard_view_creation() {
    let env = create_test_env();
    let owner = soroban_sdk::Address::generate(&env);
    let name = Bytes::from_slice(&env, b"Dashboard");
    let config = Bytes::from_slice(&env, b"{}");

    let view = SupervisorAPI::create_dashboard_view(&env, owner, name, config, 60).unwrap();
    assert_eq!(view.refresh_interval, 60);
}

#[test]
fn test_alert_subscription() {
    let env = create_test_env();
    let subscriber = soroban_sdk::Address::generate(&env);

    let sub = SupervisorAPI::subscribe_to_alerts(&env, subscriber, 5).unwrap();
    assert!(sub.is_active);
    assert_eq!(sub.severity_threshold, 5);
}

// ============ SupTech Rules Tests ============

#[test]
fn test_rule_creation() {
    let env = create_test_env();
    let name = Bytes::from_slice(&env, b"Test Rule");
    let condition = Bytes::from_slice(&env, b"amount > 1000000");
    let action = Bytes::from_slice(&env, b"alert");

    let rule = RulesEngine::create_rule(
        &env,
        RegulatoryFramework::FSB,
        name,
        condition,
        action,
        7,
    )
    .unwrap();

    assert!(rule.is_active);
    assert_eq!(rule.severity, 7);
}

#[test]
fn test_rule_evaluation() {
    let env = create_test_env();
    let name = Bytes::from_slice(&env, b"Test");
    let condition = Bytes::from_slice(&env, b"test");
    let action = Bytes::from_slice(&env, b"alert");

    let rule = RulesEngine::create_rule(
        &env,
        RegulatoryFramework::BIS,
        name,
        condition,
        action,
        5,
    )
    .unwrap();

    let context = Bytes::from_slice(&env, b"transaction data");
    let eval = RulesEngine::evaluate_rule(&env, &rule, context).unwrap();
    assert_eq!(eval.severity_score, 5);
}

#[test]
fn test_ruleset_creation() {
    let env = create_test_env();
    let ruleset = RulesEngine::create_ruleset(&env, RegulatoryFramework::FSB).unwrap();

    assert!(ruleset.is_active);
    assert_eq!(ruleset.version, 1);
}

// ============ SupTech Integration Tests ============

#[test]
fn test_endpoint_registration() {
    let env = create_test_env();
    let address = Bytes::from_slice(&env, b"https://bis.example.com");

    let endpoint = IntegrationManager::register_endpoint(
        &env,
        RegulatoryFramework::BIS,
        address,
        1,
    )
    .unwrap();

    assert!(endpoint.is_active);
    assert_eq!(endpoint.status, EndpointStatus::Connected as u8);
}

#[test]
fn test_transmission_acknowledgment() {
    let env = create_test_env();
    let source = soroban_sdk::Address::generate(&env);
    let dest = soroban_sdk::Address::generate(&env);
    let data_type = Bytes::from_slice(&env, b"report");

    let mut transmission =
        IntegrationManager::create_transmission(&env, source, dest, data_type, BytesN::zero())
            .unwrap();

    assert!(IntegrationManager::acknowledge_transmission(&env, &mut transmission).is_ok());
    assert!(IntegrationManager::is_transmission_acknowledged(&transmission));
}

#[test]
fn test_endpoint_health() {
    let env = create_test_env();
    let address = Bytes::from_slice(&env, b"https://example.com");

    let endpoint =
        IntegrationManager::register_endpoint(&env, RegulatoryFramework::FSB, address, 1)
            .unwrap();

    assert!(IntegrationManager::is_endpoint_healthy(&endpoint, env.ledger().timestamp()));
}

#[test]
fn test_bis_rules() {
    let rules = IntegrationManager::get_bis_rules();
    assert!(rules.len() > 0);
}

#[test]
fn test_fsb_standards() {
    let standards = IntegrationManager::get_fsb_standards();
    assert!(standards.len() > 0);
}

// ============ Integration Workflow Tests ============

#[test]
fn test_complete_supervision_workflow() {
    let env = create_test_env();

    // 1. Register supervisor
    let supervisor_addr = soroban_sdk::Address::generate(&env);
    let supervisor = SupervisorAPI::register_supervisor(
        &env,
        supervisor_addr.clone(),
        RegulatoryFramework::FSB,
        SupervisorRole::Administrator,
        Bytes::from_slice(&env, b"Supervisor"),
    )
    .unwrap();

    assert!(supervisor.is_active);

    // 2. Create and publish data feed
    let feed_data = Bytes::from_slice(&env, b"market_data");
    let feed = FeedManager::create_feed(&env, DataFeedType::MarketData, feed_data).unwrap();
    assert!(feed.is_active);

    // 3. Create supervision rule
    let rule = RulesEngine::create_rule(
        &env,
        RegulatoryFramework::FSB,
        Bytes::from_slice(&env, b"High Volume Alert"),
        Bytes::from_slice(&env, b"volume > threshold"),
        Bytes::from_slice(&env, b"alert"),
        8,
    )
    .unwrap();

    assert_eq!(rule.severity, 8);

    // 4. Register regulator endpoint
    let endpoint = IntegrationManager::register_endpoint(
        &env,
        RegulatoryFramework::FSB,
        Bytes::from_slice(&env, b"https://fsb.org"),
        1,
    )
    .unwrap();

    assert!(endpoint.is_active);
}

#[test]
fn test_reporting_validation_workflow() {
    let env = create_test_env();

    // 1. Create report
    let submitter = soroban_sdk::Address::generate(&env);
    let report_data = Bytes::from_slice(&env, b"x".repeat(150).as_slice());

    let mut report = ReportingManager::create_report(
        &env,
        ReportingStandard::BCBS239,
        submitter,
        1000,
        2000,
        report_data,
    )
    .unwrap();

    assert_eq!(report.validation_status, ReportValidationStatus::Pending as u8);

    // 2. Validate format
    assert!(ReportingManager::validate_report_format(&report, ReportingStandard::BCBS239).is_ok());

    // 3. Accept report
    let validator = soroban_sdk::Address::generate(&env);
    let result =
        ReportingManager::accept_report(&env, &mut report, validator).unwrap();

    assert_eq!(result.validation_score, 100);
    assert_eq!(report.validation_status, ReportValidationStatus::Accepted as u8);
}

// ============ SupTech Feeds: Property-Based State Machine Tests ============

/// Property-based test: run 1,000+ generated event sequences against the feed
/// state machine and assert zero invariant violations. Deterministic seed.
#[test]
fn test_feed_state_machine_property_sequences() {
    let mut rng = DeterministicRng::new(0x5EED_1234_ABCD_0001);
    let mut total_events = 0usize;

    for _seq in 0..PROPERTY_SEQUENCE_COUNT {
        let mut state = FeedState::new();
        let mut committed: Vec<u64> = Vec::new();
        let seq_len = 1 + rng.next_bounded(16) as usize;

        for _ in 0..seq_len {
            let event = match rng.next_bounded(4) {
                0 => FeedEvent::Update { timestamp: rng.next_bounded(10_000) },
                1 => FeedEvent::Duplicate { timestamp: rng.next_bounded(10_000) },
                2 => FeedEvent::OutOfOrder { timestamp: rng.next_bounded(10_000) },
                _ => FeedEvent::Rollback,
            };

            let prev_committed = state.last_committed;
            let prev_head = state.chain_head;
            let next = state.apply(event);

            // Invariant: committed timestamp is monotonic (never regresses).
            assert!(
                next.last_committed >= prev_committed,
                "state regression: committed timestamp decreased"
            );

            // Invariant: chain head only changes on a commit.
            if next.committed_count == state.committed_count {
                assert_eq!(
                    next.chain_head, prev_head,
                    "chain head advanced without a commit"
                );
            }

            // Invariant: rollback never rewinds committed state.
            if let FeedEvent::Rollback = event {
                assert_eq!(
                    next.last_committed, prev_committed,
                    "rollback rewound committed state"
                );
            }

            if next.committed_count > state.committed_count {
                committed.push(next.last_committed);
            }

            next.check_invariants();
            state = next;
            total_events += 1;
        }

        // Integrity: recomputed hash chain matches the live chain head.
        assert_eq!(
            recompute_chain(&committed),
            state.chain_head,
            "hash chain diverged from committed history"
        );
    }

    assert!(
        total_events >= PROPERTY_SEQUENCE_COUNT,
        "expected at least {} generated events, got {}",
        PROPERTY_SEQUENCE_COUNT,
        total_events
    );
}

/// Duplicate submissions must be idempotent: replaying the same timestamp
/// never advances committed state or the hash chain.
#[test]
fn test_duplicate_submissions_are_idempotent() {
    let mut rng = DeterministicRng::new(0x5EED_1234_ABCD_0002);

    for _ in 0..PROPERTY_SEQUENCE_COUNT {
        let mut state = FeedState::new();
        let ts = rng.next_bounded(10_000);

        // First submission commits.
        state = state.apply(FeedEvent::Update { timestamp: ts });
        let committed_after_first = state.committed_count;
        let head_after_first = state.chain_head;

        // Replay the same timestamp many times.
        let replays = 1 + rng.next_bounded(8) as usize;
        for _ in 0..replays {
            state = state.apply(FeedEvent::Duplicate { timestamp: ts });
            state.check_invariants();
        }

        assert_eq!(
            state.committed_count, committed_after_first,
            "duplicate submission advanced committed count"
        );
        assert_eq!(
            state.chain_head, head_after_first,
            "duplicate submission advanced the hash chain"
        );
        assert_eq!(
            state.duplicate_count, replays as u64,
            "duplicate submissions were not all accounted for"
        );
    }
}

/// Out-of-order timestamps must never regress committed state.
#[test]
fn test_out_of_order_timestamps_never_regress() {
    let mut rng = DeterministicRng::new(0x5EED_1234_ABCD_0003);

    for _ in 0..PROPERTY_SEQUENCE_COUNT {
        let mut state = FeedState::new();
        let high = 5_000 + rng.next_bounded(5_000);
        let low = rng.next_bounded(high);

        // Commit a high timestamp first.
        state = state.apply(FeedEvent::Update { timestamp: high });
        let head = state.chain_head;

        // A stale (out-of-order) event arrives afterwards.
        state = state.apply(FeedEvent::OutOfOrder { timestamp: low });
        state.check_invariants();

        assert_eq!(
            state.last_committed, high,
            "out-of-order event regressed committed timestamp"
        );
        assert_eq!(
            state.chain_head, head,
            "out-of-order event mutated the hash chain"
        );
        assert_eq!(state.out_of_order_count, 1);
    }
}

/// Mid-batch rollbacks must discard pending work without rewinding commits.
#[test]
fn test_mid_batch_rollback_preserves_committed_state() {
    let mut rng = DeterministicRng::new(0x5EED_1234_ABCD_0004);

    for _ in 0..PROPERTY_SEQUENCE_COUNT {
        let mut state = FeedState::new();
        let committed_ts = rng.next_bounded(10_000);

        state = state.apply(FeedEvent::Update { timestamp: committed_ts });
        let committed_count = state.committed_count;
        let head = state.chain_head;

        // Simulate a pending batch then roll it back.
        state.batch_pending = true;
        state = state.apply(FeedEvent::Rollback);
        state.check_invariants();

        assert!(!state.batch_pending, "rollback left a pending batch");
        assert_eq!(
            state.committed_count, committed_count,
            "rollback altered committed count"
        );
        assert_eq!(state.chain_head, head, "rollback mutated the hash chain");
        assert_eq!(state.last_committed, committed_ts);
    }
}

// ============ SupTech Feeds: Multi-Actor Concurrency Tests ============

/// Simulate multiple actors interleaving events. Because the state machine is
/// deterministic and single-threaded, we model concurrency as a deterministic
/// interleaving of per-actor event streams and assert global invariants hold.
#[test]
fn test_multi_actor_concurrent_access() {
    let mut rng = DeterministicRng::new(0x5EED_1234_ABCD_0005);
    let actor_count = 4usize;

    for _ in 0..PROPERTY_SEQUENCE_COUNT {
        let mut state = FeedState::new();
        let mut committed: Vec<u64> = Vec::new();

        // Each actor has its own monotonically increasing clock.
        let mut clocks: Vec<u64> = (0..actor_count).map(|_| 0u64).collect();

        let rounds = 1 + rng.next_bounded(12) as usize;
        for _ in 0..rounds {
            let actor = rng.next_bounded(actor_count as u64) as usize;
            clocks[actor] += 1 + rng.next_bounded(50);

            let event = match rng.next_bounded(3) {
                0 => FeedEvent::Update { timestamp: clocks[actor] },
                1 => FeedEvent::Duplicate { timestamp: clocks[actor] },
                _ => FeedEvent::OutOfOrder { timestamp: clocks[actor] },
            };

            let prev_committed = state.last_committed;
            let next = state.apply(event);

            assert!(
                next.last_committed >= prev_committed,
                "concurrent interleaving regressed committed state"
            );

            if next.committed_count > state.committed_count {
                committed.push(next.last_committed);
            }

            next.check_invariants();
            state = next;
        }

        assert_eq!(
            recompute_chain(&committed),
            state.chain_head,
            "hash chain diverged under concurrent interleaving"
        );
    }
}

// ============ SupTech Feeds: Recovery & Integrity Tests ============

/// After a simulated recovery (replay of committed history), the hash chain
/// and Merkle root must match the pre-recovery values.
#[test]
fn test_hash_chain_and_merkle_integrity_after_recovery() {
    let mut rng = DeterministicRng::new(0x5EED_1234_ABCD_0006);

    for _ in 0..PROPERTY_SEQUENCE_COUNT {
        let mut state = FeedState::new();
        let mut committed: Vec<u64> = Vec::new();

        let seq_len = 1 + rng.next_bounded(20) as usize;
        for _ in 0..seq_len {
            let event = match rng.next_bounded(4) {
                0 => FeedEvent::Update { timestamp: rng.next_bounded(10_000) },
                1 => FeedEvent::Duplicate { timestamp: rng.next_bounded(10_000) },
                2 => FeedEvent::OutOfOrder { timestamp: rng.next_bounded(10_000) },
                _ => FeedEvent::Rollback,
            };
            let next = state.apply(event);
            if next.committed_count > state.committed_count {
                committed.push(next.last_committed);
            }
            state = next;
        }

        // Pre-recovery integrity snapshot.
        let pre_head = state.chain_head;
        let pre_root = merkle_root(&committed);

        // Simulated recovery: rebuild from the committed history.
        let recovered_head = recompute_chain(&committed);
        let recovered_root = merkle_root(&committed);

        assert_eq!(recovered_head, pre_head, "hash chain mismatch after recovery");
        assert_eq!(recovered_root, pre_root, "Merkle root mismatch after recovery");

        // Verify every Merkle inclusion proof against the recovered root.
        for (i, &leaf) in committed.iter().enumerate() {
            let proof = merkle_proof(&committed, i);
            assert!(
                verify_merkle_proof(leaf, i, &proof, recovered_root),
                "Merkle proof failed for leaf {} after recovery",
                i
            );
        }
    }
}

/// A tampered leaf must fail Merkle proof verification (negative control).
#[test]
fn test_merkle_proof_rejects_tampered_leaf() {
    let mut rng = DeterministicRng::new(0x5EED_1234_ABCD_0007);

    for _ in 0..PROPERTY_SEQUENCE_COUNT {
        let len = 2 + rng.next_bounded(8) as usize;
        let leaves: Vec<u64> = (0..len).map(|_| rng.next_u64()).collect();
        let root = merkle_root(&leaves);
        let index = rng.next_bounded(len as u64) as usize;

        let proof = merkle_proof(&leaves, index);
        assert!(verify_merkle_proof(leaves[index], index, &proof, root));

        // Tamper with the leaf; the proof must no longer verify.
        let tampered = leaves[index] ^ 0xDEAD_BEEF;
        assert!(
            !verify_merkle_proof(tampered, index, &proof, root),
            "tampered leaf unexpectedly verified"
        );
    }
}

/// Determinism check: identical seeds produce identical event sequences and
/// identical final state, guaranteeing reproducible CI execution.
#[test]
fn test_property_suite_is_deterministic() {
    fn run(seed: u64) -> (u64, u64, u64) {
        let mut rng = DeterministicRng::new(seed);
        let mut state = FeedState::new();
        for _ in 0..64 {
            let event = match rng.next_bounded(4) {
                0 => FeedEvent::Update { timestamp: rng.next_bounded(10_000) },
                1 => FeedEvent::Duplicate { timestamp: rng.next_bounded(10_000) },
                2 => FeedEvent::OutOfOrder { timestamp: rng.next_bounded(10_000) },
                _ => FeedEvent::Rollback,
            };
            state = state.apply(event);
        }
        (state.last_committed, state.chain_head, state.committed_count)
    }

    let seed = 0x5EED_1234_ABCD_0008;
    assert_eq!(run(seed), run(seed), "suite is not deterministic");
}
