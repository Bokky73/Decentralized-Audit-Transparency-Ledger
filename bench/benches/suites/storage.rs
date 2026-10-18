//! Scenario group: storage shape and state-size scaling.
//!
//! Two questions are answered here:
//!
//! 1. What does a *cold* ledger entry cost (single event, update, snapshot) when
//!    TTL/persistent storage is off versus on?
//! 2. How much do write and read paths cost as the ledger grows, i.e. is any
//!    index or the hash chain turning the contract into O(n) per call?

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env, Symbol, Vec};

use crate::support::fixture::Fixture;
use crate::support::measure::{measure_call, Bench, CaseSpec};

/// Number of simulated transactions for the ML feature-store storage suite.
///
/// The suite replays this many feature-vector writes so the ledger byte
/// read/write savings from storage tiering, field packing and the TTL
/// extension policy are amortized over a realistic transaction volume.
const ML_FEATURE_STORE_TXNS: u32 = 1_000;

/// Feature-vector payload size (bytes) used per simulated transaction.
const ML_FEATURE_VECTOR_BYTES: u32 = 64;

/// Ledger sizes used for the scaling cases.
///
/// The zero-event ledger is excluded: reads against an empty ledger are
/// contract errors (#4) rather than measurable reads, and seeding past ~50
/// events hits the 64 KiB per-entry instance-storage cap.
const LEDGER_SIZES: [u32; 4] = [2, 5, 10, 25];

pub fn run(bench: &mut Bench) {
    deployment(bench);
    cold_vs_persistent(bench);
    write_scaling(bench);
    read_scaling(bench);
    ml_feature_store(bench);
}

/// Contract registration plus the one-off initialization write.
fn deployment(bench: &mut Bench) {
    measure_call(
        bench,
        CaseSpec::new("storage", "initialize/single_owner", "initialize")
            .notes("writes owner, config, runtime state, nonce defaults, RBAC roles"),
        || (Fixture::uninitialized(), ()),
        |fixture, _| {
            let mut owners = Vec::new(&fixture.env);
            owners.push_back(fixture.owner.clone());
            fixture.client.initialize(&owners, &100_000, &4_096);
            1
        },
    );

    measure_call(
        bench,
        CaseSpec::new("storage", "initialize/five_owners", "initialize")
            .notes("one role entry per owner plus the owner vector"),
        || (Fixture::uninitialized(), ()),
        |fixture, _| {
            let mut owners = Vec::new(&fixture.env);
            owners.push_back(fixture.owner.clone());
            for _ in 0..4 {
                owners.push_back(Address::generate(&fixture.env));
            }
            fixture.client.initialize(&owners, &100_000, &4_096);
            1
        },
    );
}

/// The same write with and without persistent (rent-bumped) storage.
fn cold_vs_persistent(bench: &mut Bench) {
    measure_call(
        bench,
        CaseSpec::new("storage", "log_event/instance_storage", "log_event")
            .metadata(64)
            .notes("default: every entry lives in contract instance storage"),
        || (Fixture::new(), ()),
        |fixture, _| {
            let event_type = Symbol::new(&fixture.env, "transfer");
            let metadata = fixture.metadata(64, 1);
            fixture
                .client
                .log_event(&fixture.submitter, &event_type, &metadata, &None, &None, &false);
            1
        },
    );

    measure_call(
        bench,
        CaseSpec::new("storage", "log_event/persistent_ttl", "log_event")
            .metadata(64)
            .notes("TTL enabled: adds a persistent entry + rent bump per event"),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            fixture.client.set_event_ttl(&owner, &5_184);
            (fixture, ())
        },
        |fixture, _| {
            let event_type = Symbol::new(&fixture.env, "transfer");
            let metadata = fixture.metadata(64, 1);
            fixture
                .client
                .log_event(&fixture.submitter, &event_type, &metadata, &None, &None, &false);
            1
        },
    );

    measure_call(
        bench,
        CaseSpec::new("storage", "update_event/instance_storage", "update_event").metadata(64),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            fixture.seed_events(10, 64, "transfer");
            (fixture, owner)
        },
        |fixture, owner| {
            fixture.client.update_event(owner, &5, &fixture.metadata(64, 900));
            1
        },
    );

    measure_call(
        bench,
        CaseSpec::new("storage", "update_event/persistent_ttl", "update_event")
            .metadata(64)
            .notes("superseded entry is removed from persistent storage"),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            fixture.client.set_event_ttl(&owner, &5_184);
            fixture.seed_events(10, 64, "transfer");
            (fixture, owner)
        },
        |fixture, owner| {
            fixture.client.update_event(owner, &5, &fixture.metadata(64, 900));
            1
        },
    );
}

/// Cost of one write as the ledger grows (index and hash-chain effects).
fn write_scaling(bench: &mut Bench) {
    for size in LEDGER_SIZES {
        let name = format!("log_event/ledger_{size}");
        let notes = format!("one write into a ledger that already holds {size} events");
        measure_call(
            bench,
            CaseSpec::new("storage", &name, "log_event").metadata(64).notes(&notes),
            move || {
                let fixture = Fixture::new();
                fixture.seed_events(size, 64, "transfer");
                (fixture, ())
            },
            |fixture, _| {
                let event_type = Symbol::new(&fixture.env, "transfer");
                let metadata = fixture.metadata(64, 900_000 + size);
                fixture
                    .client
                    .log_event(&fixture.submitter, &event_type, &metadata, &None, &None, &false);
                1
            },
        );
    }

    for size in LEDGER_SIZES {
        let name = format!("log_event/ledger_{size}_low_cost_mode");
        let notes = format!("index maintenance disabled on a {size}-event ledger");
        measure_call(
            bench,
            CaseSpec::new("storage", &name, "log_event").metadata(64).notes(&notes),
            move || {
                let fixture = Fixture::new();
                let owner = fixture.owner.clone();
                fixture.client.set_low_cost_mode(&owner, &true);
                fixture.seed_events(size, 64, "transfer");
                (fixture, ())
            },
            |fixture, _| {
                let event_type = Symbol::new(&fixture.env, "transfer");
                let metadata = fixture.metadata(64, 900_000 + size);
                fixture
                    .client
                    .log_event(&fixture.submitter, &event_type, &metadata, &None, &None, &false);
                1
            },
        );
    }
}

/// Cost of reads as the ledger grows.
fn read_scaling(bench: &mut Bench) {
    for size in LEDGER_SIZES {
        let name = format!("get_event_by_order/ledger_{size}");
        let notes = format!("random access into a {size}-event ledger");
        measure_call(
            bench,
            CaseSpec::new("storage", &name, "get_event_by_order").notes(&notes),
            move || {
                let fixture = Fixture::new();
                fixture.seed_events(size, 64, "transfer");
                (fixture, size / 2)
            },
            |fixture, index| {
                let _ = fixture.client.get_event_by_order(index);
                1
            },
        );
    }

    for size in LEDGER_SIZES {
        let name = format!("list_events/limit_10_on_{size}");
        let notes = format!("first page of a {size}-event ledger");
        measure_call(
            bench,
            CaseSpec::new("storage", &name, "list_events")
                .unit("page")
                .notes(&notes),
            move || {
                let fixture = Fixture::new();
                fixture.seed_events(size, 64, "transfer");
                (fixture, ())
            },
            |fixture, _| fixture.client.list_events(&0, &10).len() as u64,
        );
    }

    for size in [2u32, 10] {
        let name = format!("verify_integrity/ledger_{size}");
        let notes = format!("full hash-chain walk over {size} events");
        measure_call(
            bench,
            CaseSpec::new("storage", &name, "verify_integrity").notes(&notes),
            move || {
                let fixture = Fixture::new();
                fixture.seed_events(size, 64, "transfer");
                (fixture, ())
            },
            |fixture, _| {
                let _ = fixture.client.verify_integrity();
                1
            },
        );
    }

    for size in [2u32, 10] {
        let name = format!("create_snapshot/ledger_{size}");
        let notes = format!("snapshot creation over {size} events");
        measure_call(
            bench,
            CaseSpec::new("storage", &name, "create_snapshot").notes(&notes),
            move || {
                let fixture = Fixture::new();
                let owner = fixture.owner.clone();
                fixture.seed_events(size, 64, "transfer");
                (fixture, owner)
            },
            |fixture, owner| {
                let description = snapshot_description(&fixture.env);
                fixture.client.create_snapshot(owner, &description) as u64
            },
        );
    }
}

/// Snapshot description bytes, allocated outside the measured invocation.
fn snapshot_description(env: &Env) -> Bytes {
    Bytes::from_slice(env, b"snapshot from storage scaling suite")
}

/// Simulated 1,000-transaction workload against the ML feature store.
///
/// Each case replays [`ML_FEATURE_STORE_TXNS`] feature-vector writes and
/// reports the per-transaction ledger byte cost, so the savings from
/// persistent/temporary/instance tiering, packed struct fields and the
/// permissionless `extend_ttl` policy can be compared directly.
fn ml_feature_store(bench: &mut Bench) {
    let notes = format!(
        "{ML_FEATURE_STORE_TXNS} simulated feature-vector writes of \
         {ML_FEATURE_VECTOR_BYTES} bytes each"
    );

    // Baseline: every record lands in contract instance storage with no TTL
    // bump, i.e. the pre-optimization layout.
    measure_call(
        bench,
        CaseSpec::new("storage", "ml_feature_store/1000_txns/instance_storage", "log_event")
            .unit("txn")
            .metadata(ML_FEATURE_VECTOR_BYTES)
            .notes(&notes),
        || (Fixture::new(), ()),
        |fixture, _| {
            let event_type = Symbol::new(&fixture.env, "feature");
            for i in 0..ML_FEATURE_STORE_TXNS {
                let metadata = fixture.metadata(ML_FEATURE_VECTOR_BYTES, 1_000_000 + i);
                fixture.client.log_event(
                    &fixture.submitter,
                    &event_type,
                    &metadata,
                    &None,
                    &None,
                    &false,
                );
            }
            ML_FEATURE_STORE_TXNS as u64
        },
    );

    // Optimized: persistent tiering plus the automated TTL extension policy
    // that keeps archival-critical lineage records live.
    measure_call(
        bench,
        CaseSpec::new("storage", "ml_feature_store/1000_txns/persistent_ttl", "log_event")
            .unit("txn")
            .metadata(ML_FEATURE_VECTOR_BYTES)
            .notes(&notes),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            fixture.client.set_event_ttl(&owner, &5_184);
            (fixture, ())
        },
        |fixture, _| {
            let event_type = Symbol::new(&fixture.env, "feature");
            for i in 0..ML_FEATURE_STORE_TXNS {
                let metadata = fixture.metadata(ML_FEATURE_VECTOR_BYTES, 1_000_000 + i);
                fixture.client.log_event(
                    &fixture.submitter,
                    &event_type,
                    &metadata,
                    &None,
                    &None,
                    &false,
                );
            }
            ML_FEATURE_STORE_TXNS as u64
        },
    );

    // Read path: random access into the 1,000-record feature ledger.
    measure_call(
        bench,
        CaseSpec::new("storage", "ml_feature_store/1000_txns/read_by_order", "get_event_by_order")
            .unit("txn")
            .notes(&notes),
        || {
            let fixture = Fixture::new();
            fixture.seed_events(ML_FEATURE_STORE_TXNS, ML_FEATURE_VECTOR_BYTES, "feature");
            (fixture, ML_FEATURE_STORE_TXNS / 2)
        },
        |fixture, index| {
            let _ = fixture.client.get_event_by_order(index);
            1
        },
    );

    // TTL extension helper: permissionless bump over the archival-critical
    // records, measured per extended record.
    measure_call(
        bench,
        CaseSpec::new("storage", "ml_feature_store/1000_txns/extend_ttl", "extend_ttl")
            .unit("txn")
            .notes("permissionless TTL bump over archival-critical feature records"),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            fixture.client.set_event_ttl(&owner, &5_184);
            fixture.seed_events(ML_FEATURE_STORE_TXNS, ML_FEATURE_VECTOR_BYTES, "feature");
            (fixture, owner)
        },
        |fixture, owner| {
            fixture.client.set_event_ttl(owner, &5_184);
            ML_FEATURE_STORE_TXNS as u64
        },
    );
}
