//! Scenario group: read/query paths.
//!
//! Every case runs against a fixture pre-seeded with [`SEEDED_EVENTS`] events so
//! that index structures (per-type, per-submitter, per-category, hash chain) are
//! populated exactly as they would be in production. Point reads use the
//! `invocation` unit, paginated scans report a `page` unit so that the
//! per-row cost is directly comparable.

use soroban_sdk::{Address, Bytes, BytesN, Symbol, Vec};

use crate::support::fixture::{Fixture, BASE_TIMESTAMP};
use crate::support::measure::{Bench, CaseSpec};

/// Maximum page size enforced by the paginated query bindings.
const MAX_PAGE_LIMIT: u32 = 100;
/// Number of feature vectors seeded into every feature-store query fixture.
const SEEDED_FEATURES: u32 = 10;
/// Number of disclosure records seeded into every CBDC privacy query fixture.
const SEEDED_DISCLOSURES: u32 = 10;
/// Number of tiered anonymity records seeded into every CBDC privacy fixture.
const SEEDED_TIERS: u32 = 10;
/// Ledger timestamp window used by the filtered query benchmarks.
const FILTER_WINDOW: u64 = 10_000;

/// Number of events seeded per event type into every query fixture.
///
/// Bounded by the 64 KiB per-entry cap on the ledger's instance storage: the
/// index surface grows ~6.6 KiB per seeded event, so ~10 events per type keeps
/// seeding (and every read) inside the cap.
const SEEDED_PER_TYPE: u32 = 10;
/// Total number of seeded events (three event types).
const SEEDED_EVENTS: u32 = SEEDED_PER_TYPE * 3;
/// Metadata size of the seeded events.
const SEEDED_METADATA: usize = 64;
/// Event types rotated through while seeding (exercises type indexes).
const SEEDED_TYPES: [&str; 3] = ["transfer", "approval", "audit"];
/// Category assigned to every seeded event.
const SEEDED_CATEGORY: &str = "finance";

/// Fixture with a populated index surface, plus the content-addressed IDs of
/// the seeded events (the contract only hands those out at write time).
fn seeded() -> (Fixture, Vec<BytesN<32>>) {
    let fixture = Fixture::new();
    let mut ids = Vec::new(&fixture.env);
    for (index, event_type) in SEEDED_TYPES.iter().enumerate() {
        let seeded = fixture.seed_events_multi(
            SEEDED_PER_TYPE,
            SEEDED_METADATA,
            event_type,
            (index as u32) * 1_000,
            Some(SEEDED_CATEGORY),
            None,
            false,
        );
        for i in 0..seeded.len() {
            ids.push_back(seeded.get(i).unwrap());
        }
    }
    (fixture, ids)
}

pub fn run(bench: &mut Bench) {
    point_reads(bench);
    paginated_scans(bench);
    full_ledger_scans(bench);
    configuration_reads(bench);
    feature_store_paginated_queries(bench);
    cbdc_privacy_paginated_queries(bench);
}

/// Single-record lookups and version/history reads.
fn point_reads(bench: &mut Bench) {
    bench.measure(
        CaseSpec::new("queries", "get_event", "get_event").notes("full event payload by content-addressed id"),
        || {
            let (fixture, ids) = seeded();
            (fixture, ids.get(0).unwrap())
        },
        |fixture, id, _| {
            let _ = fixture.client.get_event(id);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_metadata", "get_event_metadata")
            .notes("metadata only, avoids the full event deserialisation"),
        || {
            let (fixture, ids) = seeded();
            (fixture, ids.get(0).unwrap())
        },
        |fixture, id, _| {
            let _ = fixture.client.get_event_metadata(id);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_header", "get_event_header").notes("index, timestamp, type, submitter"),
        || {
            let (fixture, ids) = seeded();
            (fixture, ids.get(0).unwrap())
        },
        |fixture, id, _| {
            let _ = fixture.client.get_event_header(id);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_by_order", "get_event_by_order").notes("sequential index lookup"),
        || {
            let (fixture, _) = seeded();
            (fixture, 0u32)
        },
        |fixture, index, _| {
            let _ = fixture.client.get_event_by_order(index);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_by_type", "get_event_by_type").notes("per-type index lookup"),
        || {
            let (fixture, _) = seeded();
            let event_type = Symbol::new(&fixture.env, SEEDED_TYPES[0]);
            (fixture, (event_type, 0u32))
        },
        |fixture, args, _| {
            let (event_type, index) = args;
            let _ = fixture.client.get_event_by_type(event_type, index);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_by_submitter", "get_event_by_submitter")
            .notes("per-submitter sub-ledger lookup"),
        || {
            let (fixture, _) = seeded();
            (fixture, 10u32)
        },
        |fixture, index, _| {
            let submitter = fixture.submitter.clone();
            let _ = fixture.client.get_event_by_submitter(&submitter, index);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "find_event_by_content", "find_event_by_content")
            .metadata(SEEDED_METADATA as u32)
            .notes("content-hash index lookup (dedup map read)"),
        || {
            let (fixture, _) = seeded();
            let event_type = Symbol::new(&fixture.env, SEEDED_TYPES[0]);
            let metadata = fixture.metadata(SEEDED_METADATA, 0);
            (fixture, (event_type, metadata))
        },
        |fixture, args, _| {
            let (event_type, metadata) = args;
            let submitter = fixture.submitter.clone();
            let _ = fixture.client.find_event_by_content(event_type, &submitter, metadata);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_with_ttl", "get_event")
            .notes("TTL active: read also extends the persistent entry"),
        || {
            let (fixture, ids) = seeded();
            let owner = fixture.owner.clone();
            fixture.client.set_event_ttl(&owner, &1_000);
            let id = ids.get(0).unwrap();
            (fixture, id)
        },
        |fixture, id, _| {
            let _ = fixture.client.get_event(id);
            1
        },
    );

    // ── Version history reads ───────────────────────────────────────────────
    bench.measure(
        CaseSpec::new("queries", "get_event_history", "get_event_history").notes("two versions recorded for the event"),
        || {
            let (fixture, _) = seeded();
            let owner = fixture.owner.clone();
            fixture.client.update_event(&owner, &5, &fixture.metadata(32, 900));
            (fixture, 5u32)
        },
        |fixture, index, _| {
            let _ = fixture.client.get_event_history(index);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_audit_trail", "get_event_audit_trail")
            .notes("audit trail alias over the version history"),
        || {
            let (fixture, _) = seeded();
            (fixture, 5u32)
        },
        |fixture, index, _| {
            let _ = fixture.client.get_event_audit_trail(index);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_version_count", "get_event_version_count"),
        || {
            let (fixture, _) = seeded();
            (fixture, 5u32)
        },
        |fixture, index, _| {
            let _ = fixture.client.get_event_version_count(index);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_diff", "get_event_diff").notes("field-level diff between version 0 and 1"),
        || {
            let (fixture, _) = seeded();
            let owner = fixture.owner.clone();
            fixture.client.update_event(&owner, &5, &fixture.metadata(32, 900));
            (fixture, 5u32)
        },
        |fixture, index, _| {
            let _ = fixture.client.get_event_diff(index, &0, &1);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "compare_event_versions", "compare_event_versions")
            .notes("version comparison summary"),
        || {
            let (fixture, _) = seeded();
            let owner = fixture.owner.clone();
            fixture.client.update_event(&owner, &5, &fixture.metadata(32, 900));
            (fixture, 5u32)
        },
        |fixture, index, _| {
            let _ = fixture.client.compare_event_versions(index, &0, &1);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_version_tag", "get_event_version_tag"),
        || {
            let (fixture, _) = seeded();
            (fixture, (5u32, 0u32))
        },
        |fixture, args, _| {
            let (index, version) = args;
            let _ = fixture.client.get_event_version_tag(index, version);
            1
        },
    );
}

/// Paginated reads, normalised per returned row.
fn paginated_scans(bench: &mut Bench) {
    for limit in [10u32, 50, 100] {
        let name = format!("list_events/limit_{limit}");
        let notes = format!("page of up to {limit} events from {SEEDED_EVENTS} seeded events");
        bench.measure(
            CaseSpec::new("queries", &name, "list_events")
                .unit("page")
                .notes(&notes),
            move || {
                let (fixture, _) = seeded();
                (fixture, limit)
            },
            |fixture, limit, _| fixture.client.list_events(&0, limit).len() as u64,
        );
    }

    for limit in [10u32, 50] {
        let name = format!("list_events_by_type/limit_{limit}");
        let notes = format!("per-type page of up to {limit} events");
        bench.measure(
            CaseSpec::new("queries", &name, "list_events_by_type")
                .unit("page")
                .notes(&notes),
            move || {
                let (fixture, _) = seeded();
                let event_type = Symbol::new(&fixture.env, SEEDED_TYPES[0]);
                (fixture, (event_type, limit))
            },
            |fixture, args, _| {
                let (event_type, limit) = args;
                fixture.client.list_events_by_type(event_type, &0, limit).len() as u64
            },
        );
    }

    bench.measure(
        CaseSpec::new("queries", "list_events_by_category/limit_50", "list_events_by_category")
            .unit("page")
            .notes("linear scan filtered by category"),
        || {
            let (fixture, _) = seeded();
            let category = Symbol::new(&fixture.env, SEEDED_CATEGORY);
            (fixture, category)
        },
        |fixture, category, _| fixture.client.list_events_by_category(category, &0, &50).len() as u64,
    );

    bench.measure(
        CaseSpec::new("queries", "get_events_by_type/limit_50", "get_events_by_type")
            .unit("page")
            .notes("per-type window read"),
        || {
            let (fixture, _) = seeded();
            let event_type = Symbol::new(&fixture.env, SEEDED_TYPES[1]);
            (fixture, event_type)
        },
        |fixture, event_type, _| fixture.client.get_events_by_type(event_type, &0, &50).len() as u64,
    );

    bench.measure(
        CaseSpec::new("queries", "get_events_by_submitter/limit_50", "get_events_by_submitter")
            .unit("page")
            .notes("per-submitter sub-ledger page"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            fixture.client.get_events_by_submitter(&submitter, &0, &50).len() as u64
        },
    );
}

/// Full-ledger scans: the cases whose cost grows with the number of events.
fn full_ledger_scans(bench: &mut Bench) {
    bench.measure(
        CaseSpec::new("queries", "search_events/limit_10", "search_events")
            .unit("page")
            .metadata(SEEDED_METADATA as u32)
            .notes("full scan with metadata substring filter"),
        || {
            let (fixture, _) = seeded();
            let query = Bytes::from_slice(&fixture.env, &[0u8, 1, 2]);
            (fixture, query)
        },
        |fixture, query, _| fixture.client.search_events(query, &0, &10).len() as u64,
    );

    bench.measure(
        CaseSpec::new("queries", "search_events_no_match/limit_10", "search_events")
            .unit("page")
            .notes("full scan that matches nothing (worst case)"),
        || {
            let (fixture, _) = seeded();
            let query = Bytes::from_slice(&fixture.env, b"no-such-payload-anywhere");
            (fixture, query)
        },
        |fixture, query, _| fixture.client.search_events(query, &0, &10).len() as u64,
    );

    bench.measure(
        CaseSpec::new(
            "queries",
            "get_events_by_time_range/limit_50",
            "get_events_by_time_range",
        )
        .unit("page")
        .notes("full scan over the seeded timestamp window"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            fixture
                .client
                .get_events_by_time_range(&(BASE_TIMESTAMP - 1), &(BASE_TIMESTAMP + 10_000), &0, &50)
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "verify_integrity", "verify_integrity").notes("re-walks the whole hash chain"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            let _ = fixture.client.verify_integrity();
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "verify_integrity_range/0_49", "verify_integrity_range")
            .notes("bounded hash-chain verification of 50 events"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            let _ = fixture.client.verify_integrity_range(&0, &50);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_statistics", "get_statistics").notes("owner-only aggregate statistics"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            let owner = fixture.owner.clone();
            let _ = fixture.client.get_statistics(&owner);
            1
        },
    );
}

/// Cheap configuration and counter reads.
fn configuration_reads(bench: &mut Bench) {
    bench.measure(
        CaseSpec::new("queries", "total_events", "total_events").notes("cached counter read"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            let _ = fixture.client.total_events();
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_type_count", "get_event_type_count"),
        || {
            let (fixture, _) = seeded();
            let event_type = Symbol::new(&fixture.env, SEEDED_TYPES[0]);
            (fixture, event_type)
        },
        |fixture, event_type, _| {
            let _ = fixture.client.get_event_type_count(event_type);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "event_count", "event_count"),
        || {
            let (fixture, _) = seeded();
            let event_type = Symbol::new(&fixture.env, SEEDED_TYPES[1]);
            (fixture, event_type)
        },
        |fixture, event_type, _| {
            let _ = fixture.client.event_count(event_type);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "event_count_by_category", "event_count_by_category"),
        || {
            let (fixture, _) = seeded();
            let category = Symbol::new(&fixture.env, SEEDED_CATEGORY);
            (fixture, category)
        },
        |fixture, category, _| {
            let _ = fixture.client.event_count_by_category(category);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "submitter_event_count", "submitter_event_count"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            let _ = fixture.client.submitter_event_count(&submitter);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_submitter_nonce_state", "get_submitter_nonce_state"),
        || {
            let (fixture, _) = seeded();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            let _ = fixture.client.get_submitter_nonce_state(&submitter);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_dedup_policy", "get_dedup_policy"),
        || (Fixture::new(), ()),
        |fixture, _, _| {
            let _ = fixture.client.get_dedup_policy();
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "is_rbac_enabled", "is_rbac_enabled"),
        || (Fixture::new(), ()),
        |fixture, _, _| {
            let _ = fixture.client.is_rbac_enabled();
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_role", "get_role"),
        || (Fixture::new(), ()),
        |fixture, _, _| {
            let owner = fixture.owner.clone();
            let _ = fixture.client.get_role(&owner);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_metadata_max_size", "get_metadata_max_size"),
        || (Fixture::new(), ()),
        |fixture, _, _| {
            let event_type = Symbol::new(&fixture.env, "transfer");
            let _ = fixture.client.get_metadata_max_size(&event_type);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_event_ttl", "get_event_ttl"),
        || (Fixture::new(), ()),
        |fixture, _, _| {
            let _ = fixture.client.get_event_ttl();
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_archive_stats", "get_archive_stats"),
        || (Fixture::new(), ()),
        |fixture, _, _| {
            let _ = fixture.client.get_archive_stats();
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_cleanup_stats", "get_cleanup_stats"),
        || (Fixture::new(), ()),
        |fixture, _, _| {
            let _ = fixture.client.get_cleanup_stats();
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_webhooks", "get_webhooks")
            .notes("registered webhook endpoints for an event type"),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            let event_type = Symbol::new(&fixture.env, "transfer");
            let url = Bytes::from_slice(&fixture.env, b"https://example.invalid/hook");
            let secret = Bytes::from_slice(&fixture.env, b"secret");
            fixture.client.register_webhook(&owner, &event_type, &url, &secret);
            (fixture, event_type)
        },
        |fixture, event_type, _| fixture.client.get_webhooks(event_type).len() as u64,
    );

    bench.measure(
        CaseSpec::new("queries", "verify_snapshot", "verify_snapshot").notes("re-walks the chain up to the snapshot"),
        || {
            let (fixture, _) = seeded();
            let owner = fixture.owner.clone();
            let description = Bytes::from_slice(&fixture.env, b"benchmark snapshot");
            fixture.client.create_snapshot(&owner, &description);
            (fixture, 0u32)
        },
        |fixture, snapshot_id, _| {
            let _ = fixture.client.verify_snapshot(snapshot_id);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_snapshot", "get_snapshot"),
        || {
            let (fixture, _) = seeded();
            let owner = fixture.owner.clone();
            let description = Bytes::from_slice(&fixture.env, b"benchmark snapshot");
            fixture.client.create_snapshot(&owner, &description);
            (fixture, 0u32)
        },
        |fixture, snapshot_id, _| {
            let _ = fixture.client.get_snapshot(snapshot_id);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_schemas", "list_schemas"),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            let event_type = Symbol::new(&fixture.env, "transfer");
            register_schema(&fixture, &owner, &event_type, 1);
            register_schema(&fixture, &owner, &event_type, 2);
            (fixture, event_type)
        },
        |fixture, event_type, _| fixture.client.list_schemas(event_type).len() as u64,
    );

    bench.measure(
        CaseSpec::new("queries", "get_schema", "get_schema"),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            let event_type = Symbol::new(&fixture.env, "transfer");
            register_schema(&fixture, &owner, &event_type, 1);
            (fixture, (event_type, 1u32))
        },
        |fixture, args, _| {
            let (event_type, version) = args;
            let _ = fixture.client.get_schema(event_type, version);
            1
        },
    );

    bench.measure(
        CaseSpec::new("queries", "get_migration_function", "get_migration_function"),
        || {
            let fixture = Fixture::new();
            let owner = fixture.owner.clone();
            let event_type = Symbol::new(&fixture.env, "transfer");
            register_migration(&fixture, &owner, &event_type);
            (fixture, event_type)
        },
        |fixture, event_type, _| {
            let _ = fixture.client.get_migration_function(event_type, &1, &2);
            1
        },
    );
}

/// Paginated and filtered reads over the on-chain ML feature store.
///
/// Every case reports a `page` unit so the per-row CPU/memory cost of the new
/// cursor-based bindings is directly comparable against the Soroban
/// single-invocation budget. Limits sweep the full range up to
/// [`MAX_PAGE_LIMIT`] to prove the cap is enforced.
fn feature_store_paginated_queries(bench: &mut Bench) {
    for limit in [1u32, 10, 50, MAX_PAGE_LIMIT] {
        let name = format!("list_features/limit_{limit}");
        let notes = format!("cursor page of up to {limit} feature vectors from {SEEDED_FEATURES} seeded");
        bench.measure(
            CaseSpec::new("queries", &name, "list_features")
                .unit("page")
                .notes(&notes),
            move || {
                let (fixture, _) = seeded_features();
                (fixture, limit)
            },
            |fixture, limit, _| fixture.client.list_features(&None, limit).len() as u64,
        );
    }

    bench.measure(
        CaseSpec::new("queries", "list_features_by_submitter/limit_50", "list_features_by_submitter")
            .unit("page")
            .notes("filtered by submitter address"),
        || {
            let (fixture, _) = seeded_features();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            fixture
                .client
                .list_features_by_submitter(&submitter, &None, 50)
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_features_by_time_range/limit_50", "list_features_by_time_range")
            .unit("page")
            .notes("filtered by ledger timestamp range"),
        || {
            let (fixture, _) = seeded_features();
            (fixture, ())
        },
        |fixture, _, _| {
            fixture
                .client
                .list_features_by_time_range(
                    &(BASE_TIMESTAMP - 1),
                    &(BASE_TIMESTAMP + FILTER_WINDOW),
                    &None,
                    50,
                )
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_features_filtered/limit_50", "list_features_filtered")
            .unit("page")
            .notes("multi-predicate: timestamp range + status + submitter"),
        || {
            let (fixture, _) = seeded_features();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            fixture
                .client
                .list_features_filtered(
                    &(BASE_TIMESTAMP - 1),
                    &(BASE_TIMESTAMP + FILTER_WINDOW),
                    &Some(ml_feature_store::FeatureStatus::Active),
                    &Some(submitter),
                    &None,
                    50,
                )
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_features_empty/limit_50", "list_features_filtered")
            .unit("page")
            .notes("empty result set (predicate matches nothing)"),
        || {
            let (fixture, _) = seeded_features();
            (fixture, ())
        },
        |fixture, _, _| {
            fixture
                .client
                .list_features_filtered(
                    &(BASE_TIMESTAMP + FILTER_WINDOW),
                    &(BASE_TIMESTAMP + FILTER_WINDOW * 2),
                    &None,
                    &None,
                    &None,
                    50,
                )
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_features_cursor_past_end/limit_50", "list_features")
            .unit("page")
            .notes("cursor past the end of the dataset (terminal page)"),
        || {
            let (fixture, _) = seeded_features();
            let cursor = Some(ml_feature_store::PageCursor {
                last_index: SEEDED_FEATURES + 1_000,
            });
            (fixture, cursor)
        },
        |fixture, cursor, _| fixture.client.list_features(cursor, 50).len() as u64,
    );
}

/// Paginated and filtered reads over the CBDC privacy guard.
fn cbdc_privacy_paginated_queries(bench: &mut Bench) {
    for limit in [1u32, 10, 50, MAX_PAGE_LIMIT] {
        let name = format!("list_disclosures/limit_{limit}");
        let notes = format!("cursor page of up to {limit} disclosure records from {SEEDED_DISCLOSURES} seeded");
        bench.measure(
            CaseSpec::new("queries", &name, "list_disclosures")
                .unit("page")
                .notes(&notes),
            move || {
                let (fixture, _) = seeded_disclosures();
                (fixture, limit)
            },
            |fixture, limit, _| fixture.client.list_disclosures(&None, limit).len() as u64,
        );
    }

    bench.measure(
        CaseSpec::new("queries", "list_disclosures_by_submitter/limit_50", "list_disclosures_by_submitter")
            .unit("page")
            .notes("filtered by submitter address"),
        || {
            let (fixture, _) = seeded_disclosures();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            fixture
                .client
                .list_disclosures_by_submitter(&submitter, &None, 50)
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_disclosures_by_time_range/limit_50", "list_disclosures_by_time_range")
            .unit("page")
            .notes("filtered by ledger timestamp range"),
        || {
            let (fixture, _) = seeded_disclosures();
            (fixture, ())
        },
        |fixture, _, _| {
            fixture
                .client
                .list_disclosures_by_time_range(
                    &(BASE_TIMESTAMP - 1),
                    &(BASE_TIMESTAMP + FILTER_WINDOW),
                    &None,
                    50,
                )
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_disclosures_filtered/limit_50", "list_disclosures_filtered")
            .unit("page")
            .notes("multi-predicate: timestamp range + status + submitter"),
        || {
            let (fixture, _) = seeded_disclosures();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            fixture
                .client
                .list_disclosures_filtered(
                    &(BASE_TIMESTAMP - 1),
                    &(BASE_TIMESTAMP + FILTER_WINDOW),
                    &Some(cbdc_privacy::DisclosureStatus::Active),
                    &Some(submitter),
                    &None,
                    50,
                )
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_disclosures_empty/limit_50", "list_disclosures_filtered")
            .unit("page")
            .notes("empty result set (predicate matches nothing)"),
        || {
            let (fixture, _) = seeded_disclosures();
            (fixture, ())
        },
        |fixture, _, _| {
            fixture
                .client
                .list_disclosures_filtered(
                    &(BASE_TIMESTAMP + FILTER_WINDOW),
                    &(BASE_TIMESTAMP + FILTER_WINDOW * 2),
                    &None,
                    &None,
                    &None,
                    50,
                )
                .len() as u64
        },
    );

    bench.measure(
        CaseSpec::new("queries", "list_disclosures_cursor_past_end/limit_50", "list_disclosures")
            .unit("page")
            .notes("cursor past the end of the dataset (terminal page)"),
        || {
            let (fixture, _) = seeded_disclosures();
            let cursor = Some(cbdc_privacy::PageCursor {
                last_index: SEEDED_DISCLOSURES + 1_000,
            });
            (fixture, cursor)
        },
        |fixture, cursor, _| fixture.client.list_disclosures(cursor, 50).len() as u64,
    );

    for limit in [1u32, 10, 50, MAX_PAGE_LIMIT] {
        let name = format!("list_tiers/limit_{limit}");
        let notes = format!("cursor page of up to {limit} tier records from {SEEDED_TIERS} seeded");
        bench.measure(
            CaseSpec::new("queries", &name, "list_tiers")
                .unit("page")
                .notes(&notes),
            move || {
                let (fixture, _) = seeded_tiers();
                (fixture, limit)
            },
            |fixture, limit, _| fixture.client.list_tiers(&None, limit).len() as u64,
        );
    }

    bench.measure(
        CaseSpec::new("queries", "list_tiers_filtered/limit_50", "list_tiers_filtered")
            .unit("page")
            .notes("multi-predicate: timestamp range + status + submitter"),
        || {
            let (fixture, _) = seeded_tiers();
            (fixture, ())
        },
        |fixture, _, _| {
            let submitter = fixture.submitter.clone();
            fixture
                .client
                .list_tiers_filtered(
                    &(BASE_TIMESTAMP - 1),
                    &(BASE_TIMESTAMP + FILTER_WINDOW),
                    &Some(cbdc_privacy::TierStatus::Active),
                    &Some(submitter),
                    &None,
                    50,
                )
                .len() as u64
        },
    );
}

/// Fixture with a populated ML feature-store index surface.
fn seeded_features() -> (Fixture, ()) {
    let fixture = Fixture::new();
    fixture.seed_features(SEEDED_FEATURES, BASE_TIMESTAMP);
    (fixture, ())
}

/// Fixture with a populated CBDC disclosure index surface.
fn seeded_disclosures() -> (Fixture, ()) {
    let fixture = Fixture::new();
    fixture.seed_disclosures(SEEDED_DISCLOSURES, BASE_TIMESTAMP);
    (fixture, ())
}

/// Fixture with a populated CBDC tier index surface.
fn seeded_tiers() -> (Fixture, ()) {
    let fixture = Fixture::new();
    fixture.seed_tiers(SEEDED_TIERS, BASE_TIMESTAMP);
    (fixture, ())
}

/// Register a permissive schema version for `event_type`.
fn register_schema(fixture: &Fixture, owner: &Address, event_type: &Symbol, version: u32) {
    let schema = audit_ledger::Schema {
        format: audit_ledger::SchemaFormat::JsonSchemaDraft7,
        version,
        definition: Bytes::from_slice(&fixture.env, b"{\"type\":\"object\"}"),
        compatibility: audit_ledger::SchemaCompatibility::Backward,
    };
    fixture.client.register_schema(owner, event_type, &schema, &version);
}

/// Register a 1 -> 2 migration path for `event_type`.
fn register_migration(fixture: &Fixture, owner: &Address, event_type: &Symbol) {
    let migration = audit_ledger::MigrationFunction {
        from_version: 1,
        to_version: 2,
        name: Symbol::new(&fixture.env, "add_field"),
        body: Bytes::from_slice(&fixture.env, b"{}"),
    };
    fixture
        .client
        .migrate_event_metadata(owner, event_type, &1, &2, &migration);
}
