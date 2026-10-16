use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Bytes, Env, Vec};

const SUBMITTERS: u32 = 5;

fn create_ledger(global_max_logs: u32) -> (Env, Address, AuditLedgerClient<'static>) {
    let env = Env::default();
    let owner = Address::generate(&env);
    let contract_id = env.register(AuditLedger, ());
    let client = AuditLedgerClient::new(&env, &contract_id);

    env.mock_all_auths();
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    client.initialize(&owners, &global_max_logs, &4096);
    (env, owner, client)
}

fn submitters(env: &Env) -> Vec<Address> {
    let mut addrs = Vec::new(env);
    for _ in 0..SUBMITTERS {
        addrs.push_back(Address::generate(env));
    }
    addrs
}

fn event_type_for(submitter_index: u32) -> Symbol {
    match submitter_index {
        0 => symbol_short!("payment"),
        1 => symbol_short!("refund"),
        2 => symbol_short!("audit"),
        3 => symbol_short!("check"),
        _ => symbol_short!("report"),
    }
}

fn metadata_for(env: &Env, submitter_index: u32, sequence: u32) -> Bytes {
    Bytes::from_slice(
        env,
        &[
            submitter_index as u8,
            (sequence & 0xff) as u8,
            ((sequence >> 8) & 0xff) as u8,
        ],
    )
}

fn log_interleaved_round(
    env: &Env,
    client: &AuditLedgerClient,
    submitters: &Vec<Address>,
    sequence: u32,
) {
    for submitter_index in 0..SUBMITTERS {
        let submitter = submitters.get(submitter_index).unwrap();
        client.log_event(
            &submitter,
            &event_type_for(submitter_index),
            &metadata_for(env, submitter_index, sequence), &None, &None, &false,
        );
    }
}

fn assert_interleaved_integrity(
    env: &Env,
    client: &AuditLedgerClient,
    submitters: &Vec<Address>,
    rounds: u32,
) {
    let expected_total = SUBMITTERS * rounds;
    assert_eq!(client.total_events(), expected_total);

    for index in 0..expected_total {
        let submitter_index = index % SUBMITTERS;
        let sequence = index / SUBMITTERS;
        let event = client.get_event_by_order(&index);

        assert_eq!(event.index, index);
        assert_eq!(event.submitter, submitters.get(submitter_index).unwrap());
        assert_eq!(event.event_type, event_type_for(submitter_index));
        assert_eq!(event.metadata, metadata_for(env, submitter_index, sequence));
    }

    for submitter_index in 0..SUBMITTERS {
        assert_eq!(client.event_count(&event_type_for(submitter_index)), rounds);
    }
}

#[test]
fn concurrent_logging_five_submitters_interleaved() {
    let (env, _owner, client) = create_ledger(600);
    let submitters = submitters(&env);

    env.mock_all_auths();
    for sequence in 0..100 {
        log_interleaved_round(&env, &client, &submitters, sequence);
    }

    assert_interleaved_integrity(&env, &client, &submitters, 100);
}

#[test]
fn concurrent_governance_cap_changes_and_logging() {
    let (env, owner, client) = create_ledger(120);
    let submitters = submitters(&env);

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &symbol_short!("payment"), &40);

    for sequence in 0..20 {
        if sequence == 5 {
            client.set_global_max_logs(&owner, &200);
        }
        if sequence == 10 {
            client.set_event_max_logs(&owner, &symbol_short!("payment"), &75);
        }
        log_interleaved_round(&env, &client, &submitters, sequence);
    }

    assert_interleaved_integrity(&env, &client, &submitters, 20);
}

#[test]
fn concurrent_ownership_transfer_and_logging() {
    let (env, owner, client) = create_ledger(150);
    let submitters = submitters(&env);
    let new_owner = Address::generate(&env);

    env.mock_all_auths();
    for sequence in 0..20 {
        if sequence == 8 {
            client.transfer_ownership(&owner, &new_owner);
        }
        if sequence == 12 {
            client.set_global_max_logs(&new_owner, &200);
        }
        log_interleaved_round(&env, &client, &submitters, sequence);
    }

    assert_interleaved_integrity(&env, &client, &submitters, 20);
}

// ---------------------------------------------------------------------------
// Multi-actor concurrent access scenarios for `src/supply_chain.rs`
// ---------------------------------------------------------------------------

fn supply_chain_actors(env: &Env, count: u32) -> Vec<Address> {
    let mut addrs = Vec::new(env);
    for _ in 0..count {
        addrs.push_back(Address::generate(env));
    }
    addrs
}

fn register_supply_chain_product(
    env: &Env,
    client: &AuditLedgerClient,
    brand: &Address,
    product_id: u32,
) {
    client.register_product(
        brand,
        &symbol_short!("coffee"),
        &Bytes::from_slice(env, &[product_id as u8, (product_id >> 8) as u8]),
        &Bytes::from_slice(env, &[0xAA, 0xBB]),
    );
}

#[test]
fn concurrent_supply_chain_custody_transfers_interleaved() {
    let (env, _owner, client) = create_ledger(600);
    let actors = supply_chain_actors(&env, 4);

    env.mock_all_auths();
    register_supply_chain_product(&env, &client, &actors.get(0).unwrap(), 1);

    // Interleave custody handoffs across multiple actors. Each transfer must
    // preserve the hash-chain linkage to the previous custody record.
    for round in 0..50u32 {
        let from = actors.get(round % 4).unwrap();
        let to = actors.get((round + 1) % 4).unwrap();
        client.transfer_custody(
            &from,
            &to,
            &Bytes::from_slice(&env, &[round as u8, (round >> 8) as u8]),
            &None,
        );
    }

    let history = client.get_custody_history();
    assert_eq!(history.len(), 50);

    // Verify hash-chain integrity: each record links to the prior hash.
    let mut previous_hash: Option<Bytes> = None;
    for i in 0..history.len() {
        let record = history.get(i).unwrap();
        if let Some(prev) = previous_hash {
            assert_eq!(record.previous_hash, prev);
        }
        previous_hash = Some(record.record_hash.clone());
    }
}

#[test]
fn concurrent_supply_chain_certification_and_reports() {
    let (env, _owner, client) = create_ledger(600);
    let actors = supply_chain_actors(&env, 3);

    env.mock_all_auths();
    register_supply_chain_product(&env, &client, &actors.get(0).unwrap(), 7);

    for round in 0..40u32 {
        let actor = actors.get(round % 3).unwrap();
        if round % 2 == 0 {
            client.submit_certification(
                &actor,
                &symbol_short!("organic"),
                &Bytes::from_slice(&env, &[round as u8]),
            );
        } else {
            client.submit_labor_report(
                &actor,
                &Bytes::from_slice(&env, &[round as u8, 0x01]),
            );
            client.submit_environmental_report(
                &actor,
                &Bytes::from_slice(&env, &[round as u8, 0x02]),
            );
        }
    }

    // State consistency: certifications and reports remain independently
    // queryable and counts match the interleaved submissions.
    assert_eq!(client.certification_count(), 20);
    assert_eq!(client.labor_report_count(), 20);
    assert_eq!(client.environmental_report_count(), 20);
}

#[test]
fn concurrent_supply_chain_brand_and_product_registration() {
    let (env, _owner, client) = create_ledger(600);
    let brands = supply_chain_actors(&env, 3);

    env.mock_all_auths();
    for brand_index in 0..3u32 {
        let brand = brands.get(brand_index).unwrap();
        client.register_brand(
            &brand,
            &Bytes::from_slice(&env, &[brand_index as u8]),
        );
    }

    // Concurrent product registration across brands with interleaved ids.
    for product_id in 0..30u32 {
        let brand = brands.get(product_id % 3).unwrap();
        register_supply_chain_product(&env, &client, &brand, product_id);
    }

    assert_eq!(client.brand_count(), 3);
    assert_eq!(client.product_count(), 30);

    // Hash-chain integrity must hold after concurrent registrations.
    let history = client.get_custody_history();
    let mut previous_hash: Option<Bytes> = None;
    for i in 0..history.len() {
        let record = history.get(i).unwrap();
        if let Some(prev) = previous_hash {
            assert_eq!(record.previous_hash, prev);
        }
        previous_hash = Some(record.record_hash.clone());
    }
}

#[test]
fn concurrent_cap_removal_and_logging_same_type() {
    let (env, owner, client) = create_ledger(150);
    let submitters = submitters(&env);
    let event_type = symbol_short!("payment");

    env.mock_all_auths();
    client.set_event_max_logs(&owner, &event_type, &12);

    for sequence in 0..20 {
        if sequence == 6 {
            client.remove_event_cap(&owner, &event_type);
        }

        let submitter_index = sequence % SUBMITTERS;
        let submitter = submitters.get(submitter_index).unwrap();
        client.log_event(
            &submitter,
            &event_type,
            &metadata_for(&env, submitter_index, sequence), &None, &None, &false,
        );
    }

    assert_eq!(client.total_events(), 20);
    assert_eq!(client.event_count(&event_type), 20);
    assert!(!client.has_cap(&event_type));

    for index in 0..20 {
        let submitter_index = index % SUBMITTERS;
        let event = client.get_event_by_order(&index);
        assert_eq!(event.index, index);
        assert_eq!(event.event_type, event_type);
        assert_eq!(event.submitter, submitters.get(submitter_index).unwrap());
        assert_eq!(event.metadata, metadata_for(&env, submitter_index, index));
    }
}
