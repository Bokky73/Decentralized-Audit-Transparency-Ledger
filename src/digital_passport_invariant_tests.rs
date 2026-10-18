#![cfg(test)]

extern crate std;

use crate::digital_passport::*;
use proptest::prelude::*;
use soroban_sdk::{bytes, vec, Address, Bytes, BytesN, Env, Symbol, Vec as SorobanVec};
use std::panic;

const INVARIANT_PASSPORTS: u32 = 5;

fn test_material(env: &Env, name: &str, code: &str, percent: u32) -> Material {
    Material {
        material_name: bytes!(env, name),
        material_code: Symbol::new(env, code),
        percentage_by_weight: percent,
        source_type: Symbol::new(env, "virgin"),
        hazardous: false,
        hazard_classification: bytes!(env, ""),
    }
}

fn test_durability(env: &Env) -> Durability {
    Durability {
        expected_lifetime_years: 5,
        warranty_years: 2,
        spare_parts_available: true,
        spare_parts_years: 10,
        repair_information: bytes!(env, "https://repair.example.com"),
        repairability_score: 8,
    }
}

fn test_circularity(env: &Env) -> Circularity {
    let mut recyclable = vec![env];
    recyclable.push_back(test_material(env, "Aluminum", "AL", 100));
    Circularity {
        recyclable_materials: recyclable,
        recycled_content_percent: 30,
        reuse_potential: true,
        refurbishment_potential: true,
        disassembly_instructions: bytes!(env, "See manual page 5"),
        recycling_instructions: bytes!(env, "Place in aluminum bin"),
        end_of_life_score: 85,
    }
}

fn test_carbon_footprint(env: &Env) -> CarbonFootprint {
    CarbonFootprint {
        manufacturing_emissions: 500,
        distribution_emissions: 100,
        use_phase_emissions: 50,
        end_of_life_emissions: 25,
        total_embodied_carbon: 675,
        carbon_neutral: false,
        carbon_offset_program: bytes!(env, ""),
        measurement_standard: Symbol::new(env, "ISO_14040"),
        measurement_date: 1692345600,
    }
}

fn create_standard_passport(env: &Env, manufacturer: &Address, product_id: Bytes) -> BytesN<32> {
    create_passport(
        env,
        product_id,
        bytes!(env, "Test Product"),
        Symbol::new(env, "test"),
        manufacturer.clone(),
        bytes!(env, "V1.0"),
        bytes!(env, "BATCH-001"),
        vec![env, test_material(env, "Aluminum", "AL", 100)],
        test_durability(env),
        test_circularity(env),
        test_carbon_footprint(env),
    )
}

/// Core invariants that must hold for every passport at all times.
fn assert_passport_invariants(env: &Env, passport_id: &BytesN<32>) {
    let passport = get_passport(env, passport_id.clone());

    assert!(passport.version >= 1, "passport version must be >= 1");
    assert!(
        passport.expiry_date >= passport.created_date,
        "expiry must not precede creation"
    );

    let score = calculate_environmental_score(env, passport_id.clone());
    assert!(score <= 100, "environmental score must be within 0..=100");

    assert_eq!(
        get_repair_count(env, passport_id.clone()) as usize,
        get_repair_history(env, passport_id.clone()).len(),
        "repair counter must match repair history length"
    );
    assert_eq!(
        get_recycling_count(env, passport_id.clone()) as usize,
        get_recycling_history(env, passport_id.clone()).len(),
        "recycling counter must match recycling history length"
    );

    let history = get_lifecycle_history(env, passport_id.clone());
    let mut previous = PassportLifecycleStage::Created;
    for event in history.iter() {
        assert_eq!(
            event.previous_stage, previous,
            "lifecycle history chain must be contiguous"
        );
        previous = event.stage.clone();
    }
    assert_eq!(
        passport.lifecycle_stage, previous,
        "current stage must match lifecycle history tail"
    );

    for material in passport.materials.iter() {
        assert!(
            material.percentage_by_weight <= 100,
            "material percentage must be bounded by 100"
        );
    }
}

fn assert_global_invariants(env: &Env, expected_passports: u32) {
    assert_eq!(
        get_total_passports(env),
        expected_passports,
        "global passport counter must match created passports"
    );
}

// ── Property-based tests ───────────────────────────────────────────────

#[derive(Clone, Debug)]
enum PassportOp {
    Transition { idx: u32, stage: PassportLifecycleStage },
    Repair { idx: u32 },
    Recycle { idx: u32 },
    Refurbish { idx: u32 },
    Compliance { idx: u32 },
    Update { idx: u32 },
}

fn passport_op_strategy() -> impl Strategy<Value = PassportOp> {
    let idx = 0u32..(INVARIANT_PASSPORTS - 1);
    let stage = prop_oneof![
        1 => Just(PassportLifecycleStage::InProduction),
        1 => Just(PassportLifecycleStage::ReadyForMarket),
        1 => Just(PassportLifecycleStage::InMarket),
        1 => Just(PassportLifecycleStage::EndOfLife),
        1 => Just(PassportLifecycleStage::Recycled),
        1 => Just(PassportLifecycleStage::Archived),
    ];
    prop_oneof![
        2 => (idx.clone(), stage).map(|(idx, stage)| PassportOp::Transition { idx, stage }),
        1 => idx.clone().map(PassportOp::Repair),
        1 => idx.clone().map(PassportOp::Recycle),
        1 => idx.clone().map(PassportOp::Refurbish),
        1 => idx.clone().map(PassportOp::Compliance),
        1 => idx.clone().map(PassportOp::Update),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 150, .. ProptestConfig::default() })]

    #[test]
    fn prop_state_consistency_under_random_ops(ops in prop::collection::vec(passport_op_strategy(), 1..=80)) {
        let env = Env::default();
        env.mock_all_auths();
        let manufacturer = Address::random(&env);

        let mut passports: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
        for i in 0..INVARIANT_PASSPORTS {
            let pid = create_standard_passport(
                &env,
                &manufacturer,
                bytes!(env, format!("PRODUCT-{i}").as_bytes()),
            );
            passports.push_back(pid);
        }

        for op in ops.iter() {
            let idx = op_index(op) as usize;
            let pid = passports.get(idx).unwrap();
            let actor = manufacturer.clone();
            match op {
                PassportOp::Transition { stage, .. } => {
                    transition_lifecycle_stage(
                        &env,
                        pid.clone(),
                        stage.clone(),
                        actor.clone(),
                        bytes!(env, "op transition"),
                    );
                }
                PassportOp::Repair { .. } => {
                    record_repair(
                        &env,
                        pid.clone(),
                        actor.clone(),
                        Symbol::new(&env, "minor"),
                        vec![&env],
                        bytes!(env, "op repair"),
                    );
                }
                PassportOp::Recycle { .. } => {
                    record_recycling(
                        &env,
                        pid.clone(),
                        actor.clone(),
                        90,
                        vec![env, test_material(&env, "Aluminum", "AL", 100)],
                        bytes!(env, "CERT-OP"),
                    );
                }
                PassportOp::Refurbish { .. } => {
                    record_refurbishment(
                        &env,
                        pid.clone(),
                        actor.clone(),
                        bytes!(env, "op refurbish"),
                    );
                }
                PassportOp::Compliance { .. } => {
                    let _ = verify_espr_compliance(&env, pid.clone(), actor.clone());
                }
                PassportOp::Update { .. } => {
                    update_passport(
                        &env,
                        pid.clone(),
                        None,
                        None,
                        None,
                        actor.clone(),
                    );
                }
            }
        }

        for pid in passports.iter() {
            assert_passport_invariants(&env, pid);
        }
        assert_global_invariants(&env, INVARIANT_PASSPORTS);
    }
}

fn op_index(op: &PassportOp) -> u32 {
    match op {
        PassportOp::Transition { idx, .. } => *idx,
        PassportOp::Repair { idx } => *idx,
        PassportOp::Recycle { idx } => *idx,
        PassportOp::Refurbish { idx } => *idx,
        PassportOp::Compliance { idx } => *idx,
        PassportOp::Update { idx } => *idx,
    }
}

// ── Chaos / fault-injection tests ──────────────────────────────────────

#[test]
fn chaos_duplicate_create_is_rejected_and_state_stays_consistent() {
    let env = Env::default();
    env.mock_all_auths();
    let manufacturer = Address::random(&env);
    let product_id = bytes!(env, "DUPLICATE-PRODUCT");

    let pid = create_standard_passport(&env, &manufacturer, product_id.clone());

    let result = panic::catch_unwind(|| {
        create_standard_passport(&env, &manufacturer, product_id.clone())
    });
    assert!(result.is_err(), "duplicate passport creation must be rejected");

    assert_eq!(get_total_passports(&env), 1);
    let index = get_product_passports(&env, product_id);
    assert_eq!(index.len(), 1);
    assert_eq!(index.get(0).unwrap(), pid);
    assert_passport_invariants(&env, &pid);
}

#[test]
fn chaos_missing_passport_operations_panic_cleanly() {
    let env = Env::default();
    env.mock_all_auths();
    let missing = BytesN::from_array(&env, [0u8; 32]);
    let actor = Address::random(&env);

    let ops: Vec<Box<dyn FnOnce()>> = vec![
        Box::new(|| {
            get_passport(&env, missing.clone());
        }),
        Box::new(|| {
            transition_lifecycle_stage(
                &env,
                missing.clone(),
                PassportLifecycleStage::InProduction,
                actor.clone(),
                bytes!(env, "x"),
            );
        }),
        Box::new(|| {
            update_passport(&env, missing.clone(), None, None, None, actor.clone());
        }),
        Box::new(|| {
            record_repair(
                &env,
                missing.clone(),
                actor.clone(),
                Symbol::new(&env, "minor"),
                vec![&env],
                bytes!(env, "x"),
            );
        }),
        Box::new(|| {
            record_recycling(
                &env,
                missing.clone(),
                actor.clone(),
                90,
                vec![&env],
                bytes!(env, "x"),
            );
        }),
        Box::new(|| {
            record_refurbishment(&env, missing.clone(), actor.clone(), bytes!(env, "x"));
        }),
    ];

    for op in ops {
        let result = panic::catch_unwind(op);
        assert!(
            result.is_err(),
            "operations on a missing passport must panic deterministically"
        );
    }
}

#[test]
fn chaos_non_manufacturer_update_leaves_state_unchanged() {
    let env = Env::default();
    env.mock_all_auths();
    let manufacturer = Address::random(&env);
    let intruder = Address::random(&env);
    let pid = create_standard_passport(&env, &manufacturer, bytes!(env, "IMMUTABLE-PRODUCT"));

    let before = get_passport(&env, pid.clone());

    let result = panic::catch_unwind(|| update_passport(&env, pid.clone(), None, None, None, intruder));
    assert!(result.is_err(), "non-manufacturer update must be rejected");

    let after = get_passport(&env, pid.clone());
    assert_eq!(before, after, "rejected update must leave passport state unchanged");
    assert_passport_invariants(&env, &pid);
}

#[test]
fn chaos_malformed_inputs_are_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let manufacturer = Address::random(&env);

    // Material percentage above 100% must be rejected at creation.
    let mut bad_materials = vec![&env];
    bad_materials.push_back(Material {
        material_name: bytes!(env, "Bad"),
        material_code: Symbol::new(env, "BD"),
        percentage_by_weight: 101,
        source_type: Symbol::new(env, "virgin"),
        hazardous: false,
        hazard_classification: bytes!(env, ""),
    });
    let result = panic::catch_unwind(|| {
        create_passport(
            &env,
            bytes!(env, "BAD-MATERIAL"),
            bytes!(env, "X"),
            Symbol::new(env, "t"),
            manufacturer.clone(),
            bytes!(env, "V1"),
            bytes!(env, "B1"),
            bad_materials,
            test_durability(&env),
            test_circularity(&env),
            test_carbon_footprint(&env),
        )
    });
    assert!(result.is_err());
    assert_eq!(get_total_passports(&env), 0);

    // Empty product id must be rejected.
    let result = panic::catch_unwind(|| {
        create_passport(
            &env,
            bytes!(env, ""),
            bytes!(env, "X"),
            Symbol::new(env, "t"),
            manufacturer.clone(),
            bytes!(env, "V1"),
            bytes!(env, "B1"),
            vec![env, test_material(&env, "Al", "AL", 100)],
            test_durability(&env),
            test_circularity(&env),
            test_carbon_footprint(&env),
        )
    });
    assert!(result.is_err());

    // Recovery rate above 100% must be rejected.
    let pid = create_standard_passport(&env, &manufacturer, bytes!(env, "RECOVERY-PRODUCT"));
    let result = panic::catch_unwind(|| {
        record_recycling(
            &env,
            pid.clone(),
            manufacturer.clone(),
            150,
            vec![&env],
            bytes!(env, "CERT"),
        )
    });
    assert!(result.is_err());
    assert_passport_invariants(&env, &pid);
}

#[test]
fn chaos_reordered_lifecycle_events_stay_consistent() {
    let env = Env::default();
    env.mock_all_auths();
    let manufacturer = Address::random(&env);
    let facility = Address::random(&env);
    let pid = create_standard_passport(&env, &manufacturer, bytes!(env, "REORDER-PRODUCT"));

    // Recycle first (>80% recovery moves to Recycled), then refurbish (back to InMarket),
    // then end-of-life and archive. Every order must preserve invariants.
    record_recycling(
        &env,
        pid.clone(),
        facility.clone(),
        95,
        vec![env, test_material(&env, "Aluminum", "AL", 100)],
        bytes!(env, "CERT-REORDER"),
    );
    record_refurbishment(&env, pid.clone(), facility.clone(), bytes!(env, "refurbished"));
    transition_lifecycle_stage(
        &env,
        pid.clone(),
        PassportLifecycleStage::EndOfLife,
        manufacturer.clone(),
        bytes!(env, "end of life"),
    );
    transition_lifecycle_stage(
        &env,
        pid.clone(),
        PassportLifecycleStage::Archived,
        manufacturer.clone(),
        bytes!(env, "archived"),
    );

    assert_passport_invariants(&env, &pid);
    assert_eq!(
        get_lifecycle_history(&env, pid.clone()).len(),
        4,
        "all four reordered events must be recorded"
    );
}

#[test]
fn chaos_interleaved_actors_preserve_invariants() {
    let env = Env::default();
    env.mock_all_auths();
    let m1 = Address::random(&env);
    let m2 = Address::random(&env);
    let facility = Address::random(&env);

    let mut passports: SorobanVec<BytesN<32>> = SorobanVec::new(&env);
    for i in 0..8u32 {
        let manufacturer = if i % 2 == 0 { m1.clone() } else { m2.clone() };
        passports.push_back(create_standard_passport(
            &env,
            &manufacturer,
            bytes!(env, format!("CONC-{i}").as_bytes()),
        ));
    }

    for round in 0..10u32 {
        for pid in passports.iter() {
            match round % 3 {
                0 => transition_lifecycle_stage(
                    &env,
                    pid.clone(),
                    PassportLifecycleStage::InProduction,
                    m1.clone(),
                    bytes!(env, "round"),
                ),
                1 => record_repair(
                    &env,
                    pid.clone(),
                    facility.clone(),
                    Symbol::new(&env, "minor"),
                    vec![&env],
                    bytes!(env, "round"),
                ),
                _ => {
                    let _ = verify_espr_compliance(&env, pid.clone(), m2.clone());
                }
            }
        }
    }

    for pid in passports.iter() {
        assert_passport_invariants(&env, pid);
    }
    assert_global_invariants(&env, 8);
}

#[test]
fn chaos_export_and_query_after_full_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();
    let manufacturer = Address::random(&env);
    let facility = Address::random(&env);
    let verifier = Address::random(&env);
    let pid = create_standard_passport(&env, &manufacturer, bytes!(env, "EXPORT-PRODUCT"));

    transition_lifecycle_stage(
        &env,
        pid.clone(),
        PassportLifecycleStage::InMarket,
        manufacturer.clone(),
        bytes!(env, "released"),
    );
    let _status = verify_espr_compliance(&env, pid.clone(), verifier.clone());
    let _export = generate_passport_export(&env, pid.clone(), ExportFormat::JsonLd);
    let _breakdown = get_material_breakdown(&env, pid.clone());
    let _carbon = get_carbon_footprint(&env, pid.clone());
    let _circularity = get_circularity_info(&env, pid.clone());

    assert_passport_invariants(&env, &pid);
    assert!(check_passport_validity(&env, pid.clone()));
}
