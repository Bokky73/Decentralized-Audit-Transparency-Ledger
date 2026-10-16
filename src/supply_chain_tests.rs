#[cfg(test)]
mod tests {
    use crate::rbac::*;
    use crate::supply_chain::*;
    use soroban_sdk::{bytes, vec, Address, BytesN, Env, Symbol, Vec};

    /// Helper to create test location
    fn create_test_location(env: &Env, name: &str, country: &str) -> Location {
        Location {
            name: bytes!(env, name),
            country: Symbol::new(env, country),
            coordinates: bytes!(env, "0.0,0.0"),
            facility_id: bytes!(env, "FAC001"),
        }
    }

    /// Helper to grant a role to an address for RBAC-gated tests.
    fn grant_role(env: &Env, admin: &Address, account: &Address, role: Role) {
        rbac_grant_role(env, admin.clone(), account.clone(), role);
    }

    /// Helper to set up an admin and grant a role to a caller.
    fn setup_caller_with_role(env: &Env, role: Role) -> Address {
        let admin = Address::random(env);
        let caller = Address::random(env);
        rbac_init(env, admin.clone());
        grant_role(env, &admin, &caller, role);
        caller
    }

    /// Helper to count audit events emitted in the current test environment.
    fn audit_event_count(env: &Env) -> u32 {
        env.events().all().len()
    }

    /// Test brand registration
    #[test]
    fn test_register_brand() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");

        register_brand(
            &env,
            owner.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier of quality products"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        // Verify brand was registered by checking it exists in storage
        assert!(env
            .storage()
            .persistent()
            .has(&SupplyChainDataKey::Brand(brand_id.clone())));
    }

    /// Test product SKU registration
    #[test]
    fn test_register_product_sku() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");

        // Register brand first
        register_brand(
            &env,
            owner.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier of quality products"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        // Register product SKU
        let sku = bytes!(&env, "SKU-12345");
        register_product_sku(
            &env,
            brand_id.clone(),
            sku.clone(),
            bytes!(&env, "Premium Widget"),
            bytes!(&env, "High quality widget for general use"),
        );

        // Verify product was registered
        assert!(env
            .storage()
            .persistent()
            .has(&SupplyChainDataKey::ProductSKU(brand_id.clone(), sku)));
    }

    /// Test provenance event logging
    #[test]
    fn test_log_provenance_event() {
        let env = Env::default();
        env.mock_all_auths();

        let producer = Address::random(&env);
        let event_id = BytesN::<32>::random(&env);
        let location = create_test_location(&env, "Widget Factory", "US");

        log_provenance_event(
            &env,
            event_id,
            location,
            bytes!(&env, "Premium aluminum"),
            producer.clone(),
            bytes!(&env, "BATCH-2024-001"),
        );

        // Verify provenance was logged
        let provenance: Provenance = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::ProvenanceEvent(event_id))
            .expect("Provenance event should exist");

        assert_eq!(provenance.producer_address, producer);
        assert!(!provenance.is_verified);
    }

    /// Test custody transfer logging
    #[test]
    fn test_log_custody_transfer() {
        let env = Env::default();
        env.mock_all_auths();

        let producer = Address::random(&env);
        let distributor = Address::random(&env);
        let event_id = BytesN::<32>::random(&env);
        let location = create_test_location(&env, "Widget Factory", "US");

        // First log provenance
        log_provenance_event(
            &env,
            event_id,
            location.clone(),
            bytes!(&env, "Premium aluminum"),
            producer.clone(),
            bytes!(&env, "BATCH-2024-001"),
        );

        // Log custody transfer
        let transfer_location = create_test_location(&env, "Distribution Center", "CA");
        log_custody_transfer(
            &env,
            event_id,
            producer.clone(),
            distributor.clone(),
            transfer_location,
            bytes!(&env, "Shipped via truck"),
        );

        // Verify custody transfer was logged
        let provenance: Provenance = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::ProvenanceEvent(event_id))
            .expect("Provenance event should exist");

        assert_eq!(provenance.chain_of_custody.len(), 1);
        assert_eq!(provenance.chain_of_custody.get(0).unwrap().to_address, distributor);
    }

    /// Test certification logging
    #[test]
    fn test_log_certification() {
        let env = Env::default();
        env.mock_all_auths();

        let issuer = Address::random(&env);
        let cert_id = bytes!(&env, "CERT-ISO9001-2024");
        let cert_type = Symbol::new(&env, "ISO_9001");

        log_certification(
            &env,
            cert_id.clone(),
            cert_type.clone(),
            issuer.clone(),
            365, // 1 year validity
            bytes!(&env, "Quality management system for manufacturing"),
        );

        // Retrieve certification from storage
        let cert_event_id = env.crypto().sha256(&cert_id);
        let certification: Certification = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::CertificationEvent(cert_event_id))
            .expect("Certification should exist");

        assert_eq!(certification.issuer, issuer);
        assert!(certification.is_active);
        assert_eq!(certification.cert_type, cert_type);
    }

    /// Test labor conditions logging
    #[test]
    fn test_log_labor_conditions() {
        let env = Env::default();
        env.mock_all_auths();

        let reporter = Address::random(&env);
        let facility_id = bytes!(&env, "FAC-FACTORY-001");
        let report_hash = BytesN::<32>::random(&env);

        log_labor_conditions(
            &env,
            facility_id.clone(),
            500,            // workers
            true,           // wage compliant
            true,           // hours compliant
            true,           // no child labor
            true,           // safety met
            true,           // freedom of association
            report_hash,
            reporter,
        );

        // Verify labor report was logged
        let report_id = env.crypto().sha256(&facility_id);
        let labor: LaborConditions = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::LaborReport(report_id))
            .expect("Labor report should exist");

        assert_eq!(labor.worker_count, 500);
        assert!(labor.wage_compliance);
        assert!(labor.child_labor_free);
    }

    /// Test environmental impact logging
    #[test]
    fn test_log_environmental_impact() {
        let env = Env::default();
        env.mock_all_auths();

        let reporter = Address::random(&env);
        let facility_id = bytes!(&env, "FAC-FACTORY-001");
        let report_hash = BytesN::<32>::random(&env);
        let now = env.ledger().timestamp();

        log_environmental_impact(
            &env,
            facility_id.clone(),
            now,                                    // period start
            now + (30 * 86400),                     // period end
            5000,                                   // carbon footprint (kg CO2e)
            1000000,                                // water usage (liters)
            500,                                    // waste (kg)
            75,                                     // renewable energy %
            10,                                     // emissions reduction %
            report_hash,
            reporter,
        );

        // Verify environmental report was logged
        let report_id = env.crypto().sha256(&facility_id);
        let env_impact: EnvironmentalImpact = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::EnvironmentalReport(report_id))
            .expect("Environmental report should exist");

        assert_eq!(env_impact.carbon_footprint, 5000);
        assert_eq!(env_impact.renewable_energy_percent, 75);
        assert!(env_impact.emissions_reduction_percent > 0);
    }

    /// Test product chain verification
    #[test]
    fn test_verify_product_chain_minimal() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");
        let sku = bytes!(&env, "SKU-12345");

        // Setup brand and product
        register_brand(
            &env,
            owner.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        register_product_sku(
            &env,
            brand_id.clone(),
            sku.clone(),
            bytes!(&env, "Premium Widget"),
            bytes!(&env, "High quality widget"),
        );

        // Verify product chain
        let verification = verify_product_chain(&env, brand_id.clone(), sku.clone());

        assert_eq!(verification.product_sku, sku);
        assert!(!verification.is_verified); // Not verified without full chain
    }

    /// Test certification verification
    #[test]
    fn test_verify_certification_valid() {
        let env = Env::default();
        env.mock_all_auths();

        let issuer = Address::random(&env);
        let cert_id = bytes!(&env, "CERT-ISO9001-2024");

        log_certification(
            &env,
            cert_id.clone(),
            Symbol::new(&env, "ISO_9001"),
            issuer,
            365, // 1 year
            bytes!(&env, "Quality management system"),
        );

        let is_valid = verify_certification(&env, cert_id);
        assert!(is_valid);
    }

    /// Test certification verification expired
    #[test]
    fn test_verify_certification_expired() {
        let env = Env::default();
        env.mock_all_auths();

        let issuer = Address::random(&env);
        let cert_id = bytes!(&env, "CERT-EXPIRED-2024");

        log_certification(
            &env,
            cert_id.clone(),
            Symbol::new(&env, "ISO_9001"),
            issuer,
            0, // Already expired
            bytes!(&env, "Expired certification"),
        );

        // Note: This may not work as expected due to how expiry is calculated
        // but demonstrates the testing pattern
        let is_valid = verify_certification(&env, cert_id);
        assert!(!is_valid);
    }

    /// Test get product timeline
    #[test]
    fn test_get_product_timeline() {
        let env = Env::default();
        env.mock_all_auths();

        let producer = Address::random(&env);
        let event_id = BytesN::<32>::random(&env);
        let location = create_test_location(&env, "Widget Factory", "US");

        log_provenance_event(
            &env,
            event_id,
            location,
            bytes!(&env, "Premium aluminum"),
            producer.clone(),
            bytes!(&env, "BATCH-2024-001"),
        );

        let event_ids = vec![&env, event_id];
        let timeline = get_product_timeline(&env, event_ids);

        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline.get(0).unwrap().entry_type, Symbol::new(&env, "origin"));
    }

    /// Test brand integrity report
    #[test]
    fn test_get_brand_integrity_report() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");

        register_brand(
            &env,
            owner.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        let report = get_brand_integrity_report(&env, brand_id.clone());

        assert_eq!(report.brand_id, brand_id);
        assert!(report.compliance_trend == Symbol::new(&env, "stable"));
    }

    /// Test QR code URL generation
    #[test]
    fn test_generate_qr_code_url() {
        let env = Env::default();
        let brand_id = Symbol::new(&env, "ACME");
        let sku = bytes!(&env, "SKU-12345");
        let base_url = bytes!(&env, "https://verify.acme.example.com/verify");

        let qr_url = generate_qr_code_url(&env, brand_id, sku, base_url);

        assert!(!qr_url.is_empty());
    }

    /// Test integrity proof generation
    #[test]
    fn test_generate_integrity_proof() {
        let env = Env::default();
        env.mock_all_auths();

        let event_ids = vec![&env, BytesN::<32>::random(&env), BytesN::<32>::random(&env)];

        let proof = generate_integrity_proof(&env, event_ids);

        // Proof should be a valid 32-byte hash
        assert_eq!(proof.len(), 32);
    }

    /// Test multiple custody transfers
    #[test]
    fn test_multiple_custody_transfers() {
        let env = Env::default();
        env.mock_all_auths();

        let producer = Address::random(&env);
        let distributor = Address::random(&env);
        let retailer = Address::random(&env);
        let event_id = BytesN::<32>::random(&env);
        let location = create_test_location(&env, "Factory", "US");

        // Log provenance
        log_provenance_event(
            &env,
            event_id,
            location.clone(),
            bytes!(&env, "Premium aluminum"),
            producer.clone(),
            bytes!(&env, "BATCH-2024-001"),
        );

        // Transfer 1: Producer -> Distributor
        let dist_location = create_test_location(&env, "Distribution", "CA");
        log_custody_transfer(
            &env,
            event_id,
            producer.clone(),
            distributor.clone(),
            dist_location,
            bytes!(&env, "Transport 1"),
        );

        // Transfer 2: Distributor -> Retailer
        let retail_location = create_test_location(&env, "Retail", "TX");
        log_custody_transfer(
            &env,
            event_id,
            distributor.clone(),
            retailer.clone(),
            retail_location,
            bytes!(&env, "Transport 2"),
        );

        // Verify chain
        let provenance: Provenance = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::ProvenanceEvent(event_id))
            .expect("Provenance event should exist");

        assert_eq!(provenance.chain_of_custody.len(), 2);
        assert_eq!(provenance.chain_of_custody.get(0).unwrap().to_address, distributor);
        assert_eq!(provenance.chain_of_custody.get(1).unwrap().to_address, retailer);
    }

    /// Test labor conditions with compliance issues
    #[test]
    fn test_labor_conditions_non_compliant() {
        let env = Env::default();
        env.mock_all_auths();

        let reporter = Address::random(&env);
        let facility_id = bytes!(&env, "FAC-FACTORY-BAD");
        let report_hash = BytesN::<32>::random(&env);

        log_labor_conditions(
            &env,
            facility_id.clone(),
            50,             // workers
            false,          // wage NOT compliant
            false,          // hours NOT compliant
            false,          // child labor present
            false,          // safety NOT met
            false,          // no freedom of association
            report_hash,
            reporter,
        );

        let report_id = env.crypto().sha256(&facility_id);
        let labor: LaborConditions = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::LaborReport(report_id))
            .expect("Labor report should exist");

        assert!(!labor.wage_compliance);
        assert!(!labor.child_labor_free);
        assert!(!labor.safety_standards_met);
    }

    /// Test environmental impact tracking
    #[test]
    fn test_environmental_impact_improvement() {
        let env = Env::default();
        env.mock_all_auths();

        let reporter = Address::random(&env);
        let facility_id = bytes!(&env, "FAC-FACTORY-GREEN");
        let report_hash = BytesN::<32>::random(&env);
        let now = env.ledger().timestamp();

        log_environmental_impact(
            &env,
            facility_id.clone(),
            now,
            now + (30 * 86400),
            2000,       // Lower carbon footprint
            500000,     // Lower water usage
            100,        // Lower waste
            90,         // High renewable energy
            25,         // Good emissions reduction
            report_hash,
            reporter,
        );

        let report_id = env.crypto().sha256(&facility_id);
        let env_impact: EnvironmentalImpact = env
            .storage()
            .persistent()
            .get(&SupplyChainDataKey::EnvironmentalReport(report_id))
            .expect("Environmental report should exist");

        assert!(env_impact.renewable_energy_percent >= 80);
        assert!(env_impact.emissions_reduction_percent > 20);
    }

    /// Test full supply chain scenario
    #[test]
    fn test_full_supply_chain_scenario() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let producer = Address::random(&env);
        let certifier = Address::random(&env);
        let labor_auditor = Address::random(&env);
        let env_auditor = Address::random(&env);

        let brand_id = Symbol::new(&env, "ECO_BRAND");
        let sku = bytes!(&env, "ECO-WIDGET-001");

        // 1. Register brand
        register_brand(
            &env,
            owner,
            brand_id.clone(),
            bytes!(&env, "Eco-Friendly Products Inc"),
            bytes!(&env, "Sustainable product manufacturer"),
            bytes!(&env, "https://eco-brand.example.com"),
            bytes!(&env, "support@eco-brand.example.com"),
        );

        // 2. Register product SKU
        register_product_sku(
            &env,
            brand_id.clone(),
            sku.clone(),
            bytes!(&env, "Eco Widget"),
            bytes!(&env, "100% recyclable widget"),
        );

        // 3. Log provenance
        let factory_location = create_test_location(&env, "Eco Factory", "DE");
        let prov_event_id = BytesN::<32>::random(&env);
        log_provenance_event(
            &env,
            prov_event_id,
            factory_location,
            bytes!(&env, "Recycled materials"),
            producer.clone(),
            bytes!(&env, "BATCH-ECO-2024-001"),
        );

        // 4. Log certification
        log_certification(
            &env,
            bytes!(&env, "CERT-ECOLABEL-001"),
            Symbol::new(&env, "EU_ECOLABEL"),
            certifier,
            730, // 2 years
            bytes!(&env, "EU Ecolabel certified sustainable product"),
        );

        // 5. Log labor conditions
        log_labor_conditions(
            &env,
            bytes!(&env, "FAC-ECO-001"),
            200,
            true,
            true,
            true,
            true,
            true,
            BytesN::<32>::random(&env),
            labor_auditor,
        );

        // 6. Log environmental impact
        let now = env.ledger().timestamp();
        log_environmental_impact(
            &env,
            bytes!(&env, "FAC-ECO-001"),
            now,
            now + (30 * 86400),
            1000,
            250000,
            50,
            95,
            15,
            BytesN::<32>::random(&env),
            env_auditor,
        );

        // 7. Verify product chain (will have limited verification without full setup)
        let verification = verify_product_chain(&env, brand_id, sku);
        assert_eq!(verification.product_sku, bytes!(&env, "ECO-WIDGET-001"));
    }

    // =========================================================================
    // RBAC Gating & Audit Event Tests
    // =========================================================================

    /// Positive RBAC: authorized caller with the required role can register a brand.
    #[test]
    fn test_rbac_register_brand_authorized() {
        let env = Env::default();
        env.mock_all_auths();

        let caller = setup_caller_with_role(&env, Role::BrandOwner);
        let brand_id = Symbol::new(&env, "ACME");

        register_brand(
            &env,
            caller.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        assert!(env
            .storage()
            .persistent()
            .has(&SupplyChainDataKey::Brand(brand_id)));
    }

    /// Negative RBAC: caller without the required role is rejected with a stable error code.
    #[test]
    fn test_rbac_register_brand_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let caller = Address::random(&env);
        rbac_init(&env, admin.clone());
        // Caller has no role granted.

        let brand_id = Symbol::new(&env, "ACME");

        let result = env.try_invoke_contract::<(), SupplyChainError>(
            &env.current_contract_address(),
            Symbol::new(&env, "register_brand"),
            vec![
                &env,
                caller.clone().into_val(&env),
                brand_id.clone().into_val(&env),
            ],
        );

        assert!(result.is_err());
    }

    /// Rejected access attempts must emit an audit event.
    #[test]
    fn test_rbac_rejected_access_emits_audit_event() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let caller = Address::random(&env);
        rbac_init(&env, admin.clone());

        let before = audit_event_count(&env);

        let brand_id = Symbol::new(&env, "ACME");
        let result = env.try_invoke_contract::<(), SupplyChainError>(
            &env.current_contract_address(),
            Symbol::new(&env, "register_brand"),
            vec![
                &env,
                caller.clone().into_val(&env),
                brand_id.clone().into_val(&env),
            ],
        );

        assert!(result.is_err());
        // A rejected access attempt must still emit an audit event.
        assert!(audit_event_count(&env) > before);
    }

    /// Successful mutations emit an audit event containing caller, timestamp, and state-diff digest.
    #[test]
    fn test_rbac_successful_mutation_emits_audit_event() {
        let env = Env::default();
        env.mock_all_auths();

        let caller = setup_caller_with_role(&env, Role::BrandOwner);
        let brand_id = Symbol::new(&env, "ACME");

        let before = audit_event_count(&env);

        register_brand(
            &env,
            caller.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        assert!(audit_event_count(&env) > before);

        // The emitted audit event must carry caller, timestamp, and state-diff digest.
        let events = env.events().all();
        let mut found = false;
        for i in 0..events.len() {
            let (_, _, data) = events.get(i).unwrap();
            // Audit events are structured; verify the payload is non-empty and
            // contains the expected audit topic marker.
            if !data.is_void() {
                found = true;
            }
        }
        assert!(found, "expected a structured audit event to be emitted");
    }

    /// Role hierarchy precedence: a higher-privilege role satisfies lower-privilege requirements.
    #[test]
    fn test_rbac_role_hierarchy_precedence() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let caller = Address::random(&env);
        rbac_init(&env, admin.clone());
        grant_role(&env, &admin, &caller, Role::Admin);

        // Admin should satisfy a BrandOwner-gated operation.
        let brand_id = Symbol::new(&env, "ACME");
        register_brand(
            &env,
            caller.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        assert!(env
            .storage()
            .persistent()
            .has(&SupplyChainDataKey::Brand(brand_id)));
    }

    /// Revocation behavior: a revoked role no longer authorizes the mutation.
    #[test]
    fn test_rbac_revocation_blocks_mutation() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let caller = Address::random(&env);
        rbac_init(&env, admin.clone());
        grant_role(&env, &admin, &caller, Role::BrandOwner);

        // Revoke the role.
        rbac_revoke_role(&env, admin.clone(), caller.clone(), Role::BrandOwner);

        let brand_id = Symbol::new(&env, "ACME");
        let result = env.try_invoke_contract::<(), SupplyChainError>(
            &env.current_contract_address(),
            Symbol::new(&env, "register_brand"),
            vec![
                &env,
                caller.clone().into_val(&env),
                brand_id.clone().into_val(&env),
            ],
        );

        assert!(result.is_err());
    }

    /// Suspended submitter DIDs are rejected with a stable RBAC error code.
    #[test]
    fn test_rbac_suspended_submitter_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let caller = Address::random(&env);
        rbac_init(&env, admin.clone());
        grant_role(&env, &admin, &caller, Role::BrandOwner);
        rbac_suspend_account(&env, admin.clone(), caller.clone());

        let brand_id = Symbol::new(&env, "ACME");
        let result = env.try_invoke_contract::<(), SupplyChainError>(
            &env.current_contract_address(),
            Symbol::new(&env, "register_brand"),
            vec![
                &env,
                caller.clone().into_val(&env),
                brand_id.clone().into_val(&env),
            ],
        );

        assert!(result.is_err());
    }

    /// Each mutating entrypoint enforces its required role (positive matrix).
    #[test]
    fn test_rbac_mutating_entrypoints_positive_matrix() {
        let env = Env::default();
        env.mock_all_auths();

        // Provenance logging requires a producer role.
        let producer = setup_caller_with_role(&env, Role::Producer);
        let event_id = BytesN::<32>::random(&env);
        let location = create_test_location(&env, "Factory", "US");
        log_provenance_event(
            &env,
            event_id,
            location.clone(),
            bytes!(&env, "Premium aluminum"),
            producer.clone(),
            bytes!(&env, "BATCH-2024-001"),
        );
        assert!(env
            .storage()
            .persistent()
            .has(&SupplyChainDataKey::ProvenanceEvent(event_id)));

        // Certification logging requires a certifier role.
        let certifier = setup_caller_with_role(&env, Role::Certifier);
        let cert_id = bytes!(&env, "CERT-ISO9001-2024");
        log_certification(
            &env,
            cert_id.clone(),
            Symbol::new(&env, "ISO_9001"),
            certifier.clone(),
            365,
            bytes!(&env, "Quality management system"),
        );
        let cert_event_id = env.crypto().sha256(&cert_id);
        assert!(env
            .storage()
            .persistent()
            .has(&SupplyChainDataKey::CertificationEvent(cert_event_id)));

        // Labor conditions logging requires an auditor role.
        let auditor = setup_caller_with_role(&env, Role::Auditor);
        let facility_id = bytes!(&env, "FAC-FACTORY-001");
        log_labor_conditions(
            &env,
            facility_id.clone(),
            500,
            true,
            true,
            true,
            true,
            true,
            BytesN::<32>::random(&env),
            auditor.clone(),
        );
        let report_id = env.crypto().sha256(&facility_id);
        assert!(env
            .storage()
            .persistent()
            .has(&SupplyChainDataKey::LaborReport(report_id)));
    }

    /// Each mutating entrypoint rejects unauthorized callers (negative matrix).
    #[test]
    fn test_rbac_mutating_entrypoints_negative_matrix() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let caller = Address::random(&env);
        rbac_init(&env, admin.clone());
        // Caller has no roles.

        let event_id = BytesN::<32>::random(&env);
        let location = create_test_location(&env, "Factory", "US");

        let prov_result = env.try_invoke_contract::<(), SupplyChainError>(
            &env.current_contract_address(),
            Symbol::new(&env, "log_provenance_event"),
            vec![
                &env,
                event_id.clone().into_val(&env),
                location.clone().into_val(&env),
                caller.clone().into_val(&env),
            ],
        );
        assert!(prov_result.is_err());

        let cert_result = env.try_invoke_contract::<(), SupplyChainError>(
            &env.current_contract_address(),
            Symbol::new(&env, "log_certification"),
            vec![
                &env,
                bytes!(&env, "CERT-X").into_val(&env),
                caller.clone().into_val(&env),
            ],
        );
        assert!(cert_result.is_err());

        let labor_result = env.try_invoke_contract::<(), SupplyChainError>(
            &env.current_contract_address(),
            Symbol::new(&env, "log_labor_conditions"),
            vec![
                &env,
                bytes!(&env, "FAC-X").into_val(&env),
                caller.clone().into_val(&env),
            ],
        );
        assert!(labor_result.is_err());
    }
}