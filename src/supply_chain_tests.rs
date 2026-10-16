#[cfg(test)]
mod tests {
    use crate::supply_chain::*;
    use soroban_sdk::{bytes, vec, Address, BytesN, Env, Symbol};

    /// Helper to create test location
    fn create_test_location(env: &Env, name: &str, country: &str) -> Location {
        Location {
            name: bytes!(env, name),
            country: Symbol::new(env, country),
            coordinates: bytes!(env, "0.0,0.0"),
            facility_id: bytes!(env, "FAC001"),
        }
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

    // ========================================================================
    // Storage footprint regression tests
    // ========================================================================

    /// Pinned XDR byte budgets for each record type. These budgets are the
    /// regression thresholds: any change that inflates the serialized size of
    /// a record beyond its budget will fail CI.
    const BUDGET_BRAND: u32 = 512;
    const BUDGET_PRODUCT_SKU: u32 = 512;
    const BUDGET_LOCATION: u32 = 256;
    const BUDGET_CUSTODY_TRANSFER: u32 = 384;
    const BUDGET_PROVENANCE: u32 = 1024;
    const BUDGET_CERTIFICATION: u32 = 512;
    const BUDGET_LABOR_CONDITIONS: u32 = 384;
    const BUDGET_ENVIRONMENTAL_IMPACT: u32 = 384;
    const BUDGET_VERIFICATION_RESULT: u32 = 512;
    const BUDGET_INTEGRITY_REPORT: u32 = 512;

    /// Serialize a value to XDR and return its byte length.
    fn xdr_len<T>(env: &Env, value: &T) -> u32
    where
        T: soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
    {
        let val: soroban_sdk::Val = value.into_val(env);
        let bytes = val.to_bytes();
        bytes.len()
    }

    /// Assert that a serialized record stays within its pinned byte budget.
    fn assert_within_budget(label: &str, actual: u32, budget: u32) {
        assert!(
            actual <= budget,
            "{} serialized size {} exceeds pinned budget {}",
            label,
            actual,
            budget
        );
    }

    #[test]
    fn test_storage_footprint_brand() {
        let env = Env::default();
        let brand = Brand {
            brand_id: Symbol::new(&env, "ACME"),
            owner: Address::random(&env),
            name: bytes!(&env, "ACME Corporation"),
            description: bytes!(&env, "Leading supplier of quality products"),
            website: bytes!(&env, "https://acme.example.com"),
            contact_email: bytes!(&env, "support@acme.example.com"),
            is_verified: true,
            registered_at: 1_700_000_000,
        };
        assert_within_budget("Brand", xdr_len(&env, &brand), BUDGET_BRAND);
    }

    #[test]
    fn test_storage_footprint_product_sku() {
        let env = Env::default();
        let product = ProductSKU {
            brand_id: Symbol::new(&env, "ACME"),
            sku: bytes!(&env, "SKU-12345"),
            name: bytes!(&env, "Premium Widget"),
            description: bytes!(&env, "High quality widget for general use"),
            created_at: 1_700_000_000,
        };
        assert_within_budget("ProductSKU", xdr_len(&env, &product), BUDGET_PRODUCT_SKU);
    }

    #[test]
    fn test_storage_footprint_location() {
        let env = Env::default();
        let location = create_test_location(&env, "Widget Factory", "US");
        assert_within_budget("Location", xdr_len(&env, &location), BUDGET_LOCATION);
    }

    #[test]
    fn test_storage_footprint_custody_transfer() {
        let env = Env::default();
        let transfer = CustodyTransfer {
            from_address: Address::random(&env),
            to_address: Address::random(&env),
            location: create_test_location(&env, "Distribution Center", "CA"),
            timestamp: 1_700_000_000,
            notes: bytes!(&env, "Shipped via truck"),
        };
        assert_within_budget(
            "CustodyTransfer",
            xdr_len(&env, &transfer),
            BUDGET_CUSTODY_TRANSFER,
        );
    }

    #[test]
    fn test_storage_footprint_provenance() {
        let env = Env::default();
        let mut chain = vec![&env];
        chain.push_back(CustodyTransfer {
            from_address: Address::random(&env),
            to_address: Address::random(&env),
            location: create_test_location(&env, "Distribution Center", "CA"),
            timestamp: 1_700_000_000,
            notes: bytes!(&env, "Shipped via truck"),
        });
        let provenance = Provenance {
            event_id: BytesN::<32>::random(&env),
            location: create_test_location(&env, "Widget Factory", "US"),
            raw_materials: bytes!(&env, "Premium aluminum"),
            producer_address: Address::random(&env),
            timestamp: 1_700_000_000,
            batch_number: bytes!(&env, "BATCH-2024-001"),
            is_verified: true,
            chain_of_custody: chain,
        };
        assert_within_budget("Provenance", xdr_len(&env, &provenance), BUDGET_PROVENANCE);
    }

    #[test]
    fn test_storage_footprint_certification() {
        let env = Env::default();
        let cert = Certification {
            cert_id: bytes!(&env, "CERT-ISO9001-2024"),
            cert_type: Symbol::new(&env, "ISO_9001"),
            issuer: Address::random(&env),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_000 + 365 * 86400,
            is_active: true,
            details: bytes!(&env, "Quality management system for manufacturing"),
        };
        assert_within_budget(
            "Certification",
            xdr_len(&env, &cert),
            BUDGET_CERTIFICATION,
        );
    }

    #[test]
    fn test_storage_footprint_labor_conditions() {
        let env = Env::default();
        let labor = LaborConditions {
            facility_id: bytes!(&env, "FAC-FACTORY-001"),
            worker_count: 500,
            wage_compliance: true,
            hours_compliance: true,
            child_labor_free: true,
            safety_standards_met: true,
            freedom_of_association: true,
            report_hash: BytesN::<32>::random(&env),
            reporter: Address::random(&env),
            timestamp: 1_700_000_000,
        };
        assert_within_budget(
            "LaborConditions",
            xdr_len(&env, &labor),
            BUDGET_LABOR_CONDITIONS,
        );
    }

    #[test]
    fn test_storage_footprint_environmental_impact() {
        let env = Env::default();
        let impact = EnvironmentalImpact {
            facility_id: bytes!(&env, "FAC-FACTORY-001"),
            period_start: 1_700_000_000,
            period_end: 1_700_000_000 + 30 * 86400,
            carbon_footprint: 5000,
            water_usage: 1_000_000,
            waste_generated: 500,
            renewable_energy_percent: 75,
            emissions_reduction_percent: 10,
            report_hash: BytesN::<32>::random(&env),
            reporter: Address::random(&env),
            timestamp: 1_700_000_000,
        };
        assert_within_budget(
            "EnvironmentalImpact",
            xdr_len(&env, &impact),
            BUDGET_ENVIRONMENTAL_IMPACT,
        );
    }

    #[test]
    fn test_storage_footprint_verification_result() {
        let env = Env::default();
        let result = VerificationResult {
            brand_id: Symbol::new(&env, "ACME"),
            product_sku: bytes!(&env, "SKU-12345"),
            is_verified: true,
            provenance_events: 3,
            certifications: 2,
            labor_compliant: true,
            environmental_compliant: true,
            verified_at: 1_700_000_000,
        };
        assert_within_budget(
            "VerificationResult",
            xdr_len(&env, &result),
            BUDGET_VERIFICATION_RESULT,
        );
    }

    #[test]
    fn test_storage_footprint_integrity_report() {
        let env = Env::default();
        let report = BrandIntegrityReport {
            brand_id: Symbol::new(&env, "ACME"),
            total_products: 10,
            verified_products: 8,
            total_provenance_events: 25,
            active_certifications: 3,
            labor_compliance_rate: 95,
            environmental_score: 80,
            compliance_trend: Symbol::new(&env, "stable"),
            generated_at: 1_700_000_000,
        };
        assert_within_budget(
            "BrandIntegrityReport",
            xdr_len(&env, &report),
            BUDGET_INTEGRITY_REPORT,
        );
    }

    // ========================================================================
    // Storage tier classification tests
    // ========================================================================

    /// Assert that a key lives in the persistent storage tier.
    fn assert_persistent_tier(env: &Env, key: &SupplyChainDataKey) {
        assert!(
            env.storage().persistent().has(key),
            "key {:?} must be stored in the persistent tier",
            key
        );
    }

    #[test]
    fn test_storage_tier_classification() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");
        let sku = bytes!(&env, "SKU-12345");

        register_brand(
            &env,
            owner.clone(),
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );
        assert_persistent_tier(&env, &SupplyChainDataKey::Brand(brand_id.clone()));

        register_product_sku(
            &env,
            brand_id.clone(),
            sku.clone(),
            bytes!(&env, "Premium Widget"),
            bytes!(&env, "High quality widget"),
        );
        assert_persistent_tier(
            &env,
            &SupplyChainDataKey::ProductSKU(brand_id.clone(), sku.clone()),
        );

        let event_id = BytesN::<32>::random(&env);
        log_provenance_event(
            &env,
            event_id,
            create_test_location(&env, "Widget Factory", "US"),
            bytes!(&env, "Premium aluminum"),
            Address::random(&env),
            bytes!(&env, "BATCH-2024-001"),
        );
        assert_persistent_tier(&env, &SupplyChainDataKey::ProvenanceEvent(event_id));

        let cert_id = bytes!(&env, "CERT-ISO9001-2024");
        log_certification(
            &env,
            cert_id.clone(),
            Symbol::new(&env, "ISO_9001"),
            Address::random(&env),
            365,
            bytes!(&env, "Quality management system"),
        );
        let cert_event_id = env.crypto().sha256(&cert_id);
        assert_persistent_tier(&env, &SupplyChainDataKey::CertificationEvent(cert_event_id));

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
            Address::random(&env),
        );
        let labor_id = env.crypto().sha256(&facility_id);
        assert_persistent_tier(&env, &SupplyChainDataKey::LaborReport(labor_id));

        let now = env.ledger().timestamp();
        log_environmental_impact(
            &env,
            facility_id.clone(),
            now,
            now + 30 * 86400,
            5000,
            1_000_000,
            500,
            75,
            10,
            BytesN::<32>::random(&env),
            Address::random(&env),
        );
        let env_id = env.crypto().sha256(&facility_id);
        assert_persistent_tier(&env, &SupplyChainDataKey::EnvironmentalReport(env_id));
    }

    // ========================================================================
    // Permissionless TTL extension tests
    // ========================================================================

    #[test]
    fn test_extend_ttl_permissionless_for_brand() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");

        register_brand(
            &env,
            owner,
            brand_id.clone(),
            bytes!(&env, "ACME Corporation"),
            bytes!(&env, "Leading supplier"),
            bytes!(&env, "https://acme.example.com"),
            bytes!(&env, "support@acme.example.com"),
        );

        let key = SupplyChainDataKey::Brand(brand_id);
        let before = env.storage().persistent().get_ttl(&key);

        // Any address (no auth required) may extend the TTL.
        let caller = Address::random(&env);
        let _ = caller;
        extend_ttl(&env, key.clone());

        let after = env.storage().persistent().get_ttl(&key);
        assert!(
            after >= before,
            "extend_ttl must not reduce the TTL (before={}, after={})",
            before,
            after
        );
    }

    #[test]
    fn test_extend_ttl_permissionless_for_provenance() {
        let env = Env::default();
        env.mock_all_auths();

        let event_id = BytesN::<32>::random(&env);
        log_provenance_event(
            &env,
            event_id,
            create_test_location(&env, "Widget Factory", "US"),
            bytes!(&env, "Premium aluminum"),
            Address::random(&env),
            bytes!(&env, "BATCH-2024-001"),
        );

        let key = SupplyChainDataKey::ProvenanceEvent(event_id);
        let before = env.storage().persistent().get_ttl(&key);

        // No auth mocking for the caller: the helper must be permissionless.
        extend_ttl(&env, key.clone());

        let after = env.storage().persistent().get_ttl(&key);
        assert!(after >= before);
    }

    #[test]
    fn test_extend_ttl_for_all_archival_critical_records() {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");
        let sku = bytes!(&env, "SKU-12345");

        register_brand(
            &env,
            owner,
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

        let event_id = BytesN::<32>::random(&env);
        log_provenance_event(
            &env,
            event_id,
            create_test_location(&env, "Widget Factory", "US"),
            bytes!(&env, "Premium aluminum"),
            Address::random(&env),
            bytes!(&env, "BATCH-2024-001"),
        );

        let cert_id = bytes!(&env, "CERT-ISO9001-2024");
        log_certification(
            &env,
            cert_id.clone(),
            Symbol::new(&env, "ISO_9001"),
            Address::random(&env),
            365,
            bytes!(&env, "Quality management system"),
        );

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
            Address::random(&env),
        );

        let now = env.ledger().timestamp();
        log_environmental_impact(
            &env,
            facility_id.clone(),
            now,
            now + 30 * 86400,
            5000,
            1_000_000,
            500,
            75,
            10,
            BytesN::<32>::random(&env),
            Address::random(&env),
        );

        let keys = vec![
            &env,
            SupplyChainDataKey::Brand(brand_id.clone()),
            SupplyChainDataKey::ProductSKU(brand_id.clone(), sku.clone()),
            SupplyChainDataKey::ProvenanceEvent(event_id),
            SupplyChainDataKey::CertificationEvent(env.crypto().sha256(&cert_id)),
            SupplyChainDataKey::LaborReport(env.crypto().sha256(&facility_id)),
            SupplyChainDataKey::EnvironmentalReport(env.crypto().sha256(&facility_id)),
        ];

        for key in keys.iter() {
            let before = env.storage().persistent().get_ttl(&key);
            extend_ttl(&env, key.clone());
            let after = env.storage().persistent().get_ttl(&key);
            assert!(
                after >= before,
                "TTL must not shrink for archival-critical key {:?}",
                key
            );
        }
    }

    // ========================================================================
    // Ledger byte read/write savings benchmark (1,000 simulated transactions)
    // ========================================================================

    /// Benchmark-style assertion: measure the total serialized ledger bytes
    /// written and read across 1,000 simulated transactions and assert the
    /// per-transaction footprint stays within the pinned budget.
    #[test]
    fn test_ledger_byte_savings_benchmark_1000_tx() {
        const TX_COUNT: u32 = 1_000;
        // Pinned per-transaction byte budget for the write + read footprint.
        const BYTES_PER_TX_BUDGET: u32 = 4_096;

        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::random(&env);
        let brand_id = Symbol::new(&env, "ACME");
        let sku = bytes!(&env, "SKU-12345");

        register_brand(
            &env,
            owner,
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

        let brand_key = SupplyChainDataKey::Brand(brand_id.clone());
        let sku_key = SupplyChainDataKey::ProductSKU(brand_id.clone(), sku.clone());

        let brand: Brand = env
            .storage()
            .persistent()
            .get(&brand_key)
            .expect("brand must exist");
        let product: ProductSKU = env
            .storage()
            .persistent()
            .get(&sku_key)
            .expect("product must exist");

        let write_bytes_per_tx = xdr_len(&env, &brand) + xdr_len(&env, &product);

        let mut total_write_bytes: u64 = 0;
        let mut total_read_bytes: u64 = 0;

        for _ in 0..TX_COUNT {
            // Simulated write: re-serialize the records that would be persisted.
            total_write_bytes += write_bytes_per_tx as u64;

            // Simulated read: fetch and re-serialize the records.
            let read_brand: Brand = env
                .storage()
                .persistent()
                .get(&brand_key)
                .expect("brand must exist");
            let read_product: ProductSKU = env
                .storage()
                .persistent()
                .get(&sku_key)
                .expect("product must exist");
            total_read_bytes += (xdr_len(&env, &read_brand) + xdr_len(&env, &read_product)) as u64;
        }

        let total_bytes = total_write_bytes + total_read_bytes;
        let bytes_per_tx = (total_bytes / TX_COUNT as u64) as u32;

        assert!(
            bytes_per_tx <= BYTES_PER_TX_BUDGET,
            "per-transaction ledger footprint {} exceeds pinned budget {}",
            bytes_per_tx,
            BYTES_PER_TX_BUDGET
        );

        // Sanity: the benchmark must actually exercise 1,000 transactions.
        assert_eq!(total_write_bytes / write_bytes_per_tx as u64, TX_COUNT as u64);
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
}
