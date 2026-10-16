#![allow(dead_code)]

//! Multi-tier supply chain custody handoff verifier.
//!
//! # Determinism, bounds and overflow safety
//!
//! All arithmetic in this module uses checked or saturating Soroban math
//! helpers. No unchecked `+`, `*`, `+=` operations remain on user-controlled
//! values, and every collection that is written to persistent storage is
//! bounded by an explicit `MAX_*` constant.
//!
//! ## Worst-case storage footprint
//!
//! Per-entry persistent storage is bounded as follows (Soroban ledger entries
//! are charged per byte; the values below are the enforced upper bounds):
//!
//! * `Brand` — 1 entry, bounded by caller-supplied `Bytes` fields.
//! * `ProductSKU` — 1 entry plus up to `MAX_CERTIFICATIONS` +
//!   `MAX_LABOR_REPORTS` + `MAX_ENVIRONMENTAL_REPORTS` link hashes
//!   (32 bytes each).
//! * `Provenance` — 1 entry plus up to `MAX_CUSTODY_TRANSFERS` custody
//!   transfer records.
//! * `Certification` — 1 entry plus up to `MAX_AUDIT_ENTRIES` audit entries.
//! * `LaborConditions` / `EnvironmentalImpact` — 1 entry plus up to
//!   `MAX_CERTIFICATIONS` certification hashes.
//!
//! ## Worst-case CPU instruction bounds
//!
//! * `log_custody_transfer` — O(1) storage read + write, bounded by
//!   `MAX_CUSTODY_TRANSFERS` deserialization cost.
//! * `verify_product_chain` — O(`MAX_CERTIFICATIONS` + `MAX_LABOR_REPORTS` +
//!   `MAX_ENVIRONMENTAL_REPORTS`) storage reads, each bounded by the
//!   per-entry limits above.
//! * `get_product_timeline` — O(`MAX_TIMELINE_EVENTS`) storage reads.
//!
//! All boundary violations return a typed [`SupplyChainError`] variant rather
//! than panicking, so callers observe deterministic, gas-bounded failures.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracterror, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec};

/// Maximum number of custody transfers recorded per provenance event.
pub const MAX_CUSTODY_TRANSFERS: u32 = 256;
/// Maximum number of certifications linked to a product SKU.
pub const MAX_CERTIFICATIONS: u32 = 128;
/// Maximum number of labor condition reports linked to a product SKU.
pub const MAX_LABOR_REPORTS: u32 = 128;
/// Maximum number of environmental reports linked to a product SKU.
pub const MAX_ENVIRONMENTAL_REPORTS: u32 = 128;
/// Maximum number of audit entries recorded per certification.
pub const MAX_AUDIT_ENTRIES: u32 = 128;
/// Maximum number of events returned by `get_product_timeline`.
pub const MAX_TIMELINE_EVENTS: u32 = 256;
/// Maximum number of issues accumulated during a verification pass.
pub const MAX_VERIFICATION_ISSUES: u32 = 64;
/// Maximum number of days a certification may be valid for.
pub const MAX_CERTIFICATION_DAYS: u64 = 36_500; // 100 years
/// Seconds in a day, used for expiry computation.
const SECONDS_PER_DAY: u64 = 86_400;

/// Supply chain specific error types
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SupplyChainError {
    /// Brand not registered in the system
    BrandNotRegistered = 1001,
    /// Product SKU not found for this brand
    SkuNotFound = 1002,
    /// Certification expired or invalid
    CertificationExpired = 1003,
    /// Labor conditions report missing or invalid
    InvalidLaborReport = 1004,
    /// Environmental impact data missing
    InvalidEnvironmentalData = 1005,
    /// Product chain verification failed
    VerificationFailed = 1006,
    /// Provenance trace incomplete
    IncompleteProvenance = 1007,
    /// Certification not verified by authority
    UnverifiedCertification = 1008,
    /// Unauthorized access to brand data
    UnauthorizedBrandAccess = 1009,
    /// Invalid chain of custody timeline
    InvalidChainOfCustody = 1010,
    /// Arithmetic overflow while computing a bounded value
    ArithmeticOverflow = 1011,
    /// A collection exceeded its configured maximum length
    CollectionLimitExceeded = 1012,
    /// A supplied payload was malformed or out of range
    InvalidPayload = 1013,
    /// Provenance event not found
    ProvenanceNotFound = 1014,
}

/// Represents a geographical location or facility
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Location {
    pub name: Bytes,           // Facility or location name
    pub country: Symbol,       // ISO country code
    pub coordinates: Bytes,    // Lat,Long as bytes
    pub facility_id: Bytes,    // Unique facility identifier
}

/// Represents provenance data for product origin tracking
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    pub origin_location: Location,      // Where the product originates
    pub timestamp: u64,                 // When origin was recorded
    pub raw_material_source: Bytes,     // Source of raw materials
    pub producer_address: Address,      // Producer's Stellar address
    pub batch_id: Bytes,                // Batch or lot number
    pub chain_of_custody: Vec<CustodyTransfer>, // Track all custody transfers
    pub is_verified: bool,              // Whether provenance is verified
}

/// Represents a transfer of custody in the supply chain
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyTransfer {
    pub from_address: Address,    // Who transferred the product
    pub to_address: Address,      // Who received the product
    pub timestamp: u64,           // When transfer occurred
    pub location: Location,       // Where transfer happened
    pub transfer_notes: Bytes,    // Additional transfer details
}

/// Represents certification data (ISO, organic, fair trade, etc.)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certification {
    pub cert_id: Bytes,                    // Unique certification ID
    pub cert_type: Symbol,                 // Type: organic, fair_trade, iso_9001, etc.
    pub issuer: Address,                   // Certifying authority address
    pub issued_date: u64,                  // When certified
    pub expiry_date: u64,                  // When certification expires
    pub scope: Bytes,                      // What is certified (products, processes)
    pub is_active: bool,                   // Current validity status
    pub verification_hash: BytesN<32>,     // Hash for verification
    pub audit_trail: Vec<AuditEntry>,      // History of certification audits
}

/// Records an audit event for a certification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEntry {
    pub timestamp: u64,      // When audit occurred
    pub auditor: Address,    // Who performed the audit
    pub status: Symbol,      // passed, failed, pending
    pub notes: Bytes,        // Audit findings
}

/// Represents labor conditions report
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaborConditions {
    pub facility_id: Bytes,              // Which facility
    pub report_date: u64,                // When report was created
    pub reporter: Address,               // Who reported
    pub worker_count: u32,               // Number of workers
    pub wage_compliance: bool,           // Wages meet minimums
    pub working_hours_compliance: bool,  // Hours within legal limits
    pub child_labor_free: bool,          // No child labor
    pub safety_standards_met: bool,      // Safety compliance
    pub freedom_of_association: bool,    // Union rights protected
    pub report_hash: BytesN<32>,         // Hash of detailed report
    pub certifications: Vec<Bytes>,      // Associated certifications
}

/// Represents environmental impact data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentalImpact {
    pub facility_id: Bytes,           // Which facility
    pub report_period: (u64, u64),    // Start and end dates
    pub carbon_footprint: u32,        // kg CO2e
    pub water_usage: u32,             // Liters used
    pub waste_generated: u32,         // kg of waste
    pub renewable_energy_percent: u32, // % of energy from renewables
    pub emissions_reduction_percent: u32, // Year-over-year reduction
    pub certifications: Vec<Bytes>,   // Environmental certifications
    pub report_hash: BytesN<32>,      // Hash of detailed environmental report
}

/// Represents a brand registration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Brand {
    pub brand_id: Symbol,           // Unique brand identifier
    pub name: Bytes,                // Brand name
    pub owner: Address,             // Brand owner address
    pub verified: bool,             // Is brand verified
    pub description: Bytes,         // Brand description/mission
    pub website: Bytes,             // Brand website URL
    pub support_contact: Bytes,     // Support contact info
}

/// Represents a product SKU tracked for supply chain
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSKU {
    pub sku: Bytes,                          // Product SKU
    pub brand_id: Symbol,                    // Associated brand
    pub product_name: Bytes,                 // Product name
    pub description: Bytes,                  // Product description
    pub provenance_id: BytesN<32>,           // Link to provenance event
    pub certifications: Vec<BytesN<32>>,     // Links to certification events
    pub labor_reports: Vec<BytesN<32>>,      // Links to labor condition reports
    pub environmental_reports: Vec<BytesN<32>>, // Links to environmental reports
    pub created_date: u64,                   // When SKU was created
    pub last_updated: u64,                   // Last modification date
}

/// Complete product chain verification result
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupplyChainVerification {
    pub product_sku: Bytes,            // Product SKU
    pub is_verified: bool,             // Overall verification result
    pub provenance_verified: bool,     // Provenance chain complete
    pub certifications_valid: bool,    // All certs current and valid
    pub labor_compliant: bool,         // Labor conditions acceptable
    pub environmental_standards_met: bool, // Environmental standards met
    pub verification_timestamp: u64,   // When verification was done
    pub verification_score: u32,       // 0-100 compliance score
    pub issues: Vec<Bytes>,            // Any outstanding issues
}

/// Consumer-friendly product timeline entry
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineEntry {
    pub timestamp: u64,         // When this event occurred
    pub entry_type: Symbol,     // Type: origin, custody, certification, etc.
    pub location: Location, // Where event occurred
    pub description: Bytes,     // Human-readable description
    pub verified: bool,         // Whether verified on-chain
    pub event_id: BytesN<32>,   // Link to on-chain event
}

/// Brand integrity report for transparency
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrandIntegrityReport {
    pub brand_id: Symbol,              // Brand identifier
    pub report_date: u64,              // When report was generated
    pub total_products_tracked: u32,   // Number of SKUs tracked
    pub avg_compliance_score: u32,     // Average compliance (0-100)
    pub certifications_count: u32,     // Total active certifications
    pub facilities_audited: u32,       // Number of facilities with labor/env reports
    pub products_fully_traceable: u32, // Products with complete chain
    pub products_verified: u32,        // Products verified this period
    pub quality_issues: u32,           // Reported issues
    pub compliance_trend: Symbol,      // improving, stable, declining
}

// ─────────────────────────────────────────────────────────────────────────────
// Data storage keys for supply chain
// ─────────────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum SupplyChainDataKey {
    /// Brand registration: brand_id -> Brand
    Brand(Symbol),
    /// Product SKU: (brand_id, sku) -> ProductSKU
    ProductSKU(Symbol, Bytes),
    /// Provenance event: event_id -> Provenance
    ProvenanceEvent(BytesN<32>),
    /// Certification event: cert_id -> Certification
    CertificationEvent(BytesN<32>),
    /// Labor conditions report: report_id -> LaborConditions
    LaborReport(BytesN<32>),
    /// Environmental report: report_id -> EnvironmentalImpact
    EnvironmentalReport(BytesN<32>),
    /// Index: brand -> list of SKUs
    BrandProductIndex(Symbol),
    /// Index: brand -> list of certifications
    BrandCertificationIndex(Symbol),
    /// Index: facility -> labor reports
    FacilityLaborIndex(Bytes),
    /// Index: facility -> environmental reports
    FacilityEnvironmentalIndex(Bytes),
    /// Cache: product -> verification result
    VerificationCache(Bytes),
    /// Cache: brand integrity report
    BrandIntegrityCache(Symbol),
    /// Timestamp: last verification for product
    LastVerificationTime(Bytes),
    /// Counter: total brands registered
    BrandCount,
    /// Counter: total products tracked
    ProductCount,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public contract functions for supply chain
// ─────────────────────────────────────────────────────────────────────────────

/// Register a new brand on the supply chain ledger
pub fn register_brand(
    env: &Env,
    owner: Address,
    brand_id: Symbol,
    name: Bytes,
    description: Bytes,
    website: Bytes,
    support_contact: Bytes,
) -> Result<(), SupplyChainError> {
    owner.require_auth();

    let brand = Brand {
        brand_id: brand_id.clone(),
        name,
        owner: owner.clone(),
        verified: false,
        description,
        website,
        support_contact,
    };

    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::Brand(brand_id.clone()), &brand);

    // Increment brand count using saturating arithmetic so a saturated counter
    // can never wrap around and corrupt the index.
    let count: u32 = env
        .storage()
        .persistent()
        .get(&SupplyChainDataKey::BrandCount)
        .unwrap_or(0);
    let next = count.saturating_add(1);
    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::BrandCount, &next);

    Ok(())
}

/// Register a product SKU for supply chain tracking
pub fn register_product_sku(
    env: &Env,
    brand_id: Symbol,
    sku: Bytes,
    product_name: Bytes,
    description: Bytes,
) -> Result<(), SupplyChainError> {
    // Verify brand exists
    if !env
        .storage()
        .persistent()
        .has(&SupplyChainDataKey::Brand(brand_id.clone()))
    {
        return Err(SupplyChainError::BrandNotRegistered);
    }

    let product = ProductSKU {
        sku: sku.clone(),
        brand_id: brand_id.clone(),
        product_name,
        description,
        provenance_id: BytesN::<32>::from_array(&env, &[0u8; 32]),
        certifications: Vec::new(&env),
        labor_reports: Vec::new(&env),
        environmental_reports: Vec::new(&env),
        created_date: env.ledger().timestamp(),
        last_updated: env.ledger().timestamp(),
    };

    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::ProductSKU(brand_id.clone(), sku), &product);

    // Increment product count using saturating arithmetic.
    let count: u32 = env
        .storage()
        .persistent()
        .get(&SupplyChainDataKey::ProductCount)
        .unwrap_or(0);
    let next = count.saturating_add(1);
    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::ProductCount, &next);

    Ok(())
}

/// Log a provenance event for product origin tracking
pub fn log_provenance_event(
    env: &Env,
    event_id: BytesN<32>,
    origin_location: Location,
    raw_material_source: Bytes,
    producer: Address,
    batch_id: Bytes,
) {
    producer.require_auth();

    let provenance = Provenance {
        origin_location,
        timestamp: env.ledger().timestamp(),
        raw_material_source,
        producer_address: producer,
        batch_id,
        chain_of_custody: Vec::new(&env),
        is_verified: false,
    };

    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::ProvenanceEvent(event_id), &provenance);
}

/// Log a custody transfer in the supply chain
pub fn log_custody_transfer(
    env: &Env,
    event_id: BytesN<32>,
    from: Address,
    to: Address,
    location: Location,
    notes: Bytes,
) -> Result<(), SupplyChainError> {
    from.require_auth();

    // Get existing provenance
    let mut provenance: Provenance = env
        .storage()
        .persistent()
        .get(&SupplyChainDataKey::ProvenanceEvent(event_id.clone()))
        .ok_or(SupplyChainError::ProvenanceNotFound)?;

    // Enforce the explicit maximum collection length before mutating state.
    if provenance.chain_of_custody.len() >= MAX_CUSTODY_TRANSFERS {
        return Err(SupplyChainError::CollectionLimitExceeded);
    }

    let transfer = CustodyTransfer {
        from_address: from,
        to_address: to,
        timestamp: env.ledger().timestamp(),
        location,
        transfer_notes: notes,
    };

    provenance.chain_of_custody.push_back(transfer);
    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::ProvenanceEvent(event_id), &provenance);

    Ok(())
}

/// Log a certification event
pub fn log_certification(
    env: &Env,
    cert_id: Bytes,
    cert_type: Symbol,
    issuer: Address,
    expiry_days: u64,
    scope: Bytes,
) -> Result<(), SupplyChainError> {
    issuer.require_auth();

    // Reject malformed payloads before any arithmetic is performed.
    if expiry_days > MAX_CERTIFICATION_DAYS {
        return Err(SupplyChainError::InvalidPayload);
    }

    let now = env.ledger().timestamp();
    // Checked multiplication and addition: both operands are user-controlled.
    let expiry_seconds = expiry_days
        .checked_mul(SECONDS_PER_DAY)
        .ok_or(SupplyChainError::ArithmeticOverflow)?;
    let expiry_date = now
        .checked_add(expiry_seconds)
        .ok_or(SupplyChainError::ArithmeticOverflow)?;

    let certification = Certification {
        cert_id,
        cert_type,
        issuer: issuer.clone(),
        issued_date: now,
        expiry_date,
        scope,
        is_active: true,
        verification_hash: BytesN::<32>::from_array(&env, &[0u8; 32]),
        audit_trail: Vec::new(&env),
    };

    let cert_event_id = env.crypto().sha256(&certification.cert_id).to_bytes();
    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::CertificationEvent(cert_event_id), &certification);

    Ok(())
}

/// Log labor conditions for a facility
pub fn log_labor_conditions(
    env: &Env,
    facility_id: Bytes,
    worker_count: u32,
    wage_compliant: bool,
    hours_compliant: bool,
    child_labor_free: bool,
    safety_met: bool,
    freedom_of_association: bool,
    report_hash: BytesN<32>,
    reporter: Address,
) -> Result<(), SupplyChainError> {
    reporter.require_auth();

    let labor_report = LaborConditions {
        facility_id: facility_id.clone(),
        report_date: env.ledger().timestamp(),
        reporter,
        worker_count,
        wage_compliance: wage_compliant,
        working_hours_compliance: hours_compliant,
        child_labor_free,
        safety_standards_met: safety_met,
        freedom_of_association,
        report_hash,
        certifications: Vec::new(&env),
    };

    let report_id = env.crypto().sha256(&facility_id).to_bytes();
    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::LaborReport(report_id), &labor_report);

    Ok(())
}

/// Log environmental impact data for a facility
pub fn log_environmental_impact(
    env: &Env,
    facility_id: Bytes,
    report_period_start: u64,
    report_period_end: u64,
    carbon_footprint: u32,
    water_usage: u32,
    waste_generated: u32,
    renewable_energy_percent: u32,
    emissions_reduction: u32,
    report_hash: BytesN<32>,
    reporter: Address,
) -> Result<(), SupplyChainError> {
    reporter.require_auth();

    // Reject malformed report periods and out-of-range percentages.
    if report_period_end < report_period_start
        || renewable_energy_percent > 100
        || emissions_reduction > 100
    {
        return Err(SupplyChainError::InvalidPayload);
    }

    let environmental = EnvironmentalImpact {
        facility_id: facility_id.clone(),
        report_period: (report_period_start, report_period_end),
        carbon_footprint,
        water_usage,
        waste_generated,
        renewable_energy_percent,
        emissions_reduction_percent: emissions_reduction,
        certifications: Vec::new(&env),
        report_hash,
    };

    let report_id = env.crypto().sha256(&facility_id).to_bytes();
    env.storage()
        .persistent()
        .set(&SupplyChainDataKey::EnvironmentalReport(report_id), &environmental);

    Ok(())
}

/// Verify a product's complete supply chain
pub fn verify_product_chain(
    env: &Env,
    brand_id: Symbol,
    sku: Bytes,
) -> Result<SupplyChainVerification, SupplyChainError> {
    // Get product
    let product: ProductSKU = env
        .storage()
        .persistent()
        .get(&SupplyChainDataKey::ProductSKU(brand_id.clone(), sku.clone()))
        .ok_or(SupplyChainError::SkuNotFound)?;

    // Enforce collection bounds before iterating over stored links.
    if product.certifications.len() > MAX_CERTIFICATIONS
        || product.labor_reports.len() > MAX_LABOR_REPORTS
        || product.environmental_reports.len() > MAX_ENVIRONMENTAL_REPORTS
    {
        return Err(SupplyChainError::CollectionLimitExceeded);
    }

    let mut provenance_verified = false;
    let mut certifications_valid = false;
    let mut labor_compliant = true;
    let environmental_standards_met = true;
    let mut issues: Vec<Bytes> = Vec::new(&env);
    let mut verification_score: u32 = 0;

    // Check provenance
    if product.provenance_id != BytesN::from_array(env, &[0u8; 32]) {
        if let Some(prov) = env
            .storage()
            .persistent()
            .get::<_, Provenance>(&SupplyChainDataKey::ProvenanceEvent(product.provenance_id))
        {
            provenance_verified = prov.is_verified;
            if provenance_verified {
                verification_score = verification_score.saturating_add(25);
            }
        }
    }

    // Check certifications
    if !product.certifications.is_empty() {
        let mut all_valid = true;
        for cert_id in product.certifications.iter() {
            if let Some(cert) = env
                .storage()
                .persistent()
                .get::<_, Certification>(&SupplyChainDataKey::CertificationEvent(cert_id))
            {
                if !cert.is_active || cert.expiry_date < env.ledger().timestamp() {
                    all_valid = false;
                    if issues.len() < MAX_VERIFICATION_ISSUES {
                        issues.push_back(Bytes::from_slice(&env, b"Certification expired"));
                    }
                }
            }
        }
        certifications_valid = all_valid;
        if certifications_valid {
            verification_score = verification_score.saturating_add(25);
        }
    }

    // Check labor conditions
    for labor_id in product.labor_reports.iter() {
        if let Some(labor) = env
            .storage()
            .persistent()
            .get::<_, LaborConditions>(&SupplyChainDataKey::LaborReport(labor_id))
        {
            if !labor.wage_compliance
                || !labor.working_hours_compliance
                || !labor.child_labor_free
                || !labor.safety_standards_met
            {
                labor_compliant = false;
                if issues.len() < MAX_VERIFICATION_ISSUES {
                    issues.push_back(Bytes::from_slice(&env, b"Labor conditions not met"));
                }
            } else {
                verification_score = verification_score.saturating_add(25);
            }
        }
    }

    // Check environmental impact
    for env_id in product.environmental_reports.iter() {
        if let Some(_env_impact) = env
            .storage()
            .persistent()
            .get::<_, EnvironmentalImpact>(&SupplyChainDataKey::EnvironmentalReport(env_id))
        {
            verification_score = verification_score.saturating_add(25);
        }
    }

    let is_verified = provenance_verified && certifications_valid && labor_compliant && environmental_standards_met;

    Ok(SupplyChainVerification {
        product_sku: sku,
        is_verified,
        provenance_verified,
        certifications_valid,
        labor_compliant,
        environmental_standards_met,
        verification_timestamp: env.ledger().timestamp(),
        verification_score: if is_verified { 100 } else { verification_score },
        issues,
    })
}

/// Get a consumer-friendly timeline of product events
pub fn get_product_timeline(
    env: &Env,
    event_ids: Vec<BytesN<32>>,
) -> Result<Vec<TimelineEntry>, SupplyChainError> {
    // Bound the input vector to keep CPU and memory deterministic.
    if event_ids.len() > MAX_TIMELINE_EVENTS {
        return Err(SupplyChainError::CollectionLimitExceeded);
    }

    let mut timeline: Vec<TimelineEntry> = Vec::new(&env);

    for event_id in event_ids.iter() {
        // Try to load as provenance
        if let Some(prov) = env
            .storage()
            .persistent()
            .get::<_, Provenance>(&SupplyChainDataKey::ProvenanceEvent(event_id.clone()))
        {
            timeline.push_back(TimelineEntry {
                timestamp: prov.timestamp,
                entry_type: Symbol::new(&env, "origin"),
                location: prov.origin_location,
                description: Bytes::from_slice(&env, b"Product origin recorded"),
                verified: prov.is_verified,
                event_id,
            });
        }
    }

    Ok(timeline)
}

/// Get brand integrity report
pub fn get_brand_integrity_report(
    env: &Env,
    brand_id: Symbol,
) -> Result<BrandIntegrityReport, SupplyChainError> {
    // Verify brand exists
    if !env
        .storage()
        .persistent()
        .has(&SupplyChainDataKey::Brand(brand_id.clone()))
    {
        return Err(SupplyChainError::BrandNotRegistered);
    }

    let now = env.ledger().timestamp();

    Ok(BrandIntegrityReport {
        brand_id,
        report_date: now,
        total_products_tracked: 0,
        avg_compliance_score: 0,
        certifications_count: 0,
        facilities_audited: 0,
        products_fully_traceable: 0,
        products_verified: 0,
        quality_issues: 0,
        compliance_trend: Symbol::new(&env, "stable"),
    })
}

/// Verify a specific certification
pub fn verify_certification(
    env: &Env,
    cert_id: Bytes,
) -> bool {
    let cert_event_id = env.crypto().sha256(&cert_id).to_bytes();

    if let Some(cert) = env
        .storage()
        .persistent()
        .get::<_, Certification>(&SupplyChainDataKey::CertificationEvent(cert_event_id))
    {
        cert.is_active && cert.expiry_date > env.ledger().timestamp()
    } else {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions for QR codes and verification
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a verification QR code URL for a product
pub fn generate_qr_code_url(
    env: &Env,
    brand_id: Symbol,
    sku: Bytes,
    base_url: Bytes,
) -> Bytes {
    // Built by concatenation: `Symbol::to_string` is host-only and `Bytes` has no
    // `as_slice` in SDK 27.
    let mut url = base_url;
    url.extend_from_slice(b"?brand=");
    url.append(&brand_id.to_xdr(env));
    url.extend_from_slice(b"&sku=");
    url.append(&sku);
    url
}

/// Generate a cryptographic proof of supply chain integrity
pub fn generate_integrity_proof(
    env: &Env,
    event_ids: Vec<BytesN<32>>,
) -> Result<BytesN<32>, SupplyChainError> {
    // Bound the input vector so the proof payload size stays deterministic.
    if event_ids.len() > MAX_TIMELINE_EVENTS {
        return Err(SupplyChainError::CollectionLimitExceeded);
    }

    let mut data = Bytes::new(env);
    for event_id in event_ids.iter() {
        data.append(&event_id.to_bytes());
    }
    Ok(env.crypto().sha256(&data).to_bytes())
}

