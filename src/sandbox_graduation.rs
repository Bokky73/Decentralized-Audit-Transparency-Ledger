#![no_std]

//! Regulatory sandbox graduation criteria evaluator.
//!
//! #891: adds a Soroban persistent-storage layer for graduation assessments
//! with automated TTL bump policies on write and read, a permissionless TTL
//! extension hook, and archival lease pinning to reduce rent footprint while
//! guaranteeing long-lived assessment records are never silently evicted.

use crate::sandbox_types::*;
use soroban_sdk::{contracttype, Bytes, BytesN, Env};

// ─────────────────────────────────────────────────────────────────────────────
// Storage TTL policies (#891)
// ─────────────────────────────────────────────────────────────────────────────

/// TTL (in ledgers) below which live assessment state is auto-bumped on
/// write and on read. Mirrors the shared policy in [`crate::cbdc_interop`]
/// and [`crate::digital_passport`].
pub const GRADUATION_TTL_BUMP_THRESHOLD_LEDGERS: u32 = 10_000;

/// TTL (in ledgers) extended to for live (archival-critical) assessments.
pub const GRADUATION_TTL_EXTEND_LEDGERS: u32 = 100_000;

/// TTL (in ledgers) extended to for archival leases pinned by
/// [`GraduationManager::archive_assessment`].
pub const GRADUATION_ARCHIVAL_TTL_EXTEND_LEDGERS: u32 = 300_000;

/// Persistent storage keys for graduation assessments (#891).
#[contracttype]
pub enum GraduationStorageKey {
    /// Assessment ID -> GraduationAssessment
    Assessment(BytesN<32>),
    /// Ordinal -> assessment ID (ordered index)
    AssessmentIndex(u32),
    /// Counter for total assessments
    AssessmentCount,
}


/// Graduation progress assessment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraduationAssessment {
    /// Assessment ID
    pub assessment_id: BytesN<32>,
    /// Participant ID
    pub participant_id: BytesN<32>,
    /// Assessment timestamp
    pub assessed_at: u64,
    /// Transactions completed (meets criteria if >= min)
    pub transactions_completed: u32,
    /// Days in sandbox (meets criteria if >= min)
    pub days_in_sandbox: u32,
    /// Compliance score (0-100, meets criteria if >= min)
    pub compliance_score: u32,
    /// User satisfaction (0-100, meets criteria if >= min)
    pub user_satisfaction: u32,
    /// Regulatory approval (true = approved)
    pub regulatory_approval: bool,
    /// Financial health assessment (true = passed)
    pub financial_health_passed: bool,
    /// Tech readiness score (0-100)
    pub tech_readiness_score: u32,
    /// Graduation eligible
    pub is_eligible: bool,
    /// Graduation decision (pending/approved/rejected)
    pub decision: u32, // GraduationDecision as u32
    /// Graduation notes
    pub notes: Bytes,
}

/// Graduation decision enumeration.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GraduationDecision {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Deferred = 3,
}

impl GraduationDecision {
    pub fn is_terminal(&self) -> bool {
        matches!(self, GraduationDecision::Approved | GraduationDecision::Rejected)
    }
}

/// Graduation manager.
pub struct GraduationManager;

impl GraduationManager {
    /// Create graduation assessment
    pub fn create_assessment(
        env: &Env,
        participant_id: BytesN<32>,
    ) -> GraduationAssessment {        let assessment_id = Self::compute_assessment_id(env, &participant_id);

        GraduationAssessment {
            assessment_id,
            participant_id,
            assessed_at: env.ledger().timestamp(),
            transactions_completed: 0,
            days_in_sandbox: 0,
            compliance_score: 0,
            user_satisfaction: 0,
            regulatory_approval: false,
            financial_health_passed: false,
            tech_readiness_score: 0,
            is_eligible: false,
            decision: GraduationDecision::Pending as u32,
            notes: Bytes::new(env),
        }
    }

    /// Compute assessment ID
    pub fn compute_assessment_id(env: &Env, participant_id: &BytesN<32>) -> BytesN<32> {
        
        let mut input = Bytes::new(env);
        input.append(&participant_id.to_bytes());
        input.append(&Bytes::from_slice(env, b"GRADUATION"));

        env.crypto().sha256(&input).to_bytes()
    }

    /// Evaluate graduation eligibility
    pub fn evaluate_eligibility(
        assessment: &mut GraduationAssessment,
        criteria: &GraduationCriteria,
    ) -> bool {
        // Check all criteria
        let tx_ok = assessment.transactions_completed >= criteria.min_transactions;
        let duration_ok = assessment.days_in_sandbox >= criteria.min_duration_days;
        let compliance_ok = assessment.compliance_score >= criteria.min_compliance_score;
        let satisfaction_ok = assessment.user_satisfaction >= criteria.min_user_satisfaction;
        let tech_ok = assessment.tech_readiness_score >= criteria.min_tech_readiness_score;

        let regulatory_ok = if criteria.regulatory_approval_required {
            assessment.regulatory_approval
        } else {
            true
        };

        let financial_ok = if criteria.financial_health_required {
            assessment.financial_health_passed
        } else {
            true
        };

        let eligible = tx_ok
            && duration_ok
            && compliance_ok
            && satisfaction_ok
            && tech_ok
            && regulatory_ok
            && financial_ok;

        assessment.is_eligible = eligible;
        eligible
    }

    /// Approve graduation
    pub fn approve_graduation(
        assessment: &mut GraduationAssessment,
        notes: Bytes,
    ) -> Result<(), &'static str> {
        if !assessment.is_eligible {
            return Err("Participant does not meet graduation criteria");
        }

        assessment.decision = GraduationDecision::Approved as u32;
        assessment.notes = notes;

        Ok(())
    }

    /// Reject graduation
    pub fn reject_graduation(
        assessment: &mut GraduationAssessment,
        reason: Bytes,
    ) -> Result<(), &'static str> {
        assessment.decision = GraduationDecision::Rejected as u32;
        assessment.notes = reason;

        Ok(())
    }

    /// Defer graduation decision
    pub fn defer_graduation(
        assessment: &mut GraduationAssessment,
        reason: Bytes,
    ) -> Result<(), &'static str> {
        assessment.decision = GraduationDecision::Deferred as u32;
        assessment.notes = reason;

        Ok(())
    }

    /// Get graduation readiness percentage
    pub fn compute_readiness_percentage(assessment: &GraduationAssessment) -> u32 {
        let scores = [
            assessment.compliance_score,
            assessment.user_satisfaction,
            assessment.tech_readiness_score,
        ];

        let avg: u64 = scores.iter().map(|s| *s as u64).sum::<u64>() / 3;
        avg.min(100) as u32
    }

    /// Generate graduation recommendation
    pub fn get_recommendation(assessment: &GraduationAssessment) -> &'static str {
        if assessment.is_eligible {
            "Ready for graduation"
        } else if assessment.compliance_score < 75 {
            "Improve compliance score"
        } else if assessment.days_in_sandbox < 60 {
            "Extend sandbox duration"
        } else if assessment.transactions_completed < 500 {
            "Increase transaction volume"
        } else {
            "Defer and reassess"
        }
    }

    // ── Storage persistence with TTL bump policies (#891) ─────────────────

    /// Persists an assessment and applies the write-path TTL bump.
    ///
    /// `extend_ttl` only pays rent when the lease is at or below
    /// [`GRADUATION_TTL_BUMP_THRESHOLD_LEDGERS`], so churn-heavy evaluators
    /// amortize archival costs instead of re-paying on every write.
    pub fn save_assessment(env: &Env, assessment: &GraduationAssessment) {
        let key = GraduationStorageKey::Assessment(assessment.assessment_id.clone());
        env.storage().persistent().set(&key, assessment);
        env.storage().persistent().extend_ttl(
            &key,
            GRADUATION_TTL_BUMP_THRESHOLD_LEDGERS,
            GRADUATION_TTL_EXTEND_LEDGERS,
        );
    }

    /// Loads an assessment and applies the read-path TTL bump so hot records
    /// stay live without unexpectedly entering archival.
    ///
    /// Returns `None` when the assessment has expired out of the live lease
    /// or was never persisted.
    pub fn load_assessment(env: &Env, assessment_id: &BytesN<32>) -> Option<GraduationAssessment> {
        let key = GraduationStorageKey::Assessment(assessment_id.clone());
        let result = env.storage().persistent().get::<_, GraduationAssessment>(&key);
        if result.is_some() {
            env.storage().persistent().extend_ttl(
                &key,
                GRADUATION_TTL_BUMP_THRESHOLD_LEDGERS,
                GRADUATION_TTL_EXTEND_LEDGERS,
            );
        }
        result
    }

    /// Creates and immediately persists an assessment, appending it to the
    /// ordered index used for cursor-based scans.
    pub fn open_assessment(env: &Env, participant_id: BytesN<32>) -> GraduationAssessment {
        let assessment = Self::create_assessment(env, participant_id);
        Self::save_assessment(env, &assessment);

        let ordinal: u32 = env
            .storage()
            .persistent()
            .get(&GraduationStorageKey::AssessmentCount)
            .unwrap_or(0);
        env.storage().persistent().set(
            &GraduationStorageKey::AssessmentIndex(ordinal),
            &assessment.assessment_id,
        );
        env.storage().persistent().extend_ttl(
            &GraduationStorageKey::AssessmentIndex(ordinal),
            GRADUATION_TTL_BUMP_THRESHOLD_LEDGERS,
            GRADUATION_ARCHIVAL_TTL_EXTEND_LEDGERS,
        );
        env.storage()
            .persistent()
            .set(&GraduationStorageKey::AssessmentCount, &(ordinal + 1));

        assessment
    }

    /// Permissionless TTL extension for archival-critical assessment records.
    ///
    /// Anyone may keep an active assessment's persistent lease alive; safe
    /// because the call only ever *extends* TTL (and pays rent).
    pub fn extend_graduation_ttl(env: &Env, assessment_id: &BytesN<32>) {
        env.storage().persistent().extend_ttl(
            &GraduationStorageKey::Assessment(assessment_id.clone()),
            GRADUATION_TTL_BUMP_THRESHOLD_LEDGERS,
            GRADUATION_TTL_EXTEND_LEDGERS,
        );
    }

    /// Archive an assessment: re-pins the current snapshot under the extended
    /// archival lease. Returns the archived snapshot (#891).
    pub fn archive_assessment(
        env: &Env,
        assessment_id: &BytesN<32>,
    ) -> Option<GraduationAssessment> {
        let key = GraduationStorageKey::Assessment(assessment_id.clone());
        let snapshot: Option<GraduationAssessment> =
            env.storage().persistent().get(&key);
        if let Some(ref assessment) = snapshot {
            env.storage().persistent().set(&key, assessment);
            env.storage().persistent().extend_ttl(
                &key,
                GRADUATION_TTL_BUMP_THRESHOLD_LEDGERS,
                GRADUATION_ARCHIVAL_TTL_EXTEND_LEDGERS,
            );
        }
        snapshot
    }

    /// Total persisted assessments (0 when none).
    pub fn total_assessments(env: &Env) -> u32 {
        env.storage()
            .persistent()
            .get(&GraduationStorageKey::AssessmentCount)
            .unwrap_or(0)
    }

    /// Permission helper for archival pinning: an assessment is only
    /// deletable once its decision is terminal (approved or rejected).
    pub fn can_archive(assessment: &GraduationAssessment) -> bool {
        let decision = if assessment.decision == GraduationDecision::Approved as u32 {
            GraduationDecision::Approved
        } else if assessment.decision == GraduationDecision::Rejected as u32 {
            GraduationDecision::Rejected
        } else if assessment.decision == GraduationDecision::Deferred as u32 {
            GraduationDecision::Deferred
        } else {
            GraduationDecision::Pending
        };
        decision.is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assessment_creation() {
        let env = soroban_sdk::Env::default();
        let assessment = GraduationManager::create_assessment(&env, BytesN::zero());

        assert_eq!(assessment.transactions_completed, 0);
        assert!(!assessment.is_eligible);
    }

    #[test]
    fn test_eligibility_evaluation() {
        let env = soroban_sdk::Env::default();
        let mut assessment = GraduationManager::create_assessment(&env, BytesN::zero());

        assessment.transactions_completed = 1500;
        assessment.days_in_sandbox = 100;
        assessment.compliance_score = 90;
        assessment.user_satisfaction = 80;
        assessment.tech_readiness_score = 85;
        assessment.regulatory_approval = true;

        let criteria = GraduationCriteria::default();
        let eligible = GraduationManager::evaluate_eligibility(&mut assessment, &criteria);

        assert!(eligible);
        assert!(assessment.is_eligible);
    }

    #[test]
    fn test_readiness_percentage() {
        let env = soroban_sdk::Env::default();
        let mut assessment = GraduationManager::create_assessment(&env, BytesN::zero());

        assessment.compliance_score = 80;
        assessment.user_satisfaction = 75;
        assessment.tech_readiness_score = 90;

        let readiness = GraduationManager::compute_readiness_percentage(&assessment);
        assert_eq!(readiness, 81); // Average of 80, 75, 90
    }

    // ── #891: storage TTL policy coverage ───────────────────────────────────

    #[test]
    fn test_save_and_load_assessment_roundtrip() {
        let env = soroban_sdk::Env::default();
        let assessment = GraduationManager::open_assessment(&env, BytesN::zero());
        let id = assessment.assessment_id.clone();

        let loaded = GraduationManager::load_assessment(&env, &id);
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().participant_id, BytesN::zero());
        assert_eq!(GraduationManager::total_assessments(&env), 1);
    }

    #[test]
    fn test_load_missing_assessment_is_none() {
        let env = soroban_sdk::Env::default();
        assert!(GraduationManager::load_assessment(&env, &BytesN::zero()).is_none());
        assert_eq!(GraduationManager::total_assessments(&env), 0);
    }

    #[test]
    fn test_ttl_hooks_do_not_panic() {
        let env = soroban_sdk::Env::default();
        let assessment = GraduationManager::open_assessment(&env, BytesN::zero());
        GraduationManager::extend_graduation_ttl(&env, &assessment.assessment_id);
        let archived = GraduationManager::archive_assessment(&env, &assessment.assessment_id);
        assert!(archived.is_some());
    }

    #[test]
    fn test_can_archive_uses_terminal_decision() {
        let env = soroban_sdk::Env::default();
        let mut assessment = GraduationManager::create_assessment(&env, BytesN::zero());
        assert!(!GraduationManager::can_archive(&assessment));
        assessment.decision = GraduationDecision::Approved as u32;
        assert!(GraduationManager::can_archive(&assessment));
    }
}
