#![no_std]

use crate::sandbox_types::*;
use soroban_sdk::{contracttype, Bytes, BytesN, Env};

/// Maximum permitted length for graduation notes (prevents unbounded growth).
const MAX_NOTES_LEN: usize = 1024;

/// Maximum permitted value for percentage-based score fields (0-100).
const MAX_SCORE: u32 = 100;

/// Maximum permitted transactions count (deterministic upper bound).
const MAX_TRANSACTIONS: u32 = 1_000_000;

/// Maximum permitted days in sandbox (deterministic upper bound).
const MAX_DAYS: u32 = 1_000;

/// Validate that a score field is within the permitted 0..=100 range.
fn validate_score(score: u32) -> Result<(), &'static str> {
    if score > MAX_SCORE {
        return Err("score exceeds 0-100 range");
    }
    Ok(())
}

/// Validate all mutable numeric fields on an assessment for overflow/bounds safety.
fn validate_assessment_bounds(assessment: &GraduationAssessment) -> Result<(), &'static str> {
    validate_score(assessment.compliance_score)?;
    validate_score(assessment.user_satisfaction)?;
    validate_score(assessment.tech_readiness_score)?;
    if assessment.transactions_completed > MAX_TRANSACTIONS {
        return Err("transactions_completed exceeds deterministic bound");
    }
    if assessment.days_in_sandbox > MAX_DAYS {
        return Err("days_in_sandbox exceeds deterministic bound");
    }
    Ok(())
}

/// Validate that notes payload respects the bounded length limit.
fn validate_notes_len(notes: &Bytes) -> Result<(), &'static str> {
    if notes.len() > MAX_NOTES_LEN {
        return Err("notes exceed maximum permitted length");
    }
    Ok(())
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
    ) -> GraduationAssessment {
        let assessment_id = Self::compute_assessment_id(env, &participant_id);

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
    ) -> Result<bool, &'static str> {
        // Enforce deterministic bounds before any comparison (overflow safety).
        validate_assessment_bounds(assessment)?;

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
        Ok(eligible)
    }

    /// Approve graduation
    pub fn approve_graduation(
        assessment: &mut GraduationAssessment,
        notes: Bytes,
    ) -> Result<(), &'static str> {
        validate_notes_len(&notes)?;

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
        validate_notes_len(&reason)?;

        assessment.decision = GraduationDecision::Rejected as u32;
        assessment.notes = reason;

        Ok(())
    }

    /// Defer graduation decision
    pub fn defer_graduation(
        assessment: &mut GraduationAssessment,
        reason: Bytes,
    ) -> Result<(), &'static str> {
        validate_notes_len(&reason)?;

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
        assessment.financial_health_passed = true;

        let criteria = GraduationCriteria::default();
        let eligible = GraduationManager::evaluate_eligibility(&mut assessment, &criteria)
            .expect("evaluation must succeed for valid inputs");

        assert!(eligible);
        assert!(assessment.is_eligible);
    }

    #[test]
    fn test_eligibility_evaluation_bounds_rejects_out_of_range_score() {
        let env = soroban_sdk::Env::default();
        let mut assessment = GraduationManager::create_assessment(&env, BytesN::zero());
        assessment.compliance_score = 150; // exceeds 0-100

        let criteria = GraduationCriteria::default();
        let result = GraduationManager::evaluate_eligibility(&mut assessment, &criteria);
        assert_eq!(result, Err("score exceeds 0-100 range"));
    }

    #[test]
    fn test_eligibility_evaluation_bounds_rejects_too_many_transactions() {
        let env = soroban_sdk::Env::default();
        let mut assessment = GraduationManager::create_assessment(&env, BytesN::zero());
        assessment.transactions_completed = 2_000_000; // exceeds 1_000_000 bound

        let criteria = GraduationCriteria::default();
        let result = GraduationManager::evaluate_eligibility(&mut assessment, &criteria);
        assert_eq!(
            result,
            Err("transactions_completed exceeds deterministic bound")
        );
    }

    #[test]
    fn test_eligibility_evaluation_bounds_rejects_too_many_days() {
        let env = soroban_sdk::Env::default();
        let mut assessment = GraduationManager::create_assessment(&env, BytesN::zero());
        assessment.days_in_sandbox = 2_000; // exceeds 1_000 bound

        let criteria = GraduationCriteria::default();
        let result = GraduationManager::evaluate_eligibility(&mut assessment, &criteria);
        assert_eq!(result, Err("days_in_sandbox exceeds deterministic bound"));
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

    #[test]
    fn test_notes_length_rejected_when_too_long() {
        let env = soroban_sdk::Env::default();
        let mut assessment = GraduationManager::create_assessment(&env, BytesN::zero());
        assessment.is_eligible = true;

        let mut long_notes = soroban_sdk::Bytes::new(&env);
        for _ in 0..2048u32 {
            long_notes.push_back(b'a');
        }
        let result = GraduationManager::approve_graduation(&mut assessment, long_notes);
        assert_eq!(result, Err("notes exceed maximum permitted length"));
    }
}
