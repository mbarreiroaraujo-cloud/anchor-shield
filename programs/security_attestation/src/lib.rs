use anchor_lang::prelude::*;

declare_id!("AShd1111111111111111111111111111111111111111");

/// On-chain security attestation program for anchor-shield.
///
/// This program stores immutable security scan results as PDAs on Solana,
/// enabling composable security infrastructure. Other programs can query
/// attestations to verify whether a target has been audited and its score.
///
/// PDA derivation: seeds = [b"attestation", target_hash]
/// where target_hash is the SHA-256 of the scanned program ID or repository.
#[program]
pub mod security_attestation {
    use super::*;

    /// Create a new security attestation for a scanned target.
    ///
    /// The attestation is stored as a PDA derived from the target hash,
    /// ensuring one attestation per target per authority. The authority
    /// (scanner operator) must sign the transaction.
    pub fn create_attestation(
        ctx: Context<CreateAttestation>,
        target_hash: [u8; 32],
        scanner_version: String,
        security_score: u8,
        patterns_checked: u8,
        issues_found: u8,
        issues_hash: [u8; 32],
        report_uri: String,
    ) -> Result<()> {
        require!(security_score <= 100, AttestationError::InvalidScore);
        require!(
            scanner_version.len() <= 32,
            AttestationError::StringTooLong
        );
        require!(report_uri.len() <= 256, AttestationError::StringTooLong);

        let attestation = &mut ctx.accounts.attestation;
        attestation.authority = ctx.accounts.authority.key();
        attestation.target_hash = target_hash;
        attestation.scanner_version = scanner_version;
        attestation.timestamp = Clock::get()?.unix_timestamp;
        attestation.security_score = security_score;
        attestation.patterns_checked = patterns_checked;
        attestation.issues_found = issues_found;
        attestation.issues_hash = issues_hash;
        attestation.report_uri = report_uri;
        attestation.bump = ctx.bumps.attestation;

        emit!(AttestationCreated {
            authority: attestation.authority,
            target_hash,
            security_score,
            issues_found,
            timestamp: attestation.timestamp,
        });

        Ok(())
    }

    /// Update an existing attestation with new scan results.
    ///
    /// Only the original authority can update an attestation.
    /// This enables re-scanning and tracking security improvements over time.
    pub fn update_attestation(
        ctx: Context<UpdateAttestation>,
        scanner_version: String,
        security_score: u8,
        patterns_checked: u8,
        issues_found: u8,
        issues_hash: [u8; 32],
        report_uri: String,
    ) -> Result<()> {
        require!(security_score <= 100, AttestationError::InvalidScore);
        require!(
            scanner_version.len() <= 32,
            AttestationError::StringTooLong
        );
        require!(report_uri.len() <= 256, AttestationError::StringTooLong);

        let attestation = &mut ctx.accounts.attestation;
        attestation.scanner_version = scanner_version;
        attestation.timestamp = Clock::get()?.unix_timestamp;
        attestation.security_score = security_score;
        attestation.patterns_checked = patterns_checked;
        attestation.issues_found = issues_found;
        attestation.issues_hash = issues_hash;
        attestation.report_uri = report_uri;

        emit!(AttestationUpdated {
            authority: attestation.authority,
            target_hash: attestation.target_hash,
            security_score,
            issues_found,
            timestamp: attestation.timestamp,
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(target_hash: [u8; 32])]
pub struct CreateAttestation<'info> {
    #[account(
        init,
        payer = authority,
        space = SecurityAttestation::SPACE,
        seeds = [b"attestation", target_hash.as_ref()],
        bump,
    )]
    pub attestation: Account<'info, SecurityAttestation>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAttestation<'info> {
    #[account(
        mut,
        has_one = authority @ AttestationError::Unauthorized,
    )]
    pub attestation: Account<'info, SecurityAttestation>,

    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct SecurityAttestation {
    /// The authority (scanner operator) that created this attestation.
    pub authority: Pubkey,
    /// SHA-256 hash of the scanned target (program ID or repo identifier).
    pub target_hash: [u8; 32],
    /// Scanner version string, e.g. "anchor-shield-0.1.0".
    pub scanner_version: String,
    /// Unix timestamp of when the scan was performed.
    pub timestamp: i64,
    /// Security score from 0 (worst) to 100 (best).
    pub security_score: u8,
    /// Number of vulnerability patterns checked.
    pub patterns_checked: u8,
    /// Number of issues found during the scan.
    pub issues_found: u8,
    /// SHA-256 hash of the full off-chain report for integrity verification.
    pub issues_hash: [u8; 32],
    /// URI pointing to the full report (IPFS, GitHub, or HTTP).
    pub report_uri: String,
    /// PDA bump seed for address derivation.
    pub bump: u8,
}

impl SecurityAttestation {
    /// Fixed portion: discriminator(8) + pubkey(32) + hash(32) + i64(8) + u8(1)
    /// + u8(1) + u8(1) + hash(32) + bump(1) = 116
    /// Variable: scanner_version(4 + 32) + report_uri(4 + 256) = 296
    /// Total: 116 + 296 = 412
    pub const SPACE: usize = 8 + 32 + 32 + (4 + 32) + 8 + 1 + 1 + 1 + 32 + (4 + 256) + 1;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct AttestationCreated {
    pub authority: Pubkey,
    pub target_hash: [u8; 32],
    pub security_score: u8,
    pub issues_found: u8,
    pub timestamp: i64,
}

#[event]
pub struct AttestationUpdated {
    pub authority: Pubkey,
    pub target_hash: [u8; 32],
    pub security_score: u8,
    pub issues_found: u8,
    pub timestamp: i64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum AttestationError {
    #[msg("Security score must be between 0 and 100")]
    InvalidScore,
    #[msg("String exceeds maximum allowed length")]
    StringTooLong,
    #[msg("Only the original authority can update this attestation")]
    Unauthorized,
}
