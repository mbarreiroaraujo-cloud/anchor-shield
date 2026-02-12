use anchor_lang::prelude::*;

declare_id!("Lend1ngPoo1111111111111111111111111111111111");

#[program]
pub mod lending_pool {
    use super::*;

    /// Initialize a new lending pool with configurable parameters.
    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        interest_rate: u64,
        liquidation_threshold: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_deposits = 0;
        pool.total_borrows = 0;
        pool.interest_rate = interest_rate;
        pool.liquidation_threshold = liquidation_threshold;
        pool.bump = ctx.bumps.pool;
        Ok(())
    }

    /// Deposit SOL into the lending pool.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        let pool = &mut ctx.accounts.pool;

        // Transfer SOL from user to pool vault
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.owner.to_account_info(),
                to: ctx.accounts.pool_vault.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        user.deposited += amount;
        pool.total_deposits += amount;

        emit!(DepositEvent {
            user: ctx.accounts.owner.key(),
            amount,
            total_deposited: user.deposited,
        });

        Ok(())
    }

    /// Borrow SOL from the lending pool against deposited collateral.
    ///
    /// BUG 1 — CRITICAL: Collateral check ignores existing debt.
    /// The check `user.deposited >= amount` does not subtract previous borrows.
    /// A user who deposited 100 SOL can borrow 100, then another 100, infinitely,
    /// because `user.deposited` never decreases and `user.borrowed` is never
    /// considered in the collateral validation.
    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        let pool = &mut ctx.accounts.pool;

        // Vulnerable: only checks total deposit, ignoring existing borrows.
        // Correct check would be: user.deposited - user.borrowed >= amount
        require!(
            user.deposited >= amount,
            LendingError::InsufficientCollateral
        );

        // Transfer SOL from pool vault to borrower
        let pool_key = pool.key();
        let seeds = &[b"vault", pool_key.as_ref(), &[pool.bump]];
        let signer_seeds = &[&seeds[..]];

        let cpi_context = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.pool_vault.to_account_info(),
                to: ctx.accounts.owner.to_account_info(),
            },
            signer_seeds,
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        user.borrowed += amount;
        pool.total_borrows += amount;

        emit!(BorrowEvent {
            user: ctx.accounts.owner.key(),
            amount,
            total_borrowed: user.borrowed,
        });

        Ok(())
    }

    /// Withdraw deposited SOL from the lending pool.
    ///
    /// BUG 2 — CRITICAL: Withdraw does not verify pending borrows.
    /// A user can deposit 100 SOL, borrow 90 SOL, then withdraw all 100 SOL.
    /// This effectively steals 90 SOL from the pool because there is no check
    /// that the user's remaining deposit covers their outstanding borrows.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        let pool = &mut ctx.accounts.pool;

        // Vulnerable: only checks deposit balance, ignores outstanding borrows.
        // Correct check would also verify: user.deposited - amount >= user.borrowed
        require!(
            user.deposited >= amount,
            LendingError::InsufficientBalance
        );

        // Transfer SOL from pool vault back to user
        let pool_key = pool.key();
        let seeds = &[b"vault", pool_key.as_ref(), &[pool.bump]];
        let signer_seeds = &[&seeds[..]];

        let cpi_context = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.pool_vault.to_account_info(),
                to: ctx.accounts.owner.to_account_info(),
            },
            signer_seeds,
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        user.deposited -= amount;
        pool.total_deposits -= amount;

        emit!(WithdrawEvent {
            user: ctx.accounts.owner.key(),
            amount,
            remaining_deposit: user.deposited,
        });

        Ok(())
    }

    /// Repay borrowed SOL to the lending pool.
    pub fn repay(ctx: Context<Repay>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        let pool = &mut ctx.accounts.pool;

        require!(user.borrowed >= amount, LendingError::RepayExceedsBorrow);

        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.owner.to_account_info(),
                to: ctx.accounts.pool_vault.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        user.borrowed -= amount;
        pool.total_borrows -= amount;

        Ok(())
    }

    /// Liquidate an under-collateralized position.
    ///
    /// BUG 3 — HIGH: Integer overflow in debt calculation.
    /// The expression `user.borrowed * pool.interest_rate * pool.total_borrows`
    /// uses wrapping arithmetic on u64 values. With large pool sizes and
    /// accumulated interest, this multiplication overflows, truncating the
    /// result. This makes heavily indebted positions appear solvent, preventing
    /// their liquidation and leaving the protocol with bad debt.
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        let pool = &mut ctx.accounts.pool;

        // Vulnerable: u64 multiplication can overflow silently.
        // With large values of total_borrows and interest_rate, the product
        // wraps around, producing a small number that passes the threshold check.
        // Correct approach: use checked_mul() or u128 intermediate arithmetic.
        let debt_with_interest =
            user.borrowed * pool.interest_rate * pool.total_borrows / 10000;

        require!(
            debt_with_interest > user.deposited * pool.liquidation_threshold / 100,
            LendingError::PositionHealthy
        );

        // Seize collateral: transfer user's deposit to liquidator
        let pool_key = pool.key();
        let seeds = &[b"vault", pool_key.as_ref(), &[pool.bump]];
        let signer_seeds = &[&seeds[..]];

        let seizure_amount = user.deposited;

        let cpi_context = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.pool_vault.to_account_info(),
                to: ctx.accounts.liquidator.to_account_info(),
            },
            signer_seeds,
        );
        anchor_lang::system_program::transfer(cpi_context, seizure_amount)?;

        pool.total_deposits -= user.deposited;
        pool.total_borrows -= user.borrowed;
        user.deposited = 0;
        user.borrowed = 0;

        emit!(LiquidateEvent {
            liquidator: ctx.accounts.liquidator.key(),
            user: ctx.accounts.owner.key(),
            seized_amount: seizure_amount,
        });

        Ok(())
    }
}

// ============================================================================
// Account Contexts
// ============================================================================

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + LendingPool::INIT_SPACE,
        seeds = [b"pool"],
        bump,
    )]
    pub pool: Account<'info, LendingPool>,

    /// CHECK: Pool vault PDA, holds SOL
    #[account(
        seeds = [b"vault", pool.key().as_ref()],
        bump,
    )]
    pub pool_vault: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"pool"],
        bump = pool.bump,
    )]
    pub pool: Account<'info, LendingPool>,

    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + UserAccount::INIT_SPACE,
        seeds = [b"user", pool.key().as_ref(), owner.key().as_ref()],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,

    /// CHECK: Pool vault PDA
    #[account(
        mut,
        seeds = [b"vault", pool.key().as_ref()],
        bump,
    )]
    pub pool_vault: AccountInfo<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(
        mut,
        seeds = [b"pool"],
        bump = pool.bump,
    )]
    pub pool: Account<'info, LendingPool>,

    #[account(
        mut,
        seeds = [b"user", pool.key().as_ref(), owner.key().as_ref()],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,

    /// CHECK: Pool vault PDA
    #[account(
        mut,
        seeds = [b"vault", pool.key().as_ref()],
        bump,
    )]
    pub pool_vault: AccountInfo<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"pool"],
        bump = pool.bump,
    )]
    pub pool: Account<'info, LendingPool>,

    #[account(
        mut,
        seeds = [b"user", pool.key().as_ref(), owner.key().as_ref()],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,

    /// CHECK: Pool vault PDA
    #[account(
        mut,
        seeds = [b"vault", pool.key().as_ref()],
        bump,
    )]
    pub pool_vault: AccountInfo<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Repay<'info> {
    #[account(
        mut,
        seeds = [b"pool"],
        bump = pool.bump,
    )]
    pub pool: Account<'info, LendingPool>,

    #[account(
        mut,
        seeds = [b"user", pool.key().as_ref(), owner.key().as_ref()],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,

    /// CHECK: Pool vault PDA
    #[account(
        mut,
        seeds = [b"vault", pool.key().as_ref()],
        bump,
    )]
    pub pool_vault: AccountInfo<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Liquidate<'info> {
    #[account(
        mut,
        seeds = [b"pool"],
        bump = pool.bump,
    )]
    pub pool: Account<'info, LendingPool>,

    #[account(
        mut,
        seeds = [b"user", pool.key().as_ref(), owner.key().as_ref()],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,

    /// CHECK: Pool vault PDA
    #[account(
        mut,
        seeds = [b"vault", pool.key().as_ref()],
        bump,
    )]
    pub pool_vault: AccountInfo<'info>,

    /// CHECK: The owner of the position being liquidated
    pub owner: AccountInfo<'info>,

    #[account(mut)]
    pub liquidator: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// Account Data
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct LendingPool {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub total_borrows: u64,
    pub interest_rate: u64,
    pub liquidation_threshold: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub deposited: u64,
    pub borrowed: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum LendingError {
    #[msg("Insufficient collateral for this borrow amount")]
    InsufficientCollateral,
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
    #[msg("Repay amount exceeds borrowed amount")]
    RepayExceedsBorrow,
    #[msg("Position is healthy and cannot be liquidated")]
    PositionHealthy,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct DepositEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub total_deposited: u64,
}

#[event]
pub struct BorrowEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub total_borrowed: u64,
}

#[event]
pub struct WithdrawEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub remaining_deposit: u64,
}

#[event]
pub struct LiquidateEvent {
    pub liquidator: Pubkey,
    pub user: Pubkey,
    pub seized_amount: u64,
}
