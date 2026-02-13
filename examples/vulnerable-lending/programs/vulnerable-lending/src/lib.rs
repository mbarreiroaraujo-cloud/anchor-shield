use anchor_lang::prelude::*;

declare_id!("BJYyF44xEVBfZDQwRdQ2d2ErjWoESsgaXHVcSw7MAv8K");

#[program]
pub mod vulnerable_lending {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_deposits = 0;
        pool.total_borrows = 0;
        pool.interest_rate = 500; // 5% in basis points
        pool.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_account;
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.depositor.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            amount,
        )?;
        user.deposited += amount;
        pool.total_deposits += amount;
        Ok(())
    }

    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_account;

        // BUG 1 (Critical): Collateral check ignores existing borrows.
        // Should be: user.deposited * 75 / 100 >= user.borrowed + amount
        // Actually does: user.deposited >= amount (ignores cumulative debt)
        require!(user.deposited >= amount, LendingError::InsufficientCollateral);

        user.borrowed += amount;
        pool.total_borrows += amount;

        let pool_key = pool.key();
        let seeds = &[b"vault".as_ref(), pool_key.as_ref(), &[pool.bump]];
        let signer = &[&seeds[..]];
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.borrower.to_account_info(),
                },
                signer,
            ),
            amount,
        )?;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_account;

        // BUG 2 (Critical): Doesn't check outstanding borrows before withdrawal.
        // User can deposit 100, borrow 90, withdraw 100 = steal 90 SOL
        require!(user.deposited >= amount, LendingError::InsufficientBalance);

        user.deposited -= amount;
        pool.total_deposits -= amount;

        let pool_key = pool.key();
        let seeds = &[b"vault".as_ref(), pool_key.as_ref(), &[pool.bump]];
        let signer = &[&seeds[..]];
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.withdrawer.to_account_info(),
                },
                signer,
            ),
            amount,
        )?;
        Ok(())
    }

    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        let pool = &ctx.accounts.pool;
        let user = &ctx.accounts.user_account;

        // BUG 3 (High): Integer overflow — unchecked u64 multiplication
        // borrowed * interest_rate * total_borrows can exceed u64::MAX
        // wraps to small number, making health appear high
        let interest = user.borrowed * pool.interest_rate as u64 * pool.total_borrows;

        // BUG 4 (Medium): Division by zero when borrowed + interest == 0
        let health = user.deposited * 100 / (user.borrowed + interest);
        require!(health < 75, LendingError::HealthyPosition);

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + Pool::INIT_SPACE)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: PDA vault controlled by the pool
    #[account(mut, seeds = [b"vault", pool.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    /// CHECK: PDA vault controlled by the pool
    #[account(mut, seeds = [b"vault", pool.key().as_ref()], bump = pool.bump)]
    pub vault: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub borrower: Signer<'info>,
    /// CHECK: PDA vault controlled by the pool
    #[account(mut, seeds = [b"vault", pool.key().as_ref()], bump = pool.bump)]
    pub vault: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub withdrawer: Signer<'info>,
    /// CHECK: PDA vault controlled by the pool
    #[account(mut, seeds = [b"vault", pool.key().as_ref()], bump = pool.bump)]
    pub vault: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Liquidate<'info> {
    pub pool: Account<'info, Pool>,
    pub user_account: Account<'info, UserAccount>,
    pub liquidator: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub total_borrows: u64,
    pub interest_rate: u16,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub deposited: u64,
    pub borrowed: u64,
}

#[error_code]
pub enum LendingError {
    #[msg("Insufficient collateral for borrow")]
    InsufficientCollateral,
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
    #[msg("Position is healthy, cannot liquidate")]
    HealthyPosition,
}
