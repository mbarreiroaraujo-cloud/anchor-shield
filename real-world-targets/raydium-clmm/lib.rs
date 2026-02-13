// ========== instructions/create_pool.rs ==========
use crate::error::ErrorCode;
use crate::states::*;
use crate::util::create_token_vault_account;
use crate::{libraries::tick_math, util};
use anchor_lang::{prelude::*, solana_program};
use anchor_spl::token_interface::{Mint, TokenInterface};
// use solana_program::{program::invoke_signed, system_instruction};
#[derive(Accounts)]
pub struct CreatePool<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub pool_creator: Signer<'info>,

    /// Which config the pool belongs to.
    pub amm_config: Box<Account<'info, AmmConfig>>,

    /// Initialize an account to store the pool state
    #[account(
        init,
        seeds = [
            POOL_SEED.as_bytes(),
            amm_config.key().as_ref(),
            token_mint_0.key().as_ref(),
            token_mint_1.key().as_ref(),
        ],
        bump,
        payer = pool_creator,
        space = PoolState::LEN
    )]
    pub pool_state: AccountLoader<'info, PoolState>,

    /// Token_0 mint, the key must be smaller then token_1 mint.
    #[account(
        constraint = token_mint_0.key() < token_mint_1.key(),
        mint::token_program = token_program_0
    )]
    pub token_mint_0: Box<InterfaceAccount<'info, Mint>>,

    /// Token_1 mint
    #[account(
        mint::token_program = token_program_1
    )]
    pub token_mint_1: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: Token_0 vault for the pool, initialized in contract
    #[account(
        mut,
        seeds =[
            POOL_VAULT_SEED.as_bytes(),
            pool_state.key().as_ref(),
            token_mint_0.key().as_ref(),
        ],
        bump,
    )]
    pub token_vault_0: UncheckedAccount<'info>,

    /// CHECK: Token_1 vault for the pool, initialized in contract
    #[account(
        mut,
        seeds =[
            POOL_VAULT_SEED.as_bytes(),
            pool_state.key().as_ref(),
            token_mint_1.key().as_ref(),
        ],
        bump,
    )]
    pub token_vault_1: UncheckedAccount<'info>,

    /// Initialize an account to store oracle observations
    #[account(
        init,
        seeds = [
            OBSERVATION_SEED.as_bytes(),
            pool_state.key().as_ref(),
        ],
        bump,
        payer = pool_creator,
        space = ObservationState::LEN
    )]
    pub observation_state: AccountLoader<'info, ObservationState>,

    /// Initialize an account to store if a tick array is initialized.
    #[account(
        init,
        seeds = [
            POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
            pool_state.key().as_ref(),
        ],
        bump,
        payer = pool_creator,
        space = TickArrayBitmapExtension::LEN
    )]
    pub tick_array_bitmap: AccountLoader<'info, TickArrayBitmapExtension>,

    /// Spl token program or token program 2022
    pub token_program_0: Interface<'info, TokenInterface>,
    /// Spl token program or token program 2022
    pub token_program_1: Interface<'info, TokenInterface>,
    /// To create a new program account
    pub system_program: Program<'info, System>,
    /// Sysvar for program account
    pub rent: Sysvar<'info, Rent>,
    // remaining account
    // #[account(
    //     seeds = [
    //     SUPPORT_MINT_SEED.as_bytes(),
    //     token_mint_0.key().as_ref(),
    // ],
    //     bump
    // )]
    // pub support_mint0_associated: Account<'info, SupportMintAssociated>,

    // #[account(
    //     seeds = [
    //     SUPPORT_MINT_SEED.as_bytes(),
    //     token_mint_1.key().as_ref(),
    // ],
    //     bump
    // )]
    // pub support_mint1_associated: Account<'info, SupportMintAssociated>,
}

pub fn create_pool(ctx: Context<CreatePool>, sqrt_price_x64: u128, open_time: u64) -> Result<()> {
    let mint0_associated_is_initialized = util::support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_mint_0,
    )?;
    let mint1_associated_is_initialized = util::support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_mint_1,
    )?;
    if !(util::is_supported_mint(&ctx.accounts.token_mint_0, mint0_associated_is_initialized)
        .unwrap()
        && util::is_supported_mint(&ctx.accounts.token_mint_1, mint1_associated_is_initialized)
            .unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
    let block_timestamp = solana_program::clock::Clock::get()?.unix_timestamp as u64;
    require_gt!(block_timestamp, open_time);
    let pool_id = ctx.accounts.pool_state.key();
    let mut pool_state = ctx.accounts.pool_state.load_init()?;

    let tick = tick_math::get_tick_at_sqrt_price(sqrt_price_x64)?;
    #[cfg(feature = "enable-log")]
    msg!(
        "create pool, init_price: {}, init_tick:{}",
        sqrt_price_x64,
        tick
    );

    // init token vault accounts
    create_token_vault_account(
        &ctx.accounts.pool_creator,
        &ctx.accounts.pool_state.to_account_info(),
        &ctx.accounts.token_vault_0,
        &ctx.accounts.token_mint_0,
        &ctx.accounts.system_program,
        &ctx.accounts.token_program_0,
        &[
            POOL_VAULT_SEED.as_bytes(),
            ctx.accounts.pool_state.key().as_ref(),
            ctx.accounts.token_mint_0.key().as_ref(),
            &[ctx.bumps.token_vault_0][..],
        ],
    )?;

    create_token_vault_account(
        &ctx.accounts.pool_creator,
        &ctx.accounts.pool_state.to_account_info(),
        &ctx.accounts.token_vault_1,
        &ctx.accounts.token_mint_1,
        &ctx.accounts.system_program,
        &ctx.accounts.token_program_1,
        &[
            POOL_VAULT_SEED.as_bytes(),
            ctx.accounts.pool_state.key().as_ref(),
            ctx.accounts.token_mint_1.key().as_ref(),
            &[ctx.bumps.token_vault_1][..],
        ],
    )?;

    // init observation
    ctx.accounts
        .observation_state
        .load_init()?
        .initialize(pool_id)?;

    let bump = ctx.bumps.pool_state;
    pool_state.initialize(
        bump,
        sqrt_price_x64,
        0,
        tick,
        ctx.accounts.pool_creator.key(),
        ctx.accounts.token_vault_0.key(),
        ctx.accounts.token_vault_1.key(),
        ctx.accounts.amm_config.as_ref(),
        ctx.accounts.token_mint_0.as_ref(),
        ctx.accounts.token_mint_1.as_ref(),
        ctx.accounts.observation_state.key(),
    )?;

    ctx.accounts
        .tick_array_bitmap
        .load_init()?
        .initialize(pool_id);

    emit!(PoolCreatedEvent {
        token_mint_0: ctx.accounts.token_mint_0.key(),
        token_mint_1: ctx.accounts.token_mint_1.key(),
        tick_spacing: ctx.accounts.amm_config.tick_spacing,
        pool_state: ctx.accounts.pool_state.key(),
        sqrt_price_x64,
        tick,
        token_vault_0: ctx.accounts.token_vault_0.key(),
        token_vault_1: ctx.accounts.token_vault_1.key(),
    });
    Ok(())
}


// ========== instructions/increase_liquidity.rs ==========
use super::add_liquidity;
use crate::error::ErrorCode;
use crate::instructions::LiquidityChangeResult;
use crate::libraries::{big_num::U128, fixed_point_64, full_math::MulDiv};
use crate::states::*;
use crate::util::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};
use anchor_spl::token_interface::{Mint, Token2022};

#[derive(Accounts)]
pub struct IncreaseLiquidity<'info> {
    /// Pays to mint the position
    pub nft_owner: Signer<'info>,

    /// The token account for nft
    #[account(
        constraint = nft_account.mint == personal_position.nft_mint,
        constraint = nft_account.amount == 1,
        token::authority = nft_owner
    )]
    pub nft_account: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,

    /// CHECK: Deprecated: protocol_position is deprecated and kept for compatibility.
    pub protocol_position: UncheckedAccount<'info>,

    /// Increase liquidity for this position
    #[account(mut, constraint = personal_position.pool_id == pool_state.key())]
    pub personal_position: Box<Account<'info, PersonalPositionState>>,

    /// Stores init state for the lower tick
    #[account(mut, constraint = tick_array_lower.load()?.pool_id == pool_state.key())]
    pub tick_array_lower: AccountLoader<'info, TickArrayState>,

    /// Stores init state for the upper tick
    #[account(mut, constraint = tick_array_upper.load()?.pool_id == pool_state.key())]
    pub tick_array_upper: AccountLoader<'info, TickArrayState>,

    /// The payer's token account for token_0
    #[account(
        mut,
        token::mint = token_vault_0.mint
    )]
    pub token_account_0: Box<Account<'info, TokenAccount>>,

    /// The token account spending token_1 to mint the position
    #[account(
        mut,
        token::mint = token_vault_1.mint
    )]
    pub token_account_1: Box<Account<'info, TokenAccount>>,

    /// The address that holds pool tokens for token_0
    #[account(
        mut,
        constraint = token_vault_0.key() == pool_state.load()?.token_vault_0
    )]
    pub token_vault_0: Box<Account<'info, TokenAccount>>,

    /// The address that holds pool tokens for token_1
    #[account(
        mut,
        constraint = token_vault_1.key() == pool_state.load()?.token_vault_1
    )]
    pub token_vault_1: Box<Account<'info, TokenAccount>>,

    /// Program to create mint account and mint tokens
    pub token_program: Program<'info, Token>,
    // remaining account
    // #[account(
    //     seeds = [
    //         POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
    //         pool_state.key().as_ref(),
    //     ],
    //     bump
    // )]
    // pub tick_array_bitmap: AccountLoader<'info, TickArrayBitmapExtension>,
}

pub fn increase_liquidity_v1<'a, 'b, 'c: 'info, 'info>(
    ctx: Context<'a, 'b, 'c, 'info, IncreaseLiquidity<'info>>,
    liquidity: u128,
    amount_0_max: u64,
    amount_1_max: u64,
    base_flag: Option<bool>,
) -> Result<()> {
    increase_liquidity(
        &ctx.accounts.nft_owner,
        &ctx.accounts.pool_state,
        &mut ctx.accounts.personal_position,
        &ctx.accounts.tick_array_lower,
        &ctx.accounts.tick_array_upper,
        &ctx.accounts.token_account_0.to_account_info(),
        &ctx.accounts.token_account_1.to_account_info(),
        &ctx.accounts.token_vault_0.to_account_info(),
        &ctx.accounts.token_vault_1.to_account_info(),
        &ctx.accounts.token_program,
        None,
        None,
        None,
        &ctx.remaining_accounts,
        liquidity,
        amount_0_max,
        amount_1_max,
        base_flag,
    )
}

pub fn increase_liquidity<'a, 'b, 'c: 'info, 'info>(
    nft_owner: &'b Signer<'info>,
    pool_state_loader: &'b AccountLoader<'info, PoolState>,
    personal_position: &'b mut Box<Account<'info, PersonalPositionState>>,
    tick_array_lower_loader: &'b AccountLoader<'info, TickArrayState>,
    tick_array_upper_loader: &'b AccountLoader<'info, TickArrayState>,
    token_account_0: &'b AccountInfo<'info>,
    token_account_1: &'b AccountInfo<'info>,
    token_vault_0: &'b AccountInfo<'info>,
    token_vault_1: &'b AccountInfo<'info>,
    token_program: &'b Program<'info, Token>,
    token_program_2022: Option<&Program<'info, Token2022>>,
    vault_0_mint: Option<Box<InterfaceAccount<'info, Mint>>>,
    vault_1_mint: Option<Box<InterfaceAccount<'info, Mint>>>,

    remaining_accounts: &'c [AccountInfo<'info>],
    liquidity: u128,
    amount_0_max: u64,
    amount_1_max: u64,
    base_flag: Option<bool>,
) -> Result<()> {
    let mut liquidity = liquidity;
    let pool_state = &mut pool_state_loader.load_mut()?;
    if !pool_state.get_status_by_bit(PoolStatusBitIndex::OpenPositionOrIncreaseLiquidity) {
        return err!(ErrorCode::NotApproved);
    }
    let tick_lower = personal_position.tick_lower_index;
    let tick_upper = personal_position.tick_upper_index;

    let use_tickarray_bitmap_extension =
        pool_state.is_overflow_default_tickarray_bitmap(vec![tick_lower, tick_upper]);

    let LiquidityChangeResult {
        amount_0,
        amount_1,
        amount_0_transfer_fee,
        amount_1_transfer_fee,
        fee_growth_inside_0_x64: fee_growth_inside_0_x64_latest,
        fee_growth_inside_1_x64: fee_growth_inside_1_x64_latest,
        reward_growths_inside: reward_growths_inside_latest,
        ..
    } = add_liquidity(
        &nft_owner,
        token_account_0,
        token_account_1,
        token_vault_0,
        token_vault_1,
        &AccountLoad::<TickArrayState>::try_from(&tick_array_lower_loader.to_account_info())?,
        &AccountLoad::<TickArrayState>::try_from(&tick_array_upper_loader.to_account_info())?,
        token_program_2022,
        token_program,
        vault_0_mint,
        vault_1_mint,
        if use_tickarray_bitmap_extension {
            require_keys_eq!(
                remaining_accounts[0].key(),
                TickArrayBitmapExtension::key(pool_state_loader.key())
            );
            Some(&remaining_accounts[0])
        } else {
            None
        },
        pool_state,
        &mut liquidity,
        amount_0_max,
        amount_1_max,
        tick_lower,
        tick_upper,
        base_flag,
    )?;

    personal_position.increase_liquidity(
        liquidity,
        fee_growth_inside_0_x64_latest,
        fee_growth_inside_1_x64_latest,
        reward_growths_inside_latest,
        get_recent_epoch()?,
    )?;
    emit!(IncreaseLiquidityEvent {
        position_nft_mint: personal_position.nft_mint,
        liquidity,
        amount_0,
        amount_1,
        amount_0_transfer_fee,
        amount_1_transfer_fee
    });

    Ok(())
}

pub fn calculate_latest_token_fees(
    last_total_fees: u64,
    fee_growth_inside_last_x64: u128,
    fee_growth_inside_latest_x64: u128,
    liquidity: u128,
) -> u64 {
    let fee_growth_delta =
        U128::from(fee_growth_inside_latest_x64.wrapping_sub(fee_growth_inside_last_x64))
            .mul_div_floor(U128::from(liquidity), U128::from(fixed_point_64::Q64))
            .unwrap()
            .to_underflow_u64();
    #[cfg(feature = "enable-log")]
    msg!("calculate_latest_token_fees fee_growth_delta:{}, fee_growth_inside_latest_x64:{}, fee_growth_inside_last_x64:{}, liquidity:{}", fee_growth_delta, fee_growth_inside_latest_x64, fee_growth_inside_last_x64, liquidity);
    last_total_fees.checked_add(fee_growth_delta).unwrap()
}


// ========== instructions/decrease_liquidity.rs ==========
use super::modify_position;
use crate::error::ErrorCode;
use crate::instructions::LiquidityChangeResult;
use crate::states::*;
use crate::util::get_recent_epoch;
use crate::util::{self, transfer_from_pool_vault_to_user};
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};
use anchor_spl::token_2022::spl_token_2022;
use anchor_spl::token_interface::{self, Mint, Token2022};
use std::cell::RefMut;
use std::ops::Deref;

/// Memo msg for decrease liquidity
pub const DECREASE_MEMO_MSG: &'static [u8] = b"raydium_decrease";
#[derive(Accounts)]
pub struct DecreaseLiquidity<'info> {
    /// The position owner or delegated authority
    pub nft_owner: Signer<'info>,

    /// The token account for the tokenized position
    #[account(
        constraint = nft_account.mint == personal_position.nft_mint,
        constraint = nft_account.amount == 1,
        token::authority = nft_owner
    )]
    pub nft_account: Box<Account<'info, TokenAccount>>,

    /// Decrease liquidity for this position
    #[account(mut, constraint = personal_position.pool_id == pool_state.key())]
    pub personal_position: Box<Account<'info, PersonalPositionState>>,

    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,

    /// CHECK: Deprecated: protocol_position is deprecated and kept for compatibility.
    pub protocol_position: UncheckedAccount<'info>,

    /// Token_0 vault
    #[account(
        mut,
        constraint = token_vault_0.key() == pool_state.load()?.token_vault_0
    )]
    pub token_vault_0: Box<Account<'info, TokenAccount>>,

    /// Token_1 vault
    #[account(
        mut,
        constraint = token_vault_1.key() == pool_state.load()?.token_vault_1
    )]
    pub token_vault_1: Box<Account<'info, TokenAccount>>,

    /// Stores init state for the lower tick
    #[account(mut, constraint = tick_array_lower.load()?.pool_id == pool_state.key())]
    pub tick_array_lower: AccountLoader<'info, TickArrayState>,

    /// Stores init state for the upper tick
    #[account(mut, constraint = tick_array_upper.load()?.pool_id == pool_state.key())]
    pub tick_array_upper: AccountLoader<'info, TickArrayState>,

    /// The destination token account for receive amount_0
    #[account(
        mut,
        token::mint = token_vault_0.mint
    )]
    pub recipient_token_account_0: Box<Account<'info, TokenAccount>>,

    /// The destination token account for receive amount_1
    #[account(
        mut,
        token::mint = token_vault_1.mint
    )]
    pub recipient_token_account_1: Box<Account<'info, TokenAccount>>,

    /// SPL program to transfer out tokens
    pub token_program: Program<'info, Token>,
    // remaining account
    // #[account(
    //     seeds = [
    //         POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
    //         pool_state.key().as_ref(),
    //     ],
    //     bump
    // )]
    // pub tick_array_bitmap: AccountLoader<'info, TickArrayBitmapExtension>,
}

pub fn decrease_liquidity_v1<'a, 'b, 'c: 'info, 'info>(
    ctx: Context<'a, 'b, 'c, 'info, DecreaseLiquidity<'info>>,
    liquidity: u128,
    amount_0_min: u64,
    amount_1_min: u64,
) -> Result<()> {
    decrease_liquidity(
        &ctx.accounts.pool_state,
        &mut ctx.accounts.personal_position,
        &ctx.accounts.token_vault_0.to_account_info(),
        &ctx.accounts.token_vault_1.to_account_info(),
        &ctx.accounts.tick_array_lower,
        &ctx.accounts.tick_array_upper,
        &ctx.accounts.recipient_token_account_0.to_account_info(),
        &ctx.accounts.recipient_token_account_1.to_account_info(),
        &ctx.accounts.token_program,
        None,
        None,
        None,
        None,
        &ctx.remaining_accounts,
        liquidity,
        amount_0_min,
        amount_1_min,
    )
}

pub fn decrease_liquidity<'a, 'b, 'c: 'info, 'info>(
    pool_state_loader: &'b AccountLoader<'info, PoolState>,
    personal_position: &'b mut Box<Account<'info, PersonalPositionState>>,
    token_vault_0: &'b AccountInfo<'info>,
    token_vault_1: &'b AccountInfo<'info>,
    tick_array_lower_loader: &'b AccountLoader<'info, TickArrayState>,
    tick_array_upper_loader: &'b AccountLoader<'info, TickArrayState>,
    recipient_token_account_0: &'b AccountInfo<'info>,
    recipient_token_account_1: &'b AccountInfo<'info>,
    token_program: &'b Program<'info, Token>,
    token_program_2022: Option<Program<'info, Token2022>>,
    _memo_program: Option<UncheckedAccount<'info>>,
    vault_0_mint: Option<Box<InterfaceAccount<'info, Mint>>>,
    vault_1_mint: Option<Box<InterfaceAccount<'info, Mint>>>,
    remaining_accounts: &'c [AccountInfo<'info>],
    liquidity: u128,
    amount_0_min: u64,
    amount_1_min: u64,
) -> Result<()> {
    // if accounts.memo_program.is_some() {
    //     let memp_program = accounts.memo_program.as_ref().unwrap().to_account_info();
    //     invoke_memo_instruction(DECREASE_MEMO_MSG, memp_program)?;
    // }
    assert!(liquidity <= personal_position.liquidity);
    let liquidity_before;
    let pool_sqrt_price_x64;
    let pool_tick_current;
    let mut tickarray_bitmap_extension = None;

    let remaining_collect_accounts = &mut Vec::new();
    {
        let pool_state = pool_state_loader.load()?;
        if !pool_state.get_status_by_bit(PoolStatusBitIndex::DecreaseLiquidity)
            && !pool_state.get_status_by_bit(PoolStatusBitIndex::CollectFee)
            && !pool_state.get_status_by_bit(PoolStatusBitIndex::CollectReward)
        {
            return err!(ErrorCode::NotApproved);
        }
        liquidity_before = pool_state.liquidity;
        pool_sqrt_price_x64 = pool_state.sqrt_price_x64;
        pool_tick_current = pool_state.tick_current;

        let use_tickarray_bitmap_extension = pool_state.is_overflow_default_tickarray_bitmap(vec![
            tick_array_lower_loader.load()?.start_tick_index,
            tick_array_upper_loader.load()?.start_tick_index,
        ]);

        for account_info in remaining_accounts.into_iter() {
            if account_info
                .key()
                .eq(&TickArrayBitmapExtension::key(pool_state.key()))
            {
                tickarray_bitmap_extension = Some(account_info);
                continue;
            }
            remaining_collect_accounts.push(account_info);
        }
        if use_tickarray_bitmap_extension {
            require!(
                tickarray_bitmap_extension.is_some(),
                ErrorCode::MissingTickArrayBitmapExtensionAccount
            );
        }
    }

    let (decrease_amount_0, latest_fees_owed_0, decrease_amount_1, latest_fees_owed_1) =
        decrease_liquidity_and_update_position(
            pool_state_loader,
            personal_position,
            tick_array_lower_loader,
            tick_array_upper_loader,
            tickarray_bitmap_extension,
            liquidity,
        )?;

    let mut transfer_fee_0 = 0;
    let mut transfer_fee_1 = 0;
    if vault_0_mint.is_some() {
        transfer_fee_0 =
            util::get_transfer_fee(vault_0_mint.clone().unwrap(), decrease_amount_0).unwrap();
    }
    if vault_1_mint.is_some() {
        transfer_fee_1 =
            util::get_transfer_fee(vault_1_mint.clone().unwrap(), decrease_amount_1).unwrap();
    }
    emit!(LiquidityCalculateEvent {
        pool_liquidity: liquidity_before,
        pool_sqrt_price_x64: pool_sqrt_price_x64,
        pool_tick: pool_tick_current,
        calc_amount_0: decrease_amount_0,
        calc_amount_1: decrease_amount_1,
        trade_fee_owed_0: latest_fees_owed_0,
        trade_fee_owed_1: latest_fees_owed_1,
        transfer_fee_0,
        transfer_fee_1,
    });
    #[cfg(feature = "enable-log")]
    msg!(
        "decrease_amount_0: {}, transfer_fee_0: {}, latest_fees_owed_0: {}, decrease_amount_1: {}, transfer_fee_1: {}, latest_fees_owed_1: {}",
        decrease_amount_0,
        transfer_fee_0,
        latest_fees_owed_0,
        decrease_amount_1,
        transfer_fee_1,
        latest_fees_owed_1
    );
    if liquidity > 0 {
        require_gte!(
            decrease_amount_0 - transfer_fee_0,
            amount_0_min,
            ErrorCode::PriceSlippageCheck
        );
        require_gte!(
            decrease_amount_1 - transfer_fee_1,
            amount_1_min,
            ErrorCode::PriceSlippageCheck
        );
    }
    let transfer_amount_0 = decrease_amount_0 + latest_fees_owed_0;
    let transfer_amount_1 = decrease_amount_1 + latest_fees_owed_1;

    let mut token_2022_program_opt: Option<AccountInfo> = None;
    if token_program_2022.is_some() {
        token_2022_program_opt = Some(token_program_2022.clone().unwrap().to_account_info());
    }

    transfer_from_pool_vault_to_user(
        pool_state_loader,
        &token_vault_0.to_account_info(),
        recipient_token_account_0,
        vault_0_mint.clone(),
        token_program,
        token_2022_program_opt.clone(),
        transfer_amount_0,
    )?;

    transfer_from_pool_vault_to_user(
        pool_state_loader,
        &token_vault_1.to_account_info(),
        recipient_token_account_1,
        vault_1_mint.clone(),
        token_program,
        token_2022_program_opt.clone(),
        transfer_amount_1,
    )?;

    check_unclaimed_fees_and_vault(pool_state_loader, token_vault_0, token_vault_1)?;

    let reward_amounts = collect_rewards(
        pool_state_loader,
        remaining_collect_accounts.as_slice(),
        token_program,
        token_2022_program_opt.clone(),
        personal_position,
        if token_2022_program_opt.is_none() {
            false
        } else {
            true
        },
    )?;
    emit!(DecreaseLiquidityEvent {
        position_nft_mint: personal_position.nft_mint,
        liquidity,
        decrease_amount_0: decrease_amount_0,
        decrease_amount_1: decrease_amount_1,
        fee_amount_0: latest_fees_owed_0,
        fee_amount_1: latest_fees_owed_1,
        reward_amounts,
        transfer_fee_0: transfer_fee_0,
        transfer_fee_1: transfer_fee_1,
    });

    Ok(())
}

pub fn decrease_liquidity_and_update_position<'a, 'b, 'c: 'info, 'info>(
    pool_state_loader: &AccountLoader<'info, PoolState>,
    personal_position: &mut Box<Account<'info, PersonalPositionState>>,
    tick_array_lower: &AccountLoader<'info, TickArrayState>,
    tick_array_upper: &AccountLoader<'info, TickArrayState>,
    tick_array_bitmap_extension: Option<&'c AccountInfo<'info>>,
    liquidity: u128,
) -> Result<(u64, u64, u64, u64)> {
    let mut pool_state = pool_state_loader.load_mut()?;
    let mut decrease_amount_0 = 0;
    let mut decrease_amount_1 = 0;
    if pool_state.get_status_by_bit(PoolStatusBitIndex::DecreaseLiquidity) {
        let LiquidityChangeResult {
            amount_0,
            amount_1,
            fee_growth_inside_0_x64: fee_growth_inside_0_x64_latest,
            fee_growth_inside_1_x64: fee_growth_inside_1_x64_latest,
            reward_growths_inside: reward_growths_inside_latest,
            ..
        } = burn_liquidity(
            &mut pool_state,
            tick_array_lower,
            tick_array_upper,
            tick_array_bitmap_extension,
            personal_position.tick_lower_index,
            personal_position.tick_upper_index,
            liquidity,
        )?;

        personal_position.decrease_liquidity(
            liquidity,
            fee_growth_inside_0_x64_latest,
            fee_growth_inside_1_x64_latest,
            reward_growths_inside_latest,
            get_recent_epoch()?,
        )?;
        decrease_amount_0 = amount_0;
        decrease_amount_1 = amount_1;
    }

    let mut latest_fees_owed_0 = 0;
    let mut latest_fees_owed_1 = 0;
    if pool_state.get_status_by_bit(PoolStatusBitIndex::CollectFee) {
        latest_fees_owed_0 = personal_position.token_fees_owed_0;
        latest_fees_owed_1 = personal_position.token_fees_owed_1;

        require_gte!(
            pool_state.total_fees_token_0 - pool_state.total_fees_claimed_token_0,
            latest_fees_owed_0
        );
        require_gte!(
            pool_state.total_fees_token_1 - pool_state.total_fees_claimed_token_1,
            latest_fees_owed_1
        );

        personal_position.token_fees_owed_0 = 0;
        personal_position.token_fees_owed_1 = 0;

        pool_state.total_fees_claimed_token_0 = pool_state
            .total_fees_claimed_token_0
            .checked_add(latest_fees_owed_0)
            .unwrap();
        pool_state.total_fees_claimed_token_1 = pool_state
            .total_fees_claimed_token_1
            .checked_add(latest_fees_owed_1)
            .unwrap();
    }

    Ok((
        decrease_amount_0,
        latest_fees_owed_0,
        decrease_amount_1,
        latest_fees_owed_1,
    ))
}

pub fn burn_liquidity<'c: 'info, 'info>(
    pool_state: &mut RefMut<PoolState>,
    tick_array_lower_loader: &AccountLoader<'info, TickArrayState>,
    tick_array_upper_loader: &AccountLoader<'info, TickArrayState>,
    tickarray_bitmap_extension: Option<&'c AccountInfo<'info>>,
    tick_lower_index: i32,
    tick_upper_index: i32,
    liquidity: u128,
) -> Result<LiquidityChangeResult> {
    require_keys_eq!(tick_array_lower_loader.load()?.pool_id, pool_state.key());
    require_keys_eq!(tick_array_upper_loader.load()?.pool_id, pool_state.key());
    let liquidity_before = pool_state.liquidity;
    // get tick_state
    let mut tick_lower_state = *tick_array_lower_loader
        .load_mut()?
        .get_tick_state_mut(tick_lower_index, pool_state.tick_spacing)?;
    let mut tick_upper_state = *tick_array_upper_loader
        .load_mut()?
        .get_tick_state_mut(tick_upper_index, pool_state.tick_spacing)?;
    let clock = Clock::get()?;
    let result = modify_position(
        -i128::try_from(liquidity).unwrap(),
        pool_state,
        &mut tick_lower_state,
        &mut tick_upper_state,
        clock.unix_timestamp as u64,
    )?;

    // update tick_state
    tick_array_lower_loader.load_mut()?.update_tick_state(
        tick_lower_index,
        pool_state.tick_spacing,
        tick_lower_state,
    )?;
    tick_array_upper_loader.load_mut()?.update_tick_state(
        tick_upper_index,
        pool_state.tick_spacing,
        tick_upper_state,
    )?;

    if result.tick_lower_flipped {
        let mut tick_array_lower = tick_array_lower_loader.load_mut()?;
        tick_array_lower.update_initialized_tick_count(false)?;
        if tick_array_lower.initialized_tick_count == 0 {
            pool_state.flip_tick_array_bit(
                tickarray_bitmap_extension,
                tick_array_lower.start_tick_index,
            )?;
        }
    }
    if result.tick_upper_flipped {
        let mut tick_array_upper = tick_array_upper_loader.load_mut()?;
        tick_array_upper.update_initialized_tick_count(false)?;
        if tick_array_upper.initialized_tick_count == 0 {
            pool_state.flip_tick_array_bit(
                tickarray_bitmap_extension,
                tick_array_upper.start_tick_index,
            )?;
        }
    }

    emit!(LiquidityChangeEvent {
        pool_state: pool_state.key(),
        tick: pool_state.tick_current,
        tick_lower: tick_lower_index,
        tick_upper: tick_upper_index,
        liquidity_before: liquidity_before,
        liquidity_after: pool_state.liquidity,
    });

    Ok(result)
}

pub fn collect_rewards<'a, 'b, 'c, 'info>(
    pool_state_loader: &AccountLoader<'info, PoolState>,
    remaining_accounts: &[&'info AccountInfo<'info>],
    token_program: &'b Program<'info, Token>,
    token_program_2022: Option<AccountInfo<'info>>,
    personal_position_state: &mut PersonalPositionState,
    need_reward_mint: bool,
) -> Result<[u64; REWARD_NUM]> {
    let mut reward_amounts: [u64; REWARD_NUM] = [0, 0, 0];
    if !pool_state_loader
        .load()?
        .get_status_by_bit(PoolStatusBitIndex::CollectReward)
    {
        return Ok(reward_amounts);
    }
    let mut reward_group_account_num = 3;
    if !need_reward_mint {
        reward_group_account_num = reward_group_account_num - 1
    }
    check_required_accounts_length(
        pool_state_loader,
        remaining_accounts,
        reward_group_account_num,
    )?;

    let remaining_accounts_len = remaining_accounts.len();
    let mut remaining_accounts = remaining_accounts.iter();
    for i in 0..remaining_accounts_len / reward_group_account_num {
        let reward_token_vault = InterfaceAccount::<token_interface::TokenAccount>::try_from(
            remaining_accounts.next().unwrap(),
        )?;
        let recipient_token_account = InterfaceAccount::<token_interface::TokenAccount>::try_from(
            remaining_accounts.next().unwrap(),
        )?;

        let mut reward_vault_mint: Option<Box<InterfaceAccount<Mint>>> = None;
        if need_reward_mint {
            reward_vault_mint = Some(Box::new(InterfaceAccount::<Mint>::try_from(
                remaining_accounts.next().unwrap(),
            )?));
        }
        require_keys_eq!(reward_token_vault.mint, recipient_token_account.mint);
        require_keys_eq!(
            reward_token_vault.key(),
            pool_state_loader.load_mut()?.reward_infos[i].token_vault
        );

        let reward_amount_owed = personal_position_state.reward_infos[i].reward_amount_owed;
        if reward_amount_owed == 0 {
            continue;
        }
        pool_state_loader
            .load()?
            .check_unclaimed_reward(i, reward_amount_owed)?;

        let transfer_amount = if reward_amount_owed > reward_token_vault.amount {
            reward_token_vault.amount
        } else {
            reward_amount_owed
        };

        if transfer_amount > 0 {
            msg!(
                "collect reward index: {}, transfer_amount: {}, reward_amount_owed:{} ",
                i,
                transfer_amount,
                reward_amount_owed
            );
            personal_position_state.reward_infos[i].reward_amount_owed =
                reward_amount_owed.checked_sub(transfer_amount).unwrap();
            pool_state_loader
                .load_mut()?
                .add_reward_clamed(i, transfer_amount)?;

            transfer_from_pool_vault_to_user(
                &pool_state_loader,
                &reward_token_vault.to_account_info(),
                &recipient_token_account.to_account_info(),
                reward_vault_mint.clone(),
                &token_program,
                token_program_2022.clone(),
                transfer_amount,
            )?;
        }
        reward_amounts[i] = transfer_amount
    }

    Ok(reward_amounts)
}

fn check_required_accounts_length(
    pool_state_loader: &AccountLoader<PoolState>,
    remaining_accounts: &[&AccountInfo],
    reward_group_account_num: usize,
) -> Result<()> {
    let pool_state = pool_state_loader.load()?;
    let mut valid_reward_count = 0;
    for item in pool_state.reward_infos {
        if item.initialized() {
            valid_reward_count = valid_reward_count + 1;
        }
    }
    let remaining_accounts_len = remaining_accounts.len();
    if remaining_accounts_len != valid_reward_count * reward_group_account_num {
        return err!(ErrorCode::InvalidRewardInputAccountNumber);
    }
    Ok(())
}

pub fn check_unclaimed_fees_and_vault(
    pool_state_loader: &AccountLoader<PoolState>,
    token_vault_0: &AccountInfo,
    token_vault_1: &AccountInfo,
) -> Result<()> {
    let token_vault_0_amount = spl_token_2022::extension::StateWithExtensions::<
        spl_token_2022::state::Account,
    >::unpack(token_vault_0.try_borrow_data()?.deref())?
    .base
    .amount;

    let token_vault_1_amount = spl_token_2022::extension::StateWithExtensions::<
        spl_token_2022::state::Account,
    >::unpack(token_vault_1.try_borrow_data()?.deref())?
    .base
    .amount;

    let pool_state = &mut pool_state_loader.load_mut()?;

    let unclaimed_fee_token_0 = pool_state
        .total_fees_token_0
        .checked_sub(pool_state.total_fees_claimed_token_0)
        .unwrap();
    let unclaimed_fee_token_1 = pool_state
        .total_fees_token_1
        .checked_sub(pool_state.total_fees_claimed_token_1)
        .unwrap();

    if (unclaimed_fee_token_0 >= token_vault_0_amount && token_vault_0_amount != 0)
        || (unclaimed_fee_token_1 >= token_vault_1_amount && token_vault_1_amount != 0)
    {
        pool_state.set_status_by_bit(PoolStatusBitIndex::CollectFee, PoolStatusBitFlag::Disable);
    }
    Ok(())
}


// ========== states/pool.rs ==========
use crate::error::ErrorCode;
use crate::libraries::{
    big_num::{U1024, U128, U256},
    check_current_tick_array_is_initialized, fixed_point_64,
    full_math::MulDiv,
    tick_array_bit_map, tick_math,
};
use crate::states::*;
use crate::util::get_recent_epoch;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_option::COption;
use anchor_spl::token_interface::Mint;
#[cfg(feature = "enable-log")]
use std::convert::identity;
use std::ops::{BitAnd, BitOr, BitXor};

/// Seed to derive account address and signature
pub const POOL_SEED: &str = "pool";
pub const POOL_VAULT_SEED: &str = "pool_vault";
pub const POOL_REWARD_VAULT_SEED: &str = "pool_reward_vault";
pub const POOL_TICK_ARRAY_BITMAP_SEED: &str = "pool_tick_array_bitmap_extension";
// Number of rewards Token
pub const REWARD_NUM: usize = 3;

#[cfg(feature = "paramset")]
pub mod reward_period_limit {
    pub const MIN_REWARD_PERIOD: u64 = 1 * 60 * 60;
    pub const MAX_REWARD_PERIOD: u64 = 2 * 60 * 60;
    pub const INCREASE_EMISSIONES_PERIOD: u64 = 30 * 60;
}
#[cfg(not(feature = "paramset"))]
pub mod reward_period_limit {
    pub const MIN_REWARD_PERIOD: u64 = 7 * 24 * 60 * 60;
    pub const MAX_REWARD_PERIOD: u64 = 90 * 24 * 60 * 60;
    pub const INCREASE_EMISSIONES_PERIOD: u64 = 72 * 60 * 60;
}

pub enum PoolStatusBitIndex {
    OpenPositionOrIncreaseLiquidity,
    DecreaseLiquidity,
    CollectFee,
    CollectReward,
    Swap,
}

#[derive(PartialEq, Eq)]
pub enum PoolStatusBitFlag {
    Enable,
    Disable,
}

/// The pool state
///
/// PDA of `[POOL_SEED, config, token_mint_0, token_mint_1]`
///
#[account(zero_copy(unsafe))]
#[repr(C, packed)]
#[derive(Default, Debug)]
pub struct PoolState {
    /// Bump to identify PDA
    pub bump: [u8; 1],
    // Which config the pool belongs
    pub amm_config: Pubkey,
    // Pool creator
    pub owner: Pubkey,

    /// Token pair of the pool, where token_mint_0 address < token_mint_1 address
    pub token_mint_0: Pubkey,
    pub token_mint_1: Pubkey,

    /// Token pair vault
    pub token_vault_0: Pubkey,
    pub token_vault_1: Pubkey,

    /// observation account key
    pub observation_key: Pubkey,

    /// mint0 and mint1 decimals
    pub mint_decimals_0: u8,
    pub mint_decimals_1: u8,

    /// The minimum number of ticks between initialized ticks
    pub tick_spacing: u16,
    /// The currently in range liquidity available to the pool.
    pub liquidity: u128,
    /// The current price of the pool as a sqrt(token_1/token_0) Q64.64 value
    pub sqrt_price_x64: u128,
    /// The current tick of the pool, i.e. according to the last tick transition that was run.
    pub tick_current: i32,

    pub padding3: u16,
    pub padding4: u16,

    /// The fee growth as a Q64.64 number, i.e. fees of token_0 and token_1 collected per
    /// unit of liquidity for the entire life of the pool.
    pub fee_growth_global_0_x64: u128,
    pub fee_growth_global_1_x64: u128,

    /// The amounts of token_0 and token_1 that are owed to the protocol.
    pub protocol_fees_token_0: u64,
    pub protocol_fees_token_1: u64,

    /// The amounts in and out of swap token_0 and token_1
    pub swap_in_amount_token_0: u128,
    pub swap_out_amount_token_1: u128,
    pub swap_in_amount_token_1: u128,
    pub swap_out_amount_token_0: u128,

    /// Bitwise representation of the state of the pool
    /// bit0, 1: disable open position and increase liquidity, 0: normal
    /// bit1, 1: disable decrease liquidity, 0: normal
    /// bit2, 1: disable collect fee, 0: normal
    /// bit3, 1: disable collect reward, 0: normal
    /// bit4, 1: disable swap, 0: normal
    pub status: u8,
    /// Leave blank for future use
    pub padding: [u8; 7],

    pub reward_infos: [RewardInfo; REWARD_NUM],

    /// Packed initialized tick array state
    pub tick_array_bitmap: [u64; 16],

    /// except protocol_fee and fund_fee
    pub total_fees_token_0: u64,
    /// except protocol_fee and fund_fee
    pub total_fees_claimed_token_0: u64,
    pub total_fees_token_1: u64,
    pub total_fees_claimed_token_1: u64,

    pub fund_fees_token_0: u64,
    pub fund_fees_token_1: u64,

    // The timestamp allowed for swap in the pool.
    // Note: The open_time is disabled for now.
    pub open_time: u64,
    // account recent update epoch
    pub recent_epoch: u64,

    // Unused bytes for future upgrades.
    pub padding1: [u64; 24],
    pub padding2: [u64; 32],
}

impl PoolState {
    pub const LEN: usize = 8
        + 1
        + 32 * 7
        + 1
        + 1
        + 2
        + 16
        + 16
        + 4
        + 2
        + 2
        + 16
        + 16
        + 8
        + 8
        + 16
        + 16
        + 16
        + 16
        + 8
        + RewardInfo::LEN * REWARD_NUM
        + 8 * 16
        + 512;

    pub fn seeds(&self) -> [&[u8]; 5] {
        [
            &POOL_SEED.as_bytes(),
            self.amm_config.as_ref(),
            self.token_mint_0.as_ref(),
            self.token_mint_1.as_ref(),
            self.bump.as_ref(),
        ]
    }

    pub fn key(&self) -> Pubkey {
        Pubkey::create_program_address(&self.seeds(), &crate::id()).unwrap()
    }

    pub fn initialize(
        &mut self,
        bump: u8,
        sqrt_price_x64: u128,
        open_time: u64,
        tick: i32,
        pool_creator: Pubkey,
        token_vault_0: Pubkey,
        token_vault_1: Pubkey,
        amm_config: &Account<AmmConfig>,
        token_mint_0: &InterfaceAccount<Mint>,
        token_mint_1: &InterfaceAccount<Mint>,
        observation_state_key: Pubkey,
    ) -> Result<()> {
        self.bump = [bump];
        self.amm_config = amm_config.key();
        self.owner = pool_creator.key();
        self.token_mint_0 = token_mint_0.key();
        self.token_mint_1 = token_mint_1.key();
        self.mint_decimals_0 = token_mint_0.decimals;
        self.mint_decimals_1 = token_mint_1.decimals;
        self.token_vault_0 = token_vault_0;
        self.token_vault_1 = token_vault_1;
        self.tick_spacing = amm_config.tick_spacing;
        self.liquidity = 0;
        self.sqrt_price_x64 = sqrt_price_x64;
        self.tick_current = tick;
        self.padding3 = 0;
        self.padding4 = 0;
        self.reward_infos = [RewardInfo::new(pool_creator); REWARD_NUM];
        self.fee_growth_global_0_x64 = 0;
        self.fee_growth_global_1_x64 = 0;
        self.protocol_fees_token_0 = 0;
        self.protocol_fees_token_1 = 0;
        self.swap_in_amount_token_0 = 0;
        self.swap_out_amount_token_1 = 0;
        self.swap_in_amount_token_1 = 0;
        self.swap_out_amount_token_0 = 0;
        self.status = 0;
        self.padding = [0; 7];
        self.tick_array_bitmap = [0; 16];
        self.total_fees_token_0 = 0;
        self.total_fees_claimed_token_0 = 0;
        self.total_fees_token_1 = 0;
        self.total_fees_claimed_token_1 = 0;
        self.fund_fees_token_0 = 0;
        self.fund_fees_token_1 = 0;
        self.open_time = open_time;
        self.recent_epoch = get_recent_epoch()?;
        self.padding1 = [0; 24];
        self.padding2 = [0; 32];
        self.observation_key = observation_state_key;

        Ok(())
    }

    pub fn initialize_reward(
        &mut self,
        open_time: u64,
        end_time: u64,
        reward_per_second_x64: u128,
        token_mint: &Pubkey,
        token_mint_freeze_authority: COption<Pubkey>,
        token_vault: &Pubkey,
        authority: &Pubkey,
        operation_state: &OperationState,
    ) -> Result<()> {
        let reward_infos = self.reward_infos;
        let lowest_index = match reward_infos.iter().position(|r| !r.initialized()) {
            Some(lowest_index) => lowest_index,
            None => return Err(ErrorCode::FullRewardInfo.into()),
        };

        if lowest_index >= REWARD_NUM {
            return Err(ErrorCode::FullRewardInfo.into());
        }

        // one of first two reward token must be a vault token and the last reward token must be controled by the admin
        let reward_mints: Vec<Pubkey> = reward_infos
            .into_iter()
            .map(|item| item.token_mint)
            .collect();
        // check init token_mint is not already in use
        require!(
            !reward_mints.contains(token_mint),
            ErrorCode::RewardTokenAlreadyInUse
        );
        let whitelist_mints = operation_state.whitelist_mints.to_vec();

        if lowest_index == REWARD_NUM - 3 {
            // The current init token is the first.
            // If the first reward is neither token_mint_0 nor token_mint_1, and is not in whitelist_mints, then this token_mint cannot have freeze_authority.
            if *token_mint != self.token_mint_0
                && *token_mint != self.token_mint_1
                && !whitelist_mints.contains(token_mint)
            {
                require!(
                    token_mint_freeze_authority.is_none(),
                    ErrorCode::ExceptRewardMint
                );
            }
        } else if lowest_index == REWARD_NUM - 2 {
            // The current init token is the penult.
            if !reward_mints.contains(&self.token_mint_0)
                && !reward_mints.contains(&self.token_mint_1)
            {
                // If both token_mint_0 and token_mint_1 are not contained in the initialized rewards token,
                // the current init reward token mint must be token_mint_0 or token_mint_1 or one of the whitelist_mints.
                require!(
                    *token_mint == self.token_mint_0
                        || *token_mint == self.token_mint_1
                        || whitelist_mints.contains(token_mint),
                    ErrorCode::ExceptRewardMint
                );
            } else {
                // If token_mint_0 or token_mint_1 is contained in the initialized rewards token,
                // the current init reward token mint is neither token_mint_0 nor token_mint_1, and is not in whitelist_mints, then this token_mint cannot have freeze_authority.
                if *token_mint != self.token_mint_0
                    && *token_mint != self.token_mint_1
                    && !whitelist_mints.contains(token_mint)
                {
                    require!(
                        token_mint_freeze_authority.is_none(),
                        ErrorCode::ExceptRewardMint
                    );
                }
            }
        } else if lowest_index == REWARD_NUM - 1 {
            // the last reward token must be controled by the admin
            require!(
                *authority == crate::admin::ID
                    || operation_state.validate_operation_owner(*authority),
                ErrorCode::NotApproved
            );
        }

        // self.reward_infos[lowest_index].reward_state = RewardState::Initialized as u8;
        self.reward_infos[lowest_index].last_update_time = open_time;
        self.reward_infos[lowest_index].open_time = open_time;
        self.reward_infos[lowest_index].end_time = end_time;
        self.reward_infos[lowest_index].emissions_per_second_x64 = reward_per_second_x64;
        self.reward_infos[lowest_index].token_mint = *token_mint;
        self.reward_infos[lowest_index].token_vault = *token_vault;
        self.reward_infos[lowest_index].authority = *authority;
        #[cfg(feature = "enable-log")]
        msg!(
            "reward_index:{}, reward_infos:{:?}",
            lowest_index,
            self.reward_infos[lowest_index],
        );
        self.recent_epoch = get_recent_epoch()?;
        Ok(())
    }

    // Calculates the next global reward growth variables based on the given timestamp.
    // The provided timestamp must be greater than or equal to the last updated timestamp.
    pub fn update_reward_infos(&mut self, curr_timestamp: u64) -> Result<[RewardInfo; REWARD_NUM]> {
        #[cfg(feature = "enable-log")]
        msg!("current block timestamp:{}", curr_timestamp);

        let mut next_reward_infos = self.reward_infos;

        for i in 0..REWARD_NUM {
            let reward_info = &mut next_reward_infos[i];
            if !reward_info.initialized() {
                continue;
            }
            if curr_timestamp <= reward_info.open_time {
                continue;
            }
            let latest_update_timestamp = curr_timestamp.min(reward_info.end_time);

            if self.liquidity != 0 {
                require_gte!(latest_update_timestamp, reward_info.last_update_time);
                let time_delta = latest_update_timestamp
                    .checked_sub(reward_info.last_update_time)
                    .unwrap();

                let reward_growth_delta = U256::from(time_delta)
                    .mul_div_floor(
                        U256::from(reward_info.emissions_per_second_x64),
                        U256::from(self.liquidity),
                    )
                    .unwrap();

                reward_info.reward_growth_global_x64 = reward_info
                    .reward_growth_global_x64
                    .checked_add(reward_growth_delta.as_u128())
                    .unwrap();

                reward_info.reward_total_emissioned = reward_info
                    .reward_total_emissioned
                    .checked_add(
                        U128::from(time_delta)
                            .mul_div_ceil(
                                U128::from(reward_info.emissions_per_second_x64),
                                U128::from(fixed_point_64::Q64),
                            )
                            .unwrap()
                            .as_u64(),
                    )
                    .unwrap();
                #[cfg(feature = "enable-log")]
                msg!(
                    "reward_index:{},latest_update_timestamp:{},reward_info.reward_last_update_time:{},time_delta:{},reward_emission_per_second_x64:{},reward_growth_delta:{},reward_info.reward_growth_global_x64:{}, reward_info.reward_claim:{}",
                    i,
                    latest_update_timestamp,
                    identity(reward_info.last_update_time),
                    time_delta,
                    identity(reward_info.emissions_per_second_x64),
                    reward_growth_delta,
                    identity(reward_info.reward_growth_global_x64),
                    identity(reward_info.reward_claimed)
                );
            }
            reward_info.last_update_time = latest_update_timestamp;
            // update reward state
            if latest_update_timestamp >= reward_info.open_time
                && latest_update_timestamp < reward_info.end_time
            {
                reward_info.reward_state = RewardState::Opening as u8;
            } else if latest_update_timestamp == next_reward_infos[i].end_time {
                next_reward_infos[i].reward_state = RewardState::Ended as u8;
            }
        }
        self.reward_infos = next_reward_infos;
        #[cfg(feature = "enable-log")]
        msg!("update pool reward info, reward_0_total_emissioned:{}, reward_1_total_emissioned:{}, reward_2_total_emissioned:{}, pool.liquidity:{}",
        identity(self.reward_infos[0].reward_total_emissioned),identity(self.reward_infos[1].reward_total_emissioned),identity(self.reward_infos[2].reward_total_emissioned), identity(self.liquidity));
        self.recent_epoch = get_recent_epoch()?;
        Ok(next_reward_infos)
    }

    pub fn check_unclaimed_reward(&self, index: usize, reward_amount_owed: u64) -> Result<()> {
        assert!(index < REWARD_NUM);
        let unclaimed_reward = self.reward_infos[index]
            .reward_total_emissioned
            .checked_sub(self.reward_infos[index].reward_claimed)
            .unwrap();
        require_gte!(unclaimed_reward, reward_amount_owed);
        Ok(())
    }

    pub fn add_reward_clamed(&mut self, index: usize, amount: u64) -> Result<()> {
        assert!(index < REWARD_NUM);
        self.reward_infos[index].reward_claimed = self.reward_infos[index]
            .reward_claimed
            .checked_add(amount)
            .unwrap();
        Ok(())
    }

    pub fn get_tick_array_offset(&self, tick_array_start_index: i32) -> Result<usize> {
        require!(
            TickArrayState::check_is_valid_start_index(tick_array_start_index, self.tick_spacing),
            ErrorCode::InvalidTickIndex
        );
        let tick_array_offset_in_bitmap = tick_array_start_index
            / TickArrayState::tick_count(self.tick_spacing)
            + tick_array_bit_map::TICK_ARRAY_BITMAP_SIZE;
        Ok(tick_array_offset_in_bitmap as usize)
    }

    fn flip_tick_array_bit_internal(&mut self, tick_array_start_index: i32) -> Result<()> {
        let tick_array_offset_in_bitmap = self.get_tick_array_offset(tick_array_start_index)?;

        let tick_array_bitmap = U1024(self.tick_array_bitmap);
        let mask = U1024::one() << tick_array_offset_in_bitmap.try_into().unwrap();
        self.tick_array_bitmap = tick_array_bitmap.bitxor(mask).0;
        Ok(())
    }

    pub fn flip_tick_array_bit<'c: 'info, 'info>(
        &mut self,
        tickarray_bitmap_extension: Option<&'c AccountInfo<'info>>,
        tick_array_start_index: i32,
    ) -> Result<()> {
        if self.is_overflow_default_tickarray_bitmap(vec![tick_array_start_index]) {
            require_keys_eq!(
                tickarray_bitmap_extension.unwrap().key(),
                TickArrayBitmapExtension::key(self.key())
            );
            AccountLoader::<TickArrayBitmapExtension>::try_from(
                tickarray_bitmap_extension.unwrap(),
            )?
            .load_mut()?
            .flip_tick_array_bit(tick_array_start_index, self.tick_spacing)
        } else {
            self.flip_tick_array_bit_internal(tick_array_start_index)
        }
    }

    pub fn get_first_initialized_tick_array(
        &self,
        tickarray_bitmap_extension: &Option<TickArrayBitmapExtension>,
        zero_for_one: bool,
    ) -> Result<(bool, i32)> {
        let (is_initialized, start_index) =
            if self.is_overflow_default_tickarray_bitmap(vec![self.tick_current]) {
                tickarray_bitmap_extension
                    .unwrap()
                    .check_tick_array_is_initialized(
                        TickArrayState::get_array_start_index(self.tick_current, self.tick_spacing),
                        self.tick_spacing,
                    )?
            } else {
                check_current_tick_array_is_initialized(
                    U1024(self.tick_array_bitmap),
                    self.tick_current,
                    self.tick_spacing.into(),
                )?
            };
        if is_initialized {
            return Ok((true, start_index));
        }
        let next_start_index = self.next_initialized_tick_array_start_index(
            tickarray_bitmap_extension,
            TickArrayState::get_array_start_index(self.tick_current, self.tick_spacing),
            zero_for_one,
        )?;
        require!(
            next_start_index.is_some(),
            ErrorCode::InsufficientLiquidityForDirection
        );
        return Ok((false, next_start_index.unwrap()));
    }

    pub fn next_initialized_tick_array_start_index(
        &self,
        tickarray_bitmap_extension: &Option<TickArrayBitmapExtension>,
        mut last_tick_array_start_index: i32,
        zero_for_one: bool,
    ) -> Result<Option<i32>> {
        last_tick_array_start_index =
            TickArrayState::get_array_start_index(last_tick_array_start_index, self.tick_spacing);

        loop {
            let (is_found, start_index) =
                tick_array_bit_map::next_initialized_tick_array_start_index(
                    U1024(self.tick_array_bitmap),
                    last_tick_array_start_index,
                    self.tick_spacing,
                    zero_for_one,
                );
            if is_found {
                return Ok(Some(start_index));
            }
            last_tick_array_start_index = start_index;

            if tickarray_bitmap_extension.is_none() {
                return err!(ErrorCode::MissingTickArrayBitmapExtensionAccount);
            }

            let (is_found, start_index) = tickarray_bitmap_extension
                .unwrap()
                .next_initialized_tick_array_from_one_bitmap(
                    last_tick_array_start_index,
                    self.tick_spacing,
                    zero_for_one,
                )?;
            if is_found {
                return Ok(Some(start_index));
            }
            last_tick_array_start_index = start_index;

            if last_tick_array_start_index < tick_math::MIN_TICK
                || last_tick_array_start_index > tick_math::MAX_TICK
            {
                return Ok(None);
            }
        }
    }

    pub fn set_status(&mut self, status: u8) {
        self.status = status
    }

    pub fn set_status_by_bit(&mut self, bit: PoolStatusBitIndex, flag: PoolStatusBitFlag) {
        let s = u8::from(1) << (bit as u8);
        if flag == PoolStatusBitFlag::Disable {
            self.status = self.status.bitor(s);
        } else {
            let m = u8::from(255).bitxor(s);
            self.status = self.status.bitand(m);
        }
    }

    /// Get status by bit, if it is `noraml` status, return true
    pub fn get_status_by_bit(&self, bit: PoolStatusBitIndex) -> bool {
        let status = u8::from(1) << (bit as u8);
        self.status.bitand(status) == 0
    }

    pub fn is_overflow_default_tickarray_bitmap(&self, tick_indexs: Vec<i32>) -> bool {
        let (min_tick_array_start_index_boundary, max_tick_array_index_boundary) =
            self.tick_array_start_index_range();
        for tick_index in tick_indexs {
            let tick_array_start_index =
                TickArrayState::get_array_start_index(tick_index, self.tick_spacing);
            if tick_array_start_index >= max_tick_array_index_boundary
                || tick_array_start_index < min_tick_array_start_index_boundary
            {
                return true;
            }
        }
        false
    }

    // the range of tick array start index that default tickarray bitmap can represent
    // if tick_spacing = 1, the result range is [-30720, 30720)
    pub fn tick_array_start_index_range(&self) -> (i32, i32) {
        // the range of ticks that default tickarrary can represent
        let mut max_tick_boundary =
            tick_array_bit_map::max_tick_in_tickarray_bitmap(self.tick_spacing);
        let mut min_tick_boundary = -max_tick_boundary;
        if max_tick_boundary > tick_math::MAX_TICK {
            max_tick_boundary =
                TickArrayState::get_array_start_index(tick_math::MAX_TICK, self.tick_spacing);
            // find the next tick array start index
            max_tick_boundary = max_tick_boundary + TickArrayState::tick_count(self.tick_spacing);
        }
        if min_tick_boundary < tick_math::MIN_TICK {
            min_tick_boundary =
                TickArrayState::get_array_start_index(tick_math::MIN_TICK, self.tick_spacing);
        }
        (min_tick_boundary, max_tick_boundary)
    }
}

#[derive(Copy, Clone, AnchorSerialize, AnchorDeserialize, Debug, PartialEq)]
/// State of reward
pub enum RewardState {
    /// Reward not initialized
    Uninitialized,
    /// Reward initialized, but reward time is not start
    Initialized,
    /// Reward in progress
    Opening,
    /// Reward end, reward time expire or
    Ended,
}

#[zero_copy(unsafe)]
#[repr(C, packed)]
#[derive(Default, Debug, PartialEq, Eq)]
pub struct RewardInfo {
    /// Reward state
    pub reward_state: u8,
    /// Reward open time
    pub open_time: u64,
    /// Reward end time
    pub end_time: u64,
    /// Reward last update time
    pub last_update_time: u64,
    /// Q64.64 number indicates how many tokens per second are earned per unit of liquidity.
    pub emissions_per_second_x64: u128,
    /// The total amount of reward emissioned
    pub reward_total_emissioned: u64,
    /// The total amount of claimed reward
    pub reward_claimed: u64,
    /// Reward token mint.
    pub token_mint: Pubkey,
    /// Reward vault token account.
    pub token_vault: Pubkey,
    /// The owner that has permission to set reward param
    pub authority: Pubkey,
    /// Q64.64 number that tracks the total tokens earned per unit of liquidity since the reward
    /// emissions were turned on.
    pub reward_growth_global_x64: u128,
}

impl RewardInfo {
    pub const LEN: usize = 1 + 8 + 8 + 8 + 16 + 8 + 8 + 32 + 32 + 32 + 16;

    /// Creates a new RewardInfo
    pub fn new(authority: Pubkey) -> Self {
        Self {
            authority,
            ..Default::default()
        }
    }

    /// Returns true if this reward is initialized.
    /// Once initialized, a reward cannot transition back to uninitialized.
    pub fn initialized(&self) -> bool {
        self.token_mint.ne(&Pubkey::default())
    }

    pub fn get_reward_growths(reward_infos: &[RewardInfo; REWARD_NUM]) -> [u128; REWARD_NUM] {
        let mut reward_growths = [0u128; REWARD_NUM];
        for i in 0..REWARD_NUM {
            reward_growths[i] = reward_infos[i].reward_growth_global_x64;
        }
        reward_growths
    }
}

/// Emitted when a pool is created and initialized with a starting price
///
#[event]
#[cfg_attr(feature = "client", derive(Debug))]
pub struct PoolCreatedEvent {
    /// The first token of the pool by address sort order
    pub token_mint_0: Pubkey,

    /// The second token of the pool by address sort order
    pub token_mint_1: Pubkey,

    /// The minimum number of ticks between initialized ticks
    pub tick_spacing: u16,

    /// The address of the created pool
    pub pool_state: Pubkey,

    /// The initial sqrt price of the pool, as a Q64.64
    pub sqrt_price_x64: u128,

    /// The initial tick of the pool, i.e. log base 1.0001 of the starting price of the pool
    pub tick: i32,

    /// Vault of token_0
    pub token_vault_0: Pubkey,
    /// Vault of token_1
    pub token_vault_1: Pubkey,
}

/// Emitted when the collected protocol fees are withdrawn by the factory owner
#[event]
#[cfg_attr(feature = "client", derive(Debug))]
pub struct CollectProtocolFeeEvent {
    /// The pool whose protocol fee is collected
    pub pool_state: Pubkey,

    /// The address that receives the collected token_0 protocol fees
    pub recipient_token_account_0: Pubkey,

    /// The address that receives the collected token_1 protocol fees
    pub recipient_token_account_1: Pubkey,

    /// The amount of token_0 protocol fees that is withdrawn
    pub amount_0: u64,

    /// The amount of token_0 protocol fees that is withdrawn
    pub amount_1: u64,
}

/// Emitted by when a swap is performed for a pool
#[event]
#[cfg_attr(feature = "client", derive(Debug))]
pub struct SwapEvent {
    /// The pool for which token_0 and token_1 were swapped
    pub pool_state: Pubkey,

    /// The address that initiated the swap call, and that received the callback
    pub sender: Pubkey,

    /// The payer token account in zero for one swaps, or the recipient token account
    /// in one for zero swaps
    pub token_account_0: Pubkey,

    /// The payer token account in one for zero swaps, or the recipient token account
    /// in zero for one swaps
    pub token_account_1: Pubkey,

    /// The real delta amount of the token_0 of the pool or user
    pub amount_0: u64,

    /// The transfer fee charged by the withheld_amount of the token_0
    pub transfer_fee_0: u64,

    /// The real delta of the token_1 of the pool or user
    pub amount_1: u64,

    /// The transfer fee charged by the withheld_amount of the token_1
    pub transfer_fee_1: u64,

    /// if true, amount_0 is negtive and amount_1 is positive
    pub zero_for_one: bool,

    /// The sqrt(price) of the pool after the swap, as a Q64.64
    pub sqrt_price_x64: u128,

    /// The liquidity of the pool after the swap
    pub liquidity: u128,

    /// The log base 1.0001 of price of the pool after the swap
    pub tick: i32,
}

/// Emitted pool liquidity change when increase and decrease liquidity
#[event]
#[cfg_attr(feature = "client", derive(Debug))]
pub struct LiquidityChangeEvent {
    /// The pool for swap
    pub pool_state: Pubkey,

    /// The tick of the pool
    pub tick: i32,

    /// The tick lower of position
    pub tick_lower: i32,

    /// The tick lower of position
    pub tick_upper: i32,

    /// The liquidity of the pool before liquidity change
    pub liquidity_before: u128,

    /// The liquidity of the pool after liquidity change
    pub liquidity_after: u128,
}

// /// Emitted when price move in a swap step
// #[event]
// #[cfg_attr(feature = "client", derive(Debug))]
// pub struct PriceChangeEvent {
//     /// The pool for swap
//
//     pub pool_state: Pubkey,

//     /// The tick of the pool before price change
//     pub tick_before: i32,

//     /// The tick of the pool after tprice change
//     pub tick_after: i32,

//     /// The sqrt(price) of the pool before price change, as a Q64.64
//     pub sqrt_price_x64_before: u128,

//     /// The sqrt(price) of the pool after price change, as a Q64.64
//     pub sqrt_price_x64_after: u128,

//     /// The liquidity of the pool before price change
//     pub liquidity_before: u128,

//     /// The liquidity of the pool after price change
//     pub liquidity_after: u128,

//     /// The direction of swap
//     pub zero_for_one: bool,
// }

#[cfg(test)]
pub mod pool_test {
    use super::*;
    use std::cell::RefCell;

    pub fn build_pool(
        tick_current: i32,
        tick_spacing: u16,
        sqrt_price_x64: u128,
        liquidity: u128,
    ) -> RefCell<PoolState> {
        let mut new_pool = PoolState::default();
        new_pool.tick_current = tick_current;
        new_pool.tick_spacing = tick_spacing;
        new_pool.sqrt_price_x64 = sqrt_price_x64;
        new_pool.liquidity = liquidity;
        new_pool.token_mint_0 = Pubkey::new_unique();
        new_pool.token_mint_1 = Pubkey::new_unique();
        new_pool.amm_config = Pubkey::new_unique();
        // let mut random = rand::random<u128>();
        new_pool.fee_growth_global_0_x64 = rand::random::<u128>();
        new_pool.fee_growth_global_1_x64 = rand::random::<u128>();
        new_pool.bump = [Pubkey::find_program_address(
            &[
                &POOL_SEED.as_bytes(),
                new_pool.amm_config.as_ref(),
                new_pool.token_mint_0.as_ref(),
                new_pool.token_mint_1.as_ref(),
            ],
            &crate::id(),
        )
        .1];
        RefCell::new(new_pool)
    }

    mod tick_array_bitmap_test {

        use super::*;

        #[test]
        fn get_arrary_start_index_negative() {
            let mut pool_state = PoolState::default();
            pool_state.tick_spacing = 10;
            pool_state.flip_tick_array_bit(None, -600).unwrap();
            assert!(U1024(pool_state.tick_array_bitmap).bit(511) == true);

            pool_state.flip_tick_array_bit(None, -1200).unwrap();
            assert!(U1024(pool_state.tick_array_bitmap).bit(510) == true);

            pool_state.flip_tick_array_bit(None, -1800).unwrap();
            assert!(U1024(pool_state.tick_array_bitmap).bit(509) == true);

            pool_state.flip_tick_array_bit(None, -38400).unwrap();
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(-38400).unwrap())
                    == true
            );
            pool_state.flip_tick_array_bit(None, -39000).unwrap();
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(-39000).unwrap())
                    == true
            );
            pool_state.flip_tick_array_bit(None, -307200).unwrap();
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(-307200).unwrap())
                    == true
            );
        }

        #[test]
        fn get_arrary_start_index_positive() {
            let mut pool_state = PoolState::default();
            pool_state.tick_spacing = 10;
            pool_state.flip_tick_array_bit(None, 0).unwrap();
            assert!(pool_state.get_tick_array_offset(0).unwrap() == 512);
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(0).unwrap())
                    == true
            );

            pool_state.flip_tick_array_bit(None, 600).unwrap();
            assert!(pool_state.get_tick_array_offset(600).unwrap() == 513);
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(600).unwrap())
                    == true
            );

            pool_state.flip_tick_array_bit(None, 1200).unwrap();
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(1200).unwrap())
                    == true
            );

            pool_state.flip_tick_array_bit(None, 38400).unwrap();
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(38400).unwrap())
                    == true
            );

            pool_state.flip_tick_array_bit(None, 306600).unwrap();
            assert!(pool_state.get_tick_array_offset(306600).unwrap() == 1023);
            assert!(
                U1024(pool_state.tick_array_bitmap)
                    .bit(pool_state.get_tick_array_offset(306600).unwrap())
                    == true
            );
        }

        #[test]
        fn default_tick_array_start_index_range_test() {
            let mut pool_state = PoolState::default();
            pool_state.tick_spacing = 60;
            // -443580 is the min tick can use to open a position when tick_spacing is 60 due to MIN_TICK is -443636
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![-443580]) == false);
            // 443580 is the min tick can use to open a position when tick_spacing is 60 due to MAX_TICK is 443636
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![443580]) == false);

            pool_state.tick_spacing = 10;
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![-307200]) == false);
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![-307201]) == true);
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![307200]) == true);
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![307199]) == false);

            pool_state.tick_spacing = 1;
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![-30720]) == false);
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![-30721]) == true);
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![30720]) == true);
            assert!(pool_state.is_overflow_default_tickarray_bitmap(vec![30719]) == false);
        }
    }

    mod pool_status_test {
        use super::*;

        #[test]
        fn get_set_status_by_bit() {
            let mut pool_state = PoolState::default();
            pool_state.set_status(17); // 00010001
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::Swap),
                false
            );
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::OpenPositionOrIncreaseLiquidity),
                false
            );
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::DecreaseLiquidity),
                true
            );
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::CollectFee),
                true
            );
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::CollectReward),
                true
            );

            // disable -> disable, nothing to change
            pool_state.set_status_by_bit(PoolStatusBitIndex::Swap, PoolStatusBitFlag::Disable);
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::Swap),
                false
            );

            // disable -> enable
            pool_state.set_status_by_bit(PoolStatusBitIndex::Swap, PoolStatusBitFlag::Enable);
            assert_eq!(pool_state.get_status_by_bit(PoolStatusBitIndex::Swap), true);

            // enable -> enable, nothing to change
            pool_state.set_status_by_bit(
                PoolStatusBitIndex::DecreaseLiquidity,
                PoolStatusBitFlag::Enable,
            );
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::DecreaseLiquidity),
                true
            );
            // enable -> disable
            pool_state.set_status_by_bit(
                PoolStatusBitIndex::DecreaseLiquidity,
                PoolStatusBitFlag::Disable,
            );
            assert_eq!(
                pool_state.get_status_by_bit(PoolStatusBitIndex::DecreaseLiquidity),
                false
            );
        }
    }

    mod update_reward_infos_test {
        use super::*;
        use anchor_lang::prelude::Pubkey;
        use std::convert::identity;
        use std::str::FromStr;

        #[test]
        fn reward_info_test() {
            let pool_state = &mut PoolState::default();
            let operation_state = OperationState {
                bump: 0,
                operation_owners: [Pubkey::default(); OPERATION_SIZE_USIZE],
                whitelist_mints: [Pubkey::default(); WHITE_MINT_SIZE_USIZE],
            };
            pool_state
                .initialize_reward(
                    1665982800,
                    1666069200,
                    10,
                    &Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap(),
                    COption::None,
                    &Pubkey::default(),
                    &Pubkey::default(),
                    &operation_state,
                )
                .unwrap();

            // before start time, nothing to update
            let mut updated_reward_infos = pool_state.update_reward_infos(1665982700).unwrap();
            assert_eq!(updated_reward_infos[0], pool_state.reward_infos[0]);

            // pool liquidity is 0
            updated_reward_infos = pool_state.update_reward_infos(1665982900).unwrap();
            assert_eq!(
                identity(updated_reward_infos[0].reward_growth_global_x64),
                0
            );

            pool_state.liquidity = 100;
            updated_reward_infos = pool_state.update_reward_infos(1665983000).unwrap();
            assert_eq!(
                identity(updated_reward_infos[0].last_update_time),
                1665983000
            );
            assert_eq!(
                identity(updated_reward_infos[0].reward_growth_global_x64),
                10
            );

            // curr_timestamp grater than reward end time
            updated_reward_infos = pool_state.update_reward_infos(1666069300).unwrap();
            assert_eq!(
                identity(updated_reward_infos[0].last_update_time),
                1666069200
            );
        }
    }

    mod use_tickarray_bitmap_extension_test {

        use std::ops::Deref;

        use super::*;

        use crate::tick_array_bitmap_extension_test::{
            build_tick_array_bitmap_extension_info, BuildExtensionAccountInfo,
        };

        pub fn pool_flip_tick_array_bit_helper<'c: 'info, 'info>(
            pool_state: &mut PoolState,
            tickarray_bitmap_extension: Option<&'c AccountInfo<'info>>,
            init_tick_array_start_indexs: Vec<i32>,
        ) {
            for start_index in init_tick_array_start_indexs {
                pool_state
                    .flip_tick_array_bit(tickarray_bitmap_extension, start_index)
                    .unwrap();
            }
        }

        #[test]
        fn get_first_initialized_tick_array_test() {
            let tick_spacing = 1;
            let tick_current = tick_spacing * TICK_ARRAY_SIZE * 511 - 1;

            let pool_state_refcel = build_pool(
                tick_current,
                tick_spacing.try_into().unwrap(),
                tick_math::get_sqrt_price_at_tick(tick_current).unwrap(),
                0,
            );

            let mut pool_state = pool_state_refcel.borrow_mut();

            let param: &mut BuildExtensionAccountInfo = &mut BuildExtensionAccountInfo::default();
            param.key = Pubkey::find_program_address(
                &[
                    POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
                    pool_state.key().as_ref(),
                ],
                &crate::id(),
            )
            .0;
            let tick_array_bitmap_extension_info: AccountInfo<'_> =
                build_tick_array_bitmap_extension_info(param);

            pool_flip_tick_array_bit_helper(
                &mut pool_state,
                Some(&tick_array_bitmap_extension_info),
                vec![
                    -tick_spacing * TICK_ARRAY_SIZE * 513, // tick in extension
                    tick_spacing * TICK_ARRAY_SIZE * 511,
                    tick_spacing * TICK_ARRAY_SIZE * 512, // tick in extension
                ],
            );

            let tick_array_bitmap_extension = Some(
                *AccountLoader::<TickArrayBitmapExtension>::try_from(
                    &tick_array_bitmap_extension_info,
                )
                .unwrap()
                .load()
                .unwrap()
                .deref(),
            );

            let (is_first_initilzied, start_index) = pool_state
                .get_first_initialized_tick_array(&tick_array_bitmap_extension, true)
                .unwrap();
            assert!(is_first_initilzied == false);
            assert!(start_index == -tick_spacing * TICK_ARRAY_SIZE * 513);

            let (is_first_initilzied, start_index) = pool_state
                .get_first_initialized_tick_array(&tick_array_bitmap_extension, false)
                .unwrap();
            assert!(is_first_initilzied == false);
            assert!(start_index == tick_spacing * TICK_ARRAY_SIZE * 511);

            pool_state.tick_current = tick_spacing * TICK_ARRAY_SIZE * 511;
            let (is_first_initilzied, start_index) = pool_state
                .get_first_initialized_tick_array(&tick_array_bitmap_extension, true)
                .unwrap();
            assert!(is_first_initilzied == true);
            assert!(start_index == tick_spacing * TICK_ARRAY_SIZE * 511);

            pool_state.tick_current = tick_spacing * TICK_ARRAY_SIZE * 512;
            let (is_first_initilzied, start_index) = pool_state
                .get_first_initialized_tick_array(&tick_array_bitmap_extension, true)
                .unwrap();
            assert!(is_first_initilzied == true);
            assert!(start_index == tick_spacing * TICK_ARRAY_SIZE * 512);
        }

        mod next_initialized_tick_array_start_index_test {

            use super::*;
            #[test]
            fn from_pool_bitmap_to_extension_negative_bitmap() {
                let tick_spacing = 1;
                let tick_current = tick_spacing * TICK_ARRAY_SIZE * 511;

                let pool_state_refcel = build_pool(
                    tick_current,
                    tick_spacing.try_into().unwrap(),
                    tick_math::get_sqrt_price_at_tick(tick_current).unwrap(),
                    0,
                );

                let mut pool_state = pool_state_refcel.borrow_mut();

                let param: &mut BuildExtensionAccountInfo =
                    &mut BuildExtensionAccountInfo::default();
                param.key = Pubkey::find_program_address(
                    &[
                        POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
                        pool_state.key().as_ref(),
                    ],
                    &crate::id(),
                )
                .0;

                let tick_array_bitmap_extension_info: AccountInfo<'_> =
                    build_tick_array_bitmap_extension_info(param);

                pool_flip_tick_array_bit_helper(
                    &mut pool_state,
                    Some(&tick_array_bitmap_extension_info),
                    vec![
                        -tick_spacing * TICK_ARRAY_SIZE * 7394, // max negative tick array start index boundary in extension
                        -tick_spacing * TICK_ARRAY_SIZE * 1000, // tick in extension
                        -tick_spacing * TICK_ARRAY_SIZE * 513,  // tick in extension
                        tick_spacing * TICK_ARRAY_SIZE * 510,   // tick in pool bitmap
                    ],
                );

                let tick_array_bitmap_extension = Some(
                    *AccountLoader::<TickArrayBitmapExtension>::try_from(
                        &tick_array_bitmap_extension_info,
                    )
                    .unwrap()
                    .load()
                    .unwrap()
                    .deref(),
                );

                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        true,
                    )
                    .unwrap();
                assert_eq!(start_index.unwrap(), tick_spacing * TICK_ARRAY_SIZE * 510);

                pool_state.tick_current = tick_spacing * TICK_ARRAY_SIZE * 510;
                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        true,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == -tick_spacing * TICK_ARRAY_SIZE * 513);

                pool_state.tick_current = -tick_spacing * TICK_ARRAY_SIZE * 513;
                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        true,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == -tick_spacing * TICK_ARRAY_SIZE * 1000);

                pool_state.tick_current = -tick_spacing * TICK_ARRAY_SIZE * 7393;
                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        true,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == -tick_spacing * TICK_ARRAY_SIZE * 7394);

                pool_state.tick_current = -tick_spacing * TICK_ARRAY_SIZE * 7394;
                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        true,
                    )
                    .unwrap();
                assert!(start_index.is_none() == true);
            }

            #[test]
            fn from_pool_bitmap_to_extension_positive_bitmap() {
                let tick_spacing = 1;
                let tick_current = 0;

                let pool_state_refcel = build_pool(
                    tick_current,
                    tick_spacing.try_into().unwrap(),
                    tick_math::get_sqrt_price_at_tick(tick_current).unwrap(),
                    0,
                );

                let mut pool_state = pool_state_refcel.borrow_mut();

                let param: &mut BuildExtensionAccountInfo =
                    &mut BuildExtensionAccountInfo::default();
                param.key = Pubkey::find_program_address(
                    &[
                        POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
                        pool_state.key().as_ref(),
                    ],
                    &crate::id(),
                )
                .0;
                let tick_array_bitmap_extension_info: AccountInfo<'_> =
                    build_tick_array_bitmap_extension_info(param);

                pool_flip_tick_array_bit_helper(
                    &mut pool_state,
                    Some(&tick_array_bitmap_extension_info),
                    vec![
                        tick_spacing * TICK_ARRAY_SIZE * 510,  // tick in pool bitmap
                        tick_spacing * TICK_ARRAY_SIZE * 511,  // tick in pool bitmap
                        tick_spacing * TICK_ARRAY_SIZE * 512,  // tick in extension boundary
                        tick_spacing * TICK_ARRAY_SIZE * 7393, // max positvie tick array start index boundary in extension
                    ],
                );

                let tick_array_bitmap_extension = Some(
                    *AccountLoader::<TickArrayBitmapExtension>::try_from(
                        &tick_array_bitmap_extension_info,
                    )
                    .unwrap()
                    .load()
                    .unwrap()
                    .deref(),
                );

                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        false,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == tick_spacing * TICK_ARRAY_SIZE * 510);

                pool_state.tick_current = tick_spacing * TICK_ARRAY_SIZE * 510;
                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        false,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == tick_spacing * TICK_ARRAY_SIZE * 511);

                pool_state.tick_current = tick_spacing * TICK_ARRAY_SIZE * 511;
                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        false,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == tick_spacing * TICK_ARRAY_SIZE * 512);

                pool_state.tick_current = tick_spacing * TICK_ARRAY_SIZE * 7393;
                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        false,
                    )
                    .unwrap();
                assert!(start_index.is_none() == true);
            }

            #[test]
            fn from_extension_negative_bitmap_to_extension_positive_bitmap() {
                let tick_spacing = 1;
                let tick_current = -tick_spacing * TICK_ARRAY_SIZE * 999;

                let pool_state_refcel = build_pool(
                    tick_current,
                    tick_spacing.try_into().unwrap(),
                    tick_math::get_sqrt_price_at_tick(tick_current).unwrap(),
                    0,
                );

                let mut pool_state = pool_state_refcel.borrow_mut();

                let param: &mut BuildExtensionAccountInfo =
                    &mut BuildExtensionAccountInfo::default();
                param.key = Pubkey::find_program_address(
                    &[
                        POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
                        pool_state.key().as_ref(),
                    ],
                    &crate::id(),
                )
                .0;

                let tick_array_bitmap_extension_info: AccountInfo<'_> =
                    build_tick_array_bitmap_extension_info(param);

                pool_flip_tick_array_bit_helper(
                    &mut pool_state,
                    Some(&tick_array_bitmap_extension_info),
                    vec![
                        -tick_spacing * TICK_ARRAY_SIZE * 1000, // tick in extension
                        tick_spacing * TICK_ARRAY_SIZE * 512,   // tick in extension boundary
                        tick_spacing * TICK_ARRAY_SIZE * 1000,  // tick in extension
                    ],
                );

                let tick_array_bitmap_extension = Some(
                    *AccountLoader::<TickArrayBitmapExtension>::try_from(
                        &tick_array_bitmap_extension_info,
                    )
                    .unwrap()
                    .load()
                    .unwrap()
                    .deref(),
                );

                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        false,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == tick_spacing * TICK_ARRAY_SIZE * 512);
            }

            #[test]
            fn from_extension_positive_bitmap_to_extension_negative_bitmap() {
                let tick_spacing = 1;
                let tick_current = tick_spacing * TICK_ARRAY_SIZE * 999;

                let pool_state_refcel = build_pool(
                    tick_current,
                    tick_spacing.try_into().unwrap(),
                    tick_math::get_sqrt_price_at_tick(tick_current).unwrap(),
                    0,
                );

                let mut pool_state = pool_state_refcel.borrow_mut();

                let param: &mut BuildExtensionAccountInfo =
                    &mut BuildExtensionAccountInfo::default();
                param.key = Pubkey::find_program_address(
                    &[
                        POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
                        pool_state.key().as_ref(),
                    ],
                    &crate::id(),
                )
                .0;
                let tick_array_bitmap_extension_info: AccountInfo<'_> =
                    build_tick_array_bitmap_extension_info(param);

                pool_flip_tick_array_bit_helper(
                    &mut pool_state,
                    Some(&tick_array_bitmap_extension_info),
                    vec![
                        -tick_spacing * TICK_ARRAY_SIZE * 1000, // tick in extension
                        -tick_spacing * TICK_ARRAY_SIZE * 513,  // tick in extension
                        tick_spacing * TICK_ARRAY_SIZE * 1000,  // tick in extension
                    ],
                );

                let tick_array_bitmap_extension = Some(
                    *AccountLoader::<TickArrayBitmapExtension>::try_from(
                        &tick_array_bitmap_extension_info,
                    )
                    .unwrap()
                    .load()
                    .unwrap()
                    .deref(),
                );

                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        true,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == -tick_spacing * TICK_ARRAY_SIZE * 513);
            }

            #[test]
            fn no_initialized_tick_array() {
                let mut pool_state = PoolState::default();
                pool_state.tick_spacing = 1;
                pool_state.tick_current = 0;

                let param: &mut BuildExtensionAccountInfo =
                    &mut BuildExtensionAccountInfo::default();
                let tick_array_bitmap_extension_info: AccountInfo<'_> =
                    build_tick_array_bitmap_extension_info(param);

                pool_flip_tick_array_bit_helper(
                    &mut pool_state,
                    Some(&tick_array_bitmap_extension_info),
                    vec![],
                );

                let tick_array_bitmap_extension = Some(
                    *AccountLoader::<TickArrayBitmapExtension>::try_from(
                        &tick_array_bitmap_extension_info,
                    )
                    .unwrap()
                    .load()
                    .unwrap()
                    .deref(),
                );

                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        true,
                    )
                    .unwrap();
                assert!(start_index.is_none());

                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        pool_state.tick_current,
                        false,
                    )
                    .unwrap();
                assert!(start_index.is_none());
            }

            #[test]
            fn min_tick_max_tick_initialized_test() {
                let tick_spacing = 1;
                let tick_current = 0;

                let pool_state_refcel = build_pool(
                    tick_current,
                    tick_spacing.try_into().unwrap(),
                    tick_math::get_sqrt_price_at_tick(tick_current).unwrap(),
                    0,
                );

                let mut pool_state = pool_state_refcel.borrow_mut();

                let param: &mut BuildExtensionAccountInfo =
                    &mut BuildExtensionAccountInfo::default();
                param.key = Pubkey::find_program_address(
                    &[
                        POOL_TICK_ARRAY_BITMAP_SEED.as_bytes(),
                        pool_state.key().as_ref(),
                    ],
                    &crate::id(),
                )
                .0;
                let tick_array_bitmap_extension_info: AccountInfo<'_> =
                    build_tick_array_bitmap_extension_info(param);

                pool_flip_tick_array_bit_helper(
                    &mut pool_state,
                    Some(&tick_array_bitmap_extension_info),
                    vec![
                        -tick_spacing * TICK_ARRAY_SIZE * 7394, // The tickarray where min_tick(-443636) is located
                        tick_spacing * TICK_ARRAY_SIZE * 7393, // The tickarray where max_tick(443636) is located
                    ],
                );

                let tick_array_bitmap_extension = Some(
                    *AccountLoader::<TickArrayBitmapExtension>::try_from(
                        &tick_array_bitmap_extension_info,
                    )
                    .unwrap()
                    .load()
                    .unwrap()
                    .deref(),
                );

                let start_index = pool_state
                    .next_initialized_tick_array_start_index(
                        &tick_array_bitmap_extension,
                        -tick_spacing * TICK_ARRAY_SIZE * 7394,
                        false,
                    )
                    .unwrap();
                assert!(start_index.unwrap() == tick_spacing * TICK_ARRAY_SIZE * 7393);
            }
        }
    }

    mod pool_layout_test {
        use super::*;
        use anchor_lang::Discriminator;
        #[test]
        fn test_pool_layout() {
            let bump: u8 = 0x12;
            let amm_config = Pubkey::new_unique();
            let owner = Pubkey::new_unique();
            let token_mint_0 = Pubkey::new_unique();
            let token_mint_1 = Pubkey::new_unique();
            let token_vault_0 = Pubkey::new_unique();
            let token_vault_1 = Pubkey::new_unique();
            let observation_key = Pubkey::new_unique();
            let mint_decimals_0: u8 = 0x13;
            let mint_decimals_1: u8 = 0x14;
            let tick_spacing: u16 = 0x1516;
            let liquidity: u128 = 0x11002233445566778899aabbccddeeff;
            let sqrt_price_x64: u128 = 0x11220033445566778899aabbccddeeff;
            let tick_current: i32 = 0x12345678;
            let padding3: u16 = 0x1718;
            let padding4: u16 = 0x191a;
            let fee_growth_global_0_x64: u128 = 0x11223300445566778899aabbccddeeff;
            let fee_growth_global_1_x64: u128 = 0x11223344005566778899aabbccddeeff;
            let protocol_fees_token_0: u64 = 0x123456789abcdef0;
            let protocol_fees_token_1: u64 = 0x123456789abcde0f;
            let swap_in_amount_token_0: u128 = 0x11223344550066778899aabbccddeeff;
            let swap_out_amount_token_1: u128 = 0x11223344556600778899aabbccddeeff;
            let swap_in_amount_token_1: u128 = 0x11223344556677008899aabbccddeeff;
            let swap_out_amount_token_0: u128 = 0x11223344556677880099aabbccddeeff;
            let status: u8 = 0x1b;
            let padding: [u8; 7] = [0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
            // RewardInfo
            let reward_state: u8 = 0x1c;
            let open_time: u64 = 0x123456789abc0def;
            let end_time: u64 = 0x123456789ab0cdef;
            let last_update_time: u64 = 0x123456789a0bcdef;
            let emissions_per_second_x64: u128 = 0x11223344556677889900aabbccddeeff;
            let reward_total_emissioned: u64 = 0x1234567890abcdef;
            let reward_claimed: u64 = 0x1234567809abcdef;
            let token_mint = Pubkey::new_unique();
            let token_vault = Pubkey::new_unique();
            let authority = Pubkey::new_unique();
            let reward_growth_global_x64: u128 = 0x112233445566778899aa00bbccddeeff;
            let mut reward_info_data = [0u8; RewardInfo::LEN];

            let mut offset = 0;
            reward_info_data[offset..offset + 1].copy_from_slice(&reward_state.to_le_bytes());
            offset += 1;
            reward_info_data[offset..offset + 8].copy_from_slice(&open_time.to_le_bytes());
            offset += 8;
            reward_info_data[offset..offset + 8].copy_from_slice(&end_time.to_le_bytes());
            offset += 8;
            reward_info_data[offset..offset + 8].copy_from_slice(&last_update_time.to_le_bytes());
            offset += 8;
            reward_info_data[offset..offset + 16]
                .copy_from_slice(&emissions_per_second_x64.to_le_bytes());
            offset += 16;
            reward_info_data[offset..offset + 8]
                .copy_from_slice(&reward_total_emissioned.to_le_bytes());
            offset += 8;
            reward_info_data[offset..offset + 8].copy_from_slice(&reward_claimed.to_le_bytes());
            offset += 8;
            reward_info_data[offset..offset + 32].copy_from_slice(&token_mint.to_bytes());
            offset += 32;
            reward_info_data[offset..offset + 32].copy_from_slice(&token_vault.to_bytes());
            offset += 32;
            reward_info_data[offset..offset + 32].copy_from_slice(&authority.to_bytes());
            offset += 32;
            reward_info_data[offset..offset + 16]
                .copy_from_slice(&reward_growth_global_x64.to_le_bytes());
            let mut reward_info_datas = [0u8; RewardInfo::LEN * REWARD_NUM];
            let mut offset = 0;
            for _ in 0..REWARD_NUM {
                reward_info_datas[offset..offset + RewardInfo::LEN]
                    .copy_from_slice(&reward_info_data);
                offset += RewardInfo::LEN;
            }
            assert_eq!(offset, reward_info_datas.len());
            assert_eq!(
                reward_info_datas.len(),
                core::mem::size_of::<RewardInfo>() * 3
            );

            // tick_array_bitmap
            let mut tick_array_bitmap: [u64; 16] = [0u64; 16];
            let mut tick_array_bitmap_data = [0u8; 8 * 16];
            let mut offset = 0;
            for i in 0..16 {
                tick_array_bitmap[i] = u64::MAX << i;
                tick_array_bitmap_data[offset..offset + 8]
                    .copy_from_slice(&tick_array_bitmap[i].to_le_bytes());
                offset += 8;
            }
            let total_fees_token_0: u64 = 0x1234567809abcdef;
            let total_fees_token_1: u64 = 0x1234567089abcdef;
            let total_fees_claimed_token_0: u64 = 0x1234560789abcdef;
            let total_fees_claimed_token_1: u64 = 0x1234506789abcdef;
            let fund_fees_token_0: u64 = 0x1234056789abcdef;
            let fund_fees_token_1: u64 = 0x1230456789abcdef;
            let pool_open_time: u64 = 0x1203456789abcdef;
            let recent_epoch: u64 = 0x1023456789abcdef;
            let mut padding1: [u64; 24] = [0u64; 24];
            let mut padding1_data = [0u8; 8 * 24];
            let mut offset = 0;
            for i in 0..24 {
                padding1[i] = u64::MAX - i as u64;
                padding1_data[offset..offset + 8].copy_from_slice(&padding1[i].to_le_bytes());
                offset += 8;
            }
            let mut padding2: [u64; 32] = [0u64; 32];
            let mut padding2_data = [0u8; 8 * 32];
            let mut offset = 0;
            for i in 24..(24 + 32) {
                padding2[i - 24] = u64::MAX - i as u64;
                padding2_data[offset..offset + 8].copy_from_slice(&padding2[i - 24].to_le_bytes());
                offset += 8;
            }
            // serialize original data
            let mut pool_data = [0u8; PoolState::LEN];
            let mut offset = 0;
            pool_data[offset..offset + 8].copy_from_slice(&PoolState::DISCRIMINATOR);
            offset += 8;
            pool_data[offset..offset + 1].copy_from_slice(&bump.to_le_bytes());
            offset += 1;
            pool_data[offset..offset + 32].copy_from_slice(&amm_config.to_bytes());
            offset += 32;
            pool_data[offset..offset + 32].copy_from_slice(&owner.to_bytes());
            offset += 32;
            pool_data[offset..offset + 32].copy_from_slice(&token_mint_0.to_bytes());
            offset += 32;
            pool_data[offset..offset + 32].copy_from_slice(&token_mint_1.to_bytes());
            offset += 32;
            pool_data[offset..offset + 32].copy_from_slice(&token_vault_0.to_bytes());
            offset += 32;
            pool_data[offset..offset + 32].copy_from_slice(&token_vault_1.to_bytes());
            offset += 32;
            pool_data[offset..offset + 32].copy_from_slice(&observation_key.to_bytes());
            offset += 32;
            pool_data[offset..offset + 1].copy_from_slice(&mint_decimals_0.to_le_bytes());
            offset += 1;
            pool_data[offset..offset + 1].copy_from_slice(&mint_decimals_1.to_le_bytes());
            offset += 1;
            pool_data[offset..offset + 2].copy_from_slice(&tick_spacing.to_le_bytes());
            offset += 2;
            pool_data[offset..offset + 16].copy_from_slice(&liquidity.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 16].copy_from_slice(&sqrt_price_x64.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 4].copy_from_slice(&tick_current.to_le_bytes());
            offset += 4;
            pool_data[offset..offset + 2].copy_from_slice(&padding3.to_le_bytes());
            offset += 2;
            pool_data[offset..offset + 2].copy_from_slice(&padding4.to_le_bytes());
            offset += 2;
            pool_data[offset..offset + 16].copy_from_slice(&fee_growth_global_0_x64.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 16].copy_from_slice(&fee_growth_global_1_x64.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 8].copy_from_slice(&protocol_fees_token_0.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8].copy_from_slice(&protocol_fees_token_1.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 16].copy_from_slice(&swap_in_amount_token_0.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 16].copy_from_slice(&swap_out_amount_token_1.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 16].copy_from_slice(&swap_in_amount_token_1.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 16].copy_from_slice(&swap_out_amount_token_0.to_le_bytes());
            offset += 16;
            pool_data[offset..offset + 1].copy_from_slice(&status.to_le_bytes());
            offset += 1;
            pool_data[offset..offset + 7].copy_from_slice(&padding);
            offset += 7;
            pool_data[offset..offset + RewardInfo::LEN * REWARD_NUM]
                .copy_from_slice(&reward_info_datas);
            offset += RewardInfo::LEN * REWARD_NUM;
            pool_data[offset..offset + 8 * 16].copy_from_slice(&tick_array_bitmap_data);
            offset += 8 * 16;
            pool_data[offset..offset + 8].copy_from_slice(&total_fees_token_0.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8]
                .copy_from_slice(&total_fees_claimed_token_0.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8].copy_from_slice(&total_fees_token_1.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8]
                .copy_from_slice(&total_fees_claimed_token_1.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8].copy_from_slice(&fund_fees_token_0.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8].copy_from_slice(&fund_fees_token_1.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8].copy_from_slice(&pool_open_time.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8].copy_from_slice(&recent_epoch.to_le_bytes());
            offset += 8;
            pool_data[offset..offset + 8 * 24].copy_from_slice(&padding1_data);
            offset += 8 * 24;
            pool_data[offset..offset + 8 * 32].copy_from_slice(&padding2_data);
            offset += 8 * 32;

            // len check
            assert_eq!(offset, pool_data.len());
            assert_eq!(pool_data.len(), core::mem::size_of::<PoolState>() + 8);

            // deserialize original data
            let unpack_data: &PoolState =
                bytemuck::from_bytes(&pool_data[8..core::mem::size_of::<PoolState>() + 8]);

            // data check
            let unpack_bump = unpack_data.bump[0];
            assert_eq!(unpack_bump, bump);
            let unpack_amm_config = unpack_data.amm_config;
            assert_eq!(unpack_amm_config, amm_config);
            let unpack_owner = unpack_data.owner;
            assert_eq!(unpack_owner, owner);
            let unpack_token_mint_0 = unpack_data.token_mint_0;
            assert_eq!(unpack_token_mint_0, token_mint_0);
            let unpack_token_mint_1 = unpack_data.token_mint_1;
            assert_eq!(unpack_token_mint_1, token_mint_1);
            let unpack_token_vault_0 = unpack_data.token_vault_0;
            assert_eq!(unpack_token_vault_0, token_vault_0);
            let unpack_token_vault_1 = unpack_data.token_vault_1;
            assert_eq!(unpack_token_vault_1, token_vault_1);
            let unpack_observation_key = unpack_data.observation_key;
            assert_eq!(unpack_observation_key, observation_key);
            let unpack_mint_decimals_0 = unpack_data.mint_decimals_0;
            assert_eq!(unpack_mint_decimals_0, mint_decimals_0);
            let unpack_mint_decimals_1 = unpack_data.mint_decimals_1;
            assert_eq!(unpack_mint_decimals_1, mint_decimals_1);
            let unpack_tick_spacing = unpack_data.tick_spacing;
            assert_eq!(unpack_tick_spacing, tick_spacing);
            let unpack_liquidity = unpack_data.liquidity;
            assert_eq!(unpack_liquidity, liquidity);
            let unpack_sqrt_price_x64 = unpack_data.sqrt_price_x64;
            assert_eq!(unpack_sqrt_price_x64, sqrt_price_x64);
            let unpack_tick_current = unpack_data.tick_current;
            assert_eq!(unpack_tick_current, tick_current);
            let unpack_padding3 = unpack_data.padding3;
            assert_eq!(unpack_padding3, padding3);
            let unpack_padding4 = unpack_data.padding4;
            assert_eq!(unpack_padding4, padding4);
            let unpack_fee_growth_global_0_x64 = unpack_data.fee_growth_global_0_x64;
            assert_eq!(unpack_fee_growth_global_0_x64, fee_growth_global_0_x64);
            let unpack_fee_growth_global_1_x64 = unpack_data.fee_growth_global_1_x64;
            assert_eq!(unpack_fee_growth_global_1_x64, fee_growth_global_1_x64);
            let unpack_protocol_fees_token_0 = unpack_data.protocol_fees_token_0;
            assert_eq!(unpack_protocol_fees_token_0, protocol_fees_token_0);
            let unpack_protocol_fees_token_1 = unpack_data.protocol_fees_token_1;
            assert_eq!(unpack_protocol_fees_token_1, protocol_fees_token_1);
            let unpack_swap_in_amount_token_0 = unpack_data.swap_in_amount_token_0;
            assert_eq!(unpack_swap_in_amount_token_0, swap_in_amount_token_0);
            let unpack_swap_out_amount_token_1 = unpack_data.swap_out_amount_token_1;
            assert_eq!(unpack_swap_out_amount_token_1, swap_out_amount_token_1);
            let unpack_swap_in_amount_token_1 = unpack_data.swap_in_amount_token_1;
            assert_eq!(unpack_swap_in_amount_token_1, swap_in_amount_token_1);
            let unpack_swap_out_amount_token_0 = unpack_data.swap_out_amount_token_0;
            assert_eq!(unpack_swap_out_amount_token_0, swap_out_amount_token_0);
            let unpack_status = unpack_data.status;
            assert_eq!(unpack_status, status);
            let unpack_padding = unpack_data.padding;
            assert_eq!(unpack_padding, padding);

            for reward in unpack_data.reward_infos {
                let unpack_reward_state = reward.reward_state;
                assert_eq!(unpack_reward_state, reward_state);
                let unpack_open_time = reward.open_time;
                assert_eq!(unpack_open_time, open_time);
                let unpack_end_time = reward.end_time;
                assert_eq!(unpack_end_time, end_time);
                let unpack_last_update_time = reward.last_update_time;
                assert_eq!(unpack_last_update_time, last_update_time);
                let unpack_emissions_per_second_x64 = reward.emissions_per_second_x64;
                assert_eq!(unpack_emissions_per_second_x64, emissions_per_second_x64);
                let unpack_reward_total_emissioned = reward.reward_total_emissioned;
                assert_eq!(unpack_reward_total_emissioned, reward_total_emissioned);
                let unpack_reward_claimed = reward.reward_claimed;
                assert_eq!(unpack_reward_claimed, reward_claimed);
                let unpack_token_mint = reward.token_mint;
                assert_eq!(unpack_token_mint, token_mint);
                let unpack_token_vault = reward.token_vault;
                assert_eq!(unpack_token_vault, token_vault);
                let unpack_authority = reward.authority;
                assert_eq!(unpack_authority, authority);
                let unpack_reward_growth_global_x64 = reward.reward_growth_global_x64;
                assert_eq!(unpack_reward_growth_global_x64, reward_growth_global_x64);
            }

            let unpack_tick_array_bitmap = unpack_data.tick_array_bitmap;
            assert_eq!(unpack_tick_array_bitmap, tick_array_bitmap);
            let unpack_total_fees_token_0 = unpack_data.total_fees_token_0;
            assert_eq!(unpack_total_fees_token_0, total_fees_token_0);
            let unpack_total_fees_claimed_token_0 = unpack_data.total_fees_claimed_token_0;
            assert_eq!(
                unpack_total_fees_claimed_token_0,
                total_fees_claimed_token_0
            );
            let unpack_total_fees_claimed_token_1 = unpack_data.total_fees_claimed_token_1;
            assert_eq!(
                unpack_total_fees_claimed_token_1,
                total_fees_claimed_token_1
            );
            let unpack_fund_fees_token_0 = unpack_data.fund_fees_token_0;
            assert_eq!(unpack_fund_fees_token_0, fund_fees_token_0);
            let unpack_fund_fees_token_1 = unpack_data.fund_fees_token_1;
            assert_eq!(unpack_fund_fees_token_1, fund_fees_token_1);
            let unpack_open_time = unpack_data.open_time;
            assert_eq!(unpack_open_time, pool_open_time);
            let unpack_recent_epoch = unpack_data.recent_epoch;
            assert_eq!(unpack_recent_epoch, recent_epoch);
            let unpack_padding1 = unpack_data.padding1;
            assert_eq!(unpack_padding1, padding1);
            let unpack_padding2 = unpack_data.padding2;
            assert_eq!(unpack_padding2, padding2);
        }
    }
}
