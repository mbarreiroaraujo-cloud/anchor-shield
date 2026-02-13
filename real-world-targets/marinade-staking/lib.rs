// ========== lib.rs ==========
#![cfg_attr(not(debug_assertions), deny(warnings))]

use anchor_lang::prelude::*;

use error::MarinadeError;

pub mod calc;
pub mod checks;
pub mod error;
pub mod events;
pub mod instructions;
pub mod state;

use instructions::*;

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;
pub use state::State;

declare_id!("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD");

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Marinade Liquid Staking",
    project_url: "https://marinade.finance",
    contacts: "link:https://docs.marinade.finance/marinade-dao,link:https://discord.com/invite/6EtUf4Euu6",
    policy: "https://docs.marinade.finance/marinade-protocol/security",
    preferred_languages: "en",
    source_code: "https://github.com/marinade-finance/liquid-staking-program",
    source_release: "v2.0",
    auditors: "https://docs.marinade.finance/marinade-protocol/security/audits"
}

fn check_context<T>(ctx: &Context<T>) -> Result<()> {
    if !check_id(ctx.program_id) {
        return err!(MarinadeError::InvalidProgramId);
    }
    // make sure there are no extra accounts
    if !ctx.remaining_accounts.is_empty() {
        return err!(MarinadeError::UnexpectedAccount);
    }

    Ok(())
}

//-----------------------------------------------------
#[program]
pub mod marinade_finance {

    use super::*;

    //----------------------------------------------------------------------------
    // Base Instructions
    //----------------------------------------------------------------------------
    // Includes: initialization, contract parameters
    // basic user functions: (liquid)stake, liquid-unstake
    // liq-pool: add-liquidity, remove-liquidity
    // Validator list management
    //----------------------------------------------------------------------------

    pub fn initialize(ctx: Context<Initialize>, data: InitializeData) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts
            .process(data, *ctx.bumps.get("reserve_pda").unwrap())?;
        Ok(())
    }

    pub fn change_authority(
        ctx: Context<ChangeAuthority>,
        data: ChangeAuthorityData,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(data)
    }

    pub fn add_validator(ctx: Context<AddValidator>, score: u32) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(score)
    }

    pub fn remove_validator(
        ctx: Context<RemoveValidator>,
        index: u32,
        validator_vote: Pubkey,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(index, validator_vote)
    }

    pub fn set_validator_score(
        ctx: Context<SetValidatorScore>,
        index: u32,
        validator_vote: Pubkey,
        score: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(index, validator_vote, score)
    }

    pub fn config_validator_system(
        ctx: Context<ConfigValidatorSystem>,
        extra_runs: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(extra_runs)
    }

    // deposit AKA stake, AKA deposit_sol
    pub fn deposit(ctx: Context<Deposit>, lamports: u64) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(lamports)
    }

    // SPL stake pool like
    pub fn deposit_stake_account(
        ctx: Context<DepositStakeAccount>,
        validator_index: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(validator_index)
    }

    pub fn liquid_unstake(ctx: Context<LiquidUnstake>, msol_amount: u64) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(msol_amount)
    }

    pub fn add_liquidity(ctx: Context<AddLiquidity>, lamports: u64) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(lamports)
    }

    pub fn remove_liquidity(ctx: Context<RemoveLiquidity>, tokens: u64) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(tokens)
    }

    pub fn config_lp(ctx: Context<ConfigLp>, params: ConfigLpParams) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(params)
    }

    pub fn config_marinade(
        ctx: Context<ConfigMarinade>,
        params: ConfigMarinadeParams,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(params)
    }

    //-------------------------------------------------------------------------------------
    // Advanced instructions: deposit-stake-account, Delayed-Unstake
    // backend/bot "crank" related functions:
    // * order_unstake (starts stake-account deactivation)
    // * withdraw (delete & withdraw from a deactivated stake-account)
    // * update (compute stake-account rewards & update mSOL price)
    //-------------------------------------------------------------------------------------

    pub fn order_unstake(ctx: Context<OrderUnstake>, msol_amount: u64) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(msol_amount)
    }

    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process()
    }

    pub fn stake_reserve(ctx: Context<StakeReserve>, validator_index: u32) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(validator_index)
    }

    pub fn update_active(
        ctx: Context<UpdateActive>,
        stake_index: u32,
        validator_index: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(stake_index, validator_index)
    }
    pub fn update_deactivated(ctx: Context<UpdateDeactivated>, stake_index: u32) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(stake_index)
    }

    pub fn deactivate_stake(
        ctx: Context<DeactivateStake>,
        stake_index: u32,
        validator_index: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(stake_index, validator_index)
    }

    pub fn emergency_unstake(
        ctx: Context<EmergencyUnstake>,
        stake_index: u32,
        validator_index: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(stake_index, validator_index)
    }

    pub fn partial_unstake(
        ctx: Context<PartialUnstake>,
        stake_index: u32,
        validator_index: u32,
        desired_unstake_amount: u64,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts
            .process(stake_index, validator_index, desired_unstake_amount)
    }

    pub fn merge_stakes(
        ctx: Context<MergeStakes>,
        destination_stake_index: u32,
        source_stake_index: u32,
        validator_index: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts
            .process(destination_stake_index, source_stake_index, validator_index)
    }

    pub fn redelegate(
        ctx: Context<ReDelegate>,
        stake_index: u32,
        source_validator_index: u32,
        dest_validator_index: u32,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts
            .process(stake_index, source_validator_index, dest_validator_index)
    }

    // emergency pauses the contract
    pub fn pause(ctx: Context<EmergencyPause>) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.pause()
    }

    // resumes the contract
    pub fn resume(ctx: Context<EmergencyPause>) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.resume()
    }

    // immediate withdraw of an active stake account - feature can be enabled or disable by the DAO
    pub fn withdraw_stake_account(
        ctx: Context<WithdrawStakeAccount>,
        stake_index: u32,
        validator_index: u32,
        msol_amount: u64,
        beneficiary: Pubkey,
    ) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts
            .process(stake_index, validator_index, msol_amount, beneficiary)
    }

    pub fn realloc_validator_list(ctx: Context<ReallocValidatorList>, capacity: u32) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(capacity)
    }

    pub fn realloc_stake_list(ctx: Context<ReallocStakeList>, capacity: u32) -> Result<()> {
        check_context(&ctx)?;
        ctx.accounts.process(capacity)
    }
}


// ========== state/mod.rs ==========
use crate::{
    calc::{shares_from_value, value_from_shares},
    error::MarinadeError,
    require_lte, ID,
};
use anchor_lang::{
    prelude::*, solana_program::native_token::LAMPORTS_PER_SOL, solana_program::program_pack::Pack,
};
use anchor_spl::token::spl_token;
use std::mem::MaybeUninit;

use self::{liq_pool::LiqPool, stake_system::StakeSystem, validator_system::ValidatorSystem};

pub mod delayed_unstake_ticket;
pub mod fee;
pub mod liq_pool;
pub mod list;
pub mod stake_system;
pub mod validator_system;

pub use fee::Fee;
pub use fee::FeeCents;

#[account]
#[derive(Debug)]
pub struct State {
    pub msol_mint: Pubkey,

    pub admin_authority: Pubkey,

    // Target for withdrawing rent reserve SOLs. Save bot wallet account here
    pub operational_sol_account: Pubkey,
    // treasury - external accounts managed by marinade DAO
    // pub treasury_sol_account: Pubkey,
    pub treasury_msol_account: Pubkey,

    // Bump seeds:
    pub reserve_bump_seed: u8,
    pub msol_mint_authority_bump_seed: u8,

    pub rent_exempt_for_token_acc: u64, // Token-Account For rent exempt

    // fee applied on rewards
    pub reward_fee: Fee,

    pub stake_system: StakeSystem,
    pub validator_system: ValidatorSystem, //includes total_balance = total stake under management

    // sum of all the orders received in this epoch
    // must not be used for stake-unstake amount calculation
    // only for reference
    // epoch_stake_orders: u64,
    // epoch_unstake_orders: u64,
    pub liq_pool: LiqPool,
    pub available_reserve_balance: u64, // reserve_pda.lamports() - self.rent_exempt_for_token_acc. Virtual value (real may be > because of transfers into reserve). Use Update* to align
    pub msol_supply: u64, // Virtual value (may be < because of token burn). Use Update* to align
    // For FE. Don't use it for token amount calculation
    pub msol_price: u64,

    ///count tickets for delayed-unstake
    pub circulating_ticket_count: u64,
    ///total lamports amount of generated and not claimed yet tickets
    pub circulating_ticket_balance: u64,
    pub lent_from_reserve: u64,
    pub min_deposit: u64,
    pub min_withdraw: u64,
    pub staking_sol_cap: u64,

    pub emergency_cooling_down: u64,

    /// emergency pause
    pub pause_authority: Pubkey,
    pub paused: bool,

    // delayed unstake account fee
    // to avoid economic attacks this value should not be zero
    // (this is required because tickets are ready at the end of the epoch)
    // preferred value is one epoch rewards
    pub delayed_unstake_fee: FeeCents,

    // withdraw stake account fee
    // to avoid economic attacks this value should not be zero
    // (this is required because stake accounts are delivered immediately)
    // preferred value is one epoch rewards
    pub withdraw_stake_account_fee: FeeCents,
    pub withdraw_stake_account_enabled: bool,

    // Limit moving stakes from one validator to another
    // by calling redelegate, emergency_unstake and partial_unstake
    // in case of stolen validator manager key or broken delegation strategy bot
    pub last_stake_move_epoch: u64, // epoch of the last stake move action
    pub stake_moved: u64,           // total amount of moved SOL during the epoch #stake_move_epoch
    pub max_stake_moved_per_epoch: Fee, // % of total_lamports_under_control
}

impl State {
    pub const PRICE_DENOMINATOR: u64 = 0x1_0000_0000;
    /// Suffix for reserve account seed
    pub const RESERVE_SEED: &'static [u8] = b"reserve";
    pub const MSOL_MINT_AUTHORITY_SEED: &'static [u8] = b"st_mint";

    // Account seeds for simplification of creation (optional)
    pub const STAKE_LIST_SEED: &'static str = "stake_list";
    pub const VALIDATOR_LIST_SEED: &'static str = "validator_list";

    pub const MAX_REWARD_FEE: Fee = Fee::from_basis_points(1_000); // 10% max reward fee
    pub const MAX_WITHDRAW_ATOM: u64 = LAMPORTS_PER_SOL / 10;

    // Note as of July 2023, observable staking reward per epoch is 0.045%
    // 1.00045 ** 160 - 1 = 0.0746 ~ 7.46 % which is normal APY for July 2023
    // set a max fee to protect users
    pub const MAX_DELAYED_UNSTAKE_FEE: FeeCents = FeeCents::from_bp_cents(2000); // 0.2% max fee
    pub const MAX_WITHDRAW_STAKE_ACCOUNT_FEE: FeeCents = FeeCents::from_bp_cents(2000); // 0.2% max fee

    // min_stake minimum value is MIN_STAKE_MULTIPLIER * rent_exempt_for_token_acc
    pub const MIN_STAKE_LOWER_LIMIT: u64 = LAMPORTS_PER_SOL / 100;

    pub fn serialized_len() -> usize {
        unsafe { MaybeUninit::<Self>::zeroed().assume_init() }
            .try_to_vec()
            .unwrap()
            .len()
            + 8
    }

    pub fn find_msol_mint_authority(state: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[&state.to_bytes()[..32], State::MSOL_MINT_AUTHORITY_SEED],
            &ID,
        )
    }

    pub fn find_reserve_address(state: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[&state.to_bytes()[..32], Self::RESERVE_SEED], &ID)
    }

    pub fn default_stake_list_address(state: &Pubkey) -> Pubkey {
        Pubkey::create_with_seed(state, Self::STAKE_LIST_SEED, &ID).unwrap()
    }

    pub fn default_validator_list_address(state: &Pubkey) -> Pubkey {
        Pubkey::create_with_seed(state, Self::VALIDATOR_LIST_SEED, &ID).unwrap()
    }

    // this fn returns Some(u64) if the treasury account is valid and ready to receive transfers
    // or None if it is not. This fn does not fail on an invalid treasury account, an invalid
    // treasury account configured in State means the protocol does not want to receive fees
    pub fn get_treasury_msol_balance<'info>(
        &self,
        treasury_msol_account: &AccountInfo<'info>,
    ) -> Option<u64> {
        if treasury_msol_account.owner != &spl_token::ID {
            msg!(
                "treasury_msol_account {} is not a token account",
                treasury_msol_account.key
            );
            return None; // Not an error. Admins may decide to reject fee transfers to themselves
        }

        match spl_token::state::Account::unpack(treasury_msol_account.data.borrow().as_ref()) {
            Ok(token_account) => {
                if token_account.mint == self.msol_mint {
                    Some(token_account.amount)
                } else {
                    msg!(
                        "treasury_msol_account {} has wrong mint {}. Expected {}",
                        treasury_msol_account.key,
                        token_account.mint,
                        self.msol_mint
                    );
                    None // Not an error. Admins may decide to reject fee transfers to themselves
                }
            }
            Err(e) => {
                msg!(
                    "treasury_msol_account {} can not be parsed as token account ({})",
                    treasury_msol_account.key,
                    e
                );
                None // Not an error. Admins may decide to reject fee transfers to themselves
            }
        }
    }

    pub fn total_cooling_down(&self) -> u64 {
        self.stake_system.delayed_unstake_cooling_down + self.emergency_cooling_down
    }

    /// total_active_balance + total_cooling_down + available_reserve_balance
    pub fn total_lamports_under_control(&self) -> u64 {
        self.validator_system.total_active_balance
            + self.total_cooling_down()
            + self.available_reserve_balance // reserve_pda.lamports() - self.rent_exempt_for_token_acc
    }

    pub fn check_staking_cap(&self, transfering_lamports: u64) -> Result<()> {
        let result_amount = self.total_lamports_under_control() + transfering_lamports;
        require_lte!(
            result_amount,
            self.staking_sol_cap,
            MarinadeError::StakingIsCapped
        );
        Ok(())
    }

    pub fn total_virtual_staked_lamports(&self) -> u64 {
        // if we get slashed it may be negative but we must use 0 instead
        self.total_lamports_under_control()
            .saturating_sub(self.circulating_ticket_balance) //tickets created -> cooling down lamports or lamports already in reserve and not claimed yet
    }

    /// calculate the amount of msol tokens corresponding to certain lamport amount
    pub fn calc_msol_from_lamports(&self, stake_lamports: u64) -> Result<u64> {
        shares_from_value(
            stake_lamports,
            self.total_virtual_staked_lamports(),
            self.msol_supply,
        )
    }
    /// calculate lamports value from some msol_amount
    /// result_lamports = msol_amount * msol_price
    pub fn msol_to_sol(&self, msol_amount: u64) -> Result<u64> {
        value_from_shares(
            msol_amount,
            self.total_virtual_staked_lamports(),
            self.msol_supply,
        )
    }

    // **i128**: when do staking/unstaking use real reserve balance instead of virtual field
    pub fn stake_delta(&self, reserve_balance: u64) -> i128 {
        // Never try to stake lamports from emergency_cooling_down
        // (we must wait for update-deactivated first to keep SOLs for claiming on reserve)
        // But if we need to unstake without counting emergency_cooling_down and we have emergency cooling down
        // then we can count part of emergency stakes as starting to cooling down delayed unstakes
        // preventing unstake duplication by recalculating stake-delta for negative values

        // OK. Lets get stake_delta without emergency first
        let raw = reserve_balance.saturating_sub(self.rent_exempt_for_token_acc) as i128
            + self.stake_system.delayed_unstake_cooling_down as i128
            - self.circulating_ticket_balance as i128;
        if raw >= 0 {
            // When it >= 0 it is right value to use
            raw
        } else {
            // Otherwise try to recalculate it with emergency
            let with_emergency = raw + self.emergency_cooling_down as i128;
            // And make sure it will not become positive
            with_emergency.min(0)
        }
    }

    pub fn on_transfer_to_reserve(&mut self, amount: u64) {
        self.available_reserve_balance += amount
    }

    pub fn on_transfer_from_reserve(&mut self, amount: u64) {
        self.available_reserve_balance -= amount
    }

    pub fn on_msol_mint(&mut self, amount: u64) {
        self.msol_supply += amount
    }

    pub fn on_msol_burn(&mut self, amount: u64) {
        self.msol_supply -= amount
    }

    pub fn on_stake_moved(&mut self, amount: u64, clock: &Clock) -> Result<()> {
        if clock.epoch != self.last_stake_move_epoch {
            self.last_stake_move_epoch = clock.epoch;
            self.stake_moved = 0;
        }
        self.stake_moved += amount;
        require_lte!(
            self.stake_moved,
            self.max_stake_moved_per_epoch
                .apply(self.total_lamports_under_control()),
            MarinadeError::MovingStakeIsCapped
        );
        Ok(())
    }
}


// ========== state/liq_pool.rs ==========
use crate::{calc::proportional, error::MarinadeError, require_lte, state::Fee, ID};
use anchor_lang::{prelude::*, solana_program::native_token::LAMPORTS_PER_SOL};
use anchor_spl::token::spl_token;

#[derive(Clone, AnchorSerialize, AnchorDeserialize, Debug)]
pub struct LiqPool {
    pub lp_mint: Pubkey,
    pub lp_mint_authority_bump_seed: u8,
    pub sol_leg_bump_seed: u8,
    pub msol_leg_authority_bump_seed: u8,
    pub msol_leg: Pubkey,

    //The next 3 values define the SOL/mSOL Liquidity pool fee curve params
    // We assume this pool is always UNBALANCED, there should be more SOL than mSOL 99% of the time
    ///Liquidity target. If the Liquidity reach this amount, the fee reaches lp_min_discount_fee
    pub lp_liquidity_target: u64, // 10_000 SOL initially
    /// Liquidity pool max fee
    pub lp_max_fee: Fee, //3% initially
    /// SOL/mSOL Liquidity pool min fee
    pub lp_min_fee: Fee, //0.3% initially
    /// Treasury cut
    pub treasury_cut: Fee, //2500 => 25% how much of the Liquid unstake fee goes to treasury_msol_account

    pub lp_supply: u64, // virtual lp token supply. May be > real supply because of burning tokens. Use UpdateLiqPool to align it with real value
    pub lent_from_sol_leg: u64,
    pub liquidity_sol_cap: u64,
}

impl LiqPool {
    pub const LP_MINT_AUTHORITY_SEED: &'static [u8] = b"liq_mint";
    pub const SOL_LEG_SEED: &'static [u8] = b"liq_sol";
    pub const MSOL_LEG_AUTHORITY_SEED: &'static [u8] = b"liq_st_sol_authority";
    pub const MSOL_LEG_SEED: &'static str = "liq_st_sol";
    pub const MAX_FEE: Fee = Fee::from_basis_points(1000); // 10%
    pub const MIN_LIQUIDITY_TARGET: u64 = 50 * LAMPORTS_PER_SOL; // 50 SOL
    pub const MAX_TREASURY_CUT: Fee = Fee::from_basis_points(7500); // 75%

    pub fn find_lp_mint_authority(state: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[&state.to_bytes()[..32], Self::LP_MINT_AUTHORITY_SEED],
            &ID,
        )
    }

    pub fn find_sol_leg_address(state: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[&state.to_bytes()[..32], Self::SOL_LEG_SEED], &ID)
    }

    pub fn find_msol_leg_authority(state: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[&state.to_bytes()[..32], Self::MSOL_LEG_AUTHORITY_SEED],
            &ID,
        )
    }

    pub fn default_msol_leg_address(state: &Pubkey) -> Pubkey {
        Pubkey::create_with_seed(state, Self::MSOL_LEG_SEED, &spl_token::ID).unwrap()
    }

    pub fn delta(&self) -> u32 {
        self.lp_max_fee
            .basis_points
            .saturating_sub(self.lp_min_fee.basis_points)
    }

    ///compute a linear fee based on liquidity amount, it goes from fee(0)=max -> fee(x>=target)=min
    pub fn linear_fee(&self, lamports: u64) -> Fee {
        if lamports >= self.lp_liquidity_target {
            self.lp_min_fee
        } else {
            Fee {
                basis_points: self.lp_max_fee.basis_points
                    - proportional(self.delta() as u64, lamports, self.lp_liquidity_target).unwrap()
                        as u32,
            }
        }
    }

    pub fn on_lp_mint(&mut self, amount: u64) {
        self.lp_supply += amount
    }

    pub fn on_lp_burn(&mut self, amount: u64) {
        self.lp_supply -= amount
    }

    pub fn check_liquidity_cap(
        &self,
        transfering_lamports: u64,
        sol_leg_balance: u64,
    ) -> Result<()> {
        let result_amount = sol_leg_balance + transfering_lamports;
        require_lte!(
            result_amount,
            self.liquidity_sol_cap,
            MarinadeError::LiquidityIsCapped
        );
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.lp_min_fee
            .check()
            .map_err(|e| e.with_source(source!()))?;
        self.lp_max_fee
            .check()
            .map_err(|e| e.with_source(source!()))?;
        self.treasury_cut
            .check()
            .map_err(|e| e.with_source(source!()))?;
        // hard-limit, max liquid unstake-fee of 10%
        require_lte!(
            self.lp_max_fee,
            Self::MAX_FEE,
            MarinadeError::LpMaxFeeIsTooHigh
        );
        require_gte!(
            self.lp_max_fee,
            self.lp_min_fee,
            MarinadeError::LpFeesAreWrongWayRound
        );
        require_gte!(
            self.lp_liquidity_target,
            Self::MIN_LIQUIDITY_TARGET,
            MarinadeError::LiquidityTargetTooLow
        );
        require_lte!(
            self.treasury_cut,
            Self::MAX_TREASURY_CUT,
            MarinadeError::TreasuryCutIsTooHigh
        );

        Ok(())
    }
}


// ========== state/fee.rs ==========
use crate::{error::MarinadeError, require_lte};
use anchor_lang::prelude::*;

use std::fmt::Display;
#[cfg(feature = "no-entrypoint")]
use std::str::FromStr;
//-----------------------------------------------------
#[derive(
    Clone, Copy, Debug, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Fee {
    pub basis_points: u32,
}

impl Display for Fee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // use integer division to avoid including f64 libs
        write!(
            f,
            "{}.{:0>2}%",
            self.basis_points / 100,
            self.basis_points % 100
        )
    }
}

impl Fee {
    pub const MAX_BASIS_POINTS: u32 = 10_000;

    pub const fn from_basis_points(basis_points: u32) -> Self {
        Self { basis_points }
    }

    pub fn check(&self) -> Result<()> {
        require_lte!(
            self.basis_points,
            Self::MAX_BASIS_POINTS,
            MarinadeError::BasisPointsOverflow
        );
        Ok(())
    }

    pub fn apply(&self, lamports: u64) -> u64 {
        // LMT no error possible
        (lamports as u128 * self.basis_points as u128 / Self::MAX_BASIS_POINTS as u128) as u64
    }
}

#[cfg(feature = "no-entrypoint")]
impl TryFrom<f64> for Fee {
    type Error = Error;

    fn try_from(n: f64) -> Result<Self> {
        let basis_points_i = (n * 100.0).floor() as i64; // 4.5% => 450 basis_points
        let basis_points =
            u32::try_from(basis_points_i).map_err(|_| MarinadeError::CalculationFailure)?;
        let fee = Fee::from_basis_points(basis_points);
        fee.check()?;
        Ok(fee)
    }
}

#[cfg(feature = "no-entrypoint")]
impl FromStr for Fee {
    type Err = Error; // TODO: better error

    fn from_str(s: &str) -> Result<Self> {
        f64::try_into(s.parse().map_err(|_| MarinadeError::CalculationFailure)?)
    }
}

/// FeeCents, same as Fee but / 1_000_000 instead of 10_000
/// 1 FeeCent = 0.0001%, 10_000 FeeCent = 1%, 1_000_000 FeeCent = 100%
#[derive(
    Clone, Copy, Debug, Default, AnchorSerialize, AnchorDeserialize, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct FeeCents {
    pub bp_cents: u32,
}

impl Display for FeeCents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // use integer division to avoid including f64 libs
        write!(
            f,
            "{}.{:0>4}%",
            self.bp_cents / 10_000,
            self.bp_cents % 10_000
        )
    }
}

impl FeeCents {
    pub const MAX_BP_CENTS: FeeCents = FeeCents::from_bp_cents(1_000_000); // 100%

    pub const fn from_bp_cents(bp_cents: u32) -> Self {
        Self { bp_cents }
    }

    pub fn check(&self) -> Result<()> {
        require_lte!(
            self,
            &Self::MAX_BP_CENTS,
            MarinadeError::BasisPointCentsOverflow
        );
        Ok(())
    }

    pub fn apply(&self, lamports: u64) -> u64 {
        // LMT no error possible
        (lamports as u128 * self.bp_cents as u128 / Self::MAX_BP_CENTS.bp_cents as u128) as u64
    }
}

#[cfg(feature = "no-entrypoint")]
impl TryFrom<f64> for FeeCents {
    type Error = Error;

    fn try_from(n: f64) -> Result<Self> {
        let bp_cents_i = (n * 10000.0).floor() as i64; // 4.5% => 45000 bp_cents
        let bp_cents = u32::try_from(bp_cents_i).map_err(|_| MarinadeError::CalculationFailure)?;
        let fee = FeeCents::from_bp_cents(bp_cents);
        fee.check()?;
        Ok(fee)
    }
}

#[cfg(feature = "no-entrypoint")]
impl FromStr for FeeCents {
    type Err = Error; // TODO: better error

    fn from_str(s: &str) -> Result<Self> {
        f64::try_into(s.parse().map_err(|_| MarinadeError::CalculationFailure)?)
    }
}


// ========== instructions/user/deposit.rs ==========
use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use anchor_lang::system_program::{transfer, Transfer};
use anchor_spl::token::{
    mint_to, transfer as transfer_tokens, Mint, MintTo, Token, TokenAccount,
    Transfer as TransferTokens,
};

use crate::error::MarinadeError;
use crate::events::user::DepositEvent;
use crate::state::liq_pool::LiqPool;
use crate::{require_lte, State};

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        has_one = msol_mint
    )]
    pub state: Box<Account<'info, State>>,

    #[account(mut)]
    pub msol_mint: Box<Account<'info, Mint>>,

    #[account(
        mut,
        seeds = [
            &state.key().to_bytes(),
            LiqPool::SOL_LEG_SEED
        ],
        bump = state.liq_pool.sol_leg_bump_seed
    )]
    pub liq_pool_sol_leg_pda: SystemAccount<'info>,

    #[account(
        mut,
        address = state.liq_pool.msol_leg
    )]
    pub liq_pool_msol_leg: Box<Account<'info, TokenAccount>>,
    /// CHECK: PDA
    #[account(
        seeds = [
            &state.key().to_bytes(),
            LiqPool::MSOL_LEG_AUTHORITY_SEED
        ],
        bump = state.liq_pool.msol_leg_authority_bump_seed
    )]
    pub liq_pool_msol_leg_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            &state.key().to_bytes(),
            State::RESERVE_SEED
        ],
        bump = state.reserve_bump_seed
    )]
    pub reserve_pda: SystemAccount<'info>,

    #[account(
        mut,
        owner = system_program::ID
    )]
    pub transfer_from: Signer<'info>,

    /// user mSOL Token account to send the mSOL
    #[account(
        mut,
        token::mint = state.msol_mint
    )]
    pub mint_to: Box<Account<'info, TokenAccount>>,

    /// CHECK: PDA
    #[account(
        seeds = [
            &state.key().to_bytes(),
            State::MSOL_MINT_AUTHORITY_SEED
        ],
        bump = state.msol_mint_authority_bump_seed
    )]
    pub msol_mint_authority: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

impl<'info> Deposit<'info> {
    // fn deposit_sol()
    pub fn process(&mut self, lamports: u64) -> Result<()> {
        require!(!self.state.paused, MarinadeError::ProgramIsPaused);

        require_gte!(
            lamports,
            self.state.min_deposit,
            MarinadeError::DepositAmountIsTooLow
        );
        let user_sol_balance = self.transfer_from.lamports();
        require_gte!(
            user_sol_balance,
            lamports,
            MarinadeError::NotEnoughUserFunds
        );

        // store for event log
        let user_msol_balance = self.mint_to.amount;
        let reserve_balance = self.reserve_pda.lamports();
        let sol_leg_balance = self.liq_pool_sol_leg_pda.lamports();

        // impossible to happen check outside bug (msol mint auth is a PDA)
        require_lte!(
            self.msol_mint.supply,
            self.state.msol_supply,
            MarinadeError::UnregisteredMsolMinted
        );

        let total_virtual_staked_lamports = self.state.total_virtual_staked_lamports();
        let msol_supply = self.state.msol_supply;

        //compute how many mSOL to sell/mint for the user, base on how many lamports being deposited
        let user_msol_buy_order = self.state.calc_msol_from_lamports(lamports)?;
        msg!("--- user_m_sol_buy_order {}", user_msol_buy_order);

        //First we try to "sell" mSOL to the user from the LiqPool.
        //The LiqPool needs to get rid of their mSOL because it works better if fully "unbalanced", i.e. with all SOL no mSOL
        //so, if we can, the LiqPool "sells" mSOL to the user (no fee)
        //
        // At max, we can sell all the mSOL in the LiqPool.mSOL_leg
        let msol_leg_balance = self.liq_pool_msol_leg.amount;
        let msol_swapped: u64 = user_msol_buy_order.min(msol_leg_balance);
        msg!("--- swap_m_sol_max {}", msol_swapped);

        //if we can sell from the LiqPool
        let sol_swapped = if msol_swapped > 0 {
            // how much lamports go into the LiqPool?
            let sol_swapped = if user_msol_buy_order == msol_swapped {
                //we are fulfilling 100% the user order
                lamports //100% of the user deposit
            } else {
                // partially filled
                // then it's the lamport value of the tokens we're selling
                self.state.msol_to_sol(msol_swapped)?
            };

            // transfer mSOL to the user

            transfer_tokens(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    TransferTokens {
                        from: self.liq_pool_msol_leg.to_account_info(),
                        to: self.mint_to.to_account_info(),
                        authority: self.liq_pool_msol_leg_authority.to_account_info(),
                    },
                    &[&[
                        &self.state.key().to_bytes(),
                        LiqPool::MSOL_LEG_AUTHORITY_SEED,
                        &[self.state.liq_pool.msol_leg_authority_bump_seed],
                    ]],
                ),
                msol_swapped,
            )?;

            // transfer lamports to the LiqPool
            transfer(
                CpiContext::new(
                    self.system_program.to_account_info(),
                    Transfer {
                        from: self.transfer_from.to_account_info(),
                        to: self.liq_pool_sol_leg_pda.to_account_info(),
                    },
                ),
                sol_swapped,
            )?;

            sol_swapped
            //end of sale from the LiqPool
        } else {
            0
        };

        // check if we have more lamports from the user besides the amount we swapped
        let sol_deposited = lamports - sol_swapped;
        if sol_deposited > 0 {
            self.state.check_staking_cap(sol_deposited)?;

            // transfer sol_deposited to reserve
            transfer(
                CpiContext::new(
                    self.system_program.to_account_info(),
                    Transfer {
                        from: self.transfer_from.to_account_info(),
                        to: self.reserve_pda.to_account_info(),
                    },
                ),
                sol_deposited,
            )?;
            self.state.on_transfer_to_reserve(sol_deposited);
        }

        // compute how much mSOL we own the user besides the amount we already swapped
        let msol_minted = user_msol_buy_order - msol_swapped;
        if msol_minted > 0 {
            msg!("--- msol_to_mint {}", msol_minted);
            mint_to(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    MintTo {
                        mint: self.msol_mint.to_account_info(),
                        to: self.mint_to.to_account_info(),
                        authority: self.msol_mint_authority.to_account_info(),
                    },
                    &[&[
                        &self.state.key().to_bytes(),
                        State::MSOL_MINT_AUTHORITY_SEED,
                        &[self.state.msol_mint_authority_bump_seed],
                    ]],
                ),
                msol_minted,
            )?;
            self.state.on_msol_mint(msol_minted);
        }

        emit!(DepositEvent {
            state: self.state.key(),
            sol_owner: self.transfer_from.key(),
            user_sol_balance,
            user_msol_balance,
            sol_leg_balance,
            msol_leg_balance,
            reserve_balance,
            sol_swapped,
            msol_swapped,
            sol_deposited,
            msol_minted,
            total_virtual_staked_lamports,
            msol_supply
        });

        Ok(())
    }
}


// ========== instructions/user/withdraw_stake_account.rs ==========
use crate::{
    checks::check_token_source_account,
    error::MarinadeError,
    events::user::WithdrawStakeAccountEvent,
    state::{
        stake_system::{StakeList, StakeSystem},
        validator_system::ValidatorList,
    },
    State,
};
use anchor_lang::{
    prelude::*,
    solana_program::{
        program::invoke_signed,
        stake,
        stake::state::{StakeAuthorize, StakeState},
        system_program,
    },
};
use anchor_spl::{
    stake::{Stake, StakeAccount},
    token::{burn, transfer, Burn, Mint, Token, TokenAccount, Transfer},
};

use crate::checks::check_stake_amount_and_validator;

#[derive(Accounts)]
pub struct WithdrawStakeAccount<'info> {
    #[account(
        mut,
        has_one = msol_mint,
        has_one = treasury_msol_account,
    )]
    pub state: Box<Account<'info, State>>,

    #[account(mut)]
    pub msol_mint: Box<Account<'info, Mint>>,

    // Note: new stake account withdraw-auth (owner) & staker-auth will be owner of burn_msol_from
    #[account(
        mut,
        token::mint = msol_mint
    )]
    pub burn_msol_from: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub burn_msol_authority: Signer<'info>,

    /// CHECK: deserialized in code, must be the one in State (State has_one treasury_msol_account)
    #[account(mut)]
    pub treasury_msol_account: UncheckedAccount<'info>,

    #[account(
        mut,
        address = state.validator_system.validator_list.account,
    )]
    pub validator_list: Account<'info, ValidatorList>,

    #[account(
        mut,
        address = state.stake_system.stake_list.account,
    )]
    pub stake_list: Account<'info, StakeList>,
    /// CHECK: PDA
    #[account(
        seeds = [
            &state.key().to_bytes(),
            StakeSystem::STAKE_WITHDRAW_SEED
        ],
        bump = state.stake_system.stake_withdraw_bump_seed
    )]
    pub stake_withdraw_authority: UncheckedAccount<'info>,
    /// CHECK: PDA
    #[account(
        seeds = [
            &state.key().to_bytes(),
            StakeSystem::STAKE_DEPOSIT_SEED
        ],
        bump = state.stake_system.stake_deposit_bump_seed
    )]
    pub stake_deposit_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub stake_account: Box<Account<'info, StakeAccount>>,

    #[account(
        init,
        payer = split_stake_rent_payer,
        space = std::mem::size_of::<StakeState>(),
        owner = stake::program::ID,
    )]
    pub split_stake_account: Account<'info, StakeAccount>,
    #[account(
        mut,
        owner = system_program::ID
    )]
    pub split_stake_rent_payer: Signer<'info>,

    pub clock: Sysvar<'info, Clock>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub stake_program: Program<'info, Stake>,
}

impl<'info> WithdrawStakeAccount<'info> {
    pub fn process(
        &mut self,
        stake_index: u32,
        validator_index: u32,
        msol_amount: u64,
        beneficiary: Pubkey,
    ) -> Result<()> {
        require!(!self.state.paused, MarinadeError::ProgramIsPaused);
        require!(
            self.state.withdraw_stake_account_enabled,
            MarinadeError::WithdrawStakeAccountIsNotEnabled
        );
        // record  for event
        let user_msol_balance = self.burn_msol_from.amount;
        // save msol price source
        let total_virtual_staked_lamports = self.state.total_virtual_staked_lamports();
        let msol_supply = self.state.msol_supply;

        check_token_source_account(
            &self.burn_msol_from,
            self.burn_msol_authority.key,
            msol_amount,
        )
        .map_err(|e| e.with_account_name("burn_msol_from"))?;

        let mut stake = self.state.stake_system.get_checked(
            &self.stake_list.to_account_info().data.as_ref().borrow(),
            stake_index,
            self.stake_account.to_account_info().key,
        )?;
        let last_update_stake_delegation = stake.last_update_delegated_lamports;

        // require the stake is not in emergency_unstake
        require_eq!(
            stake.is_emergency_unstaking,
            0,
            MarinadeError::StakeAccountIsEmergencyUnstaking
        );

        // require stake is active (deactivation_epoch == u64::MAX)
        let delegation = self.stake_account.delegation().ok_or_else(|| {
            error!(MarinadeError::RequiredDelegatedStake).with_account_name("stake_account")
        })?;
        require_eq!(
            delegation.deactivation_epoch,
            std::u64::MAX,
            MarinadeError::RequiredActiveStake
        );

        let mut validator = self.state.validator_system.get(
            &self.validator_list.to_account_info().data.as_ref().borrow(),
            validator_index,
        )?;

        // check currently_staked in this account & validator vote-key
        check_stake_amount_and_validator(
            &self.stake_account,
            stake.last_update_delegated_lamports,
            &validator.validator_account,
        )?;

        // compute how many lamport to split
        let split_lamports = {
            // compute how many lamport the withdraw request's mSOL amount represents
            let sol_value = self.state.msol_to_sol(msol_amount)?;
            require_gte!(
                sol_value,
                self.state.min_withdraw,
                MarinadeError::WithdrawAmountIsTooLow
            );
            // apply withdraw_stake_account_fee to avoid economical attacks
            // withdraw_stake_account_fee must be >= one epoch staking rewards
            let withdraw_stake_account_fee_lamports =
                self.state.withdraw_stake_account_fee.apply(sol_value);
            // The mSOL fee value is sending to the treasury but
            // the corresponding SOL value is not delivering inside the stake to the user
            // because it is a fee user is paying for running this instruction
            sol_value - withdraw_stake_account_fee_lamports
        };

        // check withdraw amount (new stake account) >= self.state.stake_system.min_stake
        require_gte!(
            split_lamports,
            self.state.stake_system.min_stake,
            MarinadeError::WithdrawStakeLamportsIsTooLow
        );
        // the user can not ask for more that what is in the stake account
        require_gte!(
            stake.last_update_delegated_lamports,
            split_lamports,
            MarinadeError::SelectedStakeAccountHasNotEnoughFunds
        );
        // require also remainder stake to be >= self.state.stake_system.min_stake
        // To simplify the flow, we always deliver the lamports in the splitted account,
        // so some lamports must remain in the original account. Check that
        // after split, the amount remaining in the stake account is >= state.stake_system.min_stake
        require_gte!(
            stake.last_update_delegated_lamports - split_lamports,
            self.state.stake_system.min_stake,
            MarinadeError::StakeAccountRemainderTooLow
        );

        let treasury_msol_balance = self
            .state
            .get_treasury_msol_balance(&self.treasury_msol_account);

        let msol_fees = if treasury_msol_balance.is_some() {
            // saturating sub may be needed in case of some weird calculation rounding
            msol_amount.saturating_sub(self.state.calc_msol_from_lamports(split_lamports)?)
        } else {
            0
        };
        let msol_burned = msol_amount - msol_fees; // guaranteed to not underflow

        if msol_fees > 0 {
            transfer(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    Transfer {
                        from: self.burn_msol_from.to_account_info(),
                        to: self.treasury_msol_account.to_account_info(),
                        authority: self.burn_msol_authority.to_account_info(),
                    },
                ),
                msol_fees,
            )?;
        }
        // burn mSOL
        if msol_burned > 0 {
            burn(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    Burn {
                        mint: self.msol_mint.to_account_info(),
                        from: self.burn_msol_from.to_account_info(),
                        authority: self.burn_msol_authority.to_account_info(),
                    },
                ),
                msol_burned,
            )?;
            self.state.on_msol_burn(msol_burned);
        }

        // split split_lamports from stake account into out split_stake_account
        msg!(
            "Split {} lamports from stake {} into {}",
            split_lamports,
            stake.stake_account,
            self.split_stake_account.key(),
        );

        let split_instruction = stake::instruction::split(
            self.stake_account.to_account_info().key,
            self.stake_deposit_authority.key,
            split_lamports,
            &self.split_stake_account.key(),
        )
        .last()
        .unwrap()
        .clone();
        invoke_signed(
            &split_instruction,
            &[
                self.stake_program.to_account_info(),
                self.stake_account.to_account_info(),
                self.split_stake_account.to_account_info(),
                self.stake_deposit_authority.to_account_info(),
            ],
            &[&[
                &self.state.key().to_bytes(),
                StakeSystem::STAKE_DEPOSIT_SEED,
                &[self.state.stake_system.stake_deposit_bump_seed],
            ]],
        )?;

        stake.last_update_delegated_lamports -= split_lamports;

        // we now consider amount no longer "active" for this specific validator
        validator.active_balance -= split_lamports;
        // and in state totals,
        self.state.validator_system.total_active_balance -= split_lamports;

        // update stake-list & validator-list
        self.state.stake_system.set(
            &mut self.stake_list.to_account_info().data.as_ref().borrow_mut(),
            stake_index,
            stake,
        )?;
        self.state.validator_system.set(
            &mut self
                .validator_list
                .to_account_info()
                .data
                .as_ref()
                .borrow_mut(),
            validator_index,
            validator,
        )?;

        // assign user staker and as withdrawer (owner) for the new split_stake_account
        invoke_signed(
            &stake::instruction::authorize(
                self.split_stake_account.to_account_info().key,
                self.stake_withdraw_authority.key,
                &beneficiary,
                StakeAuthorize::Staker,
                None,
            ),
            &[
                self.split_stake_account.to_account_info(),
                self.stake_withdraw_authority.to_account_info(),
                self.stake_program.to_account_info(),
                self.clock.to_account_info(),
            ],
            &[&[
                &self.state.key().to_bytes(),
                StakeSystem::STAKE_WITHDRAW_SEED,
                &[self.state.stake_system.stake_withdraw_bump_seed],
            ]],
        )?;
        invoke_signed(
            &stake::instruction::authorize(
                self.split_stake_account.to_account_info().key,
                self.stake_withdraw_authority.key,
                &beneficiary,
                StakeAuthorize::Withdrawer,
                None,
            ),
            &[
                self.split_stake_account.to_account_info(),
                self.stake_withdraw_authority.to_account_info(),
                self.stake_program.to_account_info(),
                self.clock.to_account_info(),
            ],
            &[&[
                &self.state.key().to_bytes(),
                StakeSystem::STAKE_WITHDRAW_SEED,
                &[self.state.stake_system.stake_withdraw_bump_seed],
            ]],
        )?;

        emit!(WithdrawStakeAccountEvent {
            state: self.state.key(),
            epoch: self.clock.epoch,
            stake_index,
            stake: self.stake_account.key(),
            last_update_stake_delegation,
            validator_index,
            validator: validator.validator_account,
            user_msol_auth: self.burn_msol_authority.key(),
            beneficiary,
            user_msol_balance,
            msol_burned,
            msol_fees,
            split_stake: self.split_stake_account.key(),
            split_lamports,
            fee_bp_cents: self.state.withdraw_stake_account_fee.bp_cents,
            total_virtual_staked_lamports,
            msol_supply,
        });

        Ok(())
    }
}


// ========== checks.rs ==========
use crate::MarinadeError;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::stake::state::StakeState;
use anchor_spl::token::{Mint, TokenAccount};

pub fn check_owner_program<'info, A: ToAccountInfo<'info>>(
    account: &A,
    owner: &Pubkey,
    field_name: &str,
) -> Result<()> {
    let actual_owner = account.to_account_info().owner;
    if actual_owner == owner {
        Ok(())
    } else {
        msg!(
            "Invalid {} owner_program: expected {} got {}",
            field_name,
            owner,
            actual_owner
        );
        Err(Error::from(ProgramError::InvalidArgument)
            .with_account_name(field_name)
            .with_pubkeys((*actual_owner, *owner))
            .with_source(source!()))
    }
}

pub fn check_mint_authority(mint: &Mint, mint_authority: &Pubkey, field_name: &str) -> Result<()> {
    if mint.mint_authority.contains(mint_authority) {
        Ok(())
    } else {
        msg!(
            "Invalid {} mint authority {}. Expected {}",
            field_name,
            mint.mint_authority.unwrap_or_default(),
            mint_authority
        );
        Err(Error::from(ProgramError::InvalidAccountData).with_source(source!()))
    }
}

pub fn check_freeze_authority(mint: &Mint, field_name: &str) -> Result<()> {
    if mint.freeze_authority.is_none() {
        Ok(())
    } else {
        msg!("Mint {} must have freeze authority not set", field_name);
        Err(Error::from(ProgramError::InvalidAccountData).with_source(source!()))
    }
}

pub fn check_mint_empty(mint: &Mint, field_name: &str) -> Result<()> {
    if mint.supply == 0 {
        Ok(())
    } else {
        msg!("Non empty mint {} supply: {}", field_name, mint.supply);
        Err(Error::from(ProgramError::InvalidArgument).with_source(source!()))
    }
}

pub fn check_token_mint(token: &TokenAccount, mint: &Pubkey, field_name: &str) -> Result<()> {
    if token.mint == *mint {
        Ok(())
    } else {
        msg!(
            "Invalid token {} mint {}. Expected {}",
            field_name,
            token.mint,
            mint
        );
        Err(Error::from(ProgramError::InvalidAccountData).with_source(source!()))
    }
}

pub fn check_token_owner(token: &TokenAccount, owner: &Pubkey, field_name: &str) -> Result<()> {
    if token.owner == *owner {
        Ok(())
    } else {
        msg!(
            "Invalid token account {} owner {}. Expected {}",
            field_name,
            token.owner,
            owner
        );
        Err(Error::from(ProgramError::InvalidAccountData).with_source(source!()))
    }
}

// check that the account is delegated and to the right validator
// also that the stake amount is updated
pub fn check_stake_amount_and_validator(
    stake_state: &StakeState,
    expected_stake_amount: u64,
    validator_vote_pubkey: &Pubkey,
) -> Result<()> {
    let currently_staked = if let Some(delegation) = stake_state.delegation() {
        require_keys_eq!(
            delegation.voter_pubkey,
            *validator_vote_pubkey,
            MarinadeError::WrongValidatorAccountOrIndex
        );
        delegation.stake
    } else {
        return err!(MarinadeError::StakeNotDelegated);
    };
    // do not allow to operate on an account where last_update_delegated_lamports != currently_staked
    if currently_staked != expected_stake_amount {
        msg!(
            "Operation on a stake account not yet updated. expected stake:{}, current:{}",
            expected_stake_amount,
            currently_staked
        );
        return err!(MarinadeError::StakeAccountNotUpdatedYet);
    }
    Ok(())
}

#[macro_export]
macro_rules! require_lte {
    ($value1: expr, $value2: expr, $error_code: expr $(,)?) => {
        if $value1 > $value2 {
            return Err(error!($error_code).with_values(($value1, $value2)));
        }
    };
}

#[macro_export]
macro_rules! require_lt {
    ($value1: expr, $value2: expr, $error_code: expr $(,)?) => {
        if $value1 >= $value2 {
            return Err(error!($error_code).with_values(($value1, $value2)));
        }
    };
}

pub fn check_token_source_account<'info>(
    source_account: &Account<'info, TokenAccount>,
    authority: &Pubkey,
    token_amount: u64,
) -> Result<()> {
    if source_account.delegate.contains(authority) {
        // if delegated, check delegated amount
        // delegated_amount & delegate must be set on the user's msol account before calling OrderUnstake
        require_lte!(
            token_amount,
            source_account.delegated_amount,
            MarinadeError::NotEnoughUserFunds
        );
    } else if *authority == source_account.owner {
        require_lte!(
            token_amount,
            source_account.amount,
            MarinadeError::NotEnoughUserFunds
        );
    } else {
        return err!(MarinadeError::WrongTokenOwnerOrDelegate)
            .map_err(|e| e.with_pubkeys((source_account.owner, *authority)));
    }
    Ok(())
}
