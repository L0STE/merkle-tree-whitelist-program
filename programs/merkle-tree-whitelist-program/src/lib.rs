use anchor_lang::prelude::*;
use svm_merkle_tree::{HashingAlgorithm, MerkleProof};

declare_id!("ApeCYpJeXLu5kuHTjpetrLJ6TUjNopbfW2Jqg3SWPUF6");

#[program]
pub mod simple_merkle_whitelist {
    use super::*;

    pub fn initialize_merkle_tree(
        ctx: Context<Initialize>, 
        merkle_root: [u8; 32]
    ) -> Result<()> {

        ctx.accounts.whitelist_state.set_inner(
            WhitelistState {
                merkle_root,
                authority: ctx.accounts.authority.key(),
                bump: ctx.bumps.whitelist_state,
            }
        );

        Ok(())
    }

    pub fn update_merkle_tree(
        ctx: Context<Update>, 
        new_root: [u8; 32]
    ) -> Result<()> {

        ctx.accounts.whitelist_state.merkle_root = new_root;

        Ok(())
    }

    pub fn action(
        ctx: Context<Action>, 
        hashes: Vec<u8>, 
        index: u64
    ) -> Result<()> {
        
        // Check if the Signer is whitelisted
        let is_whitelisted = simple_merkle_whitelist::verify_address(
            ctx.accounts.signer.key(),
            hashes,
            index,
            ctx.accounts.whitelist_state.merkle_root
        )?;
        
        require!(is_whitelisted, WhitelistError::InvalidProof);
    
        // Perform the action
    
        Ok(())
    }
}

pub fn verify_address(
    address: Pubkey, 
    hashes: Vec<u8>, 
    index: u64,
    merkle_root: [u8; 32]
) -> Result<bool> {
    let leaf = address.to_bytes().to_vec();
    let merkle_proof = MerkleProof::new(
        HashingAlgorithm::Keccak,
        32,
        index as u32,
        hashes,
    );

    let computed_root = merkle_proof.merklize(&leaf)
        .map_err(|_| WhitelistError::InvalidProof)?;

    Ok(computed_root.eq(&merkle_root))
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init, 
        seeds = [b"whitelist".as_ref()],
        bump,
        payer = authority, 
        space = 8 + 32 + 32 + 1
    )]
    pub whitelist_state: Account<'info, WhitelistState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Update<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut, 
        has_one = authority,
        seeds = [b"whitelist".as_ref()],
        bump = whitelist_state.bump
    )]
    pub whitelist_state: Account<'info, WhitelistState>,
}

#[derive(Accounts)]
pub struct Action<'info> {
    pub signer: Signer<'info>,
    #[account(
        seeds = [b"whitelist".as_ref()],
        bump = whitelist_state.bump
    )]
    pub whitelist_state: Account<'info, WhitelistState>,
}

#[account]
pub struct WhitelistState {
    pub merkle_root: [u8; 32],
    pub authority: Pubkey,
    pub bump: u8,
}

#[error_code]
pub enum WhitelistError {
    #[msg("Invalid Merkle proof")]
    InvalidProof,
}