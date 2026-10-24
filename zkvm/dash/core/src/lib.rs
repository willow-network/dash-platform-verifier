//! The Dash lane: proves a Dash Platform fact on Ethereum with no trusted key feed.
//!
//! From a Core block the verifier contract already trusts, the guest walks ChainLocks forward
//! (each ChainLock signed by an LLMQ_400_60 quorum active in the previous block's
//! merkleRootQuorums) to the Core height Platform committed to, takes the LLMQ_100_67 quorum
//! from that block's merkleRootQuorums, checks its signature on Platform's state root, and
//! reads the username and identity out of GroveDB with Drive's own verifiers.

pub mod bls;
pub mod chain;
pub mod error;
pub mod platform;
pub mod statement;
pub mod tenderdash;

use alloy_primitives::{Address, FixedBytes};
use alloy_sol_types::SolValue;
use chain::{Hash, LLMQ_CHAINLOCKS, LLMQ_PLATFORM};
use error::Error;
use serde::{Deserialize, Serialize};
use statement::{DashKey, DashUsernameStatement, KIND_USERNAME};

/// The longest ChainLock step, in blocks: one LLMQ_400_60 DKG interval (12 hours).
pub const MAX_STEP: u32 = 288;
/// The most headers between Platform's Core block and the ChainLocked block that locks it.
pub const MAX_LINK: usize = 64;
/// Identities may hold many keys; the statement carries at most this many.
pub const MAX_KEYS: usize = 32;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoreBlock {
    pub header: Vec<u8>,
    pub coinbase: Vec<u8>,
    pub coinbase_branch: Vec<Hash>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuorumWitness {
    pub commitment: Vec<u8>,
    pub branch: Vec<Hash>,
    pub index: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainLockStep {
    pub block: CoreBlock,
    pub signature: Vec<u8>,
    pub signer: QuorumWitness,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlatformCommit {
    pub height: u64,
    pub core_chain_locked_height: u32,
    pub time_ms: u64,
    pub protocol_version: u32,
    pub chain_id: String,
    pub round: u32,
    pub block_id_hash: Hash,
    pub quorum_type: u32,
    pub quorum_hash: Hash,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Input {
    pub start: CoreBlock,
    pub steps: Vec<ChainLockStep>,
    /// The block at Platform's core_chain_locked_height; locked by the walk's last block.
    pub platform_block: CoreBlock,
    /// Headers from platform_block + 1 up to the walk's last block, in order.
    pub link_headers: Vec<Vec<u8>>,
    pub platform_quorum: QuorumWitness,
    pub commit: PlatformCommit,
    pub normalized_label: String,
    pub dpns_proof: Vec<u8>,
    pub identity_proof: Vec<u8>,
}

/// A Core block whose coinbase is proven to be in it.
struct Verified {
    height: u32,
    hash: Hash,
    quorums_root: Hash,
}

fn verify_block(b: &CoreBlock) -> Result<Verified, Error> {
    let header = chain::parse_header(&b.header)?;
    let (txid, cbtx) = chain::parse_coinbase(&b.coinbase)?;
    if chain::fold_branch(txid, &b.coinbase_branch, 0)? != header.merkle_root {
        return Err(Error::CoinbaseNotInBlock);
    }
    Ok(Verified {
        height: cbtx.height,
        hash: header.hash,
        quorums_root: cbtx.merkle_root_quorums,
    })
}

fn verify_member(w: &QuorumWitness, quorums_root: &Hash, llmq_type: u8) -> Result<chain::Commitment, Error> {
    let c = chain::parse_commitment(&w.commitment)?;
    if c.llmq_type != llmq_type {
        return Err(Error::WrongQuorumType);
    }
    if chain::fold_branch(c.hash, &w.branch, w.index)? != *quorums_root {
        return Err(Error::QuorumNotActive);
    }
    Ok(c)
}

pub fn verify(input: &Input) -> Result<DashUsernameStatement, Error> {
    let start = verify_block(&input.start)?;
    let mut tip = start;
    let (start_height, start_hash) = (tip.height, tip.hash);

    for step in &input.steps {
        let next = verify_block(&step.block)?;
        if next.height <= tip.height {
            return Err(Error::StepNotForward);
        }
        if next.height - tip.height > MAX_STEP {
            return Err(Error::StepTooLong);
        }
        let signer = verify_member(&step.signer, &tip.quorums_root, LLMQ_CHAINLOCKS)?;
        let msg = chain::llmq_sign_hash(
            LLMQ_CHAINLOCKS,
            &signer.quorum_hash,
            &chain::chainlock_request_id(next.height),
            &next.hash,
        );
        let sig: &[u8; 96] = step.signature.as_slice().try_into().map_err(|_| Error::BadChainLock)?;
        if !bls::verify(&signer.public_key, &msg, sig) {
            return Err(Error::BadChainLock);
        }
        tip = next;
    }

    // A ChainLock locks its block's ancestors too: link Platform's Core block to the tip.
    let pb = verify_block(&input.platform_block)?;
    if input.link_headers.len() > MAX_LINK || pb.height as u64 + input.link_headers.len() as u64 != tip.height as u64 {
        return Err(Error::BadLink);
    }
    let mut prev = pb.hash;
    for h in &input.link_headers {
        let header = chain::parse_header(h)?;
        if header.prev != prev {
            return Err(Error::BadLink);
        }
        prev = header.hash;
    }
    if prev != tip.hash {
        return Err(Error::BadLink);
    }

    let c = &input.commit;
    if pb.height != c.core_chain_locked_height {
        return Err(Error::CoreHeightMismatch);
    }
    if c.quorum_type != LLMQ_PLATFORM as u32 {
        return Err(Error::WrongQuorumType);
    }
    let quorum = verify_member(&input.platform_quorum, &pb.quorums_root, LLMQ_PLATFORM)?;
    let mut display = quorum.quorum_hash;
    display.reverse();
    if display != c.quorum_hash {
        return Err(Error::QuorumHashMismatch);
    }

    let pv = dpp::version::PlatformVersion::get(c.protocol_version).map_err(|_| Error::UnknownProtocolVersion)?;
    let name = platform::verify_username(&input.dpns_proof, &input.normalized_label, pv)?;
    let ident = platform::verify_identity(&input.identity_proof, name.identity_id, pv)?;
    if ident.app_hash != name.app_hash {
        return Err(Error::AppHashMismatch);
    }
    if ident.keys.len() > MAX_KEYS {
        return Err(Error::TooManyKeys);
    }

    let signed = tenderdash::SignedState {
        protocol_version: c.protocol_version as u64,
        height: c.height,
        app_hash: &name.app_hash,
        core_chain_locked_height: c.core_chain_locked_height,
        time_ms: c.time_ms,
        round: c.round,
        block_id_hash: &c.block_id_hash,
        chain_id: &c.chain_id,
    };
    let digest = tenderdash::commit_sign_digest(&signed, LLMQ_PLATFORM, &c.quorum_hash);
    let sig: &[u8; 96] = c.signature.as_slice().try_into().map_err(|_| Error::BadPlatformSignature)?;
    if !bls::verify(&quorum.public_key, &digest, sig) {
        return Err(Error::BadPlatformSignature);
    }

    Ok(DashUsernameStatement {
        kind: KIND_USERNAME,
        coreStartHeight: start_height,
        coreStartHash: FixedBytes(start_hash),
        coreEndHeight: tip.height,
        coreEndHash: FixedBytes(tip.hash),
        platformHeight: c.height,
        platformTimeMs: c.time_ms,
        protocolVersion: c.protocol_version,
        appHash: FixedBytes(name.app_hash),
        normalizedLabel: name.normalized_label,
        label: name.label,
        identityId: FixedBytes(name.identity_id),
        balance: ident.balance,
        revision: ident.revision,
        keys: ident
            .keys
            .iter()
            .map(|k| DashKey {
                id: k.id,
                purpose: k.purpose,
                securityLevel: k.security_level,
                ethAddress: Address::from(k.eth_address),
            })
            .collect(),
    })
}

pub fn public_values(s: &DashUsernameStatement) -> Vec<u8> {
    s.abi_encode()
}

#[cfg(test)]
mod tests;
