//! Real mainnet fixture: "paul" (pau1.dash) at Platform height 457136, walked from Core block
//! 2559855 to 2559955. Each tamper test breaks one link of the chain and must be refused.

use crate::error::Error;
use crate::*;

fn fixture() -> Input {
    bincode::deserialize(include_bytes!("../../fixtures/pau1-2559855.stdin.bin")).unwrap()
}

fn rejects(input: &Input) -> Error {
    verify(input).err().expect("tampered input verified")
}

#[test]
fn real_fixture_verifies() {
    let s = verify(&fixture()).unwrap();
    assert_eq!(s.label, "paul");
    assert_eq!(s.normalizedLabel, "pau1");
    assert_eq!(hex::encode(s.identityId), "bd5d1db32bd4fb1e3e00e830146e9211325379be0c3f377f679ddada618e9399");
    assert_eq!(s.balance, 16_391_536_400);
    assert_eq!(s.revision, 4);
    assert_eq!((s.coreStartHeight, s.coreEndHeight), (2_559_855, 2_559_955));
    assert_eq!(hex::encode(s.coreEndHash), "f62b3ff2e6cf34dc17cf3bae52a86da403c8eb741c1d39e90500000000000000");
    assert_eq!((s.platformHeight, s.platformTimeMs, s.protocolVersion), (457_136, 1_792_738_345_123, 13));
    assert_eq!(s.keys.len(), 8);
    assert_eq!(public_values(&s), include_bytes!("../../fixtures/pau1-2559855.public.bin"));
}

#[test]
fn real_three_step_walk_verifies() {
    let i: Input = bincode::deserialize(include_bytes!("../../fixtures/pau1-2559255.stdin.bin")).unwrap();
    assert_eq!(i.steps.len(), 3);
    let s = verify(&i).unwrap();
    assert_eq!((s.coreStartHeight, s.coreEndHeight), (2_559_255, 2_559_955));
    assert_eq!(s.identityId, verify(&fixture()).unwrap().identityId);
}

#[test]
fn real_locked_through_a_descendant_verifies() {
    let i: Input = bincode::deserialize(include_bytes!("../../fixtures/pau1-2559855-link3.stdin.bin")).unwrap();
    assert_eq!(i.link_headers.len(), 3);
    let s = verify(&i).unwrap();
    assert_eq!(s.coreEndHeight, 2_559_958);
    let mut bad = i.clone();
    bad.link_headers[1][10] ^= 1;
    assert_eq!(rejects(&bad), Error::BadLink);
    let mut bad = i.clone();
    bad.link_headers.swap(0, 1);
    assert_eq!(rejects(&bad), Error::BadLink);
}

/// The input behind the first live mainnet `verifyUsername`: one step from the bootstrap block.
#[test]
fn real_verify_input_verifies() {
    let i: Input = bincode::deserialize(include_bytes!("../../fixtures/pau1-2560000.stdin.bin")).unwrap();
    let s = verify(&i).unwrap();
    assert_eq!((s.coreStartHeight, s.coreEndHeight), (2_560_000, 2_560_019));
    assert_eq!(s.platformHeight, 457_223);
    assert_eq!(public_values(&s), include_bytes!("../../fixtures/pau1-2560000.public.bin"));
}

/// The input behind the live mainnet USDC claim: two ChainLock steps from a contract-trusted block.
#[test]
fn real_claim_input_verifies() {
    let i: Input = bincode::deserialize(include_bytes!("../../fixtures/pau1-2560019.stdin.bin")).unwrap();
    assert_eq!(i.steps.len(), 2);
    let s = verify(&i).unwrap();
    assert_eq!((s.coreStartHeight, s.coreEndHeight), (2_560_019, 2_560_534));
    assert_eq!(s.platformHeight, 457_743);
    assert_eq!(public_values(&s), include_bytes!("../../fixtures/pau1-2560019.public.bin"));
}

#[test]
fn platform_signature_is_checked() {
    let mut i = fixture();
    i.commit.signature[40] ^= 1;
    assert_eq!(rejects(&i), Error::BadPlatformSignature);
}

#[test]
fn every_signed_commit_field_is_bound() {
    let mut i = fixture();
    i.commit.time_ms += 1;
    assert_eq!(rejects(&i), Error::BadPlatformSignature);
    let mut i = fixture();
    i.commit.height += 1;
    assert_eq!(rejects(&i), Error::BadPlatformSignature);
    let mut i = fixture();
    i.commit.round += 1;
    assert_eq!(rejects(&i), Error::BadPlatformSignature);
    let mut i = fixture();
    i.commit.block_id_hash[0] ^= 1;
    assert_eq!(rejects(&i), Error::BadPlatformSignature);
    let mut i = fixture();
    i.commit.chain_id = "evo2".into();
    assert_eq!(rejects(&i), Error::BadPlatformSignature);
}

#[test]
fn platform_quorum_type_is_pinned() {
    let mut i = fixture();
    i.commit.quorum_type = LLMQ_CHAINLOCKS as u32;
    assert_eq!(rejects(&i), Error::WrongQuorumType);
}

#[test]
fn platform_quorum_must_match_the_commit() {
    let mut i = fixture();
    i.commit.quorum_hash[5] ^= 1;
    assert_eq!(rejects(&i), Error::QuorumHashMismatch);
}

#[test]
fn platform_quorum_must_be_active() {
    let mut i = fixture();
    i.platform_quorum.index ^= 1;
    assert_eq!(rejects(&i), Error::QuorumNotActive);
    let mut i = fixture();
    i.platform_quorum.branch[0][0] ^= 1;
    assert_eq!(rejects(&i), Error::QuorumNotActive);
}

#[test]
fn chainlock_signature_is_checked() {
    let mut i = fixture();
    i.steps[0].signature[50] ^= 1;
    assert_eq!(rejects(&i), Error::BadChainLock);
}

#[test]
fn chainlock_signer_must_be_a_chainlock_quorum() {
    let mut i = fixture();
    i.steps[0].signer = i.platform_quorum.clone();
    assert_eq!(rejects(&i), Error::WrongQuorumType);
}

#[test]
fn chainlock_signer_must_be_active_in_the_previous_block() {
    let mut i = fixture();
    i.steps[0].signer.branch[1][7] ^= 1;
    assert_eq!(rejects(&i), Error::QuorumNotActive);
}

#[test]
fn header_tamper_breaks_the_chainlock() {
    let mut i = fixture();
    i.steps[0].block.header[79] ^= 1;
    assert_eq!(rejects(&i), Error::BadChainLock);
}

#[test]
fn coinbase_must_be_in_the_block() {
    let mut i = fixture();
    i.steps[0].block.coinbase_branch[0][3] ^= 1;
    assert_eq!(rejects(&i), Error::CoinbaseNotInBlock);
    let mut i = fixture();
    i.start.coinbase_branch.pop();
    assert_eq!(rejects(&i), Error::CoinbaseNotInBlock);
}

#[test]
fn platform_block_must_be_locked_by_the_walk() {
    let mut i = fixture();
    i.steps.clear();
    assert_eq!(rejects(&i), Error::BadLink);
    let mut i = fixture();
    i.platform_block = i.start.clone();
    assert_eq!(rejects(&i), Error::BadLink);
}

#[test]
fn link_headers_must_chain() {
    let mut i = fixture();
    i.link_headers.push(i.steps[0].block.header.clone());
    assert_eq!(rejects(&i), Error::BadLink);
}

#[test]
fn commit_core_height_must_be_the_platform_block() {
    let mut i = fixture();
    i.commit.core_chain_locked_height -= 1;
    assert_eq!(rejects(&i), Error::CoreHeightMismatch);
}

#[test]
fn start_block_is_what_the_statement_names() {
    let mut i = fixture();
    i.start.header[76] ^= 1;
    let s = verify(&i).unwrap();
    assert_ne!(hex::encode(s.coreStartHash), hex::encode(verify(&fixture()).unwrap().coreStartHash));
}

#[test]
fn wrong_username_is_refused() {
    let mut i = fixture();
    i.normalized_label = "pau2".into();
    assert!(verify(&i).is_err());
}

#[test]
fn proofs_must_share_one_signed_root() {
    let mut i = fixture();
    i.identity_proof = i.dpns_proof.clone();
    assert!(verify(&i).is_err());
}

/// Every single-byte change to either GroveDB proof is refused (none is a free byte).
#[test]
#[ignore = "slow in debug; run with --release -- --ignored"]
fn every_proof_byte_is_load_bearing() {
    let base = fixture();
    for which in 0..2 {
        let len = if which == 0 { base.dpns_proof.len() } else { base.identity_proof.len() };
        for pos in 0..len {
            let mut i = base.clone();
            let p = if which == 0 { &mut i.dpns_proof } else { &mut i.identity_proof };
            p[pos] ^= 0x01;
            assert!(verify(&i).is_err(), "proof {which} byte {pos} is free");
        }
    }
}
