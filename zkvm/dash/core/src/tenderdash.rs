//! The digest a Platform quorum signs to commit a block (Tenderdash v1.5, as checked by
//! rs-drive-proof-verifier's verify_tenderdash_proof).

use crate::chain::{sha256, sha256d, Hash};

pub struct SignedState<'a> {
    pub protocol_version: u64,
    pub height: u64,
    pub app_hash: &'a Hash,
    pub core_chain_locked_height: u32,
    pub time_ms: u64,
    pub round: u32,
    pub block_id_hash: &'a Hash,
    pub chain_id: &'a str,
}

/// SHA-256 of the length-delimited protobuf StateID (all fields fixed-width; proto3
/// omits zero-valued fields).
pub fn state_id_hash(s: &SignedState) -> Hash {
    let mut body = Vec::with_capacity(70);
    if s.protocol_version != 0 {
        body.push(0x09);
        body.extend_from_slice(&s.protocol_version.to_le_bytes());
    }
    if s.height != 0 {
        body.push(0x11);
        body.extend_from_slice(&s.height.to_le_bytes());
    }
    body.extend_from_slice(&[0x1a, 32]);
    body.extend_from_slice(s.app_hash);
    if s.core_chain_locked_height != 0 {
        body.push(0x25);
        body.extend_from_slice(&s.core_chain_locked_height.to_le_bytes());
    }
    if s.time_ms != 0 {
        body.push(0x29);
        body.extend_from_slice(&s.time_ms.to_le_bytes());
    }
    let mut msg = Vec::with_capacity(body.len() + 1);
    msg.push(body.len() as u8);
    msg.extend_from_slice(&body);
    sha256(&msg)
}

/// The BLS message for a precommit of `s`, signed by the quorum with display-order
/// `quorum_hash` of type `quorum_type`.
pub fn commit_sign_digest(s: &SignedState, quorum_type: u8, quorum_hash_display: &Hash) -> Hash {
    let state_id = state_id_hash(s);
    let mut vote = Vec::with_capacity(84 + s.chain_id.len());
    vote.extend_from_slice(&2i32.to_le_bytes());
    vote.extend_from_slice(&(s.height as i64).to_le_bytes());
    vote.extend_from_slice(&(s.round as i64).to_le_bytes());
    vote.extend_from_slice(s.block_id_hash);
    vote.extend_from_slice(&state_id);
    vote.extend_from_slice(s.chain_id.as_bytes());
    let msg_hash = sha256(&vote);

    let mut req = Vec::with_capacity(19);
    req.extend_from_slice(b"dpbvote");
    req.extend_from_slice(&(s.height as i64).to_le_bytes());
    req.extend_from_slice(&(s.round as i32).to_le_bytes());
    let request_id = sha256(&req);

    let mut buf = [0u8; 97];
    buf[0] = quorum_type;
    for i in 0..32 {
        buf[1 + i] = quorum_hash_display[31 - i];
        buf[33 + i] = request_id[31 - i];
        buf[65 + i] = msg_hash[31 - i];
    }
    sha256d(&buf)
}
