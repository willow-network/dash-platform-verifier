//! BLS12-381 signature verification, IETF basic scheme (public key in G1, signature in G2),
//! which Dash uses for LLMQ threshold signatures since v19.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G2Affine, G2Projective};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// True iff `sig` is a valid basic-scheme signature of `msg` under `pk`.
/// Both points are decompressed with subgroup checks; the identity key is refused.
pub fn verify(pk: &[u8; 48], msg: &[u8], sig: &[u8; 96]) -> bool {
    let pk = G1Affine::from_compressed(pk);
    let sig = G2Affine::from_compressed(sig);
    if pk.is_none().into() || sig.is_none().into() {
        return false;
    }
    let (pk, sig) = (pk.unwrap(), sig.unwrap());
    if bool::from(pk.is_identity()) {
        return false;
    }
    let h = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve([msg], DST);
    pairing(&pk, &G2Affine::from(h)) == pairing(&G1Affine::generator(), &sig)
}
