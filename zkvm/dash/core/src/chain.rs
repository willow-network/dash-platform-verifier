//! Dash Core consensus structures: block headers (X11), the coinbase CbTx, LLMQ final
//! commitments, Bitcoin-style merkle branches, and the LLMQ sign hash ChainLocks use.

use crate::error::Error;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// LLMQ_400_60, the mainnet ChainLock quorum type.
pub const LLMQ_CHAINLOCKS: u8 = 2;
/// LLMQ_100_67, the mainnet Platform quorum type.
pub const LLMQ_PLATFORM: u8 = 4;
/// Special transaction types (DIP-2).
const TX_COINBASE: u16 = 5;
/// CbTx v3 (CLSIG_AND_BALANCE) carries merkleRootQuorums and the best ChainLock.
const CBTX_MIN_VERSION: u16 = 3;
/// Commitment versions 3 and 4 use the basic (IETF) BLS scheme; 1 and 2 are legacy.
const BASIC_BLS_NON_INDEXED: u16 = 3;
const BASIC_BLS_INDEXED: u16 = 4;

pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

pub fn sha256d(data: &[u8]) -> Hash {
    sha256(&sha256(data))
}

extern "C" {
    fn x11_hash(input: *const u8, output: *mut u8);
}

/// X11 of an 80-byte Dash block header: the block hash, in internal byte order.
pub fn x11(header: &[u8; 80]) -> Hash {
    let mut out = [0u8; 32];
    unsafe { x11_hash(header.as_ptr(), out.as_mut_ptr()) };
    out
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    pub fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.arr()?))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    /// Bitcoin CompactSize, rejecting non-canonical encodings.
    pub fn compact(&mut self) -> Result<u64, Error> {
        let n = self.u8()?;
        let v = match n {
            0..=0xfc => return Ok(n as u64),
            0xfd => self.u16()? as u64,
            0xfe => self.u32()? as u64,
            _ => self.u64()?,
        };
        let min = match n {
            0xfd => 0xfd,
            0xfe => 0x1_0000,
            _ => 0x1_0000_0000,
        };
        if v < min {
            return Err(Error::NonCanonical);
        }
        Ok(v)
    }
    pub fn var_bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.compact()?;
        self.take(usize::try_from(n).map_err(|_| Error::Truncated)?)
    }
    pub fn done(&self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

/// The fields of a block header this lane uses.
pub struct Header {
    pub hash: Hash,
    pub prev: Hash,
    pub merkle_root: Hash,
}

pub fn parse_header(header: &[u8]) -> Result<Header, Error> {
    let h: &[u8; 80] = header.try_into().map_err(|_| Error::BadHeader)?;
    Ok(Header {
        hash: x11(h),
        prev: h[4..36].try_into().unwrap(),
        merkle_root: h[36..68].try_into().unwrap(),
    })
}

/// The DIP-4 coinbase payload (CbTx), v3 and later.
pub struct CbTx {
    pub height: u32,
    pub merkle_root_quorums: Hash,
    pub best_cl_height_diff: u64,
    pub best_cl_signature: [u8; 96],
}

/// Parse a full coinbase transaction and return its txid and CbTx payload.
pub fn parse_coinbase(tx: &[u8]) -> Result<(Hash, CbTx), Error> {
    let mut r = Reader::new(tx);
    let ver = r.u32()?;
    let (version, tx_type) = ((ver & 0xffff) as u16, (ver >> 16) as u16);
    if version < 3 || tx_type != TX_COINBASE {
        return Err(Error::NotCoinbase);
    }
    if r.compact()? != 1 {
        return Err(Error::NotCoinbase);
    }
    let prev: [u8; 32] = r.arr()?;
    let idx = r.u32()?;
    if prev != [0u8; 32] || idx != u32::MAX {
        return Err(Error::NotCoinbase);
    }
    r.var_bytes()?;
    r.u32()?;
    for _ in 0..r.compact()? {
        r.u64()?;
        r.var_bytes()?;
    }
    r.u32()?;
    let payload = r.var_bytes()?;
    r.done()?;

    let mut p = Reader::new(payload);
    let cb_version = p.u16()?;
    if cb_version < CBTX_MIN_VERSION {
        return Err(Error::CbTxVersion);
    }
    let height = p.i32()?;
    let height = u32::try_from(height).map_err(|_| Error::CbTxVersion)?;
    p.arr::<32>()?;
    let merkle_root_quorums = p.arr()?;
    let best_cl_height_diff = p.compact()?;
    let best_cl_signature = p.arr()?;
    p.u64()?;
    p.done()?;
    Ok((
        sha256d(tx),
        CbTx {
            height,
            merkle_root_quorums,
            best_cl_height_diff,
            best_cl_signature,
        },
    ))
}

/// An LLMQ final commitment (CFinalCommitment), as committed in merkleRootQuorums.
pub struct Commitment {
    pub llmq_type: u8,
    pub quorum_hash: Hash,
    pub public_key: [u8; 48],
    /// SerializeHash of the commitment: its merkleRootQuorums leaf.
    pub hash: Hash,
}

pub fn parse_commitment(bytes: &[u8]) -> Result<Commitment, Error> {
    let mut r = Reader::new(bytes);
    let version = r.u16()?;
    if version != BASIC_BLS_NON_INDEXED && version != BASIC_BLS_INDEXED {
        return Err(Error::CommitmentVersion);
    }
    let llmq_type = r.u8()?;
    let quorum_hash = r.arr()?;
    if version == BASIC_BLS_INDEXED {
        r.u16()?;
    }
    for _ in 0..2 {
        let bits = r.compact()?;
        r.take(usize::try_from(bits.div_ceil(8)).map_err(|_| Error::Truncated)?)?;
    }
    let public_key = r.arr()?;
    r.arr::<32>()?;
    r.arr::<96>()?;
    r.arr::<96>()?;
    r.done()?;
    Ok(Commitment {
        llmq_type,
        quorum_hash,
        public_key,
        hash: sha256d(bytes),
    })
}

/// Fold a Bitcoin-style merkle branch from `leaf` at position `index`.
pub fn fold_branch(leaf: Hash, branch: &[Hash], index: u32) -> Result<Hash, Error> {
    if branch.len() > 31 || (index as u64) >> branch.len() != 0 {
        return Err(Error::BadBranch);
    }
    let mut h = leaf;
    let mut buf = [0u8; 64];
    for (level, sib) in branch.iter().enumerate() {
        if (index >> level) & 1 == 1 {
            buf[..32].copy_from_slice(sib);
            buf[32..].copy_from_slice(&h);
        } else {
            buf[..32].copy_from_slice(&h);
            buf[32..].copy_from_slice(sib);
        }
        h = sha256d(&buf);
    }
    Ok(h)
}

/// llmq::SignHash: SHA256d(llmqType || quorumHash || requestId || msgHash), internal order.
pub fn llmq_sign_hash(llmq_type: u8, quorum_hash: &Hash, request_id: &Hash, msg_hash: &Hash) -> Hash {
    let mut buf = [0u8; 97];
    buf[0] = llmq_type;
    buf[1..33].copy_from_slice(quorum_hash);
    buf[33..65].copy_from_slice(request_id);
    buf[65..97].copy_from_slice(msg_hash);
    sha256d(&buf)
}

/// ChainLock request id: SerializeHash(pair("clsig", height)).
pub fn chainlock_request_id(height: u32) -> Hash {
    let mut buf = [0u8; 10];
    buf[0] = 5;
    buf[1..6].copy_from_slice(b"clsig");
    buf[6..10].copy_from_slice(&(height as i32).to_le_bytes());
    sha256d(&buf)
}
