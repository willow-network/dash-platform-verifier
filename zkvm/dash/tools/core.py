"""Dash Core block/tx parsing (consensus serialization) + DAPI Core fetch."""
import hashlib, io, struct, sys, os, random
sys.path.insert(0, os.path.dirname(__file__))
from dapi import *

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

class R:
    def __init__(s, b): s.b = b; s.i = 0
    def read(s, n):
        if s.i + n > len(s.b): raise ValueError("short read")
        v = s.b[s.i:s.i+n]; s.i += n; return v
    def u8(s): return s.read(1)[0]
    def u16(s): return struct.unpack('<H', s.read(2))[0]
    def u32(s): return struct.unpack('<I', s.read(4))[0]
    def i32(s): return struct.unpack('<i', s.read(4))[0]
    def u64(s): return struct.unpack('<Q', s.read(8))[0]
    def cs(s):
        n = s.u8()
        if n < 0xfd: return n
        if n == 0xfd: return s.u16()
        if n == 0xfe: return s.u32()
        return s.u64()
    def vb(s): return s.read(s.cs())

def parse_tx(r):
    start = r.i
    ver = r.u32(); version = ver & 0xffff; txtype = ver >> 16
    vin = []
    for _ in range(r.cs()):
        prev = r.read(32); idx = r.u32(); script = r.vb(); seq = r.u32()
        vin.append((prev, idx, script, seq))
    vout = []
    for _ in range(r.cs()):
        val = r.u64(); script = r.vb(); vout.append((val, script))
    locktime = r.u32()
    payload = r.vb() if (version >= 3 and txtype != 0) else b''
    raw = r.b[start:r.i]
    return dict(version=version, type=txtype, vin=vin, vout=vout, locktime=locktime, payload=payload, raw=raw, txid=sha256d(raw))

def parse_block(b):
    r = R(b)
    header = r.read(80)
    txs = [parse_tx(r) for _ in range(r.cs())]
    assert r.i == len(b), (r.i, len(b))
    return header, txs

def parse_cbtx(payload):
    r = R(payload)
    d = dict(version=r.u16(), height=r.i32(), merkleRootMNList=r.read(32))
    if d['version'] >= 2: d['merkleRootQuorums'] = r.read(32)
    if d['version'] >= 3:
        d['bestCLHeightDiff'] = r.cs(); d['bestCLSignature'] = r.read(96); d['creditPoolBalance'] = struct.unpack('<q', r.read(8))[0]
    assert r.i == len(payload)
    return d

def parse_bits(r, n):
    nbytes = (n + 7) // 8
    return r.read(nbytes)

def parse_commitment(r):
    start = r.i
    d = dict(nVersion=r.u16(), llmqType=r.u8(), quorumHash=r.read(32))
    if d['nVersion'] in (2, 4): d['quorumIndex'] = r.u16()
    n = r.cs(); d['signers'] = parse_bits(r, n); d['signers_n'] = n
    n = r.cs(); d['validMembers'] = parse_bits(r, n); d['valid_n'] = n
    d['quorumPublicKey'] = r.read(48); d['quorumVvecHash'] = r.read(32)
    d['quorumSig'] = r.read(96); d['membersSig'] = r.read(96)
    d['raw'] = r.b[start:r.i]; d['hash'] = sha256d(d['raw'])
    return d

def parse_qc_payload(payload):
    r = R(payload)
    d = dict(version=r.u16(), height=r.u32())
    d['commitment'] = parse_commitment(r)
    assert r.i == len(payload), (r.i, len(payload))
    return d

def merkle_root(hashes):
    lvl = list(hashes)
    if not lvl: return b'\0' * 32
    while len(lvl) > 1:
        if len(lvl) % 2: lvl.append(lvl[-1])
        lvl = [sha256d(lvl[i] + lvl[i+1]) for i in range(0, len(lvl), 2)]
    return lvl[0]

def merkle_branch(hashes, idx):
    lvl = list(hashes); br = []
    while len(lvl) > 1:
        if len(lvl) % 2: lvl.append(lvl[-1])
        br.append(lvl[idx ^ 1]); idx >>= 1
        lvl = [sha256d(lvl[i] + lvl[i+1]) for i in range(0, len(lvl), 2)]
    return br

import threading, time
_pool = []; _pool_lock = threading.Lock(); _rr = [0]
def _init_pool(n=24):
    nodes = evonodes(); random.shuffle(nodes)
    for addr in nodes:
        if len(_pool) >= n: break
        try:
            st = CG.CoreStub(channel(addr)); st.getBestBlockHeight(C.GetBestBlockHeightRequest(), timeout=8)
            _pool.append(st)
        except Exception: pass

def core_stub():
    with _pool_lock:
        if not _pool: _init_pool()
        _rr[0] += 1
        return _pool[_rr[0] % len(_pool)]

def get_block(height):
    cache = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'core-blocks', f'{height}.bin')
    if os.path.exists(cache): return open(cache, 'rb').read()
    for attempt in range(12):
        try:
            b = core_stub().getBlock(C.GetBlockRequest(height=height), timeout=30).block
            break
        except Exception:
            time.sleep(0.5 + attempt * 0.5)
    else:
        raise RuntimeError(f"getBlock {height} failed")
    os.makedirs(os.path.dirname(cache), exist_ok=True); open(cache, 'wb').write(b)
    return b
