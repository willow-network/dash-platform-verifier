"""Build the Dash username guest input (JSON, hex) from a saved Platform fixture.

usage: build_input.py <fixture dir> <start core height>
Walks ChainLocks from the start block to the Platform commit's core_chain_locked_height,
in steps of at most MAX_STEP blocks, picking each step's signer from the previous block's
active quorum set.
"""
import sys, os, json, struct; sys.path.insert(0, 'tools')
from quorums import *
from py_ecc.bls import G2Basic

MAX_STEP = 288

def block_witness(h):
    hdr, txs = parse_block(get_block(h))
    txids = [t['txid'] for t in txs]
    assert merkle_root(txids) == hdr[36:68]
    return dict(header=hdr.hex(), coinbase=txs[0]['raw'].hex(), coinbase_branch=[x.hex() for x in merkle_branch(txids, 0)])

def quorum_witness(leaves, q):
    hashes = sorted(x['hash'] for x in leaves)
    i = hashes.index(q['hash'])
    return dict(commitment=q['raw'].hex(), branch=[x.hex() for x in merkle_branch(hashes, i)], index=i)

def chainlock(h):
    """The ChainLock for block h from a later coinbase's bestCL, or None (not every block gets one)."""
    for k in range(h + 1, h + 12):
        _, txs = parse_block(get_block(k))
        cb = parse_cbtx(txs[0]['payload'])
        if k - 1 - cb['bestCLHeightDiff'] == h:
            return cb['bestCLSignature']
        if k - 1 - cb['bestCLHeightDiff'] > h:
            return None

def block_hash(h):
    hdr, _ = parse_block(get_block(h + 1))
    return hdr[4:36]

def signer_for(h, prev_leaves):
    sig = chainlock(h)
    if sig is None:
        return None, None
    bh = block_hash(h)
    req = sha256d(bytes([5]) + b'clsig' + struct.pack('<i', h))
    for q in prev_leaves:
        if q['llmqType'] == 2 and G2Basic.Verify(q['quorumPublicKey'], sha256d(bytes([2]) + q['quorumHash'] + req + bh), sig):
            return q, sig
    return None, sig

def main():
    fx, start = sys.argv[1], int(sys.argv[2])
    plat = json.load(open(f"{fx}/platform.json"))
    meta, proof = plat['dpns']['metadata'], plat['dpns']['proof']
    assert plat['identity']['proof']['signature'] == proof['signature'], "proofs from different blocks"
    pb = meta['core_chain_locked_height']
    target = pb + int(os.environ.get('LINK_EXTRA', '0'))   # test hook: lock through a later block
    while chainlock(target) is None:            # lock Platform's block through its first locked descendant
        target += 1
    cur, cur_leaves = start, active_set(start)
    steps = []
    while cur != target:
        nxt = min(cur + MAX_STEP, target)
        while True:
            q, sig = signer_for(nxt, cur_leaves)
            if q: break
            nxt -= 1                       # signer rotated in after `cur`: try an earlier block
            assert nxt > cur, "no reachable ChainLock"
        steps.append(dict(block=block_witness(nxt), signature=sig.hex(), signer=quorum_witness(cur_leaves, q)))
        print(f"step {cur} -> {nxt} signed by {q['quorumHash'][::-1].hex()[:16]}", file=sys.stderr)
        cur, cur_leaves = nxt, active_set(nxt)
    pb_leaves = cur_leaves if pb == cur else active_set(pb)
    qh = bytes.fromhex(proof['quorum_hash'])[::-1]
    pq = [q for q in pb_leaves if q['llmqType'] == 4 and q['quorumHash'] == qh]
    assert len(pq) == 1, "platform quorum not active at the committed core height"
    out = dict(
        start=block_witness(start), steps=steps, platform_block=block_witness(pb),
        link_headers=[parse_block(get_block(h))[0].hex() for h in range(pb + 1, cur + 1)],
        platform_quorum=quorum_witness(pb_leaves, pq[0]),
        commit=dict(height=meta['height'], core_chain_locked_height=pb, time_ms=meta['time_ms'],
                    protocol_version=meta['protocol_version'], chain_id=meta['chain_id'], round=proof['round'],
                    block_id_hash=proof['block_id_hash'], quorum_type=proof['quorum_type'],
                    quorum_hash=proof['quorum_hash'], signature=proof['signature']),
        normalized_label=plat['label'], dpns_proof=proof['grovedb_proof'], identity_proof=plat['identity']['proof']['grovedb_proof'])
    path = f"{fx}/input-from-{start}" + (f"-link{cur - pb}" if cur != pb else "") + ".json"
    json.dump(out, open(path, "w"), indent=1)
    print(path)

main()
