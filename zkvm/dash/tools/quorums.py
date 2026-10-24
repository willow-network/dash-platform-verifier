"""Reconstruct the active LLMQ commitment set at a Core block, checked against its CbTx merkleRootQuorums."""
import sys, os, json
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(__file__))
from core import *

# mainnet params: type -> (signingActiveQuorumCount, rotation)
PARAMS = {1: (24, False), 2: (4, False), 3: (4, False), 4: (24, False), 5: (32, True)}

def commitments_in(height):
    hdr, txs = parse_block(get_block(height))
    out = []
    for t in txs[1:]:
        if t['type'] == 6:
            p = parse_qc_payload(t['payload']); q = p['commitment']
            if any(q['signers']) or any(q['validMembers']):
                q['mined_height'] = height; q['payload_height'] = p['height']; out.append(q)
    return out

def scan(lo, hi, workers=8):
    with ThreadPoolExecutor(workers) as ex:
        res = list(ex.map(commitments_in, range(lo, hi + 1)))
    return [q for r in res for q in r]

def llmq50_last24():
    """The last 24 mined LLMQ_50_60 commitments (fixtures/llmq50-last24.json, from llmq50_last24.py)."""
    path = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'llmq50-last24.json')
    out = []
    for e in json.load(open(path)):
        q = parse_commitment(R(bytes.fromhex(e['commitment'])))
        q['mined_height'] = e['mined_height']; q['payload_height'] = e['payload_height']; out.append(q)
    return out

def active_set(X, window=3200):
    qs = scan(X - window, X)
    by = {}
    for q in qs: by.setdefault(q['llmqType'], []).append(q)
    by.setdefault(1, [])
    if len(by[1]) < PARAMS[1][0]:
        # LLMQ_50_60 stopped DKGs at DIP0024 (~1.738M); Core still counts its last 24 mined commitments.
        by[1] = llmq50_last24() + by[1]
    leaves = []
    for t, lst in by.items():
        n, rot = PARAMS[t]
        lst.sort(key=lambda q: q['mined_height'])
        if rot:
            latest = {}
            for q in lst: latest[q['quorumIndex']] = q
            chosen = list(latest.values())
        else:
            chosen = lst[-n:]
        leaves += chosen
    return leaves

if __name__ == "__main__":
    X = int(sys.argv[1])
    hdr, txs = parse_block(get_block(X)); cb = parse_cbtx(txs[0]['payload'])
    leaves = active_set(X)
    hashes = sorted(q['hash'] for q in leaves)
    root = merkle_root(hashes)
    from collections import Counter
    print('leaves', len(leaves), Counter(q['llmqType'] for q in leaves))
    print('computed', root[::-1].hex()); print('cbtx    ', cb['merkleRootQuorums'][::-1].hex())
    print('MATCH' if root == cb['merkleRootQuorums'] else 'MISMATCH')
