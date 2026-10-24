import sys, struct, time; sys.path.insert(0, 'tools')
from quorums import *
from py_ecc.bls import G2Basic
X = int(sys.argv[1])
hdr_next, txs_next = parse_block(get_block(X + 1))
cb = parse_cbtx(txs_next[0]['payload'])
cl_height = X + 1 - 1 - cb['bestCLHeightDiff']
assert cl_height == X, cl_height
block_hash = hdr_next[4:36]          # internal byte order (prev hash of X+1)
sig = cb['bestCLSignature']
req = sha256d(bytes([5]) + b'clsig' + struct.pack('<i', X))
leaves = active_set(X)
cands = [q for q in leaves if q['llmqType'] == 2]
print('chainlock quorum candidates', len(cands))
for q in cands:
    sh = sha256d(bytes([2]) + q['quorumHash'] + req + block_hash)
    t = time.time(); ok = G2Basic.Verify(q['quorumPublicKey'], sh, sig)
    print('quorum', q['quorumHash'][::-1].hex()[:20], 'verify', ok, f'{time.time()-t:.1f}s')
    if ok: break
