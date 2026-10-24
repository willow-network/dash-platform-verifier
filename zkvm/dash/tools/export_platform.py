"""Export saved DAPI responses (protobuf) to a flat JSON the Rust tools read."""
import sys, json; sys.path.insert(0, 'tools')
from dapi import *
d = sys.argv[1]
def meta(m): return dict(height=m.height, core_chain_locked_height=m.core_chain_locked_height, epoch=m.epoch, time_ms=m.time_ms, protocol_version=m.protocol_version, chain_id=m.chain_id)
def pf(p): return dict(grovedb_proof=p.grovedb_proof.hex(), quorum_hash=p.quorum_hash.hex(), signature=p.signature.hex(), round=p.round, block_id_hash=p.block_id_hash.hex(), quorum_type=p.quorum_type)
dp = P.GetDocumentsResponse.FromString(open(f"{d}/dpns_response.pb", "rb").read()).v0
ip = P.GetIdentityResponse.FromString(open(f"{d}/identity_response.pb", "rb").read()).v0
info = json.load(open(f"{d}/info.json"))
out = dict(label=info['label'], owner=info['owner'], dpns=dict(metadata=meta(dp.metadata), proof=pf(dp.proof)), identity=dict(metadata=meta(ip.metadata), proof=pf(ip.proof)))
json.dump(out, open(f"{d}/platform.json", "w"), indent=1)
print("wrote", f"{d}/platform.json")
