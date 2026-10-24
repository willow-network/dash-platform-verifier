import sys, json, os, time
sys.path.insert(0, 'tools')
from dapi import *
from fetch_name import get_channel, dpns_query

label = sys.argv[1]
addr, ch = get_channel(); stub = PG.PlatformStub(ch)
out = f"fixtures/{label}"; os.makedirs(out, exist_ok=True)
r = dpns_query(stub, label, False)
if not r.documents.documents:
    raise SystemExit(f"{label}.dash is not registered")
doc = r.documents.documents[0]
owner = doc[33:65]
for attempt in range(10):
    rp = dpns_query(stub, label, True)
    ri = stub.getIdentity(P.GetIdentityRequest(v0=P.GetIdentityRequest.GetIdentityRequestV0(id=owner, prove=True)), timeout=20).v0
    if rp.proof.signature == ri.proof.signature:
        break                                  # both proofs are against the same signed block
    time.sleep(2)
else:
    raise SystemExit("could not get both proofs from one Platform block")
open(f"{out}/dpns_response.pb", "wb").write(P.GetDocumentsResponse(v0=rp).SerializeToString())
open(f"{out}/identity_response.pb", "wb").write(P.GetIdentityResponse(v0=ri).SerializeToString())
meta = lambda m: dict(height=m.height, core_chain_locked_height=m.core_chain_locked_height, epoch=m.epoch, time_ms=m.time_ms, protocol_version=m.protocol_version, chain_id=m.chain_id)
pf = lambda p: dict(grovedb_proof_len=len(p.grovedb_proof), quorum_hash=p.quorum_hash.hex(), signature=p.signature.hex(), round=p.round, block_id_hash=p.block_id_hash.hex(), quorum_type=p.quorum_type)
info = dict(node=addr, label=label, doc_id=doc[1:33].hex(), owner=owner.hex(), fetched=time.time(),
            dpns=dict(meta=meta(rp.metadata), proof=pf(rp.proof)), identity=dict(meta=meta(ri.metadata), proof=pf(ri.proof)))
json.dump(info, open(f"{out}/info.json", "w"), indent=1)
print(out)
