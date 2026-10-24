import sys, random, json, os
sys.path.insert(0, 'tools')
from dapi import *

def get_channel():
    nodes = evonodes(); random.shuffle(nodes)
    for addr in nodes:
        try:
            ch = channel(addr); PG.PlatformStub(ch).getStatus(P.GetStatusRequest(v0=P.GetStatusRequest.GetStatusRequestV0()), timeout=10)
            return addr, ch
        except Exception: pass

def dpns_query(stub, label, prove):
    where = cbor2.dumps([["normalizedParentDomainName", "==", "dash"], ["normalizedLabel", "==", label]])
    req = P.GetDocumentsRequest(v0=P.GetDocumentsRequest.GetDocumentsRequestV0(
        data_contract_id=DPNS_CONTRACT, document_type="domain", where=where, limit=1, prove=prove))
    return stub.getDocuments(req, timeout=20).v0

if __name__ == "__main__":
    addr, ch = get_channel(); stub = PG.PlatformStub(ch)
    print("node", addr)
    for label in sys.argv[1:]:
        r = dpns_query(stub, label, False)
        docs = list(r.documents.documents)
        print(label, "docs:", len(docs), [d.hex()[:120] for d in docs])
