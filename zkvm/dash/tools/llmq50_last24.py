"""Find the last 24 mined LLMQ_50_60 commitments and save them to fixtures/llmq50-last24.json."""
import sys, json; sys.path.insert(0, 'tools')
from quorums import *
qs = scan(1736400, 1739200, workers=10)
t1 = sorted([q for q in qs if q['llmqType'] == 1], key=lambda q: q['mined_height'])
print('type1 found', len(t1), 'last mined', [q['mined_height'] for q in t1[-26:]])
json.dump([dict(mined_height=q['mined_height'], payload_height=q['payload_height'], commitment=q['raw'].hex())
           for q in t1[-24:]], open('fixtures/llmq50-last24.json', 'w'), indent=1)
