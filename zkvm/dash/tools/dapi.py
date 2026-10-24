"""Minimal DAPI client for Dash Platform mainnet: fetch proofs as raw bytes."""
import sys, ssl, socket, json, random, urllib.request
sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__file__), '..', 'gen'))
import grpc, cbor2, base58
import dapi_platform_pb2 as P, dapi_platform_pb2_grpc as PG
import dapi_core_pb2 as C, dapi_core_pb2_grpc as CG

DPNS_CONTRACT = base58.b58decode("GWRSAVFMjXx8HpQFaNJMqBV7MBgMK4br5UESsB4S31Ec")

def evonodes():
    d = json.load(urllib.request.urlopen("https://quorums.mainnet.networks.dash.org/masternodes", timeout=20))
    out = []
    for m in d["data"]:
        if m.get("status") == "ENABLED" and m.get("versionCheck") == "success":
            for a in m.get("addresses", {}).get("platform_https", []):
                out.append(a)
    return out

def channel(addr):
    host, port = addr.rsplit(":", 1)
    pem = ssl.get_server_certificate((host, int(port)), timeout=10).encode()
    creds = grpc.ssl_channel_credentials(root_certificates=pem)
    # certs are issued for the IP; override target name check via the cert's own subject
    return grpc.secure_channel(addr, creds, options=[("grpc.ssl_target_name_override", host), ("grpc.max_receive_message_length", 64 << 20)])
