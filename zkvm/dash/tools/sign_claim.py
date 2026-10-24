"""Sign a DashUsernameEscrow claim with a Dash identity key, on your own machine.

usage:
  sign_claim.py key <claim.txt> <identity eth address>      # prompts for the private key (hex or WIF)
  sign_claim.py phrase <claim.txt> <identity eth address>   # prompts for a recovery phrase (DIP-13 identity keys)
  sign_claim.py det <claim.txt|-> <identity eth address> <evo tool db> <identity id hex>
                                                            # key from a Dash Evo Tool database ("-": only check)
  sign_claim.py log <claim.txt|-> <identity eth address> <key log>
                                                            # key from a platform-tui new_identity_private_keys.log

The claim text is DashUsernameEscrow.claimMessage(id, to), byte for byte. The eth address is one of
the identity's keys in the verified statement. With a recovery phrase, the tool derives identity
authentication keys (DIP-13: m/9'/5'/5'/0'/0'/identity'/key', identities and keys 0 to 7) and uses the
one whose address matches. Prompts are hidden; nothing is written to disk or sent anywhere. Prints
the key's address and the 65-byte Dash signed-message signature for `claim(..., keyId, signature)`.
"""
import sys, hashlib, hmac, getpass, unicodedata
import base58, ecdsa
from ecdsa.util import sigencode_string_canonize
from Crypto.Hash import keccak

N = ecdsa.SECP256k1.order

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def eth_address(sk):
    k = keccak.new(digest_bits=256); k.update(sk.get_verifying_key().to_string())
    return "0x" + k.digest()[-20:].hex()

def from_key(s):
    s = s.strip()
    raw = bytes.fromhex(s) if len(s) == 64 else base58.b58decode_check(s)[1:33]
    return ecdsa.SigningKey.from_string(raw, curve=ecdsa.SECP256k1)

def ckd_priv(k, c, i):
    """BIP32 child private key derivation (hardened when i >= 2**31)."""
    if i >= 2**31:
        data = b"\x00" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
    else:
        pub = ecdsa.SigningKey.from_secret_exponent(k, curve=ecdsa.SECP256k1).get_verifying_key().to_string("compressed")
        data = pub + i.to_bytes(4, "big")
    I = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % N, I[32:]

def dip13_keys(phrase, passphrase="", identities=8, keys=8):
    seed = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", phrase).encode(),
                               unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode(), 2048)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    H = 2**31
    for i in (9 + H, 5 + H, 5 + H, 0 + H, 0 + H):
        k, c = ckd_priv(k, c, i)
    for ident in range(identities):
        ki, ci = ckd_priv(k, c, ident + H)
        for key in range(keys):
            kk, _ = ckd_priv(ki, ci, key + H)
            yield ident, key, ecdsa.SigningKey.from_secret_exponent(kk, curve=ecdsa.SECP256k1)

def from_det(db, identity_hex, want):
    """Find the clear-stored private key in a Dash Evo Tool identity row whose address is `want`."""
    import sqlite3
    row = sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
        "select data from identity where hex(id) = ?", (identity_hex.upper(),)).fetchone()
    if row is None:
        sys.exit("identity not in this database")
    blob = row[0]
    for i in range(len(blob) - 31):
        x = int.from_bytes(blob[i:i + 32], "big")
        if 0 < x < N:
            sk = ecdsa.SigningKey.from_secret_exponent(x, curve=ecdsa.SECP256k1)
            if eth_address(sk) == want:
                return sk
    sys.exit("no clear key for " + want + " in this identity (keys may be encrypted)")

def from_log(path, want):
    """Find the private key whose address is `want` in a platform-tui key log (hex or WIF tokens)."""
    import re
    text = open(path, errors="replace").read()
    tokens = re.findall(r"\b[0-9a-fA-F]{64}\b", text) + re.findall(r"\b[1-9A-HJ-NP-Za-km-z]{51,52}\b", text)
    for t in tokens:
        try:
            sk = from_key(t)
        except Exception:
            continue
        if eth_address(sk) == want:
            return sk
    sys.exit("no key for " + want + " in this log")

def main():
    mode, msg_path, want = sys.argv[1], sys.argv[2], sys.argv[3].lower()
    if mode in ("det", "log"):
        sk = from_det(sys.argv[4], sys.argv[5], want) if mode == "det" else from_log(sys.argv[4], want)
        if msg_path == "-":
            print("can sign with", eth_address(sk)); return
    msg = open(msg_path, "rb").read()
    assert len(msg) <= 252, "claim text too long"
    if mode in ("det", "log"):
        pass
    elif mode == "key":
        sk = from_key(getpass.getpass("identity private key (hex or WIF): "))
    else:
        phrase = " ".join(getpass.getpass("recovery phrase: ").split())
        sk = next((s for _, _, s in dip13_keys(phrase) if eth_address(s) == want), None)
        if sk is None:
            sys.exit("no identity key from this phrase matches " + want)
    if eth_address(sk) != want:
        sys.exit(f"this key is {eth_address(sk)}, not {want}")
    magic = b"DarkCoin Signed Message:\n"
    digest = sha256d(bytes([len(magic)]) + magic + bytes([len(msg)]) + msg)
    sig = sk.sign_digest_deterministic(digest, sigencode=sigencode_string_canonize)
    pub = sk.get_verifying_key().to_string()
    recid = [c.to_string() for c in ecdsa.VerifyingKey.from_public_key_recovery_with_digest(sig, digest, ecdsa.SECP256k1)].index(pub)
    print("key address ", eth_address(sk))
    print("signature    0x" + (bytes([31 + recid]) + sig).hex())

main()
