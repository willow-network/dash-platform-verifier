# Dash lane: Dash Platform data, verified on Ethereum

One SP1 program proves that a Dash username (DPNS) resolves to an identity, with that identity's
credit balance and keys, as of a Platform block. `DashPlatformVerifier` (contracts/dash-verifier)
verifies the proof on Ethereum. The trust root is Dash's own consensus, and no key feed is involved.
`DashUsernameEscrow` builds on it: anyone can send a token to a Dash username, and only a holder of
one of that identity's keys can claim it.

Both contracts are live on Ethereum mainnet; see contracts/dash-verifier/DEPLOYED.md.

## What the program verifies

1. **Core start.** The 80-byte header of a Core block the contract already trusts, hashed with X11,
   and its coinbase (CbTx v3) proven into the header's merkle root. That gives the block's
   `merkleRootQuorums`, the merkle root of every active LLMQ final commitment.
2. **ChainLock walk.** Each step is a later block, at most 288 blocks on, whose ChainLock
   (`SHA256d(llmqType ‖ quorumHash ‖ SHA256d("clsig", height) ‖ blockHash)`, BLS basic scheme) is
   signed by an LLMQ_400_60 quorum. That quorum's commitment must be in the previous block's
   `merkleRootQuorums`.
3. **Platform's Core block.** Platform commits to a Core height (`core_chain_locked_height`). That
   block is linked to the walk's last block by up to 64 headers (a ChainLock also locks its
   ancestors, and not every block gets its own).
4. **Platform quorum.** The LLMQ_100_67 quorum that signed the Platform block must be in that Core
   block's `merkleRootQuorums`, and the quorum type is pinned to 4.
5. **Platform signature.** The quorum's threshold signature on the Tenderdash precommit, which binds
   the state root (`app_hash`), height, round, time, core height, protocol version, and chain id.
6. **GroveDB.** Drive v4.1.1's own verifiers read the DPNS `domain` document and the full identity.
   Both proofs must give the same signed `app_hash`.

The public values are `abi.encode(DashUsernameStatement)` (core/src/statement.rs). The contract
trusts the walk's last Core block afterwards, so the next proof can start there.

## Trust

- The bootstrap Core block pinned in the contract at deployment.
- The quorums involved having an honest threshold: 60% of 400 for ChainLocks, 67% of 100 for Platform.
  Dash has no slashing, so this is an honest-majority assumption, not an economic one.

## Commands

```bash
cargo test --release -p dash-lane-core                 # real mainnet fixtures and every tamper case
cargo test --release -p dash-lane-core -- --ignored    # every GroveDB proof byte is load-bearing
cargo run --release -p dash-execrun -- <input.json>    # native run: statement, public values, stdin blob
scripts/build-guest-reproducible.sh dash-username      # the ELF whose vkey may be pinned (from repo root)
cd prove && cargo run --release -- execute <elf> <stdin.bin> <public.bin>
cd prove && cargo run --release -- prove <elf> <stdin.bin> <public.bin> <out.json> groth16
```

`core/` and `program/` are not reformatted (their `rustfmt.toml` disables it): the mainnet vkey pins
this exact source, and moving a line moves the panic locations compiled into the ELF.

## Inputs

The Python tools in `tools/` fetch everything from public Dash nodes (DAPI Platform and Core gRPC on
evonodes' port 443) and build the guest input. Run them from this directory:

```bash
python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt
.venv/bin/python -m grpc_tools.protoc -I tools/protos --python_out=gen --grpc_python_out=gen \
  tools/protos/dapi_core.proto tools/protos/dapi_platform.proto
.venv/bin/python tools/save_fixture.py pau1              # DPNS + identity proofs from one Platform block
.venv/bin/python tools/export_platform.py fixtures/pau1  # must run after every save_fixture
.venv/bin/python tools/build_input.py fixtures/pau1 <trusted core height>
.venv/bin/python tools/quorums.py <core height>          # rebuild a block's quorum root, compare to its CbTx
```

`tools/protos` is copied unchanged from dashpay/platform v4.1.1 (`packages/dapi-grpc/protos`, MIT),
renamed so the generated modules don't shadow Python's `platform` module. `tools/prove-username`
runs the whole pipeline. `tools/sign_claim.py` signs an escrow claim with an identity key on the
claimant's own machine and prints only the address and the signature.

The input builder rebuilds each block's active quorum set from mined commitments and verifies it
against the CbTx root. Core still counts the last 24 LLMQ_50_60 commitments, which were mined in
2022 before that type stopped running; `fixtures/llmq50-last24.json` holds them
(`tools/llmq50_last24.py` regenerates it).

## Measured

- Native verify: about 10 ms.
- SP1 execution of the minted ELF: 14.85M cycles for one ChainLock step, 20.61M for two.
- Groth16 on CPU (16 vCPU, 128 GB): 903 s and 1,150 s for the two mainnet proofs.
- Ethereum gas: `verifyUsername` 307,537 for the whole transaction; the escrow claim, which verifies
  a proof too, 389,169.

## C code

The guest links C: the vendored sph X11 (core/x11, from dashpay/rs-x11-hash, MIT) and secp256k1-sys
through Dash's dpp. `.cargo/config.toml` builds both with clang, which the pinned mint image ships.
