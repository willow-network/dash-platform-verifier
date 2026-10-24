# Dash Platform verifier

This repository holds an SP1 program and two Ethereum contracts that let a smart contract verify Dash Platform data. The program proves that a Dash username resolves to an identity, along with that identity's credit balance and keys, as of a Platform block. `DashPlatformVerifier` verifies the proof on Ethereum. `DashUsernameEscrow` builds on it: anyone can send a token to a Dash username, and only a holder of one of that identity's keys can claim it.

The only thing the proof trusts is Dash's own consensus, starting from one Core block pinned in the contract. Anyone can submit a proof, and there is no oracle, trusted relayer, or key feed.

## Deployed on Ethereum mainnet

| contract | address |
|---|---|
| DashPlatformVerifier | [`0x34c2B2cF7a64B5541BbAFd99f02f0Ca874114e5d`](https://etherscan.io/address/0x34c2B2cF7a64B5541BbAFd99f02f0Ca874114e5d) |
| DashUsernameEscrow | [`0x2f7042d5c46157CFb3617AB1Ad7C5c1b2D442901`](https://etherscan.io/address/0x2f7042d5c46157CFb3617AB1Ad7C5c1b2D442901) |

Neither contract has an owner or any setter. The verifier pins the SP1 program key `0x00af476dfc655c16341961c2f543487b99b78d39731941486c9b6febb6d05655`, the SP1 Groth16 gateway `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B`, and the bootstrap Core block 2,560,000 (`0000000000000007c3d73af34a556850b5748c66812021a136387bec1dd79675`). The escrow holds USDC.

The first uses:

- `verifyUsername` for the username "paul": [`0xc35c0a12…27e5c5`](https://etherscan.io/tx/0xc35c0a12bc15b98ab1e8c9e4ab785ce2bb19fcb50699b5acd55660f13327e5c5), 307,537 gas.
- A 1 USDC deposit to "paul", claimed by a signature from one of that identity's keys: [`0x2f765b8f…bf731f`](https://etherscan.io/tx/0x2f765b8fc0a6add502abbd5645534bf561040651668dc2d926d4f7ef28bf731f), 389,169 gas.

`contracts/dash-verifier/DEPLOYED.md` has the deploy transactions and every pin.

## What the program verifies

The program (`zkvm/dash/program`, logic in `zkvm/dash/core`) takes a Core block the contract already trusts and works forward from it.

1. **Core start.** The block's 80-byte header, hashed with X11, and its coinbase (CbTx v3) proven into the header's merkle root. That gives the block's `merkleRootQuorums`, the merkle root of every active LLMQ final commitment.
2. **ChainLock walk.** Each step is a later block, at most 288 blocks on, with a ChainLock signed by an LLMQ_400_60 quorum. That quorum's commitment must be in the previous block's `merkleRootQuorums`.
3. **Platform's Core block.** Platform commits to a Core height. That block is linked to the walk's last block by up to 64 headers, since a ChainLock also locks its ancestors and not every block gets its own.
4. **Platform quorum.** The LLMQ_100_67 quorum that signed the Platform block must be in that Core block's `merkleRootQuorums`.
5. **Platform signature.** The quorum's threshold signature on the Tenderdash commit, which binds the state root (`app_hash`), height, round, time, Core height, protocol version, and chain id.
6. **GroveDB.** Drive's own verifiers (dashpay/platform v4.1.1) read the DPNS `domain` document for the username and the full identity it points to. Both proofs must give the same signed `app_hash`.

The public values are `abi.encode(DashUsernameStatement)` (`zkvm/dash/core/src/statement.rs`): the Core blocks at both ends of the walk, the Platform height, time, protocol version, and `app_hash`, the username, the identity id, balance, and revision, and every enabled secp256k1 key with its purpose, security level, and Ethereum address. After a proof verifies, the contract also trusts the walk's last Core block, so the next proof can start there.

## What it trusts

- **The bootstrap Core block** pinned in the verifier at deployment. Every later start block is one that an earlier proof walked to.
- **Dash's quorums.** 60% of the 400 masternodes in a ChainLock quorum and 67% of the 100 in a Platform quorum must be honest. Dash has no slashing, so this is an honest-majority assumption.
- **The program key** pinned in the verifier. The next section rebuilds the program and its key from this source.
- **SP1's Groth16 verifier** behind the gateway, and the dependencies pinned in the `Cargo.lock` files, among them Drive and DPP from dashpay/platform v4.1.1 and SP1 6.8.1.

It doesn't trust the Dash nodes the inputs come from, or whoever runs the prover. A wrong input fails inside the proof.

## The escrow

- `deposit(normalizedLabel, amount)` holds the tokens for a DPNS normalized label (for example "pau1" for "paul", since DPNS maps o to 0 and i and l to 1).
- `claim(id, to, publicValues, proofBytes, keyId, signature)` pays out when the proof verifies, its username matches the deposit, its Platform block is no older than the deposit, and `signature` is a Dash signed-message signature over `claimMessage(id, to)` by key `keyId`. The key must be an authentication or transfer key at HIGH security or above. The claim text names the deposit, the recipient, the escrow, and the chain, so a signature can't be replayed elsewhere.
- `refund(id)` returns an unclaimed deposit to the depositor after 30 days.

`zkvm/dash/tools/sign_claim.py` signs a claim on the claimant's own machine. It takes the key from a hidden prompt, from a recovery phrase (identity keys at the DIP-13 path), or from a local key file, refuses any key but the one named, and prints only the address and the signature.

## Rebuild the program and its key

The ELF comes from SP1's docker build, which mounts the repository at a fixed path, so the result doesn't depend on where the checkout lives. You need docker and the SP1 toolchain (`sp1up --version v6.8.1`). From the repository root:

```bash
scripts/build-guest-reproducible.sh dash-username --expect 5c3ecc18bd716083d3d72f89a35919f93a262ff45dd248980fbe973193748c89
cd zkvm/dash/prove && cargo run --release -- vkey <path to the ELF it printed>
```

The ELF is 4,166,512 bytes, and its key is `0x00af476dfc655c16341961c2f543487b99b78d39731941486c9b6febb6d05655`. The script pins the image (`ghcr.io/succinctlabs/sp1:v6.8.1` at `sha256:e672d7160039916f40a6a4c2ea4cb0c8cd3dab120fdb24d08560d386ad8f59c2`), and `--twice` rebuilds from a second path and requires the same bytes.

`zkvm/dash/core` and `zkvm/dash/program` aren't reformatted (their `rustfmt.toml` turns it off), because moving a line moves the panic locations compiled into the ELF.

## Tests

```bash
cd zkvm/dash && cargo test --release -p dash-lane-core -- --include-ignored
```

This runs the verifier natively on real mainnet inputs, including the two that were proven on Ethereum. It then tampers with every link of the chain and flips every byte of both GroveDB proofs. The program must refuse each change, except a changed start block, which must show up in the statement so the contract refuses it.

```bash
cd contracts/dash-verifier
forge install foundry-rs/forge-std@v1.16.2 --no-git
forge test
```

`RPC_MAINNET=<url>` adds a fork test that verifies the real proof against the live SP1 gateway. `RPC_MAINNET_ARCHIVE=<archive url>` adds one that replays the live claim against the deployed escrow, one block before it landed.

## Make a proof

The Python tools in `zkvm/dash/tools` fetch everything from public Dash nodes (DAPI on evonodes' port 443) and build the program's input. From `zkvm/dash`:

```bash
python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt
.venv/bin/python -m grpc_tools.protoc -I tools/protos --python_out=gen --grpc_python_out=gen \
  tools/protos/dapi_core.proto tools/protos/dapi_platform.proto
.venv/bin/python tools/save_fixture.py pau1              # DPNS and identity proofs from one Platform block
.venv/bin/python tools/export_platform.py fixtures/pau1  # run after every save_fixture
.venv/bin/python tools/build_input.py fixtures/pau1 <trusted Core height>   # prints <input>.json
cargo run --release -p dash-execrun -- <input>.json      # writes <input>.json.stdin.bin and .public.bin
cargo run --release --manifest-path prove/Cargo.toml -- prove <elf> <input>.json.stdin.bin <input>.json.public.bin proof.json groth16
```

The start height must be the bootstrap block or one that an earlier proof walked to (the verifier's `CoreBlockTrusted` events). `tools/prove-username` runs the whole pipeline. The input builder rebuilds each block's quorum set from mined commitments and verifies it against the CbTx root. Core still counts the last 24 LLMQ_50_60 commitments, which were mined in 2022 before that quorum type stopped running, and `fixtures/llmq50-last24.json` holds them.

Measured on the mainnet proofs: about 10 ms natively, 14.85M SP1 cycles for one ChainLock step and 20.61M for two, and 903 s and 1,150 s for the Groth16 proof on a 16-vCPU CPU machine with 128 GB of memory (32 GB ran out).

## Layout

- `zkvm/dash/core`: the verification logic, shared by the program and the native runner, with the tests.
- `zkvm/dash/program`: the SP1 program.
- `zkvm/dash/execrun`: the native runner. It prints the statement and writes the public values and the program's input.
- `zkvm/dash/prove`: the SP1 host (key, execute, and prove).
- `zkvm/dash/tools`: input fetching and claim signing.
- `zkvm/dash/fixtures`: real mainnet inputs and the two Groth16 proofs used on Ethereum.
- `contracts/dash-verifier`: the contracts, their tests, and the deploy script.
- `scripts/build-guest-reproducible.sh`: the reproducible ELF build.

## License

MIT, Copyright (c) 2026 Willow Core, Inc. Vendored code keeps its own MIT license: the X11 hash in `zkvm/dash/core/x11` (from dashpay/rs-x11-hash), the DAPI protos in `zkvm/dash/tools/protos` (from dashpay/platform), and `ISP1Verifier.sol` (from succinctlabs/sp1-contracts).
