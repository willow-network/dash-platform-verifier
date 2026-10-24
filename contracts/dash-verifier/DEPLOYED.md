# Deployed on Ethereum mainnet, 2026-10-23

| contract | address | tx | block | gas |
|---|---|---|---:|---:|
| DashPlatformVerifier | `0x34c2B2cF7a64B5541BbAFd99f02f0Ca874114e5d` | `0xc1fd24d208b07c169b33105e8346c54b5e0959f04651a28b0cd588274b7ccd04` | 26,255,217 | 705,117 |
| DashUsernameEscrow | `0x2f7042d5c46157CFb3617AB1Ad7C5c1b2D442901` | `0xe79a804a0f7a32bd5430b82a0b5e5638be053fda87a122dfcd220991457efe72` | 26,255,218 | 1,481,403 |

Deployer `0x8C06C6a80f1401dB27A81931daC29E613801051e`. Neither contract has an owner or any setter.

Pins (read back from chain after deploy):
- `sp1Verifier` = `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B`, the canonical SP1 Groth16 gateway. Route `0x4388a21c` (v6.1.0 Groth16) goes to `0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2`, not frozen.
- `programVKey` = `0x00af476dfc655c16341961c2f543487b99b78d39731941486c9b6febb6d05655`, the reproducible mint of `dash-username`:
  - `scripts/build-guest-reproducible.sh dash-username --twice`, byte-identical across two checkout paths.
  - ELF sha256 `5c3ecc18bd716083d3d72f89a35919f93a262ff45dd248980fbe973193748c89` (4,166,512 bytes).
  - Image `ghcr.io/succinctlabs/sp1:v6.8.1@sha256:e672d716…59c2`.
  - Rebuild it with `scripts/build-guest-reproducible.sh dash-username --expect 5c3ecc18bd716083d3d72f89a35919f93a262ff45dd248980fbe973193748c89`.
- Bootstrap Core block 2,560,000:
  - Internal-order hash `0x7596d71dec7b3836a1212081668c74b55068554af33ad7c30700000000000000`.
  - Explorer form `0000000000000007c3d73af34a556850b5748c66812021a136387bec1dd79675`.
  - ChainLocked by LLMQ_400_60 `0000000000000029aba1…`.
- Escrow `token` = USDC `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`; `dash` = the verifier above.

Before deploy, the real "paul" proof (zkvm/dash/fixtures/pau1-2560000.groth16.json) verified against the live gateway via eth_call (275K gas). `test/DashPlatformVerifierFork.t.sol` runs verifyUsername with it on a mainnet fork: 275,507 gas, and a one-byte change reverts.

## Live use

| what | tx | block | gas |
|---|---|---:|---:|
| `verifyUsername` for "paul" (Platform 457,223; Core walk to 2,560,019) | `0xc35c0a12bc15b98ab1e8c9e4ab785ce2bb19fcb50699b5acd55660f13327e5c5` | 26,256,222 | 307,537 |
| `deposit` of 1 USDC to "pau1" (deposit 0) | `0x87055696815e37e6937e4492b5b698985473a3d31542a7e595a3daf0de061eb7` | 26,261,207 | 159,280 |
| `claim` of deposit 0, signed with identity key 1 (Platform 457,743; Core walk 2,560,019 → 2,560,534) | `0x2f765b8fc0a6add502abbd5645534bf561040651668dc2d926d4f7ef28bf731f` | 26,261,369 | 389,169 |

The claim's proof is zkvm/dash/fixtures/pau1-2560019.groth16.json. `test_realClaimOnMainnetFork` replays the claim against the live escrow one block before it landed (needs an archive RPC in `RPC_MAINNET_ARCHIVE`).
