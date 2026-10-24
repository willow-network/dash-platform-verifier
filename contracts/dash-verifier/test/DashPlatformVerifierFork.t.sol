// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ISP1Verifier} from "../src/ISP1Verifier.sol";
import {DashPlatformVerifier, DashUsernameStatement} from "../src/DashPlatformVerifier.sol";
import {DashUsernameEscrow} from "../src/DashUsernameEscrow.sol";

/// The real Groth16 proofs of "paul" (minted program, vkey 0x00af476d…) against the live mainnet SP1
/// gateway, on a mainnet fork. Skips without RPC_MAINNET.
contract DashPlatformVerifierFork is Test {
    ISP1Verifier constant GATEWAY = ISP1Verifier(0x397A5f7f3dBd538f23DE225B51f532c34448dA9B);
    bytes32 constant VKEY = 0x00af476dfc655c16341961c2f543487b99b78d39731941486c9b6febb6d05655;
    bytes32 constant BOOT = 0x7596d71dec7b3836a1212081668c74b55068554af33ad7c30700000000000000;

    function test_realProofOnMainnetFork() public {
        string memory rpc = vm.envOr("RPC_MAINNET", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc);
        string memory j = vm.readFile("../../zkvm/dash/fixtures/pau1-2560000.groth16.json");
        bytes memory pv = vm.parseJsonBytes(j, ".public_values");
        bytes memory proof = vm.parseJsonBytes(j, ".proof");
        DashPlatformVerifier v = new DashPlatformVerifier(GATEWAY, VKEY, BOOT, 2_560_000);
        uint256 g = gasleft();
        DashUsernameStatement memory s = v.verifyUsername(pv, proof);
        console2.log("verifyUsername gas", g - gasleft());
        assertEq(s.label, "paul");
        assertEq(s.identityId, 0xbd5d1db32bd4fb1e3e00e830146e9211325379be0c3f377f679ddada618e9399);
        assertEq(s.coreEndHeight, 2_560_019);
        assertEq(v.trustedCoreHeight(s.coreEndHash), 2_560_019);

        proof[40] ^= 0x01;
        vm.expectRevert();
        v.verifyUsername(pv, proof);
    }

    /// Replays the live claim of deposit 0 against the deployed escrow, one block before it landed.
    /// Needs an archive RPC in RPC_MAINNET_ARCHIVE (state at a past block); skips without one.
    function test_realClaimOnMainnetFork() public {
        string memory rpc = vm.envOr("RPC_MAINNET_ARCHIVE", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc, 26_261_368);
        DashUsernameEscrow escrow = DashUsernameEscrow(0x2f7042d5c46157CFb3617AB1Ad7C5c1b2D442901);
        IBalance usdc = IBalance(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        address to = 0x8C06C6a80f1401dB27A81931daC29E613801051e;
        string memory j = vm.readFile("../../zkvm/dash/fixtures/pau1-2560019.groth16.json");
        bytes memory pv = vm.parseJsonBytes(j, ".public_values");
        bytes memory proof = vm.parseJsonBytes(j, ".proof");
        bytes memory sig =
            hex"205a548db518ac243df75bf0f8440cf820ad45f34809f08d6eee3f9cfde137f200027b49647a08e444519da70eea45a93ce944511f98abe3d3019ecfbec075d0b3";
        assertEq(escrow.recoverDashSigner(escrow.claimMessage(0, to), sig), 0x37E909B01ccfAAF7e2f83f1f651be96d31E03247);

        uint256 before = usdc.balanceOf(to);
        escrow.claim(0, to, pv, proof, 1, sig);
        assertEq(usdc.balanceOf(to) - before, 1_000_000);

        vm.expectRevert(DashUsernameEscrow.AlreadySettled.selector);
        escrow.claim(0, to, pv, proof, 1, sig);
    }
}

interface IBalance {
    function balanceOf(address) external view returns (uint256);
}
