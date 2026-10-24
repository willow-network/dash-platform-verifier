// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ISP1Verifier} from "../src/ISP1Verifier.sol";
import {DashPlatformVerifier} from "../src/DashPlatformVerifier.sol";
import {DashUsernameEscrow, IERC20} from "../src/DashUsernameEscrow.sol";

/// forge script script/Deploy.s.sol --rpc-url mainnet --broadcast
/// env: SP1_VERIFIER, PROGRAM_VKEY, BOOTSTRAP_HASH (internal byte order), BOOTSTRAP_HEIGHT, TOKEN
contract Deploy is Script {
    function run() external {
        ISP1Verifier sp1 = ISP1Verifier(vm.envAddress("SP1_VERIFIER"));
        bytes32 vkey = vm.envBytes32("PROGRAM_VKEY");
        bytes32 bootHash = vm.envBytes32("BOOTSTRAP_HASH");
        uint32 bootHeight = uint32(vm.envUint("BOOTSTRAP_HEIGHT"));
        IERC20 token = IERC20(vm.envAddress("TOKEN"));
        vm.startBroadcast();
        DashPlatformVerifier dash = new DashPlatformVerifier(sp1, vkey, bootHash, bootHeight);
        DashUsernameEscrow escrow = new DashUsernameEscrow(dash, token);
        vm.stopBroadcast();
        console2.log("DashPlatformVerifier", address(dash));
        console2.log("DashUsernameEscrow", address(escrow));
    }
}
