// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ISP1Verifier} from "../src/ISP1Verifier.sol";
import {DashPlatformVerifier, DashUsernameStatement} from "../src/DashPlatformVerifier.sol";

contract AcceptAll is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}

contract RejectAll is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {
        revert("bad proof");
    }
}

/// Feeds the public values the Rust guest logic emitted for the real mainnet fixture
/// (zkvm/dash/fixtures/pau1-2559855.*) through the contract.
contract DashPlatformVerifierKat is Test {
    bytes32 constant START = 0x6fb096fdc9d330f0674bd7e375a3d21fb9f74cbd3603ba561c00000000000000;
    bytes32 constant END = 0xf62b3ff2e6cf34dc17cf3bae52a86da403c8eb741c1d39e90500000000000000;
    bytes publicValues;

    function setUp() public {
        publicValues = vm.readFileBinary("../../zkvm/dash/fixtures/pau1-2559855.public.bin");
    }

    function test_realStatementDecodes() public {
        DashPlatformVerifier v = new DashPlatformVerifier(new AcceptAll(), bytes32(uint256(1)), START, 2_559_855);
        DashUsernameStatement memory s = v.verifyUsername(publicValues, "");
        assertEq(s.kind, 0x5101);
        assertEq(s.label, "paul");
        assertEq(s.normalizedLabel, "pau1");
        assertEq(s.identityId, 0xbd5d1db32bd4fb1e3e00e830146e9211325379be0c3f377f679ddada618e9399);
        assertEq(s.balance, 16_391_536_400);
        assertEq(s.platformHeight, 457_136);
        assertEq(s.coreEndHash, END);
        assertEq(s.keys.length, 8);
        assertEq(s.keys[1].ethAddress, 0x37E909B01ccfAAF7e2f83f1f651be96d31E03247);
        assertEq(v.trustedCoreHeight(END), 2_559_955);
    }

    function test_untrustedStartIsRefused() public {
        DashPlatformVerifier v = new DashPlatformVerifier(new AcceptAll(), bytes32(uint256(1)), END, 2_559_955);
        vm.expectRevert(abi.encodeWithSelector(DashPlatformVerifier.UntrustedStart.selector, START, uint32(2_559_855)));
        v.verifyUsername(publicValues, "");
    }

    function test_startHeightMustMatch() public {
        DashPlatformVerifier v = new DashPlatformVerifier(new AcceptAll(), bytes32(uint256(1)), START, 2_559_854);
        vm.expectRevert(abi.encodeWithSelector(DashPlatformVerifier.UntrustedStart.selector, START, uint32(2_559_855)));
        v.verifyUsername(publicValues, "");
    }

    function test_invalidProofIsRefused() public {
        DashPlatformVerifier v = new DashPlatformVerifier(new RejectAll(), bytes32(uint256(1)), START, 2_559_855);
        vm.expectRevert(bytes("bad proof"));
        v.verifyUsername(publicValues, "");
    }

    function test_endBlockBecomesAStart() public {
        DashPlatformVerifier v = new DashPlatformVerifier(new AcceptAll(), bytes32(uint256(1)), START, 2_559_855);
        v.verifyUsername(publicValues, "");
        DashUsernameStatement memory s = abi.decode(publicValues, (DashUsernameStatement));
        s.coreStartHash = END;
        s.coreStartHeight = 2_559_955;
        v.verifyUsername(abi.encode(s), "");
    }

    function test_wrongKindIsRefused() public {
        DashPlatformVerifier v = new DashPlatformVerifier(new AcceptAll(), bytes32(uint256(1)), START, 2_559_855);
        DashUsernameStatement memory s = abi.decode(publicValues, (DashUsernameStatement));
        s.kind = 0x5102;
        vm.expectRevert(abi.encodeWithSelector(DashPlatformVerifier.WrongKind.selector, uint16(0x5102)));
        v.verifyUsername(abi.encode(s), "");
    }
}
