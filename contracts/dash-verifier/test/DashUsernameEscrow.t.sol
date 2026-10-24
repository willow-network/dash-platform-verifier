// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ISP1Verifier} from "../src/ISP1Verifier.sol";
import {DashPlatformVerifier, DashUsernameStatement, DashKey} from "../src/DashPlatformVerifier.sol";
import {DashUsernameEscrow, IERC20} from "../src/DashUsernameEscrow.sol";

contract AcceptAll is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}

contract MockUSDC is IERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }

    function transferFrom(address from, address to, uint256 a) external returns (bool) {
        balanceOf[from] -= a;
        balanceOf[to] += a;
        return true;
    }
}

contract DashUsernameEscrowTest is Test {
    bytes32 constant START = keccak256("start");
    uint256 constant KEY = 0xA11CE;
    DashPlatformVerifier dash;
    DashUsernameEscrow escrow;
    MockUSDC usdc;
    address sender = address(0xBEEF);
    address recipient = address(0xCAFE);

    function setUp() public {
        vm.warp(1_792_700_000);
        dash = new DashPlatformVerifier(new AcceptAll(), bytes32(uint256(1)), START, 100);
        usdc = new MockUSDC();
        escrow = new DashUsernameEscrow(dash, usdc);
        usdc.mint(sender, 1_000e6);
    }

    function statement(string memory label, uint64 timeMs, uint8 purpose, uint8 security)
        internal
        view
        returns (bytes memory)
    {
        DashKey[] memory keys = new DashKey[](2);
        keys[0] = DashKey(0, 0, 0, address(0x1234));
        keys[1] = DashKey(7, purpose, security, vm.addr(KEY));
        return abi.encode(
            DashUsernameStatement(
                0x5101,
                100,
                START,
                150,
                keccak256("end"),
                457_136,
                timeMs,
                13,
                bytes32(0),
                label,
                label,
                keccak256("identity"),
                0,
                1,
                keys
            )
        );
    }

    function dashSign(uint256 key, string memory message) internal pure returns (bytes memory) {
        bytes32 digest = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(uint8(25), "DarkCoin Signed Message:\n", uint8(bytes(message).length), message))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(v + 4, r, s);
    }

    function depositFive() internal returns (uint256 id) {
        vm.startPrank(sender);
        id = escrow.deposit("pau1", 5e6);
        vm.stopPrank();
    }

    function test_claimByUsernameKey() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau1", uint64(block.timestamp) * 1000 + 5, 0, 2);
        bytes memory sig = dashSign(KEY, escrow.claimMessage(id, recipient));
        escrow.claim(id, recipient, pv, "", 7, sig);
        assertEq(usdc.balanceOf(recipient), 5e6);
        vm.expectRevert(DashUsernameEscrow.AlreadySettled.selector);
        escrow.claim(id, recipient, pv, "", 7, sig);
    }

    function test_signatureForAnotherRecipientIsRefused() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau1", uint64(block.timestamp) * 1000, 0, 2);
        bytes memory sig = dashSign(KEY, escrow.claimMessage(id, recipient));
        vm.expectRevert(DashUsernameEscrow.BadSignature.selector);
        escrow.claim(id, address(0xD00D), pv, "", 7, sig);
    }

    function test_otherKeyIsRefused() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau1", uint64(block.timestamp) * 1000, 0, 2);
        bytes memory sig = dashSign(0xB0B, escrow.claimMessage(id, recipient));
        vm.expectRevert(DashUsernameEscrow.BadSignature.selector);
        escrow.claim(id, recipient, pv, "", 7, sig);
    }

    function test_wrongUsernameIsRefused() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau2", uint64(block.timestamp) * 1000, 0, 2);
        bytes memory sig = dashSign(KEY, escrow.claimMessage(id, recipient));
        vm.expectRevert(DashUsernameEscrow.WrongUsername.selector);
        escrow.claim(id, recipient, pv, "", 7, sig);
    }

    function test_proofOlderThanDepositIsRefused() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau1", (uint64(block.timestamp) - 1) * 1000, 0, 2);
        bytes memory sig = dashSign(KEY, escrow.claimMessage(id, recipient));
        vm.expectRevert(DashUsernameEscrow.StaleProof.selector);
        escrow.claim(id, recipient, pv, "", 7, sig);
    }

    function test_mediumKeyIsRefused() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau1", uint64(block.timestamp) * 1000, 0, 3);
        bytes memory sig = dashSign(KEY, escrow.claimMessage(id, recipient));
        vm.expectRevert(DashUsernameEscrow.KeyNotUsable.selector);
        escrow.claim(id, recipient, pv, "", 7, sig);
    }

    function test_encryptionKeyIsRefused() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau1", uint64(block.timestamp) * 1000, 1, 2);
        bytes memory sig = dashSign(KEY, escrow.claimMessage(id, recipient));
        vm.expectRevert(DashUsernameEscrow.KeyNotUsable.selector);
        escrow.claim(id, recipient, pv, "", 7, sig);
    }

    function test_unknownKeyIdIsRefused() public {
        uint256 id = depositFive();
        bytes memory pv = statement("pau1", uint64(block.timestamp) * 1000, 0, 2);
        bytes memory sig = dashSign(KEY, escrow.claimMessage(id, recipient));
        vm.expectRevert(DashUsernameEscrow.KeyNotUsable.selector);
        escrow.claim(id, recipient, pv, "", 9, sig);
    }

    function test_refundAfterDelay() public {
        uint256 id = depositFive();
        vm.expectRevert(DashUsernameEscrow.TooEarly.selector);
        escrow.refund(id);
        vm.warp(block.timestamp + 30 days);
        escrow.refund(id);
        assertEq(usdc.balanceOf(sender), 1_000e6);
        vm.expectRevert(DashUsernameEscrow.AlreadySettled.selector);
        escrow.refund(id);
    }

    function test_claimMessageText() public view {
        assertEq(
            escrow.claimMessage(3, address(0xCAFE)),
            string.concat(
                "Willow Dash username escrow\nclaim 3\nto 0x000000000000000000000000000000000000cafe\nescrow ",
                vm.toLowercase(vm.toString(address(escrow))),
                "\nchain 31337"
            )
        );
    }

    /// A signature from zkvm/dash/tools/sign_claim.py (key 0x11..11) recovers to its address.
    function test_signClaimToolVector() public view {
        string memory m =
            "Willow Dash username escrow\nclaim 3\nto 0x000000000000000000000000000000000000cafe\nescrow 0x0000000000000000000000000000000000000001\nchain 1";
        bytes memory sig =
            hex"20ce3bddfb09434f6552e0f751ef6f70ed2a567766411112d2e497af099d3a1926003f9704d93d3fdfa8b70454214934f588deaa6d2e16a4512d6a471d6f35b56a";
        assertEq(escrow.recoverDashSigner(m, sig), 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A);
    }
}
