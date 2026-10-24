// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DashPlatformVerifier, DashUsernameStatement, DashKey} from "./DashPlatformVerifier.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title DashUsernameEscrow
/// @author Willow
/// @notice Send a token to a Dash username. Only whoever controls that username's identity on
///         Dash Platform can claim it, by signing the claim with one of the identity's keys.
/// @dev A claim carries a DashPlatformVerifier proof that the username resolves to an identity
///      holding an enabled secp256k1 key, as of a Platform block no older than the deposit, plus
///      that key's Dash signed-message signature over the claim text from `claimMessage`. The
///      depositor can take the funds back after REFUND_DELAY if nobody has claimed them.
contract DashUsernameEscrow {
    uint256 public constant REFUND_DELAY = 30 days;
    uint8 internal constant PURPOSE_AUTHENTICATION = 0;
    uint8 internal constant PURPOSE_TRANSFER = 3;
    uint8 internal constant SECURITY_HIGH = 2;

    DashPlatformVerifier public immutable dash;
    IERC20 public immutable token;

    struct Deposit {
        address from;
        uint64 createdAt;
        bool settled;
        uint256 amount;
        string normalizedLabel;
    }

    mapping(uint256 => Deposit) public deposits;
    uint256 public nextId;

    event Deposited(uint256 indexed id, string normalizedLabel, address indexed from, uint256 amount);
    event Claimed(uint256 indexed id, bytes32 indexed identityId, address to, uint256 amount);
    event Refunded(uint256 indexed id);

    error AlreadySettled();
    error WrongUsername();
    error StaleProof();
    error KeyNotUsable();
    error BadSignature();
    error TooEarly();
    error TransferFailed();

    constructor(DashPlatformVerifier _dash, IERC20 _token) {
        dash = _dash;
        token = _token;
    }

    /// @param normalizedLabel the DPNS normalized label, e.g. "pau1" for "Paul" (under ".dash").
    function deposit(string calldata normalizedLabel, uint256 amount) external returns (uint256 id) {
        id = nextId++;
        deposits[id] = Deposit(msg.sender, uint64(block.timestamp), false, amount, normalizedLabel);
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        emit Deposited(id, normalizedLabel, msg.sender, amount);
    }

    /// @param keyId the identity key that signed `claimMessage(id, to)`.
    /// @param signature 65-byte Dash signed-message signature (header byte, r, s).
    function claim(
        uint256 id,
        address to,
        bytes calldata publicValues,
        bytes calldata proofBytes,
        uint32 keyId,
        bytes calldata signature
    ) external {
        Deposit storage d = deposits[id];
        if (d.settled || d.from == address(0)) revert AlreadySettled();
        DashUsernameStatement memory s = dash.verifyUsername(publicValues, proofBytes);
        if (keccak256(bytes(s.normalizedLabel)) != keccak256(bytes(d.normalizedLabel))) revert WrongUsername();
        if (s.platformTimeMs / 1000 < d.createdAt) revert StaleProof();
        address signer = recoverDashSigner(claimMessage(id, to), signature);
        if (signer == address(0)) revert BadSignature();
        bool found;
        for (uint256 i; i < s.keys.length; i++) {
            DashKey memory k = s.keys[i];
            if (k.id != keyId) continue;
            if ((k.purpose != PURPOSE_AUTHENTICATION && k.purpose != PURPOSE_TRANSFER) || k.securityLevel > SECURITY_HIGH) {
                revert KeyNotUsable();
            }
            if (k.ethAddress != signer) revert BadSignature();
            found = true;
            break;
        }
        if (!found) revert KeyNotUsable();
        d.settled = true;
        if (!token.transfer(to, d.amount)) revert TransferFailed();
        emit Claimed(id, s.identityId, to, d.amount);
    }

    function refund(uint256 id) external {
        Deposit storage d = deposits[id];
        if (d.settled || d.from == address(0)) revert AlreadySettled();
        if (block.timestamp < d.createdAt + REFUND_DELAY) revert TooEarly();
        d.settled = true;
        if (!token.transfer(d.from, d.amount)) revert TransferFailed();
        emit Refunded(id);
    }

    /// @notice The text a Dash identity key signs to claim deposit `id` to `to`.
    function claimMessage(uint256 id, address to) public view returns (string memory) {
        return string.concat(
            "Willow Dash username escrow\nclaim ",
            _dec(id),
            "\nto ",
            _hex(to),
            "\nescrow ",
            _hex(address(this)),
            "\nchain ",
            _dec(block.chainid)
        );
    }

    /// @notice Recover the signer of a Dash Core "signmessage" signature as an Ethereum address.
    function recoverDashSigner(string memory message, bytes calldata sig) public pure returns (address) {
        if (sig.length != 65 || bytes(message).length > 252) return address(0);
        uint8 header = uint8(sig[0]);
        if (header < 27 || header > 34) return address(0);
        bytes32 r = bytes32(sig[1:33]);
        bytes32 s = bytes32(sig[33:65]);
        bytes memory preimage = abi.encodePacked(
            uint8(25), "DarkCoin Signed Message:\n", uint8(bytes(message).length), message
        );
        bytes32 digest = sha256(abi.encodePacked(sha256(preimage)));
        return ecrecover(digest, 27 + ((header - 27) & 3), r, s);
    }

    function _dec(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n;
        for (uint256 t = v; t != 0; t /= 10) n++;
        bytes memory b = new bytes(n);
        for (; v != 0; v /= 10) b[--n] = bytes1(uint8(48 + v % 10));
        return string(b);
    }

    function _hex(address a) internal pure returns (string memory) {
        bytes memory digits = "0123456789abcdef";
        bytes memory b = new bytes(42);
        b[0] = "0";
        b[1] = "x";
        uint160 v = uint160(a);
        for (uint256 i = 41; i > 1; i--) {
            b[i] = digits[v & 0xf];
            v >>= 4;
        }
        return string(b);
    }
}
