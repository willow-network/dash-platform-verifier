// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "./ISP1Verifier.sol";

/// @notice One enabled secp256k1 key of a Dash identity, as an Ethereum address.
struct DashKey {
    uint32 id;
    uint8 purpose;
    uint8 securityLevel;
    address ethAddress;
}

/// @notice Public values of the Dash username program (zkvm/dash), `abi.encode`d.
/// @dev Core block hashes are in Dash's internal byte order (explorers print them reversed).
struct DashUsernameStatement {
    uint16 kind;
    uint32 coreStartHeight;
    bytes32 coreStartHash;
    uint32 coreEndHeight;
    bytes32 coreEndHash;
    uint64 platformHeight;
    uint64 platformTimeMs;
    uint32 protocolVersion;
    bytes32 appHash;
    string normalizedLabel;
    string label;
    bytes32 identityId;
    uint64 balance;
    uint64 revision;
    DashKey[] keys;
}

/// @title DashPlatformVerifier
/// @author Willow
/// @notice Verifies Dash Platform data on Ethereum, with Dash's own consensus as the only trust root.
/// @dev Each SP1 proof starts at a Dash Core block this contract already trusts and walks ChainLocks
///      forward, each signed by an LLMQ_400_60 quorum active in the previous block's merkleRootQuorums,
///      to the Core height Platform committed to. There it takes the LLMQ_100_67 quorum from that
///      block's merkleRootQuorums, checks the quorum's signature on Platform's state root, and reads
///      the data out of GroveDB with Drive's own verifiers. The end block becomes trusted, so the
///      contract follows Dash with no keeper and no admin.
///
///      Trust: the bootstrap block below, and that each quorum involved had an honest threshold
///      (60% of 400 for ChainLocks, 67% of 100 for Platform). Nothing in this contract can be
///      changed after deployment; a new program is a new deployment.
contract DashPlatformVerifier {
    uint16 public constant KIND_USERNAME = 0x5101;

    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;

    /// @notice Height of each trusted Core block, by hash; 0 means not trusted.
    mapping(bytes32 => uint32) public trustedCoreHeight;

    event CoreBlockTrusted(bytes32 indexed blockHash, uint32 height);
    event UsernameVerified(
        string normalizedLabel, bytes32 indexed identityId, uint64 platformHeight, uint64 platformTimeMs
    );

    error WrongKind(uint16 kind);
    error UntrustedStart(bytes32 blockHash, uint32 height);

    constructor(ISP1Verifier _sp1Verifier, bytes32 _programVKey, bytes32 bootstrapHash, uint32 bootstrapHeight) {
        require(bootstrapHeight != 0, "bootstrap height");
        sp1Verifier = _sp1Verifier;
        programVKey = _programVKey;
        trustedCoreHeight[bootstrapHash] = bootstrapHeight;
        emit CoreBlockTrusted(bootstrapHash, bootstrapHeight);
    }

    /// @notice Verify a username statement and trust the Core block it ended on.
    /// @dev Reverts unless the proof is valid and its start block is trusted.
    function verifyUsername(bytes calldata publicValues, bytes calldata proofBytes)
        external
        returns (DashUsernameStatement memory s)
    {
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);
        s = abi.decode(publicValues, (DashUsernameStatement));
        if (s.kind != KIND_USERNAME) revert WrongKind(s.kind);
        uint32 h = trustedCoreHeight[s.coreStartHash];
        if (h == 0 || h != s.coreStartHeight) revert UntrustedStart(s.coreStartHash, s.coreStartHeight);
        if (trustedCoreHeight[s.coreEndHash] == 0) {
            trustedCoreHeight[s.coreEndHash] = s.coreEndHeight;
            emit CoreBlockTrusted(s.coreEndHash, s.coreEndHeight);
        }
        emit UsernameVerified(s.normalizedLabel, s.identityId, s.platformHeight, s.platformTimeMs);
    }
}
