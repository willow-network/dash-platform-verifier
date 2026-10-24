//! The public values: ABI-encoded so DashPlatformVerifier.sol can abi.decode them.

alloy_sol_types::sol! {
    struct DashKey {
        uint32 id;
        uint8 purpose;
        uint8 securityLevel;
        address ethAddress;
    }

    /// Block hashes are in Dash's internal byte order (the reverse of how explorers print them).
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
}

/// Statement kind for a DPNS username resolved to an identity.
pub const KIND_USERNAME: u16 = 0x5101;
