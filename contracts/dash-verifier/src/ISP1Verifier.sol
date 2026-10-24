// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ISP1Verifier
/// @notice Vendored verbatim from succinctlabs/sp1-contracts (contracts/src/ISP1Verifier.sol).
///         Both the canonical `SP1VerifierGateway` and each concrete `SP1VerifierGroth16`
///         implement this interface, so a verifier contract can point at EITHER address.
/// @dev    verifyProof is a `view` that REVERTS on an invalid proof and returns on success.
interface ISP1Verifier {
    /// @notice Verifies a proof with given public values and vkey.
    /// @param programVKey The verification key for the RISC-V program (the guest ELF).
    /// @param publicValues The public values committed by the guest via `sp1_zkvm::io::commit_*`.
    /// @param proofBytes The proof, prefixed with a 4-byte verifier selector.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title ISP1VerifierWithHash
/// @notice Extends ISP1Verifier with the verifier identity hash whose first 4 bytes are the route selector.
interface ISP1VerifierWithHash is ISP1Verifier {
    /// @notice The 32-byte verifier hash; `bytes4(VERIFIER_HASH())` is the proof selector.
    function VERIFIER_HASH() external pure returns (bytes32);
}
