// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IPostProofHook
/// @notice Interface for optional post-solve side effects triggered by `ProofOfSolve`.
/// @dev Implementations must treat `data` as untrusted user input and enforce their
///      own authorization, replay protection, and input validation as needed.
interface IPostProofHook {
    /// @notice Handles side effects after a solver has been marked as solved.
    /// @dev The caller is expected to be a `ProofOfSolve` instance, but hooks should
    ///      not rely on `msg.sender` alone as authorization for privileged actions.
    /// @param solver The address that successfully satisfied `ProofOfSolve.solve`.
    /// @param data Arbitrary solver-provided data forwarded from `ProofOfSolve`;
    ///        implementations should be decoded and validated before use.
    function hook(address solver, bytes calldata data) external;
}
