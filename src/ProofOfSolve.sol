// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable2Step, Ownable} from "@openzeppelin-contracts-5.6.1/access/Ownable2Step.sol";
import {MessageHashUtils} from "@openzeppelin-contracts-5.6.1/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin-contracts-5.6.1/utils/cryptography/ECDSA.sol";
import {IPostProofHook} from "./IPostProofHook.sol";

/// @title ProofOfSolve
/// @notice Records when an address has presented a valid signer-approved proof that they know a secret, 
///         such as the solution to a puzzle.
/// @dev Optionally calls a configured hook contract after a successful solve.
/// @author mpeyfuss & skominers/QED
/// @custom:contributor Expands and builds upon the framework introduced in CROSSHASHES 0x6570ba3cb863dd2e634f4d0ce1cbe9f8957b347. 'Proof of Solve' term suggested by Selkie.
contract ProofOfSolve is Ownable2Step {
    ////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////

    bool public signerLocked;
    bool public hookLocked;
    uint16 public solveLimit; // 0 means no limit
    address public solutionSigner;
    address public postProofHook;

    string public name;
    
    mapping(address solver => uint16) public solverCounts;
    mapping(bytes32 messagehash => bool) private _messageHashUsed;

    ////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////

    event HookLocked();
    event PostProofHookSet(address indexed hook);
    event SignerLocked();
    event SolutionSignerSet(address indexed signer);
    event Solved(address indexed solver, uint16 indexed count);

    ////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////

    error InvalidAddress();
    error NotAllowed();
    error SignerMismatch();

    ////////////////////////////////////////////////////////////////
    // CONSTRUCTOR
    ////////////////////////////////////////////////////////////////

    /// @notice Deploys the contract and configures the initial signer and post-proof hook.
    /// @param name_ The string identifier for the Proof of Solve instance, such as the name of a puzzle or game.
    /// @param solveLimit_ The solve limit per solver. 0 means no limit.
    /// @param initOwner The initial owner with permission to update contract configuration.
    /// @param initSolutionSigner The EOA authorized to sign solve payloads for this contract.
    /// @param initPostProofHook The hook contract called after an address is marked as solved.
    constructor(string memory name_, uint16 solveLimit_, address initOwner, address initSolutionSigner, address initPostProofHook) Ownable(initOwner) {
        // checks
        if (initSolutionSigner == address(0)) revert InvalidAddress();
        if (initPostProofHook != address(0) && initPostProofHook.code.length == 0) revert InvalidAddress();

        // effects
        name = name_;
        solveLimit = solveLimit_;
        solutionSigner = initSolutionSigner;
        emit SolutionSignerSet(initSolutionSigner);

        postProofHook = initPostProofHook;
        emit PostProofHookSet(initPostProofHook);
    }

    ////////////////////////////////////////////////////////////////
    // SOLVER FUNCTIONS
    ////////////////////////////////////////////////////////////////

    /// @notice Marks the caller as solved if they present a valid signer-issued proof.
    /// @dev The signed payload is domain-separated by this contract address and the current
    ///      chain id to prevent cross-contract and cross-chain replay. The hook receives
    ///      solver-provided `data`, so hook implementations must validate it before use.
    /// @param data Arbitrary solver-provided data included in the signed payload and
    ///        forwarded to the configured post-proof hook.
    /// @param signature A signature from `solutionSigner` over
    ///        `keccak256(abi.encode(address(this), block.chainid, msg.sender, data))`
    ///        [constituting the proof of successful solve].
    function solve(bytes calldata data, bytes calldata signature) external {
        // checks
        if (solveLimit != 0 && solverCounts[msg.sender] == solveLimit) revert NotAllowed();
        bytes32 messageHash = keccak256(abi.encode(address(this), block.chainid, msg.sender, data));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(messageHash);
        if (ECDSA.recover(digest, signature) != solutionSigner) revert SignerMismatch();

        // effects
        uint16 count = ++solverCounts[msg.sender];
        _messageHashUsed[messageHash] = true;

        // interactions
        if (postProofHook != address(0)) {
            IPostProofHook(postProofHook).hook(msg.sender, data);
        }

        emit Solved(msg.sender, count);
    }

    ////////////////////////////////////////////////////////////////
    // ADMIN FUNCTIONS
    ////////////////////////////////////////////////////////////////

    /// @notice Updates the signer authorized to approve solve payloads.
    /// @dev Reverts if signer has been permanently locked.
    /// @param newSolutionSigner The new EOA that will be trusted for solve signatures.
    function setSolutionSigner(address newSolutionSigner) external onlyOwner {
        // checks
        if (newSolutionSigner == address(0)) revert InvalidAddress();
        if (signerLocked) revert NotAllowed();

        // effects
        solutionSigner = newSolutionSigner;

        emit SolutionSignerSet(newSolutionSigner);
    }

    /// @notice Permanently disables future updates to `solutionSigner`.
    /// @dev This action is irreversible once executed.
    function lockSigner() external onlyOwner {
        // checks
        if (signerLocked) revert NotAllowed();

        // effects
        signerLocked = true;

        emit SignerLocked();
    }

    /// @notice Updates the hook contract invoked after a successful solve.
    /// @dev Reverts if the hook has been locked.
    /// @param newPostProofHook The new hook contract that implements `IPostProofHook`.
    function setPostProofHook(address newPostProofHook) external onlyOwner {
        // checks
        if (newPostProofHook != address (0) && newPostProofHook.code.length == 0) revert InvalidAddress();
        if (hookLocked) revert NotAllowed();

        // effects
        postProofHook = newPostProofHook;

        emit PostProofHookSet(newPostProofHook);
    }

    /// @notice Permanently disables future updates to `postProofHook`.
    /// @dev This action is irreversible once executed.
    function lockHook() external onlyOwner {
        // checks
        if (hookLocked) revert NotAllowed();

        // effects
        hookLocked = true;

        emit HookLocked();
    }
}
