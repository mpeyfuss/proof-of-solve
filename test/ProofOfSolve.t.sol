// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ProofOfSolve, Ownable, Ownable2Step, MessageHashUtils} from "src/ProofOfSolve.sol";
import {Hook} from "./mocks/Hook.sol";
import {RevertingHook} from "./mocks/RevertingHook.sol";

contract ProofOfSolveTest is Test {
    ProofOfSolve pf;
    address signer;
    uint256 signerPrivateKey;
    address owner = makeAddr("owner");

    function _sign(address sender, bytes memory data, address validatorContract, uint256 chainId, uint256 privateKey)
        internal
        returns (bytes memory signature)
    {
        bytes32 messageHash = keccak256(abi.encode(validatorContract, chainId, sender, data));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function setUp() public {
        (signer, signerPrivateKey) = makeAddrAndKey("signer");
        pf = new ProofOfSolve("test", owner, signer, address(0));
    }

    function test_constructor_errors_zeroOwner() public {
        // Ownable(initOwner) should reject the zero owner.
        vm.expectRevert();
        new ProofOfSolve("test", address(0), signer, address(0));
    }

    function test_constructor_errors_zeroSigner() public {
        // initSolutionSigner may not be the zero address.
        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        new ProofOfSolve("test", owner, address(0), address(0));
    }

    function test_constructor_errors_nonContractHook() public {
        // A nonzero hook must be a contract.
        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        new ProofOfSolve("test", owner, signer, signer);
    }

    function test_constructor_zeroHook_emitsBothEventsAndSetsStorage(address o, address s) public {
        vm.assume(o != address(0));
        vm.assume(s != address(0));

        // Constructor always emits the signer event.
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.SolutionSignerSet(s);

        // Constructor also emits the hook event even when the hook is address(0).
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.PostProofHookSet(address(0));

        ProofOfSolve local = new ProofOfSolve("test", o, s, address(0));

        assertEq(local.owner(), o);
        assertEq(local.solutionSigner(), s);
        assertEq(local.postProofHook(), address(0));
        assertEq(local.name(), "test");
        assertFalse(local.signerLocked());
    }

    function test_constructor_contractHook_emitsBothEventsAndSetsStorage(address o, address s) public {
        vm.assume(o != address(0));
        vm.assume(s != address(0));

        Hook h = new Hook();

        // Constructor always emits the signer event.
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.SolutionSignerSet(s);

        // Constructor emits the hook event for a nonzero contract hook as well.
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.PostProofHookSet(address(h));

        ProofOfSolve local = new ProofOfSolve("test", o, s, address(h));

        assertEq(local.owner(), o);
        assertEq(local.solutionSigner(), s);
        assertEq(local.postProofHook(), address(h));
        assertEq(local.name(), "test");
        assertFalse(local.signerLocked());
    }

    function test_adminAccessControl(address hacker) public {
        vm.assume(hacker != owner);

        vm.startPrank(hacker);

        // Non-owner cannot rotate the signer.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, hacker));
        pf.setSolutionSigner(hacker);

        // Non-owner cannot lock the signer.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, hacker));
        pf.lockSigner();

        // Non-owner cannot change the hook.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, hacker));
        pf.setPostProofHook(hacker);

        vm.stopPrank();
    }

    function test_transferOwnership_twoStepFlow(address newOwner, address outsider) public {
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != owner);
        vm.assume(outsider != newOwner);

        // Owner nominates a pending owner.
        vm.prank(owner);
        pf.transferOwnership(newOwner);

        assertEq(pf.pendingOwner(), newOwner);

        // Anyone other than the pending owner must not be able to accept.
        vm.prank(outsider);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable2Step.Ownable2StepUnauthorizedAccount.selector, outsider)
        );
        pf.acceptOwnership();

        // Pending owner accepts and becomes the new owner.
        vm.prank(newOwner);
        pf.acceptOwnership();

        assertEq(pf.owner(), newOwner);
        assertEq(pf.pendingOwner(), address(0));

        // Old owner no longer has admin privileges.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        pf.lockSigner();

        // New owner does have admin privileges.
        vm.prank(newOwner);
        pf.lockSigner();
        assertTrue(pf.signerLocked());
    }

    function test_setSolutionSigner(address s) public {
        vm.assume(s != address(0));

        // try setting zero address
        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        vm.prank(owner);
        pf.setSolutionSigner(address(0));

        // set it
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.SolutionSignerSet(s);
        vm.prank(owner);
        pf.setSolutionSigner(s);

        assertEq(pf.solutionSigner(), s);

        // lock it
        vm.prank(owner);
        pf.lockSigner();

        // try setting again
        vm.expectRevert(ProofOfSolve.NotAllowed.selector);
        vm.prank(owner);
        pf.setSolutionSigner(s);
    }

    function test_signerRotation_invalidatesOldSignatures_andAcceptsNewSigner(address solver, bytes memory data)
        public
    {
        vm.assume(solver != address(0));

        (address newSigner, uint256 newSignerPrivateKey) = makeAddrAndKey("newSigner");

        // Signature from the old signer is initially valid in principle.
        bytes memory oldSignature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);

        // Rotate signer.
        vm.prank(owner);
        pf.setSolutionSigner(newSigner);

        // Old signature must now fail.
        vm.expectRevert(ProofOfSolve.InvalidSignature.selector);
        vm.prank(solver);
        pf.solve(data, oldSignature);

        // New signer can authorize the solve.
        bytes memory newSignature = _sign(solver, data, address(pf), block.chainid, newSignerPrivateKey);

        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.Solved(solver);
        vm.prank(solver);
        pf.solve(data, newSignature);

        assertTrue(pf.solvers(solver));
    }

    function test_lockSigner() public {
        // lock
        vm.expectEmit(false, false, false, false);
        emit ProofOfSolve.SignerLocked();
        vm.prank(owner);
        pf.lockSigner();

        assertTrue(pf.signerLocked());

        // try locking again
        vm.expectRevert(ProofOfSolve.NotAllowed.selector);
        vm.prank(owner);
        pf.lockSigner();
    }

    function test_lockSigner_doesNotAffectSolve(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // Locking freezes signer rotation only; it should not disable ordinary solves.
        vm.prank(owner);
        pf.lockSigner();

        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);

        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.Solved(solver);
        vm.prank(solver);
        pf.solve(data, signature);

        assertTrue(pf.solvers(solver));
    }

    function test_setPostProofHook() public {
        // try setting address(0)
        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        vm.prank(owner);
        pf.setPostProofHook(address(0));

        // try setting just an eoa
        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        vm.prank(owner);
        pf.setPostProofHook(owner);

        // set to a contract
        Hook h = new Hook();
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.PostProofHookSet(address(h));
        vm.prank(owner);
        pf.setPostProofHook(address(h));

        assertEq(pf.postProofHook(), address(h));
    }

    function test_solveWithoutHook(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // invalid validator contract (cross contract replay)
        bytes memory signature = _sign(solver, data, address(this), block.chainid, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.InvalidSignature.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // invalid chain id (cross chain replay)
        signature = _sign(solver, data, address(pf), block.chainid + 1, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.InvalidSignature.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // invalid solver (use someone else's solution)
        signature = _sign(address(0), data, address(pf), block.chainid, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.InvalidSignature.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // sign wrong data
        bytes memory badData = abi.encode(keccak256(data));
        signature = _sign(solver, badData, address(pf), block.chainid, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.InvalidSignature.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // wrong signer pk
        uint256 badSignerKey = uint256(keccak256("bad pk"));
        signature = _sign(solver, data, address(pf), block.chainid, badSignerKey);
        vm.expectRevert(ProofOfSolve.InvalidSignature.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // solve
        signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.Solved(solver);
        vm.prank(solver);
        pf.solve(data, signature);

        assertTrue(pf.solvers(solver));

        // try solving again
        vm.expectRevert(ProofOfSolve.NotAllowed.selector);
        vm.prank(solver);
        pf.solve(data, signature);
    }

    function test_solveWithoutHook_emptyData(address solver) public {
        vm.assume(solver != address(0));

        // Empty bytes should be a valid payload provided the signer signed exactly that payload.
        bytes memory data = bytes("");
        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);

        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.Solved(solver);
        vm.prank(solver);
        pf.solve(data, signature);

        assertTrue(pf.solvers(solver));
    }

    function test_solveWithoutHook_largeData(address solver) public {
        vm.assume(solver != address(0));

        // Exercise a larger arbitrary payload to make sure hashing / forwarding assumptions hold.
        bytes memory data = new bytes(4096);
        for (uint256 i = 0; i < data.length; ++i) {
            data[i] = bytes1(uint8(i));
        }

        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);

        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.Solved(solver);
        vm.prank(solver);
        pf.solve(data, signature);

        assertTrue(pf.solvers(solver));
    }

    function test_solveWithHook(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // set hook
        Hook h = new Hook();
        vm.prank(owner);
        pf.setPostProofHook(address(h));

        // solve
        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);

        // Current implementation calls the hook and only then emits Solved.
        vm.expectEmit(true, false, false, true);
        emit Hook.ReceivedHook(solver, data);

        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.Solved(solver);

        vm.prank(solver);
        pf.solve(data, signature);

        assertTrue(pf.solvers(solver));
    }

    function test_solveWithRevertingHook(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // set hook
        RevertingHook h = new RevertingHook();
        vm.prank(owner);
        pf.setPostProofHook(address(h));

        // solve should revert because the hook reverts
        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);
        vm.expectRevert();
        vm.prank(solver);
        pf.solve(data, signature);

        // The revert must roll back the earlier write to solvers[msg.sender].
        assertFalse(pf.solvers(solver));
    }

    function test_solve_revertsOnEmptyMalformedSignature(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // Malformed signatures may revert from OZ ECDSA before the contract can raise InvalidSignature.
        vm.expectRevert();
        vm.prank(solver);
        pf.solve(data, bytes(""));
    }

    function test_solve_revertsOnShortMalformedSignature(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        bytes memory malformed = hex"123456";
        vm.expectRevert();
        vm.prank(solver);
        pf.solve(data, malformed);
    }

    function test_solve_revertsOnRandom65ByteGarbageSignature(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // Even when the signature has the right length, random garbage should not validate.
        bytes memory malformed = new bytes(65);
        for (uint256 i = 0; i < malformed.length; ++i) {
            malformed[i] = bytes1(uint8(255 - i));
        }

        vm.expectRevert();
        vm.prank(solver);
        pf.solve(data, malformed);
    }
}