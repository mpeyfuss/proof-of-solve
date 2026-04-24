// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ProofOfSolve, Ownable, MessageHashUtils, ECDSA} from "src/ProofOfSolve.sol";
import {RevertHook} from "src/hooks/RevertHook.sol";
import {Hook} from "./mocks/Hook.sol";

contract ProofOfSolveTest is Test {
    ProofOfSolve pf;
    address signer;
    uint256 signerPrivateKey;
    address owner = makeAddr("owner");
    address hook = makeAddr("hook");

    function _sign(address sender, bytes memory data, address validatorContract, uint256 chainId, uint256 privateKey)
        internal
        pure
        returns (bytes memory signature)
    {
        bytes32 messageHash = keccak256(abi.encode(validatorContract, chainId, sender, data));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function setUp() public {
        (signer, signerPrivateKey) = makeAddrAndKey("signer");

        pf = new ProofOfSolve("test", 1, owner, signer, address(0));
    }

    function test_constructor_errors() public {
        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        pf = new ProofOfSolve("test", 0, owner, address(0), address(0));

        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        pf = new ProofOfSolve("test", 0, owner, signer, signer);
    }

    function test_constructor(address o, address s, address h) public {
        vm.assume(o != address(0));
        vm.assume(s != address(0));
        if (h != address(0) && h.code.length == 0) {
            h = address(0);
        }

        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.SolutionSignerSet(s);

        if (h != address(0)) {
            vm.expectEmit(true, false, false, false);
            emit ProofOfSolve.PostProofHookSet(h);
        }

        pf = new ProofOfSolve("test", 10, o, s, h);

        assertEq(pf.owner(), o);
        assertEq(pf.solveLimit(), 10);
        assertEq(pf.solutionSigner(), s);
        assertEq(pf.postProofHook(), h);
    }

    function test_adminAccessControl(address hacker) public {
        vm.assume(hacker != owner);

        vm.startPrank(hacker);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, hacker));
        pf.setSolutionSigner(hacker);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, hacker));
        pf.lockSigner();

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, hacker));
        pf.setPostProofHook(hacker);

        vm.stopPrank();
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

    function test_setPostProofHook() public {
        // try setting address(1)
        vm.expectRevert(ProofOfSolve.InvalidAddress.selector);
        vm.prank(owner);
        pf.setPostProofHook(address(1));

        // set to a contract
        Hook h = new Hook();
        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.PostProofHookSet(address(h));
        vm.prank(owner);
        pf.setPostProofHook(address(h));

        assertEq(pf.postProofHook(), address(h));

        // set to address(0)
        vm.prank(owner);
        pf.setPostProofHook(address(0));

        assertEq(pf.postProofHook(), address(0));

        // lock hook
        vm.prank(owner);
        pf.lockHook();

        // try setting again
        vm.expectRevert(ProofOfSolve.NotAllowed.selector);
        vm.prank(owner);
        pf.setPostProofHook(address(h));

    }

    function test_lockHook() public {
        // lock
        vm.expectEmit(false, false, false, false);
        emit ProofOfSolve.HookLocked();
        vm.prank(owner);
        pf.lockHook();

        assertTrue(pf.hookLocked());

        // try locking again
        vm.expectRevert(ProofOfSolve.NotAllowed.selector);
        vm.prank(owner);
        pf.lockHook();
    }

    function test_solveWithoutHook(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // invalid validator contract (cross contract replay)
        bytes memory signature = _sign(solver, data, address(this), block.chainid, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.SignerMismatch.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // invalid chain id (cross chain replay)
        signature = _sign(solver, data, address(pf), block.chainid + 1, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.SignerMismatch.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // invalid solver (use someone else's solution)
        signature = _sign(address(0), data, address(pf), block.chainid, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.SignerMismatch.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // sign wrong data
        bytes memory badData = abi.encode(keccak256(data));
        signature = _sign(solver, badData, address(pf), block.chainid, signerPrivateKey);
        vm.expectRevert(ProofOfSolve.SignerMismatch.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // wrong signer pk
        uint256 badSignerKey = uint256(keccak256("bad pk"));
        signature = _sign(solver, data, address(pf), block.chainid, badSignerKey);
        vm.expectRevert(ProofOfSolve.SignerMismatch.selector);
        vm.prank(solver);
        pf.solve(data, signature);

        // solve
        signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);
        vm.expectEmit(true, true, false, false);
        emit ProofOfSolve.Solved(solver, 1);
        vm.prank(solver);
        pf.solve(data, signature);

        assertEq(pf.solverCounts(solver), 1);

        // try solving again
        vm.expectRevert(ProofOfSolve.NotAllowed.selector);
        vm.prank(solver);
        pf.solve(data, signature);
    }

    function test_solveWithUnlimitedSolves(address solver, bytes memory data, uint8 num) public {
        vm.assume(solver != address(0));
        pf = new ProofOfSolve("test", 0, owner, signer, address(0));

        for (uint256 i = 0; i < num; ++i) {
            bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);
            vm.expectEmit(true, true, false, false);
            emit ProofOfSolve.Solved(solver, uint16(i + 1));
            vm.prank(solver);
            pf.solve(data, signature);
            assertEq(pf.solverCounts(solver), i + 1);
        }
    }

    function test_lockSigner_doesNotAffectSolve(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // Locking freezes signer rotation only; it should not disable ordinary solves.
        vm.prank(owner);
        pf.lockSigner();

        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);

        vm.expectEmit(true, false, false, false);
        emit ProofOfSolve.Solved(solver, 1);
        vm.prank(solver);
        pf.solve(data, signature);

        assertEq(pf.solverCounts(solver), 1);
    }

    function test_solveWithHook(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // set hook
        Hook h = new Hook();
        vm.prank(owner);
        pf.setPostProofHook(address(h));

        // solve
        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);
        vm.expectEmit(true, false, false, true);
        emit Hook.ReceivedHook(solver, data);
        vm.expectEmit(true, true, false, false);
        emit ProofOfSolve.Solved(solver, 1);
        vm.prank(solver);
        pf.solve(data, signature);
    }

    function test_solveWithRevertingHook(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // set hook
        RevertHook h = new RevertHook();
        vm.prank(owner);
        pf.setPostProofHook(address(h));

        // solve
        bytes memory signature = _sign(solver, data, address(pf), block.chainid, signerPrivateKey);
        vm.expectRevert();
        vm.prank(solver);
        pf.solve(data, signature);
    }

    function test_solve_revertsOnEmptyMalformedSignature(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        // Malformed signatures may revert from OZ ECDSA before the contract can raise InvalidSignature.
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 0));
        vm.prank(solver);
        pf.solve(data, bytes(""));
    }

    function test_solve_revertsOnShortMalformedSignature(address solver, bytes memory data) public {
        vm.assume(solver != address(0));

        bytes memory malformed = hex"123456";
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 3));
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

        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureS.selector, 0xdfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0));
        vm.prank(solver);
        pf.solve(data, malformed);
    }
}