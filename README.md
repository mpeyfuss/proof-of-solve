# Proof Of Solve

`ProofOfSolve` is a small verification contract for puzzle-style or challenge-style systems that record when an address has successfully solved something. This was originally concepted by Scott Kominers' [CROSSHASHES](https://etherscan.io/address/0x6570ba3cb863dd2e634f4d0ce1cbe9f8957b347f) project and expanded upon in this repository. Credit to [Selkie](https://x.com/madam_selkie) for the name `Proof of Solve`.

The repo contains one primary contract, one hook interface, and a test suite around the expected behaviors:

- `src/ProofOfSolve.sol`
- `src/IPostProofHook.sol`
- `test/ProofOfSolve.t.sol`

The original impetus for the contract was puzzle systems where the solution itself reveals a seed phrase or other secret that only a real solver should be able to obtain. In that mode, the signer is not really being trusted to judge correctness. The signer can safely sign for anyone who demonstrates knowledge of the secret, and the secret is the actual proof of solve.

The same contract shape also generalizes into a broader trusted-signer system. In that mode, the contract does not verify puzzle solutions onchain. Instead, it verifies that a configured signer approved a specific solver and a specific payload for a specific contract on a specific chain, then permanently marks that solver as solved.

## Contract System Overview

The contract system has two moving parts:

1. `ProofOfSolve`
2. An optional `IPostProofHook` implementation

`ProofOfSolve` is the canonical state holder. It decides whether a caller can be marked as solved. A signer authorizes solve payloads. In the original seed-phrase use case, the signer is just attesting that the caller revealed the secret. In the broader generalized version, the signer can also act as a trusted offchain judge of whether some solve is valid. If a solve succeeds, the contract can optionally call a hook to trigger follow-up behavior such as minting, accounting, role assignment, or custom application logic.

That split is the main design choice:

- the contract only verifies signer authorization, not puzzle semantics
- the actual proof of solve can either be a revealed secret or an operator decision
- authorization to record that solution happens via ECDSA signature
- durable onchain state is only "has this address solved?"
- post-solve side effects are modularized behind a hook

This keeps the base contract simple and makes it usable across very different challenge systems.

## Core Flow

The normal lifecycle looks like this:

1. The owner deploys `ProofOfSolve` with an initial `solutionSigner`.
2. A user solves some challenge offchain or otherwise obtains the secret required to prove solve status.
3. The signer either verifies the revealed secret or decides offchain that the solve is valid, then signs a payload for that exact user and that exact `data` blob.
4. The user calls `solve(data, signature)`.
5. The contract reconstructs the signed message and verifies the signer.
6. If the signature is valid and the user has not solved before, the contract records `solvers[msg.sender] = true`.
7. If a hook is configured, the contract calls `hook(msg.sender, data)`.
8. The contract emits `Solved(msg.sender)`.

The important consequence is that the user does not submit a proof that the contract understands semantically. The contract only checks whether the configured signer authorized the submission. Whether that signer is acting as a mere witness to a revealed secret or as a trusted arbiter depends on the application.

## `ProofOfSolve`

### State

The main contract stores five pieces of state:

- `name`: the human-readable identifier of the puzzle/game
- `solutionSigner`: the address allowed to authorize solves
- `signerLocked`: whether signer rotation has been permanently disabled
- `postProofHook`: an optional contract called after a successful solve
- `solvers[address]`: whether an address has already solved

The state machine is deliberately simple:

- an address starts as unsolved
- a valid call to `solve` marks it solved
- there is no unset/reset path
- a solved address cannot solve again

This makes the contract behave like a one-time attestation registry.

### Constructor

The constructor takes:

- `name_`
- `initOwner`
- `initSolutionSigner`
- `initPostProofHook`

Constructor rules:

- the signer cannot be the zero address
- the hook may be zero
- if the hook is nonzero, it must be a deployed contract

The constructor emits:

- `SolutionSignerSet(initSolutionSigner)`
- `PostProofHookSet(initPostProofHook)` when a nonzero hook is provided

### Solve Verification

The `solve(bytes data, bytes signature)` function is the center of the system.

It rejects:

- callers that have already solved
- signatures not produced by `solutionSigner`
- signatures for a different contract
- signatures for a different chain
- signatures for a different solver
- signatures for different `data`

The signed message is:

```solidity
keccak256(abi.encode(address(this), block.chainid, msg.sender, data))
```

That hash is then converted into an Ethereum signed message digest with OpenZeppelin's `MessageHashUtils.toEthSignedMessageHash`, and the signer is recovered with `ECDSA.recover`.

This message structure gives the contract several useful security properties:

- cross-contract replay resistance because `address(this)` is included
- cross-chain replay resistance because `block.chainid` is included
- caller binding because `msg.sender` is included
- payload binding because `data` is included

This means a valid signature is only valid for:

- one deployed `ProofOfSolve` instance
- one chain
- one solver address
- one exact byte payload

### Ordering and Side Effects

The function follows checks-effects-interactions order:

1. verify the caller is unsolved
2. verify the signature
3. mark the caller as solved
4. call the hook if configured
5. emit `Solved`

The hook call happens after state is updated, but because the whole transaction reverts atomically, a reverting hook causes the entire solve to fail and the solver remains unsolved. This behavior is tested in `test_solveWithRevertingHook`.

That is an important integration detail: a hook is part of the success path.

## `IPostProofHook`

`IPostProofHook` is a minimal extension point:

```solidity
function hook(address solver, bytes calldata data) external;
```

The base contract forwards:

- `solver`: the address that just solved
- `data`: the same solver-supplied bytes used in signature verification

This interface is intentionally opinionated in one way: it assumes hook implementations must treat `data` as untrusted input.

The interface comments already point to the main security expectations:

- decode carefully
- validate all assumptions
- implement any replay protection the hook needs
- do not rely on `msg.sender` alone for privileged authorization decisions

In practice, a production hook should do at least some of the following:

- verify `msg.sender` is the expected `ProofOfSolve` contract
- maintain its own one-time-use or idempotency guarantees if needed
- validate payload length and decode shape before use
- constrain what the payload is allowed to do
- avoid external-call patterns that create unnecessary reentrancy or griefing surfaces

## Admin Controls

The contract inherits `Ownable2Step`, so ownership management uses OpenZeppelin's two-step ownership transfer flow.

The owner has three administrative capabilities:

### `setSolutionSigner(address newSolutionSigner)`

This rotates the signer used to authorize new solves.

Restrictions:

- only the owner can call it
- zero address is rejected
- it cannot be called after the signer has been locked

This is useful while the system is still being operated actively and signer rotation may be required for operational or security reasons.

### `lockSigner()`

This permanently disables future signer updates.

Restrictions:

- only the owner can call it
- it can only be called once

This is the contract's immutability lever for signer trust. Once locked, the current signer remains the signer forever.

Whether to use it depends on the operating model:

- if you want upgradable trust in an operating team, keep signer rotation available
- if you want the signer policy frozen after launch, call `lockSigner`

### `setPostProofHook(address newPostProofHook)`

This updates the post-solve hook.

Restrictions:

- only the owner can call it
- the new address must be a contract
- this function does not allow setting the hook back to zero

That last point matters. The constructor allows deploying with no hook, but once the owner sets a hook through `setPostProofHook`, there is no admin path in this version to disable hooks again by setting `address(0)`. Any future change must point to another deployed contract.

## Trust Model

The trust model depends on what the signer is actually attesting to.

### Seed-Phrase Mode

In the original intended mode, a real solution reveals a seed phrase or similar secret. The signer is not being trusted to determine correctness in any meaningful sense. The signer is only checking whether the user knows the secret.

In that setup:

- the secret is the real proof of solve
- the signer acts more like a gateway that converts secret knowledge into an onchain attestation
- users do not need to trust the signer to honestly evaluate an ambiguous submission
- users still need to trust the signer not to censor them and to protect its own key material

This is not fully trustless onchain verification, but it is substantially less trust-heavy than a pure offchain judging model.

### Trusted-Signer Mode

The same contract also supports a broader operational model where the signer is the actual authority deciding whether a solve is valid.

In that setup:

- the signer can approve legitimate solves
- the signer can refuse legitimate solves
- the signer can approve arbitrary solves whether or not a user actually solved anything

That is not a bug in the implementation. It is the governance model for that deployment style.

So the real application-level guarantees depend on offchain process:

- how challenge submissions are reviewed
- how signatures are issued
- how signer keys are secured
- whether users trust the operator to judge solutions honestly

If you need permissionless proof verification, this design is still the wrong primitive. If you need a cheap onchain record backed either by revealed-secret proofs or by offchain-reviewed approvals, it is a clean fit.

## Security Properties and Tradeoffs

### What the system does well

- Prevents replay across contracts and chains.
- Prevents users from reusing another user's signature.
- Prevents post-signing mutation of the `data` payload.
- Prevents double-solving by the same address.
- Allows optional composition through a hook without complicating the base contract.

### What the system does not try to do

- It does not verify challenge correctness onchain.
- It does not support multiple solves per address.
- It does not support revocation or admin resets.
- It does not support signature expiries, nonces, or deadlines.
- It does not support disabling the hook after one has been set through admin.

### Operational risks

- If the signer key is compromised, arbitrary solves can be authorized.
- If the hook is buggy or malicious, valid solves can be blocked by reverting.
- If the hook trusts unvalidated `data`, it can introduce its own vulnerabilities.
- If the owner rotates the signer unexpectedly, integrators relying on the previous signer can break.

## Integration Notes

### Offchain Signing

To produce a valid signature, the signer must sign the Ethereum signed message for:

```solidity
keccak256(abi.encode(proofOfSolveAddress, chainId, solverAddress, data))
```

The encoding must match Solidity's `abi.encode`, not `abi.encodePacked`.

If any field changes, the signature becomes invalid:

- different contract address
- different chain id
- different solver
- different data bytes

### Data Payload Design

Because `data` is application-defined, you should decide what it means before integrating.

Common patterns:

- empty bytes if the contract only needs a yes/no authorization
- encoded puzzle metadata such as challenge id or level id
- encoded mint or reward metadata consumed by a hook
- encoded allowlist or entitlement context

The base contract does not interpret `data`, so consistency between offchain signing and any hook-side decoding is entirely your responsibility.

### Hook Design

A hook is appropriate when "solved" should trigger more than a boolean registry update.

Examples:

- mint an NFT
- issue points
- assign an onchain role in another system
- notify another contract
- store richer solve metadata elsewhere

Because the hook is on the critical path, keep it simple. If the post-solve action is failure-prone or depends on external conditions, consider whether it should happen in a separate user action instead.

## Tests

The test suite covers the contract's important behavior:

- constructor validation
- owner-only admin actions
- signer rotation and signer locking
- hook validation
- replay protection across contract address and chain id
- solver binding
- payload binding
- rejection of bad signer keys
- successful solve path without hook
- successful solve path with hook
- full revert when the hook reverts

Run the standard suite with:

```bash
make test-std
```

Other useful commands:

```bash
make build
make test-quick
make test-gas
make test-cov
make test-fuzz
```

## Development

Install dependencies:

```bash
make install
```

Format:

```bash
make fmt
```

Build:

```bash
make build
```

## When To Use This System

This contract system is a good fit when:

- a valid solve can be reduced to knowledge of a secret such as a seed phrase
- or challenge validity is determined offchain by an operator
- you want a cheap onchain record of successful completion
- you need one-time solver recognition per address
- you may want custom post-solve behavior

It is a poor fit when:

- proof verification must be trustless and onchain
- users need repeatable completions
- solves need revocation or expiration
- admin policies must be fully immutable from day one except for ownership transfer

## Files

- [README.md](/Users/mpeyfuss/MP/proof-of-solve/README.md)
- [src/ProofOfSolve.sol](/Users/mpeyfuss/MP/proof-of-solve/src/ProofOfSolve.sol)
- [src/IPostProofHook.sol](/Users/mpeyfuss/MP/proof-of-solve/src/IPostProofHook.sol)
- [test/ProofOfSolve.t.sol](/Users/mpeyfuss/MP/proof-of-solve/test/ProofOfSolve.t.sol)

## Disclaimer

This repository is provided as-is, without warranty of any kind. Use at your own risk.

## License
This repository is licensed under the MIT License. See [LICENSE](/Users/mpeyfuss/MP/proof-of-solve/LICENSE).
