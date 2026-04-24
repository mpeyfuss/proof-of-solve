# Proof Of Solve

`ProofOfSolve` is a verification protocol for recording when a user (as represented by an address) has successfully solved a puzzle-style challenge. This was originally concepted in [Scott Duke Kominers](https://scottkom.com/)'s [CROSSHASHES](https://etherscan.io/address/0x6570ba3cb863dd2e634f4d0ce1cbe9f8957b347f) project and expanded upon in this repository. Credit to [Selkie](https://x.com/madam_selkie) for the name `Proof of Solve`.

The repo contains one primary contract, one hook interface, and a test suite around the expected behaviors:

- `src/ProofOfSolve.sol`
- `src/IPostProofHook.sol`
- `test/ProofOfSolve.t.sol`

The original impetus for the contract was systems a puzzle solution comprises or reveals a secret that only a real solver should be able to obtain. In that mode, knowing the secret automatically implies correctness of the solution, and so the signer can safely sign for anyone who demonstrates knowledge of the secret---the secret itself is the actual proof of solve. This framework applies, to the following example use case:
> A cryptic puzzle is shared with prospective solvers. The secret is the answer to the puzzle, which itself is a word or phrase. When a user solves the puzzle, they learn the answer, which comprises the secret; they can then activate the `ProofOfSolve` signer.

The same contract shape also generalizes into a broader trusted-signer system. In that mode, the contract does not verify puzzle solutions onchain. Instead, it verifies that a configured signer approved a specific solver and a specific payload for a specific contract on a specific chain, then increments that solver's recorded solve count.

## Contract System Overview

The contract system has two moving parts:

1. `ProofOfSolve`
2. An optional `IPostProofHook` implementation

`ProofOfSolve` is the canonical state holder. It decides whether a caller can be marked as solved. A signer authorizes solve payloads. In the original puzzle answer use case, the signer is just attesting that the caller revealed the secret. In the broader generalized version, the signer can also act as a trusted offchain judge of whether some solve is valid. If a solve succeeds, the contract can optionally call a hook to trigger follow-up behavior such as minting, accounting, role assignment, or custom application logic.

That split is the main design choice:

- the contract only verifies signer authorization, not puzzle semantics
- the actual proof of solve can either be a revealed secret or an operator decision
- authorization to record that solution happens via ECDSA signature
- durable onchain state is "how many times has this address solved?"
- post-solve side effects are modularized behind a hook

This keeps the base contract simple and makes it usable across very different challenge systems.

## Core Flow

The normal lifecycle looks like this:

1. The owner deploys `ProofOfSolve` with an initial `solutionSigner`.
2. A user solves some challenge offchain or otherwise obtains the secret required to prove solve status.
3. The signer either verifies the revealed secret or decides offchain that the solve is valid, then signs a payload for that exact user and that exact `data` blob.
4. The user calls `solve(data, signature)`.
5. The contract reconstructs the signed message and verifies the signer.
6. If the signature is valid and the caller is still below the configured per-address limit, the contract increments `solverCounts[msg.sender]`.
7. If a hook is configured, the contract calls `hook(msg.sender, data)`.
8. The contract emits `Solved(msg.sender, count)`.

The important consequence is that the user does not submit a proof that the contract understands semantically. The contract only checks whether the configured signer authorized the submission. Whether that signer is acting as a mere witness to a revealed secret or as a trusted arbiter depends on the application.

## Solve Counts

`ProofOfSolve` tracks solves with a per-address counter:

- `solverCounts[address]` stores how many successful solves that address has recorded
- `solveLimit` is the maximum number of successful solves each address is allowed to accumulate
- `solveLimit == 0` is a sentinel value meaning "no explicit admin-configured cap [at the smart contract level]"

The limit check happens before incrementing:

```solidity
if (solveLimit != 0 && solverCounts[msg.sender] == solveLimit) revert NotAllowed();
uint16 count = ++solverCounts[msg.sender];
```

That means:

- if `solveLimit == 1`, the contract behaves like the old one-time-attestation model
- if `solveLimit == N`, each address can solve successfully `N` times
- each successful call emits the new cumulative count in `Solved(solver, count)`

One implementation detail matters for integrators: both `solveLimit` and `solverCounts` are `uint16`.

- the largest representable count is `65,535`
- when `solveLimit` is nonzero, that type choice is usually fine because the configured cap is also `uint16`
- when `solveLimit == 0`, the contract is still not truly unbounded; a single address can only reach `65535` successful solves before the next increment would overflow and revert

So "unlimited" here should be read as "no configurable limit lower than the type ceiling," not mathematically infinite solves.

## `ProofOfSolve`

### State

The main contract stores seven pieces of state:

- `name`: the human-readable identifier of the puzzle/game
- `solveLimit`: the configured per-address solve cap, where `0` means no explicit admin-configured cap
- `solutionSigner`: the address allowed to authorize solves
- `signerLocked`: whether signer rotation has been permanently disabled
- `postProofHook`: an optional contract called after a successful solve
- `hookLocked`: whether hook updates have been permanently disabled
- `solverCounts[address]`: how many successful solves an address has recorded

The state machine is deliberately simple:

- an address starts at `solverCounts[address] == 0`
- a valid call to `solve` increments the count by `1`
- there is no unset/reset path
- once the count reaches `solveLimit`, additional solve attempts revert (when `solveLimit != 0`)

This makes the contract behave like a bounded per-address attestation counter.

### Constructor

The constructor takes:

- `name_`
- `solveLimit_`
- `initOwner`
- `initSolutionSigner`
- `initPostProofHook`

Constructor rules:

- the signer cannot be the zero address
- the hook may be zero
- if the hook is nonzero, it must be a deployed contract

The constructor emits:

- `SolutionSignerSet(initSolutionSigner)`
- `PostProofHookSet(initPostProofHook)`

### Solve Verification

The `solve(bytes data, bytes signature)` function is the center of the system.

It rejects:

- callers that have already reached `solveLimit` (when a nonzero limit is configured)
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

1. verify the caller is still allowed to solve
2. verify the signature
3. increment the caller's solve count
4. call the hook if configured
5. emit `Solved`

The hook call happens after state is updated, but because the whole transaction reverts atomically, a reverting hook causes the entire solve to fail and the solver's count remains unchanged. This is by design. A solve is only successful if both the base `ProofOfSolve` checks and the configured hook complete successfully. This behavior is tested in `test_solveWithRevertingHook`.

That is an important integration detail: a hook is part of the success path, not a best-effort callback.

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

The owner has four administrative capabilities:

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
- nonzero hook addresses must be deployed contracts
- it cannot be called after the hook has been locked

Setting the hook to `address(0)` disables post-solve hook calls. This is useful if the hook is only needed temporarily, if a hook needs to be paused without replacing it, or if a deployment starts with a hook and later wants to return to counter-only behavior.

### `lockHook()`

This permanently disables future hook updates.

Restrictions:

- only the owner can call it
- it can only be called once

This is the contract's immutability lever for post-solve side effects. Once locked, the current `postProofHook` value remains fixed forever. If the current value is `address(0)`, then the contract permanently has no hook. If the current value is a contract, successful solves permanently call that hook unless the hook itself implements some separate internal disable path.

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
- Enforces a per-address solve cap when `solveLimit` is nonzero.
- Allows optional composition through a hook without complicating the base contract.

### What the system does not try to do

- It does not verify challenge correctness onchain.
- It does not support revocation or admin resets.
- It does not support signature expiries, nonces, or deadlines.
- In `solveLimit == 0` mode, the number of solves per address is still bounded by the `uint16` counter ceiling of `65535`.

### Operational risks

- If the signer key is compromised, arbitrary solves can be authorized.
- If the hook is buggy or malicious, valid solves can be blocked by reverting.
- If the hook trusts unvalidated `data`, it can introduce its own vulnerabilities.
- If the owner rotates the signer unexpectedly, integrators relying on the previous signer can break.
- If the owner updates or disables the hook unexpectedly before `lockHook()` is called, downstream post-solve behavior can change.

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

A hook is appropriate when a successful solve should trigger more than a counter update.

Examples:

- mint an NFT
- issue points
- assign an onchain role in another system
- notify another contract
- store richer solve metadata elsewhere

Hooks are also the right place for most restrictive application logic. The base `ProofOfSolve` registry deliberately stays narrow: it checks the caller's solve limit, verifies that the configured signer authorized the exact `(contract, chain, solver, data)` tuple, increments the counter, and then delegates application-specific behavior to the hook. If an integration needs extra constraints such as challenge phases, eligibility checks, inventory limits, reward rules, or downstream contract requirements, those checks should usually live in the hook instead of being added to the registry.

Because hook execution is part of the same transaction, any hook revert reverts the entire `solve` call. This includes intentional reverts from restrictive hook logic and unintentional reverts from bugs, paused downstream systems, exhausted supply, authorization failures, or deprecated external dependencies. Once a hook has been deployed or locked in, the registry does not have a separate way to know whether that hook will accept a particular call. The only reliable way to find out is to execute the transaction or simulate it with the exact current onchain state.

Because the hook is on the critical path, keep it simple. If the post-solve action is failure-prone or depends on external conditions, consider whether it should happen in a separate user action instead.

## Tests

The test suite covers the contract's important behavior:

- constructor validation
- owner-only admin actions
- signer rotation and signer locking
- hook validation, disabling, and locking
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
- you need to enforce a maximum number of solves per address, such as one-time solver recognition with `solveLimit == 1`; or you are comfortable with solved counts that are effectively unbounded in practical use cases, but still technically bounded by the `uint16` threshold.
- you may want custom post-solve behavior

It is a poor fit when:

- proof verification must be trustless and onchain
- users need truly unbounded completions per address
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

## QED
