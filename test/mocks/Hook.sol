// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IPostProofHook} from "src/IPostProofHook.sol";

contract Hook is IPostProofHook {

    event ReceivedHook(address indexed solver, bytes data);
    
    function hook(address solver, bytes calldata data) external {
        emit ReceivedHook(solver, data);
    }

}