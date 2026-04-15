// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IPostProofHook} from "src/IPostProofHook.sol";

contract RevertingHook is IPostProofHook {
    
    function hook(address, bytes calldata) external pure {
        revert();
    }

}