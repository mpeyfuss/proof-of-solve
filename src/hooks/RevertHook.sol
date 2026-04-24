// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IPostProofHook} from "../IPostProofHook.sol";

contract RevertHook is IPostProofHook {

    /// @inheritdoc IPostProofHook
    function hook(address /*solver*/, bytes calldata /*data*/) external pure {
        revert("closed");
    }
    
}