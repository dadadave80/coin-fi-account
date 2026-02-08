// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AccountBase} from "../libraries/account/AccountBase.sol";

/// @title AccountFacet
/// @notice A facet for the account contract.
contract AccountFacet is AccountBase {
    /// @dev Initializes the account contract.
    function initialize(address orchestrator, string calldata name, string calldata version) public initializer {
        __AccountBase_init(orchestrator);
        __EIP712_init(name, version);
    }
}
