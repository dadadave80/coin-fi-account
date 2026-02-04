// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Diamond, FacetCut} from "@coinfi-account-diamond/Diamond.sol";
import {Receiver} from "solady/accounts/Receiver.sol";

/// @dev Unauthorized to perform the action.
error Unauthorized();

/// @title Account
/// @notice EIP-7702 Account contract, utilizing ERC-2535 Diamond Standard for upgradability and modularity.
/// @author David Dada <daveproxy80@gmail.com> (https://github.com/dadadave80)
contract Account is Diamond, Receiver {
    /// @dev Modifier to ensure the function is called by the account contract itself.
    modifier onlyThis() {
        if (msg.sender != address(this)) revert Unauthorized();
        _;
    }

    /// @dev Initializes the account with facets, initializer, and calldata.
    function initialize(FacetCut[] calldata _facetCuts, address _init, bytes calldata _calldata)
        public
        virtual
        override
        onlyThis
        initializer
    {
        super.initialize(_facetCuts, _init, _calldata);
    }

    /// @dev Fallback function that delegates calls to the appropriate facet based on function selector
    fallback() external payable virtual override(Receiver, Diamond) receiverFallback {
        _delegate(_facet());
    }
}
