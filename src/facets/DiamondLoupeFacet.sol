// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {DiamondStorage, Facet, LibDiamond} from "@coinfi-account-lib/diamond/LibDiamond.sol";

contract DiamondLoupeFacet {
    /// @notice Gets all facet addresses and their function selectors.
    function facets() external view returns (Facet[] memory) {
        return LibDiamond.facets();
    }

    /// @notice Gets all the function selectors provided by a facet.
    /// @param _facet The facet address.
    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory) {
        return LibDiamond.facetToSelectors(_facet);
    }

    /// @notice Get all the facet addresses used by a diamond.
    function facetAddresses() external view returns (address[] memory) {
        return LibDiamond.diamondStorage().facetAddresses;
    }

    /// @notice Gets the facet address for a given function selector.
    /// @param _functionSelector The function selector.
    function facetAddress(bytes4 _functionSelector) external view returns (address) {
        return LibDiamond.selectorToFacet(_functionSelector);
    }

    /// @notice Query if a contract implements an interface
    /// @param _interfaceId The interface identifier, as specified in ERC-165
    /// @dev Interface identification is specified in ERC-165. This function
    ///  uses less than 30,000 gas.
    /// @return `true` if the contract implements `interfaceID` and
    ///  `interfaceID` is not 0xffffffff, `false` otherwise
    function supportsInterface(bytes4 _interfaceId) external view returns (bool) {
        return LibDiamond.diamondStorage().supportedInterfaces[_interfaceId];
    }
}
