// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {EIP712Lib} from "./EIP712Lib.sol";
import {Initializable} from "solady/utils/Initializable.sol";

/// @notice Contract for EIP-712 typed structured data hashing and signing.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/EIP712.sol)
/// @author Modified from Solbase (https://github.com/Sol-DAO/solbase/blob/main/src/utils/EIP712.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/EIP712.sol)
///
/// @dev Note, this implementation:
/// - Uses `address(this)` for the `verifyingContract` field.
/// - Does NOT use the optional EIP-712 salt.
/// - Does NOT use any EIP-712 extensions.
/// This is for simplicity and to save gas.
/// If you need to customize, please fork / modify accordingly.
abstract contract EIP712 is Initializable {
    using EIP712Lib for *;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Cache the hashes for cheaper runtime gas costs.
    /// In the case of upgradeable contracts (i.e. proxies),
    /// or if the chain id changes due to a hard fork,
    /// the domain separator will be seamlessly calculated on-the-fly.
    function __EIP712_Init(
        string calldata _name,
        string calldata _version
    ) internal virtual onlyInitializing {
        EIP712Lib.eip712Init(_name, _version);
    }

    /// @dev Please override this function to return the domain name and version.
    /// ```
    ///     function _domainNameAndVersion()
    ///         internal
    ///         pure
    ///         virtual
    ///         returns (string memory name, string memory version)
    ///     {
    ///         name = "Solady";
    ///         version = "1";
    ///     }
    /// ```
    ///
    /// Note: If the returned result may change after the contract has been deployed,
    /// you must override `_domainNameAndVersionMayChange()` to return true.
    function _domainNameAndVersion()
        internal
        view
        virtual
        returns (string memory name, string memory version)
    {
        EIP712Lib.domainNameAndVersion();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HASHING OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the EIP-712 domain separator.
    function _domainSeparator()
        internal
        view
        virtual
        returns (bytes32 separator)
    {
        EIP712Lib.domainSeparator();
    }

    /// @dev Returns the hash of the fully encoded EIP-712 message for this domain,
    /// given `structHash`, as defined in
    /// https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct.
    ///
    /// The hash can be used together with {ECDSA-recover} to obtain the signer of a message:
    /// ```
    ///     bytes32 digest = _hashTypedData(keccak256(abi.encode(
    ///         keccak256("Mail(address to,string contents)"),
    ///         mailTo,
    ///         keccak256(bytes(mailContents))
    ///     )));
    ///     address signer = ECDSA.recover(digest, signature);
    /// ```
    function _hashTypedData(
        bytes32 _structHash
    ) internal view virtual returns (bytes32) {
        return EIP712Lib.hashTypedData(_structHash);
    }

    /// @dev Variant of `_hashTypedData` that excludes the chain ID.
    /// Included for the niche use case of cross-chain workflows.
    function _hashTypedDataSansChainId(
        bytes32 _structHash
    ) internal view virtual returns (bytes32) {
        return EIP712Lib.hashTypedDataSansChainId(_structHash);
    }

    /// @dev Variant of `_hashTypedData` that excludes the chain ID and verifying contract.
    /// Included for the niche use case of cross-chain and multi-verifier workflows.
    function _hashTypedDataSansChainIdAndVerifyingContract(
        bytes32 _structHash
    ) internal view virtual returns (bytes32) {
        return
            EIP712Lib.hashTypedDataSansChainIdAndVerifyingContract(_structHash);
    }

    /// @dev Variant of `_hashTypedData` that excludes the chain ID and verifying contract.
    /// Included for the niche use case of multi-verifier workflows.
    function _hashTypedDataSansVerifyingContract(
        bytes32 _structHash
    ) internal view virtual returns (bytes32) {
        return EIP712Lib.hashTypedDataSansVerifyingContract(_structHash);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    EIP-5267 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev See: https://eips.ethereum.org/EIPS/eip-5267
    function eip712Domain()
        public
        view
        virtual
        returns (
            bytes1 fields_,
            string memory name_,
            string memory version_,
            uint256 chainId_,
            address verifyingContract_,
            bytes32 salt_,
            uint256[] memory extensions_
        )
    {
        (
            fields_,
            name_,
            version_,
            chainId_,
            verifyingContract_,
            salt_,
            extensions_
        ) = EIP712Lib.eip712Domain();
    }
}
