// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Call, LibERC7821} from "./LibERC7821.sol";

// import {Receiver} from "solady/accounts/Receiver.sol";

/// @notice Minimal batch executor mixin.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC7821.sol)
///
/// @dev This contract can be inherited to create fully-fledged smart accounts.
/// If you merely want to combine approve-swap transactions into a single transaction
/// using [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702), you will need to implement basic
/// [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) `isValidSignature` functionality to
/// validate signatures with `ecrecover` against the EOA address. This is necessary because some
/// signature checks skip `ecrecover` if the signer has code. For a basic EOA batch executor,
/// please refer to [BEBE](https://github.com/vectorized/bebe), which inherits from this class.
contract ERC7821 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    EXECUTION OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Executes the calls in `executionData`.
    /// Reverts and bubbles up error if any call fails.
    ///
    /// `executionData` encoding (single batch):
    /// - If `opData` is empty, `executionData` is simply `abi.encode(calls)`.
    /// - Else, `executionData` is `abi.encode(calls, opData)`.
    ///   See: https://eips.ethereum.org/EIPS/eip-7579
    ///
    /// `executionData` encoding (batch of batches):
    /// - `executionData` is `abi.encode(bytes[])`, where each element in `bytes[]`
    ///   is an `executionData` for a single batch.
    ///
    /// Supported modes:
    /// - `0x01000000000000000000...`: Single batch. Does not support optional `opData`.
    /// - `0x01000000000078210001...`: Single batch. Supports optional `opData`.
    /// - `0x01000000000078210002...`: Batch of batches.
    ///
    /// For the "batch of batches" mode, each batch will be recursively passed into
    /// `execute` internally with mode `0x01000000000078210001...`.
    /// Useful for passing in batches signed by different signers.
    ///
    /// Authorization checks:
    /// - If `opData` is empty, the implementation SHOULD require that
    ///   `msg.sender == address(this)`.
    /// - If `opData` is not empty, the implementation SHOULD use the signature
    ///   encoded in `opData` to determine if the caller can perform the execution.
    /// - If `msg.sender` is an authorized entry point, then `execute` MAY accept
    ///   calls from the entry point, and MAY use `opData` for specialized logic.
    ///
    /// `opData` may be used to store additional data for authentication,
    /// paymaster data, gas limits, etc.
    function execute(bytes32 _mode, bytes calldata _executionData) public payable virtual {
        LibERC7821.execute(_mode, _executionData);
    }

    /// @dev Provided for execution mode support detection.
    function supportsExecutionMode(bytes32 _mode) public view virtual returns (bool) {
        return LibERC7821.supportsExecutionMode(_mode);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev 0: invalid mode, 1: no `opData` support, 2: with `opData` support, 3: batch of batches.
    function _executionModeId(bytes32 _mode) internal view virtual returns (uint256) {
        return LibERC7821.executionModeId(_mode);
    }

    /// @dev For execution of a batch of batches.
    function _executeBatchOfBatches(bytes32 _mode, bytes calldata _executionData) internal virtual {
        LibERC7821.executeBatchOfBatches(_mode, _executionData);
    }

    /// @dev Executes the calls.
    /// Reverts and bubbles up error if any call fails.
    /// The `mode` and `executionData` are passed along in case there's a need to use them.
    /// Note: Return `_execute(calls, extraData)` when you override this function.
    function _execute(bytes32 _mode, bytes calldata _executionData, Call[] calldata _calls, bytes calldata _opData)
        internal
        virtual
    {
        LibERC7821.execute(_mode, _executionData, _calls, _opData);
    }

    /// @dev Executes the calls.
    /// Reverts and bubbles up error if any call fails.
    /// `extraData` can be any supplementary data (e.g. a memory pointer, some hash).
    function _execute(Call[] calldata _calls, bytes32 _extraData) internal virtual {
        LibERC7821.execute(_calls, _extraData);
    }

    /// @dev Executes the call.
    /// Reverts and bubbles up error if any call fails.
    /// `extraData` can be any supplementary data (e.g. a memory pointer, some hash).
    function _execute(address _to, uint256 _value, bytes calldata _data, bytes32 _extraData) internal virtual {
        LibERC7821.execute(_to, _value, _data, _extraData);
    }

    /// @dev Convenience function for getting `calls[i]`, without bounds checks.
    function _get(Call[] calldata _calls, uint256 _i) internal view virtual returns (address, uint256, bytes calldata) {
        return LibERC7821.get(_calls, _i);
    }
}
