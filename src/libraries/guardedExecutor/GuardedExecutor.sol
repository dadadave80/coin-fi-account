// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    CallCheckerInfo,
    GuardedExecutorKeyStorage,
    GuardedExecutorLib,
    SpendInfo,
    SpendPeriod,
    TokenPeriodSpend,
    TokenSpendStorage
} from "./GuardedExecutorLib.sol";
import {Call, ERC7821} from "@coinfi-account-lib/erc7821/ERC7821.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";

/// @title GuardedExecutor
/// @notice Mixin for spend limits and calldata execution guards.
/// @dev
/// Overview:
/// - Execution guards are implemented on a whitelist basis.
///   With the exception of the EOA itself and super admin keys,
///   execution targets and function selectors has to be approved for each new key.
/// - Spend limits are implemented on a whitelist basis.
///   With the exception of the EOA itself and super admin keys,
///   a key cannot spend tokens (ERC20s and native) until spend permissions have been added.
/// - When a spend permission is removed and re-added, its spent amount will be reset.
abstract contract GuardedExecutor is ERC7821 {
    /// @dev Returns the storage pointer.
    function _getGuardedExecutorKeyStorage(bytes32 keyHash) internal view returns (GuardedExecutorKeyStorage storage) {
        return GuardedExecutorLib.getGuardedExecutorKeyStorage(keyHash);
    }

    /// @dev The `_execute` function imposes spending limits with the following:
    /// 1. For every token with a spending limit, the
    ///    `max(sum(outgoingAmounts), balanceBefore - balanceAfter)`
    ///    will be added to the spent limit.
    /// 2. Any token that is granted a non-zero approval will have the approval
    ///    reset to zero after the calls.
    /// 3. Except for the EOA and super admins, a spend limit has to be set for the
    ///    `keyHash` in order for it to spend tokens.
    /// Note: Called internally in ERC7821, which coalesce zero-address `target`s to `address(this)`.
    function _execute(Call[] calldata calls, bytes32 keyHash) internal virtual override {
        GuardedExecutorLib.execute(calls, keyHash);
    }

    /// @dev Override to add a check on `keyHash`.
    /// Note: Called internally in ERC7821, which coalesce zero-address `target`s to `address(this)`.
    function _execute(address target, uint256 value, bytes calldata data, bytes32 keyHash) internal virtual override {
        GuardedExecutorLib.execute(target, value, data, keyHash);
    }

    ////////////////////////////////////////////////////////////////////////
    // Admin Functions
    ////////////////////////////////////////////////////////////////////////

    /// @dev Sets the ability of a key hash to execute a call with a function selector.
    /// Note: Does NOT coalesce a zero-address `target` to `address(this)`.
    function setCanExecute(bytes32 keyHash, address target, bytes4 fnSel, bool can) public virtual {
        GuardedExecutorLib.setCanExecute(keyHash, target, fnSel, can);
    }

    /// @dev Sets a third party call checker, which has a view function
    /// `canExecute(bytes32,address,bytes)` to return if a call can be executed.
    /// By setting `checker` to `address(0)`, it removes the it from the list of
    /// call checkers on this account.
    /// The `ANY_KEYHASH` and `ANY_TARGET` wildcards apply here too.
    function setCallChecker(bytes32 keyHash, address target, address checker) public virtual {
        GuardedExecutorLib.setCallChecker(keyHash, target, checker);
    }

    /// @dev Sets the spend limit of `token` for `keyHash` for `period`.
    function setSpendLimit(bytes32 keyHash, address token, SpendPeriod period, uint256 limit) public virtual {
        GuardedExecutorLib.setSpendLimit(keyHash, token, period, limit);
    }

    /// @dev Removes the spend limit of `token` for `keyHash` for `period`.
    function removeSpendLimit(bytes32 keyHash, address token, SpendPeriod period) public virtual {
        GuardedExecutorLib.removeSpendLimit(keyHash, token, period);
    }

    ////////////////////////////////////////////////////////////////////////
    // Public View Functions
    ////////////////////////////////////////////////////////////////////////

    /// @dev Returns whether a key hash can execute a call.
    /// Note: Does NOT coalesce a zero-address `target` to `address(this)`.
    function canExecute(bytes32 keyHash, address target, bytes calldata data) public view virtual returns (bool) {
        return GuardedExecutorLib.canExecute(keyHash, target, data);
    }

    /// @dev Returns an array of packed (`target`, `fnSel`) that `keyHash` is authorized to execute on.
    /// - `target` is in the upper 20 bytes.
    /// - `fnSel` is in the lower 4 bytes.
    function canExecutePackedInfos(bytes32 keyHash) public view virtual returns (bytes32[] memory) {
        return GuardedExecutorLib.canExecutePackedInfos(keyHash);
    }

    /// @dev Returns an array containing information on all the spends for `keyHash`.
    function spendInfos(bytes32 keyHash) public view virtual returns (SpendInfo[] memory) {
        return GuardedExecutorLib.spendInfos(keyHash);
    }

    /// @dev Returns the list of call checker infos.
    function callCheckerInfos(bytes32 keyHash) public view virtual returns (CallCheckerInfo[] memory) {
        return GuardedExecutorLib.callCheckerInfos(keyHash);
    }

    /// @dev Returns spend and execute infos for each provided key hash in the same order.
    function spendAndExecuteInfos(bytes32[] calldata keyHashes)
        public
        view
        virtual
        returns (SpendInfo[][] memory, bytes32[][] memory)
    {
        return GuardedExecutorLib.spendAndExecuteInfos(keyHashes);
    }

    /// @dev Rounds the unix timestamp down to the period.
    function startOfSpendPeriod(uint256 unixTimestamp, SpendPeriod period) public pure returns (uint256) {
        return GuardedExecutorLib.startOfSpendPeriod(unixTimestamp, period);
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal Helpers
    ////////////////////////////////////////////////////////////////////////

    /// @dev Returns if the call can be executed via consulting a 3rd party checker.
    function _checkCall(bytes32 forKeyHash, bytes32 keyHash, address forTarget, address target, bytes calldata data)
        internal
        view
        returns (bool)
    {
        return GuardedExecutorLib.checkCall(forKeyHash, keyHash, forTarget, target, data);
    }

    /// @dev Returns whether the call is a self execute.
    function _isSelfExecute(address target, bytes4 fnSel) internal view returns (bool) {
        return GuardedExecutorLib.isSelfExecute(target, fnSel);
    }

    /// @dev Returns a bytes32 value that contains `target` and `fnSel`.
    function _packCanExecute(address target, bytes4 fnSel) internal pure returns (bytes32 result) {
        return GuardedExecutorLib.packCanExecute(target, fnSel);
    }

    /// @dev Increments the amount spent.
    function _incrementSpent(TokenSpendStorage storage s, address token, uint256 amount) internal {
        GuardedExecutorLib.incrementSpent(s, token, amount);
    }

    /// @dev Stores the spend struct.
    function _storeSpend(LibBytes.BytesStorage storage $, TokenPeriodSpend memory spend) internal {
        GuardedExecutorLib.storeSpend($, spend);
    }

    /// @dev Loads the spend struct.
    function _loadSpend(LibBytes.BytesStorage storage $) internal view returns (TokenPeriodSpend memory spend) {
        return GuardedExecutorLib.loadSpend($);
    }

    ////////////////////////////////////////////////////////////////////////
    // Configurables
    ////////////////////////////////////////////////////////////////////////

    /// @dev To be overriden to return if `keyHash` corresponds to a super admin key.
    function _isSuperAdmin(bytes32 keyHash) internal view virtual returns (bool);

    /// @dev To be overriden to return the storage slot seed for a `keyHash`.
    function _getGuardedExecutorKeyStorageSeed(bytes32 keyHash) internal view virtual returns (bytes32);
}
