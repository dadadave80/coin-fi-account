// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AccountLib, Call, Key, Unauthorized} from "./AccountLib.sol";
import {EIP712Lib} from "@coinfi-account-lib//eip712/EIP712Lib.sol";
import {EIP712} from "@coinfi-account-lib/eip712/EIP712.sol";
import {GuardedExecutor} from "@coinfi-account-lib/guardedexecutor/GuardedExecutor.sol";
import {Initializable} from "solady/utils/Initializable.sol";

/// @title AccountBase
/// @notice A base account contract for EOAs with EIP7702.
contract AccountBase is Initializable, EIP712, GuardedExecutor {
    /// @dev For EIP712 signature digest calculation for the `execute` function.
    bytes32 public constant EXECUTE_TYPEHASH =
        keccak256("Execute(bool multichain,Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)");

    /// @dev For EIP712 signature digest calculation for the `execute` function.
    bytes32 public constant CALL_TYPEHASH = keccak256("Call(address to,uint256 value,bytes data)");

    /// @dev For EIP712 signature digest calculation.
    bytes32 public constant DOMAIN_TYPEHASH = EIP712Lib._DOMAIN_TYPEHASH;

    /// @dev For ERC1271 replay-safe hashing.
    bytes32 public constant SIGN_TYPEHASH = keccak256("ERC1271Sign(bytes32 digest)");

    /// @dev Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
    /// This constant is a pun for "chain ID 0".
    uint16 public constant MULTICHAIN_NONCE_PREFIX = 0xc1d0;

    /// @dev A unique identifier to be passed into `upgradeHook(bytes32 previousVersion)`
    /// via the transient storage slot at `_UPGRADE_HOOK_GUARD_TRANSIENT_SLOT`.
    bytes32 internal constant _UPGRADE_HOOK_ID = keccak256("ITHACA_ACCOUNT_UPGRADE_HOOK_ID");

    /// @dev This transient slot must be set to `_UPGRADE_HOOK_ID` before `upgradeHook` can be processed.
    bytes32 internal constant _UPGRADE_HOOK_GUARD_TRANSIENT_SLOT =
        bytes32(uint256(keccak256("_UPGRADE_HOOK_GUARD_TRANSIENT_SLOT")) - 1);

    /// @dev List of keyhashes that have authorized the current execution context.
    /// Increasing in order of recursive depth.
    uint256 internal constant _KEYHASH_STACK_TRANSIENT_SLOT = uint256(keccak256("_KEYHASH_STACK_TRANSIENT_SLOT")) - 1;

    /// @dev General capacity for enumerable sets,
    /// to prevent off-chain full enumeration from running out-of-gas.
    uint256 internal constant _CAP = 512;

    ////////////////////////////////////////////////////////////////////////
    // Constructor
    ////////////////////////////////////////////////////////////////////////

    constructor() payable {
        _disableInitializers();
    }

    function __AccountBase_init(address orchestrator) internal virtual onlyInitializing {
        AccountLib.getAccountStorage().ORCHESTRATOR = orchestrator;
    }

    ////////////////////////////////////////////////////////////////////////
    // ERC1271
    ////////////////////////////////////////////////////////////////////////

    /// @dev Variant of `_hashTypedData` that includes only the verifying contract.
    function _hashTypedDataOnlyVerifyingContract(bytes32 structHash) internal view virtual returns (bytes32) {
        return AccountLib.hashTypedDataOnlyVerifyingContract(structHash);
    }

    /// @dev Checks if a signature is valid.
    /// Note: For security reasons, we can only let this function validate against the
    /// original EOA key and other super admin keys.
    /// Otherwise, any session key can be used to approve infinite allowances
    /// via Permit2 by default, which will allow apps infinite power.
    /// @dev Note: The rehashing scheme is not EIP-5267 compliant.
    /// A different domain separator is used for the rehashing, which excludes `name` and `version`
    /// from the domain, for latency improvements offchain.
    function isValidSignature(bytes32 digest, bytes calldata signature) public view virtual returns (bytes4) {
        return AccountLib.isValidSignature(digest, signature);
    }

    ////////////////////////////////////////////////////////////////////////
    // Admin Functions
    ////////////////////////////////////////////////////////////////////////

    // The following functions can only be called by this contract.
    // If a signature is required to call these functions, please use the `execute`
    // function with `auth` set to `abi.encode(nonce, signature)`.

    /// @dev Sets the label.
    function setLabel(string calldata newLabel) public virtual onlyThis {
        AccountLib.setLabel(newLabel);
    }

    /// @dev Revokes the key corresponding to `keyHash`.
    function revoke(bytes32 keyHash) public virtual onlyThis {
        AccountLib.removeKey(keyHash);
    }

    /// @dev Authorizes the key.
    function authorize(Key memory key) public virtual onlyThis returns (bytes32) {
        return AccountLib.addKey(key);
    }

    /// @dev Sets whether `checker` can use `isValidSignature` to successfully validate
    /// a signature for a given key hash.
    function setSignatureCheckerApproval(bytes32 keyHash, address checker, bool isApproved) public virtual onlyThis {
        AccountLib.setSignatureCheckerApproval(keyHash, checker, isApproved);
    }

    /// @dev Increments the sequence for the `seqKey` in nonce (i.e. upper 192 bits).
    /// This invalidates the nonces for the `seqKey`, up to (inclusive) `uint64(nonce)`.
    function invalidateNonce(uint256 nonce) public virtual onlyThis {
        AccountLib.invalidateNonce(nonce);
    }

    // /// @dev Upgrades the proxy account.
    // /// If this account is delegated directly without usage of EIP7702Proxy,
    // /// this operation will not affect the logic until the authority is redelegated
    // /// to a proper EIP7702Proxy. The `newImplementation` should implement
    // /// `upgradeProxyAccount` or similar, otherwise upgrades will be locked and
    // /// only a new EIP-7702 transaction can change the authority's logic.
    // function upgradeProxyAccount(
    //     address newImplementation
    // ) public virtual onlyThis {
    //     if (newImplementation == address(0)) revert NewImplementationIsZero();
    //     LibEIP7702.upgradeProxyDelegation(newImplementation);
    //     (, string memory version) = _domainNameAndVersion();
    //     // Using a dedicated guard makes the hook only callable via this function
    //     // prevents direct self-calls which may accidentally use the wrong hook ID and version.
    //     LibTransient.tBytes32(_UPGRADE_HOOK_GUARD_TRANSIENT_SLOT).set(
    //         _UPGRADE_HOOK_ID
    //     );
    //     // We MUST use `this`, so that it uses the new implementation's `upgradeHook`.
    //     require(this.upgradeHook(LibString.toSmallString(version)));
    // }

    // /// @dev For this very first version, the upgrade hook is just an no-op.
    // /// Provided to enable calling it via plain Solidity.
    // /// For future implementations, we will have an upgrade hook which can contain logic
    // /// to migrate storage on a case-by-case basis if needed.
    // /// If this hook is implemented to mutate storage,
    // /// it MUST check that `_UPGRADE_HOOK_GUARD_TRANSIENT_SLOT` is correctly set.
    // function upgradeHook(
    //     bytes32 previousVersion
    // ) external virtual onlyThis returns (bool) {
    //     previousVersion = previousVersion; // Silence unused variable warning.
    //     // Example of how we are supposed to load, check and clear the upgrade hook guard.
    //     bytes32 hookId = LibTransient
    //         .tBytes32(_UPGRADE_HOOK_GUARD_TRANSIENT_SLOT)
    //         .get();
    //     require(hookId == _UPGRADE_HOOK_ID);
    //     LibTransient.tBytes32(_UPGRADE_HOOK_GUARD_TRANSIENT_SLOT).clear();
    //     // Always returns true for cheaper call success check (even in plain Solidity).
    //     return true;
    // }

    ////////////////////////////////////////////////////////////////////////
    // Public View Functions
    ////////////////////////////////////////////////////////////////////////

    /// @dev Return current nonce with sequence key.
    function getNonce(uint192 seqKey) public view virtual returns (uint256) {
        return AccountLib.getNonce(seqKey);
    }

    /// @dev Returns the label.
    function label() public view virtual returns (string memory) {
        return AccountLib.label();
    }

    /// @dev Returns the number of authorized keys.
    function keyCount() public view virtual returns (uint256) {
        return AccountLib.keyCount();
    }

    /// @dev Returns the authorized key at index `i`.
    function keyAt(uint256 i) public view virtual returns (Key memory) {
        return AccountLib.keyAt(i);
    }

    /// @dev Returns the key corresponding to the `keyHash`. Reverts if the key does not exist.
    function getKey(bytes32 keyHash) public view virtual returns (Key memory) {
        return AccountLib.getKey(keyHash);
    }

    /// @dev Returns arrays of all (non-expired) authorized keys and their hashes.
    function getKeys() public view virtual returns (Key[] memory, bytes32[] memory) {
        return AccountLib.getKeys();
    }

    /// @dev Return the key hash that signed the latest execution context.
    /// @dev Returns bytes32(0) if the EOA key was used.
    function getContextKeyHash() public view virtual returns (bytes32) {
        return AccountLib.getContextKeyHash();
    }

    /// @dev Returns the hash of the key, which does not includes the expiry.
    function hash(Key memory key) public pure virtual returns (bytes32) {
        // `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`.
        return AccountLib.hash(key);
    }

    /// @dev Returns the list of approved signature checkers for `keyHash`.
    function approvedSignatureCheckers(bytes32 keyHash) public view virtual returns (address[] memory) {
        return AccountLib.approvedSignatureCheckers(keyHash);
    }

    /// @dev Computes the EIP712 digest for `calls`.
    /// If the the nonce starts with `MULTICHAIN_NONCE_PREFIX`,
    /// the digest will be computed without the chain ID.
    /// Otherwise, the digest will be computed with the chain ID.
    function computeDigest(Call[] calldata calls, uint256 nonce) public view virtual returns (bytes32 result) {
        return AccountLib.computeDigest(calls, nonce);
    }

    /// @dev Returns if the signature is valid, along with its `keyHash`.
    /// The `signature` is a wrapped signature, given by
    /// `abi.encodePacked(bytes(innerSignature), bytes32(keyHash), bool(prehash))`.
    function unwrapAndValidateSignature(bytes32 digest, bytes calldata signature)
        public
        view
        virtual
        returns (bool isValid, bytes32 keyHash)
    {
        return AccountLib.unwrapAndValidateSignature(digest, signature);
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal Helpers
    ////////////////////////////////////////////////////////////////////////

    /// @dev Adds the key. If the key already exist, its expiry will be updated.
    function _addKey(Key memory key) internal virtual returns (bytes32) {
        return AccountLib.addKey(key);
    }

    /// @dev Removes the key corresponding to the `keyHash`. Reverts if the key does not exist.
    function _removeKey(bytes32 keyHash) internal virtual {
        AccountLib.removeKey(keyHash);
    }

    ////////////////////////////////////////////////////////////////////////
    // Orchestrator Functions
    ////////////////////////////////////////////////////////////////////////

    /// @dev Checks current nonce and increments the sequence for the `seqKey`.
    function checkAndIncrementNonce(uint256 nonce) public payable virtual {
        AccountLib.checkAndIncrementNonce(nonce);
    }

    /// @dev Pays `paymentAmount` of `paymentToken` to the `paymentRecipient`.
    function pay(uint256 paymentAmount, bytes32 keyHash, bytes32 intentDigest, bytes calldata encodedIntent)
        public
        virtual
    {
        AccountLib.pay(paymentAmount, keyHash, intentDigest, encodedIntent);
    }

    ////////////////////////////////////////////////////////////////////////
    // ERC7821
    ////////////////////////////////////////////////////////////////////////

    /// @dev For ERC7821.
    function _execute(bytes32 mode, bytes calldata executionData, Call[] calldata calls, bytes calldata opData)
        internal
        virtual
        override
    {
        AccountLib.execute(mode, executionData, calls, opData);
    }

    ////////////////////////////////////////////////////////////////////////
    // GuardedExecutor
    ////////////////////////////////////////////////////////////////////////

    /// @dev Returns if `keyHash` corresponds to a super admin key.
    function _isSuperAdmin(bytes32 keyHash) internal view virtual override returns (bool) {
        return AccountLib.isSuperAdmin(keyHash);
    }

    /// @dev Returns the storage seed for a `keyHash`.
    function _getGuardedExecutorKeyStorageSeed(bytes32 keyHash) internal view virtual override returns (bytes32) {
        return AccountLib.getGuardedExecutorKeyStorageSeed(keyHash);
    }

    ////////////////////////////////////////////////////////////////////////
    // EIP712
    ////////////////////////////////////////////////////////////////////////

    /// @dev For EIP712.
    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "IthacaAccount";
        version = "0.5.10";
    }

    /// @dev Guards a function such that it can only be called by `address(this)`.
    modifier onlyThis() {
        if (msg.sender != address(this)) revert Unauthorized();
        _;
    }
}
