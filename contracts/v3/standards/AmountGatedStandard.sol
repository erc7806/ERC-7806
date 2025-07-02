// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStandard} from "./../interfaces/IStandard.sol";

/// @title AmountGatedStandard
/// @notice This is an abstract contract that implements the IStandard interface and provides a mechanism to track and validate amounts associated with specific hashes.
abstract contract AmountGatedStandard is IStandard {
    /// @notice AmountUsed event is emitted when an amount is used for a specific hash
    event AmountUsed(address indexed sender, uint256 indexed hash, uint256 amount);

    /// @notice _hashes is a mapping that stores the amount used for a specific hash
    mapping(bytes32 hash => uint256 amount) internal _hashes;

    /// @notice getAmount is a function that returns the amount used for a specific hash
    /// @param sender The address of the sender
    /// @param hash The hash to get the amount for
    /// @return amount The amount used for the specific hash
    function getAmount(address sender, uint256 hash) external view returns (uint256) {
        bytes32 compositeKey = keccak256(abi.encode(sender, hash));
        return _hashes[compositeKey];
    }

    /// @notice markAmount is a function that marks an amount for a specific hash
    /// @param hash The hash to mark the amount for
    /// @param amount The amount to mark
    function markAmount(uint256 hash, uint256 amount) external {
        bytes32 compositeKey = keccak256(abi.encode(msg.sender, hash));
        _hashes[compositeKey] += amount;

        emit AmountUsed(msg.sender, hash, amount);
    }
}
