// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IAccount
/// @notice This is an interface that defines the ERC78006 account, which needs to implement the executeUserIntent function
/// @dev The user intent is a bytes array, the schema definition is delegated to the account and standard implementation
interface IAccount {
    /// @notice executeUserIntent is a function that executes an intent
    /// @param intent The intent to execute
    /// @return result of the execution
    function executeUserIntent(bytes calldata intent) external returns (bytes memory);
}
