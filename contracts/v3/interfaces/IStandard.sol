// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IStandard
/// @notice This is an interface that defines the ERC78006 standard, which needs to implement the validateUserIntent and unpackOperations functions
/// @dev The user intent is a bytes array, the schema definition is delegated to the account and standard implementation
interface IStandard {
    /// @notice validateUserIntent is a function that validates an intent
    /// @dev the validation logic is highly customizable, but the return value SHOULD include the ERC7806Constants.VALIDATION_APPROVED or ERC7806Constants.VALIDATION_DENIED
    /// @param intent The intent to validate
    /// @return result of the validation
    function validateUserIntent(bytes calldata intent) external view returns (bytes4);

    /// @notice unpackOperations is a function that unpacks an intent into executable operations
    /// @dev it is highly RECOMMENDED to include validation logic within this function
    /// @param intent The intent to unpack
    /// @return result validation code and executable operations
    function unpackOperations(bytes calldata intent) external view returns (bytes4, bytes[] memory);
}
