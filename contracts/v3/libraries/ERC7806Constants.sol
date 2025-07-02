// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ERC7806Constants
/// @notice This is a library that defines the constants for the ERC7806 standard
library ERC7806Constants {
    /// @notice VALIDATION_DENIED is the magic value of denied intent
    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    
    /// @notice VALIDATION_APPROVED is the magic value of validated intent
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
}
