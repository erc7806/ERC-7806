// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ITokenRelayer
/// @notice This is an interface that can transfer ETH and ERC20 tokens in a permissionless manner.
/// @dev The ITokenRelayer implementation MUST be used as a token holder, tokens transferred to ITokenRelayer should be transferred out to other addresses within the same transaction
/// @dev token receiver is RECOMMENDED to be the msg.sender
interface ITokenRelayer {
    /// @notice transferEth is a function that transfers ETH
    /// @param amount The amount of ETH to transfer
    function transferEth(uint256 amount) external;

    /// @notice transferERC20 is a function that transfers ERC20 tokens
    /// @param token The address of the ERC20 token to transfer
    /// @param amount The amount of ERC20 tokens to transfer
    function transferERC20(address token, uint256 amount) external;

    /// @notice transferERC20From is a function that transfers ERC20 tokens from a specific address
    /// @dev the caller must have approval to transfer the ERC20 tokens from the sender
    /// @dev the from parameter is RECOMMENDED to be the tx.origin only
    /// @param from The address of the sender
    /// @param token The address of the ERC20 token to transfer
    /// @param amount The amount of ERC20 tokens to transfer
    function transferERC20From(address from, address token, uint256 amount) external;
}
