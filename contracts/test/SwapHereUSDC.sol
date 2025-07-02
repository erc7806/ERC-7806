// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title SwapHereUSDC
/// @notice A simple ERC20 token for testing purposes
contract SwapHereUSDC is ERC20 {
    constructor()
        // solhint-disable-next-line no-empty-blocks
        ERC20("SwapHereUSDC", "shUSDC")
    {}

    /// @notice A function to mint tokens
    /// @param to The address to mint the tokens to
    /// @param amount The amount of tokens to mint
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @notice A function to set approval for another account
    /// @param owner The owner of the tokens
    /// @param spender The spender of the tokens
    /// @param amount The amount of tokens to approve
    /// @return result true if the approval is set
    function approveFor(address owner, address spender, uint256 amount) public returns (bool) {
        _approve(owner, spender, amount);
        return true;
    }

    /// @notice A function to get the decimals of the token
    /// @return result the decimals of the token
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}
