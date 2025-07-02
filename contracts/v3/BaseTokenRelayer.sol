// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ITokenRelayer} from "./interfaces/ITokenRelayer.sol";

/// @title BaseTokenRelayer
/// @notice This is a base implementation of ITokenRelayer
/// @dev The tokens will be transferred to msg.sender
contract BaseTokenRelayer is ITokenRelayer {
    /// @notice The function to transfer ETH to the sender
    /// @param amount The amount of ETH to transfer
    function transferEth(uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient balance");
        payable(msg.sender).transfer(amount);
    }

    /// @notice The function to transfer ERC20 tokens to the sender
    /// @param token The address of the ERC20 token
    /// @param amount The amount of ERC20 tokens to transfer
    function transferERC20(address token, uint256 amount) external {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20.transfer.selector, msg.sender, amount)
        );

        require(success && (data.length == 0 || abi.decode(data, (bool))), "Failed to ERC20 transfer");
    }

    /// @notice The function to transfer ERC20 tokens from the sender to the relayer
    /// @dev tx.origin needs to makes sure the usage of this function is safe
    /// @param from The address of the sender, can only be tx.origin or this address
    /// @param token The address of the ERC20 token
    /// @param amount The amount of ERC20 tokens to transfer
    function transferERC20From(address from, address token, uint256 amount) external {
        require(from == tx.origin || from == address(this), "Can only transfer from tx.origin or this address");
        if (from == tx.origin) {
            (bool success, bytes memory data) = token.call(
                abi.encodeWithSelector(IERC20.transferFrom.selector, from, msg.sender, amount)
            );

            require(success && (data.length == 0 || abi.decode(data, (bool))), "Failed to ERC20 transferFrom");
        } else {
            (bool success, bytes memory data) = token.call(
                abi.encodeWithSelector(IERC20.transfer.selector, msg.sender, amount)
            );

            require(success && (data.length == 0 || abi.decode(data, (bool))), "Failed to ERC20 transfer");
        }
    }

    /// @notice The function to receive ETH
    receive() external payable {}
}
