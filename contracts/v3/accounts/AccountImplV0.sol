// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {StandardRegistryV2} from "./../../StandardRegistryV2.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {SelfExecutableAccount} from "./SelfExecutableAccount.sol";
import {ERC7806Constants} from "./../libraries/ERC7806Constants.sol";

/// @title AccountImplV0
/// @notice This is a stateless account that can execute intents on self-standard or external standards
contract AccountImplV0 is SelfExecutableAccount {
    /// @notice DESCRIPTION is the description of the account
    string public constant DESCRIPTION = "Account with Batch Execution, Standard Registry and Self-Standard";
    /// @notice VERSION is the version of the account
    string public constant VERSION = "0.0.0";
    /// @notice AUTHOR is github account of the author of the account
    string public constant AUTHOR = "hellohanchen";

    /// @notice The AccountImplV0 is a stateless account, so it delegates the standard access control to the StandardRegistryV2 contract
    /// @dev This is a constant address that could be used by other ERC7806 accounts as well
    StandardRegistryV2 public constant REGISTRY = StandardRegistryV2(0x1EcBE25525F6e6cDe8631e602Df6D55D3967cDF8);

    /// @notice executeOtherIntent is a function that executes an intent on an external standard
    /// @param intent The intent to execute
    /// @param standard The standard to execute the intent on
    /// @return result of the execution
    function executeOtherIntent(bytes calldata intent, address standard) override internal returns (bytes memory) {
        require(REGISTRY.isRegistered(address(this), standard), "Standard not registered");
        // standard validation and unpack
        (bytes4 validationCode, bytes[] memory instructions) = IStandard(standard).unpackOperations(intent);
        require(validationCode == ERC7806Constants.VALIDATION_APPROVED, "Validation failed");

        // batch execute
        for (uint256 i = 0; i < instructions.length; ++i) {
            (address dest, uint256 value, bytes memory data) = abi.decode(instructions[i], (address, uint256, bytes));

            (bool success,) = dest.call{value : value, gas : gasleft()}(data);
            if (!success) {
                revert SelfExecutableAccount.ExecutionError();
            }
        }

        return new bytes(0);
    }

    /// @notice receive is a function that receives ETH
    receive() external payable {}
}
