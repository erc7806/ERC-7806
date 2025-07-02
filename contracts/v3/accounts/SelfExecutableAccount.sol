// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {IAccount} from "./../interfaces/IAccount.sol";

/// @title SelfExecutableAccount
/// @notice This is an abstract contract that implements the IAccount interface that handles self-standard and external standards in different ways. The self-standard execution implementation is fixed, while the external standard execution implementation is customizable.
/// @dev Self-standard means the standard address is the same as the account address
abstract contract SelfExecutableAccount is IAccount {
    /// @notice ExecutionError is an error that is thrown when an execution fails
    error ExecutionError();

    /// @notice executeUserIntent is a function that executes an intent
    /// @dev to execute a self-standard intent, the intent must be sent from the same address as the account
    /// @param intent The intent to execute
    /// @return result of the execution
    function executeUserIntent(bytes calldata intent) external returns (bytes memory) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        require(address(this) == sender, "Not intent sender");

        if (address(this) == tx.origin && address(this) == standard) {
            return executeSelfIntent(intent);
        }

        return executeOtherIntent(intent, standard);
    }

    /// @notice executeSelfIntent is a function that executes an intent on self-standard
    /// @dev this self-standard execution is fixed, the instructions to executed are concantenated into the intent and there is no signature needed
    /// @param intent The intent to execute
    /// @return result of the execution
    function executeSelfIntent(bytes calldata intent) internal returns (bytes memory) {
        (uint256 headerLength, uint256 instructionLength,) = PackedIntent.getLengths(intent);
        // no signature
        require(intent.length == headerLength + instructionLength + 46, "Lengths not match");
        
        // start pointer, skip (32-bytes offset, sender, standard, 3 x lengths, header)
        uint256 instructionStartIndex = 78 + headerLength;

        address dest;
        bytes1 hasValue;
        bool success;
        uint16 dataLength;

        for (uint256 i = 0; i < headerLength; i += 2) {
            dataLength = uint16(bytes2(intent[46 + i : 48 + i]));
            dest = address(bytes20(intent[instructionStartIndex : instructionStartIndex + 20]));
            hasValue = bytes1(intent[instructionStartIndex + 20 : instructionStartIndex + 21]);
            if (hasValue == bytes1(0x01)) {
                (success,) = dest.call{
                    value : uint256(bytes32(intent[instructionStartIndex + 21 : instructionStartIndex + 53])),
                    gas : gasleft()
                }(intent[instructionStartIndex + 53 : instructionStartIndex + 53 + dataLength]);
                instructionStartIndex = instructionStartIndex + 53 + dataLength;
            } else {
                (success,) = dest.call{
                value : uint256(bytes32(intent[instructionStartIndex + 21 : instructionStartIndex + 53])),
                gas : gasleft()
                }(intent[instructionStartIndex + 21 : instructionStartIndex + 21 + dataLength]);
                instructionStartIndex = instructionStartIndex + 21 + dataLength;
            }

            if (!success) {
                revert ExecutionError();
            }
        }

        return new bytes(0);
    }

    /// @notice executeOtherIntent is a function that executes an intent on an external standard
    /// @param intent The intent to execute
    /// @param standard The address of the standard
    /// @return result of the execution
    function executeOtherIntent(bytes calldata intent, address standard) internal virtual returns (bytes memory);
}
