// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {IStandard} from "./../interfaces/IStandard.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {ERC7806Constants} from "./../libraries/ERC7806Constants.sol";
import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {HashGatedStandard} from "./HashGatedStandard.sol";
import {SafeEIP7702IntentExecutor} from "./../../SafeEIP7702IntentExecutor.sol";

/*
RelayedExecutionStandard

This standard allows sender to define a list of execution instructions and asks the relayer to execute
on chain on behalf of the sender. It is hash and time gated means the intent can only be executed before
a timestamp and can only be executed once.

The first 20 bytes of the `intent` is sender address.
The next 20 bytes of the `intent` is the standard address, which should be equal to address of this standard.
The following is the length section, containing 3 uint16 defining header length, instructions length and signature length.

The header is 64 bytes long.
The first 8 bytes is the timestamp in epoch seconds.
The next 20 bytes is the assigned relayer address, address(0) means the sender wants any relayer to execute.
The next 20 bytes is the payment token address, address(0) means the sender will pay with ETH.
The next 16 bytes is the payment amount.

The instructions are packed into a bytes array.
The first 1-byte is an uint8 defining the number of instructions to execute.
The following instructions are concatenated together, the first 2 bytes (uint16) defines the length of each instruction, the following
is the instruction body. Instructions should be abi.encode(address, uint256, bytes) which can directly be executed by
the sender account.

The signature field is always 65 bytes long. It contains the signed bytes.concat(header, instructions).
*/
contract RelayedExecutionStandard is
    HashGatedStandard,
    SafeEIP7702IntentExecutor
{
    using ECDSA for bytes32;

    string public constant ICS_NUMBER = "ICS1";
    string public constant DESCRIPTION =
        "Timed Hashed Relayed Execution Standard";
    string public constant VERSION = "0.1.0";
    string public constant AUTHOR = "hellohanchen";

    /// @notice The domain separator of this standard
    bytes32 public immutable DOMAIN_SEPARATOR;
    /// @notice The type hash of the signed data of this standard
    bytes32 public immutable SIGNED_DATA_TYPEHASH;

    /// @notice The constructor of this standard
    /// @dev The domain separator and type hash are generated for EIP-712 standard
    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("RelayedExecutionStandard")),
                keccak256(bytes("0.1.0")),
                block.chainid,
                address(this)
            )
        );

        SIGNED_DATA_TYPEHASH = keccak256(
            "Intent(uint64 expiration,address relayer,address paymentToken,uint128 paymentAmount,bytes[] instructions)"
        );
    }

    // --- signature validation ---
    /// @notice The function to hash the bytes array
    function _hashBytesArray(
        bytes[] memory arr,
        uint256 start,
        uint256 end
    ) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) {
            hashes[i - start] = keccak256(arr[i]);
        }

        return keccak256(abi.encodePacked(hashes));
    }

    function _validateSignatures(
        address sender,
        bytes calldata intent,
        bytes[] memory instructions,
        uint256 insStart,
        uint256 insEnd,
        uint256 sigStartIndex
    ) internal view returns (uint256) {
        bytes32 intentHash = keccak256(
            abi.encode(
                SIGNED_DATA_TYPEHASH,
                uint64(bytes8(intent[46:54])), // expiration
                address(bytes20(intent[54:74])), // relayer
                address(bytes20(intent[74:94])), // paymentToken
                uint128(bytes16(intent[94:110])), // paymentAmount
                _hashBytesArray(instructions, insStart, insEnd) // instructions
            )
        );

        bytes32 messageHash = MessageHashUtils.toTypedDataHash(
            DOMAIN_SEPARATOR,
            intentHash
        );
        require(
            sender == messageHash.recover(intent[sigStartIndex:sigStartIndex + 65]),
            "Invalid sender signature"
        );

        return uint256(intentHash);
    }

    function validateUserIntent(
        bytes calldata intent
    ) external view returns (bytes4) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(
            intent
        );
        require(standard == address(this), "Not this standard");
        (
            uint256 headerLength,
            uint256 instructionsLength,
            uint256 signatureLength
        ) = PackedIntent.getLengths(intent);
        require(headerLength == 64, "Invalid header length");
        require(instructionsLength >= 1, "Instructions too short");
        require(signatureLength == 65, "Invalid signature length");
        // end of instructions
        uint256 instructionsSectionEnd = 110 + instructionsLength; // 110 = [sender, standard, lengths] (46) + header length (64)
        require(
            instructionsSectionEnd + 65 == intent.length,
            "Invalid intent length"
        ); // 65 = signature

        // header contains expiration timestamp and assigned relayer (optional)
        require(
            uint256(uint64(bytes8(intent[46:54]))) >= block.timestamp,
            "Intent expired"
        );
        // assignedRelayerAddress = address(intent[54 : 74])

        // first 20 bytes of instruction is out token address
        address paymentTokenAddress = address(bytes20(intent[74:94]));
        // out token amount, use uint128 to shorten the intent
        uint256 paymentAmount = uint256(uint128(bytes16(intent[94:110])));
        if (paymentTokenAddress != address(0)) {
            (bool success, bytes memory data) = paymentTokenAddress.staticcall(
                abi.encodeWithSelector(IERC20.balanceOf.selector, sender)
            );
            if (!success || data.length != 32) {
                revert("Not ERC20 token");
            }
            require(
                abi.decode(data, (uint256)) >= paymentAmount,
                "Insufficient token balance"
            );
        } else {
            require(
                sender.balance >= paymentAmount,
                "Insufficient eth balance"
            );
        }

        // end of outToken instruction
        uint256 numExecutions = uint256(uint8(bytes1(intent[110:111])));
        bytes[] memory instructions = new bytes[](numExecutions);
        // instruction index
        uint256 instructionIndex = 0;
        // begin of the first instruction
        uint256 singleInstructionStart;
        uint256 singleInstructionEnd = 111;

        while (instructionIndex < numExecutions) {
            singleInstructionStart = singleInstructionEnd; // start of next instruction is the end of the previous instruction
            require(
                singleInstructionStart + 2 <= instructionsSectionEnd,
                "Intent too short: instruction length"
            );
            // end of this execution instruction
            singleInstructionEnd =
                singleInstructionStart +
                2 +
                uint256(
                    uint16(
                        bytes2(
                            intent[singleInstructionStart:singleInstructionStart + 2]
                        )
                    )
                );
            require(
                singleInstructionEnd <= instructionsSectionEnd,
                "Intent too short: single instruction"
            );

            instructions[instructionIndex] = intent[singleInstructionStart + 2:singleInstructionEnd];

            instructionIndex += 1;
        }
        require(
            singleInstructionEnd == instructionsSectionEnd,
            "Intent length doesn't match"
        );

        // validate signature
        uint256 hash = _validateSignatures(
            sender,
            intent,
            instructions,
            0,
            instructions.length,
            instructionsSectionEnd
        );
        require(!this.checkHash(sender, hash), "Hash is already executed");

        return ERC7806Constants.VALIDATION_APPROVED;
    }

    function unpackOperations(
        bytes calldata intent
    ) external view returns (bytes4 code, bytes[] memory unpackedInstructions) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        require(standard == address(this), "Not this standard");
        (
            uint256 headerLength,
            uint256 instructionsLength,
            uint256 signatureLength
        ) = PackedIntent.getLengths(intent);
        require(headerLength == 64, "Invalid header length");
        require(instructionsLength >= 1, "Instructions too short");
        require(signatureLength == 65, "Invalid signature length");
        // end of instructions
        uint256 instructionsSectionEnd = 110 + instructionsLength; // 110 = [sender, standard, lengths] (46) + header length (64)
        require(
            instructionsSectionEnd + 65 == intent.length,
            "Invalid intent length"
        ); // 65 = signature

        // fetch header content (timestamp, relayer address [optional])
        require(
            uint256(uint64(bytes8(intent[46:54]))) >= block.timestamp,
            "Intent expired"
        );
        address assignedRelayer = address(bytes20(intent[54:74]));
        // assigned relayer
        require(
            tx.origin == assignedRelayer || address(0) == assignedRelayer,
            "Invalid relayer"
        );

        // total instructions = mark hash + transfer token to relayer + executions
        // the first 1 byte in instructions defines the number of execution instructions
        unpackedInstructions = new bytes[](2 + uint8(bytes1(intent[110:111])));

        // payment token instruction
        address paymentTokenAddress = address(bytes20(intent[74:94]));
        uint256 paymentAmount = uint256(uint128(bytes16(intent[94:110])));
        if (paymentTokenAddress == address(0)) {
            unpackedInstructions[1] = abi.encode(
                address(tx.origin),
                paymentAmount,
                ""
            );
        } else {
            unpackedInstructions[1] = abi.encode(
                paymentTokenAddress,
                uint256(0),
                abi.encodeWithSelector(
                    IERC20.transfer.selector,
                    address(tx.origin),
                    paymentAmount
                )
            );
        }

        // instruction index
        uint256 instructionIndex = 2;
        uint256 singleInstructionEnd = 111;
        uint256 singleInstructionStart;
        while (instructionIndex < unpackedInstructions.length) {
            // start of next execution instruction
            singleInstructionStart = singleInstructionEnd;
            require(
                singleInstructionStart + 2 <= instructionsSectionEnd,
                "Intent too short: instruction length"
            );
            // end of next execution instruction
            singleInstructionEnd =
                singleInstructionStart +
                2 +
                uint256(
                    uint16(
                        bytes2(
                            intent[singleInstructionStart:singleInstructionStart + 2]
                        )
                    )
                );
            require(
                singleInstructionEnd <= instructionsSectionEnd,
                "Intent too short: single instruction"
            );

            unpackedInstructions[instructionIndex] = intent[singleInstructionStart + 2:singleInstructionEnd];

            instructionIndex += 1;
        }
        require(
            singleInstructionEnd == instructionsSectionEnd,
            "Intent length doesn't match"
        );

        uint256 intentHash = _validateSignatures(
            sender,
            intent,
            unpackedInstructions,
            2,
            unpackedInstructions.length,
            instructionsSectionEnd
        );
        require(
            !this.checkHash(sender, intentHash),
            "Hash is already executed"
        );
        // first instruction is mark hash to prevent re-entry attack
        unpackedInstructions[0] = abi.encode(
            address(this),
            0,
            abi.encodeWithSelector(this.markHash.selector, intentHash)
        );

        return (ERC7806Constants.VALIDATION_APPROVED, unpackedInstructions);
    }
}
