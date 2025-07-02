// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ITokenRelayer} from "./../interfaces/ITokenRelayer.sol";
import {IAccount} from "./../interfaces/IAccount.sol";
import {ERC7806Constants} from "./../libraries/ERC7806Constants.sol";
import {PackedIntent} from "./../libraries/PackedIntent.sol";
import {AmountGatedStandard} from "./AmountGatedStandard.sol";
import {BaseTokenRelayer} from "./../BaseTokenRelayer.sol";

/**
@title PartialTokenSwapStandard
@notice This is a standard that allows sender to defines an order that swaps 2 tokens (native or ERC20). It is amount and time gated, meaning the intent can only be executed before a timestamp (expiration) or before the amount is fulfilled.

This standard follows the PackedIntent library's intent schame with its specific intent header, instructions and signature format:

The header is fixed to be 32 bytes long.
- The first 1 byte (uint8) is either "0x0" or "0x1", representing partial order and full order.
- The next 3 bytes (uint24) are a random salt to allow users placing the same order multiple times.
- The following 8 bytes (uint64) are the timestamp in epoch seconds.
- The last 20 bytes (address) are the solver of this intent.
  - When the solver is address(0), the intent is for validation only and can't be executed.
  - When the solver is the sender, the intent is self-solved and only 1 signature is needed.
  - When the solver is not the sender, the intent is relayed and 2 signatures are needed.

The instructions contains 3 main part.
- The first 36 bytes are packed encoded (address, uint128) pair representing the token and maximum amount the sender is willing to send out.
- The next 36 bytes are packed encoded (address, uint128) pair representing the token and amount the sender will get back when the out amount is at max.
- The following 16 bytes (uint128) are the out token amount of this execution. Only partial order needs this and this field is filled in by the solver.

The signature field is 65 bytes long if the intent solver is sender, 130 bytes long if the intent solver is not the sender.

When executing, the operations will be carried out in the following order:
- mark amount
- transfer out token with amount to the relayer
- execute nested intents (if any)
- transfer in token back from the relayer

This standard allows nested intents to follow it, the first byte (uint8) after the intent body defines the number of nested intents. Then the first 2-bytes of each nested intent defines the total length of the corresponding intent.

@dev The unpackOperations method should only be called if the intent is validated by validateUserIntent.
@dev To improve user experience and enhance security, this standard is using EIP-712 standard for intent signing and verification.
*/
contract PartialTokenSwapStandard is AmountGatedStandard, BaseTokenRelayer {
    using ECDSA for bytes32;

    /// @notice The description of this standard
    string public constant DESCRIPTION = "Timed Hashed Pre-Delegated Partial ERC20 Token Swap Standard";
    /// @notice The version of this standard
    string public constant VERSION = "0.1.0";
    /// @notice The github account of the author of this standard
    string public constant AUTHOR = "hellohanchen";

    /// @notice This is a special validation code when the solver is address(0)
    bytes4 public constant VALIDATION_APPROVED_SENDER_ONLY = 0x00000002;
    /// @notice The domain separator of this standard
    bytes32 public immutable DOMAIN_SEPARATOR;
    /// @notice The type hash of the signed data of this standard
    bytes32 public immutable SIGNED_DATA_TYPEHASH;

    /// @notice The constructor of this standard
    /// @dev The domain separator and type hash are generated for EIP-712 standard
    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("PartialTokenSwapStandard")),
                keccak256(bytes("0.1.0")),
                block.chainid,
                address(this)
            )
        );

        SIGNED_DATA_TYPEHASH = keccak256(
            "Order(bool isFullOrder,uint24 salt,uint64 expiration,address solver,address outToken,uint128 outAmount,address inToken,uint128 inAmount)"
        );
    }

    /// @notice The function to validate the user intent
    /// @dev The function is used to validate the user intent
    /// @param intent The intent to validate
    /// @return result code of the validation
    function validateUserIntent(bytes calldata intent) external view returns (bytes4) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        require(standard == address(this), "Not this standard");
        (uint256 headerLength, uint256 instructionsLength, uint256 signatureLength) = PackedIntent.getLengths(intent);
        require(headerLength == 32, "Invalid header length");
        require(intent.length >= 78 + instructionsLength + signatureLength, "Not enough intent length");
        // isFullOrder
        bool isFullOrder = bytes1(intent[46 : 47]) == bytes1(0x01);
        if (isFullOrder) {
            require(instructionsLength == 72, "Invalid full order instruction length");
        } else {
            require(instructionsLength == 88, "Invalid partial order instruction length");
        }
        uint256 signatureStart = 78 + instructionsLength;
        require(signatureLength == 65 || signatureLength == 130, "Invalid signature length");

        // fetch header content
        // salt = uint24(bytes3(intent[48:50]));  // we don't need to parse salt
        uint256 expiration = uint256(uint64(bytes8(intent[50 : 58])));
        // timestamp
        require(expiration >= block.timestamp, "Intent expired");

        // validate out token instruction
        // after header
        address outTokenAddress = address(bytes20(intent[78 : 98]));
        // max out token amount
        uint256 maxOutTokenAmount = uint256(uint128(bytes16(intent[98 : 114])));
        // amount of out token for this oder
        uint256 orderOutTokenAmount = isFullOrder ? maxOutTokenAmount : uint256(uint128(bytes16(intent[150 : 166])));
        if (outTokenAddress != address(0)) {
            (bool success, bytes memory data) = outTokenAddress.staticcall(abi.encodeCall(IERC20.balanceOf, (sender)));
            if (!success || data.length != 32) {
                revert("Not ERC20 token");
            }
            require(abi.decode(data, (uint256)) >= orderOutTokenAmount, "Insufficient token balance");
        } else {
            require(sender.balance >= orderOutTokenAmount, "Insufficient eth balance");
        }

        // after outToken ins is the inToken instruction
        address inTokenAddress = address(bytes20(intent[114 : 134]));
        if (inTokenAddress != address(0)) {
            (bool success, bytes memory data) = inTokenAddress.staticcall(abi.encodeCall(IERC20.totalSupply, ()));
            if (!success || data.length != 32) {
                revert("Not ERC20 token");
            }
        }

        (uint8 numValidatedSignatures, uint256 intentHash) = _validateSignatures(sender, address(bytes20(intent[58 : 78])), intent, signatureStart);
        if (numValidatedSignatures == 0) {
            return VALIDATION_APPROVED_SENDER_ONLY;
        }
        if (numValidatedSignatures == 1) {
            require(signatureLength == 65, "Only 1 signature is needed");
        }
        require(this.getAmount(sender, intentHash) + orderOutTokenAmount <= maxOutTokenAmount, "Order limit exceeded");

        // no need to validate nested intent as that should be validated separately
        return ERC7806Constants.VALIDATION_APPROVED;
    }

    /// @notice The function to unpack the operations of this standard
    /// @dev The function is used to unpack the operations of this standard
    /// @param intent The intent to unpack
    /// @return code of the validation
    /// @return unpackedInstructions the unpacked instructions
    function unpackOperations(bytes calldata intent) external view returns (bytes4 code, bytes[] memory unpackedInstructions) {
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        require(standard == address(this), "Not this standard");
        bool isFullOrder = bytes1(intent[46 : 47]) == bytes1(0x01);
        // signature offset
        uint256 signatureStartIndex = isFullOrder ? 150 : 166;

        // fetch header content
        // salt = uint24(bytes3(intent[48:50]));  // we don't need to parse salt
        // timestamp
        require(uint256(uint64(bytes8(intent[50 : 58]))) >= block.timestamp, "Intent expired");
        (uint8 numValidatedSignatures, uint256 intentHash) = _validateSignatures(sender, address(bytes20(intent[58 : 78])), intent, signatureStartIndex);
        // solver != address(0), this numUsedSig should only be 1 or 2
        require(numValidatedSignatures != 0, "Solver is not assigned");
        // total length of this intent
        uint256 currentIntentLength = numValidatedSignatures == 1 ? signatureStartIndex + 65 : signatureStartIndex + 130;
        // # of nested intents
        uint8 numNestedIntents = intent.length == currentIntentLength ? 0 : uint8(bytes1(intent[currentIntentLength : currentIntentLength + 1]));

        // total instructions = mark amount + transfer out + nestIntents execution (optional) + transfer in
        unpackedInstructions = new bytes[](3 + numNestedIntents);

        // out token instruction, send token to tx.origin (aka. relayer)
        address outTokenAddress = address(bytes20(intent[78 : 98]));
        // max amount
        uint256 maxOutTokenAmount = uint256(uint128(bytes16(intent[98 : 114])));
        // out amount of this order
        uint256 orderOutTokenAmount = isFullOrder ? maxOutTokenAmount : uint256(uint128(bytes16(intent[150 : 166])));
        require(this.getAmount(sender, intentHash) + orderOutTokenAmount <= maxOutTokenAmount, "Order limit exceeded");

        // first instruction is mark amount to prevent re-entry attack
        unpackedInstructions[0] = abi.encode(
            address(this), 0, abi.encodeCall(AmountGatedStandard.markAmount, (intentHash, orderOutTokenAmount)));

        // out token instruction
        if (outTokenAddress == address(0)) {
            unpackedInstructions[1] = abi.encode(tx.origin, orderOutTokenAmount, "");
        } else {
            unpackedInstructions[1] = abi.encode(
                outTokenAddress,
                uint256(0),
                abi.encodeCall(IERC20.transfer, (tx.origin, orderOutTokenAmount)));
        }

        address inTokenAddress = address(bytes20(intent[114 : 134]));
        // max in amount
        uint256 maxInTokenAmount = uint256(uint128(bytes16(intent[134 : 150])));
        // in token amount of this order
        uint256 orderInTokenAmount = isFullOrder ? maxInTokenAmount : (maxInTokenAmount * orderOutTokenAmount) / maxOutTokenAmount;
        // can't take in 0 amount
        orderInTokenAmount = orderInTokenAmount > 0 ? orderInTokenAmount : 1;
        // max operation index
        uint256 inTokenInstructionIndex = unpackedInstructions.length - 1;
        if (inTokenAddress == address(0)) {
            // transfer native token out from this standard address
            unpackedInstructions[inTokenInstructionIndex] = abi.encode(
                address(this), uint256(0), abi.encodeCall(ITokenRelayer.transferEth, (orderInTokenAmount)));
        } else {
            // transfer ERC20 token from tx.origin (aka relayer) through this standard
            unpackedInstructions[inTokenInstructionIndex] = abi.encode(
                address(this), uint256(0), abi.encodeCall(
                    ITokenRelayer.transferERC20From, (tx.origin, inTokenAddress, orderInTokenAmount)));
        }

        // nested intents
        if (numNestedIntents > 0) {
            uint256 nestedIntentStartIndex = currentIntentLength + 1;
            // max nested intent execution operation index
            uint256 lastNestedIntentInstructionIndex = inTokenInstructionIndex - 1;
            // start index of nested intent execution operation
            uint256 nestedIntentInstructionIndex = 2;
            // index of nested intent starts from 2 because 0 is markAmount, 1 is out token instruction
            while (nestedIntentInstructionIndex <= lastNestedIntentInstructionIndex) {
                require(nestedIntentStartIndex + 46 <= intent.length, "Invalid nested intent");
                uint256 nestedIntentLength = PackedIntent.getIntentLengthFromSection(bytes6(intent[nestedIntentStartIndex + 40 : nestedIntentStartIndex + 46]));
                // nested intent length
                address nestedIntentSender = address(bytes20(intent[nestedIntentStartIndex : nestedIntentStartIndex + 20]));
                unpackedInstructions[nestedIntentInstructionIndex] = abi.encode(
                    nestedIntentSender,
                    uint256(0),
                    abi.encodeCall(IAccount.executeUserIntent, (intent[nestedIntentStartIndex : nestedIntentStartIndex + nestedIntentLength])));
                nestedIntentStartIndex += nestedIntentLength;
                nestedIntentInstructionIndex ++;
            }
        }

        code = ERC7806Constants.VALIDATION_APPROVED;
        return (code, unpackedInstructions);
    }

    /// @notice The function to validate the signatures of this standard
    /// @dev The function is used to validate the signatures of this standard
    /// @param sender The sender of the intent
    /// @param solver The solver of the intent
    /// @param intent The intent to validate
    /// @param signatureStartIndex The index of the beginning of the first signature
    /// @return numUsedSig the number of valid signatures
    /// @return intentHash the hash of the intent
    function _validateSignatures(
        address sender, address solver, bytes calldata intent, uint256 signatureStartIndex
    ) internal view returns (uint8, uint256) {
        bytes32 intentHash = keccak256(
            abi.encode(
                SIGNED_DATA_TYPEHASH,
                bytes1(intent[46 : 47]) == bytes1(0x01), // isFullOrder
                uint24(bytes3(intent[47 : 50])), // salt
                uint64(bytes8(intent[50 : 58])), // expiration
                solver,
                address(bytes20(intent[78 : 98])), // outToken
                uint128(bytes16(intent[98 : 114])), // outAmount
                address(bytes20(intent[114 : 134])), // inToken
                uint128(bytes16(intent[134 : 150]))  // inAmount
            )
        );
        bytes32 messageHash = MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, intentHash);
        uint256 firstSignatureEndIndex = signatureStartIndex + 65;
        // first signature ends
        require(sender == messageHash.recover(intent[signatureStartIndex : firstSignatureEndIndex]), "Invalid sender signature");

        // solver is not determined, no need to check solver signature
        if (solver == address(0)) {
            return (0, uint256(intentHash));
        }

        // only 1 signature is needed if
        // 1. self-solved
        // 2. solver-relayed
        if (solver == sender || solver == tx.origin) {
            return (1, uint256(intentHash));
        }

        // solver signs with assigned relayer
        uint256 secondSignatureEndIndex = signatureStartIndex + 130;
        // second signature ends
        require(intent.length >= secondSignatureEndIndex, "At least 2 signatures are needed to assign relayer");
        bytes32 solverHash = keccak256(abi.encode(intentHash, tx.origin));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        if (solver == messageHash.recover(intent[firstSignatureEndIndex : secondSignatureEndIndex])) {
            return (2, uint256(intentHash));
        }

        // otherwise, solver signs with relayer == address(0) and everyone can relay this intent
        solverHash = keccak256(abi.encode(intentHash, address(0)));
        messageHash = MessageHashUtils.toEthSignedMessageHash(solverHash);
        require(solver == messageHash.recover(intent[firstSignatureEndIndex : secondSignatureEndIndex]), "Invalid solver signature");

        return (2, uint256(intentHash));
    }

    /// @notice The function to execute the user intent
    /// @dev The function is used to execute the user intent
    /// @param intent The intent to execute
    /// @return result the result of the execution
    function executeUserIntent(bytes calldata intent) external returns (bytes memory) {
        (address sender,) = PackedIntent.getSenderAndStandard(intent);
        bytes memory executeCallData = abi.encodeCall(IAccount.executeUserIntent, (intent));

        (, bytes memory result) = sender.call{value : 0, gas : gasleft()}(executeCallData);
        return result;
    }
}
