// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title PackedIntent
/// @notice This is a library that packs metadata of intent (sender, standard, lengths) into bytes
/// @dev the packed intent data schema is defined as follows:
/// @dev 1. sender: address, 20-bytes
/// @dev 2. standard: address, 20-bytes
/// @dev 3. headerLength: uint16, 2-bytes
/// @dev 4. instructionLength: uint16, 2-bytes
/// @dev 5. signatureLength: uint16, 2-bytes
library PackedIntent {
    /// @notice getSenderAndStandard is a function that gets the sender and standard from the intent
    /// @param intent The intent to get the sender and standard from
    /// @return sender The sender of the intent
    /// @return standard The standard of the intent
    function getSenderAndStandard(bytes calldata intent) external pure returns (address, address) {
        require(intent.length >= 40, "Intent too short");
        return (address(bytes20(intent[: 20])), address(bytes20(intent[20 : 40])));
    }

    /// @notice getLengths is a function that gets the lengths from the intent
    /// @param intent The intent to get the lengths from
    /// @return headerLength The length of the header
    /// @return instructionLength The length of the instructions
    /// @return signatureLength The length of the signature
    function getLengths(bytes calldata intent) external pure returns (uint256, uint256, uint256) {
        require(intent.length >= 46, "Missing length section");
        return (
            uint256(uint16(bytes2(intent[40 : 42]))),
            uint256(uint16(bytes2(intent[42 : 44]))),
            uint256(uint16(bytes2(intent[44 : 46])))
        );
    }

    /// @notice getSignatureLength is a function that gets the signature length from the intent
    /// @param intent The intent to get the signature length from
    /// @return signatureLength The length of the signature
    function getSignatureLength(bytes calldata intent) external pure returns (uint256) {
        require(intent.length >= 46, "Missing length section");
        return uint256(uint16(bytes2(intent[44 : 46])));
    }

    /// @notice getIntentLength is a function that gets the intent length from the intent
    /// @param intent The intent to get the intent length from
    /// @return result The sum of header, instruction and signature lengths
    function getIntentLength(bytes calldata intent) external pure returns (uint256) {
        require(intent.length >= 46, "Missing length section");
        uint256 headerLength = uint256(uint16(bytes2(intent[40 : 42])));
        uint256 instructionLength = uint256(uint16(bytes2(intent[42 : 44])));
        uint256 signatureLength = uint256(uint16(bytes2(intent[44 : 46])));
        return headerLength + instructionLength + signatureLength + 46;
    }

    /// @notice getIntentLengthFromSection is a function that gets the intent length from the length section
    /// @param lengthSection The length section to get the intent length from
    /// @return result The sum of header, instruction and signature lengths
    function getIntentLengthFromSection(bytes6 lengthSection) external pure returns (uint16 result) {
        assembly {
            let value := lengthSection
            let a := shr(240, value) // Extract first 2 bytes
            let b := and(shr(224, value), 0xFFFF) // Extract next 2 bytes
            let c := and(shr(208, value), 0xFFFF) // Extract last 2 bytes
            result := add(add(add(a, b), c), 46)
        }
    }
}
