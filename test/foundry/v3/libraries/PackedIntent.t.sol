// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PackedIntent} from "./../../../../contracts/v3/libraries/PackedIntent.sol";

contract PackedIntentTest is Test {
    function testGetSenderAndStandard() pure public {
        bytes memory intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(0x5678)));
        (address sender, address standard) = PackedIntent.getSenderAndStandard(intent);
        assertEq(sender, address(0x1234));
        assertEq(standard, address(0x5678));
    }

    function testGetSenderAndStandard_Fail_ShortIntent() public {
        bytes memory intent = bytes.concat(bytes20(address(0x1234)));
        vm.expectRevert("Intent too short");
        PackedIntent.getSenderAndStandard(intent);
    }

    function testGetLengths() pure public {
        bytes memory intent = bytes.concat(
            bytes20(address(0x1234)),
            bytes20(address(0x5678)),
            bytes2(uint16(10)),
            bytes2(uint16(20)),
            bytes2(uint16(30))
        );
        (uint256 headerLength, uint256 instructionLength, uint256 signatureLength) = PackedIntent.getLengths(intent);
        assertEq(headerLength, 10);
        assertEq(instructionLength, 20);
        assertEq(signatureLength, 30);
    }

    function testGetLengths_Fail_ShortIntent() public {
        bytes memory intent = bytes.concat(
            bytes20(address(0x1234)),
            bytes20(address(0x5678)),
            bytes2(uint16(10))
        );
        vm.expectRevert("Missing length section");
        PackedIntent.getLengths(intent);
    }

    function testGetSignatureLength() pure public {
        bytes memory intent = bytes.concat(
            bytes20(address(0x1234)),
            bytes20(address(0x5678)),
            bytes2(uint16(10)),
            bytes2(uint16(20)),
            bytes2(uint16(40))
        );
        uint256 signatureLength = PackedIntent.getSignatureLength(intent);
        assertEq(signatureLength, 40);
    }

    function testGetIntentLength() pure public {
        bytes memory intent = bytes.concat(
            bytes20(address(0x1234)),
            bytes20(address(0x5678)),
            bytes2(uint16(10)),
            bytes2(uint16(20)),
            bytes2(uint16(30))
        );
        uint256 intentLength = PackedIntent.getIntentLength(intent);
        assertEq(intentLength, 10 + 20 + 30 + 46);
    }

    function testGetIntentLengthFromSection() pure public {
        bytes6 lengthSection = bytes6(bytes.concat(bytes2(uint16(10)), bytes2(uint16(20)), bytes2(uint16(30))));
        uint16 result = PackedIntent.getIntentLengthFromSection(lengthSection);
        assertEq(result, 10 + 20 + 30 + 46);
    }
}
