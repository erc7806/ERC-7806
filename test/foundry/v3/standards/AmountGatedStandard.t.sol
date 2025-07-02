// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AmountGatedStandard} from "./../../../../contracts/v3/standards/AmountGatedStandard.sol";

contract MockAmountGatedStandard is AmountGatedStandard {
    function validateUserIntent(bytes calldata intent) external pure override returns (bytes4) {
        return 0x00000001;
    }

    function unpackOperations(bytes calldata intent) external pure override returns (bytes4, bytes[] memory) {
        bytes[] memory operations;
        return (0x00000001, operations);
    }
}

contract AmountGatedStandardTest is Test {
    MockAmountGatedStandard gatedStandard;
    address user;
    uint256 testHash = uint256(keccak256("test"));

    function setUp() public {
        gatedStandard = new MockAmountGatedStandard();
        user = address(0x1234);
    }

    function testMarkAmount() public {
        vm.prank(user);
        gatedStandard.markAmount(testHash, 100);
        uint256 recordedAmount = gatedStandard.getAmount(user, testHash);
        assertEq(recordedAmount, 100);
    }

    function testMarkAmount_Increment() public {
        vm.startPrank(user);
        gatedStandard.markAmount(testHash, 50);
        gatedStandard.markAmount(testHash, 30);
        uint256 recordedAmount = gatedStandard.getAmount(user, testHash);
        assertEq(recordedAmount, 80);
    }
}
