// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "openzeppelin/token/ERC20/IERC20.sol";
import {IERC20Errors} from "openzeppelin/interfaces/draft-IERC6093.sol";
import {TestERC20} from "./../../../contracts/test/TestERC20.sol";
import {BaseTokenRelayer} from "./../../../contracts/v3/BaseTokenRelayer.sol";

contract BaseTokenRelayerTest is Test {
    BaseTokenRelayer relayer;
    address payable user;
    address payable attacker;
    IERC20 mockToken;

    function setUp() public {
        relayer = new BaseTokenRelayer();
        user = payable(address(0x1234));
        attacker = payable(address(0x5678));
        mockToken = IERC20(address(new TestERC20()));
        TestERC20(address(mockToken)).mint(address(user), 100);
        TestERC20(address(mockToken)).mint(address(relayer), 200);
    }

    function testTransferEth_Success() public {
        vm.deal(address(relayer), 1 ether);
        vm.prank(address(user));
        relayer.transferEth(0.6 ether);
        assertEq(user.balance, 0.6 ether);
    }

    function testTransferEth_Fail_InsufficientBalance() public {
        vm.expectRevert("Insufficient balance");
        relayer.transferEth(1 ether);
    }

    function testTransferERC20_Success() public {
        vm.prank(address(user));
        relayer.transferERC20(address(mockToken), 60);
        assertEq(mockToken.balanceOf(address(user)), 160);
    }

    function testTransferERC20From_Success() public {
        vm.startPrank(address(user));
        relayer.transferERC20From(address(relayer), address(mockToken), 60);
        assertEq(mockToken.balanceOf(address(user)), 160);
    }

    function testTransferERC20From_Success_fromOrigin() public {
        vm.startPrank(tx.origin);
        TestERC20(address(mockToken)).mint(tx.origin, 200);
        mockToken.approve(address(relayer), 100);
        vm.startPrank(address(user));
        relayer.transferERC20From(tx.origin, address(mockToken), 60);
        assertEq(mockToken.balanceOf(address(user)), 160);
    }

    function testTransferERC20From_ExceedLimit() public {
        vm.prank(address(user));
        vm.expectRevert();
        relayer.transferERC20From(tx.origin, address(mockToken), 60);
    }

    function testTransferERC20From_InsufficientBalance() public {
        vm.expectRevert();
        relayer.transferERC20From(address(relayer), address(mockToken), 260);
    }

    function testTransferERC20From_Fail_NotAuthorized() public {
        vm.expectRevert("Can only transfer from tx.origin or this address");
        relayer.transferERC20From(address(attacker), address(mockToken), 60);
    }
}
