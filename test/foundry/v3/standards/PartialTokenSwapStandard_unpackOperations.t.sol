/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {ERC7806Constants} from "./../../../../contracts/v3/libraries/ERC7806Constants.sol";
import {PartialTokenSwapStandard} from "./../../../../contracts/v3/standards/PartialTokenSwapStandard.sol";
import {ITokenRelayer} from "./../../../../contracts/v3/interfaces/ITokenRelayer.sol";
import {IAccount} from "./../../../../contracts/v3/interfaces/IAccount.sol";
import {TestERC20} from "./../../../../contracts/test/TestERC20.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract ICS4Test is Test {
    using ECDSA for bytes32;

    address public account;
    uint256 public accountKey;
    address public solver;
    uint256 public solverKey;
    PartialTokenSwapStandard public standard;
    TestERC20 public erc20;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        (solver, solverKey) = makeAddrAndKey("solver");
        standard = new PartialTokenSwapStandard();
        erc20 = new TestERC20();
    }

    function test_unpackOperations_success() public {
        erc20.mint(account, 1);

        bool isFullOrder = false;
        uint24 salt = 0;
        uint64 expiration = uint64(block.timestamp + 1);
        address solverAddress = address(account);
        address tokenAddress = address(erc20);

        // no nested intent
        bytes memory content = bytes.concat(bytes1(uint8(isFullOrder ? 1 : 0)), bytes3(salt), bytes8(expiration), bytes20(solverAddress), bytes20(tokenAddress), bytes16(uint128(1)), bytes20(tokenAddress), bytes16(uint128(0)));

        bytes32 intentHash = keccak256(
            abi.encode(standard.SIGNED_DATA_TYPEHASH(), isFullOrder, salt, expiration, solverAddress, tokenAddress, uint128(1), tokenAddress, uint128(0))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toTypedDataHash(standard.DOMAIN_SEPARATOR(), intentHash));
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(65)), content, bytes16(uint128(1)), signature);

        (bytes4 code, bytes[] memory operations) = standard.unpackOperations(intent);
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
        assertEq(3, operations.length);

        // mark amount
        (address dest, uint256 value, bytes memory data) = abi.decode(operations[0], (address, uint256, bytes));
        assertEq(address(standard), dest);
        assertEq(0, value);
        assertEq(abi.encodeWithSelector(standard.markAmount.selector, intentHash, uint256(1)), data);

        // send token out
        (dest, value, data) = abi.decode(operations[1], (address, uint256, bytes));
        assertEq(address(erc20), dest);
        assertEq(0, value);
        assertEq(abi.encodeWithSelector(IERC20.transfer.selector, tx.origin, uint256(1)), data);

        // get token in
        (dest, value, data) = abi.decode(operations[2], (address, uint256, bytes));
        assertEq(address(standard), dest);
        assertEq(0, value);
        assertEq(abi.encodeWithSelector(ITokenRelayer.transferERC20From.selector, tx.origin, address(erc20), uint256(1)), data);
    }

    function test_unpackOperations_success_nativeAndNested() public {
        // native tokens with nested intent
        vm.deal(address(account), 1 ether);

        bool isFullOrder = true;
        uint24 salt = 0;
        uint64 expiration = uint64(block.timestamp + 1);
        address solverAddress = address(account);
        address tokenAddress = address(0);

        bytes memory content = bytes.concat(bytes1(uint8(isFullOrder ? 1 : 0)), bytes3(salt), bytes8(expiration), bytes20(solverAddress), bytes20(tokenAddress), bytes16(uint128(1)), bytes20(tokenAddress), bytes16(uint128(1)));

        bytes32 intentHash = keccak256(
            abi.encode(standard.SIGNED_DATA_TYPEHASH(), isFullOrder, salt, expiration, solverAddress, tokenAddress, uint128(1), tokenAddress, uint128(1))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toTypedDataHash(standard.DOMAIN_SEPARATOR(), intentHash));
        bytes memory bytesVar = abi.encodePacked(r, s, v);

        bytes memory intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), content, bytesVar);

        (bytes4 code, bytes[] memory operations) = standard.unpackOperations(bytes.concat(intent, bytes1(uint8(1)), intent));
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
        assertEq(4, operations.length);

        // send token out
        address dest;
        uint256 value;
        (dest, value, bytesVar) = abi.decode(operations[1], (address, uint256, bytes));
        assertEq(address(tx.origin), dest);
        assertEq(1, value);
        assertEq("", bytesVar);

        // get token in
        (dest, value, bytesVar) = abi.decode(operations[3], (address, uint256, bytes));
        assertEq(address(standard), dest);
        assertEq(0, value);
        assertEq(abi.encodeWithSelector(ITokenRelayer.transferEth.selector, uint256(1)), bytesVar);

        // nested intent
        (dest, value, bytesVar) = abi.decode(operations[2], (address, uint256, bytes));
        assertEq(address(account), dest);
        assertEq(0, value);
        assertEq(abi.encodeWithSelector(IAccount.executeUserIntent.selector, intent), bytesVar);
    }

    function test_unpackOperations_failure_validations() public {
        // not this address
        bytes memory intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(0x5678)));
        vm.expectRevert("Not this standard");
        standard.unpackOperations(intent);

        // intent expired
        intent = bytes.concat(bytes20(address(0x1234)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), bytes1(0x01), bytes3(0x000000), bytes8(uint64(block.timestamp - 1)), new bytes(200));
        vm.expectRevert("Intent expired");
        standard.unpackOperations(intent);
    }

    function test_unpackOperations_failure_signatures() public {
        bool isFullOrder = true;
        uint24 salt = 0;
        uint64 expiration = uint64(block.timestamp + 1);
        address solverAddress = address(0);
        address tokenAddress = address(erc20);

        bytes memory content = bytes.concat(bytes1(uint8(isFullOrder ? 1 : 0)), bytes3(salt), bytes8(expiration), bytes20(solverAddress), bytes20(tokenAddress), bytes16(uint128(0)), bytes20(tokenAddress), bytes16(uint128(0)));

        bytes32 intentHash = keccak256(
            abi.encode(standard.SIGNED_DATA_TYPEHASH(), isFullOrder, salt, expiration, solverAddress, tokenAddress, uint128(0), tokenAddress, uint128(0))
        );

        // Solver is not assigned
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toTypedDataHash(standard.DOMAIN_SEPARATOR(), intentHash));
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(72)), bytes2(uint16(65)), content, signature);
        vm.expectRevert("Solver is not assigned");
        standard.unpackOperations(intent);
    }

    function test_unpackOperations_failure_afterSig() public {
        erc20.mint(account, 1);

        bool isFullOrder = false;
        uint24 salt = 0;
        uint64 expiration = uint64(block.timestamp + 1);
        address solverAddress = address(account);
        address tokenAddress = address(erc20);

        bytes memory content = bytes.concat(bytes1(uint8(isFullOrder ? 1 : 0)), bytes3(salt), bytes8(expiration), bytes20(solverAddress), bytes20(tokenAddress), bytes16(uint128(0)), bytes20(tokenAddress), bytes16(uint128(0)));

        bytes32 intentHash = keccak256(
            abi.encode(standard.SIGNED_DATA_TYPEHASH(), isFullOrder, salt, expiration, solverAddress, tokenAddress, uint128(0), tokenAddress, uint128(0))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, MessageHashUtils.toTypedDataHash(standard.DOMAIN_SEPARATOR(), intentHash));
        bytes memory signature = abi.encodePacked(r, s, v);

        // order limit exceed
        bytes memory intent = bytes.concat(bytes20(address(account)), bytes20(address(standard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(65)), content, bytes16(uint128(1)), signature);
        vm.expectRevert("Order limit exceeded");
        standard.unpackOperations(intent);
    }
}
