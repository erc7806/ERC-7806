// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../../../contracts/test/TestERC20.sol";
import "forge-std/Test.sol";
import {AccountImplV0} from "./../../../../contracts/v3/accounts/AccountImplV0.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {IStandard} from "./../../../../contracts/v3/interfaces/IStandard.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ERC7806Constants} from "./../../../../contracts/v3/libraries/ERC7806Constants.sol";
import {PartialTokenSwapStandard} from  "./../../../../contracts/v3/standards/PartialTokenSwapStandard.sol";
import {StandardRegistryV2} from "./../../../../contracts/StandardRegistryV2.sol";
import {TestERC20} from "./../../../../contracts/test/TestERC20.sol";

contract AccountImplV0Test is Test {
    TestERC20 public erc20;
    StandardRegistryV2 public registry;
    PartialTokenSwapStandard public partialTokenSwapStandard;
    bytes4 public constant VALIDATION_APPROVED = 0x00000001;
    bytes4 public constant VALIDATION_DENIED = 0x00000000;
    address public user;
    uint256 public userKey;


    function setUp() public {
        erc20 = new TestERC20();

        // enforce StandardRegistry at 0xa6673924437D5864488CEC4B8fa1654226bb1E8D
        StandardRegistryV2 mockRegistry = new StandardRegistryV2();
        address registryAddress = 0x1EcBE25525F6e6cDe8631e602Df6D55D3967cDF8;
        vm.etch(registryAddress, address(mockRegistry).code);
        registry = StandardRegistryV2(registryAddress);


        // register standard using registry.update
        partialTokenSwapStandard = new PartialTokenSwapStandard();
        (user, userKey) = makeAddrAndKey("account");
        AccountImplV0 mockAccountImplV0 = new AccountImplV0();
        vm.etch(user, address(mockAccountImplV0).code);

        bool registering = true;
        uint256 nonce = 123;
        vm.prank(user);
        registry.update(registering, address(partialTokenSwapStandard), nonce);
        require(registry.isRegistered(user, address(partialTokenSwapStandard)), "not registered");
    }

    function testExecuteOtherIntent() public {
        erc20.mint(user, 1);
        erc20.mint(tx.origin, 1);
        vm.startPrank(tx.origin);
        erc20.approve(address(partialTokenSwapStandard), 1);

        // construct intent to send 1 erc20 from user
        bytes memory content = bytes.concat(bytes1(0x00), bytes3(0x000000), bytes8(uint64(block.timestamp + 1)), bytes20(address(user)), bytes20(address(erc20)), bytes16(uint128(1)), bytes20(address(erc20)), bytes16(uint128(0)));

        bytes32 intentHash = keccak256(
            abi.encode(partialTokenSwapStandard.SIGNED_DATA_TYPEHASH(), false, uint24(0), uint64(block.timestamp + 1), address(user), address(erc20), uint128(1), address(erc20), uint128(0))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, MessageHashUtils.toTypedDataHash(partialTokenSwapStandard.DOMAIN_SEPARATOR(), intentHash));
        bytes memory signature = abi.encodePacked(r, s, v);
//
//        bytes32 intentHash = keccak256(abi.encode(content, address(partialTokenSwapStandard), block.chainid));
//        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, MessageHashUtils.toEthSignedMessageHash(intentHash));
//        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory intent = bytes.concat(bytes20(address(user)), bytes20(address(partialTokenSwapStandard)), bytes2(uint16(32)), bytes2(uint16(88)), bytes2(uint16(65)), content, bytes16(uint128(1)), signature);
        vm.startPrank(user);
        bytes4 code = partialTokenSwapStandard.validateUserIntent(intent);
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);

        bytes[] memory operations;
        (code, operations) = partialTokenSwapStandard.unpackOperations(intent);
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
        assertEq(3, operations.length);

        require(registry.isRegistered(user, address(partialTokenSwapStandard)), "not registered");
        bytes memory result = AccountImplV0(payable(user)).executeUserIntent(intent);
        assertEq(result, new bytes(0));
    }
}
