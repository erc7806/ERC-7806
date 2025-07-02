/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {StandardRegistryV2} from "./../../contracts/StandardRegistryV2.sol";

contract StandardRegistryV2Test is Test {
    using ECDSA for bytes32;

    StandardRegistryV2 registry;

    address public account;
    uint256 public accountKey;

    function setUp() public {
        (account, accountKey) = makeAddrAndKey("account");
        registry = new StandardRegistryV2();
    }

    function test_permit() public {
        bool registering = true;
        address standard = address(0);
        uint256 nonce = 123;

        // Hash the structured message
        bytes32 structHash = keccak256(
            abi.encode(
                registry.SIGNED_DATA_TYPEHASH(),
                registering,
                standard,
                nonce
            )
        );

        // Create final EIP-712 digest
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), structHash));

        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(address(account));

        // wrong signature
        vm.expectRevert();
        registry.permit(registering, address(account), standard, nonce, abi.encodePacked(v, s, r));
        vm.expectRevert("Invalid signature");
        registry.permit(registering, address(0), standard, nonce, signature);

        // register new standard
        vm.expectEmit(true, false, false, true);
        emit StandardRegistryV2.StandardRegistered(address(account), standard);
        registry.permit(registering, address(account), standard, nonce, signature);

        (bool nonceUsed) = registry.isNonceUsed(address(account), nonce);
        assertEq(nonceUsed, true);

        (bool registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, true);

        vm.expectRevert("Invalid nonce");
        registry.permit(registering, address(account), standard, nonce, signature);

        registering = false;
        nonce = 124;

        // unregister standard
        structHash = keccak256(
            abi.encode(
                registry.SIGNED_DATA_TYPEHASH(),
                registering,
                standard,
                nonce
            )
        );

        // Create final EIP-712 digest
        digest = keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), structHash));

        // Sign the digest
        (v, r, s) = vm.sign(accountKey, digest);
        signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, false, false, true);
        emit StandardRegistryV2.StandardUnregistered(address(account), standard);
        registry.permit(registering, address(account), standard, nonce, signature);

        (registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, false);

        vm.stopPrank();
    }

    function test_update() public {
        bool registering = true;
        address standard = address(0);
        uint256 nonce = 123;

        vm.startPrank(address(account));

        // register new standard
        vm.expectEmit(true, false, false, true);
        emit StandardRegistryV2.StandardRegistered(address(account), standard);
        registry.update(registering, standard, nonce);

        (bool nonceUsed) = registry.isNonceUsed(address(account), nonce);
        assertEq(nonceUsed, true);

        (bool registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, true);

        vm.expectRevert("Invalid nonce");
        registry.update(registering, standard, nonce);

        registering = false;
        nonce = 124;

        // unregister standard
        vm.expectEmit(true, false, false, true);
        emit StandardRegistryV2.StandardUnregistered(address(account), standard);
        registry.update(registering, standard, nonce);

        (registered) = registry.isRegistered(address(account), standard);
        assertEq(registered, false);

        vm.stopPrank();
    }
}
