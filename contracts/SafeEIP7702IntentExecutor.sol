// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount} from "./v3/interfaces/IAccount.sol";

contract SafeEIP7702IntentExecutor {
    error InvalidCodeHash();

    function getCodeHash(address addr) public view returns (bytes32) {
        return addr.codehash;
    }

    function hasCodeHash(address addr, bytes32 codeHash) public view returns (bool) {
        return addr.codehash == codeHash;
    }

    function isSameCode(address addr1, address addr2) public view returns (bool) {
        return addr1.codehash == addr2.codehash;
    }

    function safeExecuteUserIntent(address user, bytes32 requiredCodehash, bytes calldata intent) public {
        if (user.codehash != requiredCodehash) {
            revert InvalidCodeHash();
        }
        IAccount(user).executeUserIntent(intent);
    }

    function safeExecuteUserIntent(address[] calldata users, bytes32 requiredCodehash, bytes calldata intent) public {
        require(users.length > 0, "No users");
        
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i].codehash != requiredCodehash) {
                revert InvalidCodeHash();
            }
        }
        
        IAccount(users[0]).executeUserIntent(intent);
    }

    function safeExecuteUserIntent(address[] calldata users, bytes32[] calldata requiredCodehashes, bytes calldata intent) public {
        require(users.length > 0, "No users");
        require(users.length == requiredCodehashes.length, "Length mismatch");

        for (uint256 i = 0; i < users.length; i++) {
            if (users[i].codehash != requiredCodehashes[i]) {
                revert InvalidCodeHash();
            }
        }
        
        IAccount(users[0]).executeUserIntent(intent);
    }
}
