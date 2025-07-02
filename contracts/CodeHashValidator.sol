// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract CodeHashValidator {
    function getCodeHash(address addr) public view returns (bytes32) {
        return addr.codehash;
    }

    function hasCodeHash(address addr, bytes32 codeHash) public view returns (bool) {
        return addr.codehash == codeHash;
    }

    function isSameCode(address addr1, address addr2) public view returns (bool) {
        return addr1.codehash == addr2.codehash;
    }
}
