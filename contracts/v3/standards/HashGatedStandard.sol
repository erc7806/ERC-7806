// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStandard} from "./../interfaces/IStandard.sol";

abstract contract HashGatedStandard is IStandard {
    event HashUsed(address sender, uint256 hash);

    mapping(bytes32 => bool) internal _hashes;

    function checkHash(address sender, uint256 hash) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encode(sender, hash));
        return _hashes[compositeKey];
    }

    function markHash(uint256 hash) external {
        bytes32 compositeKey = keccak256(abi.encode(msg.sender, hash));
        _hashes[compositeKey] = true;

        emit HashUsed(msg.sender, hash);
    }
}
