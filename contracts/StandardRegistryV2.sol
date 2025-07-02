// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title StandardRegistryV2
/// @notice This is a registry for standards, determining whether an account accepts a standard
/// @dev EIP-712 is used for signature verification
contract StandardRegistryV2 {
    using ECDSA for bytes32;

    /// @notice The event emitted when a standard is registered
    event StandardRegistered(address indexed signer, address indexed standard);
    /// @notice The event emitted when a standard is unregistered
    event StandardUnregistered(address indexed signer, address indexed standard);

    /// @notice The domain separator of this contract
    bytes32 public immutable DOMAIN_SEPARATOR;
    /// @notice The type hash of the signed data of this contract
    bytes32 public immutable SIGNED_DATA_TYPEHASH;

    /// @notice The mapping of nonces
    mapping(bytes32 nonce => bool used) private _nonces;
    /// @notice The mapping of registrations
    mapping(bytes32 standard => bool registered) private _registrations;

    /// @notice The constructor of this contract
    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("StandardRegistry")), // Contract name
                keccak256(bytes("2")), // Version
                block.chainid, // Chain ID
                address(this) // Contract address
            )
        );

        SIGNED_DATA_TYPEHASH = keccak256(
            "Permission(bool registering,address standard,uint256 nonce)"
        );
    }

    /// @notice The function to permit a standard, allowing a relayer to register or unregister a standard for a user
    /// @param registering Whether registering or unregistering
    /// @param signer The signer of the permission
    /// @param standard The standard to permit
    /// @param nonce The nonce of the permission
    /// @param signature The signature of the permission
    function permit(bool registering, address signer, address standard, uint256 nonce, bytes calldata signature) external {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, nonce));
        require(!_nonces[compositeKey], "Invalid nonce");

        // validate signature
        bytes32 structHash = keccak256(
            abi.encode(SIGNED_DATA_TYPEHASH, registering, standard, nonce)
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, structHash);
        require(signer == digest.recover(signature), "Invalid signature");

        _process(registering, signer, standard, nonce);
    }

    /// @notice The function to update a standard registration directly
    /// @param registering Whether registering or unregistering
    /// @param standard The standard to update
    /// @param nonce The nonce of the update
    function update(bool registering, address standard, uint256 nonce) external {
        address signer = msg.sender;
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, nonce));
        require(!_nonces[compositeKey], "Invalid nonce");

        _process(registering, signer, standard, nonce);
    }

    /// @notice The function to check if a nonce is used
    /// @param signer The signer of the nonce
    /// @param nonce The nonce to check
    /// @return result true if the nonce is used
    function isNonceUsed(address signer, uint256 nonce) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, nonce));
        return _nonces[compositeKey];
    }

    /// @notice The function to check if a standard is registered
    /// @param signer The signer of the standard
    /// @param standard The standard to check
    /// @return result true if the standard is registered
    function isRegistered(address signer, address standard) external view returns (bool) {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, standard));

        return _registrations[compositeKey];
    }

    /// @notice The function to process a standard registration or unregistration
    /// @param registering Whether registering or unregistering
    /// @param signer The signer of the registration
    /// @param standard The standard to process
    /// @param nonce The nonce of the registration
    function _process(bool registering, address signer, address standard, uint256 nonce) internal {
        bytes32 compositeKey = keccak256(abi.encodePacked(signer, standard));

        if (registering) {
            _registrations[compositeKey] = true;
            emit StandardRegistered(signer, standard);
        } else {
            _registrations[compositeKey] = false;
            emit StandardUnregistered(signer, standard);
        }

        compositeKey = keccak256(abi.encodePacked(signer, nonce));
        _nonces[compositeKey] = true;
    }
}
