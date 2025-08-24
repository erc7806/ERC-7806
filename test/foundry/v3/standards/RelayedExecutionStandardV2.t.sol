// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {TestERC20} from "../../../../contracts/test/TestERC20.sol";
import {HashGatedStandard} from "../../../../contracts/v3/standards/HashGatedStandard.sol";
import {RelayedExecutionStandard} from "../../../../contracts/v3/standards/RelayedExecutionStandardV2.sol";
import {ERC7806Constants} from "../../../../contracts/v3/libraries/ERC7806Constants.sol";
import {PackedIntent} from "../../../../contracts/v3/libraries/PackedIntent.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "openzeppelin/utils/cryptography/MessageHashUtils.sol";

contract RelayedExecutionStandardV2Test is Test {
    using ECDSA for bytes32;

    RelayedExecutionStandard standard;
    TestERC20 paymentToken;
    
    address sender;
    address relayer;
    address attacker;
    uint256 senderPrivateKey;
    uint256 relayerPrivateKey;
    
    uint64 expiration;
    uint128 paymentAmount;
    bytes[] instructions;

    function setUp() public {
        // Generate deterministic addresses and private keys
        (sender, senderPrivateKey) = makeAddrAndKey("sender");
        (relayer, relayerPrivateKey) = makeAddrAndKey("relayer");
        attacker = makeAddr("attacker");
        
        // Deploy contracts
        standard = new RelayedExecutionStandard();
        paymentToken = new TestERC20();
        
        // Setup expiration (1 hour from now)
        expiration = uint64(block.timestamp + 3600);
        paymentAmount = 1000;
        
        // Mint tokens to sender
        paymentToken.mint(sender, 10000);
        
        // Give ETH to sender
        vm.deal(sender, 10 ether);
        
        // Setup basic instructions
        instructions = new bytes[](1);
        instructions[0] = abi.encode(address(0x1234), uint256(100), "");
    }

    // Helper function to create a valid intent
    function createValidIntent(
        address _sender,
        address _relayer,
        address _paymentToken,
        uint128 _paymentAmount,
        uint64 _expiration,
        bytes[] memory _instructions,
        uint256 _privateKey
    ) internal view returns (bytes memory) {
        // Pack the intent structure
        bytes memory header = abi.encodePacked(
            _expiration,      // 8 bytes
            _relayer,         // 20 bytes
            _paymentToken,    // 20 bytes
            _paymentAmount    // 16 bytes
        );
        
        // Pack instructions
        bytes memory packedInstructions = abi.encodePacked(uint8(_instructions.length));
        for (uint256 i = 0; i < _instructions.length; i++) {
            packedInstructions = abi.encodePacked(
                packedInstructions,
                uint16(_instructions[i].length),
                _instructions[i]
            );
        }
        
        // Create the data to sign - note: the contract uses _hashBytesArray for instructions
        bytes32[] memory instructionHashes = new bytes32[](_instructions.length);
        for (uint256 i = 0; i < _instructions.length; i++) {
            instructionHashes[i] = keccak256(_instructions[i]);
        }
        bytes32 instructionsHash = keccak256(abi.encodePacked(instructionHashes));
        
        bytes32 intentHash = keccak256(
            abi.encode(
                standard.SIGNED_DATA_TYPEHASH(),
                _expiration,
                _relayer,
                _paymentToken,
                _paymentAmount,
                instructionsHash
            )
        );
        
        bytes32 messageHash = MessageHashUtils.toTypedDataHash(standard.DOMAIN_SEPARATOR(), intentHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Pack the complete intent
        return abi.encodePacked(
            _sender,                                    // 20 bytes
            address(standard),                          // 20 bytes
            uint16(64),                                 // header length (2 bytes)
            uint16(packedInstructions.length),          // instructions length (2 bytes)
            uint16(65),                                 // signature length (2 bytes)
            header,                                     // 64 bytes
            packedInstructions,                         // variable length
            signature                                   // 65 bytes
        );
    }

    // Test basic setup and constants
    function testConstants() public {
        assertEq(standard.ICS_NUMBER(), "ICS1");
        assertEq(standard.DESCRIPTION(), "Timed Hashed Relayed Execution Standard");
        assertEq(standard.VERSION(), "0.1.0");
        assertEq(standard.AUTHOR(), "hellohanchen");
        assertTrue(standard.DOMAIN_SEPARATOR() != bytes32(0));
        assertTrue(standard.SIGNED_DATA_TYPEHASH() != bytes32(0));
    }

    // Test valid intent validation with ETH payment
    function testValidateUserIntent_ValidWithETH() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(0), // ETH payment
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        bytes4 result = standard.validateUserIntent(intent);
        assertEq(result, ERC7806Constants.VALIDATION_APPROVED);
    }

    // Test valid intent validation with ERC20 payment
    function testValidateUserIntent_ValidWithERC20() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        bytes4 result = standard.validateUserIntent(intent);
        assertEq(result, ERC7806Constants.VALIDATION_APPROVED);
    }

    // Test intent validation with any relayer (address(0))
    function testValidateUserIntent_AnyRelayer() public {
        bytes memory intent = createValidIntent(
            sender,
            address(0), // Any relayer
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        bytes4 result = standard.validateUserIntent(intent);
        assertEq(result, ERC7806Constants.VALIDATION_APPROVED);
    }

    // Test expired intent rejection
    function testValidateUserIntent_ExpiredIntent() public {
        // Use a timestamp that won't cause overflow
        uint64 pastExpiration = uint64(block.timestamp - 1);
        
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            pastExpiration,
            instructions,
            senderPrivateKey
        );
        
        vm.expectRevert("Intent expired");
        standard.validateUserIntent(intent);
    }

    // Test insufficient ETH balance
    function testValidateUserIntent_InsufficientETHBalance() public {
        uint128 largeAmount = 100 ether;
        
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(0), // ETH payment
            largeAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        vm.expectRevert("Insufficient eth balance");
        standard.validateUserIntent(intent);
    }

    // Test insufficient ERC20 balance
    function testValidateUserIntent_InsufficientERC20Balance() public {
        uint128 largeAmount = 20000; // More than sender has
        
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            largeAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        vm.expectRevert("Insufficient token balance");
        standard.validateUserIntent(intent);
    }

    // Test invalid signature
    function testValidateUserIntent_InvalidSignature() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            relayerPrivateKey // Wrong private key
        );
        
        vm.expectRevert("Invalid sender signature");
        standard.validateUserIntent(intent);
    }

    // Test wrong standard address
    function testValidateUserIntent_WrongStandard() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        // Modify the standard address in the intent
        bytes memory modifiedIntent = new bytes(intent.length);
        for (uint256 i = 0; i < intent.length; i++) {
            modifiedIntent[i] = intent[i];
        }
        // Replace standard address with attacker address
        for (uint256 i = 20; i < 40; i++) {
            modifiedIntent[i] = bytes1(uint8(uint160(attacker) >> (8 * (39 - i))));
        }
        
        vm.expectRevert("Not this standard");
        standard.validateUserIntent(modifiedIntent);
    }

    // Test invalid header length
    function testValidateUserIntent_InvalidHeaderLength() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        // Modify header length to be wrong
        bytes memory modifiedIntent = new bytes(intent.length);
        for (uint256 i = 0; i < intent.length; i++) {
            modifiedIntent[i] = intent[i];
        }
        // Set header length to 32 instead of 64
        modifiedIntent[40] = 0x00;
        modifiedIntent[41] = 0x20;
        
        vm.expectRevert("Invalid header length");
        standard.validateUserIntent(modifiedIntent);
    }

    // Test invalid signature length
    function testValidateUserIntent_InvalidSignatureLength() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        // Modify signature length to be wrong
        bytes memory modifiedIntent = new bytes(intent.length);
        for (uint256 i = 0; i < intent.length; i++) {
            modifiedIntent[i] = intent[i];
        }
        // Set signature length to 64 instead of 65
        modifiedIntent[44] = 0x00;
        modifiedIntent[45] = 0x40;
        
        vm.expectRevert("Invalid signature length");
        standard.validateUserIntent(modifiedIntent);
    }

    // Test unpack operations with ETH payment
    function testUnpackOperations_WithETH() public {
        bytes memory intent = createValidIntent(
            sender,
            address(0),
            address(0), // ETH payment
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        vm.prank(relayer);
        vm.txGasPrice(1);
        (bytes4 code, bytes[] memory operations) = standard.unpackOperations(intent);
        
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
        assertEq(operations.length, 3); // markHash + payment + execution
        
        // Check markHash operation
        (address target, uint256 value, bytes memory data) = abi.decode(operations[0], (address, uint256, bytes));
        assertEq(target, address(standard));
        assertEq(value, 0);
        
        // Check payment operation (ETH transfer to relayer)
        (target, value, data) = abi.decode(operations[1], (address, uint256, bytes));
        assertEq(target, tx.origin);
        assertEq(value, paymentAmount);
        assertEq(data.length, 0);
        
        // Check execution operation
        (target, value, data) = abi.decode(operations[2], (address, uint256, bytes));
        assertEq(target, address(0x1234));
        assertEq(value, 100);
    }

    // Test unpack operations with ERC20 payment
    function testUnpackOperations_WithERC20() public {
        bytes memory intent = createValidIntent(
            sender,
            address(0),
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        vm.prank(relayer);
        vm.txGasPrice(1);
        (bytes4 code, bytes[] memory operations) = standard.unpackOperations(intent);
        
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
        assertEq(operations.length, 3); // markHash + payment + execution
        
        // Check markHash operation
        (address target, uint256 value, bytes memory data) = abi.decode(operations[0], (address, uint256, bytes));
        assertEq(target, address(standard));
        assertEq(value, 0);
        
        // Check payment operation (ERC20 transfer to relayer)
        (target, value, data) = abi.decode(operations[1], (address, uint256, bytes));
        assertEq(target, address(paymentToken));
        assertEq(value, 0);
        // Verify it's a transfer call to relayer
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        assertEq(selector, IERC20.transfer.selector);
        
        // Check execution operation
        (target, value, data) = abi.decode(operations[2], (address, uint256, bytes));
        assertEq(target, address(0x1234));
        assertEq(value, 100);
    }

    // Test unpack operations with multiple instructions
    function testUnpackOperations_MultipleInstructions() public {
        bytes[] memory multiInstructions = new bytes[](2);
        multiInstructions[0] = abi.encode(address(0x1234), uint256(100), "");
        multiInstructions[1] = abi.encode(address(0x5678), uint256(200), "");
        
        bytes memory intent = createValidIntent(
            sender,
            address(0),
            address(paymentToken),
            paymentAmount,
            expiration,
            multiInstructions,
            senderPrivateKey
        );
        
        vm.prank(relayer);
        vm.txGasPrice(1);
        (bytes4 code, bytes[] memory operations) = standard.unpackOperations(intent);
        
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
        assertEq(operations.length, 4); // markHash + payment + 2 executions
        
        // Check execution operations
        (address target, uint256 value, bytes memory data) = abi.decode(operations[2], (address, uint256, bytes));
        assertEq(target, address(0x1234));
        assertEq(value, 100);
        
        (target, value, data) = abi.decode(operations[3], (address, uint256, bytes));
        assertEq(target, address(0x5678));
        assertEq(value, 200);
    }

    // Test unpack operations with wrong relayer
    function testUnpackOperations_WrongRelayer() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        vm.prank(attacker); // Wrong relayer
        vm.expectRevert("Invalid relayer");
        standard.unpackOperations(intent);
    }

    // Test unpack operations with any relayer
    function testUnpackOperations_AnyRelayer() public {
        bytes memory intent = createValidIntent(
            sender,
            address(0), // Any relayer
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        vm.prank(attacker); // Should work with any relayer
        vm.txGasPrice(1);
        (bytes4 code, bytes[] memory operations) = standard.unpackOperations(intent);
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
    }

    // Test hash marking functionality
    function testHashMarking() public {
        bytes memory intent = createValidIntent(
            sender,
            address(0), // Use address(0) to bypass tx.origin checks
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        // Get the intent hash by calling unpackOperations to see what hash it generates
        vm.prank(relayer);
        vm.txGasPrice(1);
        (bytes4 code, bytes[] memory operations) = standard.unpackOperations(intent);
        assertEq(code, ERC7806Constants.VALIDATION_APPROVED);
        
        // Extract the hash from the markHash operation
        (address target, uint256 value, bytes memory data) = abi.decode(operations[0], (address, uint256, bytes));
        assertEq(target, address(standard));
        assertEq(value, 0);
        
        // The data should be the markHash selector + the hash
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        assertEq(selector, standard.markHash.selector);
        
        // Extract the hash from the data
        uint256 intentHash;
        assembly {
            intentHash := mload(add(data, 36)) // Skip 4 bytes (selector) + 32 bytes offset
        }
        
        // Initially hash should not be marked
        assertFalse(standard.checkHash(sender, intentHash));
        
        // Mark the hash
        vm.prank(sender);
        vm.expectEmit(true, true, false, true);
        emit HashGatedStandard.HashUsed(sender, intentHash);
        standard.markHash(intentHash);
        
        // Hash should now be marked
        assertTrue(standard.checkHash(sender, intentHash));
    }

    // Test intent with empty instructions
    function testValidateUserIntent_EmptyInstructions() public view {
        // Create an intent with 0 instructions in the packed data
        bytes memory header = abi.encodePacked(
            expiration,      // 8 bytes
            relayer,         // 20 bytes
            address(paymentToken),    // 20 bytes
            paymentAmount    // 16 bytes
        );
        
        // Pack instructions with 0 count
        bytes memory packedInstructions = abi.encodePacked(uint8(0));
        
        // Create signature for empty instructions
        bytes32[] memory instructionHashes = new bytes32[](0);
        bytes32 instructionsHash = keccak256(abi.encodePacked(instructionHashes));
        
        bytes32 intentHash = keccak256(
            abi.encode(
                standard.SIGNED_DATA_TYPEHASH(),
                expiration,
                relayer,
                address(paymentToken),
                paymentAmount,
                instructionsHash
            )
        );
        
        bytes32 messageHash = MessageHashUtils.toTypedDataHash(standard.DOMAIN_SEPARATOR(), intentHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Pack the complete intent
        bytes memory intent = abi.encodePacked(
            sender,                                    // 20 bytes
            address(standard),                          // 20 bytes
            uint16(64),                                 // header length (2 bytes)
            uint16(packedInstructions.length),          // instructions length (2 bytes)
            uint16(65),                                 // signature length (2 bytes)
            header,                                     // 64 bytes
            packedInstructions,                         // variable length
            signature                                   // 65 bytes
        );

        bytes4 result = standard.validateUserIntent(intent);
        assertEq(result, ERC7806Constants.VALIDATION_APPROVED);
    }

    // Test intent with malformed instruction length
    function testValidateUserIntent_MalformedInstructionLength() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        // Modify the instruction length to be too short
        bytes memory modifiedIntent = new bytes(intent.length);
        for (uint256 i = 0; i < intent.length; i++) {
            modifiedIntent[i] = intent[i];
        }
        // Set instruction length to 0
        modifiedIntent[42] = 0x00;
        modifiedIntent[43] = 0x00;
        
        vm.expectRevert("Instructions too short");
        standard.validateUserIntent(modifiedIntent);
    }

    // Test intent with invalid instruction length in packed data
    function testValidateUserIntent_InvalidPackedInstructionLength() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        // Modify the packed instruction length to be too long
        bytes memory modifiedIntent = new bytes(intent.length);
        for (uint256 i = 0; i < intent.length; i++) {
            modifiedIntent[i] = intent[i];
        }
        // Set the instruction length in the packed data to be too long
        modifiedIntent[111] = 0xFF; // Set length to 255
        
        vm.expectRevert("Intent too short: single instruction");
        standard.validateUserIntent(modifiedIntent);
    }

    // Test non-ERC20 token address
    function testValidateUserIntent_NonERC20Token() public {
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(0x1234), // Non-ERC20 address
            paymentAmount,
            expiration,
            instructions,
            senderPrivateKey
        );
        
        vm.expectRevert("Not ERC20 token");
        standard.validateUserIntent(intent);
    }

    // Test domain separator calculation
    function testDomainSeparator() public {
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("RelayedExecutionStandard")),
                keccak256(bytes("0.1.0")),
                block.chainid,
                address(standard)
            )
        );
        
        assertEq(standard.DOMAIN_SEPARATOR(), expectedDomainSeparator);
    }

    // Test signed data type hash
    function testSignedDataTypeHash() public {
        bytes32 expectedTypeHash = keccak256(
            "Intent(uint64 expiration,address relayer,address paymentToken,uint128 paymentAmount,bytes[] instructions)"
        );
        
        assertEq(standard.SIGNED_DATA_TYPEHASH(), expectedTypeHash);
    }

    // Test _hashBytesArray helper function
    function testHashBytesArray() public {
        bytes[] memory testArray = new bytes[](3);
        testArray[0] = "test1";
        testArray[1] = "test2";
        testArray[2] = "test3";
        
        // This would require making the function public or testing through a public interface
        // For now, we test it indirectly through the validation process
        bytes memory intent = createValidIntent(
            sender,
            relayer,
            address(paymentToken),
            paymentAmount,
            expiration,
            testArray,
            senderPrivateKey
        );
        
        bytes4 result = standard.validateUserIntent(intent);
        assertEq(result, ERC7806Constants.VALIDATION_APPROVED);
    }
}
