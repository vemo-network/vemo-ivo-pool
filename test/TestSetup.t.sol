// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {TestVoucherFactory} from "./helper/TestVoucherFactory.sol";
import "./helper/TestToken.sol";
import "./helper/TestVoucherImplementation.sol";

contract TestSetup is Test {
    uint256 public deployerPrivateKey;
    uint256 public operatorPrivateKey;
    uint256 public buyerPrivateKey;
    uint256 public buyer2PrivateKey;

    TestVoucherFactory public voucherFactory;
    TestVoucherImplementation public voucherImplementation;
    TestToken public mockToken;
    TestToken public mockToken1;

    bytes32 public root;

    function setUp() public virtual {
        vm.chainId(11155111);

        deployerPrivateKey = 0x00000000000000000000000000000000000000000000000000000000002f7c57;
        operatorPrivateKey = 0x00000000000000000000000000000000000000000000000000000000002f7c57;
        buyerPrivateKey = 0xB232D;
        buyer2PrivateKey = 0xA262F;

        mockToken = new TestToken("test", "tst");
        mockToken.mint(vm.addr(deployerPrivateKey), 100000000);

        mockToken1 = new TestToken("test1", "TEST1");
        mockToken1.mint(vm.addr(buyerPrivateKey), 1000000);
        mockToken1.mint(vm.addr(buyer2PrivateKey), 1000000);
        
        voucherFactory = new TestVoucherFactory();
        voucherImplementation = new TestVoucherImplementation();
        generateProof();
    }

    function generateProof() private {
        bytes memory source = hex"463e98ff5309fa96e74ec4d4ae55d0c1c39a955692c2d3352f4cfbf5aa41d634";
        root = stringToBytes32(source);
    }

    function iToHex(bytes32 data) public pure returns (string memory) {
        bytes memory buffer = abi.encodePacked(data);

        // Fixed buffer size for hexadecimal convertion
        bytes memory converted = new bytes(buffer.length * 2);

        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return string(abi.encodePacked("0x", converted));
    }

    function stringToBytes32(bytes memory source) public pure returns (bytes32 result) {
        bytes memory tempEmptyStringTest = bytes(source);
        if (tempEmptyStringTest.length == 0) {
            return 0x0;
        }

        assembly {
            result := mload(add(source, 32))
        }
    }
}
