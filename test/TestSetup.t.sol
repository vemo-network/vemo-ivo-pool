// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {TestVoucher} from "./helper/TestVoucher.sol";
import "./helper/TestToken.sol";
import "./helper/TestVoucherImplementation.sol";

contract TestSetup is Test {
    uint256 public deployerPrivateKey = 0x00000000000000000000000000000000000000000000000000000000002f7c57;
    uint256 public operatorPrivateKey = 0x00000000000000000000000000000000000000000000000000000000002f7c57;
    uint256 public buyerPrivateKey = 0xB232D;
    uint256 public buyer2PrivateKey = 0xA262F;

    address public deployerAddress = vm.addr(deployerPrivateKey);
    address public operatorAddress = vm.addr(operatorPrivateKey);
    address public buyerAddress = vm.addr(buyerPrivateKey);
    address public buyer2Address = vm.addr(buyer2PrivateKey);

    TestVoucher public voucher;
    TestToken public mockToken;
    TestToken public mockToken1;

    bytes32 public root;

    function setUp() public virtual {
        vm.chainId(11155111);

        mockToken = new TestToken("test", "tst");
        mockToken.mint(deployerAddress, 100000000);

        mockToken1 = new TestToken("test1", "TEST1");
        mockToken1.mint(buyerAddress, 1000000);
        mockToken1.mint(buyer2Address, 1000000);

        voucher = new TestVoucher("TestVoucher", "TVC");
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
