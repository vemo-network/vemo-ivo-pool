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

    TestVoucherFactory public voucherFactory;
    TestVoucherImplementation public voucherImplementation;
    TestToken public mockToken;
    TestToken public mockToken1;

    function setUp() public virtual {
        vm.chainId(11155111);

        deployerPrivateKey = 0x00000000000000000000000000000000000000000000000000000000002f7c57;
        operatorPrivateKey = 0x00000000000000000000000000000000000000000000000000000000002f7c57;
        buyerPrivateKey = 0xB232D;

        mockToken = new TestToken("test", "tst");
        mockToken.mint(vm.addr(deployerPrivateKey), 100000000);

        mockToken1 = new TestToken("test1", "TEST1");
        mockToken1.mint(vm.addr(buyerPrivateKey), 1000000);

        voucherFactory = new TestVoucherFactory();
        voucherImplementation = new TestVoucherImplementation();

        console.log(vm.addr(deployerPrivateKey));
        console.log(vm.addr(operatorPrivateKey));
        console.log(vm.addr(buyerPrivateKey));
    }
}
