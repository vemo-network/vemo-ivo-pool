// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract TestVoucherImplementation {
    constructor() {}

    function createVoucherImplementation() public view returns (address addr) {
        addr = address(bytes20(keccak256(abi.encode(block.timestamp + 2))));
    }
}
