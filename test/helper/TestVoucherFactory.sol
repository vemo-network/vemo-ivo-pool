// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IVemoVoucher} from "vemo-data-registry/interfaces/IVemoVoucher.sol";

contract TestVoucher is IVemoVoucher {
    constructor() {}

    /**
     * @return NFT address, created tokenId, erc6551 account address
     */
    function create(
        CreateVoucherParams calldata params
    ) external returns (address, uint256, address) {
        address addr = address(bytes20(keccak256(abi.encode(block.timestamp + 1))));
        address addr2 = address(bytes20(keccak256(abi.encode(block.timestamp + 2))));

        return (addr, 1, addr2);
    }

    /**
     * @return NFT address, start tokenId, end tokenId, list of erc6551 account addresses
     */
    function createBatch(
        uint8 batchSize,
        CreateVoucherParams calldata params
    ) external returns (address, uint256, uint256, address[] memory) {
        address addr = address(bytes20(keccak256(abi.encode(block.timestamp + 1))));
        address addr2 = address(bytes20(keccak256(abi.encode(block.timestamp + 2))));

        address[] memory ret = new address[](1);
        ret[0] = addr2;

        return (addr, 1, 1, ret);
    }
}

contract TestVoucherFactory {
    constructor() {}

    function createVoucher() public returns (address addr) {
        TestVoucher voucher = new TestVoucher();

        return address(voucher);
    }
}
