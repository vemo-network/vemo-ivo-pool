// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../src/IVoucher.sol";

contract TestVoucher is IVoucher {
    constructor() {}

    /**
     * @return NFT address, created tokenId, erc6551 account address
     */
    function create(
        address tokenAddress, IVoucher.Vesting memory vesting
    ) external returns (uint256) {
        return 1;
    }
}
