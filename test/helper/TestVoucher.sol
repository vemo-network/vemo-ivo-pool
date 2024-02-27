// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../src/IVoucher.sol";
import {ERC721} from "@openzeppelin-contracts/token/ERC721/ERC721.sol";

contract TestVoucher is IVoucher, ERC721 {
    uint8 private lock = 0;
    modifier noReentrance() {
        require(lock == 0, "Contract is locking");
        lock = 1;
        _;
        lock = 0;
    }

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    /**
     * @return NFT address, created tokenId, erc6551 account address
     */
    function create(
        address tokenAddress, IVoucher.Vesting memory vesting
    ) public noReentrance returns (address, uint256) {
        _safeMint(msg.sender, 1);
        return (address(this), 1);
    }
}
