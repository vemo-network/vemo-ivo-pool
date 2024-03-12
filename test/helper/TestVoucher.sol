// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../src/IVoucher.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC721} from "@openzeppelin-contracts/token/ERC721/ERC721.sol";

contract TestVoucher is IVoucher, ERC721 {
    using SafeERC20 for IERC20;
    uint8 private lock = 0;
    modifier noReentrance() {
        require(lock == 0, "Contract is locking");
        lock = 1;
        _;
        lock = 0;
    }

    uint256 private _fee;
    mapping(uint256 => IVoucher.VestingFee) private _feeByTokenId;

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    /**
     * @return _fee amount when created
     */
    function getFee(uint256 tokenId) public view returns (IVoucher.VestingFee memory) {
        return _feeByTokenId[tokenId];
    }

    /**
     * @return NFT address, created tokenId, erc6551 account address
     */
    function createBatch(
        address tokenAddress,
        BatchVesting memory batch,
        uint96 royaltyRate
    ) public noReentrance returns (address, uint256, uint256) {
        _safeMint(msg.sender, 1);

        IERC20(tokenAddress).safeTransferFrom(
            msg.sender, address(this), batch.vesting.balance
        );

        uint256 startId = 1;
        for (uint256 i = startId; i < startId + batch.quantity; i++) {
            _feeByTokenId[i] = batch.vesting.fee;
        }

        return (address(this), startId, startId + batch.quantity - 1);
    }
}
