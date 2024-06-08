// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../src/interfaces/IVoucherFactory.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC721} from "@openzeppelin-contracts/token/ERC721/ERC721.sol";

contract TestVoucher is IVoucherFactory, ERC721 {
    using SafeERC20 for IERC20;
    uint8 private lock = 0;
    modifier noReentrance() {
        require(lock == 0, "Contract is locking");
        lock = 1;
        _;
        lock = 0;
    }

    uint256 private _fee;
    mapping(uint256 => IVoucherFactory.VestingFee) private _feeByTokenId;
    mapping(uint256 => IVoucherFactory.VestingSchedule[]) private _vestingScheduleByTokenId;

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    /**
     * @return _fee amount when created
     */
    function getFee(uint256 tokenId) public view returns (IVoucherFactory.VestingFee memory) {
        return _feeByTokenId[tokenId];
    }

    /**
     * @return _vestingSchedules amount when created
     */
    function getVestingSchedules(uint256 tokenId, uint8 index) public view returns (IVoucherFactory.VestingSchedule memory) {
        return _vestingScheduleByTokenId[tokenId][index];
    }

    /**
     * @return NFT address, created tokenId, erc6551 account address
     */
    function createBatchFor(
        address tokenAddress,
        BatchVesting memory batch,
        uint96 royaltyRate,
        address receiver
    ) public noReentrance returns (address, uint256, uint256) {
        _safeMint(receiver, 1);

        IERC20(tokenAddress).safeTransferFrom(
            msg.sender, address(this), batch.vesting.balance
        );

        uint256 startId = 1;
        for (uint256 i = startId; i < startId + batch.quantity; i++) {
            _feeByTokenId[i] = batch.vesting.fee;
            for (uint8 j = 0; j < batch.vesting.schedules.length; j++)
                _vestingScheduleByTokenId[i].push(batch.vesting.schedules[j]);
        }

        return (address(this), startId, startId + batch.quantity - 1);
    }

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
            for (uint8 j = 0; j < batch.vesting.schedules.length; j++)
                _vestingScheduleByTokenId[i].push(batch.vesting.schedules[j]);
        }

        return (address(this), startId, startId + batch.quantity - 1);
    }

    function createFor(
        address tokenAddress,
        Vesting memory vesting,
        address receiver
    ) external returns (address, uint256) {
         _safeMint(msg.sender, 1);

        IERC20(tokenAddress).safeTransferFrom(
            msg.sender, address(this), vesting.balance
        );

        uint256 startId = 1;
        _feeByTokenId[0] = vesting.fee;
        for (uint8 j = 0; j < vesting.schedules.length; j++)
            _vestingScheduleByTokenId[0].push(vesting.schedules[j]);

        return (address(this), startId);
    }
}
