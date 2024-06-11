// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../src/interfaces/IVoucherFactory.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC721} from "@openzeppelin-contracts/token/ERC721/ERC721.sol";
import "forge-std/Test.sol";

contract TestVoucher is IVoucherFactory, ERC721, Test {
    using SafeERC20 for IERC20;
    uint8 private lock = 0;
    uint256 public nftID = 1;
    uint256 tbaIndex = 99999;

    mapping(address => mapping(uint256 => address)) private _tbaNftMap;
    function setTokenBoundAccount(address nftAddress, uint256 tokenId, address tba) external{
        _tbaNftMap[nftAddress][tokenId] = tba;
    }

    function getTokenBoundAccount(address nftAddress, uint256 tokenId) external view returns (address account){
        return _tbaNftMap[nftAddress][tokenId];
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
    ) public returns (address, uint256, uint256) {
        uint256 startId = nftID - 1;
        for (uint256 i = startId; i < startId + batch.quantity; i++) {
            _feeByTokenId[i] = batch.vesting.fee;
            for (uint8 j = 0; j < batch.vesting.schedules.length; j++)
                _vestingScheduleByTokenId[i].push(batch.vesting.schedules[j]);
            
            address tba = vm.addr(tbaIndex++);
            _tbaNftMap[tokenAddress][nftID] = tba;

            _safeMint(receiver, nftID++);
            IERC20(tokenAddress).safeTransferFrom(
                msg.sender, tba, batch.vesting.balance
            );
        }

        return (tokenAddress, startId, startId + batch.quantity - 1);
    }

    function createBatch(
        address tokenAddress,
        BatchVesting memory batch,
        uint96 royaltyRate
    ) public returns (address, uint256, uint256) {
        address tba = vm.addr(tbaIndex++);
        _tbaNftMap[tokenAddress][nftID] = tba;

        _safeMint(msg.sender, nftID++);

        IERC20(tokenAddress).safeTransferFrom(
            msg.sender, address(this), batch.vesting.balance
        );

        uint256 startId = nftID - 1;
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
        address tba = vm.addr(tbaIndex++);
        _tbaNftMap[tokenAddress][nftID] = tba;

        _safeMint(receiver, nftID++);

        IERC20(tokenAddress).safeTransferFrom(
            msg.sender, tba, vesting.balance
        );

        _feeByTokenId[0] = vesting.fee;
        _vestingScheduleByTokenId[0].push(vesting.schedules[0]);

        return (tokenAddress, nftID);
    }
}
