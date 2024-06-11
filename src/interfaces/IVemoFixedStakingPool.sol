// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./IVoucherFactory.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";

interface IERC20Extented is IERC20 {
    function decimals() external view returns (uint8);
}

/**
 * CreateVestingPoolParams struct
 * @param principalToken            - The address of staking token
 * @param rewardToken               - The address of reward token
 * @param maxAllocations            - Maximum amount of staking tokne
 * @param maxAllocationPerWallets   - max allocation (bought) amount that a wallet can participate in this pool
 * @param rewardSchedule            - struct defines the schedule unlocking reward token
 * @param stakingPeriods            - array defines staking periods options
 * @param rewardRates               - array defines rewardrate with unit is RewardToken(no decimals)/StakingToken(no decimals) -  decimals 18
 * @param baseUrl                   - Base Url for Voucher created by this pool
 
*/
struct FixedStakingPool {
    uint256 poolId;
    address principalToken;
    address rewardToken;
    uint256[] maxAllocations;
    uint256[] maxAllocationPerWallets;
    uint256[] stakingPeriods;
    uint256[] rewardRates;  // ie [1e17, 2e18, 5e18, 1e18] ~ 0.1 , 2, 5, 10 per year
    IVoucherFactory.VestingSchedule rewardSchedule; 
    string baseUrl;
    uint256 startAt;
    uint256 endAt;
}

interface IVemoFixedStakingPool {
    event Deposit(
        address indexed _user,
        address indexed _stakingToken,
        uint256 _amount,
        address pVoucherNFT,
        address yVoucherNFT,
        uint256 pVoucherId,
        uint256 yVoucherId
    );

    event UpdatePoolAllocation(
        uint8 _id,
        uint256 _newAllocation
    );

    function staked(uint8 periodIndex, address staker) external returns (uint256);

    function adjustAllocation(uint8 periodIndex, uint256 newAllo) external;

    function reward(uint256 amount, uint8 periodIndex) external returns (uint256);
}
