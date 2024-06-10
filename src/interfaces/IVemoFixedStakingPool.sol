// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./IVoucherFactory.sol";

/**
 * CreateVestingPoolParams struct
 * @param principalToken            - The address of staking token
 * @param rewardToken               - The address of reward token
 * @param maxAllocation             - Maximum amount of staking token
 * @param rewardRates               - The reward rates  = (number of reward tokens without decimals) per 1 staking token - without decimals - decimals 18
 * @param maxAllocation             - Maximum amount of staking tokne
 * @param maxAllocationPerWallet    - max allocation (bought) amount that a wallet can participate in this pool
 * @param royaltyRate               - royalty rate of the vesting voucher
 * @param fee                       - vesting fee
 * @param baseUrl                   - Base Url for Voucher created by this pool
 
*/
struct FixedStakingPool {
    uint256 poolId;
    address principalToken;
    address rewardToken;
    uint256[] maxAllocations;
    uint256[] maxAllocationPerWallets;
    uint256[] rewardAmounts;
    uint256[] stakingPeriods;
    uint256[] rewardRates;  // ie [1e17, 2e18, 5e18, 1e18] ~ 0.1 , 2, 5, 10 per year
    string baseUrl;
    uint256 startAt;
    uint256 endAt;
}

interface IVemoFixedStakingPool {
    event Deposit(
        address indexed _user,
        address indexed _stakingToken,
        uint256 _amount,
        address pVoucher,
        address yVoucher
    );

    event UpdatePoolAllocation(
        address indexed _stakingToken,
        uint256 _newAllocation
    );

    event UpdatePoolRewards(
        address indexed _stakingToken,
        uint256[] _newPeriods,
        uint256[] _newRates
    );

    function stakedAmount(address user) external returns (uint256);

    // function adjustAllocation(uint256 _newAllo) external;

    // function adjustRewards(uint256[] memory _newPeriods, uint256[] memory _newRates) external;
}
