// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/interfaces/VestingPool.sol";
import "../src/pools/VemoFixedStakingPool.sol";
import "../src/VemoPoolFactory.sol";
import "./TestSetup.t.sol";

contract VemoFixedStakingPoolTest is TestSetup {
    VemoPoolFactory private factory;
    TestToken principalToken;
    TestToken rewardToken;

    uint256 MONTH = 30 days;
    uint256[]  stakingPeriods = [MONTH* 3, MONTH * 6, MONTH * 9];
    uint256[]  rewardRates = [5e16, 10e16, 15e16];
    uint256[]  rewardAmounts = [10e18, 100e18, 1000e18];
    uint256[]  maxAllocations = [10e18, 100e18, 1000e18];
    uint256[]  maxAllocationPerWallets = [100e18, 1000e18, 1000e18];
    uint256  totalReward = 0;
    string baseURI = "https://vemo.fixed.staking.pool.com";
    uint256 duration = 60;

    function setUp() public override {
        super.setUp();
        principalToken = new TestToken("test", "tst");
        rewardToken = new TestToken("test1", "TEST1");

        vm.startPrank(deployerAddress);
        factory = new VemoPoolFactory();
        factory.initialize(deployerAddress, "VemoPoolFactory", "0.1");
        factory.setVoucherAddress(address(voucher));

        principalToken.approve(address(factory), UINT256_MAX);
        vm.stopPrank();

        for (uint i = 0; i < stakingPeriods.length; i++) {
            require(stakingPeriods[i] > 0);
            require(maxAllocationPerWallets[i] > 0);
            require(maxAllocations[i] > 0);
            require(rewardRates[i] > 0);
            totalReward += (maxAllocations[i] * rewardRates[i]) * rewardToken.decimals() / 1e18 / principalToken.decimals();
        }
    }

    function generateParams() private view returns (FixedStakingPool memory params) {
        params = FixedStakingPool(
            1,
            address(principalToken),
            address(rewardToken),
            maxAllocations,
            maxAllocationPerWallets,
            stakingPeriods,
            rewardRates,
            baseURI,
            block.timestamp + duration,
            block.timestamp + duration*2
        );
        return params;
    }

    function test_createFixedStakingPoolSuccessfully() public {
        FixedStakingPool memory params = generateParams();
        vm.expectRevert();
        address pool = factory.createFixedStakingPool(params);

        vm.startPrank(deployerAddress);
        rewardToken.mint(deployerAddress, totalReward);
        rewardToken.approve(address(factory), totalReward);

        pool = factory.createFixedStakingPool(params);

        console.log("rewardToken.balanceOf(pool) ", rewardToken.balanceOf(pool));
        // assert(rewardToken.balanceOf(pool) == totalReward);
        assert(VemoFixedStakingPool(pool).principalToken() == address(principalToken));
        assert(VemoFixedStakingPool(pool).rewardToken() == address(rewardToken));
        vm.stopPrank();
    }

    function testFuzz_createFixedStakingPoolMalform(
        uint256[] memory _maxAllocations,
        uint256[] memory _maxAllocationPerWallets,
        uint256[] memory _stakingPeriods,
        uint256[] memory _rewardRates
    ) public {
        FixedStakingPool memory params = FixedStakingPool(
            1,
            address(principalToken),
            address(rewardToken),
            _maxAllocations,
            _maxAllocationPerWallets,
            _stakingPeriods,
            _rewardRates,
            baseURI,
            block.timestamp + 60,
            block.timestamp + 120
        );
        vm.startPrank(deployerAddress);
        rewardToken.mint(deployerAddress, totalReward);
        rewardToken.approve(address(factory), totalReward);

        vm.expectRevert("Pool Factory: malform input");
        factory.createFixedStakingPool(params);

        vm.stopPrank();
    }

    function test_StakeSuccessfully() public {
        FixedStakingPool memory params = generateParams();

        vm.startPrank(deployerAddress);
        rewardToken.mint(deployerAddress, totalReward);
        rewardToken.approve(address(factory), totalReward);

        address pool = factory.createFixedStakingPool(params);
        vm.stopPrank();

        skip(duration);

        vm.startPrank(buyerAddress);
        uint256 stakingAmount = 100;
        uint8 stakingPeriodIndex = 0;
        uint256 expectedReward = VemoFixedStakingPool(pool).reward(stakingAmount, stakingPeriodIndex);

        principalToken.mint(buyerAddress, stakingAmount);
        principalToken.approve(pool, stakingAmount);

        VemoFixedStakingPool(pool).stake(stakingAmount, stakingPeriodIndex, baseURI, baseURI);
        
        uint256 pVoucherId = voucher.nftID() - 2;
        uint256 yVoucherId = voucher.nftID() - 1;

        assert(voucher.ownerOf(pVoucherId) == buyerAddress);
        assert(principalToken.balanceOf(voucher.getTokenBoundAccount(address(principalToken), pVoucherId) ) == stakingAmount);
        assert(voucher.ownerOf(yVoucherId) == buyerAddress);
        assert(rewardToken.balanceOf(voucher.getTokenBoundAccount(address(rewardToken), yVoucherId) ) == expectedReward);
        vm.stopPrank();
    }

    function test_ChangingAllocation() public {
        FixedStakingPool memory params = generateParams();

        vm.startPrank(deployerAddress);
        rewardToken.mint(deployerAddress, totalReward);
        rewardToken.approve(address(factory), totalReward);

        address pool = factory.createFixedStakingPool(params);
        vm.stopPrank();

        skip(duration);
        console.log("total reward ", rewardToken.balanceOf(pool));

        vm.startPrank(buyerAddress);
        uint256 stakingAmount = 100;
        uint8 stakingPeriodIndex = 0;

        principalToken.mint(buyerAddress, stakingAmount);
        principalToken.approve(pool, stakingAmount);

        VemoFixedStakingPool(pool).stake(stakingAmount, stakingPeriodIndex, baseURI, baseURI);
        vm.stopPrank();

        vm.startPrank(deployerAddress);
        VemoFixedStakingPool(pool).adjustAllocation(0, stakingAmount);
        vm.stopPrank();

        // expect noone can stake into pool 0
        vm.startPrank(buyerAddress);
        stakingAmount = 100;
        stakingPeriodIndex = 0;

        principalToken.mint(buyerAddress, stakingAmount);
        principalToken.approve(pool, stakingAmount);

        vm.expectRevert("FIXED_STAKING_POOL: staked amount exceeds max allocation");
        VemoFixedStakingPool(pool).stake(stakingAmount, stakingPeriodIndex, baseURI, baseURI);
        vm.stopPrank();

        vm.startPrank(deployerAddress);
        rewardToken.approve(pool, rewardToken.balanceOf(deployerAddress));
        VemoFixedStakingPool(pool).adjustAllocation(0, maxAllocations[stakingPeriodIndex] - stakingAmount);
        vm.stopPrank();
    }

    function test_stakeMoreThanAllowance() public {
        FixedStakingPool memory params = generateParams();

        vm.startPrank(deployerAddress);
        rewardToken.mint(deployerAddress, totalReward);
        rewardToken.approve(address(factory), totalReward);

        address pool = factory.createFixedStakingPool(params);
        vm.stopPrank();

        skip(duration);

        vm.startPrank(buyerAddress);
        uint8 stakingPeriodIndex = 0;
        uint256 stakingAmount = maxAllocationPerWallets[stakingPeriodIndex] + 1;

        principalToken.mint(buyerAddress, stakingAmount);
        principalToken.approve(pool, stakingAmount);

        vm.expectRevert("FIXED_STAKING_POOL: staked amount exceeds max allocation");
        VemoFixedStakingPool(pool).stake(stakingAmount, stakingPeriodIndex, baseURI, baseURI);
        vm.stopPrank();
    }

    function test_poolTiming() public {
        FixedStakingPool memory params = generateParams();

        vm.startPrank(deployerAddress);
        rewardToken.mint(deployerAddress, totalReward);
        rewardToken.approve(address(factory), totalReward);

        address pool = factory.createFixedStakingPool(params);

        vm.expectRevert("FIXED_STAKING_POOL: the staking pool has not started yet");
        VemoFixedStakingPool(pool).stake(100, 1, baseURI, baseURI);
        skip(duration*2 + 1);
        vm.expectRevert("FIXED_STAKING_POOL: the staking pool has ended");
        VemoFixedStakingPool(pool).stake(100, 1, baseURI, baseURI);
        vm.stopPrank();
    }

}
