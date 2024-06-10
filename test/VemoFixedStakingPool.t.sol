// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/interfaces/VestingPool.sol";
import "../src/pools/VemoFixedStakingPool.sol";
import "../src/VemoPoolFactory.sol";
import "./TestSetup.t.sol";

contract VemoFixedStakingPoolTest is TestSetup {
    VemoPoolFactory private factory;
    TestToken principalToken = mockToken;
    TestToken rewardToken = mockToken1;

    uint256 MONTH = 30 days;
    uint256[]  stakingPeriods = [MONTH* 3, MONTH * 6, MONTH * 9];
    uint256[]  rewardRates = [5e18, 10e18, 15e18];
    uint256[]  rewardAmounts = [10e18, 100e18, 1000e18];
    uint256[]  maxAllocations = [1000e18, 10000e18, 10000e18];
    uint256[]  maxAllocationPerWallets = [100e18, 1000e18, 1000e18];
    uint256  totalReward = 10e18 + 100e18 + 1000e18;
    string baseURI = "https://vemo.fixed.staking.pool.com";
    uint256 duration = 60;
    function setUp() public override {
        super.setUp();
        vm.startPrank(deployerAddress);
        factory = new VemoPoolFactory();
        factory.initialize(deployerAddress, "VemoPoolFactory", "0.1");
        factory.setVoucherAddress(address(voucher));
        mockToken.approve(address(factory), UINT256_MAX);
        vm.stopPrank();
    }

    function generateParams() private view returns (FixedStakingPool memory params) {
        params = FixedStakingPool(
            1,
            address(principalToken),
            address(rewardToken),
            maxAllocations,
            maxAllocationPerWallets,
            rewardAmounts,
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

        assert(rewardToken.balanceOf(pool) == totalReward);
        assert(VemoFixedStakingPool(pool).principalToken() == address(mockToken));
        assert(VemoFixedStakingPool(pool).rewardToken() == address(rewardToken));
        assert(VemoFixedStakingPool(pool).stakingPeriods(0) == stakingPeriods[0]);
        assert(VemoFixedStakingPool(pool).stakingPeriods(1) == stakingPeriods[1]);
        assert(VemoFixedStakingPool(pool).stakingPeriods(2) == stakingPeriods[2]);
        vm.stopPrank();
    }

    function testFuzz_createFixedStakingPoolMalform(
        uint256[] memory _maxAllocations,
        uint256[] memory _maxAllocationPerWallets,
        uint256[] memory _rewardAmounts,
        uint256[] memory _stakingPeriods,
        uint256[] memory _rewardRates
    ) public {
        FixedStakingPool memory params = FixedStakingPool(
            1,
            address(mockToken),
            address(mockToken1),
            _maxAllocations,
            _maxAllocationPerWallets,
            _rewardAmounts,
            _stakingPeriods,
            _rewardRates,
            baseURI,
            block.timestamp + 60,
            block.timestamp + 120
        );
        vm.startPrank(deployerAddress);
        mockToken1.mint(deployerAddress, totalReward);
        mockToken1.approve(address(factory), totalReward);

        vm.expectRevert("Pool Factory: malform input");
        factory.createFixedStakingPool(params);

        vm.stopPrank();
    }

    function test_StakeSuccessfully() public {
        FixedStakingPool memory params = generateParams();

        vm.startPrank(deployerAddress);
        mockToken1.mint(deployerAddress, totalReward);
        address pool = factory.createFixedStakingPool(params);
        vm.stopPrank();

        skip(duration);

        vm.startPrank(buyerAddress);
        uint256 stakingAmount = 100;
        mockToken.mint(buyerAddress, stakingAmount);
        mockToken.approve(pool, stakingAmount);

        console.log("mockToken ", address(mockToken));
        console.log("buyerAddress ", address(buyerAddress));
        VemoFixedStakingPool(pool).stake(stakingAmount, 0, baseURI, baseURI);
        vm.stopPrank();
    }

    function test_ChangingAllocation() public {
        assert(true == false);
    }

    function test_ChangingReward() public {
        assert(true == false);
    }
    
    function test_depositMoreThanAllowance() public {
        assert(true == false);
    }

    function test_depositOverMaxAllocation() public {
        assert(true == false);
    }

    function test_noMaximumPerWallet() public {
        assert(true == false);
    }

    function test_noMaxAllocation() public {
        assert(true == false);
    }

    function test_poolTiming() public {
        FixedStakingPool memory params = generateParams();

        vm.startPrank(deployerAddress);
        mockToken1.mint(deployerAddress, totalReward);
        mockToken1.approve(address(factory), totalReward);

        address pool = factory.createFixedStakingPool(params);

        vm.expectRevert("FIXED_STAKING_POOL: the staking pool has not started yet");
        VemoFixedStakingPool(pool).stake(100, 1, baseURI, baseURI);
        skip(duration*2 + 1);
        vm.expectRevert("FIXED_STAKING_POOL: the staking pool has ended");
        VemoFixedStakingPool(pool).stake(100, 1, baseURI, baseURI);
        vm.stopPrank();
    }

    function test_poolEnded() public {
        assert(true == false);
    }
}
