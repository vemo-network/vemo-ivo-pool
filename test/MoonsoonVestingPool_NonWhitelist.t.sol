// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/interfaces/VestingPool.sol";
import "../src/MoonsoonVestingPool.sol";
import "../src/MoonsoonVestingPoolFactory.sol";
import "./TestSetup.t.sol";

contract MoonsoonVestingPoolTest_NonWhitelist is TestSetup {
    MoonsoonVestingPoolFactory private factory;

    function setUp() public override {
        super.setUp();

        vm.startPrank(vm.addr(deployerPrivateKey));
        factory = new MoonsoonVestingPoolFactory("MoonsoonVestingPoolFactory", "0.1");
        factory.setOperatorAddress(vm.addr(operatorPrivateKey));
        factory.setVoucherFactoryAddress(address(voucherFactory));
        mockToken.approve(address(factory), UINT256_MAX);
        vm.stopPrank();

        console.log("MoonsoonVestingPoolFactory Address: ", address(factory));
    }

    function generateParams() private view returns (CreateVestingPoolParams memory params) {
        VestingSchedule memory vestingSchedule = VestingSchedule(
            0,
            10000,
            block.timestamp + 600,
            600,
            60
        );

        VestingSchedule[] memory schedules = new VestingSchedule[](1);
        schedules[0] = vestingSchedule;

        VestingMetadata memory vestingMetadata = VestingMetadata(
            address(mockToken),
            10000,
            vm.addr(deployerPrivateKey),
            schedules
        );

        RoyaltyInfo memory royaltyInfo = RoyaltyInfo(
            vm.addr(deployerPrivateKey),
            100
        );

        bytes memory callData = abi.encodeCall(TestVoucherFactory.createVoucher, ());

        params = CreateVestingPoolParams(
            address(mockToken),
            100000000,
            address(mockToken1),
            1,
            1,
            false,
            2000000,
            callData,
            vestingMetadata,
            royaltyInfo,
            address(voucherImplementation),
            keccak256(""),
            block.timestamp + 60,
            bytes("0x")
        );
    }

    function test_BuySuccessfully() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buy(1000000);
        vm.stopPrank();

        assert(MoonsoonVestingPool(pool).token1Amount(1000000) == 1000000);
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 0);
        assert(MoonsoonVestingPool(pool).vestingUnlockTimestamps().length == 0);
        assert(MoonsoonVestingPool(pool).vestingUnlockAmounts().length == 0);
    }

    function test_BuySuccessfullyWith2VestingSchedule() public {
        CreateVestingPoolParams memory params = generateParams();

        VestingSchedule memory vestingSchedule = VestingSchedule(
            0,
            5000,
            block.timestamp + 600,
            600,
            60
        );

        VestingSchedule memory vestingSchedule1 = VestingSchedule(
            1,
            5000,
            block.timestamp + 600,
            600,
            60
        );

        VestingSchedule[] memory schedules = new VestingSchedule[](2);
        schedules[0] = vestingSchedule;
        schedules[1] = vestingSchedule1;

        params.vestingMetadata.vestingSchedule = schedules;

        VestingMetadata memory vestingMetadata = VestingMetadata(
            address(mockToken),
            10000,
            vm.addr(deployerPrivateKey),
            schedules
        );

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buy(1000000);
        vm.stopPrank();

        assert(MoonsoonVestingPool(pool).token1Amount(1000000) == 1000000);
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 0);
        assert(MoonsoonVestingPool(pool).vestingUnlockTimestamps().length == 0);
        assert(MoonsoonVestingPool(pool).vestingUnlockAmounts().length == 0);
    }

    function test_CalculateVestingData() public {
        CreateVestingPoolParams memory params = generateParams();

        VestingSchedule memory vestingSchedule = VestingSchedule(
            0,
            5000,
            block.timestamp + 600,
            600,
            60
        );

        VestingSchedule memory vestingSchedule1 = VestingSchedule(
            1,
            5000,
            block.timestamp + 600,
            600,
            120
        );

        VestingSchedule[] memory schedules = new VestingSchedule[](2);
        schedules[0] = vestingSchedule;
        schedules[1] = vestingSchedule1;

        params.vestingMetadata.vestingSchedule = schedules;

        VestingMetadata memory vestingMetadata = VestingMetadata(
            address(mockToken),
            10000,
            vm.addr(deployerPrivateKey),
            schedules
        );

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).calculateVestingData(1000000);
        vm.stopPrank();


        uint256[] memory vestingUnlockAmounts = MoonsoonVestingPool(pool).vestingUnlockAmounts();
        uint256[] memory vestingUnlockTimestamps = MoonsoonVestingPool(pool).vestingUnlockTimestamps();

        assert(vestingUnlockAmounts.length == 7);
        assert(vestingUnlockTimestamps.length == 7);

        assert(vestingUnlockAmounts[0] == 500000);
        assert(vestingUnlockAmounts[1] == 83333);
    }
}
