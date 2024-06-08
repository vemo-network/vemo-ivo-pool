// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/interfaces/VestingPool.sol";
import "../src/pools/VemoFixedStakingPool.sol";
import "../src/VemoPoolFactory.sol";
import "./TestSetup.t.sol";

contract VemoFixedStakingPoolTest is TestSetup {
    VemoPoolFactory private factory;

    function setUp() public override {
        super.setUp();

        vm.startPrank(vm.addr(deployerPrivateKey));
        factory = new VemoPoolFactory();
        factory.initialize(vm.addr(deployerPrivateKey), "VemoPoolFactory", "0.1");
        factory.setVoucherAddress(address(voucher));
        mockToken.approve(address(factory), UINT256_MAX);
        vm.stopPrank();

        console.log("VemoPoolFactory Address: ", address(factory));
    }

    function generateParams() private view returns (CreateVestingPoolParams memory params) {
        IVoucherFactory.VestingSchedule memory vestingSchedule = IVoucherFactory.VestingSchedule(
            1000000,
            1, // linear: 1 | staged: 2
            1,
            block.timestamp + 60,
            block.timestamp + 600,
            0,
            1000000
        );

        IVoucherFactory.VestingSchedule[] memory schedules = new IVoucherFactory.VestingSchedule[](1);
        schedules[0] = vestingSchedule;

        IVoucherFactory.VestingFee memory fee = IVoucherFactory.VestingFee(
            0,
            address(mockToken1),
            vm.addr(deployerPrivateKey),
            100000,
            0
        );

        bytes32 hash = keccak256(abi.encodePacked(uint256(1), address(mockToken), address(mockToken1)));
        params = CreateVestingPoolParams(
            hash,
            1,
            address(mockToken),
            100000000,
            address(mockToken1),
            100000000,
            0,
            true,
            2000000,
            500,
            schedules,
            fee,
            "https://test.com",
            root,
            block.timestamp + 60,
            block.timestamp + 120
        );
    }

    function test_CreateFixedStakingPoolSuccessfully() public {
        assert(true == false);
    }

    function test_StakeSuccessfully() public {
        assert(true == false);
    }

    function test_ChangingAllocation() public {
        assert(true == false);
    }

    function test_ChangingReward() public {
        assert(true == false);
    }
}
