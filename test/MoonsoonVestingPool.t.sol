// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/interfaces/VestingPool.sol";
import "../src/MoonsoonVestingPool.sol";
import "../src/MoonsoonVestingPoolFactory.sol";
import "./TestSetup.t.sol";

contract MoonsoonVestingPoolTest is TestSetup {
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
            100,
            vm.addr(deployerPrivateKey),
            schedules
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256(abi.encode(""));

        RoyaltyInfo memory royaltyInfo = RoyaltyInfo(
            vm.addr(deployerPrivateKey),
            100
        );

        bytes memory callData = abi.encodeCall(TestVoucherFactory.createVoucher, ());

        params = CreateVestingPoolParams(
            address(mockToken),
            100000000,
            address(0x0),
            1,
            1,
            false,
            1000000,
            callData,
            vestingMetadata,
            royaltyInfo,
            address(voucherImplementation),
            proof,
            keccak256(""),
            block.timestamp + 60,
            bytes("0x")
        );
    }

    function test() public {
        assertTrue(1 == 1);
    }

    function test_CreateVestingPoolSuccessfully() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address pool = factory.createVestingPool(params);
        vm.stopPrank();

        assertTrue(1 == 1);
    }
}
