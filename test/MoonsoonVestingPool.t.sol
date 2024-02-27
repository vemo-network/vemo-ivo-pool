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
            0,
            false,
            1000000,
            callData,
            vestingMetadata,
            royaltyInfo,
            address(voucherImplementation),
            root,
            block.timestamp + 60,
            bytes("0x")
        );
    }

    function generateParamsWithNativeToken1() private view returns (CreateVestingPoolParams memory params) {
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
            0,
            false,
            1000000,
            callData,
            vestingMetadata,
            royaltyInfo,
            address(voucherImplementation),
            root,
            block.timestamp + 60,
            bytes("0x")
        );
    }
    
    function test_BuySuccessfully() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buyWhitelist(100000, 100000, proof);
        vm.stopPrank();

        assert(MoonsoonVestingPool(pool).token1Amount(1000000) == 1000000);
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 900000);
        assert(MoonsoonVestingPool(pool).vestingUnlockTimestamps().length == 0);
        assert(MoonsoonVestingPool(pool).vestingUnlockAmounts().length == 0);
    }

    function testFail_BuyAmountExceedAllocation() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buyWhitelist(150000, 100000, proof);
        vm.stopPrank();
    }

    function test_BuySuccessfullyWith2Buyer2VestingSchedule() public {
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

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;
        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buyWhitelist(100000, 100000, proof);
        vm.stopPrank();
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 900000);
        assert(MoonsoonVestingPool(pool).vestingUnlockTimestamps().length == 0);
        assert(MoonsoonVestingPool(pool).vestingUnlockAmounts().length == 0);

        bytes memory source2 = hex"712fbbeb217ea6491ef97ec6a84380e369b59f3eeb5ff127a22ab420cf78e2fe";
        bytes32 p2 = stringToBytes32(source2);
        bytes32[] memory proof2 = new bytes32[](1);
        proof2[0] = p2;
        vm.startPrank(vm.addr(buyer2PrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buyWhitelist(150000, 200000, proof2);
        vm.stopPrank();
        assert(mockToken1.balanceOf(vm.addr(buyer2PrivateKey)) == 850000);
        assert(MoonsoonVestingPool(pool).vestingUnlockTimestamps().length == 0);
        assert(MoonsoonVestingPool(pool).vestingUnlockAmounts().length == 0);
    }
}
