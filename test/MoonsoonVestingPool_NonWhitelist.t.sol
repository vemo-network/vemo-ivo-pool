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
        factory.setVoucherAddress(address(voucher));
        mockToken.approve(address(factory), UINT256_MAX);
        vm.stopPrank();

        console.log("MoonsoonVestingPoolFactory Address: ", address(factory));
    }

    function generateParams() private view returns (CreateVestingPoolParams memory params) {
        IVoucher.VestingSchedule memory vestingSchedule = IVoucher.VestingSchedule(
            1000000,
            1, // linear: 1 | staged: 2
            1,
            block.timestamp + 60,
            block.timestamp + 600,
            0,
            1000000
        );

        IVoucher.VestingSchedule[] memory schedules = new IVoucher.VestingSchedule[](1);
        schedules[0] = vestingSchedule;

        IVoucher.VestingFee memory fee = IVoucher.VestingFee(
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
            1,
            true,
            2000000,
            500,
            schedules,
            fee,
            keccak256(""),
            block.timestamp + 60,
            block.timestamp + 120
        );
    }

    function test_BuySuccessfully() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(60);

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buy(1000000);
        vm.stopPrank();

        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 0);
    }

    function test_BuySuccessfullyWithETH() public {
        CreateVestingPoolParams memory params = generateParams();
        params.token1 = address(0);
        params.expectedToken1Amount = 100000000000;

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();
        assert(pool.balance == 0);
        assert(MoonsoonVestingPool(pool).token1Amount(1000000) == 1000000000);

        skip(60);

        vm.deal(vm.addr(buyerPrivateKey), 1000000000000000000);

        vm.startPrank(vm.addr(buyerPrivateKey));
        MoonsoonVestingPool(pool).buy{value: MoonsoonVestingPool(pool).token1Amount(1000000)}(1000000);
        vm.stopPrank();

        assert(pool.balance == 1000000000);
    }

    function testFailed_BuyFailedWithETH() public {
        CreateVestingPoolParams memory params = generateParams();
        params.token1 = address(0);

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();
        assert(pool.balance == 0);
        assert(MoonsoonVestingPool(pool).token1Amount(1000000) == 1000000000000000000);

        skip(60);

        vm.deal(vm.addr(buyerPrivateKey), 1000000000000000000);

        vm.startPrank(vm.addr(buyerPrivateKey));
        MoonsoonVestingPool(pool).buy{value: 232}(1000000);
        vm.stopPrank();
    }

    function testFailed_PoolHasNotStarted() public {
        CreateVestingPoolParams memory params = generateParams();
        params.token1 = address(0);

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();
        assert(pool.balance == 0);
        assert(MoonsoonVestingPool(pool).token1Amount(1000000) == 1000000000000000000);

        skip(40);

        vm.deal(vm.addr(buyerPrivateKey), 1000000000000000000);

        vm.startPrank(vm.addr(buyerPrivateKey));
        MoonsoonVestingPool(pool).buy{value: MoonsoonVestingPool(pool).token1Amount(1000000)}(1000000);
        vm.stopPrank();
    }

    function testFailed_PoolHasEnded() public {
        CreateVestingPoolParams memory params = generateParams();
        params.token1 = address(0);

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();
        assert(pool.balance == 0);
        assert(MoonsoonVestingPool(pool).token1Amount(1000000) == 1000000000000000000);

        skip(125);

        vm.deal(vm.addr(buyerPrivateKey), 1000000000000000000);

        vm.startPrank(vm.addr(buyerPrivateKey));
        MoonsoonVestingPool(pool).buy{value: MoonsoonVestingPool(pool).token1Amount(1000000)}(1000000);
        vm.stopPrank();
    }

    function testFailed_BuyMoreThanAllocationInFirstTx() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(70);

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buy(3000000);
        vm.stopPrank();
    }

    function testFailed_BuyMoreThanAllocationIn2ndTx() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(70);

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buy(1000000);
        MoonsoonVestingPool(pool).buy(1100000);
        vm.stopPrank();
    }

    function testFailed_BuyLessThanAllocationInNonFlexiblePool() public {
        CreateVestingPoolParams memory params = generateParams();
        params.flexibleAllocation = false;

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(70);

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        MoonsoonVestingPool(pool).buy(1000000);
        vm.stopPrank();
    }

}
