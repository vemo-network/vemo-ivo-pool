// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/interfaces/VestingPool.sol";
import "../src/VemoVestingPool.sol";
import "../src/VemoVestingPoolFactory.sol";
import "./TestSetup.t.sol";

contract VemoVestingPoolTest_NonWhitelist2 is TestSetup {
    VemoVestingPoolFactory private factory;

    TestToken private _mockToken3;

    function setUp() public override {
        super.setUp();

        _mockToken3 = new TestToken("test3", "TEST3");
        _mockToken3.mint(vm.addr(deployerPrivateKey), 100000000000000000000);

        vm.startPrank(vm.addr(deployerPrivateKey));
        factory = new VemoVestingPoolFactory();
        factory.initialize(vm.addr(deployerPrivateKey), "VemoVestingPoolFactory", "0.1");
        factory.setVoucherAddress(address(voucher));
        _mockToken3.approve(address(factory), UINT256_MAX);
        vm.stopPrank();
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
            address(_mockToken3),
            vm.addr(deployerPrivateKey),
            100000,
            0
        );

        bytes32 hash = keccak256(abi.encodePacked(uint256(1), address(mockToken), address(mockToken1)));
        params = CreateVestingPoolParams(
            hash,
            1,
            address(_mockToken3),
            100000000000000000000,
            address(mockToken1),
            10000000000000000000,
            1,
            true,
            50000000000000000000,
            500,
            schedules,
            fee,
            "https://test.com",
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

        assert(pool.balance == 0);
        assert(VemoVestingPool(pool).token1Amount(50000000000000000000) == 5000000000000000000);

        skip(60);
        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.mint(vm.addr(buyerPrivateKey), 5000000000000000000);
        mockToken1.approve(pool, 5000000000000000000);
        VemoVestingPool(pool).buy(50000000000000000000, "/test.png");
        vm.stopPrank();
    }

    function test_BuySuccessfullyWithETH() public {
        CreateVestingPoolParams memory params = generateParams();
        params.token1 = address(0);
        params.expectedToken1Amount = 10000000000000000000;

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();
        assert(pool.balance == 0);
        assert(VemoVestingPool(pool).token1Amount(50000000000000000000) == 5000000000000000000);

        skip(60);

        vm.startPrank(vm.addr(buyerPrivateKey));
        vm.deal(vm.addr(buyerPrivateKey), 5000000000000000000);
        VemoVestingPool(pool).buy{value: 5000000000000000000}(50000000000000000000, "/test.png");
        vm.stopPrank();
    }
}
