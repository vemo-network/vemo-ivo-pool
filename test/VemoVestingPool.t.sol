// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/interfaces/VestingPool.sol";
import "../src/VemoVestingPool.sol";
import "../src/VemoVestingPoolFactory.sol";
import "./TestSetup.t.sol";

contract VemoVestingPoolTest is TestSetup {
    VemoVestingPoolFactory private factory;

    function setUp() public override {
        super.setUp();

        vm.startPrank(vm.addr(deployerPrivateKey));
        factory = new VemoVestingPoolFactory();
        factory.initialize(vm.addr(deployerPrivateKey), "VemoVestingPoolFactory", "0.1");
        factory.setVoucherAddress(address(voucher));
        mockToken.approve(address(factory), UINT256_MAX);
        vm.stopPrank();

        console.log("VemoVestingPoolFactory Address: ", address(factory));
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
            0,
            true,
            2000000,
            500,
            schedules,
            fee,
            root,
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

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;


        assert(VemoVestingPool(pool).token1Amount(100000) == 100000);

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        VemoVestingPool(pool).buyWhitelist(100000, 100000, proof);
        vm.stopPrank();

        assert(voucher.ownerOf(1) == vm.addr(buyerPrivateKey));
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 900000);
    }

    function testFail_BuyAmountExceedAllocation() public {
        CreateVestingPoolParams memory params = generateParams();

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(60);

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        VemoVestingPool(pool).buyWhitelist(150000, 100000, proof);
        vm.stopPrank();
    }

    function testFailed_PoolHasNotStarted() public {
        CreateVestingPoolParams memory params = generateParams();
        params.token1 = address(0);

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(60);

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        VemoVestingPool(pool).buyWhitelist(150000, 100000, proof);
        vm.stopPrank();
    }

    function test_BuySuccessfullyWithFee() public {
        CreateVestingPoolParams memory params = generateParams();

        IVoucher.VestingFee memory fee = IVoucher.VestingFee(
            1,
            address(mockToken1),
            vm.addr(deployerPrivateKey),
            100000,
            0
        );
        params.fee = fee;

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(60);

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;

        assert(VemoVestingPool(pool).token1Amount(100000) == 100000);

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        VemoVestingPool(pool).buyWhitelist(100000, 100000, proof);
        vm.stopPrank();

        assert(voucher.getVestingSchedules(1, 0).amount == 1000);
        assert(voucher.getFee(1).totalFee == 100);
        assert(voucher.getFee(1).receiverAddress == vm.addr(deployerPrivateKey));
        assert(voucher.getFee(1).feeTokenAddress == address(mockToken1));
        assert(voucher.getFee(1).remainingFee == 0);
        assert(voucher.ownerOf(1) == vm.addr(buyerPrivateKey));
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 900000);
    }

    function test_BuySuccessfullyWithFeeWithDifferentToken() public {
        CreateVestingPoolParams memory params = generateParams();

        TestToken token3 = new TestToken("token3", "TK3");

        IVoucher.VestingFee memory fee = IVoucher.VestingFee(
            1,
            address(token3),
            vm.addr(deployerPrivateKey),
            100000,
            0
        );
        params.fee = fee;

        vm.startPrank(vm.addr(deployerPrivateKey));
        address payable pool = factory.createVestingPool(params);
        vm.stopPrank();

        skip(60);

        bytes memory source = hex"af4177ad59fb38eeb0a69363fb1e21f23129d65e1e7f7aad13fe6bb6ce5a4adc";
        bytes32 p = stringToBytes32(source);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = p;

        assert(VemoVestingPool(pool).token1Amount(100000) == 100000);

        vm.startPrank(vm.addr(buyerPrivateKey));
        mockToken1.approve(pool, UINT256_MAX);
        VemoVestingPool(pool).buyWhitelist(100000, 100000, proof);
        vm.stopPrank();

        assert(voucher.getVestingSchedules(1, 0).amount == 1000);
        assert(voucher.getFee(1).totalFee == 100);
        assert(voucher.getFee(1).receiverAddress == vm.addr(deployerPrivateKey));
        assert(voucher.getFee(1).feeTokenAddress == address(token3));
        assert(voucher.getFee(1).remainingFee == 0);
        assert(voucher.ownerOf(1) == vm.addr(buyerPrivateKey));
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 900000);
    }
}
