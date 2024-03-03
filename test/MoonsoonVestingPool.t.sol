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
            100000
        );

        bytes32 hash = keccak256(abi.encodePacked(uint256(1), address(mockToken), address(mockToken1)));
//        bytes32 hash = keccak256(abi.encodePacked(uint256(1), address(0x21b2E6c9805871743aeAD44c65bAb6cb9F0f1c60), address(0x38BE5E3f75C7D5F67558FC47c75c010783a28Cc9)));
        console.logBytes32(hash);
        params = CreateVestingPoolParams(
            hash,
            1,
            address(mockToken),
            100000000,
            address(mockToken1),
            1,
            0,
            true,
            2000000,
            500,
            schedules,
            fee,
            root,
            block.timestamp + 60
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

        assert(voucher.ownerOf(1) == vm.addr(buyerPrivateKey));
        assert(mockToken1.balanceOf(vm.addr(buyerPrivateKey)) == 900000);
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
}
