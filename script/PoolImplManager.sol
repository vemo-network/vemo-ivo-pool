// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import "../src/PoolImplManager.sol";
import "../src/VemoPoolFactory.sol";
import {Upgrades, Options} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract PoolImplManagerScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address poolFactory = vm.envAddress("POOL_FACTORY");

        vm.startBroadcast(deployerPrivateKey);
        address implManager = Upgrades.deployUUPSProxy(
            "PoolImplManager.sol",
            abi.encodeCall(PoolImplManager.initialize, (deployer))
        );
        VemoPoolFactory factory = VemoPoolFactory(payable(poolFactory));
        factory.setImplManager(implManager);
        vm.stopBroadcast();
    }
}
